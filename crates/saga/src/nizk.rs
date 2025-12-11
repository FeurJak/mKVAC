use super::Params as SAGAParams;
use super::PublicKey as SagaPK;
use super::SAGAPres;
use super::SecretKey as SagaSK;
use super::Signature as SAGASig;
use super::curve::*;
use super::errors::*;
use super::traits::*;

use cosmian_crypto_core::{
    CsRng,
    bytes_ser_de::{Deserializer, Serializable, Serializer, to_leb128_len},
    reexport::rand_core::{CryptoRngCore, RngCore, SeedableRng},
};
use rayon::prelude::*;
use tiny_keccak::{Hasher, Sha3};
use zeroize::Zeroize;

const PROT_NAME_REQ: &[u8] = b"AKVAC-REQ";
const PROT_NAME_ISSUE: &[u8] = b"AKVAC-ISSUE";
const PROT_NAME_SHOW: &[u8] = b"AKVAC-SHOW";

/// Public parameters for AKVAC
#[derive(Clone, Debug)]
pub struct PublicParams {
    /// Group base (G) carried from saga params
    pub g: R25519Point,
    /// Random presentation base H
    pub h: R25519Point,
    /// saga params with ℓ = n + 2; contains:
    ///   - pp_saga = G_0
    ///   - g_vec = [G_1..g_{n+2}]
    pub saga_params: SAGAParams,
}

/// AKVAC issuer key material
#[derive(Clone, Debug)]
pub struct IssuerSecret {
    pub saga_sk: SagaSK,
    pub e: R25519Scalar,
}

#[derive(Clone, Debug)]
pub struct IssuerPublic {
    pub saga_pk: SagaPK,
    pub e: R25519Point, // E = e * G
}

/// AKVAC verifier key material
#[derive(Clone, Debug)]
pub struct VerifierSecret {
    /// x_0..x_n
    pub x_0_to_x_n: Vec<R25519Scalar>,
}

#[derive(Clone, Debug)]
pub struct VerifierPublic {
    /// (X_1..x_n, X_0, Z_0)
    pub x_1_to_n: Vec<R25519Point>,
    pub x_0: R25519Point,
    pub z_0: R25519Point,
    /// τ (saga MAC over X_1..x_n, X_0, Z_0)
    pub tau: SAGASig,
}

#[derive(Clone, Debug)]
pub struct ReceiveCredState {
    pub s: R25519Scalar,
    pub bar_x0: R25519Scalar,
    pub bar_X0: R25519Point,
    pub bar_Z0: R25519Point,
    // not strictly required by the LaTeX to be stored;
    // keeping attrs here is handy for the final output:
    pub attrs: Vec<R25519Scalar>,
}

#[derive(Clone, Debug)]
pub struct CredReq {
    pub saga_pres: SAGAPres,
    pub c_j_vec: Vec<R25519Point>,
    // C_1..C_{n+2}
    pub bar_X0: R25519Point,
    pub bar_Z0: R25519Point,
    pub c_attr: R25519Point,
    pub nizk: ReqProof,
}

#[derive(Clone, Debug)]
pub struct BlindCred {
    pub bar_u: R25519Point,
    pub bar_v: R25519Point,
    pub nizk: IssProof,
}

#[derive(Clone, Debug)]
pub struct Credential {
    pub u: R25519Point,
    pub v: R25519Point,
    pub attrs: Vec<R25519Scalar>,
}

// simple 32-byte digest proof
#[derive(Clone, Debug)]
pub struct Proof32 {
    pub digest: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct Presentation {
    pub tilde_u: R25519Point,
    pub z: R25519Point,
    pub c_v: R25519Point,
    pub c_j_vec: Vec<R25519Point>,
    // C_1..C_n
    pub nizk: ShowProof, // cmzcpzshow
}

/// Schnorr-style NIZK for AKVAC request (cmzcpzrec)
#[derive(Clone, Debug)]
pub struct ReqProof {
    pub c: R25519Scalar,

    // responses
    pub s_s: R25519Scalar,             // for s
    pub s_attrs: Vec<R25519Scalar>,    // for a_j, j=1..n
    pub s_xi_prime: Vec<R25519Scalar>, // for xi'_j = a_j * xi_j, j=1..n
    pub s_bar_x0: R25519Scalar,        // for \bar x_0
    pub s_bar_nu: R25519Scalar,        // for \bar \nu
    pub s_r: R25519Scalar,             // for r
    pub s_e: R25519Scalar,             // for e  (BBS signature R25519Scalar)
    pub s_xi: Vec<R25519Scalar>,       // for xi_j, j=1..n+2  (from VKA present)
    pub s_eta: R25519Scalar,           // for \eta
    pub s_prod: R25519Scalar,          // for prod   = e * r
    pub s_prod_prime: R25519Scalar,    // for prod'  = r * \eta

    // include ProdCom in the proof (part of the statement hash)
    pub prod_com: R25519Point, // eG + eta H
}

/// Schnorr-style NIZK for AKVAC issuance (cmzcpzissue)
#[derive(Clone, Debug)]
pub struct IssProof {
    pub c: R25519Scalar,      // challenge
    pub s_e: R25519Scalar,    // response for e
    pub s_u: R25519Scalar,    // response for u
    pub s_prod: R25519Scalar, // response for prod = e * u
}

/// Schnorr OR-proof for AKVAC presentation (cmzcpzshow)
/// Honest prover knows witness for part (1): (\tildeγ, (a_j, γ_j)_{j=1..n})
/// and simulates part (2) over statement X1.
#[derive(Clone, Debug)]
pub struct ShowProof {
    // challenges for both branches
    pub c1: R25519Scalar, // for part (1)
    pub c2: R25519Scalar, // for part (2), simulated

    // responses for part (1) witness:
    pub s_tilde_gamma: R25519Scalar,   // response for \tildeγ
    pub s_attrs: Vec<R25519Scalar>,    // responses for a_j
    pub s_gamma_js: Vec<R25519Scalar>, // responses for γ_j

    // response for part (2) (scalar for x1 in φ^(2): x1 G = X1)
    pub s2: R25519Scalar,
}

fn hash_challenge_show(
    pres_ctx: &[u8],
    // statement:
    x_1_to_n: &[R25519Point],
    tilde_u: &R25519Point,
    // part (1) announcement:
    t_z: &R25519Point,
    t_cj_vec: &[R25519Point],
    // part (2) announcement:
    t2: &R25519Point,
) -> Result<R25519Scalar, Error> {
    let mut hasher = Sha3::v512();
    let mut bytes = [0; 512 / 8];

    hasher.update(PROT_NAME_SHOW);
    hasher.update(pres_ctx);

    for xj in x_1_to_n {
        hasher.update(&xj.serialize()?);
    }

    hasher.update(&tilde_u.serialize()?);

    hasher.update(&t_z.serialize()?);
    for t_cj in t_cj_vec {
        hasher.update(&t_cj.serialize()?);
    }

    hasher.update(&t2.serialize()?);

    let s = R25519Scalar::from(&bytes);
    bytes.zeroize();

    Ok(s)
}

fn hash_challenge_issue(
    // full public statement (binds everything used in T4):
    e: &R25519Point,
    bar_u: &R25519Point,
    bar_v: &R25519Point,
    bar_x0: &R25519Point,
    bar_z0: &R25519Point,
    c_attr: &R25519Point,
    // accepting announcement:
    t1: &R25519Point,
    t2: &R25519Point,
    t3: &R25519Point,
    t4: &R25519Point,
) -> Result<R25519Scalar, Error> {
    let mut hasher = Sha3::v512();
    let mut bytes = [0; 512 / 8];

    hasher.update(PROT_NAME_ISSUE);

    // statement
    hasher.update(&e.serialize()?);
    hasher.update(&bar_u.serialize()?);
    hasher.update(&bar_v.serialize()?);
    hasher.update(&bar_x0.serialize()?);
    hasher.update(&bar_z0.serialize()?);
    hasher.update(&c_attr.serialize()?);

    // announcement
    hasher.update(&t1.serialize()?);
    hasher.update(&t2.serialize()?);
    hasher.update(&t3.serialize()?);
    hasher.update(&t4.serialize()?);

    let s = R25519Scalar::from(&bytes);
    bytes.zeroize();

    Ok(s)
}

/// Prover for cmzcpzissue
/// Statement (public): (E, Ū, V̄, X̄0, Z̄0, c_attr)
/// Witness (secret):   (e, u), and we also include prod = e*u
pub fn nizk_prove_issue<R: RngCore + CryptoRngCore>(
    rng: &mut R,
    pp: &PublicParams,
    e: &R25519Point,
    bar_u: &R25519Point,
    bar_v: &R25519Point,
    bar_x0: &R25519Point,
    bar_z0: &R25519Point,
    c_attr: &R25519Point,
    wit_e: &R25519Scalar,
    wit_u: &R25519Scalar,
) -> Result<IssProof, Error> {
    // Witness value for the product:
    let prod = wit_e.clone() * wit_u.clone();

    // a-values
    let a_e = R25519Scalar::random(rng);
    let a_u = R25519Scalar::random(rng);
    let a_prod = R25519Scalar::random(rng);

    // Announcement T = φ(a)
    // t1 = a_u G                    (corresponds to Ū)
    let t1 = &pp.g * &a_u;
    // t2 = a_e G                    (corresponds to E)
    let t2 = &pp.g * &a_e;
    // t3 = a_prod G - a_u E         (corresponds to 0)
    let t3 = &pp.g * &a_prod - e * &a_u;
    // t4 = a_u*X̄0 - a_prod*Z̄0 + a_u*c_attr   (corresponds to V̄)
    let t4 = bar_x0 * &a_u - bar_z0 * &a_prod + c_attr * &a_u;

    // Challenge
    let c = hash_challenge_issue(e, bar_u, bar_v, bar_x0, bar_z0, c_attr, &t1, &t2, &t3, &t4)?;

    // Responses
    let s_e = a_e + c.clone() * wit_e.clone();
    let s_u = a_u + c.clone() * wit_u.clone();
    let s_prod = a_prod + c.clone() * prod;

    Ok(IssProof {
        c,
        s_e,
        s_u,
        s_prod,
    })
}

/// Verifier for cmzcpzissue
pub fn nizk_verify_issue(
    pp: &PublicParams,
    e: &R25519Point,
    bar_u: &R25519Point,
    bar_v: &R25519Point,
    bar_x0: &R25519Point,
    bar_z0: &R25519Point,
    c_attr: &R25519Point,
    proof: &IssProof,
) -> Result<bool, Error> {
    // Recompute accepting announcement U = φ(s) - c * S
    // Derived statement image S = (Ū, E, 0, V̄)
    // u1 = s_u G      - c*Ū
    let u1 = &pp.g * &proof.s_u - bar_u * &proof.c;

    // u2 = s_e G      - c*E
    let u2 = &pp.g * &proof.s_e - e * &proof.c;

    // u3 = s_prod G - s_u E    - c*0
    let u3 = &pp.g * &proof.s_prod - e * &proof.s_u;

    // u4 = s_u*X̄0 - s_prod*Z̄0 + s_u*c_attr  - c*V̄
    let u4 = bar_x0 * &proof.s_u - bar_z0 * &proof.s_prod + c_attr * &proof.s_u - bar_v * &proof.c;

    // Challenge must match
    let c_prime =
        hash_challenge_issue(e, bar_u, bar_v, bar_x0, bar_z0, c_attr, &u1, &u2, &u3, &u4)?;
    Ok(c_prime == proof.c)
}

fn hash_challenge_req(
    // derived statement (6 group elements):
    s1: &R25519Point,
    s2: &R25519Point,
    s3: &R25519Point,
    s4: &R25519Point,
    s5: &R25519Point,
    s6: &R25519Point,
    // accepting announcement (6 group elements):
    t1: &R25519Point,
    t2: &R25519Point,
    t3: &R25519Point,
    t4: &R25519Point,
    t5: &R25519Point,
    t6: &R25519Point,
) -> Result<R25519Scalar, Error> {
    let mut hasher = Sha3::v512();
    let mut bytes = [0; 512 / 8];

    hasher.update(PROT_NAME_REQ);

    // statement
    hasher.update(&s1.serialize()?);
    hasher.update(&s2.serialize()?);
    hasher.update(&s3.serialize()?);
    hasher.update(&s4.serialize()?);
    hasher.update(&s5.serialize()?);
    hasher.update(&s6.serialize()?);

    // statement
    hasher.update(&t1.serialize()?);
    hasher.update(&t2.serialize()?);
    hasher.update(&t3.serialize()?);
    hasher.update(&t4.serialize()?);
    hasher.update(&t5.serialize()?);
    hasher.update(&t6.serialize()?);

    let s = R25519Scalar::from(&bytes);
    bytes.zeroize();

    Ok(s)
}

/// Prover for cmzcpzrec (request proof)
pub fn nizk_prove_req<R: RngCore + CryptoRngCore>(
    rng: &mut R,
    pp: &PublicParams,
    ipk: &IssuerPublic,  // for E and (X, Y_j)
    params: &SAGAParams, // for G, G_j
    // public statement inputs:
    vka_pres: &super::SAGAPres, // has C_A, T
    c_j_vec: &[R25519Point],    // C_1..C_{n+2}
    bar_X0: &R25519Point,
    bar_Z0: &R25519Point,
    c_attr: &R25519Point,
    // secret witness inputs:
    s: &R25519Scalar,
    attrs: &[R25519Scalar], // a_j, j=1..n
    bar_x0: &R25519Scalar,
    bar_nu: &R25519Scalar,
    r: &R25519Scalar,
    e: &R25519Scalar,        // BBS signature e
    xi_vec: &[R25519Scalar], // xi_1..xi_{n+2}
) -> Result<ReqProof, Error> {
    let l = params.g_vec.len(); // l = n + 2
    let n = l - 2;
    debug_assert_eq!(c_j_vec.len(), l);
    debug_assert_eq!(attrs.len(), n);
    debug_assert_eq!(xi_vec.len(), l);

    // prod commitments
    let eta = R25519Scalar::random(rng);
    let prod_com = &pp.g * e + &pp.h * &eta;
    let prod = e.clone() * r.clone();
    let prod_prime = r.clone() * eta.clone();

    // 1) randomizers (a-values)
    let a_s = R25519Scalar::random(rng);
    let a_attrs: Vec<R25519Scalar> = (0..n).map(|_| R25519Scalar::random(rng)).collect();
    let a_xi_prime: Vec<R25519Scalar> = (0..n).map(|_| R25519Scalar::random(rng)).collect();
    let a_bar_x0 = R25519Scalar::random(rng);
    let a_bar_nu = R25519Scalar::random(rng);
    let a_r = R25519Scalar::random(rng);
    let a_e = R25519Scalar::random(rng);
    let a_xi: Vec<R25519Scalar> = (0..l).map(|_| R25519Scalar::random(rng)).collect();
    let a_eta = R25519Scalar::random(rng);
    let a_prod = R25519Scalar::random(rng);
    let a_prod_prime = R25519Scalar::random(rng);

    // 2) announcement T = φ(a)
    // T1 = - a_xi_{n+1} G_{n+1} + a_bar_x0 G + a_bar_nu E
    let t1 = -(&params.g_vec[n] * &a_xi[n]) + (&params.g * &a_bar_x0) + (&ipk.e * &a_bar_nu);
    // T2 = - a_xi_{n+2} G_{n+2} + a_bar_nu G
    let t2 = -(&params.g_vec[n + 1] * &a_xi[n + 1]) + (&params.g * &a_bar_nu);
    // T3 = a_s G + sum_j a_j C_j - sum_j a_xi'_j G_j  (j in 1..n; our arrays are 0..n-1)
    // let mut t3 = &pp.g, &a_s);
    // for j in 0..n {
    //     t3 += &c_j_vec[j], &a_attrs[j]);
    //     t3 -= &params.g_vec[j], &a_xi_prime[j]);
    // }
    let sum_ca: R25519Point = c_j_vec
        .par_iter()
        .zip(a_attrs.par_iter())
        .map(|(cj, a)| cj * a)
        .reduce(R25519Point::zero, |acc, p| acc + p);

    let sum_gxi: R25519Point = params.g_vec[..n]
        .par_iter()
        .zip(a_xi_prime.par_iter())
        .map(|(gj, xi)| gj * xi)
        .reduce(R25519Point::zero, |acc, p| acc + p);

    let t3 = (&pp.g * &a_s) + sum_ca - sum_gxi;
    // T4 = a_r X - a_e C_A + a_prod G - sum_{j=1..l} a_xi_j Y_j
    let mut t4 = &ipk.saga_pk.x * &a_r;
    t4 -= &vka_pres.c_a * &a_e;
    t4 += &pp.g * &a_prod;
    // for j in 0..l {
    //     t4 -= &ipk.saga_pk.y_vec[j], &a_xi[j]);
    // }
    // Parallel version:
    let sum_yxi: R25519Point = ipk.saga_pk.y_vec[..l]
        .par_iter()
        .zip(a_xi.par_iter())
        .map(|(yj, xi)| yj * xi)
        .reduce(R25519Point::zero, |acc, p| acc + p);

    t4 -= sum_yxi;
    // T5 = a_e G + a_eta H
    let t5 = &pp.g * &a_e + &pp.h * &a_eta;
    // T6 = a_prod G + a_prod' H - a_r * ProdCom
    let t6 = (&pp.g * &a_prod) + (&pp.h * &a_prod_prime) - (&prod_com * &a_r);

    // 3) derive statement image S = (S1..S6)
    let s1 = bar_X0.clone() - c_j_vec[n].clone(); // \bar X_0 - C_{n+1}
    let s2 = bar_Z0.clone() - c_j_vec[n + 1].clone(); // \bar Z_0 - C_{n+2}
    let s3 = c_attr.clone(); // c_attr
    let s4 = vka_pres.t.clone(); // T
    let s5 = prod_com.clone(); // ProdCom = eG + eta H
    let s6 = R25519Point::zero(); // 0

    // 4) FS challenge
    let c = hash_challenge_req(&s1, &s2, &s3, &s4, &s5, &s6, &t1, &t2, &t3, &t4, &t5, &t6)?;

    // 5) responses s = a + c * witness
    let s_s = a_s + c.clone() * s.clone();
    // let mut s_attrs: Vec<Scalar> = Vec::with_capacity(n);
    // let mut s_xi_prime: Vec<Scalar> = Vec::with_capacity(n);
    // for j in 0..n {
    //     s_attrs.push(a_attrs[j] + c * attrs[j]);
    //     // xi'_j = a_j * xi_j  (witness value)
    //     let xi_prime_j = attrs[j] * xi_vec[j];
    //     s_xi_prime.push(a_xi_prime[j] + c * xi_prime_j);
    // }
    // parallel:
    let (s_attrs, s_xi_prime): (Vec<R25519Scalar>, Vec<R25519Scalar>) = a_attrs
        .par_iter()
        .zip(attrs.par_iter())
        .zip(xi_vec.par_iter())
        .zip(a_xi_prime.par_iter())
        .map(|(((a_attr, attr), xi), a_xi_p)| {
            let s_attr = a_attr.clone() + c.clone() * attr.clone();
            let xi_prime_j = a_attr.clone() * xi.clone(); // ξ'_j = a_j * ξ_j
            let s_xip = a_xi_p.clone() + c.clone() * xi_prime_j;
            (s_attr, s_xip)
        })
        .unzip();

    let s_bar_x0 = a_bar_x0 + c.clone() * bar_x0;
    let s_bar_nu = a_bar_nu + c.clone() * bar_nu;
    let s_r = a_r + c.clone() * r;
    let s_e = a_e + c.clone() * e;

    // let mut s_xi: Vec<Scalar> = Vec::with_capacity(l);
    // for j in 0..l {
    //     s_xi.push(a_xi[j] + c * xi_vec[j]);
    // }
    // Parallel compute: s_xi[j] = a_xi[j] + c * xi_vec[j]
    let s_xi: Vec<R25519Scalar> = a_xi
        .par_iter()
        .zip(xi_vec.par_iter())
        .map(|(axi, xi)| axi.clone() + c.clone() * xi.clone())
        .collect();

    let s_eta = a_eta + c.clone() * eta;
    let s_prod = a_prod + c.clone() * prod.clone();
    let s_prod_prime = a_prod_prime + c.clone() * prod_prime.clone();

    Ok(ReqProof {
        c,
        s_s,
        s_attrs,
        s_xi_prime,
        s_bar_x0,
        s_bar_nu,
        s_r,
        s_e,
        s_xi,
        s_eta,
        s_prod,
        s_prod_prime,
        prod_com,
    })
}

/// Verifier for cmzcpzrec
pub fn nizk_verify_req(
    pp: &PublicParams,
    ipk: &IssuerPublic,
    params: &SAGAParams,
    vka_pres: &SAGAPres,
    c_j_vec: &[R25519Point],
    bar_X0: &R25519Point,
    bar_Z0: &R25519Point,
    c_attr: &R25519Point,
    proof: &ReqProof,
) -> Result<bool, Error> {
    let l = params.g_vec.len();
    let n = l - 2;
    if c_j_vec.len() != l {
        return Ok(false);
    }
    if proof.s_attrs.len() != n || proof.s_xi_prime.len() != n || proof.s_xi.len() != l {
        return Ok(false);
    }

    // Statement image S
    let s1 = bar_X0.clone() - c_j_vec[n].clone();
    let s2 = bar_Z0.clone() - c_j_vec[n + 1].clone();
    let s3 = c_attr.clone();
    let s4 = vka_pres.t.clone();
    let s5 = proof.prod_com.clone();
    let s6 = R25519Point::zero();

    // φ(s) - c S  (component-wise)
    // U1 = - s_xi_{n+1} G_{n+1} + s_bar_x0 G + s_bar_nu E  - c*s1
    let mut u1 = -(&params.g_vec[n] * &proof.s_xi[n]);
    u1 += &params.g * &proof.s_bar_x0;
    u1 += &ipk.e * &proof.s_bar_nu;
    u1 -= &s1 * &proof.c;

    // U2 = - s_xi_{n+2} G_{n+2} + s_bar_nu G  - c*s2
    let mut u2 = -(&params.g_vec[n + 1] * &proof.s_xi[n + 1]);
    u2 += &params.g * &proof.s_bar_nu;
    u2 -= &s2 * &proof.c;

    // U3 = s_s G + Σ s_attrs_j C_j - Σ s_xi'_j G_j  - c*s3
    let mut u3 = &pp.g * &proof.s_s;
    for j in 0..n {
        u3 += &c_j_vec[j] * &proof.s_attrs[j];
        u3 -= &params.g_vec[j] * &proof.s_xi_prime[j];
    }
    u3 -= &s3 * &proof.c;

    // U4 = s_r X - s_e C_A + s_prod G - Σ s_xi_j Y_j  - c*s4
    let mut u4 = &ipk.saga_pk.x * &proof.s_r;
    u4 -= &vka_pres.c_a * &proof.s_e;
    u4 += &pp.g * &proof.s_prod;
    for j in 0..l {
        u4 -= &ipk.saga_pk.y_vec[j] * &proof.s_xi[j];
    }
    u4 -= &s4 * &proof.c;

    // U5 = s_e G + s_eta H  - c*s5
    let mut u5 = (&pp.g * &proof.s_e) + (&pp.h * &proof.s_eta);
    u5 -= &s5 * &proof.c;

    // U6 = s_prod G + s_prod' H - s_r * ProdCom  - c*s6 (s6=0)
    let u6 =
        (&pp.g * &proof.s_prod) + (&pp.h * &proof.s_prod_prime) - (&proof.prod_com * &proof.s_r);

    // Recompute challenge
    let c_prime = hash_challenge_req(&s1, &s2, &s3, &s4, &s5, &s6, &u1, &u2, &u3, &u4, &u5, &u6)?;
    Ok(c_prime == proof.c)
}

/// Prover for cmzcpzshow (OR-proof).
/// Statement: (X_1..x_n, \tilde U, Z, (C_j)_1..n)
/// Witness (part 1): (\tildeγ, (a_j, γ_j)_1..n)
pub fn nizk_prove_show<R: RngCore + CryptoRngCore>(
    rng: &mut R,
    pp: &PublicParams,
    vpk: &VerifierPublic,
    // statement pieces:
    tilde_u: &R25519Point,
    z: &R25519Point,
    c_j_vec: &[R25519Point], // len = n
    // witness for part (1):
    tilde_gamma: &R25519Scalar,
    attrs: &[R25519Scalar],    // a_j
    gamma_js: &[R25519Scalar], // γ_j
    // context to bind:
    pres_ctx: &[u8],
) -> Result<ShowProof, Error> {
    let n = vpk.x_1_to_n.len();
    debug_assert_eq!(c_j_vec.len(), n);
    debug_assert_eq!(attrs.len(), n);
    debug_assert_eq!(gamma_js.len(), n);

    // --- Simulate branch (2) over statement X1: φ^(2)(x1)=x1 G = X1 ---
    let c2 = R25519Scalar::random(rng);
    let s2 = R25519Scalar::random(rng);
    // Announcement t2 = φ^(2)(s2) - c2 * X1 = s2 G - c2 X1
    let t2 = &pp.g * &s2 - &vpk.x_1_to_n[0] * &c2;

    // --- Real branch (1) over (Z, (C_j)) with witness ---
    // a-values (randomizers)
    let a_tg = R25519Scalar::random(rng);
    let a_attrs: Vec<R25519Scalar> = (0..n).map(|_| R25519Scalar::random(rng)).collect();
    let a_gammas: Vec<R25519Scalar> = (0..n).map(|_| R25519Scalar::random(rng)).collect();

    // Announcement for branch (1):
    // tZ = sum_j a_γj X_j - a_tg * H
    // let mut tZ = Point::zero();
    // for j in 0..n {
    //     tZ += &vpk.x_1_to_n[j], &a_gammas[j]);
    // }
    // tZ -= &pp.h, &a_tg);
    // tZ = Σ_j a_gamma_j * X_j  −  a_tg * H
    let tz_sum = vpk
        .x_1_to_n
        .par_iter()
        .zip(a_gammas.par_iter())
        .map(|(xj, a_gamma_j)| xj * a_gamma_j)
        .reduce(|| R25519Point::zero(), |acc, p| acc + p);

    let tz = tz_sum - &pp.h * &a_tg;

    // tCj_j = a_aj * \tilde U + a_γj * G
    // let mut tcj_vec = Vec::with_capacity(n);
    // for j in 0..n {
    //     tcj_vec.push(tilde_u, &a_attrs[j]) + &pp.g, &a_gammas[j]));
    // }
    // tcj_vec = [ tilde_u, a_attr_j) + G, a_gamma_j) ] for j=1..n
    let tcj_vec: Vec<R25519Point> = a_attrs
        .par_iter()
        .zip(a_gammas.par_iter())
        .map(|(a_attr, a_gamma)| tilde_u * a_attr + &pp.g * a_gamma)
        .collect();

    // Fiat–Shamir total challenge
    let c = hash_challenge_show(pres_ctx, &vpk.x_1_to_n, tilde_u, &tz, &tcj_vec, &t2)?;

    // Split: c1 = c - c2, c2 as above
    let c1 = c - c2.clone();

    // Responses for branch (1): s = a + c1 * witness
    let s_tilde_gamma = a_tg + c1.clone() * tilde_gamma.clone();
    // let mut s_attrs: Vec<Scalar> = Vec::with_capacity(n);
    // let mut s_gamma_js: Vec<Scalar> = Vec::with_capacity(n);
    // for j in 0..n {
    //     s_attrs.push(a_attrs[j]  + c1 * attrs[j]);
    //     s_gamma_js.push(a_gammas[j] + c1 * gamma_js[j]);
    // }
    let (s_attrs, s_gamma_js): (Vec<R25519Scalar>, Vec<R25519Scalar>) = a_attrs
        .par_iter()
        .zip(attrs.par_iter())
        .zip(a_gammas.par_iter().zip(gamma_js.par_iter()))
        .map(|((a_attr, attr), (a_gamma, gamma_j))| {
            (
                a_attr.clone() + c1.clone() * attr.clone(),
                a_gamma.clone() + c1.clone() * gamma_j.clone(),
            )
        })
        .unzip();

    Ok(ShowProof {
        c1,
        c2,
        s_tilde_gamma,
        s_attrs,
        s_gamma_js,
        s2,
    })
}

/// Verifier for cmzcpzshow.
/// Checks the OR-proof and (your existing) linear relation separately.
pub fn nizk_verify_show(
    pp: &PublicParams,
    vpk: &VerifierPublic,
    pres_ctx: &[u8],
    // statement:
    tilde_u: &R25519Point,
    z: &R25519Point,
    c_j_vec: &[R25519Point], // len = n
    // proof:
    proof: &ShowProof,
) -> Result<bool, Error> {
    let n = vpk.x_1_to_n.len();
    if c_j_vec.len() != n {
        return Ok(false);
    }
    if proof.s_attrs.len() != n || proof.s_gamma_js.len() != n {
        return Ok(false);
    }

    // Recompute accepting announcements:

    // Branch (1):
    // For Z: uZ = (Σ s_γj X_j - s_tildeγ H) - c1 * Z
    // let mut uZ = Point::zero();
    // for j in 0..n {
    //     uZ += &vpk.x_1_to_n[j], &proof.s_gamma_js[j]);
    // }
    // uZ -= &pp.h, &proof.s_tilde_gamma);
    // uZ -= Z, &proof.c1);
    // Parallel sum of  Σ_j  s_gamma_js[j] * X_1_to_n[j]
    let sum_x = vpk
        .x_1_to_n
        .par_iter()
        .zip(proof.s_gamma_js.par_iter())
        .map(|(xj, gamma_j)| xj * gamma_j)
        .reduce(|| R25519Point::zero(), |a, b| a + b);

    // Finish the expression
    let mut uz = sum_x;
    uz -= &pp.h * &proof.s_tilde_gamma;
    uz -= z * &proof.c1;

    // For each C_j: uCj = (s_aj \tilde U + s_γj G) - c1 * C_j
    // let mut uCj_vec = Vec::with_capacity(n);
    // for j in 0..n {
    //     let u = tilde_u, &proof.s_attrs[j]) + &pp.g, &proof.s_gamma_js[j])
    //         - &c_j_vec[j], &proof.c1);
    //     uCj_vec.push(u);
    // }
    let u_cj_vec: Vec<R25519Point> = (0..n)
        .into_par_iter()
        .map(|j| {
            tilde_u * &proof.s_attrs[j] + &pp.g * &proof.s_gamma_js[j] - &c_j_vec[j] * &proof.c1
        })
        .collect();

    // Branch (2):
    // u2 = s2 G - c2 X1
    let u2 = &pp.g * &proof.s2 - &vpk.x_1_to_n[0] * &proof.c2;

    // Recompute total challenge:
    let c_prime = hash_challenge_show(pres_ctx, &vpk.x_1_to_n, tilde_u, &uz, &u_cj_vec, &u2)?;

    // Accept iff c1 + c2 == c'
    Ok(proof.c1.clone() + proof.c2.clone() == c_prime)
}
