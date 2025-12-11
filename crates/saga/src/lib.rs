mod curve;
mod errors;
mod traits;

use cosmian_crypto_core::{
    CsRng,
    bytes_ser_de::{Deserializer, Serializable, Serializer, to_leb128_len},
    reexport::rand_core::{CryptoRngCore, RngCore, SeedableRng},
};
use curve::*;
use errors::Error;
use rayon::prelude::*;
use tiny_keccak::{Hasher, Sha3};
use traits::*;
use zeroize::Zeroize;

const PROT_NAME_MAC: &[u8] = b"AKVAC-BBSsaga-MAC";

/// Parameters from setup. The authority keeps the discrete logs `a_j`.
#[derive(Clone, Debug)]
pub struct Params {
    /// The canonical curve generator G.
    pub g: R25519Point,
    /// pp_saga := G_0
    pub pp_saga: R25519Point,
    /// (G_1, ..., G_l)
    pub g_vec: Vec<R25519Point>,
    /// (td_1, ..., td_l) where G_j = td_j * G and G_0 = td_0 * G
    pub td_vec: Vec<R25519Scalar>,
}

/// Secret key and public key for a user.
#[derive(Clone, Debug)]
pub struct SecretKey {
    pub x: R25519Scalar,
    pub y_vec: Vec<R25519Scalar>, // y_1..y_ell
}

#[derive(Clone, Debug)]
pub struct PublicKey {
    pub x: R25519Point,
    pub y_vec: Vec<R25519Point>, // Y_j = y_j * G_j
}

#[derive(Clone, Debug)]
pub struct Signature {
    pub a: R25519Point,
    pub e: R25519Scalar,
    pub proof: MacProof,
}

/// Output of presentation
#[derive(Clone, Debug)]
pub struct SAGAPres {
    pub c_a: R25519Point,
    pub t: R25519Point,
}

/// Schnorr-style NIZK for BBS-SAGA MAC correctness (Fiat–Shamir)
#[derive(Clone, Debug)]
pub struct MacProof {
    pub c: R25519Scalar,
    // challenge
    pub s_x: R25519Scalar,
    // response for x
    pub s_y_vec: Vec<R25519Scalar>, // responses for y_1..y_l
}

/// Present: randomize with r, xi_j and compute commitments and T.
///
/// Returns:
/// - sagapres = (C_A, T)
/// - C_j with their blinding R25519Scalars xi_j
/// - witness (r, e) to pass to the predicate
#[derive(Clone, Debug)]
pub struct PresentResult {
    pub saga_pres: SAGAPres,
    pub c_j_vec: Vec<R25519Point>,
    pub x_i_vec: Vec<R25519Scalar>,
    pub wit_r: R25519Scalar,
    pub wit_e: R25519Scalar,
}

/// Setup for SAGA scheme. Returns public parameters.
pub fn saga_setup<R: RngCore + CryptoRngCore>(rng: &mut R, l: usize) -> Params {
    let g = R25519Point::generator();

    // G0
    let r = R25519Scalar::random(rng);
    let g_0 = &g * &r;

    // Sample td_1..td_l
    let mut td_vec = Vec::with_capacity(l);
    for _ in 1..=l {
        td_vec.push(R25519Scalar::random(rng));
    }

    // Build G_0 and G_1..G_l
    // let G0 = smul(&G, &td_vec[0]);
    let mut g_vec = Vec::with_capacity(l);
    for j in 0..l {
        g_vec.push(&g * &td_vec[j]);
    }

    Params {
        g: g,
        pp_saga: g_0,
        g_vec: g_vec,
        td_vec: td_vec,
    }
}

/// Keygen: sk=(x,y_1..y_l), pk=(X=xG, Y_j=y_j G_j)
pub fn saga_keygen<R: RngCore + CryptoRngCore>(
    rng: &mut R,
    params: &Params,
) -> (SecretKey, PublicKey) {
    let l = params.g_vec.len();
    let sk_x = R25519Scalar::random(rng);
    let mut sk_y_vec = Vec::with_capacity(l);
    for _ in 1..=l {
        sk_y_vec.push(R25519Scalar::random(rng));
    }

    let pk_x = &params.g * &sk_x;
    let mut pk_y_vec = Vec::with_capacity(l);
    for j in 0..l {
        pk_y_vec.push(&params.g_vec[j] * &sk_y_vec[j]);
    }

    (
        SecretKey {
            x: sk_x,
            y_vec: sk_y_vec,
        },
        PublicKey {
            x: pk_x,
            y_vec: pk_y_vec,
        },
    )
}

fn hash_challenge_mac(
    // statement
    x: &R25519Point,
    y_vec: &[R25519Point],
    e_a_minus_g0: &R25519Point,
    // announcement
    t1: &R25519Point,
    t2_vec: &[R25519Point],
    t3: &R25519Point,
) -> Result<R25519Scalar, Error> {
    let mut hasher = Sha3::v512();
    let mut bytes = [0; 512 / 8];

    hasher.update(PROT_NAME_MAC);

    hasher.update(&x.serialize()?);
    for yj in y_vec {
        hasher.update(&yj.serialize()?);
    }

    hasher.update(&e_a_minus_g0.serialize()?);

    hasher.update(&t1.serialize()?);
    for t2j in t2_vec {
        hasher.update(&t2j.serialize()?);
    }

    hasher.update(&t3.serialize()?);
    hasher.finalize(&mut bytes);

    let s = R25519Scalar::from(&bytes);
    bytes.zeroize();

    Ok(s)
}

/// Prover for \nizkbbssaga:
/// Statement  : (X, (Y_j)_{j=1..l}, eA - G0)
/// Witness    : (x, (y_j)_{j=1..l})
/// Homomorph. : (x,y)->(xG, (y_j G_j),  -xA + Σ y_j M_j)
fn nizk_prove_bbs_saga<R: RngCore + CryptoRngCore>(
    rng: &mut R,
    params: &Params,
    pk: &PublicKey,
    a: &R25519Point,
    e: &R25519Scalar,
    messages: &[R25519Point],
    sk: &SecretKey,
) -> Result<MacProof, Error> {
    let l = params.g_vec.len();
    debug_assert_eq!(messages.len(), l);
    debug_assert_eq!(sk.y_vec.len(), l);
    debug_assert_eq!(pk.y_vec.len(), l);

    // 1) Sample a = (a_x, a_y1..a_yl)
    let a_x = R25519Scalar::random(rng);
    let mut a_y_vec = Vec::with_capacity(l);
    for _ in 0..l {
        a_y_vec.push(R25519Scalar::random(rng));
    }

    // 2) Announcement T = φ(a)
    // T1 = a_x * G
    let t1 = &params.g * &a_x;
    // T2_j = a_yj * G_j
    let mut t2_vec = Vec::with_capacity(l);
    for j in 0..l {
        t2_vec.push(&params.g_vec[j] * &a_y_vec[j]);
    }
    // T3 = - a_x * A + Σ a_yj * M_j
    let mut t3 = -(a * &a_x);
    for j in 0..l {
        t3 += &messages[j] * &a_y_vec[j];
    }

    // Statement: S = (X, Y_vec, eA - G0)
    let mut e_a_minus_g0 = a * e;
    e_a_minus_g0 -= params.pp_saga.clone();

    // 3) c = H(ProtName, statement, announcement)
    let c = hash_challenge_mac(&pk.x, &pk.y_vec, &e_a_minus_g0, &t1, &t2_vec, &t3)?;

    // 4) s = a + c * witness  (entry-wise)
    let s_x = a_x + c.clone() * sk.x.clone();
    let mut s_y_vec = Vec::with_capacity(l);
    for j in 0..l {
        s_y_vec.push(a_y_vec[j].clone() + c.clone() * sk.y_vec[j].clone());
    }

    Ok(MacProof { c, s_x, s_y_vec })
}

/// Sign: A = (x+e)^(-1) * (G_0 + sum_j y_j M_j), plus NIZK over (A,e,M).
pub fn saga_mac<R: RngCore + CryptoRngCore>(
    rng: &mut R,
    sk: &SecretKey,
    params: &Params,
    messages: &[R25519Point],
    pk_saga: &PublicKey, // for NIZK, so that we don't need to recompute it
) -> Result<Signature, Error> {
    let l = params.g_vec.len();
    if messages.len() != l {
        return Err(Error::LengthMismatch {
            expected: l,
            got: messages.len(),
        });
    }
    if sk.y_vec.len() != l {
        return Err(Error::LengthMismatch {
            expected: l,
            got: sk.y_vec.len(),
        });
    }

    // Sample e such that x + e != 0
    let e = loop {
        let e_try = R25519Scalar::random(rng);
        if !(sk.x.clone() + e_try.clone()).is_zero() {
            break e_try;
        }
    };

    // S = G_0 + Σ y_j * M_j
    let mut s = params.pp_saga.clone(); // G_0
    for j in 0..l {
        s += &messages[j] * &sk.y_vec[j];
    }

    // A = (x+e)^(-1) * S
    let inv = (sk.x.clone() + e.clone()).inverse()?; //.ok_or(SAGAError::NonInvertible)?;

    let a = &s * &inv;

    // Build a local pk-view from sk (no secret leakage; all recomputable)
    // TODO: performance opt: pass pk as argument
    // let local_pk = PublicKey {
    //     X: smul(&params.G, &sk.x),
    //     Y_vec: (0..l).map(|j| smul(&params.G_vec[j], &sk.y_vec[j])).collect(),
    // };
    let proof = nizk_prove_bbs_saga(rng, params, &pk_saga, &a, &e, messages, sk)?;

    Ok(Signature { a, e, proof })
}

/// Verifier for \nizkbbssaga
fn nizk_verify_bbs_saga(
    params: &Params,
    pk: &PublicKey,
    a: &R25519Point,
    e: &R25519Scalar,
    messages: &[R25519Point],
    proof: &MacProof,
) -> bool {
    let l = params.g_vec.len();
    if messages.len() != l || pk.y_vec.len() != l || proof.s_y_vec.len() != l {
        println!("Length mismatch in nizk_verify_bbs_saga");
        return false;
    }

    // Statement: S = (X, Y_vec, eA - G0)
    let mut e_a_minus_g0 = a * e;
    e_a_minus_g0 -= params.pp_saga.clone();

    // Recompute accepting announcement  T' = φ(s) - c * S
    // φ(s): (s_x G, (s_yj G_j),  - s_x A + Σ s_yj M_j)
    let t1_s = &params.g * &proof.s_x;
    let mut t2_s_vec = Vec::with_capacity(l);
    for j in 0..l {
        t2_s_vec.push(&params.g_vec[j] * &proof.s_y_vec[j]);
    }

    let mut t3_s = -(a * &proof.s_x);
    for j in 0..l {
        t3_s += &messages[j] * &proof.s_y_vec[j];
    }

    // subtract c*S
    let t1 = t1_s - &pk.x * &proof.c;
    let mut t2_vec = Vec::with_capacity(l);
    for j in 0..l {
        t2_vec.push(t2_s_vec[j].clone() - &pk.y_vec[j] * &proof.c);
    }
    let t3 = t3_s - &e_a_minus_g0 * &proof.c;

    // c' = H(ProtName, statement, T')
    let c_prime = hash_challenge_mac(&pk.x, &pk.y_vec, &e_a_minus_g0, &t1, &t2_vec, &t3).unwrap();
    c_prime == proof.c
}

pub fn saga_present<R: RngCore + CryptoRngCore>(
    rng: &mut R,
    pk: &PublicKey,
    params: &Params,
    tau: &Signature,
    messages: &[R25519Point],
) -> Result<PresentResult, Error> {
    let l = params.g_vec.len();
    if messages.len() != l {
        return Err(Error::LengthMismatch {
            expected: l,
            got: messages.len(),
        });
    }
    if pk.y_vec.len() != l {
        return Err(Error::LengthMismatch {
            expected: l,
            got: pk.y_vec.len(),
        });
    }

    let ok = nizk_verify_bbs_saga(params, pk, &tau.a, &tau.e, messages, &tau.proof);
    if !ok {
        return Err(Error::NonInvertible);
    }

    // r, xi_1..xi_l
    let wit_r = R25519Scalar::random(rng);
    let mut x_i_vec = Vec::with_capacity(l); // ξ
    for _ in 1..=l {
        x_i_vec.push(R25519Scalar::random(rng));
    }

    // C_j = M_j + xi_j * G_j
    // let mut C_j_vec = Vec::with_capacity(l);
    // for j in 0..l {
    //     let cj = messages[j] + smul(&params.G_vec[j], &xi_vec[j]);
    //     C_j_vec.push(cj);
    // }
    let c_j_vec: Vec<R25519Point> = messages
        .par_iter()
        .zip(params.g_vec.par_iter())
        .zip(x_i_vec.par_iter())
        .map(|((msg, g_j), xi)| msg.clone() + g_j * xi)
        .collect();

    // C_A = A + r * G
    let c_a = tau.a.clone() + &params.g * &wit_r;

    // T = rX - e C_A + (e r) G - Σ xi_j Y_j
    // let mut T = smul(&pk.X, &r);         // rX
    // T -= smul(&C_A, &tau.e);                   // - e C_A
    // T += smul(&params.G, &(tau.e * r));        // + e r G
    // for j in 0..l {
    //     T -= smul(&pk.Y_vec[j], &xi_vec[j]);       // - xi_j Y_j
    // }
    // Parallel sum S = sum_j (xi_j * Y_j)
    let sum_yxi: R25519Point = pk
        .y_vec
        .par_iter()
        .zip(x_i_vec.par_iter())
        .map(|(y_j, xij)| y_j * xij)
        .reduce(R25519Point::zero, |a, b| a + b);

    // T = rX - e C_A + e r G - sum_j xi_j Y_j
    let mut t = &pk.x * &wit_r; // rX
    t -= c_a.clone() * &tau.e; // - e C_A
    t += &params.g * &(tau.e.clone() * wit_r.clone()); // + e r G
    t -= sum_yxi; // - Σ xi_j Y_j

    Ok(PresentResult {
        saga_pres: SAGAPres { c_a, t },
        c_j_vec: c_j_vec,
        x_i_vec: x_i_vec,
        wit_r: wit_r,
        wit_e: tau.e.clone(),
    })
}

/// Predicate check (holder side):
/// Verify T == rX - e C_A + e r G - Σ xi_j Y_j
pub fn saga_predicate(
    pk: &PublicKey,
    params: &Params,
    saga_pres: &SAGAPres,
    r: &R25519Scalar,
    e: &R25519Scalar,
    xi_vec: &[R25519Scalar],
) -> Result<bool, Error> {
    let l = pk.y_vec.len();
    if xi_vec.len() != l {
        return Err(Error::LengthMismatch {
            expected: l,
            got: xi_vec.len(),
        });
    }

    let mut rhs = &pk.x * r;
    rhs -= &saga_pres.c_a * e;
    rhs += &params.g * &(e.clone() * r.clone());
    for j in 0..l {
        rhs -= &pk.y_vec[j] * &xi_vec[j];
    }

    Ok(rhs == saga_pres.t)
}

/// Verify (issuer/MAC owner side):
/// Check: x C_A ?= G_0 + Σ y_j C_j + T
pub fn pres_verify(
    sk: &SecretKey,
    params: &Params,
    saga_pres: &SAGAPres,
    c_j_vec: &[R25519Point],
) -> Result<bool, Error> {
    let l = params.g_vec.len();
    if c_j_vec.len() != l || sk.y_vec.len() != l {
        return Err(Error::LengthMismatch {
            expected: l,
            got: c_j_vec.len(),
        });
    }

    let lhs = &saga_pres.c_a * &sk.x; // x C_A

    // RHS = G_0 + Σ y_j C_j + T
    let mut rhs = params.pp_saga.clone();
    for j in 0..l {
        rhs += &c_j_vec[j].clone() * &sk.y_vec[j];
    }
    rhs += saga_pres.t.clone();

    Ok(lhs == rhs)
}

/// Verify MAC (issuer): (x+e) A == G_0 + sum_j y_j M_j
pub fn saga_verify_mac(
    sk: &SecretKey,
    params: &Params,
    tau: &Signature,
    messages: &[R25519Point],
) -> Result<bool, Error> {
    let l = params.g_vec.len();
    if messages.len() != l || sk.y_vec.len() != l {
        return Err(Error::LengthMismatch {
            expected: l,
            got: messages.len(),
        });
    }

    let lhs = &tau.a * &(sk.x.clone() + tau.e.clone());

    let mut rhs = params.pp_saga.clone();
    for j in 0..l {
        rhs += &messages[j] * &sk.y_vec[j];
    }

    Ok(lhs == rhs)
}

#[cfg(test)]
mod bbs_saga_tests {
    use crate::*;
    use ark_std::rand::{SeedableRng, rngs::StdRng};

    #[test]
    fn full_bbs_saga_flow_test() -> anyhow::Result<()> {
        let mut rng = StdRng::seed_from_u64(42);
        let l = 3;

        // 1) Setup
        let params = saga_setup(&mut rng, l);

        // 2) Keygen
        let (sk, pk) = saga_keygen(&mut rng, &params);

        // 3) Messages as points (toy example: hash-free demo using multiples of G)
        let messages: Vec<R25519Point> = (0..l)
            .map(|i| {
                let s = R25519Scalar::from(i as u64);
                &params.g * &s
            })
            .collect();

        // 4) Sign
        let tau = saga_mac(&mut rng, &sk, &params, &messages, &pk)?;

        // 5) Present
        let pres = saga_present(&mut rng, &pk, &params, &tau, &messages)?;

        // 6) Holder predicate check
        let ok_pred = saga_predicate(
            &pk,
            &params,
            &pres.saga_pres,
            &pres.wit_r,
            &pres.wit_e,
            &pres.x_i_vec,
        )?;
        assert!(ok_pred, "predicate failed");

        // 8) Issuer MAC verify on original (A,e,M)
        let ok_mac = saga_verify_mac(&sk, &params, &tau, &messages)?;
        assert!(ok_mac, "MAC check failed");

        println!("All checks passed");
        Ok(())
    }
}
