use super::Params as SAGAParams;
use super::PublicKey as SagaPK;
use super::SAGAPres;
use super::SecretKey as SagaSK;
use super::Signature as SAGASig;
use super::curve::*;
use super::errors::*;
use super::traits::*;

use super::nizk::{
    BlindCred, CredReq, Credential, IssuerPublic, IssuerSecret, Presentation, Proof32,
    PublicParams, ReceiveCredState, VerifierPublic, VerifierSecret, nizk_prove_issue,
    nizk_prove_req, nizk_prove_show, nizk_verify_issue, nizk_verify_req, nizk_verify_show,
};

use cosmian_crypto_core::{
    CsRng,
    bytes_ser_de::{Deserializer, Serializable, Serializer, to_leb128_len},
    reexport::rand_core::{CryptoRngCore, RngCore, SeedableRng},
};
use rayon::prelude::*;
use tiny_keccak::{Hasher, Sha3};
use zeroize::Zeroize;

// ------------------------------------
// Helper: vfcred (wraps saga.verify)
// ------------------------------------
fn vfcred(
    isk: &IssuerSecret,
    pp: &PublicParams,
    saga_pres: &SAGAPres,
    c_j_vec: &[R25519Point],
) -> Result<bool, Error> {
    Ok(super::pres_verify(
        &isk.saga_sk,
        &pp.saga_params,
        saga_pres,
        c_j_vec,
    )?)
}

/// AKVAC.setup(λ, 1^n)
/// Internally sets ℓ = n + 2 for the underlying saga.
pub fn akvac_setup<R: RngCore + CryptoRngCore>(rng: &mut R, n: usize) -> PublicParams {
    let l = n + 2;
    let saga_params = super::saga_setup(rng, l);

    // Sample H as a randomom multiple of G (prime-order group)
    let h = &saga_params.g * &R25519Scalar::random(rng);

    PublicParams {
        g: saga_params.g.clone(),
        h: h,
        saga_params,
    }
}

/// AKVAC.issuerkg()
pub fn issuer_keygen<R: RngCore + CryptoRngCore>(
    rng: &mut R,
    pp: &PublicParams,
) -> (IssuerSecret, IssuerPublic) {
    let (saga_sk, saga_pk) = super::saga_keygen(rng, &pp.saga_params);

    let random_e = R25519Scalar::random(rng);
    let e = &pp.g * &random_e;

    (
        IssuerSecret {
            saga_sk,
            e: random_e.clone(),
        },
        IssuerPublic { saga_pk, e },
    )
}

/// AKVAC.verifierkg(isk, ipk)
/// Builds (X_1..X_n, X_0, Z_0) and requests a saga MAC τ from the issuer.
pub fn verifier_keygen<R: RngCore + CryptoRngCore>(
    rng: &mut R,
    pp: &PublicParams,
    isk: &IssuerSecret,
    ipk: &IssuerPublic,
) -> Result<(VerifierSecret, VerifierPublic), Error> {
    // ℓ = n + 2  ⇒  n = ℓ - 2
    let l = pp.saga_params.g_vec.len();
    assert!(l >= 2, "saga was not set with ℓ = n + 2");
    let n = l - 2;

    // Sample x_0..x_n, ν, x_r
    let mut x_0_to_x_n = Vec::with_capacity(n + 1);
    for _ in 0..=n {
        x_0_to_x_n.push(R25519Scalar::random(rng));
    }
    assert_eq!(x_0_to_x_n.len(), n + 1);
    let v = R25519Scalar::random(rng);

    // Compute X_i = x_i * G for i=1..n
    let mut x_1_to_n = Vec::with_capacity(n);
    for i in 1..=n {
        x_1_to_n.push(&pp.g * &x_0_to_x_n[i]);
    }
    assert_eq!(x_1_to_n.len(), n);

    // Z_0 = ν G
    let z_0 = &pp.g * &v;

    // X_0 = x_0 G + ν E
    // let X_0 = smul(&pp.g, &x_vec[0]) + smul(&ipk.E, &R25519Scalar::from(1u64)); // E already has e folded into it
    // let X_0 = X_0 + smul(&pp.g, &(v * isk.e)); // equivalently: x0*G + ν*(eG) = x0*G + (νe)*G
    let mut x_0 = &pp.g * &x_0_to_x_n[0];
    x_0 += &pp.g * &(v * isk.e.clone()); // equivalently: x0*G + ν*(eG) = x0*G + (νe)*G

    // Assemble messages for saga MAC in the order: (X_1..X_n, X_0, Z_0)
    let mut msgs = x_1_to_n.clone();
    msgs.push(x_0.clone());
    msgs.push(z_0.clone());

    // Ask issuer to MAC (using issuer's saga secret)
    let tau = super::saga_mac(rng, &isk.saga_sk, &pp.saga_params, &msgs, &ipk.saga_pk)?;

    let vsk = VerifierSecret {
        x_0_to_x_n: x_0_to_x_n,
    };
    let vpk = VerifierPublic {
        x_1_to_n: x_1_to_n,
        x_0: x_0,
        z_0: z_0,
        tau: tau,
    };
    Ok((vsk, vpk))
}

/// Client side (verifier) prepares a blinded request.
/// attrs: a_1..a_n in the paper; commitment c_attr = sum a_j X_j + s G
pub fn receive_cred_1<R: RngCore + CryptoRngCore>(
    rng: &mut R,
    pp: &PublicParams,
    ipk: &IssuerPublic,
    vpk: &VerifierPublic,
    attrs: &[R25519Scalar],
) -> Result<(ReceiveCredState, CredReq), Error> {
    // n = ℓ - 2
    let l = pp.saga_params.g_vec.len();
    let n = l - 2;
    if attrs.len() != n {
        return Err(Error::LengthMismatch {
            expected: n,
            got: attrs.len(),
        });
    }

    // Present the issuer MAC τ on (X_1..X_n, X_0, Z_0)
    // messages in the same order as when it was MACed
    let mut msgs = vpk.x_1_to_n.clone();
    msgs.push(vpk.x_0.clone());
    msgs.push(vpk.z_0.clone());

    let saga_pres = super::saga_present(rng, &ipk.saga_pk, &pp.saga_params, &vpk.tau, &msgs)?;

    // Sample s, bar_x0, bar_v and compute the blinding of (X_0, Z_0)
    let s = R25519Scalar::random(rng);
    let bar_x0 = R25519Scalar::random(rng);
    let bar_v = R25519Scalar::random(rng);

    // bar_X0 = X_0 + bar_x0 * G + bar_v * E
    let bar_X0 = vpk.x_0.clone() + &pp.g * &bar_x0 + &ipk.e * &bar_v;
    // bar_Z0 = Z_0 + bar_v * G
    let bar_Z0 = vpk.z_0.clone() + &pp.g * &bar_v;

    // Commitment to attributes: c_attr = sum_j attr_j * X_j + s G
    // let mut c_attr = smul(&pp.g, &s);
    // for (a, Xj) in attrs.iter().zip(vpk.x_1_to_n.iter()) {
    //     c_attr += smul(Xj, a);
    // }
    // Parallel sum of a_j * X_j
    let sum_ax: R25519Point = attrs
        .par_iter()
        .zip(vpk.x_1_to_n.par_iter())
        .map(|(a, xj)| xj * a)
        .reduce(R25519Point::zero, |acc, p| acc + p);

    // c_attr = sG + sum_j a_j X_j
    let c_attr = &pp.g * &s + sum_ax;

    // Build C_j = M_j + ξ_j G_j were returned already in pres.C_j_vec
    // Assemble statement and placeholder proof
    assert_eq!(saga_pres.c_j_vec.len(), n + 2);
    let stmt_cs = saga_pres.c_j_vec.clone();

    // Witness scalars fed into the placeholder hash:
    // include s, bar_x0, bar_v, r, e, xi_1..xi_{n+2}, and (a_j * xi_j) if you like
    let mut witness_scalars = vec![
        s.clone(),
        bar_x0.clone(),
        bar_v.clone(),
        saga_pres.wit_r.clone(),
        saga_pres.wit_e.clone(),
    ];
    witness_scalars.extend_from_slice(&saga_pres.x_i_vec);

    let nizk = nizk_prove_req(
        rng,
        pp,
        ipk,
        &pp.saga_params,
        &saga_pres.saga_pres, // has C_A, T
        &stmt_cs,             // C_1..C_{n+2}
        &bar_X0,
        &bar_Z0,
        &c_attr,
        &s.clone(),
        &attrs,
        &bar_x0.clone(),
        &bar_v.clone(), // note: bar_v is \bar\nu
        &saga_pres.wit_r.clone(),
        &saga_pres.wit_e.clone(),
        &saga_pres.x_i_vec,
    )?;

    let state = ReceiveCredState {
        s: s,
        bar_x0: bar_x0,
        bar_X0: bar_X0.clone(),
        bar_Z0: bar_Z0.clone(),
        attrs: attrs.to_vec(),
    };

    let credreq = CredReq {
        saga_pres: saga_pres.saga_pres,
        c_j_vec: stmt_cs,
        bar_X0,
        bar_Z0,
        c_attr,
        nizk,
    };

    Ok((state, credreq))
}

pub fn issue_cred<R: RngCore + CryptoRngCore>(
    rng: &mut R,
    pp: &PublicParams,
    isk: &IssuerSecret,
    ipk: &IssuerPublic,
    cred_req: &CredReq,
) -> Result<BlindCred, Error> {
    let ok = nizk_verify_req(
        pp,
        ipk,
        &pp.saga_params,
        &cred_req.saga_pres,
        &cred_req.c_j_vec,
        &cred_req.bar_X0,
        &cred_req.bar_Z0,
        &cred_req.c_attr,
        &cred_req.nizk,
    )?;

    if !ok {
        println!("AKVAC request proof does not verify");
        return Err(Error::NonInvertible);
    }

    // Verify the saga presentation (MAC correctness over C_j etc.)
    let verified = vfcred(isk, pp, &cred_req.saga_pres, &cred_req.c_j_vec)?;
    if !verified {
        println!("AKVAC saga presentation does not verify");
        return Err(Error::NonInvertible);
    }

    // u ← Z_p,  ȗ = u G,  V̄ = u((X̄0 − e Z̄0) + c_attr)
    let u = R25519Scalar::random(rng);
    let bar_u = &pp.g * &u;

    // (bar_X0 - e * bar_Z0)
    let x0_part = cred_req.bar_X0.clone() - &cred_req.bar_Z0 * &isk.e;
    let bar_v = &(x0_part + cred_req.c_attr.clone()) * &u;

    let nizk = nizk_prove_issue(
        rng,
        pp,
        &ipk.e,
        &bar_u,
        &bar_v,
        &cred_req.bar_X0,
        &cred_req.bar_Z0,
        &cred_req.c_attr,
        &isk.e,
        &u,
    )?;

    Ok(BlindCred {
        bar_u: bar_u,
        bar_v: bar_v,
        nizk: nizk,
    })
}

pub fn receive_cred_2<R: RngCore + CryptoRngCore>(
    rng: &mut R,
    pp: &PublicParams,
    ipk: &IssuerPublic,
    state: &ReceiveCredState,
    credreq: &CredReq,
    blind: &BlindCred,
) -> Result<Credential, Error> {
    let ok = nizk_verify_issue(
        pp,
        &ipk.e,
        &blind.bar_u,
        &blind.bar_v,
        &credreq.bar_X0,
        &credreq.bar_Z0,
        &credreq.c_attr,
        &blind.nizk,
    )?;
    if !ok {
        println!("AKVAC issue proof does not verify");
        return Err(Error::NonInvertible);
    }

    let gamma = rand_nonzero(rng);

    let u = &blind.bar_u * &gamma;
    let correction = state.s.clone() + state.bar_x0.clone();
    let v_inner = blind.bar_v.clone() - &blind.bar_u * &correction;
    let v = &v_inner * &gamma;

    Ok(Credential {
        u,
        v,
        attrs: state.attrs.clone(),
    })
}

#[inline]
fn rand_nonzero<R: RngCore + CryptoRngCore>(rng: &mut R) -> R25519Scalar {
    loop {
        let s = R25519Scalar::random(rng);
        if !s.is_zero() {
            return s;
        }
    }
}

fn hash_points_scalars_with_ctx(
    points: &[R25519Point],
    scalars: &[R25519Scalar],
    pres_ctx: &[u8],
) -> Result<[u8; 32], Error> {
    let mut hasher = Sha3::v512();
    let mut bytes = [0; 512 / 16];

    for p in points {
        hasher.update(&p.serialize()?);
    }

    for s in scalars {
        hasher.update(&s.serialize()?);
    }

    hasher.update(pres_ctx);
    hasher.finalize(&mut bytes);

    Ok(bytes)
}

/// Prover: include witness scalars and pres_ctx in the digest
fn prove_cmzcpzshow(
    x_1_to_n: &[R25519Point],
    tilde_u: &R25519Point,
    tilde_gamma: &R25519Scalar,
    attrs: &[R25519Scalar],
    gamma_js: &[R25519Scalar],
    pres_ctx: &[u8],
) -> Result<Proof32, Error> {
    let mut points = Vec::with_capacity(x_1_to_n.len() + 1);
    points.extend_from_slice(x_1_to_n);
    points.push(tilde_u.clone());

    // witness order: [tilde_gamma, attrs..., gamma_js...]
    let mut ws: Vec<R25519Scalar> = Vec::with_capacity(1 + attrs.len() + gamma_js.len());
    ws.push(tilde_gamma.clone());
    ws.extend_from_slice(attrs);
    ws.extend_from_slice(gamma_js);

    let digest = hash_points_scalars_with_ctx(&points, &ws, pres_ctx)?;
    Ok(Proof32 { digest })
}

/// Verifier: only statement + ctx (INSECURE placeholder)
fn verify_cmzcpzshow(
    x_1_to_n: &[R25519Point],
    tilde_u: &R25519Point,
    pres_ctx: &[u8],
    proof: &Proof32,
) -> Result<bool, Error> {
    let mut points = Vec::with_capacity(x_1_to_n.len() + 1);
    points.extend_from_slice(x_1_to_n);
    points.push(tilde_u.clone());

    let digest = hash_points_scalars_with_ctx(&points, &[], pres_ctx)?;
    Ok(digest == proof.digest)
}

/// Show credential:
/// - Randomize (U,V) -> (tilde_u, tilde_V)
/// - Sample tilde_gamma, gamma_j in Z_p^*
/// - Compute:
///   Z  = sum_j gamma_j * X_j  - tilde_gamma * H
///   C_V = tilde_V + tilde_gamma * H
///   C_j = attr_j * tilde_u + gamma_j * G
/// - Produce placeholder NIZK bound to (X_1..X_n, tilde_u, pres_ctx)
pub fn show_cred<R: RngCore + CryptoRngCore>(
    rng: &mut R,
    pp: &PublicParams,
    _ipk: &IssuerPublic,
    vpk: &VerifierPublic,
    cred: &Credential,
    pres_ctx: &[u8],
) -> Result<Presentation, Error> {
    // γ, \tildeγ, γ_j ∈ Z_p^*
    let gamma = rand_nonzero(rng);
    let tilde_gamma = rand_nonzero(rng);
    let gamma_j_vec: Vec<R25519Scalar> =
        (0..vpk.x_1_to_n.len()).map(|_| rand_nonzero(rng)).collect();

    // (tilde_u, tilde_V) = (γU, γV)
    let tilde_u = &cred.u * &gamma;
    let tilde_v = &cred.v * &gamma;

    // Z = sum_j γ_j X_j - tildeγ * H
    // let mut Z = R25519Point::zero();
    // for (gamma_j, Xj) in gamma_j_vec.iter().zip(vpk.x_1_to_n.iter()) {
    //     Z += smul(Xj, gamma_j);
    // }
    // Z -= smul(&pp.H, &tilde_gamma);
    // Z = Σ_j γ_j X_j  -  tilde_gamma * H
    let sum_X = vpk
        .x_1_to_n
        .par_iter()
        .zip(gamma_j_vec.par_iter())
        .map(|(xj, gamma_j)| xj * gamma_j)
        .reduce(|| R25519Point::zero(), |a, b| a + b);

    let z = sum_X - &pp.h * &tilde_gamma;

    // C_V = tilde_V + tildeγ * H
    let c_v = tilde_v + &pp.h * &tilde_gamma;

    // C_j = attr_j * tilde_u + γ_j * G
    // let mut C_j_vec = Vec::with_capacity(cred.attrs.len());
    // assert_eq!(cred.attrs.len(), gamma_j_vec.len());
    // for (attr, gamma_j) in cred.attrs.iter().zip(gamma_j_vec.iter()) {
    //     C_j_vec.push(smul(&tilde_u, attr) + smul(&pp.g, gamma_j));
    // }
    // C_j = attr_j * tilde_u + gamma_j * G
    assert_eq!(cred.attrs.len(), gamma_j_vec.len());
    let c_j_vec: Vec<R25519Point> = cred
        .attrs
        .par_iter()
        .zip(gamma_j_vec.par_iter())
        .map(|(attr, gamma_j)| &tilde_u * attr + &pp.g * gamma_j)
        .collect();

    // Placeholder NIZK bound to (X_1..X_n, tilde_u, pres_ctx)
    let nizk = nizk_prove_show(
        rng,
        pp,
        vpk,
        &tilde_u,
        &z,
        &c_j_vec,
        &tilde_gamma,
        &cred.attrs,
        &gamma_j_vec,
        pres_ctx,
    )?;

    Ok(Presentation {
        tilde_u: tilde_u,
        z: z,
        c_v: c_v,
        c_j_vec: c_j_vec,
        nizk: nizk,
    })
}

/// Verify presentation:
/// - Check placeholder cmzcpzshow over (X_1..X_n, tilde_u, pres_ctx)
/// - Check Z == x0*tilde_u + sum_j xj * C_j - C_V
pub fn verify_cred_show(
    pp: &PublicParams,
    vsk: &VerifierSecret,
    vpk: &VerifierPublic,
    pres: &Presentation,
    pres_ctx: &[u8],
) -> Result<bool, Error> {
    let ok = nizk_verify_show(
        pp,
        vpk,
        pres_ctx,
        &pres.tilde_u,
        &pres.z,
        &pres.c_j_vec,
        &pres.nizk,
    )?;
    if !ok {
        println!("AKVAC show proof does not verify");
        return Ok(false);
    }

    // Equation: Z ?= x0 * tilde_u + sum_j xj * C_j - C_V
    let mut rhs = &pres.tilde_u * &vsk.x_0_to_x_n[0];

    // for i in 1..vsk.x_0_to_x_n.len() {
    //     let xj = &vsk.x_0_to_x_n[i];
    //     let Cj = &pres.C_j_vec[i - 1];
    //     rhs += smul(Cj, xj);
    // }

    rhs += (1..vsk.x_0_to_x_n.len())
        .into_par_iter()
        .map(|i| {
            let xj = &vsk.x_0_to_x_n[i];
            let cj = &pres.c_j_vec[i - 1];
            cj * xj
        })
        .reduce(R25519Point::zero, |a, b| a + b);

    rhs -= pres.c_v.clone();

    Ok(pres.z == rhs)
}

#[cfg(test)]
mod akvac_tests {
    use super::*;

    fn random_attrs(rng: &mut impl CryptoRngCore, n: usize) -> Vec<R25519Scalar> {
        (0..n).map(|_| R25519Scalar::random(rng)).collect()
    }

    #[test]
    fn akvac_end_to_end_ok() -> anyhow::Result<()> {
        let mut rng = CsRng::from_entropy();
        let n = 3;

        // Setup
        let pp = akvac_setup(&mut rng, n);
        assert_eq!(pp.saga_params.g_vec.len(), n + 2);

        // Issuer & Verifier keygen
        let (isk, ipk) = issuer_keygen(&mut rng, &pp);
        let (vsk, vpk) = verifier_keygen(&mut rng, &pp, &isk, &ipk)?;
        assert_eq!(vpk.x_1_to_n.len(), n);
        assert!(!vpk.x_0.is_zero());
        assert!(!vpk.z_0.is_zero());

        // Client request (receivecred_1)
        let attrs = random_attrs(&mut rng, n);
        let (state, cred_req) = receive_cred_1(&mut rng, &pp, &ipk, &vpk, &attrs)?;
        assert_eq!(state.attrs.len(), n);
        assert!(!state.bar_X0.is_zero());
        assert!(!state.bar_Z0.is_zero());
        assert_eq!(cred_req.c_j_vec.len(), n + 2);

        // Issuer issues blind credential
        let blind = issue_cred(&mut rng, &pp, &isk, &ipk, &cred_req)?;
        assert!(!blind.bar_u.is_zero());
        assert!(!blind.bar_v.is_zero());

        // Client finalizes
        let cred = receive_cred_2(&mut rng, &pp, &ipk, &state, &cred_req, &blind)?;
        assert!(!cred.u.is_zero());
        assert!(!cred.v.is_zero());
        assert_eq!(cred.attrs, attrs);

        Ok(())
    }

    #[test]
    fn akvac_show_verify_ok() -> anyhow::Result<()> {
        let mut rng = CsRng::from_entropy();
        let n = 3;

        // Setup + issuance (reuse your flow)
        let pp = akvac_setup(&mut rng, n);
        let (isk, ipk) = issuer_keygen(&mut rng, &pp);
        let (vsk, vpk) = verifier_keygen(&mut rng, &pp, &isk, &ipk)?;
        let attrs: Vec<R25519Scalar> = (0..n).map(|_| R25519Scalar::random(&mut rng)).collect();

        let (state, cred_req) = receive_cred_1(&mut rng, &pp, &ipk, &vpk, &attrs)?;
        let blind = issue_cred(&mut rng, &pp, &isk, &ipk, &cred_req)?;
        let cred = receive_cred_2(&mut rng, &pp, &ipk, &state, &cred_req, &blind)?;

        // Show
        let pres_ctx = b"demo-context-123";
        let pres = show_cred(&mut rng, &pp, &ipk, &vpk, &cred, pres_ctx)?;

        // Verify
        let ok = verify_cred_show(&pp, &vsk, &vpk, &pres, pres_ctx)?;
        assert!(ok);
        Ok(())
    }

    #[test]
    fn setup_receive1_issue_cred_receive2_show_cred_verify() -> anyhow::Result<()> {
        let mut rng = CsRng::from_entropy();
        let n = 3;

        let pp = akvac_setup(&mut rng, n);
        assert_eq!(pp.saga_params.g_vec.len(), n + 2);

        let (isk, ipk) = issuer_keygen(&mut rng, &pp);

        let (vsk, vpk) = verifier_keygen(&mut rng, &pp, &isk, &ipk)?;
        // Tuple has n+3 points: X_1..X_n, X_0, Z_0
        assert_eq!(vpk.x_1_to_n.len(), n);

        let attrs: Vec<R25519Scalar> = (0..n).map(|_| R25519Scalar::random(&mut rng)).collect();
        let (state, cred_req) = receive_cred_1(&mut rng, &pp, &ipk, &vpk, &attrs)?;
        assert_eq!(state.attrs.len(), n);
        assert!(!state.bar_X0.is_zero());
        assert!(!state.bar_Z0.is_zero());
        assert_eq!(cred_req.c_j_vec.len(), n + 2);

        let blind = issue_cred(&mut rng, &pp, &isk, &ipk, &cred_req)?;
        assert!(!blind.bar_u.is_zero());
        assert!(!blind.bar_v.is_zero());

        let cred = receive_cred_2(&mut rng, &pp, &ipk, &state, &cred_req, &blind)?;
        assert!(!cred.u.is_zero());
        assert!(!cred.v.is_zero());
        assert_eq!(cred.attrs, attrs);

        let pres_ctx = b"presentation context";
        let pres = show_cred(&mut rng, &pp, &ipk, &vpk, &cred, pres_ctx)?;

        let ok = verify_cred_show(&pp, &vsk, &vpk, &pres, pres_ctx)?;
        assert!(ok);

        Ok(())
    }
}
// #[cfg(test)]
// mod akvac_tests {
//     use ark_ff::Zero;
//     use ark_std::random::{rngs::StdRng, SeedableRng};
//     use ark_std::UniformRand;
//     use crate::mkvak::mkvak::{akvac_setup, Error, issue_cred, issuer_keygen, receive_cred_1, receive_cred_2, show_cred, verifier_keygen, verify_cred_show};
//     use crate::saga::bbs_saga::R25519Scalar;

//     #[test]
//     fn setup_receive1() -> anyhow::Result<()> {
//         let mut rng = StdRng::seed_from_u64(42);
//         let n = 3;

//         let pp = akvac_setup(&mut rng, n);
//         assert_eq!(pp.saga_params.g_vec.len(), n + 2);

//         let (isk, ipk) = issuer_keygen(&mut rng, &pp);

//         let (_vsk, vpk) = verifier_keygen(&mut rng, &pp, &isk, &ipk)?;
//         // Tuple has n+3 points: X_1..X_n, X_0, Z_0
//         assert_eq!(vpk.x_1_to_n.len(), n);

//         let attrs: Vec<R25519Scalar> = (0..n).map(|_| R25519Scalar::random(&mut rng)).collect();
//         let (state, cred_req) = receive_cred_1(&mut rng, &pp, &ipk, &vpk, &attrs)?;
//         assert_eq!(state.attrs.len(), n);
//         assert!(!state.bar_X0.is_zero());
//         assert!(!state.bar_Z0.is_zero());
//         assert_eq!(cred_req.C_j_vec.len(), n + 2);

//         Ok(())
//     }

//     #[test]
//     fn setup_receive1_issue_cred() -> anyhow::Result<()> {
//         let mut rng = StdRng::seed_from_u64(7);
//         let n = 3;

//         let pp = akvac_setup(&mut rng, n);
//         assert_eq!(pp.saga_params.g_vec.len(), n + 2);

//         let (isk, ipk) = issuer_keygen(&mut rng, &pp);

//         let (_vsk, vpk) = verifier_keygen(&mut rng, &pp, &isk, &ipk)?;
//         // Tuple has n+3 points: X_1..X_n, X_0, Z_0
//         assert_eq!(vpk.x_1_to_n.len(), n);

//         let attrs: Vec<R25519Scalar> = (0..n).map(|_| R25519Scalar::random(&mut rng)).collect();
//         let (state, cred_req) = receive_cred_1(&mut rng, &pp, &ipk, &vpk, &attrs)?;
//         assert_eq!(state.attrs.len(), n);
//         assert!(!state.bar_X0.is_zero());
//         assert!(!state.bar_Z0.is_zero());
//         assert_eq!(cred_req.C_j_vec.len(), n + 2);

//         let blind = issue_cred(&mut rng, &pp, &isk, &ipk, &cred_req)?;
//         assert!(!blind.bar_U.is_zero());
//         assert!(!blind.bar_V.is_zero());

//         Ok(())
//     }

//     #[test]
//     fn setup_receive1_issue_cred_receive2() -> anyhow::Result<()> {
//         let mut rng = StdRng::seed_from_u64(7);
//         let n = 3;

//         let pp = akvac_setup(&mut rng, n);
//         assert_eq!(pp.saga_params.g_vec.len(), n + 2);

//         let (isk, ipk) = issuer_keygen(&mut rng, &pp);

//         let (_vsk, vpk) = verifier_keygen(&mut rng, &pp, &isk, &ipk)?;
//         // Tuple has n+3 points: X_1..X_n, X_0, Z_0
//         assert_eq!(vpk.x_1_to_n.len(), n);

//         let attrs: Vec<R25519Scalar> = (0..n).map(|_| R25519Scalar::random(&mut rng)).collect();
//         let (state, cred_req) = receive_cred_1(&mut rng, &pp, &ipk, &vpk, &attrs)?;
//         assert_eq!(state.attrs.len(), n);
//         assert!(!state.bar_X0.is_zero());
//         assert!(!state.bar_Z0.is_zero());
//         assert_eq!(cred_req.C_j_vec.len(), n + 2);

//         let blind = issue_cred(&mut rng, &pp, &isk, &ipk, &cred_req)?;
//         assert!(!blind.bar_U.is_zero());
//         assert!(!blind.bar_V.is_zero());

//         let cred = receive_cred_2(&pp, &ipk, &state, &cred_req, &blind)?;
//         assert!(!cred.U.is_zero());
//         assert!(!cred.V.is_zero());
//         assert_eq!(cred.attrs, attrs);

//         Ok(())
//     }

//     #[test]
//     fn akvac_setup_issuer_verifier_kg() -> anyhow::Result<()> {
//         let mut rng = StdRng::seed_from_u64(7);
//         let n = 3;

//         let pp = akvac_setup(&mut rng, n);
//         assert_eq!(pp.saga_params.g_vec.len(), n + 2);

//         let (isk, ipk) = issuer_keygen(&mut rng, &pp);

//         let (_vsk, vpk) = verifier_keygen(&mut rng, &pp, &isk, &ipk)?;
//         // Tuple has n+2 points: X_1..X_n, X_0, Z_0
//         assert_eq!(vpk.x_1_to_n.len(), n);

//         Ok(())
//     }

//     fn random_attrs(rng: &mut StdRng, n: usize) -> Vec<R25519Scalar> {
//         (0..n).map(|_| R25519Scalar::random(rng)).collect()
//     }

//     #[test]
//     fn receivecred_1_rejects_wrong_attr_len() {
//         let mut rng = StdRng::seed_from_u64(7);
//         let n = 2;

//         let pp = akvac_setup(&mut rng, n);
//         let (isk, ipk) = issuer_keygen(&mut rng, &pp);
//         let (_vsk, vpk) = verifier_keygen(&mut rng, &pp, &isk, &ipk).unwrap();

//         // Wrong length (n-1)
//         let attrs = random_attrs(&mut rng, n - 1);
//         let err = receive_cred_1(&mut rng, &pp, &ipk, &vpk, &attrs).unwrap_err();
//         match err {
//             Error::LengthMismatch { expected, got } => {
//                 assert_eq!(expected, n);
//                 assert_eq!(got, n - 1);
//             }
//             _ => panic!("expected LengthMismatch, got {err:?}"),
//         }
//     }

//     #[test]
//     fn issue_cred_rejects_tampered_cj_vector() -> anyhow::Result<()> {
//         let mut rng = StdRng::seed_from_u64(99);
//         let n = 2;

//         let pp = akvac_setup(&mut rng, n);
//         let (isk, ipk) = issuer_keygen(&mut rng, &pp);
//         let (_vsk, vpk) = verifier_keygen(&mut rng, &pp, &isk, &ipk)?;

//         let attrs = random_attrs(&mut rng, n);
//         let (_state, mut credreq) = receive_cred_1(&mut rng, &pp, &ipk, &vpk, &attrs)?;

//         // Tamper one C_j to break the saga verification
//         credreq.C_j_vec[0] = credreq.C_j_vec[0] + pp.g;

//         // The issuer should reject during vfcred or (earlier) proof check
//         let err = issue_cred(&mut rng, &pp, &isk, &ipk, &credreq).unwrap_err();
//         matches!(err, Error::SAGA(_));
//         Ok(())
//     }

// }
