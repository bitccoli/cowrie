use blstrs::{pairing, Compress, G1Affine, G1Projective, G2Projective, Gt, Scalar};
use ff::Field;
use group::{prime::PrimeCurveAffine, Curve, Group};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_bytes;
use sha2::{Digest, Sha256};

use crate::tbs::{lagrange_coeff_at_zero, BlindedMessage, PublicKeyG2};
use crate::CryptoError;

pub const IBE_TPE_DST_G2: &[u8] = b"SEAL_IBE_TPE_BLS12381G2_XMD:SHA-256_SSWU_RO_";

/// Ciphertext for Boneh-Franklin IBE / Fedimint `LNv2` Threshold Point Encryption (TPE).
/// Encrypts an arbitrary payload (e.g. a 32-byte Walrus symmetric key or 32-byte Lightning preimage)
/// toward `(namespace, identity)` under `ibe_agg_pk_g1 = ibe_msk * G1`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IbeTpeCiphertext {
    #[serde(with = "serde_bytes")]
    pub namespace: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub identity: Vec<u8>,
    /// `U = r * G1` (48-byte compressed G1).
    #[serde(with = "serde_bytes")]
    pub u_g1: Vec<u8>,
    /// `V = payload XOR expand_key(SHA256(bcs/gt_bytes(e(mpk_g1, H_G2(namespace || identity))^r)))`.
    #[serde(with = "serde_bytes")]
    pub encrypted_payload: Vec<u8>,
}

/// Guardian's partial IBE/TPE decryption subkey `D_i = ibe_msk_i * H_G2(namespace || identity)` in `G2`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IbeDecryptionShare {
    pub peer_id: u16,
    pub subkey_g2: PublicKeyG2,
}

fn hash_identity_to_g2(namespace: &[u8], identity: &[u8]) -> G2Projective {
    let mut buf = Vec::with_capacity(4 + namespace.len() + identity.len());
    buf.extend_from_slice(&(namespace.len() as u32).to_be_bytes());
    buf.extend_from_slice(namespace);
    buf.extend_from_slice(identity);
    G2Projective::hash_to_curve(&buf, IBE_TPE_DST_G2, &[])
}

fn canonical_gt_bytes(gt: &Gt) -> Result<Vec<u8>, CryptoError> {
    let mut buf = Vec::with_capacity(288);
    gt.write_compressed(&mut buf)
        .map_err(|_| CryptoError::InvalidEncoding("failed to compress cyclotomic Gt element"))?;
    Ok(buf)
}

fn derive_xor_stream(canonical_gt: &[u8], out_len: usize) -> Vec<u8> {
    let mut stream = Vec::with_capacity(out_len);
    let mut counter: u32 = 0;
    while stream.len() < out_len {
        let mut hasher = Sha256::new();
        hasher.update(b"BLIND_SEAL_IBE_KDF_V2_CANONICAL_GT");
        hasher.update(counter.to_be_bytes());
        hasher.update(canonical_gt);
        let digest = hasher.finalize();
        let take = (out_len - stream.len()).min(digest.len());
        stream.extend_from_slice(&digest[..take]);
        counter += 1;
    }
    stream
}

/// Client-side Boneh-Franklin / TPE encryption toward `(namespace, identity)`.
pub fn ibe_encrypt(
    ibe_agg_pk_g1: &[u8],
    namespace: &[u8],
    identity: &[u8],
    payload: &[u8],
    mut rng: impl RngCore,
) -> Result<IbeTpeCiphertext, CryptoError> {
    let mpk_g1 = BlindedMessage(ibe_agg_pk_g1.to_vec()).to_g1()?.to_affine();
    let q_id = hash_identity_to_g2(namespace, identity);

    let r = loop {
        let s = Scalar::random(&mut rng);
        if !bool::from(s.is_zero()) {
            break s;
        }
    };

    let u_g1 = (G1Projective::generator() * r)
        .to_affine()
        .to_compressed()
        .to_vec();
    let r_q_id = (q_id * r).to_affine();
    let gid = pairing(&mpk_g1, &r_q_id);
    let gid_bytes = canonical_gt_bytes(&gid)?;
    let mask = derive_xor_stream(&gid_bytes, payload.len());
    let encrypted_payload = payload
        .iter()
        .zip(mask.iter())
        .map(|(a, b)| a ^ b)
        .collect();

    Ok(IbeTpeCiphertext {
        namespace: namespace.to_vec(),
        identity: identity.to_vec(),
        u_g1,
        encrypted_payload,
    })
}

/// Key-server derivation of partial decryption subkey `D_i = ibe_msk_i * H_G2(namespace || identity)`.
pub fn derive_ibe_decryption_share(
    peer_id: u16,
    ibe_secret_share: &Scalar,
    namespace: &[u8],
    identity: &[u8],
) -> Result<IbeDecryptionShare, CryptoError> {
    let q_id = hash_identity_to_g2(namespace, identity);
    let d_i = q_id * ibe_secret_share;
    Ok(IbeDecryptionShare {
        peer_id,
        subkey_g2: PublicKeyG2::from_g2(&d_i)?,
    })
}

/// Verifies a guardian's IBE/TPE decryption share against its `G1` public key share:
/// `e(G1, D_i) == e(PK_i_g1, H_G2(namespace || identity))`.
pub fn verify_ibe_decryption_share(
    peer_pk_g1: &[u8],
    namespace: &[u8],
    identity: &[u8],
    share: &IbeDecryptionShare,
) -> Result<(), CryptoError> {
    let pk_i = BlindedMessage(peer_pk_g1.to_vec()).to_g1()?.to_affine();
    let q_id = hash_identity_to_g2(namespace, identity).to_affine();
    let d_i = share.subkey_g2.to_g2_affine()?;

    if pairing(&G1Affine::generator(), &d_i) == pairing(&pk_i, &q_id) {
        Ok(())
    } else {
        Err(CryptoError::InvalidSignatureShare {
            peer_id: share.peer_id,
        })
    }
}

/// Combines `threshold` decryption shares in `G2` and decrypts the `IbeTpeCiphertext`.
pub fn ibe_combine_and_decrypt(
    ciphertext: &IbeTpeCiphertext,
    shares: &[IbeDecryptionShare],
    threshold: usize,
) -> Result<Vec<u8>, CryptoError> {
    if shares.len() < threshold {
        return Err(CryptoError::InsufficientShares {
            got: shares.len(),
            need: threshold,
        });
    }
    let subset = &shares[..threshold];
    let peer_ids: Vec<u16> = subset.iter().map(|s| s.peer_id).collect();

    let mut d_combined = G2Projective::identity();
    for s in subset {
        let lambda = lagrange_coeff_at_zero(s.peer_id, &peer_ids)?;
        let pt = G2Projective::from(s.subkey_g2.to_g2_affine()?);
        d_combined += pt * lambda;
    }

    let u_affine = BlindedMessage(ciphertext.u_g1.clone()).to_g1()?.to_affine();
    let gid = pairing(&u_affine, &d_combined.to_affine());
    let gid_bytes = canonical_gt_bytes(&gid)?;
    let mask = derive_xor_stream(&gid_bytes, ciphertext.encrypted_payload.len());
    Ok(ciphertext
        .encrypted_payload
        .iter()
        .zip(mask.iter())
        .map(|(a, b)| a ^ b)
        .collect())
}
