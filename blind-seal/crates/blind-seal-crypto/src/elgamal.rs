use blstrs::{G1Projective, Scalar};
use ff::Field;
use group::{Curve, Group};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_bytes;

use crate::tbs::BlindedMessage;
use crate::CryptoError;

/// Ephemeral client ElGamal keypair over `G1` matching Mysten Labs' Seal `/v1/fetch_key`
/// encrypted-in-transit share delivery (`(C1, C2) = (k * G1, share_pt + k * epk)`).
#[derive(Clone)]
pub struct EphemeralElGamalSecretKey(pub Scalar);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EphemeralElGamalPublicKey(#[serde(with = "serde_bytes")] pub Vec<u8>);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedG1Share {
    pub peer_id: u16,
    #[serde(with = "serde_bytes")]
    pub c1_g1: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub c2_g1: Vec<u8>,
}

impl EphemeralElGamalSecretKey {
    pub fn generate(mut rng: impl RngCore) -> (Self, EphemeralElGamalPublicKey) {
        let sk = loop {
            let s = Scalar::random(&mut rng);
            if !bool::from(s.is_zero()) {
                break s;
            }
        };
        let pk = (G1Projective::generator() * sk)
            .to_affine()
            .to_compressed()
            .to_vec();
        (Self(sk), EphemeralElGamalPublicKey(pk))
    }

    pub fn decrypt_g1(&self, enc: &EncryptedG1Share) -> Result<Vec<u8>, CryptoError> {
        let c1 = BlindedMessage(enc.c1_g1.clone()).to_g1()?;
        let c2 = BlindedMessage(enc.c2_g1.clone()).to_g1()?;
        let pt = c2 - (c1 * self.0);
        Ok(BlindedMessage::from_g1(&pt)?.0)
    }
}

pub fn encrypt_g1_share(
    peer_id: u16,
    share_g1_bytes: &[u8],
    epk: &EphemeralElGamalPublicKey,
    mut rng: impl RngCore,
) -> Result<EncryptedG1Share, CryptoError> {
    let share_pt = BlindedMessage(share_g1_bytes.to_vec()).to_g1()?;
    let epk_pt = BlindedMessage(epk.0.clone()).to_g1()?;
    let k = loop {
        let s = Scalar::random(&mut rng);
        if !bool::from(s.is_zero()) {
            break s;
        }
    };
    let c1 = (G1Projective::generator() * k)
        .to_affine()
        .to_compressed()
        .to_vec();
    let c2 = (share_pt + epk_pt * k)
        .to_affine()
        .to_compressed()
        .to_vec();
    Ok(EncryptedG1Share {
        peer_id,
        c1_g1: c1,
        c2_g1: c2,
    })
}
