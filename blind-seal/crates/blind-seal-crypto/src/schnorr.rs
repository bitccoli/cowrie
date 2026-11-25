use k256::schnorr::{
    signature::{Signer, Verifier},
    Signature as Bip340Signature, SigningKey, VerifyingKey,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_bytes;

use crate::CryptoError;

/// BIP-340 `secp256k1` Schnorr keypair used for:
/// 1. Fedimint `SpendKey` -> `Nonce` (preventing mempool front-running via `sui::ecdsa_k1`).
/// 2. Cashu `NUT-11` P2PK locked eCash spending conditions.
#[derive(Clone)]
pub struct SpendKeypair {
    signing_key: SigningKey,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct XOnlyPubKey(pub [u8; 32]);

impl std::fmt::Debug for XOnlyPubKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "XOnlyPubKey({})", hex::encode(self.0))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchnorrSig(#[serde(with = "serde_bytes")] pub Vec<u8>);

impl SpendKeypair {
    pub fn random(mut rng: impl RngCore) -> Self {
        let mut bytes = [0u8; 32];
        loop {
            rng.fill_bytes(&mut bytes);
            if let Ok(signing_key) = SigningKey::from_bytes(&bytes) {
                return Self { signing_key };
            }
        }
    }

    pub fn from_secret_bytes(bytes: &[u8; 32]) -> Result<Self, CryptoError> {
        let signing_key = SigningKey::from_bytes(bytes)
            .map_err(|_| CryptoError::InvalidEncoding("invalid secp256k1 secret key"))?;
        Ok(Self { signing_key })
    }

    pub fn to_secret_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes().into()
    }

    pub fn public_key(&self) -> XOnlyPubKey {
        XOnlyPubKey(self.signing_key.verifying_key().to_bytes().into())
    }

    pub fn sign(&self, message: &[u8]) -> SchnorrSig {
        let sig: Bip340Signature = self.signing_key.sign(message);
        SchnorrSig(sig.to_bytes().to_vec())
    }
}

pub fn verify_bip340_schnorr(
    pubkey: &XOnlyPubKey,
    message: &[u8],
    sig: &SchnorrSig,
) -> Result<(), CryptoError> {
    let vk = VerifyingKey::from_bytes(&pubkey.0)
        .map_err(|_| CryptoError::InvalidEncoding("invalid x-only secp256k1 pubkey"))?;
    let parsed_sig = Bip340Signature::try_from(sig.0.as_slice())
        .map_err(|_| CryptoError::InvalidEncoding("invalid 64-byte Schnorr signature"))?;
    vk.verify(message, &parsed_sig)
        .map_err(|_| CryptoError::SchnorrVerificationFailed)
}
