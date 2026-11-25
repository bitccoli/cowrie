use blind_seal_crypto::{
    dkg::PublicKeyset,
    elgamal::{EncryptedG1Share, EphemeralElGamalPublicKey},
    ibe_tpe::IbeDecryptionShare,
    tbs::{BlindSignatureShare, BlindedMessage},
};
use serde::{Deserialize, Serialize};
use serde_bytes;

/// On-chain `BlindSigningTicket` representation committed inside a finalized Sui checkpoint.
/// Storing `slots` and `blinded_messages` immutably on-chain eliminates Trap 3 (`dry_run` replay).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlindTicketOnChain {
    pub ticket_id: [u8; 32],
    pub keyset_id: String,
    pub slots: Vec<u8>,
    pub blinded_messages: Vec<BlindedMessage>,
    pub finalized_checkpoint: u64,
}

/// On-chain authorization record for standard Seal IBE / Walrus passes / Fedimint `LNv2` TPE.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IbeApprovalOnChain {
    pub approval_id: [u8; 32],
    pub keyset_id: String,
    #[serde(with = "serde_bytes")]
    pub namespace: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub identity: Vec<u8>,
    pub finalized_checkpoint: u64,
}

/// Request sent to `POST /v1/fetch_blind_sig` on each Blind-Seal Key Server.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FetchBlindSigRequest {
    pub keyset_id: String,
    pub ticket_id_hex: String,
    /// Optional raw Sui Programmable Transaction Block bytes calling `seal_approve_blind_sign*`
    /// for `sui_dryRunTransactionBlock` policy verification on live Sui full nodes.
    pub seal_approve_ptb_b64: Option<String>,
    /// Optional client ephemeral ElGamal `G1` public key to encrypt signature shares in transit.
    pub ephemeral_elgamal_pk: Option<EphemeralElGamalPublicKey>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SharePayload {
    Plain(Vec<BlindSignatureShare>),
    Encrypted(Vec<EncryptedG1Share>),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FetchBlindSigResponse {
    pub peer_id: u16,
    pub ticket_id_hex: String,
    pub shares: SharePayload,
}

/// Request sent to `POST /v1/fetch_key` for Boneh-Franklin IBE / Walrus / Fedimint `LNv2` TPE.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FetchIbeKeyRequest {
    pub keyset_id: String,
    pub approval_id_hex: String,
    pub seal_approve_ptb_b64: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FetchIbeKeyResponse {
    pub share: IbeDecryptionShare,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeysetsResponse {
    pub peer_id: u16,
    pub keysets: Vec<PublicKeyset>,
}
