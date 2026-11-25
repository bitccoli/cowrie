use std::collections::BTreeMap;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use blind_seal_crypto::tbs::{BlindingFactor, PublicKeyG2};
use serde::{Deserialize, Serialize};
use serde_bytes;
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const CASHU_V4_PREFIX: &str = "cashuB";

// Standard Cashu `NUT-00` protocol error codes
pub const ERR_TOKEN_ALREADY_SPENT: u32 = 11001;
pub const ERR_TX_NOT_BALANCED: u32 = 11002;
pub const ERR_WITNESS_OR_SIG_INVALID: u32 = 11005;
pub const ERR_KEYSET_UNKNOWN: u32 = 12001;
pub const ERR_QUOTE_NOT_PAID: u32 = 20001;
pub const ERR_QUOTE_ALREADY_ISSUED: u32 = 20002;
pub const ERR_LIGHTNING_OR_BACKEND: u32 = 20000;

/// Standard Cashu `NUT-00` error payload (`{ "detail": "...", "code": 11001 }`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CashuErrorResponse {
    pub detail: String,
    pub code: u32,
}

/// Derives a deterministic 16-character hex `NUT-02` keyset ID:
/// `<1-byte version prefix><first 7 bytes of SHA256(sorted (amount_u64_be || pubkey_bytes))>`.
/// Version `0x02` denotes `BLS12-381` threshold keysets (distinguishing from `0x00`/`0x01` secp256k1).
pub fn derive_nut02_keyset_id(version_byte: u8, slot_agg_pks: &[PublicKeyG2]) -> String {
    let mut hasher = Sha256::new();
    for (slot, pk) in slot_agg_pks.iter().enumerate() {
        let amount: u64 = 1u64 << slot;
        hasher.update(amount.to_be_bytes());
        hasher.update(pk.as_bytes());
    }
    let digest = hasher.finalize();
    let mut id_bytes = [0u8; 8];
    id_bytes[0] = version_byte;
    id_bytes[1..8].copy_from_slice(&digest[..7]);
    hex::encode(id_bytes)
}

/// `NUT-01` Keyset public keys (`amount -> hex(96-byte BLS12-381 G2 pubkey)`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Nut01KeysetKeys {
    pub id: String,
    pub unit: String,
    pub keys: BTreeMap<u64, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Nut01KeysResponse {
    pub keysets: Vec<Nut01KeysetKeys>,
}

/// `NUT-02` Keyset descriptor.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Nut02KeysetDescriptor {
    pub id: String,
    pub unit: String,
    pub active: bool,
    pub input_fee_ppk: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Nut02KeysetsResponse {
    pub keysets: Vec<Nut02KeysetDescriptor>,
}

/// `NUT-00` BlindedMessage (`B_`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CashuBlindedMessage {
    pub amount: u64,
    pub id: String,
    #[serde(rename = "B_")]
    pub b_hex: String,
}

/// `NUT-00` BlindSignature (`C_`) — aggregated server-side from $t$-of-$n$ Blind-Seal shares.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CashuBlindSignature {
    pub amount: u64,
    pub id: String,
    #[serde(rename = "C_")]
    pub c_hex: String,
}

/// Standard `NUT-11` / `NUT-14` JSON witness payload serialized inside `CashuProof.witness`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Nut10WitnessPayload {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signatures: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preimage: Option<String>,
}

/// `NUT-00` unblinded spendable bearer proof (standard JSON representation).
/// Per `NUT-10`/`11`/`14`, `witness` is a serialized JSON string (`{"signatures":["..."]}`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CashuProof {
    pub amount: u64,
    pub id: String,
    pub secret: String,
    #[serde(rename = "C")]
    pub c_hex: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub witness: Option<String>,
}

/// Compact binary proof inside a `NUT-00` V4 CBOR token (`t[].p[]`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct V4CompactProof {
    #[serde(rename = "a")]
    pub amount: u64,
    #[serde(rename = "s")]
    pub secret: String,
    #[serde(rename = "c", with = "serde_bytes")]
    pub c_bytes: Vec<u8>,
    #[serde(rename = "w", default, skip_serializing_if = "Option::is_none")]
    pub witness: Option<String>,
}

/// Keyset-grouped proof bucket inside a `NUT-00` V4 CBOR token (`t[]`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct V4KeysetProofGroup {
    #[serde(rename = "i", with = "serde_bytes")]
    pub keyset_id_bytes: Vec<u8>,
    #[serde(rename = "p")]
    pub proofs: Vec<V4CompactProof>,
}

/// Official `NUT-00` V4 Binary CBOR Token (`cashuB...`) grouping raw binary signatures by
/// binary keyset ID (`i: bytes`) alongside explicit `unit` (`u`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CashuTokenV4 {
    #[serde(rename = "m")]
    pub mint_url: String,
    #[serde(rename = "u")]
    pub unit: String,
    #[serde(rename = "t")]
    pub token_groups: Vec<V4KeysetProofGroup>,
    #[serde(rename = "d", default, skip_serializing_if = "Option::is_none")]
    pub memo: Option<String>,
}

impl CashuTokenV4 {
    /// Packs standard JSON `CashuProof`s into compact `NUT-00` V4 binary CBOR groups.
    pub fn from_proofs(
        mint_url: impl Into<String>,
        unit: impl Into<String>,
        proofs: &[CashuProof],
        memo: Option<String>,
    ) -> Result<Self, String> {
        let mut grouped: BTreeMap<Vec<u8>, Vec<V4CompactProof>> = BTreeMap::new();
        for p in proofs {
            let ks_bytes =
                hex::decode(&p.id).map_err(|_| format!("keyset id '{}' must be hex", p.id))?;
            let sig_bytes =
                hex::decode(&p.c_hex).map_err(|_| "proof C must be valid hex".to_string())?;
            grouped
                .entry(ks_bytes)
                .or_default()
                .push(V4CompactProof {
                    amount: p.amount,
                    secret: p.secret.clone(),
                    c_bytes: sig_bytes,
                    witness: p.witness.clone(),
                });
        }
        let token_groups = grouped
            .into_iter()
            .map(|(keyset_id_bytes, proofs)| V4KeysetProofGroup {
                keyset_id_bytes,
                proofs,
            })
            .collect();

        Ok(Self {
            mint_url: mint_url.into(),
            unit: unit.into(),
            token_groups,
            memo,
        })
    }

    pub fn to_proofs(&self) -> Vec<CashuProof> {
        let mut out = Vec::new();
        for grp in &self.token_groups {
            let id = hex::encode(&grp.keyset_id_bytes);
            for p in &grp.proofs {
                out.push(CashuProof {
                    amount: p.amount,
                    id: id.clone(),
                    secret: p.secret.clone(),
                    c_hex: hex::encode(&p.c_bytes),
                    witness: p.witness.clone(),
                });
            }
        }
        out
    }

    pub fn encode(&self) -> Result<String, String> {
        let cbor = serde_cbor::to_vec(self).map_err(|e| e.to_string())?;
        Ok(format!("{CASHU_V4_PREFIX}{}", URL_SAFE_NO_PAD.encode(cbor)))
    }

    pub fn decode(token_str: &str) -> Result<Self, String> {
        let b64 = token_str
            .strip_prefix(CASHU_V4_PREFIX)
            .ok_or_else(|| "missing cashuB prefix".to_string())?;
        let raw = URL_SAFE_NO_PAD
            .decode(b64)
            .map_err(|e| format!("invalid base64url: {e}"))?;
        serde_cbor::from_slice(&raw).map_err(|e| format!("invalid V4 CBOR token: {e}"))
    }

    pub fn total_amount(&self) -> u64 {
        self.token_groups
            .iter()
            .flat_map(|g| g.proofs.iter())
            .map(|p| p.amount)
            .sum()
    }
}

/// `NUT-10` well-known spending condition parsed from a JSON-array `secret` string:
/// `["P2PK", { "nonce": "...", "data": "<hex>", "tags": [["sigflag", "SIG_ALL"]] }]`
/// or `["HTLC", { "nonce": "...", "data": "<sha256_hex>", "tags": [...] }]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Nut10Condition {
    PlainSecret,
    P2pk {
        xonly_pubkey: [u8; 32],
        sig_all: bool,
    },
    Htlc {
        expected_sha256: [u8; 32],
        sig_all: bool,
    },
}

#[derive(Deserialize)]
struct Nut10SecretBody {
    data: String,
    #[serde(default)]
    tags: Vec<Vec<String>>,
}

impl Nut10Condition {
    pub fn parse(secret: &str) -> Result<Self, String> {
        let trimmed = secret.trim_start();
        if !trimmed.starts_with('[') {
            return Ok(Self::PlainSecret);
        }
        let Ok(arr) = serde_json::from_str::<Vec<Value>>(trimmed) else {
            return Ok(Self::PlainSecret);
        };
        if arr.len() != 2 {
            return Ok(Self::PlainSecret);
        }
        let Some(kind) = arr[0].as_str() else {
            return Ok(Self::PlainSecret);
        };
        let body: Nut10SecretBody =
            serde_json::from_value(arr[1].clone()).map_err(|e| format!("bad NUT-10 body: {e}"))?;

        let sig_all = body.tags.iter().any(|tag| {
            tag.len() >= 2
                && tag[0].eq_ignore_ascii_case("sigflag")
                && tag[1].eq_ignore_ascii_case("SIG_ALL")
        });

        match kind {
            "P2PK" => {
                let raw_pk =
                    hex::decode(&body.data).map_err(|_| "invalid P2PK pubkey hex".to_string())?;
                // Accept both 32-byte x-only pubkeys and 33-byte `02`/`03` compressed pubkeys (`NUT-11`)!
                let xonly: [u8; 32] = match raw_pk.len() {
                    32 => raw_pk.try_into().unwrap(),
                    33 if raw_pk[0] == 0x02 || raw_pk[0] == 0x03 => {
                        raw_pk[1..33].try_into().unwrap()
                    }
                    _ => return Err("NUT-11 P2PK data must be 32 or 33 bytes".into()),
                };
                Ok(Self::P2pk {
                    xonly_pubkey: xonly,
                    sig_all,
                })
            }
            "HTLC" => {
                let raw_hash =
                    hex::decode(&body.data).map_err(|_| "invalid HTLC hash hex".to_string())?;
                let expected_sha256: [u8; 32] = raw_hash
                    .try_into()
                    .map_err(|_| "NUT-14 HTLC hash must be 32 bytes".to_string())?;
                Ok(Self::Htlc {
                    expected_sha256,
                    sig_all,
                })
            }
            _ => Ok(Self::PlainSecret),
        }
    }

    /// Helper to build a standard `NUT-10`/`11` JSON secret string (`["P2PK", {...}]`).
    pub fn format_p2pk_secret(nonce: &str, xonly_pk: &[u8; 32], sig_all: bool) -> String {
        let tags = if sig_all {
            serde_json::json!([["sigflag", "SIG_ALL"]])
        } else {
            serde_json::json!([])
        };
        serde_json::json!(["P2PK", {
            "nonce": nonce,
            "data": format!("02{}", hex::encode(xonly_pk)),
            "tags": tags
        }])
        .to_string()
    }

    /// Helper to build a standard `NUT-10`/`14` JSON secret string (`["HTLC", {...}]`).
    pub fn format_htlc_secret(nonce: &str, sha256_hash: &[u8; 32]) -> String {
        serde_json::json!(["HTLC", {
            "nonce": nonce,
            "data": hex::encode(sha256_hash),
            "tags": []
        }])
        .to_string()
    }
}

/// Computes the canonical `NUT-11` `SIG_INPUTS` message (`SHA256(secret)`).
pub fn nut11_sig_inputs_digest(secret: &str) -> [u8; 32] {
    Sha256::digest(secret.as_bytes()).into()
}

/// Computes the canonical `NUT-11` `SIG_ALL` digest over EVERY input `(secret, C)` and
/// EVERY output `(amount, B_)` in a `/v1/swap` request—preventing partial output substitution!
pub fn nut11_sig_all_swap_digest(
    inputs: &[CashuProof],
    outputs: &[CashuBlindedMessage],
) -> [u8; 32] {
    let mut h = Sha256::new();
    for inp in inputs {
        h.update(inp.secret.as_bytes());
        h.update(inp.c_hex.to_lowercase().as_bytes());
    }
    for out in outputs {
        h.update(out.amount.to_string().as_bytes());
        h.update(out.b_hex.to_lowercase().as_bytes());
    }
    h.finalize().into()
}

/// Computes the canonical `NUT-11` `SIG_ALL` digest for a `/v1/melt` request (`inputs || quote_id`).
pub fn nut11_sig_all_melt_digest(inputs: &[CashuProof], quote_or_dest: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    for inp in inputs {
        h.update(inp.secret.as_bytes());
        h.update(inp.c_hex.to_lowercase().as_bytes());
    }
    h.update(quote_or_dest.as_bytes());
    h.finalize().into()
}

// ============================================================================
// Standard Two-Step Quote & Operation Models (`NUT-03`, `04`, `05`, `07`, `09`, `23`)
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MintQuoteState {
    UNPAID,
    PAID,
    ISSUED,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Nut04MintQuoteRequest {
    pub amount: u64,
    pub unit: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Nut04MintQuoteResponse {
    pub quote: String,
    /// `BOLT11` invoice (`lnbc...`) for `bolt11`, or Sui deposit intent string for `sui`.
    pub request: String,
    pub amount: u64,
    pub unit: String,
    pub state: MintQuoteState,
    pub expiry: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Nut04MintExecuteRequest {
    pub quote: String,
    pub outputs: Vec<CashuBlindedMessage>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NutSignaturesResponse {
    pub signatures: Vec<CashuBlindSignature>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Nut03SwapRequest {
    pub inputs: Vec<CashuProof>,
    pub outputs: Vec<CashuBlindedMessage>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MeltQuoteState {
    UNPAID,
    PENDING,
    PAID,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Nut05MeltQuoteRequest {
    /// `BOLT11` invoice for `bolt11`, or destination Sui address for `sui`.
    pub request: String,
    pub unit: String,
    /// Optional explicit amount for `sui` or amountless invoices.
    #[serde(default)]
    pub amount: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Nut05MeltQuoteResponse {
    pub quote: String,
    pub amount: u64,
    pub fee_reserve: u64,
    pub unit: String,
    pub state: MeltQuoteState,
    pub expiry: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payment_preimage: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change: Option<Vec<CashuBlindSignature>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Nut05MeltExecuteRequest {
    pub quote: String,
    pub inputs: Vec<CashuProof>,
    #[serde(default)]
    pub outputs: Vec<CashuBlindedMessage>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofStateFlag {
    UNSPENT,
    PENDING,
    SPENT,
}

/// Official `NUT-07` `/v1/checkstate` request taking curve points `Ys` (`hex(48-byte G1)`),
/// NEVER exposing unspent plaintext `secret`s to the mint!
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Nut07CheckStateRequest {
    #[serde(rename = "Ys")]
    pub ys: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Nut07StateEntry {
    #[serde(rename = "Y")]
    pub y: String,
    pub state: ProofStateFlag,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub witness: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Nut07CheckStateResponse {
    pub states: Vec<Nut07StateEntry>,
}

/// Official `NUT-09` `/v1/restore` request & response for recovering dropped signatures!
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Nut09RestoreRequest {
    pub outputs: Vec<CashuBlindedMessage>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Nut09RestoreResponse {
    pub outputs: Vec<CashuBlindedMessage>,
    pub signatures: Vec<CashuBlindSignature>,
}

pub fn amount_to_power_of_two_slot(amount: u64) -> Result<u8, String> {
    if amount == 0 || !amount.is_power_of_two() {
        return Err(format!("Cashu amount {amount} must be a power of 2"));
    }
    Ok(amount.trailing_zeros() as u8)
}

/// `NUT-13` Deterministic Secret & `BLS12-381` Blinding Factor Derivation:
/// Derives `(secret_hex_64, BlindingFactor)` deterministically from `(seed, keyset_id, counter)`
/// so wiped wallets can recover 100% of unspent eCash via `POST /v1/restore` (`NUT-09`) + `POST /v1/checkstate` (`NUT-07`)!
pub fn derive_nut13_deterministic_output(
    master_seed: &str,
    keyset_id: &str,
    counter: u64,
) -> (String, BlindingFactor) {
    let mut s_hash = Sha256::new();
    s_hash.update(b"NUT13_COWRIE_SECRET_V1|");
    s_hash.update(master_seed.trim().as_bytes());
    s_hash.update(b"|");
    s_hash.update(keyset_id.as_bytes());
    s_hash.update(b"|");
    s_hash.update(counter.to_string().as_bytes());
    let secret_hex = hex::encode(s_hash.finalize());

    let mut r_hash = Sha256::new();
    r_hash.update(b"NUT13_COWRIE_BLIND_FACTOR_V1|");
    r_hash.update(master_seed.trim().as_bytes());
    r_hash.update(b"|");
    r_hash.update(keyset_id.as_bytes());
    r_hash.update(b"|");
    r_hash.update(counter.to_string().as_bytes());
    let mut r_bytes: [u8; 32] = r_hash.finalize().into();
    // Clear top 2 bits so big-endian 254-bit scalar is strictly `< q` on BLS12-381
    r_bytes[0] &= 0x3F;
    if r_bytes == [0u8; 32] {
        r_bytes[31] = 1;
    }
    let factor = BlindingFactor::from_be_bytes(&r_bytes).expect("valid reduced BLS12-381 scalar");
    (secret_hex, factor)
}
