use std::collections::BTreeMap;

use bech32::{Bech32, Hrp};
use blind_seal_crypto::{
    dkg::PublicKeyset,
    ibe_tpe::{IbeDecryptionShare, IbeTpeCiphertext},
    schnorr::{SchnorrSig, SpendKeypair, XOnlyPubKey},
    tbs::{BlindSignatureShare, BlindedMessage, BlindingFactor, UnblindedSignature},
};
use blind_seal_sdk::sui_backend::SuiFedimintSessionEvent;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::encoding::{
    decode_tlv_stream, decode_varint, encode_tlv_stream, encode_varint, DecodeError,
    DynModuleEnvelope, FedimintDecodable, FedimintEncodable, TlvRecord,
};

/// Upstream Fedimint Bech32 Human-Readable Part (`HRP = "fed1"`), which combined with the
/// Bech32 `'1'` separator produces standard `"fed11..."` `OOBNotes` and `InviteCode` strings!
pub const FEDIMINT_BECH32_HRP: &str = "fed1";
pub const MINT_MODULE_INSTANCE_ID: u16 = 0;
pub const LNV2_MODULE_INSTANCE_ID: u16 = 1;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct FederationId(pub [u8; 32]);

impl FederationId {
    pub fn prefix(&self) -> [u8; 4] {
        [self.0[0], self.0[1], self.0[2], self.0[3]]
    }

    pub fn matches_or_prefix(&self, other: &FederationId) -> bool {
        self == other || (other.0[4..] == [0u8; 28] && self.prefix() == other.prefix())
    }
}

impl std::fmt::Debug for FederationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "FederationId({}..)", hex::encode(&self.0[..6]))
    }
}

impl FedimintEncodable for FederationId {
    fn consensus_encode(&self, out: &mut Vec<u8>) {
        self.0.consensus_encode(out);
    }
}

impl FedimintDecodable for FederationId {
    fn consensus_decode(slice: &mut &[u8]) -> Result<Self, DecodeError> {
        Ok(Self(<[u8; 32]>::consensus_decode(slice)?))
    }
}

/// Optional `iroh` QUIC endpoint descriptor advertised by Virtual Guardians (`fedimint/rpc/0` ALPN).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IrohPeerEndpoint {
    pub peer_id: u16,
    /// 32-byte Ed25519 `NodeId` encoded as 64-char hex (matching `iroh::NodeId`).
    pub node_id_hex: String,
    pub relay_url: String,
    pub alpn: String,
}

/// Downstream Fedimint `InviteCode` encoded as `Vec<InviteCodePart>` TLV + Bech32 `fed11...`.
/// TLV layout matches upstream `fedimint_core::invite_code::InviteCodePart`:
/// - `0`: `Url { url: String, peer: u16 }`
/// - `1`: `FederationId([u8; 32])`
/// - `2`: `ApiSecret(String)`
/// - `3`: `IrohEndpoint { peer: u16, node_id_hex: String, relay_url: String }`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteCode {
    pub federation_id: FederationId,
    pub peers: Vec<(u16, String)>,
    #[serde(default)]
    pub api_secret: Option<String>,
    #[serde(default)]
    pub iroh_endpoints: Vec<IrohPeerEndpoint>,
}

impl FedimintEncodable for InviteCode {
    fn consensus_encode(&self, out: &mut Vec<u8>) {
        let mut records = Vec::new();
        for (peer, url) in &self.peers {
            let mut b = Vec::new();
            url.consensus_encode(&mut b);
            peer.consensus_encode(&mut b);
            records.push(TlvRecord {
                variant: 0,
                bytes: b,
            });
        }
        records.push(TlvRecord {
            variant: 1,
            bytes: self.federation_id.consensus_encode_to_vec(),
        });
        if let Some(sec) = &self.api_secret {
            records.push(TlvRecord {
                variant: 2,
                bytes: sec.consensus_encode_to_vec(),
            });
        }
        for ep in &self.iroh_endpoints {
            let mut b = Vec::new();
            ep.peer_id.consensus_encode(&mut b);
            ep.node_id_hex.consensus_encode(&mut b);
            ep.relay_url.consensus_encode(&mut b);
            records.push(TlvRecord {
                variant: 3,
                bytes: b,
            });
        }
        encode_tlv_stream(&records, out);
    }
}

impl FedimintDecodable for InviteCode {
    fn consensus_decode(slice: &mut &[u8]) -> Result<Self, DecodeError> {
        let records = decode_tlv_stream(slice)?;
        let mut federation_id = None;
        let mut peers = Vec::new();
        let mut api_secret = None;
        let mut iroh_endpoints = Vec::new();

        for rec in records {
            let mut cur = rec.bytes.as_slice();
            match rec.variant {
                0 => {
                    let url = String::consensus_decode(&mut cur)?;
                    let peer = u16::consensus_decode(&mut cur)?;
                    peers.push((peer, url));
                }
                1 => {
                    federation_id = Some(FederationId::consensus_decode(&mut cur)?);
                }
                2 => {
                    api_secret = Some(String::consensus_decode(&mut cur)?);
                }
                3 => {
                    let peer_id = u16::consensus_decode(&mut cur)?;
                    let node_id_hex = String::consensus_decode(&mut cur)?;
                    let relay_url = String::consensus_decode(&mut cur)?;
                    iroh_endpoints.push(IrohPeerEndpoint {
                        peer_id,
                        node_id_hex,
                        relay_url,
                        alpn: "fedimint/rpc/0".into(),
                    });
                }
                // Forward-compatible: ignore unknown future InviteCodePart TLV variants
                _ => {}
            }
        }
        Ok(Self {
            federation_id: federation_id
                .ok_or_else(|| DecodeError("InviteCode missing FederationId TLV".into()))?,
            peers,
            api_secret,
            iroh_endpoints,
        })
    }
}

impl InviteCode {
    /// Encodes the `InviteCode` into a standard Bech32 `"fed11..."` string.
    pub fn encode(&self) -> Result<String, String> {
        let raw = self.consensus_encode_to_vec();
        let hrp = Hrp::parse(FEDIMINT_BECH32_HRP).map_err(|e| e.to_string())?;
        bech32::encode::<Bech32>(hrp, &raw).map_err(|e| e.to_string())
    }

    pub fn decode(s: &str) -> Result<Self, String> {
        let (hrp, raw) = bech32::decode(s.trim()).map_err(|e| format!("invalid InviteCode bech32: {e}"))?;
        if hrp.as_str() != FEDIMINT_BECH32_HRP {
            return Err(format!("unexpected InviteCode HRP {}", hrp.as_str()));
        }
        Self::consensus_decode_whole(&raw).map_err(|e| e.to_string())
    }
}

/// Downstream `ClientConfig` served by Virtual Guardians (`fedimint-mint` + `fedimint-lnv2`,
/// intentionally omitting `fedimint-wallet` L1 descriptors since BTC reserves live on Sui Move).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FedimintClientConfig {
    pub federation_id: FederationId,
    pub federation_name: String,
    pub active_modules: Vec<String>,
    pub mint_tbs_keyset: PublicKeyset,
    pub guardian_ed25519_pks: Vec<[u8; 32]>,
}

impl FedimintClientConfig {
    pub fn compute_federation_id(
        mint_tbs_keyset: &PublicKeyset,
        guardian_ed25519_pks: &[[u8; 32]],
    ) -> FederationId {
        let mut h = Sha256::new();
        h.update(b"SEAL_FEDIMINT_CONFIG_V1");
        h.update(mint_tbs_keyset.keyset_id.as_bytes());
        for pk in &mint_tbs_keyset.slot_agg_pks {
            h.update(pk.as_bytes());
        }
        h.update(&mint_tbs_keyset.ibe_agg_pk_g1);
        for gpk in guardian_ed25519_pks {
            h.update(gpk);
        }
        FederationId(h.finalize().into())
    }
}

/// Downstream Fedimint `SpendableNote` pairing `Nonce` + `tbs::Signature` (48B G1) + `SpendKey` (32B).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpendableNote {
    pub slot: u8,
    pub spend_key_secret: [u8; 32],
    pub nonce: XOnlyPubKey,
    pub signature: UnblindedSignature,
}

impl SpendableNote {
    pub fn amount_msat(&self) -> u64 {
        1u64 << self.slot
    }

    pub fn keypair(&self) -> Result<SpendKeypair, String> {
        SpendKeypair::from_secret_bytes(&self.spend_key_secret).map_err(|e| e.to_string())
    }
}

/// Compact 80-byte binary note body (`signature_g1: [u8; 48] || spend_key: [u8; 32]`)
/// matching upstream `fedimint_mint_common::SpendableNoteUndecoded` (`nonce` is derived from `spend_key`!).
struct WireSpendableNoteBody {
    sig_48: [u8; 48],
    spend_key_32: [u8; 32],
}

impl FedimintEncodable for WireSpendableNoteBody {
    fn consensus_encode(&self, out: &mut Vec<u8>) {
        self.sig_48.consensus_encode(out);
        self.spend_key_32.consensus_encode(out);
    }
}

impl FedimintDecodable for WireSpendableNoteBody {
    fn consensus_decode(slice: &mut &[u8]) -> Result<Self, DecodeError> {
        Ok(Self {
            sig_48: <[u8; 48]>::consensus_decode(slice)?,
            spend_key_32: <[u8; 32]>::consensus_decode(slice)?,
        })
    }
}

/// Standard out-of-band bearer eCash string (`fed11...`) encoded as `Vec<OOBNotesPart>` TLV + Bech32!
/// TLV layout matches upstream `fedimint-mint-client`:
/// - `0` (`Notes`): `TieredMulti<SpendableNote>` (`BTreeMap<u64 /* amount_msat */, Vec<SpendableNote>>`)
/// - `1` (`FederationIdPrefix`): `[u8; 4]`
/// - `2` (`FullFederationId` extension): `[u8; 32]` (ignored by older decoders via `Default` variant, lossless for 32B IDs!)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OOBNotes {
    pub federation_id: FederationId,
    pub notes: Vec<SpendableNote>,
}

impl FedimintEncodable for OOBNotes {
    fn consensus_encode(&self, out: &mut Vec<u8>) {
        // Group notes into `TieredMulti<SpendableNote>` (`BTreeMap<u64, Vec<WireSpendableNoteBody>>`)
        let mut tiered: BTreeMap<u64, Vec<WireSpendableNoteBody>> = BTreeMap::new();
        for n in &self.notes {
            let mut sig_48 = [0u8; 48];
            sig_48.copy_from_slice(n.signature.as_bytes());
            tiered
                .entry(n.amount_msat())
                .or_default()
                .push(WireSpendableNoteBody {
                    sig_48,
                    spend_key_32: n.spend_key_secret,
                });
        }
        let mut notes_bytes = Vec::new();
        encode_varint(tiered.len() as u64, &mut notes_bytes);
        for (amt_msat, tier_vec) in &tiered {
            encode_varint(*amt_msat, &mut notes_bytes);
            encode_varint(tier_vec.len() as u64, &mut notes_bytes);
            for item in tier_vec {
                item.consensus_encode(&mut notes_bytes);
            }
        }

        let records = vec![
            TlvRecord {
                variant: 0,
                bytes: notes_bytes,
            },
            TlvRecord {
                variant: 1,
                bytes: self.federation_id.prefix().to_vec(),
            },
            TlvRecord {
                variant: 2,
                bytes: self.federation_id.0.to_vec(),
            },
        ];
        encode_tlv_stream(&records, out);
    }
}

impl FedimintDecodable for OOBNotes {
    fn consensus_decode(slice: &mut &[u8]) -> Result<Self, DecodeError> {
        let records = decode_tlv_stream(slice)?;
        let mut notes = Vec::new();
        let mut prefix_opt: Option<[u8; 4]> = None;
        let mut full_id_opt: Option<FederationId> = None;

        for rec in records {
            let mut cur = rec.bytes.as_slice();
            match rec.variant {
                0 => {
                    let num_tiers = decode_varint(&mut cur)? as usize;
                    for _ in 0..num_tiers {
                        let amt_msat = decode_varint(&mut cur)?;
                        if !amt_msat.is_power_of_two() {
                            return Err(DecodeError(format!(
                                "non-power-of-two msat tier {amt_msat}"
                            )));
                        }
                        let slot = amt_msat.trailing_zeros() as u8;
                        let count = decode_varint(&mut cur)? as usize;
                        for _ in 0..count {
                            let body = WireSpendableNoteBody::consensus_decode(&mut cur)?;
                            let kp = SpendKeypair::from_secret_bytes(&body.spend_key_32)
                                .map_err(|e| DecodeError(e.to_string()))?;
                            notes.push(SpendableNote {
                                slot,
                                spend_key_secret: body.spend_key_32,
                                nonce: kp.public_key(),
                                signature: UnblindedSignature(body.sig_48.to_vec()),
                            });
                        }
                    }
                }
                1 => {
                    prefix_opt = Some(<[u8; 4]>::consensus_decode(&mut cur)?);
                }
                2 => {
                    full_id_opt = Some(FederationId::consensus_decode(&mut cur)?);
                }
                // Ignore unknown future OOBNotesPart variants per Fedimint TLV spec
                _ => {}
            }
        }

        let federation_id = if let Some(full) = full_id_opt {
            full
        } else if let Some(pref) = prefix_opt {
            let mut padded = [0u8; 32];
            padded[..4].copy_from_slice(&pref);
            FederationId(padded)
        } else {
            return Err(DecodeError("OOBNotes missing FederationIdPrefix TLV".into()));
        };

        Ok(Self {
            federation_id,
            notes,
        })
    }
}

impl OOBNotes {
    pub fn total_msat(&self) -> u64 {
        self.notes.iter().map(SpendableNote::amount_msat).sum()
    }

    /// Encodes `OOBNotes` into a Bech32-checksummed `"fed11..."` string.
    pub fn encode(&self) -> Result<String, String> {
        let raw = self.consensus_encode_to_vec();
        let hrp = Hrp::parse(FEDIMINT_BECH32_HRP).map_err(|e| e.to_string())?;
        bech32::encode::<Bech32>(hrp, &raw).map_err(|e| e.to_string())
    }

    pub fn decode(s: &str) -> Result<Self, String> {
        let (hrp, raw) =
            bech32::decode(s.trim()).map_err(|e| format!("invalid fed11 bech32 OOBNotes: {e}"))?;
        if hrp.as_str() != FEDIMINT_BECH32_HRP {
            return Err(format!("unexpected OOBNotes HRP {}", hrp.as_str()));
        }
        Self::consensus_decode_whole(&raw).map_err(|e| e.to_string())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FedimintMintInput {
    pub slot: u8,
    pub nonce: XOnlyPubKey,
    pub tbs_signature: UnblindedSignature,
}

impl FedimintMintInput {
    pub fn to_dyn_envelope(&self) -> DynModuleEnvelope {
        let mut p = Vec::new();
        encode_varint(0, &mut p); // MintInput::V0 variant = 0
        encode_varint(1u64 << self.slot, &mut p); // amount_msat
        p.extend_from_slice(&self.nonce.0);
        p.extend_from_slice(self.tbs_signature.as_bytes());
        DynModuleEnvelope {
            module_instance_id: MINT_MODULE_INSTANCE_ID,
            payload: p,
        }
    }

    pub fn from_dyn_envelope(env: &DynModuleEnvelope) -> Result<Self, DecodeError> {
        if env.module_instance_id != MINT_MODULE_INSTANCE_ID {
            return Err(DecodeError(format!(
                "expected mint module 0, got {}",
                env.module_instance_id
            )));
        }
        let mut cur = env.payload.as_slice();
        let variant = decode_varint(&mut cur)?;
        if variant != 0 {
            return Err(DecodeError(format!("unsupported MintInput variant {variant}")));
        }
        let amt = decode_varint(&mut cur)?;
        if !amt.is_power_of_two() {
            return Err(DecodeError("MintInput amount not power of two".into()));
        }
        let nonce = XOnlyPubKey(<[u8; 32]>::consensus_decode(&mut cur)?);
        let sig = <[u8; 48]>::consensus_decode(&mut cur)?;
        Ok(Self {
            slot: amt.trailing_zeros() as u8,
            nonce,
            tbs_signature: UnblindedSignature(sig.to_vec()),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FedimintMintOutput {
    pub slot: u8,
    pub blind_nonce: BlindedMessage,
}

impl FedimintMintOutput {
    pub fn to_dyn_envelope(&self) -> DynModuleEnvelope {
        let mut p = Vec::new();
        encode_varint(0, &mut p); // MintOutput::V0 variant = 0
        encode_varint(1u64 << self.slot, &mut p); // amount_msat
        p.extend_from_slice(self.blind_nonce.as_bytes());
        DynModuleEnvelope {
            module_instance_id: MINT_MODULE_INSTANCE_ID,
            payload: p,
        }
    }

    pub fn from_dyn_envelope(env: &DynModuleEnvelope) -> Result<Self, DecodeError> {
        if env.module_instance_id != MINT_MODULE_INSTANCE_ID {
            return Err(DecodeError(format!(
                "expected mint module 0, got {}",
                env.module_instance_id
            )));
        }
        let mut cur = env.payload.as_slice();
        let variant = decode_varint(&mut cur)?;
        if variant != 0 {
            return Err(DecodeError(format!("unsupported MintOutput variant {variant}")));
        }
        let amt = decode_varint(&mut cur)?;
        if !amt.is_power_of_two() {
            return Err(DecodeError("MintOutput amount not power of two".into()));
        }
        let bm = <[u8; 48]>::consensus_decode(&mut cur)?;
        Ok(Self {
            slot: amt.trailing_zeros() as u8,
            blind_nonce: BlindedMessage(bm.to_vec()),
        })
    }
}

/// Downstream Fedimint `Transaction` spending `DynInput`s into `DynOutput`s,
/// authenticated by BIP-340 Schnorr `SpendKey` signatures over `txid()`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FedimintTransaction {
    pub inputs: Vec<FedimintMintInput>,
    pub outputs: Vec<FedimintMintOutput>,
    pub spend_signatures: Vec<SchnorrSig>,
}

impl FedimintEncodable for FedimintTransaction {
    fn consensus_encode(&self, out: &mut Vec<u8>) {
        encode_varint(self.inputs.len() as u64, out);
        for inp in &self.inputs {
            inp.to_dyn_envelope().consensus_encode(out);
        }
        encode_varint(self.outputs.len() as u64, out);
        for outp in &self.outputs {
            outp.to_dyn_envelope().consensus_encode(out);
        }
        // `TransactionSignature::NaiveMultisig(Vec<schnorr::Signature>)` -> variant 0 + Vec<[u8; 64]>
        if self.spend_signatures.is_empty() {
            out.push(0x00); // Option::None
        } else {
            out.push(0x01); // Option::Some
            encode_varint(0, out); // NaiveMultisig variant = 0
            encode_varint(self.spend_signatures.len() as u64, out);
            for sig in &self.spend_signatures {
                out.extend_from_slice(&sig.0);
            }
        }
    }
}

impl FedimintDecodable for FedimintTransaction {
    fn consensus_decode(slice: &mut &[u8]) -> Result<Self, DecodeError> {
        let n_in = decode_varint(slice)? as usize;
        let mut inputs = Vec::with_capacity(n_in);
        for _ in 0..n_in {
            let env = DynModuleEnvelope::consensus_decode(slice)?;
            inputs.push(FedimintMintInput::from_dyn_envelope(&env)?);
        }
        let n_out = decode_varint(slice)? as usize;
        let mut outputs = Vec::with_capacity(n_out);
        for _ in 0..n_out {
            let env = DynModuleEnvelope::consensus_decode(slice)?;
            outputs.push(FedimintMintOutput::from_dyn_envelope(&env)?);
        }
        let has_sigs = u8::consensus_decode(slice)?;
        let mut spend_signatures = Vec::new();
        if has_sigs == 1 {
            let _variant = decode_varint(slice)?;
            let n_sigs = decode_varint(slice)? as usize;
            for _ in 0..n_sigs {
                spend_signatures.push(SchnorrSig(<[u8; 64]>::consensus_decode(slice)?.to_vec()));
            }
        }
        Ok(Self {
            inputs,
            outputs,
            spend_signatures,
        })
    }
}

impl FedimintTransaction {
    /// Canonical `TransactionId`: SHA-256 over the `FedimintEncodable` `inputs` and `outputs`
    /// (excluding witness `signatures`, matching upstream `Transaction::tx_hash()`).
    pub fn txid(&self) -> [u8; 32] {
        let mut body = Vec::new();
        encode_varint(self.inputs.len() as u64, &mut body);
        for inp in &self.inputs {
            inp.to_dyn_envelope().consensus_encode(&mut body);
        }
        encode_varint(self.outputs.len() as u64, &mut body);
        for outp in &self.outputs {
            outp.to_dyn_envelope().consensus_encode(&mut body);
        }
        Sha256::digest(&body).into()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OutPoint {
    pub txid: [u8; 32],
    pub out_idx: u32,
}

impl FedimintEncodable for OutPoint {
    fn consensus_encode(&self, out: &mut Vec<u8>) {
        self.txid.consensus_encode(out);
        (self.out_idx as u64).consensus_encode(out);
    }
}

impl FedimintDecodable for OutPoint {
    fn consensus_decode(slice: &mut &[u8]) -> Result<Self, DecodeError> {
        let txid = <[u8; 32]>::consensus_decode(slice)?;
        let idx = decode_varint(slice)?;
        Ok(Self {
            txid,
            out_idx: idx as u32,
        })
    }
}

/// Guardian-specific output outcome containing ONLY that guardian's `BlindSignatureShare`
/// (matching Fedimint's client-side Lagrange aggregation model!).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MintOutputOutcome {
    pub peer_id: u16,
    pub share: BlindSignatureShare,
}

impl MintOutputOutcome {
    /// Encodes as upstream `SerdeModuleEncoding<DynOutputOutcome>` hex (`module_id = 0`, `MintOutputOutcome::V0(share_48)`).
    pub fn to_serde_module_hex(&self) -> String {
        let mut p = Vec::new();
        encode_varint(0, &mut p); // MintOutputOutcome::V0
        p.extend_from_slice(&self.share.share_g1);
        DynModuleEnvelope {
            module_instance_id: MINT_MODULE_INSTANCE_ID,
            payload: p,
        }
        .consensus_encode_to_hex()
    }

    pub fn from_serde_module_hex(peer_id: u16, hex_str: &str) -> Result<Self, DecodeError> {
        let env = DynModuleEnvelope::consensus_decode_hex(hex_str)?;
        if env.module_instance_id != MINT_MODULE_INSTANCE_ID {
            return Err(DecodeError("unexpected module instance id".into()));
        }
        let mut cur = env.payload.as_slice();
        let variant = decode_varint(&mut cur)?;
        if variant != 0 {
            return Err(DecodeError("unexpected MintOutputOutcome variant".into()));
        }
        let g1 = <[u8; 48]>::consensus_decode(&mut cur)?;
        Ok(Self {
            peer_id,
            share: BlindSignatureShare {
                peer_id,
                share_g1: g1.to_vec(),
            },
        })
    }
}

/// Signed epoch `SessionOutcome` returned by each Virtual Guardian for BIP-39 seed recovery.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedSessionOutcome {
    pub peer_id: u16,
    pub event: SuiFedimintSessionEvent,
    #[serde(with = "serde_bytes")]
    pub guardian_ed25519_sig: Vec<u8>,
}

/// Outgoing `LNv2` Lightning Gateway payment request locked with `BLS12-381` TPE.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Lnv2OutgoingRequest {
    pub inputs: Vec<FedimintMintInput>,
    pub spend_signatures: Vec<SchnorrSig>,
    pub payment_hash: [u8; 32],
    pub tpe_encrypted_preimage: IbeTpeCiphertext,
    pub gateway_claim_pk: XOnlyPubKey,
    pub user_refund_pk: XOnlyPubKey,
    pub expiry_epoch: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Lnv2TpeShareOutcome {
    pub peer_id: u16,
    pub decryption_share: IbeDecryptionShare,
}

/// Deterministic BIP-39 style hierarchical note derivation from a 32-byte wallet master seed.
/// Enables full stateless wallet recovery by scanning `SignedSessionOutcome` blocks!
pub fn derive_deterministic_note_material(
    master_seed: &[u8; 32],
    derivation_idx: u64,
) -> (SpendKeypair, BlindingFactor) {
    let mut sk_hash = Sha256::new();
    sk_hash.update(b"FEDIMINT_BIP39_SPEND_KEY");
    sk_hash.update(master_seed);
    sk_hash.update(derivation_idx.to_be_bytes());
    let mut sk_bytes: [u8; 32] = sk_hash.finalize().into();
    let spend_kp = loop {
        if let Ok(kp) = SpendKeypair::from_secret_bytes(&sk_bytes) {
            break kp;
        }
        sk_bytes[0] = sk_bytes[0].wrapping_add(1);
    };

    let mut bf_hash = Sha256::new();
    bf_hash.update(b"FEDIMINT_BIP39_BLIND_FACTOR");
    bf_hash.update(master_seed);
    bf_hash.update(derivation_idx.to_be_bytes());
    let mut bf_bytes: [u8; 32] = bf_hash.finalize().into();
    // Clear top 2 bits so scalar `< q` on BLS12-381 (~255 bits)
    bf_bytes[0] &= 0x3F;
    if bf_bytes == [0u8; 32] {
        bf_bytes[31] = 1;
    }
    let factor = BlindingFactor::from_be_bytes(&bf_bytes).expect("valid reduced scalar");
    (spend_kp, factor)
}
