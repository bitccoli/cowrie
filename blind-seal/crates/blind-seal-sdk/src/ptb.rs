//! Canonical Sui Programmable Transaction Block (PTB) BCS builder, `Blake2b-256` intent signer,
//! `suiprivkey1...` Bech32 key parser, and Move call constructors for `blind_seal` & `cowrie_cashu`.

use base64::{engine::general_purpose::STANDARD as B64_STD, Engine};
use bech32::{Bech32, Hrp};
use blake2::{
    digest::{consts::U32, Digest as BlakeDigest},
    Blake2b,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::SdkError;

type Blake2b256 = Blake2b<U32>;

pub const SUI_ED25519_FLAG: u8 = 0x00;
pub const SUI_CLOCK_OBJECT_ID: SuiAddress = {
    let mut b = [0u8; 32];
    b[31] = 0x06;
    SuiAddress(b)
};

/// 32-byte Sui address or object ID (`%x00..%xFF * 32` in BCS without length prefix).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize)]
pub struct SuiAddress(pub [u8; 32]);

impl std::fmt::Debug for SuiAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl std::fmt::Display for SuiAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl SuiAddress {
    pub fn from_hex(s: &str) -> Result<Self, SdkError> {
        let stripped = s.trim().strip_prefix("0x").unwrap_or(s.trim());
        if stripped.is_empty() || stripped.len() > 64 {
            return Err(SdkError::Rpc(format!("invalid Sui hex address: {s}")));
        }
        let padded = format!("{stripped:0>64}");
        let raw = hex::decode(padded).map_err(|e| SdkError::Rpc(format!("hex error: {e}")))?;
        let mut out = [0u8; 32];
        out.copy_from_slice(&raw);
        Ok(Self(out))
    }

    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.0))
    }
}

/// 32-byte Sui `ObjectDigest` / `TransactionDigest`.
/// Per Sui BCS ABNF (`digest = %x20 32OCTET`), serialized with a `0x20` length prefix via `serde_bytes`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct SuiDigest(pub [u8; 32]);

impl std::fmt::Debug for SuiDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_base58())
    }
}

impl Serialize for SuiDigest {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serde_bytes::serialize(&self.0[..], serializer)
    }
}

impl<'de> Deserialize<'de> for SuiDigest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let v: Vec<u8> = serde_bytes::deserialize(deserializer)?;
        let arr: [u8; 32] = v
            .try_into()
            .map_err(|_| serde::de::Error::custom("SuiDigest must be 32 bytes"))?;
        Ok(Self(arr))
    }
}

impl SuiDigest {
    pub fn from_base58(s: &str) -> Result<Self, SdkError> {
        let raw = bs58::decode(s.trim())
            .into_vec()
            .map_err(|e| SdkError::Rpc(format!("invalid base58 digest {s}: {e}")))?;
        let arr: [u8; 32] = raw
            .try_into()
            .map_err(|_| SdkError::Rpc(format!("base58 digest {s} is not 32 bytes")))?;
        Ok(Self(arr))
    }

    pub fn to_base58(&self) -> String {
        bs58::encode(self.0).into_string()
    }
}

/// Owned or immutable Sui object reference `(object_id, version, digest)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuiObjectRef {
    pub object_id: SuiAddress,
    pub version: u64,
    pub digest: SuiDigest,
}

/// Shared Sui object reference `(object_id, initial_shared_version, mutable)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharedObjectInput {
    pub object_id: SuiAddress,
    pub initial_shared_version: u64,
    pub mutable: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObjectArg {
    ImmOrOwnedObject(SuiObjectRef),
    SharedObject(SharedObjectInput),
    Receiving(SuiObjectRef),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CallArg {
    Pure(#[serde(with = "serde_bytes")] Vec<u8>),
    Object(ObjectArg),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Argument {
    GasCoin,
    Input(u16),
    Result(u16),
    NestedResult(u16, u16),
}

/// Move `TypeTag` matching Sui's exact BCS discriminant ordering:
/// `Bool=0, U8=1, U64=2, U128=3, Address=4, Signer=5, Vector=6, Struct=7, U16=8, U32=9, U256=10`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SuiTypeTag {
    Bool,
    U8,
    U64,
    U128,
    Address,
    Signer,
    Vector(Box<SuiTypeTag>),
    Struct(Box<SuiStructTag>),
    U16,
    U32,
    U256,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuiStructTag {
    pub address: SuiAddress,
    pub module: String,
    pub name: String,
    pub type_params: Vec<SuiTypeTag>,
}

impl SuiTypeTag {
    /// Parses a struct type tag like `"0x2::sui::SUI"` or `"0xabcd::usdc::USDC"`.
    pub fn parse_struct(tag: &str) -> Result<Self, SdkError> {
        let parts: Vec<&str> = tag.trim().split("::").collect();
        if parts.len() != 3 {
            return Err(SdkError::Rpc(format!(
                "expected <pkg>::<module>::<name> type tag, got {tag}"
            )));
        }
        Ok(SuiTypeTag::Struct(Box::new(SuiStructTag {
            address: SuiAddress::from_hex(parts[0])?,
            module: parts[1].to_string(),
            name: parts[2].to_string(),
            type_params: Vec::new(),
        })))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgrammableMoveCall {
    pub package: SuiAddress,
    pub module: String,
    pub function: String,
    pub type_arguments: Vec<SuiTypeTag>,
    pub arguments: Vec<Argument>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PtbCommand {
    MoveCall(ProgrammableMoveCall),
    TransferObjects(Vec<Argument>, Argument),
    SplitCoins(Argument, Vec<Argument>),
    MergeCoins(Argument, Vec<Argument>),
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgrammableTransaction {
    pub inputs: Vec<CallArg>,
    pub commands: Vec<PtbCommand>,
}

/// Ergonomic builder for Sui Programmable Transaction Blocks.
#[derive(Default)]
pub struct PtbBuilder {
    inputs: Vec<CallArg>,
    commands: Vec<PtbCommand>,
}

impl PtbBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn pure<T: Serialize>(&mut self, val: &T) -> Result<Argument, SdkError> {
        let raw = bcs::to_bytes(val).map_err(|e| SdkError::Rpc(format!("BCS pure error: {e}")))?;
        let idx = self.inputs.len() as u16;
        self.inputs.push(CallArg::Pure(raw));
        Ok(Argument::Input(idx))
    }

    pub fn obj(&mut self, obj_arg: ObjectArg) -> Argument {
        let idx = self.inputs.len() as u16;
        self.inputs.push(CallArg::Object(obj_arg));
        Argument::Input(idx)
    }

    pub fn split_coins(&mut self, coin: Argument, amounts: Vec<Argument>) -> Argument {
        let idx = self.commands.len() as u16;
        self.commands.push(PtbCommand::SplitCoins(coin, amounts));
        Argument::Result(idx)
    }

    pub fn move_call(
        &mut self,
        package: SuiAddress,
        module: impl Into<String>,
        function: impl Into<String>,
        type_arguments: Vec<SuiTypeTag>,
        arguments: Vec<Argument>,
    ) -> Argument {
        let idx = self.commands.len() as u16;
        self.commands.push(PtbCommand::MoveCall(ProgrammableMoveCall {
            package,
            module: module.into(),
            function: function.into(),
            type_arguments,
            arguments,
        }));
        Argument::Result(idx)
    }

    pub fn finish(self) -> ProgrammableTransaction {
        ProgrammableTransaction {
            inputs: self.inputs,
            commands: self.commands,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransactionKind {
    ProgrammableTransaction(ProgrammableTransaction),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GasData {
    pub payment: Vec<SuiObjectRef>,
    pub owner: SuiAddress,
    pub price: u64,
    pub budget: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransactionExpiration {
    #[default]
    None,
    Epoch(u64),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionDataV1 {
    pub kind: TransactionKind,
    pub sender: SuiAddress,
    pub gas_data: GasData,
    pub expiration: TransactionExpiration,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransactionData {
    V1(TransactionDataV1),
}

impl TransactionData {
    pub fn new_ptb(
        sender: SuiAddress,
        ptb: ProgrammableTransaction,
        gas_payment: Vec<SuiObjectRef>,
        gas_price: u64,
        gas_budget: u64,
    ) -> Self {
        TransactionData::V1(TransactionDataV1 {
            kind: TransactionKind::ProgrammableTransaction(ptb),
            sender,
            gas_data: GasData {
                payment: gas_payment,
                owner: sender,
                price: gas_price,
                budget: gas_budget,
            },
            expiration: TransactionExpiration::None,
        })
    }

    pub fn to_bcs_base64(&self) -> Result<String, SdkError> {
        let raw = bcs::to_bytes(self).map_err(|e| SdkError::Rpc(e.to_string()))?;
        Ok(B64_STD.encode(raw))
    }
}

#[derive(Clone, Debug)]
pub struct SignedSuiTransaction {
    pub tx_bytes_b64: String,
    pub signature_b64: String,
    pub tx_digest: SuiDigest,
}

/// Ed25519 Sui transaction signer implementing `suiprivkey1...` Bech32 import/export,
/// `Blake2b-256([0x00] || pk)` address derivation, and `IntentScope::TransactionData` (`[0,0,0]`) signing.
#[derive(Clone)]
pub struct SuiEd25519Signer {
    signing_key: SigningKey,
}

impl SuiEd25519Signer {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(&seed),
        }
    }

    /// Parses `suiprivkey1...` Bech32, `0x`/hex 32-byte seed, or Base64 `sui.keystore` entry.
    pub fn parse_sui_key(raw_key: &str) -> Result<Self, SdkError> {
        let trimmed = raw_key.trim();
        if trimmed.starts_with("suiprivkey1") {
            let (hrp, data) = bech32::decode(trimmed)
                .map_err(|e| SdkError::Rpc(format!("invalid suiprivkey bech32: {e}")))?;
            if hrp.as_str() != "suiprivkey" {
                return Err(SdkError::Rpc(format!("unexpected HRP {}", hrp.as_str())));
            }
            if data.len() != 33 || data[0] != SUI_ED25519_FLAG {
                return Err(SdkError::Rpc(
                    "suiprivkey must be 33 bytes with Ed25519 scheme flag 0x00".into(),
                ));
            }
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&data[1..33]);
            return Ok(Self::from_seed(seed));
        }

        let maybe_hex = trimmed.strip_prefix("0x").unwrap_or(trimmed);
        if maybe_hex.len() == 64 && maybe_hex.chars().all(|c| c.is_ascii_hexdigit()) {
            let decoded = hex::decode(maybe_hex).map_err(|e| SdkError::Rpc(e.to_string()))?;
            let seed: [u8; 32] = decoded.try_into().unwrap();
            return Ok(Self::from_seed(seed));
        }

        if let Ok(b64) = B64_STD.decode(trimmed) {
            if b64.len() == 33 && b64[0] == SUI_ED25519_FLAG {
                let mut seed = [0u8; 32];
                seed.copy_from_slice(&b64[1..33]);
                return Ok(Self::from_seed(seed));
            } else if b64.len() == 32 {
                let seed: [u8; 32] = b64.try_into().unwrap();
                return Ok(Self::from_seed(seed));
            }
        }

        Err(SdkError::Rpc(
            "unsupported Sui private key format (expected suiprivkey1..., 64-char hex, or 33-byte base64)"
                .into(),
        ))
    }

    pub fn to_sui_privkey_bech32(&self) -> Result<String, SdkError> {
        let mut payload = [0u8; 33];
        payload[0] = SUI_ED25519_FLAG;
        payload[1..33].copy_from_slice(&self.signing_key.to_bytes());
        let hrp = Hrp::parse("suiprivkey").map_err(|e| SdkError::Rpc(e.to_string()))?;
        bech32::encode::<Bech32>(hrp, &payload).map_err(|e| SdkError::Rpc(e.to_string()))
    }

    pub fn sui_address(&self) -> SuiAddress {
        let pk = self.signing_key.verifying_key().to_bytes();
        let mut hasher = Blake2b256::new();
        hasher.update([SUI_ED25519_FLAG]);
        hasher.update(pk);
        SuiAddress(hasher.finalize().into())
    }

    pub fn sign_transaction(&self, tx: &TransactionData) -> Result<SignedSuiTransaction, SdkError> {
        let tx_bytes = bcs::to_bytes(tx).map_err(|e| SdkError::Rpc(e.to_string()))?;

        // TransactionDigest = Blake2b256("TransactionData::" || bcs(TransactionData))
        let mut td_hasher = Blake2b256::new();
        td_hasher.update(b"TransactionData::");
        td_hasher.update(&tx_bytes);
        let tx_digest = SuiDigest(td_hasher.finalize().into());

        // IntentMessage = [IntentScope::TransactionData(0), IntentVersion::V0(0), AppId::Sui(0)] || tx_bytes
        let mut intent_hasher = Blake2b256::new();
        intent_hasher.update([0u8, 0u8, 0u8]);
        intent_hasher.update(&tx_bytes);
        let signing_digest: [u8; 32] = intent_hasher.finalize().into();

        let ed_sig = self.signing_key.sign(&signing_digest);
        let pk = self.signing_key.verifying_key().to_bytes();
        let mut sui_sig = Vec::with_capacity(97);
        sui_sig.push(SUI_ED25519_FLAG);
        sui_sig.extend_from_slice(&ed_sig.to_bytes());
        sui_sig.extend_from_slice(&pk);

        Ok(SignedSuiTransaction {
            tx_bytes_b64: B64_STD.encode(&tx_bytes),
            signature_b64: B64_STD.encode(&sui_sig),
            tx_digest,
        })
    }
}

/// Verifies a Base64-encoded 97-byte Sui Ed25519 `UserSignature` against `tx_bytes_b64` and returns the signer's `SuiAddress`.
pub fn verify_sui_ed25519_signature(
    tx_bytes_b64: &str,
    signature_b64: &str,
) -> Result<SuiAddress, SdkError> {
    let tx_bytes = B64_STD
        .decode(tx_bytes_b64)
        .map_err(|e| SdkError::Rpc(e.to_string()))?;
    let sig_raw = B64_STD
        .decode(signature_b64)
        .map_err(|e| SdkError::Rpc(e.to_string()))?;
    if sig_raw.len() != 97 || sig_raw[0] != SUI_ED25519_FLAG {
        return Err(SdkError::Rpc("invalid 97-byte Sui Ed25519 signature".into()));
    }
    let sig = Signature::from_slice(&sig_raw[1..65]).map_err(|e| SdkError::Rpc(e.to_string()))?;
    let pk_bytes: [u8; 32] = sig_raw[65..97].try_into().unwrap();
    let vk = VerifyingKey::from_bytes(&pk_bytes).map_err(|e| SdkError::Rpc(e.to_string()))?;

    let mut intent_hasher = Blake2b256::new();
    intent_hasher.update([0u8, 0u8, 0u8]);
    intent_hasher.update(&tx_bytes);
    let digest: [u8; 32] = intent_hasher.finalize().into();
    vk.verify(&digest, &sig)
        .map_err(|e| SdkError::Rpc(format!("Sui signature verification failed: {e}")))?;

    let mut addr_hasher = Blake2b256::new();
    addr_hasher.update([SUI_ED25519_FLAG]);
    addr_hasher.update(pk_bytes);
    Ok(SuiAddress(addr_hasher.finalize().into()))
}

// ============================================================================
// High-Level Cowrie & Blind-Seal Move Call PTB Constructors
// ============================================================================

/// Builds a Base64-encoded `TransactionData` calling `blind_seal::blind_seal::seal_approve_blind_sign`
/// suitable for off-chain evaluation via `sui_dryRunTransactionBlock`.
pub fn build_seal_approve_blind_sign_tx_b64(
    blind_seal_pkg: SuiAddress,
    sender: SuiAddress,
    ticket_ref: SuiObjectRef,
    expected_keyset_id: &str,
    gas_price: u64,
) -> Result<String, SdkError> {
    let mut b = PtbBuilder::new();
    let ticket_arg = b.obj(ObjectArg::ImmOrOwnedObject(ticket_ref));
    let ks_arg = b.pure(&expected_keyset_id.as_bytes().to_vec())?;
    b.move_call(
        blind_seal_pkg,
        "blind_seal",
        "seal_approve_blind_sign",
        vec![],
        vec![ticket_arg, ks_arg],
    );
    TransactionData::new_ptb(sender, b.finish(), vec![], gas_price, 10_000_000).to_bcs_base64()
}

/// Builds a Base64-encoded `TransactionData` calling `blind_seal::blind_seal::seal_approve_ibe`.
pub fn build_seal_approve_ibe_tx_b64(
    blind_seal_pkg: SuiAddress,
    sender: SuiAddress,
    identity: &[u8],
    approval_ref: SuiObjectRef,
    expected_keyset_id: &str,
    gas_price: u64,
) -> Result<String, SdkError> {
    let mut b = PtbBuilder::new();
    let id_arg = b.pure(&identity.to_vec())?;
    let app_arg = b.obj(ObjectArg::ImmOrOwnedObject(approval_ref));
    let ks_arg = b.pure(&expected_keyset_id.as_bytes().to_vec())?;
    b.move_call(
        blind_seal_pkg,
        "blind_seal",
        "seal_approve_ibe",
        vec![],
        vec![id_arg, app_arg, ks_arg],
    );
    TransactionData::new_ptb(sender, b.finish(), vec![], gas_price, 10_000_000).to_bcs_base64()
}

/// Builds a `ProgrammableTransaction` calling `cowrie_cashu::mint_vault::mint_from_sui<Asset>`
/// by splitting `deposit_coin_units` from `payment_source` (`Argument::GasCoin` for native SUI, or an owned `Coin<Asset>`).
pub fn build_mint_from_sui_ptb(
    cowrie_cashu_pkg: SuiAddress,
    asset_type: SuiTypeTag,
    vault: SharedObjectInput,
    payment_coin: Option<SuiObjectRef>,
    deposit_coin_units: u64,
    out_slots: &[u8],
    out_blinded_g1: &[Vec<u8>],
) -> Result<ProgrammableTransaction, SdkError> {
    let mut b = PtbBuilder::new();
    let vault_arg = b.obj(ObjectArg::SharedObject(SharedObjectInput {
        mutable: true,
        ..vault
    }));
    let src_coin = match payment_coin {
        Some(c) => b.obj(ObjectArg::ImmOrOwnedObject(c)),
        None => Argument::GasCoin,
    };
    let amt_arg = b.pure(&deposit_coin_units)?;
    let split_res = b.split_coins(src_coin, vec![amt_arg]);
    let exact_coin = Argument::NestedResult(
        match split_res {
            Argument::Result(i) => i,
            _ => 0,
        },
        0,
    );
    let slots_arg = b.pure(&out_slots.to_vec())?;
    let blinded_arg = b.pure(&out_blinded_g1.to_vec())?;
    b.move_call(
        cowrie_cashu_pkg,
        "mint_vault",
        "mint_from_sui",
        vec![asset_type],
        vec![vault_arg, exact_coin, slots_arg, blinded_arg],
    );
    Ok(b.finish())
}

/// Builds a `ProgrammableTransaction` calling `cowrie_cashu::mint_vault::swap_native_dst<Asset>`.
#[allow(clippy::too_many_arguments)]
pub fn build_swap_native_dst_ptb(
    cowrie_cashu_pkg: SuiAddress,
    asset_type: SuiTypeTag,
    vault: SharedObjectInput,
    keyset_info: SuiObjectRef,
    in_slots: &[u8],
    secrets: &[Vec<u8>],
    raw_sigs_g1: &[Vec<u8>],
    p2pk_pubkeys: &[Vec<u8>],
    p2pk_sigs: &[Vec<u8>],
    out_slots: &[u8],
    out_blinded_g1: &[Vec<u8>],
    fee_notes: u64,
    sighash_context: &[u8],
) -> Result<ProgrammableTransaction, SdkError> {
    let mut b = PtbBuilder::new();
    let vault_arg = b.obj(ObjectArg::SharedObject(SharedObjectInput {
        mutable: true,
        ..vault
    }));
    let ks_arg = b.obj(ObjectArg::ImmOrOwnedObject(keyset_info));
    let in_slots_arg = b.pure(&in_slots.to_vec())?;
    let secrets_arg = b.pure(&secrets.to_vec())?;
    let sigs_arg = b.pure(&raw_sigs_g1.to_vec())?;
    let p2pk_pk_arg = b.pure(&p2pk_pubkeys.to_vec())?;
    let p2pk_sig_arg = b.pure(&p2pk_sigs.to_vec())?;
    let out_slots_arg = b.pure(&out_slots.to_vec())?;
    let out_bm_arg = b.pure(&out_blinded_g1.to_vec())?;
    let fee_arg = b.pure(&fee_notes)?;
    let ctx_arg = b.pure(&sighash_context.to_vec())?;

    b.move_call(
        cowrie_cashu_pkg,
        "mint_vault",
        "swap_native_dst",
        vec![asset_type],
        vec![
            vault_arg,
            ks_arg,
            in_slots_arg,
            secrets_arg,
            sigs_arg,
            p2pk_pk_arg,
            p2pk_sig_arg,
            out_slots_arg,
            out_bm_arg,
            fee_arg,
            ctx_arg,
        ],
    );
    Ok(b.finish())
}

/// Builds a `ProgrammableTransaction` calling `cowrie_cashu::mint_vault::melt_native_dst<Asset>`.
#[allow(clippy::too_many_arguments)]
pub fn build_melt_native_dst_ptb(
    cowrie_cashu_pkg: SuiAddress,
    asset_type: SuiTypeTag,
    vault: SharedObjectInput,
    keyset_info: SuiObjectRef,
    in_slots: &[u8],
    secrets: &[Vec<u8>],
    raw_sigs_g1: &[Vec<u8>],
    p2pk_pubkeys: &[Vec<u8>],
    p2pk_sigs: &[Vec<u8>],
    recipient: SuiAddress,
    sighash_context: &[u8],
) -> Result<ProgrammableTransaction, SdkError> {
    let mut b = PtbBuilder::new();
    let vault_arg = b.obj(ObjectArg::SharedObject(SharedObjectInput {
        mutable: true,
        ..vault
    }));
    let ks_arg = b.obj(ObjectArg::ImmOrOwnedObject(keyset_info));
    let clock_arg = b.obj(ObjectArg::SharedObject(SharedObjectInput {
        object_id: SUI_CLOCK_OBJECT_ID,
        initial_shared_version: 1,
        mutable: false,
    }));
    let in_slots_arg = b.pure(&in_slots.to_vec())?;
    let secrets_arg = b.pure(&secrets.to_vec())?;
    let sigs_arg = b.pure(&raw_sigs_g1.to_vec())?;
    let p2pk_pk_arg = b.pure(&p2pk_pubkeys.to_vec())?;
    let p2pk_sig_arg = b.pure(&p2pk_sigs.to_vec())?;
    let recip_arg = b.pure(&recipient)?;
    let ctx_arg = b.pure(&sighash_context.to_vec())?;

    b.move_call(
        cowrie_cashu_pkg,
        "mint_vault",
        "melt_native_dst",
        vec![asset_type],
        vec![
            vault_arg,
            ks_arg,
            clock_arg,
            in_slots_arg,
            secrets_arg,
            sigs_arg,
            p2pk_pk_arg,
            p2pk_sig_arg,
            recip_arg,
            ctx_arg,
        ],
    );
    Ok(b.finish())
}
