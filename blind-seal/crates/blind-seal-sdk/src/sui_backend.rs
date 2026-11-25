use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fs,
    future::Future,
    path::Path,
    pin::Pin,
    sync::{Arc, RwLock},
};

use blind_seal_crypto::{
    dkg::PublicKeyset,
    dst::DstProfile,
    schnorr::{verify_bip340_schnorr, SchnorrSig, XOnlyPubKey},
    tbs::{
        hash_secret_to_y_bytes, verify_batch_notes, BlindedMessage, PublicKeyG2, UnblindedSignature,
    },
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::{
    api::{BlindTicketOnChain, IbeApprovalOnChain},
    ptb::{
        build_melt_native_dst_ptb, build_mint_from_sui_ptb, build_seal_approve_blind_sign_tx_b64,
        build_seal_approve_ibe_tx_b64, build_swap_native_dst_ptb, ProgrammableTransaction,
        SharedObjectInput, SuiAddress, SuiDigest, SuiEd25519Signer, SuiObjectRef, SuiTypeTag,
        TransactionData,
    },
    SdkError,
};

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum NullifierStatus {
    Unspent,
    Pending,
    Spent,
}

/// Input note proof submitted to the Sui Move "Consensus Box" during Cashu swap/melt
/// or Fedimint reissuance/melt.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SpendProofInput {
    pub slot: u8,
    pub secret_or_nonce: Vec<u8>,
    pub signature: UnblindedSignature,
    /// Optional `NUT-11` P2PK or Fedimint `SpendKey` BIP-340 Schnorr witness `(pubkey, sig)`.
    pub schnorr_lock: Option<(XOnlyPubKey, SchnorrSig)>,
    /// Optional per-input Schnorr message override (used by `NUT-11` `SIG_INPUTS` = `SHA256(secret)`).
    /// When `None`, `sighash_context` passed to the transaction is verified (`SIG_ALL` / `fedimint_txid`).
    pub schnorr_msg_override: Option<Vec<u8>>,
    /// Optional `NUT-14` HTLC preimage (`SHA256(preimage) == expected_hash`).
    pub htlc_preimage: Option<Vec<u8>>,
    /// Optional expected `NUT-14` HTLC 32-byte SHA256 hash extracted from `NUT-10` JSON secret.
    pub htlc_expected_hash: Option<[u8; 32]>,
}

/// Fedimint `SessionClosedEvent` emitted on Sui for deterministic 12-word BIP-39 wallet recovery.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuiFedimintSessionEvent {
    pub session_index: u64,
    pub finalized_txids: Vec<[u8; 32]>,
    pub outputs_by_tx: Vec<([u8; 32], Vec<(u8, BlindedMessage)>)>,
}

/// Fedimint `LNv2` incoming/outgoing contract stored in `move/cowrie_fedimint`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Lnv2ContractOnChain {
    pub contract_id: [u8; 32],
    pub keyset_id: String,
    pub amount_msat: u64,
    pub payment_hash: [u8; 32],
    pub claim_pk: XOnlyPubKey,
    pub refund_pk: XOnlyPubKey,
    pub expiry_epoch: u64,
    pub settled: bool,
    pub preimage_approval_id: [u8; 32],
}

/// Abstract interface to the Sui Move Consensus & Policy layer (used by Blind-Seal Guardian Key Servers).
pub trait SuiConsensusBackend: Send + Sync {
    fn verify_and_load_blind_ticket<'a>(
        &'a self,
        keyset_id: &'a str,
        ticket_id: [u8; 32],
        seal_approve_ptb_b64: Option<&'a str>,
    ) -> BoxFuture<'a, Result<BlindTicketOnChain, SdkError>>;

    fn verify_and_load_ibe_approval<'a>(
        &'a self,
        keyset_id: &'a str,
        approval_id: [u8; 32],
        seal_approve_ptb_b64: Option<&'a str>,
    ) -> BoxFuture<'a, Result<IbeApprovalOnChain, SdkError>>;
}

/// Polymorphic Federated Cashu "Consensus Box" trait implemented by BOTH:
/// 1. `EmbeddedMoveEngine` (standalone Bitcoin/Lightning `cowried` with atomic CBOR disk snapshots)
/// 2. `LiveSuiJsonRpcBackend` (live on-chain `cowrie_cashu::mint_vault` shared object via `sui_executeTransactionBlock`)
pub trait CashuConsensusBox: Send + Sync {
    fn box_deposit_and_create_ticket<'a>(
        &'a self,
        keyset_id: &'a str,
        deposit_coin_units: u64,
        slots: Vec<u8>,
        blinded_messages: Vec<BlindedMessage>,
    ) -> BoxFuture<'a, Result<BlindTicketOnChain, SdkError>>;

    fn box_atomic_swap<'a>(
        &'a self,
        keyset_id: &'a str,
        inputs: Vec<SpendProofInput>,
        out_slots: Vec<u8>,
        out_blinded: Vec<BlindedMessage>,
        explicit_fee_notes: Option<u64>,
        sighash_context: &'a [u8],
    ) -> BoxFuture<'a, Result<BlindTicketOnChain, SdkError>>;

    fn box_atomic_melt<'a>(
        &'a self,
        keyset_id: &'a str,
        inputs: Vec<SpendProofInput>,
        sighash_context: &'a [u8],
    ) -> BoxFuture<'a, Result<u64, SdkError>>;

    fn box_check_y_state<'a>(
        &'a self,
        keyset_id: &'a str,
        y_compressed_g1: &'a [u8],
    ) -> BoxFuture<'a, Result<NullifierStatus, SdkError>>;

    fn box_lookup_restore_ticket<'a>(
        &'a self,
        keyset_id: &'a str,
        b_hex: &'a str,
    ) -> BoxFuture<'a, Option<(BlindTicketOnChain, usize, u8)>>;

    fn box_vault_reserve_coin_units<'a>(
        &'a self,
        keyset_id: &'a str,
    ) -> BoxFuture<'a, Result<u64, SdkError>>;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VaultConfig {
    pub keyset: PublicKeyset,
    pub dst: DstProfile,
    pub notes_per_coin_unit: u64,
    pub hourly_melt_cap_notes: u64,
    #[serde(default)]
    pub input_fee_ppk: u64,
}

#[derive(Clone, Default, Serialize, Deserialize)]
struct VaultState {
    reserve_coin_units: u64,
    melted_this_window_notes: u64,
    /// Keyed by hex-encoded 48-byte compressed `G1` point `Y = H_dst(secret)` (`NUT-07`).
    spent_ys_hex: HashMap<String, NullifierStatus>,
}

#[derive(Clone, Serialize, Deserialize)]
struct RestoreEntry {
    ticket_id: [u8; 32],
    output_idx: usize,
    slot: u8,
}

#[derive(Clone, Serialize, Deserialize)]
struct InnerMoveState {
    checkpoint: u64,
    vaults: HashMap<String, (VaultConfig, VaultState)>,
    blind_tickets_hex: HashMap<String, BlindTicketOnChain>,
    /// `(keyset_id, hex(B_)) -> RestoreEntry` for stateless `NUT-09` `/v1/restore` recovery!
    restore_by_b_hex: HashMap<(String, String), RestoreEntry>,
    ibe_approvals_hex: HashMap<String, IbeApprovalOnChain>,
    // Fedimint-specific upstream state
    fedimint_outpoint_tickets: Vec<(([u8; 32], u32), [u8; 32])>,
    fedimint_pending_txs: Vec<([u8; 32], Vec<(u8, BlindedMessage)>)>,
    fedimint_sessions: Vec<SuiFedimintSessionEvent>,
    fedimint_txs_per_session: usize,
    lnv2_contracts_hex: HashMap<String, Lnv2ContractOnChain>,
}

/// Deterministic, thread-safe Rust execution engine mirroring `move/blind_seal`,
/// `move/cowrie_cashu`, and `move/cowrie_fedimint` shared-object semantics,
/// with optional disk snapshot persistence for standalone `cowried` deployments.
#[derive(Clone)]
pub struct EmbeddedMoveEngine {
    inner: Arc<RwLock<InnerMoveState>>,
    snapshot_path: Option<Arc<std::path::PathBuf>>,
}

impl Default for EmbeddedMoveEngine {
    fn default() -> Self {
        Self::new(2)
    }
}

impl EmbeddedMoveEngine {
    pub fn new(fedimint_txs_per_session: usize) -> Self {
        Self {
            inner: Arc::new(RwLock::new(InnerMoveState {
                checkpoint: 1,
                vaults: HashMap::new(),
                blind_tickets_hex: HashMap::new(),
                restore_by_b_hex: HashMap::new(),
                ibe_approvals_hex: HashMap::new(),
                fedimint_outpoint_tickets: Vec::new(),
                fedimint_pending_txs: Vec::new(),
                fedimint_sessions: Vec::new(),
                fedimint_txs_per_session: fedimint_txs_per_session.max(1),
                lnv2_contracts_hex: HashMap::new(),
            })),
            snapshot_path: None,
        }
    }

    /// Loads persisted Consensus Box state from `path` if it exists, and auto-persists every commit!
    pub fn open_or_create_persistent(
        path: impl AsRef<Path>,
        fedimint_txs_per_session: usize,
    ) -> Result<Self, SdkError> {
        let path_buf = path.as_ref().to_path_buf();
        if path_buf.exists() {
            let data = fs::read(&path_buf).map_err(|e| SdkError::Rpc(e.to_string()))?;
            let state: InnerMoveState =
                serde_cbor::from_slice(&data).map_err(|e| SdkError::Rpc(e.to_string()))?;
            Ok(Self {
                inner: Arc::new(RwLock::new(state)),
                snapshot_path: Some(Arc::new(path_buf)),
            })
        } else {
            let mut engine = Self::new(fedimint_txs_per_session);
            engine.snapshot_path = Some(Arc::new(path_buf));
            engine.flush_if_persistent()?;
            Ok(engine)
        }
    }

    fn flush_locked(&self, state: &InnerMoveState) -> Result<(), SdkError> {
        if let Some(path) = &self.snapshot_path {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).map_err(|e| SdkError::Rpc(e.to_string()))?;
            }
            let tmp = path.with_extension("cbor.tmp");
            let bytes = serde_cbor::to_vec(state).map_err(|e| SdkError::Rpc(e.to_string()))?;
            fs::write(&tmp, bytes).map_err(|e| SdkError::Rpc(e.to_string()))?;
            fs::rename(&tmp, path.as_ref()).map_err(|e| SdkError::Rpc(e.to_string()))?;
        }
        Ok(())
    }

    pub fn flush_if_persistent(&self) -> Result<(), SdkError> {
        let guard = self.inner.read().unwrap();
        self.flush_locked(&guard)
    }

    pub fn register_vault(&self, cfg: VaultConfig) {
        let mut guard = self.inner.write().unwrap();
        guard
            .vaults
            .entry(cfg.keyset.keyset_id.clone())
            .or_insert_with(|| (cfg, VaultState::default()));
        let _ = self.flush_locked(&guard);
    }

    pub fn vault_configs(&self) -> Vec<VaultConfig> {
        let guard = self.inner.read().unwrap();
        let mut out: Vec<_> = guard.vaults.values().map(|(c, _)| c.clone()).collect();
        out.sort_by(|a, b| a.keyset.keyset_id.cmp(&b.keyset.keyset_id));
        out
    }

    pub fn vault_reserve_coin_units(&self, keyset_id: &str) -> Result<u64, SdkError> {
        let guard = self.inner.read().unwrap();
        let (_, st) = guard
            .vaults
            .get(keyset_id)
            .ok_or_else(|| SdkError::MoveAbort(format!("unknown keyset vault {keyset_id}")))?;
        Ok(st.reserve_coin_units)
    }

    /// `NUT-07` privacy-preserving state check using the 48-byte `G1` point `Y = H_dst(secret)`!
    pub fn check_y_state(&self, keyset_id: &str, y_compressed_g1: &[u8]) -> Result<NullifierStatus, SdkError> {
        let guard = self.inner.read().unwrap();
        let (_, st) = guard
            .vaults
            .get(keyset_id)
            .ok_or_else(|| SdkError::MoveAbort(format!("unknown keyset vault {keyset_id}")))?;
        Ok(st
            .spent_ys_hex
            .get(&hex::encode(y_compressed_g1))
            .copied()
            .unwrap_or(NullifierStatus::Unspent))
    }

    /// Computes required `NUT-02` fee in base note units: `ceil(num_inputs * input_fee_ppk / 1000)`.
    pub fn compute_required_fee(&self, keyset_id: &str, num_inputs: usize) -> Result<u64, SdkError> {
        let guard = self.inner.read().unwrap();
        let (cfg, _) = guard
            .vaults
            .get(keyset_id)
            .ok_or_else(|| SdkError::MoveAbort(format!("unknown keyset vault {keyset_id}")))?;
        if cfg.input_fee_ppk == 0 || num_inputs == 0 {
            return Ok(0);
        }
        let ppk_sum = (num_inputs as u64).saturating_mul(cfg.input_fee_ppk);
        Ok(ppk_sum.div_ceil(1_000))
    }

    /// `NUT-09` `/v1/restore`: Looks up a previously committed `BlindedMessage` (`B_`) and returns
    /// its finalized `(BlindTicketOnChain, output_index, slot)`.
    pub fn lookup_restore_ticket(
        &self,
        keyset_id: &str,
        b_hex: &str,
    ) -> Option<(BlindTicketOnChain, usize, u8)> {
        let guard = self.inner.read().unwrap();
        let entry = guard
            .restore_by_b_hex
            .get(&(keyset_id.to_string(), b_hex.to_lowercase()))?;
        let ticket = guard
            .blind_tickets_hex
            .get(&hex::encode(entry.ticket_id))?
            .clone();
        Some((ticket, entry.output_idx, entry.slot))
    }

    fn index_ticket_for_restore(state: &mut InnerMoveState, ticket: &BlindTicketOnChain) {
        for (idx, (&slot, bm)) in ticket
            .slots
            .iter()
            .zip(ticket.blinded_messages.iter())
            .enumerate()
        {
            state.restore_by_b_hex.insert(
                (ticket.keyset_id.clone(), hex::encode(bm.as_bytes())),
                RestoreEntry {
                    ticket_id: ticket.ticket_id,
                    output_idx: idx,
                    slot,
                },
            );
        }
        state
            .blind_tickets_hex
            .insert(hex::encode(ticket.ticket_id), ticket.clone());
    }

    fn slots_sum(slots: &[u8], max_slots: usize) -> Result<u64, SdkError> {
        let mut total = 0u64;
        for &s in slots {
            if usize::from(s) >= max_slots || s >= 63 {
                return Err(SdkError::MoveAbort(format!("invalid denomination slot {s}")));
            }
            total = total
                .checked_add(1u64 << s)
                .ok_or_else(|| SdkError::MoveAbort("amount overflow".into()))?;
        }
        Ok(total)
    }

    fn next_object_id(checkpoint: u64, domain: &[u8], extra: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(domain);
        h.update(checkpoint.to_be_bytes());
        h.update(extra);
        h.finalize().into()
    }

    pub fn deposit_and_create_ticket(
        &self,
        keyset_id: &str,
        deposit_coin_units: u64,
        slots: Vec<u8>,
        blinded_messages: Vec<BlindedMessage>,
    ) -> Result<BlindTicketOnChain, SdkError> {
        if slots.len() != blinded_messages.len() || slots.is_empty() {
            return Err(SdkError::MoveAbort(
                "slots and blinded_messages length mismatch".into(),
            ));
        }
        for bm in &blinded_messages {
            bm.to_g1()?;
        }

        let mut guard = self.inner.write().unwrap();
        let (cfg, st) = guard
            .vaults
            .get_mut(keyset_id)
            .ok_or_else(|| SdkError::MoveAbort(format!("unknown keyset {keyset_id}")))?;

        let requested_notes = Self::slots_sum(&slots, cfg.keyset.num_slots())?;
        let backed_notes = deposit_coin_units
            .checked_mul(cfg.notes_per_coin_unit)
            .ok_or_else(|| SdkError::MoveAbort("deposit overflow".into()))?;
        if requested_notes != backed_notes {
            return Err(SdkError::MoveAbort(format!(
                "conservation failed: deposit backs {backed_notes} note units, requested {requested_notes}"
            )));
        }

        st.reserve_coin_units = st
            .reserve_coin_units
            .checked_add(deposit_coin_units)
            .ok_or_else(|| SdkError::MoveAbort("reserve overflow".into()))?;

        guard.checkpoint += 1;
        let cp = guard.checkpoint;
        let ticket_id =
            Self::next_object_id(cp, b"BLIND_TICKET_MINT", blinded_messages[0].as_bytes());
        let ticket = BlindTicketOnChain {
            ticket_id,
            keyset_id: keyset_id.to_string(),
            slots,
            blinded_messages,
            finalized_checkpoint: cp,
        };
        Self::index_ticket_for_restore(&mut guard, &ticket);
        self.flush_locked(&guard)?;
        Ok(ticket)
    }

    fn verify_and_consume_inputs_locked(
        cfg: &VaultConfig,
        st: &mut VaultState,
        inputs: &[SpendProofInput],
        sighash_context: &[u8],
    ) -> Result<u64, SdkError> {
        if inputs.is_empty() {
            return Err(SdkError::MoveAbort("empty spend inputs".into()));
        }

        // Compute fixed 48-byte `Y = H_dst(secret)` for every input and check duplicates / spent status
        let mut ys_hex = Vec::with_capacity(inputs.len());
        let mut seen_in_tx = HashSet::with_capacity(inputs.len());
        for inp in inputs {
            let y = hash_secret_to_y_bytes(&inp.secret_or_nonce, &cfg.dst);
            let y_hex = hex::encode(y);
            if !seen_in_tx.insert(y_hex.clone()) {
                return Err(SdkError::MoveAbort(
                    "duplicate Y nullifier within same transaction".into(),
                ));
            }
            if matches!(
                st.spent_ys_hex.get(&y_hex),
                Some(NullifierStatus::Spent | NullifierStatus::Pending)
            ) {
                return Err(SdkError::NullifierAlreadySpent(y_hex));
            }
            ys_hex.push(y_hex);
        }

        let input_slots: Vec<u8> = inputs.iter().map(|i| i.slot).collect();
        let total_in = Self::slots_sum(&input_slots, cfg.keyset.num_slots())?;

        for inp in inputs {
            if let Some((pk, sig)) = &inp.schnorr_lock {
                let msg = inp
                    .schnorr_msg_override
                    .as_deref()
                    .unwrap_or(sighash_context);
                verify_bip340_schnorr(pk, msg, sig)?;
            }
            if let Some(expected_hash) = &inp.htlc_expected_hash {
                let preimage = inp
                    .htlc_preimage
                    .as_ref()
                    .ok_or_else(|| SdkError::MoveAbort("missing HTLC preimage".into()))?;
                let actual: [u8; 32] = Sha256::digest(preimage).into();
                if &actual != expected_hash {
                    return Err(SdkError::MoveAbort("HTLC preimage hash mismatch".into()));
                }
            }
        }

        let mut slot_pks: BTreeMap<u8, PublicKeyG2> = BTreeMap::new();
        for (idx, pk) in cfg.keyset.slot_agg_pks.iter().enumerate() {
            slot_pks.insert(idx as u8, pk.clone());
        }
        let batch_refs: Vec<_> = inputs
            .iter()
            .map(|inp| (inp.slot, inp.secret_or_nonce.as_slice(), &inp.signature))
            .collect();
        verify_batch_notes(&batch_refs, &slot_pks, &cfg.dst)?;

        for y_hex in ys_hex {
            st.spent_ys_hex.insert(y_hex, NullifierStatus::Spent);
        }

        Ok(total_in)
    }

    pub fn atomic_swap(
        &self,
        keyset_id: &str,
        inputs: Vec<SpendProofInput>,
        out_slots: Vec<u8>,
        out_blinded: Vec<BlindedMessage>,
        explicit_fee_notes: Option<u64>,
        sighash_context: &[u8],
    ) -> Result<BlindTicketOnChain, SdkError> {
        if out_slots.len() != out_blinded.len() || out_slots.is_empty() {
            return Err(SdkError::MoveAbort("invalid swap outputs".into()));
        }
        for bm in &out_blinded {
            bm.to_g1()?;
        }

        let required_fee = match explicit_fee_notes {
            Some(f) => f,
            None => self.compute_required_fee(keyset_id, inputs.len())?,
        };

        let mut guard = self.inner.write().unwrap();
        let (cfg, st) = guard
            .vaults
            .get_mut(keyset_id)
            .ok_or_else(|| SdkError::MoveAbort(format!("unknown keyset {keyset_id}")))?;

        let total_out = Self::slots_sum(&out_slots, cfg.keyset.num_slots())?;
        let pre_check_in = Self::slots_sum(
            &inputs.iter().map(|i| i.slot).collect::<Vec<_>>(),
            cfg.keyset.num_slots(),
        )?;
        if pre_check_in != total_out.saturating_add(required_fee) {
            return Err(SdkError::TransactionUnbalanced {
                total_in: pre_check_in,
                total_out,
                fee: required_fee,
            });
        }

        Self::verify_and_consume_inputs_locked(cfg, st, &inputs, sighash_context)?;

        guard.checkpoint += 1;
        let cp = guard.checkpoint;
        let ticket_id = Self::next_object_id(cp, b"BLIND_TICKET_SWAP", out_blinded[0].as_bytes());
        let ticket = BlindTicketOnChain {
            ticket_id,
            keyset_id: keyset_id.to_string(),
            slots: out_slots,
            blinded_messages: out_blinded,
            finalized_checkpoint: cp,
        };
        Self::index_ticket_for_restore(&mut guard, &ticket);
        self.flush_locked(&guard)?;
        Ok(ticket)
    }

    pub fn atomic_melt(
        &self,
        keyset_id: &str,
        inputs: Vec<SpendProofInput>,
        sighash_context: &[u8],
    ) -> Result<u64, SdkError> {
        let required_fee = self.compute_required_fee(keyset_id, inputs.len())?;
        let mut guard = self.inner.write().unwrap();
        let (cfg, st) = guard
            .vaults
            .get_mut(keyset_id)
            .ok_or_else(|| SdkError::MoveAbort(format!("unknown keyset {keyset_id}")))?;

        let pre_in = Self::slots_sum(
            &inputs.iter().map(|i| i.slot).collect::<Vec<_>>(),
            cfg.keyset.num_slots(),
        )?;
        let net_notes = pre_in
            .checked_sub(required_fee)
            .ok_or_else(|| SdkError::MoveAbort("inputs smaller than fee".into()))?;
        if net_notes % cfg.notes_per_coin_unit != 0 {
            return Err(SdkError::MoveAbort(
                "melt note amount not divisible by base Sui coin unit".into(),
            ));
        }
        if st.melted_this_window_notes.saturating_add(net_notes) > cfg.hourly_melt_cap_notes {
            return Err(SdkError::MoveAbort(
                "Move vault hourly melt circuit-breaker tripped".into(),
            ));
        }

        let coin_units = net_notes / cfg.notes_per_coin_unit;
        if st.reserve_coin_units < coin_units {
            return Err(SdkError::MoveAbort("insufficient vault reserve".into()));
        }

        Self::verify_and_consume_inputs_locked(cfg, st, &inputs, sighash_context)?;
        st.reserve_coin_units -= coin_units;
        st.melted_this_window_notes += net_notes;
        guard.checkpoint += 1;
        self.flush_locked(&guard)?;
        Ok(coin_units)
    }

    pub fn burn_blind_pass_for_ibe_approval(
        &self,
        keyset_id: &str,
        pass_input: SpendProofInput,
        namespace: Vec<u8>,
        identity: Vec<u8>,
    ) -> Result<IbeApprovalOnChain, SdkError> {
        let mut guard = self.inner.write().unwrap();
        let (cfg, st) = guard
            .vaults
            .get_mut(keyset_id)
            .ok_or_else(|| SdkError::MoveAbort(format!("unknown keyset {keyset_id}")))?;

        Self::verify_and_consume_inputs_locked(cfg, st, &[pass_input], &identity)?;

        guard.checkpoint += 1;
        let cp = guard.checkpoint;
        let approval_id = Self::next_object_id(cp, b"IBE_PASS_APPROVAL", &identity);
        let approval = IbeApprovalOnChain {
            approval_id,
            keyset_id: keyset_id.to_string(),
            namespace,
            identity,
            finalized_checkpoint: cp,
        };
        guard
            .ibe_approvals_hex
            .insert(hex::encode(approval_id), approval.clone());
        self.flush_locked(&guard)?;
        Ok(approval)
    }

    pub fn process_fedimint_tx(
        &self,
        keyset_id: &str,
        fedimint_txid: [u8; 32],
        inputs: Vec<SpendProofInput>,
        outputs: Vec<(u8, BlindedMessage)>,
        fee_msat: u64,
    ) -> Result<Vec<[u8; 32]>, SdkError> {
        {
            let guard = self.inner.read().unwrap();
            let existing: Vec<[u8; 32]> = guard
                .fedimint_outpoint_tickets
                .iter()
                .filter(|((tid, _), _)| *tid == fedimint_txid)
                .map(|(_, ticket_id)| *ticket_id)
                .collect();
            if !existing.is_empty() {
                return Ok(existing);
            }
        }

        for inp in &inputs {
            if inp.schnorr_lock.is_none() {
                return Err(SdkError::MoveAbort(
                    "Fedimint MintInput missing mandatory SpendKey Schnorr signature".into(),
                ));
            }
        }

        let out_slots: Vec<u8> = outputs.iter().map(|(s, _)| *s).collect();
        let out_blinded: Vec<BlindedMessage> = outputs.iter().map(|(_, b)| b.clone()).collect();

        let batch_ticket = self.atomic_swap(
            keyset_id,
            inputs,
            out_slots,
            out_blinded,
            Some(fee_msat),
            &fedimint_txid,
        )?;

        let mut guard = self.inner.write().unwrap();
        let mut per_out_tickets = Vec::with_capacity(outputs.len());
        for (idx, (slot, bm)) in outputs.iter().enumerate() {
            let tid = Self::next_object_id(
                batch_ticket.finalized_checkpoint,
                &fedimint_txid,
                &(idx as u32).to_be_bytes(),
            );
            let single = BlindTicketOnChain {
                ticket_id: tid,
                keyset_id: keyset_id.to_string(),
                slots: vec![*slot],
                blinded_messages: vec![bm.clone()],
                finalized_checkpoint: batch_ticket.finalized_checkpoint,
            };
            Self::index_ticket_for_restore(&mut guard, &single);
            guard
                .fedimint_outpoint_tickets
                .push(((fedimint_txid, idx as u32), tid));
            per_out_tickets.push(tid);
        }

        guard.fedimint_pending_txs.push((fedimint_txid, outputs));
        if guard.fedimint_pending_txs.len() >= guard.fedimint_txs_per_session {
            let drained = std::mem::take(&mut guard.fedimint_pending_txs);
            let session_index = guard.fedimint_sessions.len() as u64;
            let finalized_txids = drained.iter().map(|(id, _)| *id).collect();
            guard.fedimint_sessions.push(SuiFedimintSessionEvent {
                session_index,
                finalized_txids,
                outputs_by_tx: drained,
            });
        }
        self.flush_locked(&guard)?;

        Ok(per_out_tickets)
    }

    pub fn lookup_fedimint_outpoint_ticket(&self, txid: [u8; 32], out_idx: u32) -> Option<[u8; 32]> {
        self.inner
            .read()
            .unwrap()
            .fedimint_outpoint_tickets
            .iter()
            .find(|(k, _)| *k == (txid, out_idx))
            .map(|(_, v)| *v)
    }

    pub fn fedimint_sessions(&self) -> Vec<SuiFedimintSessionEvent> {
        self.inner.read().unwrap().fedimint_sessions.clone()
    }

    pub fn lock_lnv2_outgoing_contract(
        &self,
        keyset_id: &str,
        inputs: Vec<SpendProofInput>,
        payment_hash: [u8; 32],
        claim_pk: XOnlyPubKey,
        refund_pk: XOnlyPubKey,
        expiry_epoch: u64,
    ) -> Result<Lnv2ContractOnChain, SdkError> {
        let mut guard = self.inner.write().unwrap();
        let (cfg, st) = guard
            .vaults
            .get_mut(keyset_id)
            .ok_or_else(|| SdkError::MoveAbort(format!("unknown keyset {keyset_id}")))?;

        let amount_msat = Self::verify_and_consume_inputs_locked(cfg, st, &inputs, &payment_hash)?;
        guard.checkpoint += 1;
        let cp = guard.checkpoint;

        let contract_id = Self::next_object_id(cp, b"LNV2_CONTRACT", &payment_hash);
        let approval_id = Self::next_object_id(cp, b"LNV2_TPE_APPROVAL", &contract_id);
        let approval = IbeApprovalOnChain {
            approval_id,
            keyset_id: keyset_id.to_string(),
            namespace: b"fedimint_lnv2".to_vec(),
            identity: contract_id.to_vec(),
            finalized_checkpoint: cp,
        };
        guard
            .ibe_approvals_hex
            .insert(hex::encode(approval_id), approval);

        let contract = Lnv2ContractOnChain {
            contract_id,
            keyset_id: keyset_id.to_string(),
            amount_msat,
            payment_hash,
            claim_pk,
            refund_pk,
            expiry_epoch,
            settled: false,
            preimage_approval_id: approval_id,
        };
        guard
            .lnv2_contracts_hex
            .insert(hex::encode(contract_id), contract.clone());
        self.flush_locked(&guard)?;
        Ok(contract)
    }

    pub fn claim_lnv2_contract_with_preimage(
        &self,
        contract_id: [u8; 32],
        preimage: &[u8; 32],
        gateway_sig: &SchnorrSig,
        out_slots: Vec<u8>,
        out_blinded: Vec<BlindedMessage>,
    ) -> Result<BlindTicketOnChain, SdkError> {
        for bm in &out_blinded {
            bm.to_g1()?;
        }
        let actual_hash: [u8; 32] = Sha256::digest(preimage).into();
        let cid_hex = hex::encode(contract_id);

        let mut guard = self.inner.write().unwrap();
        let contract = guard
            .lnv2_contracts_hex
            .get(&cid_hex)
            .cloned()
            .ok_or_else(|| SdkError::MoveAbort("unknown LNv2 contract".into()))?;
        if contract.settled {
            return Err(SdkError::MoveAbort("LNv2 contract already settled".into()));
        }
        if actual_hash != contract.payment_hash {
            return Err(SdkError::MoveAbort("invalid LNv2 preimage".into()));
        }
        verify_bip340_schnorr(&contract.claim_pk, &contract_id, gateway_sig)?;

        let (cfg, _) = guard
            .vaults
            .get(&contract.keyset_id)
            .ok_or_else(|| SdkError::MoveAbort("unknown keyset".into()))?;
        let out_sum = Self::slots_sum(&out_slots, cfg.keyset.num_slots())?;
        if out_sum != contract.amount_msat {
            return Err(SdkError::MoveAbort(
                "LNv2 claim output msat mismatch".into(),
            ));
        }

        guard.lnv2_contracts_hex.get_mut(&cid_hex).unwrap().settled = true;
        guard.checkpoint += 1;
        let cp = guard.checkpoint;
        let ticket_id = Self::next_object_id(cp, b"BLIND_TICKET_LNV2_CLAIM", &contract_id);
        let ticket = BlindTicketOnChain {
            ticket_id,
            keyset_id: contract.keyset_id,
            slots: out_slots,
            blinded_messages: out_blinded,
            finalized_checkpoint: cp,
        };
        Self::index_ticket_for_restore(&mut guard, &ticket);
        self.flush_locked(&guard)?;
        Ok(ticket)
    }
}

impl SuiConsensusBackend for EmbeddedMoveEngine {
    fn verify_and_load_blind_ticket<'a>(
        &'a self,
        keyset_id: &'a str,
        ticket_id: [u8; 32],
        _seal_approve_ptb_b64: Option<&'a str>,
    ) -> BoxFuture<'a, Result<BlindTicketOnChain, SdkError>> {
        Box::pin(async move {
            let guard = self.inner.read().unwrap();
            let ticket = guard
                .blind_tickets_hex
                .get(&hex::encode(ticket_id))
                .cloned()
                .ok_or_else(|| {
                    SdkError::MoveAbort(format!(
                        "BlindSigningTicket {} not found in finalized state",
                        hex::encode(ticket_id)
                    ))
                })?;
            if ticket.keyset_id != keyset_id {
                return Err(SdkError::MoveAbort(format!(
                    "ticket keyset mismatch: expected {keyset_id}, got {}",
                    ticket.keyset_id
                )));
            }
            if ticket.finalized_checkpoint > guard.checkpoint {
                return Err(SdkError::MoveAbort("ticket checkpoint not finalized".into()));
            }
            Ok(ticket)
        })
    }

    fn verify_and_load_ibe_approval<'a>(
        &'a self,
        keyset_id: &'a str,
        approval_id: [u8; 32],
        _seal_approve_ptb_b64: Option<&'a str>,
    ) -> BoxFuture<'a, Result<IbeApprovalOnChain, SdkError>> {
        Box::pin(async move {
            let guard = self.inner.read().unwrap();
            let app = guard
                .ibe_approvals_hex
                .get(&hex::encode(approval_id))
                .cloned()
                .ok_or_else(|| SdkError::MoveAbort("IBE approval not finalized".into()))?;
            if app.keyset_id != keyset_id {
                return Err(SdkError::MoveAbort("IBE approval keyset mismatch".into()));
            }
            Ok(app)
        })
    }
}

impl CashuConsensusBox for EmbeddedMoveEngine {
    fn box_deposit_and_create_ticket<'a>(
        &'a self,
        keyset_id: &'a str,
        deposit_coin_units: u64,
        slots: Vec<u8>,
        blinded_messages: Vec<BlindedMessage>,
    ) -> BoxFuture<'a, Result<BlindTicketOnChain, SdkError>> {
        Box::pin(async move {
            self.deposit_and_create_ticket(keyset_id, deposit_coin_units, slots, blinded_messages)
        })
    }

    fn box_atomic_swap<'a>(
        &'a self,
        keyset_id: &'a str,
        inputs: Vec<SpendProofInput>,
        out_slots: Vec<u8>,
        out_blinded: Vec<BlindedMessage>,
        explicit_fee_notes: Option<u64>,
        sighash_context: &'a [u8],
    ) -> BoxFuture<'a, Result<BlindTicketOnChain, SdkError>> {
        Box::pin(async move {
            self.atomic_swap(
                keyset_id,
                inputs,
                out_slots,
                out_blinded,
                explicit_fee_notes,
                sighash_context,
            )
        })
    }

    fn box_atomic_melt<'a>(
        &'a self,
        keyset_id: &'a str,
        inputs: Vec<SpendProofInput>,
        sighash_context: &'a [u8],
    ) -> BoxFuture<'a, Result<u64, SdkError>> {
        Box::pin(async move { self.atomic_melt(keyset_id, inputs, sighash_context) })
    }

    fn box_check_y_state<'a>(
        &'a self,
        keyset_id: &'a str,
        y_compressed_g1: &'a [u8],
    ) -> BoxFuture<'a, Result<NullifierStatus, SdkError>> {
        Box::pin(async move { self.check_y_state(keyset_id, y_compressed_g1) })
    }

    fn box_lookup_restore_ticket<'a>(
        &'a self,
        keyset_id: &'a str,
        b_hex: &'a str,
    ) -> BoxFuture<'a, Option<(BlindTicketOnChain, usize, u8)>> {
        Box::pin(async move { self.lookup_restore_ticket(keyset_id, b_hex) })
    }

    fn box_vault_reserve_coin_units<'a>(
        &'a self,
        keyset_id: &'a str,
    ) -> BoxFuture<'a, Result<u64, SdkError>> {
        Box::pin(async move { self.vault_reserve_coin_units(keyset_id) })
    }
}

/// Pluggable JSON-RPC transport so `LiveSuiJsonRpcBackend` runs against live HTTP Sui fullnodes
/// (`http://127.0.0.1:9000` / Sui Testnet) as well as deterministic in-process mock fullnodes in tests.
pub trait SuiJsonRpcTransport: Send + Sync {
    fn call<'a>(&'a self, payload: serde_json::Value) -> BoxFuture<'a, Result<serde_json::Value, SdkError>>;
}

pub struct ReqwestSuiRpcTransport {
    rpc_url: String,
    http: reqwest::Client,
}

impl SuiJsonRpcTransport for ReqwestSuiRpcTransport {
    fn call<'a>(&'a self, payload: serde_json::Value) -> BoxFuture<'a, Result<serde_json::Value, SdkError>> {
        Box::pin(async move {
            self.http
                .post(&self.rpc_url)
                .json(&payload)
                .send()
                .await
                .map_err(|e| SdkError::Rpc(e.to_string()))?
                .json()
                .await
                .map_err(|e| SdkError::Rpc(e.to_string()))
        })
    }
}

#[derive(Clone, Debug)]
pub struct SuiOnChainDeployment {
    pub blind_seal_pkg: SuiAddress,
    pub cowrie_cashu_pkg: SuiAddress,
    pub vault_object_id: SuiAddress,
    pub keyset_info_id: Option<SuiAddress>,
    pub asset_type: SuiTypeTag,
}

#[derive(Clone, Debug)]
pub struct SuiExecutionOutcome {
    pub tx_digest: String,
    pub ticket_id: Option<[u8; 32]>,
    pub created_objects: Vec<SuiAddress>,
}

#[derive(Default)]
struct LiveSuiBoxCache {
    restore_by_b_hex: HashMap<(String, String), (BlindTicketOnChain, usize, u8)>,
    spent_ys_hex: HashSet<String>,
}

#[derive(Clone)]
pub struct LiveSuiJsonRpcBackend {
    transport: Arc<dyn SuiJsonRpcTransport>,
    deployment: Option<SuiOnChainDeployment>,
    operator_signer: Option<SuiEd25519Signer>,
    live_cache: Arc<RwLock<LiveSuiBoxCache>>,
}

impl LiveSuiJsonRpcBackend {
    pub fn new(rpc_url: impl Into<String>) -> Self {
        Self {
            transport: Arc::new(ReqwestSuiRpcTransport {
                rpc_url: rpc_url.into(),
                http: reqwest::Client::new(),
            }),
            deployment: None,
            operator_signer: None,
            live_cache: Arc::new(RwLock::new(LiveSuiBoxCache::default())),
        }
    }

    pub fn with_transport(transport: Arc<dyn SuiJsonRpcTransport>) -> Self {
        Self {
            transport,
            deployment: None,
            operator_signer: None,
            live_cache: Arc::new(RwLock::new(LiveSuiBoxCache::default())),
        }
    }

    pub fn with_deployment(mut self, deployment: SuiOnChainDeployment) -> Self {
        self.deployment = Some(deployment);
        self
    }

    pub fn with_operator_signer(mut self, signer: SuiEd25519Signer) -> Self {
        self.operator_signer = Some(signer);
        self
    }

    pub fn deployment(&self) -> Option<&SuiOnChainDeployment> {
        self.deployment.as_ref()
    }

    pub fn operator_signer(&self) -> Option<&SuiEd25519Signer> {
        self.operator_signer.as_ref()
    }

    async fn rpc_call(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value, SdkError> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });
        let resp = self.transport.call(body).await?;
        if let Some(err) = resp.get("error") {
            return Err(SdkError::Rpc(format!("Sui JSON-RPC error in {method}: {err}")));
        }
        Ok(resp)
    }

    pub async fn get_reference_gas_price(&self) -> Result<u64, SdkError> {
        let resp = self.rpc_call("suix_getReferenceGasPrice", json!([])).await?;
        if let Some(s) = resp.get("result").and_then(|v| v.as_str()) {
            return s.parse::<u64>().map_err(|e| SdkError::Rpc(e.to_string()));
        }
        if let Some(n) = resp.get("result").and_then(|v| v.as_u64()) {
            return Ok(n);
        }
        Ok(1_000)
    }

    pub async fn get_owned_or_immutable_ref(&self, object_id: SuiAddress) -> Result<SuiObjectRef, SdkError> {
        let resp = self
            .rpc_call(
                "sui_getObject",
                json!([object_id.to_hex(), { "showOwner": true }]),
            )
            .await?;
        let data = resp
            .pointer("/result/data")
            .ok_or_else(|| SdkError::Rpc(format!("missing object data for {object_id}: {resp}")))?;
        let ver_val = data
            .get("version")
            .ok_or_else(|| SdkError::Rpc("missing object version".into()))?;
        let version = match ver_val.as_str() {
            Some(s) => s.parse::<u64>().map_err(|e| SdkError::Rpc(e.to_string()))?,
            None => ver_val.as_u64().unwrap_or(1),
        };
        let digest_str = data
            .get("digest")
            .and_then(|v| v.as_str())
            .ok_or_else(|| SdkError::Rpc("missing object digest".into()))?;
        Ok(SuiObjectRef {
            object_id,
            version,
            digest: SuiDigest::from_base58(digest_str)?,
        })
    }

    pub async fn get_shared_object_input(
        &self,
        object_id: SuiAddress,
        mutable: bool,
    ) -> Result<SharedObjectInput, SdkError> {
        let resp = self
            .rpc_call(
                "sui_getObject",
                json!([object_id.to_hex(), { "showOwner": true }]),
            )
            .await?;
        let init_v = resp
            .pointer("/result/data/owner/Shared/initial_shared_version")
            .ok_or_else(|| SdkError::Rpc(format!("object {object_id} is not Shared: {resp}")))?;
        let initial_shared_version = match init_v.as_str() {
            Some(s) => s.parse::<u64>().map_err(|e| SdkError::Rpc(e.to_string()))?,
            None => init_v.as_u64().unwrap_or(1),
        };
        Ok(SharedObjectInput {
            object_id,
            initial_shared_version,
            mutable,
        })
    }

    pub async fn select_gas_coin(
        &self,
        owner: SuiAddress,
        min_balance: u64,
    ) -> Result<SuiObjectRef, SdkError> {
        let resp = self
            .rpc_call("suix_getCoins", json!([owner.to_hex(), "0x2::sui::SUI"]))
            .await?;
        let coins = resp
            .pointer("/result/data")
            .and_then(|v| v.as_array())
            .ok_or_else(|| SdkError::Rpc(format!("missing coins array in {resp}")))?;
        for c in coins {
            let bal = c
                .get("balance")
                .and_then(|v| v.as_str().and_then(|s| s.parse::<u64>().ok()).or_else(|| v.as_u64()))
                .unwrap_or(0);
            if bal >= min_balance {
                let oid = c
                    .get("coinObjectId")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| SdkError::Rpc("missing coinObjectId".into()))?;
                let ver = c
                    .get("version")
                    .and_then(|v| v.as_str().and_then(|s| s.parse::<u64>().ok()).or_else(|| v.as_u64()))
                    .unwrap_or(1);
                let dig = c
                    .get("digest")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| SdkError::Rpc("missing coin digest".into()))?;
                return Ok(SuiObjectRef {
                    object_id: SuiAddress::from_hex(oid)?,
                    version: ver,
                    digest: SuiDigest::from_base58(dig)?,
                });
            }
        }
        Err(SdkError::Rpc(format!(
            "no SUI gas coin >= {min_balance} MIST found for {owner}"
        )))
    }

    /// Signs and executes a Programmable Transaction Block via `sui_executeTransactionBlock` (`WaitForLocalExecution`).
    pub async fn execute_ptb(
        &self,
        signer: &SuiEd25519Signer,
        ptb: ProgrammableTransaction,
        gas_budget: u64,
    ) -> Result<SuiExecutionOutcome, SdkError> {
        let sender = signer.sui_address();
        let gas_price = self.get_reference_gas_price().await?;
        let gas_coin = self.select_gas_coin(sender, gas_budget).await?;
        let tx_data = TransactionData::new_ptb(sender, ptb, vec![gas_coin], gas_price, gas_budget);
        let signed = signer.sign_transaction(&tx_data)?;

        let resp = self
            .rpc_call(
                "sui_executeTransactionBlock",
                json!([
                    signed.tx_bytes_b64,
                    [signed.signature_b64],
                    {
                        "showEffects": true,
                        "showEvents": true,
                        "showObjectChanges": true
                    },
                    "WaitForLocalExecution"
                ]),
            )
            .await?;

        let status = resp
            .pointer("/result/effects/status/status")
            .and_then(|v| v.as_str())
            .unwrap_or("failure");
        if status != "success" {
            return Err(SdkError::MoveAbort(format!(
                "sui_executeTransactionBlock failed: {resp}"
            )));
        }

        let tx_digest = resp
            .pointer("/result/digest")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| signed.tx_digest.to_base58());

        // Extract `ticket_id` from `TicketIssuedEvent` if emitted
        let mut ticket_id = None;
        if let Some(events) = resp.pointer("/result/events").and_then(|v| v.as_array()) {
            for ev in events {
                let ev_type = ev.get("type").and_then(|v| v.as_str()).unwrap_or_default();
                if ev_type.ends_with("::TicketIssuedEvent") {
                    if let Some(tid_str) = ev
                        .pointer("/parsedJson/ticket_id")
                        .and_then(|v| v.as_str())
                    {
                        ticket_id = Some(SuiAddress::from_hex(tid_str)?.0);
                    }
                }
            }
        }

        let mut created_objects = Vec::new();
        if let Some(changes) = resp
            .pointer("/result/objectChanges")
            .and_then(|v| v.as_array())
        {
            for ch in changes {
                if ch.get("type").and_then(|v| v.as_str()) == Some("created") {
                    if let Some(oid) = ch.get("objectId").and_then(|v| v.as_str()) {
                        if let Ok(addr) = SuiAddress::from_hex(oid) {
                            created_objects.push(addr);
                        }
                    }
                }
            }
        }

        Ok(SuiExecutionOutcome {
            tx_digest,
            ticket_id,
            created_objects,
        })
    }

    /// High-level helper submitting `cowrie_cashu::mint_vault::mint_from_sui` on-chain!
    pub async fn submit_mint_from_sui(
        &self,
        deposit_coin_units: u64,
        payment_coin: Option<SuiObjectRef>,
        out_slots: &[u8],
        out_blinded: &[BlindedMessage],
    ) -> Result<SuiExecutionOutcome, SdkError> {
        let dep = self
            .deployment
            .as_ref()
            .ok_or_else(|| SdkError::Rpc("missing SuiOnChainDeployment config".into()))?;
        let signer = self
            .operator_signer
            .as_ref()
            .ok_or_else(|| SdkError::Rpc("missing operator SuiEd25519Signer".into()))?;
        let vault_shared = self
            .get_shared_object_input(dep.vault_object_id, true)
            .await?;
        let raw_bm: Vec<Vec<u8>> = out_blinded.iter().map(|b| b.as_bytes().to_vec()).collect();
        let ptb = build_mint_from_sui_ptb(
            dep.cowrie_cashu_pkg,
            dep.asset_type.clone(),
            vault_shared,
            payment_coin,
            deposit_coin_units,
            out_slots,
            &raw_bm,
        )?;
        self.execute_ptb(signer, ptb, 50_000_000).await
    }

    /// High-level helper submitting `cowrie_cashu::mint_vault::swap_native_dst` on-chain!
    #[allow(clippy::too_many_arguments)]
    pub async fn submit_swap_native_dst(
        &self,
        in_slots: &[u8],
        secrets: &[Vec<u8>],
        raw_sigs_g1: &[Vec<u8>],
        p2pk_pubkeys: &[Vec<u8>],
        p2pk_sigs: &[Vec<u8>],
        out_slots: &[u8],
        out_blinded: &[BlindedMessage],
        fee_notes: u64,
        sighash_context: &[u8],
    ) -> Result<SuiExecutionOutcome, SdkError> {
        let dep = self
            .deployment
            .as_ref()
            .ok_or_else(|| SdkError::Rpc("missing SuiOnChainDeployment config".into()))?;
        let signer = self
            .operator_signer
            .as_ref()
            .ok_or_else(|| SdkError::Rpc("missing operator SuiEd25519Signer".into()))?;
        let ks_id = dep
            .keyset_info_id
            .ok_or_else(|| SdkError::Rpc("missing keyset_info_id in deployment".into()))?;
        let vault_shared = self
            .get_shared_object_input(dep.vault_object_id, true)
            .await?;
        let ks_ref = self.get_owned_or_immutable_ref(ks_id).await?;
        let raw_bm: Vec<Vec<u8>> = out_blinded.iter().map(|b| b.as_bytes().to_vec()).collect();
        let ptb = build_swap_native_dst_ptb(
            dep.cowrie_cashu_pkg,
            dep.asset_type.clone(),
            vault_shared,
            ks_ref,
            in_slots,
            secrets,
            raw_sigs_g1,
            p2pk_pubkeys,
            p2pk_sigs,
            out_slots,
            &raw_bm,
            fee_notes,
            sighash_context,
        )?;
        self.execute_ptb(signer, ptb, 50_000_000).await
    }

    /// High-level helper submitting `cowrie_cashu::mint_vault::melt_native_dst` on-chain!
    #[allow(clippy::too_many_arguments)]
    pub async fn submit_melt_native_dst(
        &self,
        in_slots: &[u8],
        secrets: &[Vec<u8>],
        raw_sigs_g1: &[Vec<u8>],
        p2pk_pubkeys: &[Vec<u8>],
        p2pk_sigs: &[Vec<u8>],
        recipient: SuiAddress,
        sighash_context: &[u8],
    ) -> Result<SuiExecutionOutcome, SdkError> {
        let dep = self
            .deployment
            .as_ref()
            .ok_or_else(|| SdkError::Rpc("missing SuiOnChainDeployment config".into()))?;
        let signer = self
            .operator_signer
            .as_ref()
            .ok_or_else(|| SdkError::Rpc("missing operator SuiEd25519Signer".into()))?;
        let ks_id = dep
            .keyset_info_id
            .ok_or_else(|| SdkError::Rpc("missing keyset_info_id in deployment".into()))?;
        let vault_shared = self
            .get_shared_object_input(dep.vault_object_id, true)
            .await?;
        let ks_ref = self.get_owned_or_immutable_ref(ks_id).await?;
        let ptb = build_melt_native_dst_ptb(
            dep.cowrie_cashu_pkg,
            dep.asset_type.clone(),
            vault_shared,
            ks_ref,
            in_slots,
            secrets,
            raw_sigs_g1,
            p2pk_pubkeys,
            p2pk_sigs,
            recipient,
            sighash_context,
        )?;
        self.execute_ptb(signer, ptb, 50_000_000).await
    }

    async fn dry_run_ptb(&self, ptb_b64: &str) -> Result<(), SdkError> {
        let resp = self
            .rpc_call("sui_dryRunTransactionBlock", json!([ptb_b64]))
            .await?;
        let status = resp
            .pointer("/result/effects/status/status")
            .and_then(|v| v.as_str())
            .unwrap_or("failure");
        if status != "success" {
            return Err(SdkError::MoveAbort(format!(
                "seal_approve dry_run failed on Sui RPC: {resp}"
            )));
        }
        Ok(())
    }
}

fn parse_sui_vec_u8_or_str(val: Option<&serde_json::Value>) -> Result<Vec<u8>, SdkError> {
    let Some(v) = val else {
        return Ok(Vec::new());
    };
    if let Some(s) = v.as_str() {
        return Ok(s.as_bytes().to_vec());
    }
    serde_json::from_value(v.clone()).map_err(|e| SdkError::Rpc(e.to_string()))
}

fn parse_sui_element_g1_vec(val: Option<&serde_json::Value>) -> Result<Vec<Vec<u8>>, SdkError> {
    let Some(arr) = val.and_then(|v| v.as_array()) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        // Sui JSON-RPC serializes `sui::group_ops::Element<G1>` either as `{"fields": {"bytes": [...]}}` or raw `[...]`
        if let Some(inner) = item.pointer("/fields/bytes").or_else(|| item.get("bytes")) {
            let b: Vec<u8> =
                serde_json::from_value(inner.clone()).map_err(|e| SdkError::Rpc(e.to_string()))?;
            out.push(b);
        } else {
            let b: Vec<u8> =
                serde_json::from_value(item.clone()).map_err(|e| SdkError::Rpc(e.to_string()))?;
            out.push(b);
        }
    }
    Ok(out)
}

impl SuiConsensusBackend for LiveSuiJsonRpcBackend {
    fn verify_and_load_blind_ticket<'a>(
        &'a self,
        keyset_id: &'a str,
        ticket_id: [u8; 32],
        seal_approve_ptb_b64: Option<&'a str>,
    ) -> BoxFuture<'a, Result<BlindTicketOnChain, SdkError>> {
        Box::pin(async move {
            let ptb_owned: String;
            let ptb = match seal_approve_ptb_b64 {
                Some(s) => s,
                None => {
                    // Auto-synthesize `seal_approve_blind_sign` dry-run PTB if deployment metadata is configured!
                    let dep = self.deployment.as_ref().ok_or_else(|| {
                        SdkError::MoveAbort(
                            "live Sui backend requires seal_approve_ptb_b64 or configured SuiOnChainDeployment"
                                .into(),
                        )
                    })?;
                    let ticket_ref = self.get_owned_or_immutable_ref(SuiAddress(ticket_id)).await?;
                    let gas_price = self.get_reference_gas_price().await?;
                    let sender = self
                        .operator_signer
                        .as_ref()
                        .map(SuiEd25519Signer::sui_address)
                        .unwrap_or_default();
                    ptb_owned = build_seal_approve_blind_sign_tx_b64(
                        dep.blind_seal_pkg,
                        sender,
                        ticket_ref,
                        keyset_id,
                        gas_price,
                    )?;
                    ptb_owned.as_str()
                }
            };
            self.dry_run_ptb(ptb).await?;

            let obj_id = format!("0x{}", hex::encode(ticket_id));
            let resp = self
                .rpc_call("sui_getObject", json!([obj_id, { "showContent": true }]))
                .await?;

            let fields = resp
                .pointer("/result/data/content/fields")
                .ok_or_else(|| SdkError::Rpc(format!("missing object fields in {resp}")))?;
            let onchain_ks_bytes = parse_sui_vec_u8_or_str(fields.get("keyset_id"))?;
            if onchain_ks_bytes != keyset_id.as_bytes() {
                return Err(SdkError::MoveAbort("on-chain keyset_id mismatch".into()));
            }

            let slots: Vec<u8> =
                serde_json::from_value(fields.get("slots").cloned().unwrap_or(json!([])))
                    .map_err(|e| SdkError::Rpc(e.to_string()))?;
            let raw_pts = parse_sui_element_g1_vec(fields.get("blinded_messages"))?;

            Ok(BlindTicketOnChain {
                ticket_id,
                keyset_id: keyset_id.to_string(),
                slots,
                blinded_messages: raw_pts.into_iter().map(BlindedMessage).collect(),
                finalized_checkpoint: 1,
            })
        })
    }

    fn verify_and_load_ibe_approval<'a>(
        &'a self,
        keyset_id: &'a str,
        approval_id: [u8; 32],
        seal_approve_ptb_b64: Option<&'a str>,
    ) -> BoxFuture<'a, Result<IbeApprovalOnChain, SdkError>> {
        Box::pin(async move {
            let obj_id = format!("0x{}", hex::encode(approval_id));
            let resp = self
                .rpc_call("sui_getObject", json!([obj_id, { "showContent": true }]))
                .await?;
            let fields = resp
                .pointer("/result/data/content/fields")
                .ok_or_else(|| SdkError::Rpc(format!("missing IBE approval fields: {resp}")))?;
            let onchain_ks = parse_sui_vec_u8_or_str(fields.get("keyset_id"))?;
            if onchain_ks != keyset_id.as_bytes() {
                return Err(SdkError::MoveAbort("IBE approval keyset_id mismatch".into()));
            }
            let namespace = parse_sui_vec_u8_or_str(fields.get("namespace"))?;
            let identity = parse_sui_vec_u8_or_str(fields.get("identity"))?;

            let ptb_owned: String;
            let ptb = match seal_approve_ptb_b64 {
                Some(s) => s,
                None => {
                    let dep = self.deployment.as_ref().ok_or_else(|| {
                        SdkError::MoveAbort("live Sui backend requires seal_approve_ptb_b64".into())
                    })?;
                    let app_ref = self
                        .get_owned_or_immutable_ref(SuiAddress(approval_id))
                        .await?;
                    let gas_price = self.get_reference_gas_price().await?;
                    let sender = self
                        .operator_signer
                        .as_ref()
                        .map(SuiEd25519Signer::sui_address)
                        .unwrap_or_default();
                    ptb_owned = build_seal_approve_ibe_tx_b64(
                        dep.blind_seal_pkg,
                        sender,
                        &identity,
                        app_ref,
                        keyset_id,
                        gas_price,
                    )?;
                    ptb_owned.as_str()
                }
            };
            self.dry_run_ptb(ptb).await?;

            Ok(IbeApprovalOnChain {
                approval_id,
                keyset_id: keyset_id.to_string(),
                namespace,
                identity,
                finalized_checkpoint: 1,
            })
        })
    }
}

impl LiveSuiJsonRpcBackend {
    fn index_live_ticket(&self, ticket: &BlindTicketOnChain) {
        let mut guard = self.live_cache.write().unwrap();
        for (idx, (&slot, bm)) in ticket
            .slots
            .iter()
            .zip(ticket.blinded_messages.iter())
            .enumerate()
        {
            guard.restore_by_b_hex.insert(
                (ticket.keyset_id.clone(), hex::encode(bm.as_bytes())),
                (ticket.clone(), idx, slot),
            );
        }
    }
}

impl CashuConsensusBox for LiveSuiJsonRpcBackend {
    fn box_deposit_and_create_ticket<'a>(
        &'a self,
        keyset_id: &'a str,
        deposit_coin_units: u64,
        slots: Vec<u8>,
        blinded_messages: Vec<BlindedMessage>,
    ) -> BoxFuture<'a, Result<BlindTicketOnChain, SdkError>> {
        Box::pin(async move {
            let outcome = self
                .submit_mint_from_sui(deposit_coin_units, None, &slots, &blinded_messages)
                .await?;
            let ticket_id = outcome
                .ticket_id
                .or_else(|| outcome.created_objects.first().map(|a| a.0))
                .ok_or_else(|| SdkError::Rpc("Sui mint tx produced no BlindSigningTicket ID".into()))?;
            let ticket = BlindTicketOnChain {
                ticket_id,
                keyset_id: keyset_id.to_string(),
                slots,
                blinded_messages,
                finalized_checkpoint: 1,
            };
            self.index_live_ticket(&ticket);
            Ok(ticket)
        })
    }

    fn box_atomic_swap<'a>(
        &'a self,
        keyset_id: &'a str,
        inputs: Vec<SpendProofInput>,
        out_slots: Vec<u8>,
        out_blinded: Vec<BlindedMessage>,
        explicit_fee_notes: Option<u64>,
        sighash_context: &'a [u8],
    ) -> BoxFuture<'a, Result<BlindTicketOnChain, SdkError>> {
        Box::pin(async move {
            let in_slots: Vec<u8> = inputs.iter().map(|i| i.slot).collect();
            let secrets: Vec<Vec<u8>> = inputs.iter().map(|i| i.secret_or_nonce.clone()).collect();
            let raw_sigs: Vec<Vec<u8>> = inputs
                .iter()
                .map(|i| i.signature.as_bytes().to_vec())
                .collect();
            let mut p2pk_pks = Vec::new();
            let mut p2pk_sigs = Vec::new();
            for inp in &inputs {
                if let Some((pk, sig)) = &inp.schnorr_lock {
                    p2pk_pks.push(pk.0.to_vec());
                    p2pk_sigs.push(sig.0.clone());
                }
            }
            let in_total: u64 = in_slots.iter().map(|&s| 1u64 << s).sum();
            let out_total: u64 = out_slots.iter().map(|&s| 1u64 << s).sum();
            let fee_notes = explicit_fee_notes.unwrap_or_else(|| in_total.saturating_sub(out_total));

            let outcome = self
                .submit_swap_native_dst(
                    &in_slots,
                    &secrets,
                    &raw_sigs,
                    &p2pk_pks,
                    &p2pk_sigs,
                    &out_slots,
                    &out_blinded,
                    fee_notes,
                    sighash_context,
                )
                .await?;
            {
                let mut guard = self.live_cache.write().unwrap();
                for sec in &secrets {
                    let y = hash_secret_to_y_bytes(sec, &DstProfile::SuiNative);
                    guard.spent_ys_hex.insert(hex::encode(y));
                }
            }
            let ticket_id = outcome
                .ticket_id
                .or_else(|| outcome.created_objects.first().map(|a| a.0))
                .ok_or_else(|| SdkError::Rpc("Sui swap tx produced no BlindSigningTicket ID".into()))?;
            let ticket = BlindTicketOnChain {
                ticket_id,
                keyset_id: keyset_id.to_string(),
                slots: out_slots,
                blinded_messages: out_blinded,
                finalized_checkpoint: 1,
            };
            self.index_live_ticket(&ticket);
            Ok(ticket)
        })
    }

    fn box_atomic_melt<'a>(
        &'a self,
        _keyset_id: &'a str,
        inputs: Vec<SpendProofInput>,
        sighash_context: &'a [u8],
    ) -> BoxFuture<'a, Result<u64, SdkError>> {
        Box::pin(async move {
            let in_slots: Vec<u8> = inputs.iter().map(|i| i.slot).collect();
            let secrets: Vec<Vec<u8>> = inputs.iter().map(|i| i.secret_or_nonce.clone()).collect();
            let raw_sigs: Vec<Vec<u8>> = inputs
                .iter()
                .map(|i| i.signature.as_bytes().to_vec())
                .collect();
            let mut p2pk_pks = Vec::new();
            let mut p2pk_sigs = Vec::new();
            for inp in &inputs {
                if let Some((pk, sig)) = &inp.schnorr_lock {
                    p2pk_pks.push(pk.0.to_vec());
                    p2pk_sigs.push(sig.0.clone());
                }
            }
            let recipient = self
                .operator_signer
                .as_ref()
                .map(SuiEd25519Signer::sui_address)
                .unwrap_or_default();
            let total_in: u64 = in_slots.iter().map(|&s| 1u64 << s).sum();
            self.submit_melt_native_dst(
                &in_slots,
                &secrets,
                &raw_sigs,
                &p2pk_pks,
                &p2pk_sigs,
                recipient,
                sighash_context,
            )
            .await?;
            {
                let mut guard = self.live_cache.write().unwrap();
                for sec in &secrets {
                    let y = hash_secret_to_y_bytes(sec, &DstProfile::SuiNative);
                    guard.spent_ys_hex.insert(hex::encode(y));
                }
            }
            Ok(total_in)
        })
    }

    fn box_check_y_state<'a>(
        &'a self,
        _keyset_id: &'a str,
        y_compressed_g1: &'a [u8],
    ) -> BoxFuture<'a, Result<NullifierStatus, SdkError>> {
        Box::pin(async move {
            let y_hex = hex::encode(y_compressed_g1);
            if self.live_cache.read().unwrap().spent_ys_hex.contains(&y_hex) {
                return Ok(NullifierStatus::Spent);
            }
            let Some(dep) = &self.deployment else {
                return Ok(NullifierStatus::Unspent);
            };
            let v_resp = self
                .rpc_call(
                    "sui_getObject",
                    json!([dep.vault_object_id.to_hex(), { "showContent": true }]),
                )
                .await?;
            let Some(table_id) = v_resp
                .pointer("/result/data/content/fields/spent_ys/fields/id/id")
                .and_then(|v| v.as_str())
            else {
                return Ok(NullifierStatus::Unspent);
            };
            let df_resp = self
                .rpc_call(
                    "suix_getDynamicFieldObject",
                    json!([table_id, { "type": "vector<u8>", "value": y_compressed_g1 }]),
                )
                .await;
            if let Ok(val) = df_resp {
                if val.pointer("/result/data").is_some() {
                    return Ok(NullifierStatus::Spent);
                }
            }
            Ok(NullifierStatus::Unspent)
        })
    }

    fn box_lookup_restore_ticket<'a>(
        &'a self,
        keyset_id: &'a str,
        b_hex: &'a str,
    ) -> BoxFuture<'a, Option<(BlindTicketOnChain, usize, u8)>> {
        Box::pin(async move {
            self.live_cache
                .read()
                .unwrap()
                .restore_by_b_hex
                .get(&(keyset_id.to_string(), b_hex.to_lowercase()))
                .cloned()
        })
    }

    fn box_vault_reserve_coin_units<'a>(
        &'a self,
        _keyset_id: &'a str,
    ) -> BoxFuture<'a, Result<u64, SdkError>> {
        Box::pin(async move {
            let Some(dep) = &self.deployment else {
                return Ok(0);
            };
            let resp = self
                .rpc_call(
                    "sui_getObject",
                    json!([dep.vault_object_id.to_hex(), { "showContent": true }]),
                )
                .await?;
            let bal_val = resp.pointer("/result/data/content/fields/reserve");
            let bal = bal_val
                .and_then(|v| {
                    v.as_str()
                        .and_then(|s| s.parse::<u64>().ok())
                        .or_else(|| v.as_u64())
                        .or_else(|| {
                            v.pointer("/fields/value")
                                .and_then(|iv| iv.as_str().and_then(|s| s.parse::<u64>().ok()).or_else(|| iv.as_u64()))
                        })
                })
                .unwrap_or(0);
            Ok(bal)
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use base64::{engine::general_purpose::STANDARD as B64_STD, Engine};
    use blind_seal_crypto::{dst::DstProfile, tbs::blind_message};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use serde_json::json;

    use super::*;
    use crate::ptb::verify_sui_ed25519_signature;

    struct MockSuiFullnode {
        expected_sender: SuiAddress,
        blinded_g1: Vec<u8>,
        ticket_id: [u8; 32],
    }

    impl SuiJsonRpcTransport for MockSuiFullnode {
        fn call<'a>(
            &'a self,
            payload: serde_json::Value,
        ) -> BoxFuture<'a, Result<serde_json::Value, SdkError>> {
            Box::pin(async move {
                let method = payload
                    .get("method")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                match method {
                    "suix_getReferenceGasPrice" => Ok(json!({ "jsonrpc": "2.0", "id": 1, "result": "1000" })),
                    "suix_getCoins" => Ok(json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "result": {
                            "data": [{
                                "coinObjectId": "0x0000000000000000000000000000000000000000000000000000000000009999",
                                "version": "7",
                                "digest": SuiDigest([0x44u8; 32]).to_base58(),
                                "balance": "5000000000"
                            }]
                        }
                    })),
                    "sui_getObject" => {
                        let oid = payload
                            .pointer("/params/0")
                            .and_then(|v| v.as_str())
                            .unwrap_or_default();
                        if oid.ends_with("aaaa") {
                            Ok(json!({
                                "jsonrpc": "2.0",
                                "id": 1,
                                "result": {
                                    "data": {
                                        "objectId": oid,
                                        "version": "12",
                                        "digest": SuiDigest([0x55u8; 32]).to_base58(),
                                        "owner": { "Shared": { "initial_shared_version": 3 } }
                                    }
                                }
                            }))
                        } else {
                            Ok(json!({
                                "jsonrpc": "2.0",
                                "id": 1,
                                "result": {
                                    "data": {
                                        "objectId": oid,
                                        "version": "15",
                                        "digest": SuiDigest([0x66u8; 32]).to_base58(),
                                        "owner": "Immutable",
                                        "content": {
                                            "fields": {
                                                "keyset_id": b"02cowriesui00001".to_vec(),
                                                "slots": [3u8],
                                                "blinded_messages": [
                                                    { "fields": { "bytes": self.blinded_g1 } }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }))
                        }
                    }
                    "sui_executeTransactionBlock" => {
                        let tx_b64 = payload
                            .pointer("/params/0")
                            .and_then(|v| v.as_str())
                            .unwrap();
                        let sig_b64 = payload
                            .pointer("/params/1/0")
                            .and_then(|v| v.as_str())
                            .unwrap();
                        // Verify both BCS deserialization of TransactionData AND 97-byte Ed25519 intent signature!
                        let raw_tx = B64_STD.decode(tx_b64).unwrap();
                        let decoded_tx: TransactionData = bcs::from_bytes(&raw_tx).unwrap();
                        let TransactionData::V1(v1) = decoded_tx;
                        assert_eq!(v1.sender, self.expected_sender);
                        let recovered = verify_sui_ed25519_signature(tx_b64, sig_b64).unwrap();
                        assert_eq!(recovered, self.expected_sender);

                        Ok(json!({
                            "jsonrpc": "2.0",
                            "id": 1,
                            "result": {
                                "digest": SuiDigest([0x88u8; 32]).to_base58(),
                                "effects": { "status": { "status": "success" } },
                                "events": [{
                                    "type": "0x1111::mint_vault::TicketIssuedEvent",
                                    "parsedJson": {
                                        "ticket_id": SuiAddress(self.ticket_id).to_hex(),
                                        "note_amount": "8"
                                    }
                                }],
                                "objectChanges": [{
                                    "type": "created",
                                    "objectId": SuiAddress(self.ticket_id).to_hex()
                                }]
                            }
                        }))
                    }
                    "sui_dryRunTransactionBlock" => {
                        let tx_b64 = payload
                            .pointer("/params/0")
                            .and_then(|v| v.as_str())
                            .unwrap();
                        let raw_tx = B64_STD.decode(tx_b64).unwrap();
                        let _decoded_tx: TransactionData = bcs::from_bytes(&raw_tx).unwrap();
                        Ok(json!({
                            "jsonrpc": "2.0",
                            "id": 1,
                            "result": { "effects": { "status": { "status": "success" } } }
                        }))
                    }
                    other => Err(SdkError::Rpc(format!("unhandled mock method {other}"))),
                }
            })
        }
    }

    #[tokio::test]
    async fn test_sui_ptb_bcs_bech32_signer_and_live_jsonrpc_backend() {
        let signer = SuiEd25519Signer::from_seed([0x42u8; 32]);
        let bech32_key = signer.to_sui_privkey_bech32().unwrap();
        assert!(bech32_key.starts_with("suiprivkey1"));
        let parsed = SuiEd25519Signer::parse_sui_key(&bech32_key).unwrap();
        assert_eq!(parsed.sui_address(), signer.sui_address());

        let mut rng = ChaCha20Rng::from_seed([0x19u8; 32]);
        let (bm, _) = blind_message(b"sui_ptb_note", &DstProfile::SuiNative, &mut rng).unwrap();
        let ticket_id = [0xCCu8; 32];

        let mock = Arc::new(MockSuiFullnode {
            expected_sender: signer.sui_address(),
            blinded_g1: bm.as_bytes().to_vec(),
            ticket_id,
        });

        let backend = LiveSuiJsonRpcBackend::with_transport(mock)
            .with_deployment(SuiOnChainDeployment {
                blind_seal_pkg: SuiAddress::from_hex("0x1110").unwrap(),
                cowrie_cashu_pkg: SuiAddress::from_hex("0x1111").unwrap(),
                vault_object_id: SuiAddress::from_hex("0xaaaa").unwrap(),
                keyset_info_id: Some(SuiAddress::from_hex("0xbbbb").unwrap()),
                asset_type: SuiTypeTag::parse_struct("0x2::sui::SUI").unwrap(),
            })
            .with_operator_signer(signer);

        let exec = backend
            .submit_mint_from_sui(8, None, &[3], &[bm.clone()])
            .await
            .unwrap();
        assert_eq!(exec.ticket_id, Some(ticket_id));

        // Now verify guardian `verify_and_load_blind_ticket` auto-builds `seal_approve_blind_sign` PTB,
        // dry-runs it, and parses Sui Move `Element<G1>` fields!
        let loaded = backend
            .verify_and_load_blind_ticket("02cowriesui00001", ticket_id, None)
            .await
            .unwrap();
        assert_eq!(loaded.slots, vec![3]);
        assert_eq!(loaded.blinded_messages, vec![bm]);
    }
}
