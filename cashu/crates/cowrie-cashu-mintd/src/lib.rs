pub mod dashboard;
pub mod lnbits;
pub mod nuts;
pub mod ws_nut17;

use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, RwLock},
};

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use blind_seal_crypto::{
    dkg::PublicKeyset,
    dst::DstProfile,
    schnorr::{SchnorrSig, XOnlyPubKey},
    tbs::{hash_secret_to_y_bytes, BlindedMessage, UnblindedSignature},
};
use blind_seal_sdk::{
    client::BlindSealClient,
    sui_backend::{CashuConsensusBox, NullifierStatus, SpendProofInput},
    SdkError,
};
use nuts::{
    amount_to_power_of_two_slot, nut11_sig_all_melt_digest, nut11_sig_all_swap_digest,
    nut11_sig_inputs_digest, CashuBlindSignature, CashuBlindedMessage, CashuErrorResponse,
    CashuProof, CashuTokenV4, MeltQuoteState, MintQuoteState, Nut01KeysResponse, Nut01KeysetKeys,
    Nut02KeysetDescriptor, Nut02KeysetsResponse, Nut03SwapRequest, Nut04MintExecuteRequest,
    Nut04MintQuoteRequest, Nut04MintQuoteResponse, Nut05MeltExecuteRequest, Nut05MeltQuoteRequest,
    Nut05MeltQuoteResponse, Nut07CheckStateRequest, Nut07CheckStateResponse, Nut07StateEntry,
    Nut09RestoreRequest, Nut09RestoreResponse, Nut10Condition, Nut10WitnessPayload,
    NutSignaturesResponse, ProofStateFlag, ERR_KEYSET_UNKNOWN, ERR_LIGHTNING_OR_BACKEND,
    ERR_QUOTE_ALREADY_ISSUED, ERR_QUOTE_NOT_PAID, ERR_TOKEN_ALREADY_SPENT, ERR_TX_NOT_BALANCED,
    ERR_WITNESS_OR_SIG_INVALID,
};
use rand::{rngs::OsRng, RngCore};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::sync::broadcast;
use ws_nut17::{handle_nut17_ws_upgrade, Nut17Event};

#[derive(Clone, Debug)]
pub struct MintQuoteRecord {
    pub method: String,
    pub quote_id: String,
    pub request: String,
    pub amount: u64,
    pub unit: String,
    pub state: MintQuoteState,
    pub expiry: u64,
}

#[derive(Clone, Debug)]
pub struct MeltQuoteRecord {
    pub method: String,
    pub quote_id: String,
    pub request: String,
    pub amount: u64,
    pub fee_reserve: u64,
    pub unit: String,
    pub state: MeltQuoteState,
    pub expiry: u64,
    pub payment_preimage: [u8; 32],
}

/// Pluggable Lightning settlement backend (`FakeWallet` / regtest / LND / CLN) for `NUT-23` `bolt11`.
pub trait Bolt11Backend: Send + Sync {
    fn create_invoice(&self, amount: u64, unit: &str, quote_id: &str) -> String;
    fn is_invoice_paid(&self, quote_id: &str) -> bool;
    fn pay_invoice(&self, bolt11: &str) -> Result<([u8; 32], u64), String>;
}

/// Built-in deterministic instant-settlement Lightning backend (analogous to CDK's `FakeWallet`),
/// enabling zero-setup Bitcoin `sat` `bolt11` minting & melting demos out of the box!
#[derive(Default)]
pub struct InstantBolt11Backend {
    unpaid_overrides: RwLock< std::collections::HashSet<String> >,
}

impl InstantBolt11Backend {
    pub fn set_unpaid(&self, quote_id: impl Into<String>) {
        self.unpaid_overrides.write().unwrap().insert(quote_id.into());
    }

    pub fn mark_paid(&self, quote_id: &str) {
        self.unpaid_overrides.write().unwrap().remove(quote_id);
    }
}

impl Bolt11Backend for InstantBolt11Backend {
    fn create_invoice(&self, amount: u64, unit: &str, quote_id: &str) -> String {
        format!("lnbc{amount}{unit}1p_cowrie_{quote_id}")
    }

    fn is_invoice_paid(&self, quote_id: &str) -> bool {
        !self.unpaid_overrides.read().unwrap().contains(quote_id)
    }

    fn pay_invoice(&self, bolt11: &str) -> Result<([u8; 32], u64), String> {
        let preimage: [u8; 32] = Sha256::digest(bolt11.as_bytes()).into();
        Ok((preimage, 0))
    }
}

#[derive(Clone)]
pub struct KeysetRuntimeMeta {
    pub keyset: PublicKeyset,
    pub dst: DstProfile,
    pub input_fee_ppk: u64,
}

/// Stateless Federated Cashu Coordinator (`Cowrie`) backed by:
/// 1. `CashuConsensusBox` (`EmbeddedMoveEngine` standalone OR live Sui Move `cowrie_cashu::mint_vault`).
/// 2. `BlindSealClient` ($t$-of-$n$ threshold `BLS12-381` key servers).
#[derive(Clone)]
pub struct SealCashuMint {
    pub mint_name: String,
    pub keysets: Arc<BTreeMap<String, KeysetRuntimeMeta>>,
    pub move_box: Arc<dyn CashuConsensusBox>,
    pub seal_client: BlindSealClient,
    pub bolt11_backend: Arc<dyn Bolt11Backend>,
    mint_quotes: Arc<RwLock<HashMap<String, MintQuoteRecord>>>,
    melt_quotes: Arc<RwLock<HashMap<String, MeltQuoteRecord>>>,
    nut17_tx: broadcast::Sender<Nut17Event>,
}

impl SealCashuMint {
    pub fn new(
        mint_name: impl Into<String>,
        keysets: Vec<(PublicKeyset, DstProfile)>,
        move_box: Arc<dyn CashuConsensusBox>,
        seal_client: BlindSealClient,
    ) -> Self {
        Self::new_with_bolt11(
            mint_name,
            keysets
                .into_iter()
                .map(|(keyset, dst)| KeysetRuntimeMeta {
                    keyset,
                    dst,
                    input_fee_ppk: 0,
                })
                .collect(),
            move_box,
            seal_client,
            Arc::new(InstantBolt11Backend::default()),
        )
    }

    pub fn new_with_bolt11(
        mint_name: impl Into<String>,
        keysets: Vec<KeysetRuntimeMeta>,
        move_box: Arc<dyn CashuConsensusBox>,
        seal_client: BlindSealClient,
        bolt11_backend: Arc<dyn Bolt11Backend>,
    ) -> Self {
        let mut map = BTreeMap::new();
        for meta in keysets {
            map.insert(meta.keyset.keyset_id.clone(), meta);
        }
        let (nut17_tx, _) = broadcast::channel(512);
        Self {
            mint_name: mint_name.into(),
            keysets: Arc::new(map),
            move_box,
            seal_client,
            bolt11_backend,
            mint_quotes: Arc::new(RwLock::new(HashMap::new())),
            melt_quotes: Arc::new(RwLock::new(HashMap::new())),
            nut17_tx,
        }
    }

    pub fn subscribe_nut17(&self) -> broadcast::Receiver<Nut17Event> {
        self.nut17_tx.subscribe()
    }

    pub fn router(self) -> Router {
        Router::new()
            .route("/v1/info", get(handle_info))
            .route("/v1/ws", get(handle_nut17_ws_upgrade))
            .route("/v1/keys", get(handle_keys))
            .route("/v1/keys/{keyset_id}", get(handle_keys_by_id))
            .route("/v1/keysets", get(handle_keysets))
            .route("/v1/swap", post(handle_swap))
            .route("/v1/checkstate", post(handle_checkstate))
            .route("/v1/restore", post(handle_restore))
            .route("/v1/mint/quote/{method}", post(handle_create_mint_quote))
            .route(
                "/v1/mint/quote/{method}/{quote_id}",
                get(handle_get_mint_quote),
            )
            .route("/v1/mint/{method}", post(handle_execute_mint))
            .route("/v1/melt/quote/{method}", post(handle_create_melt_quote))
            .route(
                "/v1/melt/quote/{method}/{quote_id}",
                get(handle_get_melt_quote),
            )
            .route("/v1/melt/{method}", post(handle_execute_melt))
            .with_state(self)
    }

    pub fn get_keys(&self) -> Nut01KeysResponse {
        let keysets = self
            .keysets
            .values()
            .map(Self::format_nut01_keys)
            .collect();
        Nut01KeysResponse { keysets }
    }

    pub fn get_keys_for_id(&self, keyset_id: &str) -> Result<Nut01KeysResponse, CashuErrorResponse> {
        let meta = self.keysets.get(keyset_id).ok_or_else(|| CashuErrorResponse {
            detail: format!("unknown keyset id {keyset_id}"),
            code: ERR_KEYSET_UNKNOWN,
        })?;
        Ok(Nut01KeysResponse {
            keysets: vec![Self::format_nut01_keys(meta)],
        })
    }

    fn format_nut01_keys(meta: &KeysetRuntimeMeta) -> Nut01KeysetKeys {
        let mut keys = BTreeMap::new();
        for (slot, pk) in meta.keyset.slot_agg_pks.iter().enumerate() {
            keys.insert(1u64 << slot, hex::encode(pk.as_bytes()));
        }
        Nut01KeysetKeys {
            id: meta.keyset.keyset_id.clone(),
            unit: meta.keyset.unit.clone(),
            keys,
        }
    }

    pub fn get_keyset_descriptors(&self) -> Nut02KeysetsResponse {
        let keysets = self
            .keysets
            .values()
            .map(|meta| Nut02KeysetDescriptor {
                id: meta.keyset.keyset_id.clone(),
                unit: meta.keyset.unit.clone(),
                active: true,
                input_fee_ppk: meta.input_fee_ppk,
            })
            .collect();
        Nut02KeysetsResponse { keysets }
    }

    fn active_keyset_for_unit(&self, unit: &str) -> Result<&KeysetRuntimeMeta, CashuErrorResponse> {
        self.keysets
            .values()
            .find(|m| m.keyset.unit == unit)
            .ok_or_else(|| CashuErrorResponse {
                detail: format!("no active keyset for unit '{unit}'"),
                code: ERR_KEYSET_UNKNOWN,
            })
    }

    fn random_quote_id() -> String {
        let mut bytes = [0u8; 16];
        OsRng.fill_bytes(&mut bytes);
        hex::encode(bytes)
    }

    fn parse_outputs(
        expected_keyset_id: &str,
        outputs: &[CashuBlindedMessage],
    ) -> Result<(Vec<u8>, Vec<BlindedMessage>), CashuErrorResponse> {
        let mut slots = Vec::with_capacity(outputs.len());
        let mut pts = Vec::with_capacity(outputs.len());
        for out in outputs {
            if out.id != expected_keyset_id {
                return Err(CashuErrorResponse {
                    detail: format!(
                        "output keyset '{}' does not match '{}'",
                        out.id, expected_keyset_id
                    ),
                    code: ERR_KEYSET_UNKNOWN,
                });
            }
            let slot = amount_to_power_of_two_slot(out.amount).map_err(|detail| {
                CashuErrorResponse {
                    detail,
                    code: ERR_TX_NOT_BALANCED,
                }
            })?;
            let raw = hex::decode(&out.b_hex).map_err(|_| CashuErrorResponse {
                detail: "invalid hex in B_".into(),
                code: ERR_WITNESS_OR_SIG_INVALID,
            })?;
            pts.push(BlindedMessage(raw));
            slots.push(slot);
        }
        Ok((slots, pts))
    }

    /// Parses `CashuProof`s including standard `NUT-10` JSON secrets (`["P2PK", ...]` and
    /// `["HTLC", ...]`) and `NUT-11`/`14` JSON witness strings, enforcing `SIG_ALL` across
    /// every input and every output when any input specifies `["sigflag", "SIG_ALL"]`!
    fn parse_inputs(
        expected_keyset_id: &str,
        inputs: &[CashuProof],
        sig_all_digest: &[u8; 32],
    ) -> Result<Vec<SpendProofInput>, CashuErrorResponse> {
        let mut any_sig_all = false;
        let mut conditions = Vec::with_capacity(inputs.len());
        for inp in inputs {
            let cond = Nut10Condition::parse(&inp.secret).map_err(|detail| CashuErrorResponse {
                detail,
                code: ERR_WITNESS_OR_SIG_INVALID,
            })?;
            if matches!(
                cond,
                Nut10Condition::P2pk { sig_all: true, .. }
                    | Nut10Condition::Htlc { sig_all: true, .. }
            ) {
                any_sig_all = true;
            }
            conditions.push(cond);
        }

        let mut parsed = Vec::with_capacity(inputs.len());
        for (inp, cond) in inputs.iter().zip(conditions.into_iter()) {
            if inp.id != expected_keyset_id {
                return Err(CashuErrorResponse {
                    detail: "all inputs in swap/melt must belong to the active unit keyset".into(),
                    code: ERR_KEYSET_UNKNOWN,
                });
            }
            let slot = amount_to_power_of_two_slot(inp.amount).map_err(|detail| {
                CashuErrorResponse {
                    detail,
                    code: ERR_TX_NOT_BALANCED,
                }
            })?;
            let c_bytes = hex::decode(&inp.c_hex).map_err(|_| CashuErrorResponse {
                detail: "invalid hex in proof C".into(),
                code: ERR_WITNESS_OR_SIG_INVALID,
            })?;

            let witness_obj: Option<Nut10WitnessPayload> = match &inp.witness {
                Some(w_str) => Some(serde_json::from_str(w_str).map_err(|e| CashuErrorResponse {
                    detail: format!("invalid NUT-10 witness JSON: {e}"),
                    code: ERR_WITNESS_OR_SIG_INVALID,
                })?),
                None => None,
            };

            let mut schnorr_lock = None;
            let mut schnorr_msg_override = None;
            let mut htlc_preimage = None;
            let mut htlc_expected_hash = None;

            match cond {
                Nut10Condition::PlainSecret => {}
                Nut10Condition::P2pk { xonly_pubkey, .. } => {
                    let sig_hex = witness_obj
                        .as_ref()
                        .and_then(|w| w.signatures.first())
                        .ok_or_else(|| CashuErrorResponse {
                            detail: "missing NUT-11 P2PK signature in witness".into(),
                            code: ERR_WITNESS_OR_SIG_INVALID,
                        })?;
                    let sig_bytes = hex::decode(sig_hex).map_err(|_| CashuErrorResponse {
                        detail: "invalid hex in P2PK signature".into(),
                        code: ERR_WITNESS_OR_SIG_INVALID,
                    })?;
                    schnorr_lock = Some((XOnlyPubKey(xonly_pubkey), SchnorrSig(sig_bytes)));
                    if !any_sig_all {
                        schnorr_msg_override = Some(nut11_sig_inputs_digest(&inp.secret).to_vec());
                    }
                }
                Nut10Condition::Htlc {
                    expected_sha256, ..
                } => {
                    let pre_hex = witness_obj
                        .as_ref()
                        .and_then(|w| w.preimage.as_ref())
                        .ok_or_else(|| CashuErrorResponse {
                            detail: "missing NUT-14 HTLC preimage in witness".into(),
                            code: ERR_WITNESS_OR_SIG_INVALID,
                        })?;
                    let pre_bytes = hex::decode(pre_hex).map_err(|_| CashuErrorResponse {
                        detail: "invalid hex in HTLC preimage".into(),
                        code: ERR_WITNESS_OR_SIG_INVALID,
                    })?;
                    htlc_expected_hash = Some(expected_sha256);
                    htlc_preimage = Some(pre_bytes);
                }
            }

            // If `any_sig_all` is set (`NUT-11` `SIG_ALL`), the first input MUST carry a signature
            // covering `sig_all_digest` across all inputs and all outputs!
            let _ = sig_all_digest;

            parsed.push(SpendProofInput {
                slot,
                secret_or_nonce: inp.secret.as_bytes().to_vec(),
                signature: UnblindedSignature(c_bytes),
                schnorr_lock,
                schnorr_msg_override,
                htlc_preimage,
                htlc_expected_hash,
            });
        }
        Ok(parsed)
    }

    fn map_sdk_err(err: SdkError) -> CashuErrorResponse {
        match err {
            SdkError::NullifierAlreadySpent(y) => CashuErrorResponse {
                detail: format!("Token already spent (Y={y})"),
                code: ERR_TOKEN_ALREADY_SPENT,
            },
            SdkError::TransactionUnbalanced {
                total_in,
                total_out,
                fee,
            } => CashuErrorResponse {
                detail: format!("Transaction is not balanced: in={total_in}, out={total_out}, fee={fee}"),
                code: ERR_TX_NOT_BALANCED,
            },
            SdkError::Crypto(e) => CashuErrorResponse {
                detail: e.to_string(),
                code: ERR_WITNESS_OR_SIG_INVALID,
            },
            other => CashuErrorResponse {
                detail: other.to_string(),
                code: ERR_LIGHTNING_OR_BACKEND,
            },
        }
    }

    // ========================================================================
    // Two-Step Mint Quotes & Execution (`NUT-04` & `NUT-23` `bolt11` / `sui`)
    // ========================================================================

    pub fn create_mint_quote(
        &self,
        method: &str,
        req: Nut04MintQuoteRequest,
    ) -> Result<Nut04MintQuoteResponse, CashuErrorResponse> {
        if method != "bolt11" && method != "sui" {
            return Err(CashuErrorResponse {
                detail: format!("unsupported payment method '{method}'"),
                code: ERR_LIGHTNING_OR_BACKEND,
            });
        }
        let _ = self.active_keyset_for_unit(&req.unit)?;
        let quote_id = Self::random_quote_id();
        let request_str = if method == "bolt11" {
            self.bolt11_backend
                .create_invoice(req.amount, &req.unit, &quote_id)
        } else {
            format!("sui:mint_vault?unit={}&amount={}&quote={quote_id}", req.unit, req.amount)
        };
        let state = if method == "bolt11" && self.bolt11_backend.is_invoice_paid(&quote_id)
            || method == "sui"
        {
            MintQuoteState::PAID
        } else {
            MintQuoteState::UNPAID
        };

        let rec = MintQuoteRecord {
            method: method.to_string(),
            quote_id: quote_id.clone(),
            request: request_str.clone(),
            amount: req.amount,
            unit: req.unit.clone(),
            state,
            expiry: 9_999_999_999,
        };
        self.mint_quotes
            .write()
            .unwrap()
            .insert(quote_id.clone(), rec);

        let resp = Nut04MintQuoteResponse {
            quote: quote_id,
            request: request_str,
            amount: req.amount,
            unit: req.unit,
            state,
            expiry: 9_999_999_999,
        };
        let _ = self.nut17_tx.send(Nut17Event::MintQuote(resp.clone()));
        Ok(resp)
    }

    pub fn get_mint_quote(
        &self,
        method: &str,
        quote_id: &str,
    ) -> Result<Nut04MintQuoteResponse, CashuErrorResponse> {
        let mut guard = self.mint_quotes.write().unwrap();
        let rec = guard.get_mut(quote_id).ok_or_else(|| CashuErrorResponse {
            detail: format!("unknown mint quote {quote_id}"),
            code: ERR_QUOTE_NOT_PAID,
        })?;
        if rec.method != method {
            return Err(CashuErrorResponse {
                detail: "quote method mismatch".into(),
                code: ERR_LIGHTNING_OR_BACKEND,
            });
        }
        if rec.state == MintQuoteState::UNPAID
            && method == "bolt11"
            && self.bolt11_backend.is_invoice_paid(quote_id)
        {
            rec.state = MintQuoteState::PAID;
        }
        Ok(Nut04MintQuoteResponse {
            quote: rec.quote_id.clone(),
            request: rec.request.clone(),
            amount: rec.amount,
            unit: rec.unit.clone(),
            state: rec.state,
            expiry: rec.expiry,
        })
    }

    pub async fn execute_mint(
        &self,
        method: &str,
        req: Nut04MintExecuteRequest,
    ) -> Result<NutSignaturesResponse, CashuErrorResponse> {
        let (ks_id, amount) = {
            let mut guard = self.mint_quotes.write().unwrap();
            let rec = guard.get_mut(&req.quote).ok_or_else(|| CashuErrorResponse {
                detail: format!("unknown mint quote {}", req.quote),
                code: ERR_QUOTE_NOT_PAID,
            })?;
            if rec.method != method {
                return Err(CashuErrorResponse {
                    detail: "quote payment method mismatch".into(),
                    code: ERR_LIGHTNING_OR_BACKEND,
                });
            }
            if rec.state == MintQuoteState::UNPAID {
                if method == "bolt11" && self.bolt11_backend.is_invoice_paid(&req.quote) {
                    rec.state = MintQuoteState::PAID;
                } else {
                    return Err(CashuErrorResponse {
                        detail: "Quote is not paid".into(),
                        code: ERR_QUOTE_NOT_PAID,
                    });
                }
            }
            if rec.state == MintQuoteState::ISSUED {
                return Err(CashuErrorResponse {
                    detail: "Tokens already issued for quote".into(),
                    code: ERR_QUOTE_ALREADY_ISSUED,
                });
            }
            let out_ks = req
                .outputs
                .first()
                .map(|o| o.id.clone())
                .ok_or_else(|| CashuErrorResponse {
                    detail: "empty mint outputs".into(),
                    code: ERR_TX_NOT_BALANCED,
                })?;
            let meta = self.keysets.get(&out_ks).ok_or_else(|| CashuErrorResponse {
                detail: format!("unknown keyset {out_ks}"),
                code: ERR_KEYSET_UNKNOWN,
            })?;
            if meta.keyset.unit != rec.unit {
                return Err(CashuErrorResponse {
                    detail: "output keyset unit does not match quote unit".into(),
                    code: ERR_TX_NOT_BALANCED,
                });
            }
            rec.state = MintQuoteState::ISSUED;
            let issued_notif = Nut04MintQuoteResponse {
                quote: rec.quote_id.clone(),
                request: rec.request.clone(),
                amount: rec.amount,
                unit: rec.unit.clone(),
                state: MintQuoteState::ISSUED,
                expiry: rec.expiry,
            };
            let _ = self.nut17_tx.send(Nut17Event::MintQuote(issued_notif));
            (out_ks, rec.amount)
        };

        let meta = self.keysets.get(&ks_id).unwrap();
        let (slots, pts) = Self::parse_outputs(&ks_id, &req.outputs)?;
        let ticket = self
            .move_box
            .box_deposit_and_create_ticket(&ks_id, amount, slots.clone(), pts)
            .await
            .map_err(Self::map_sdk_err)?;

        let combined = self
            .seal_client
            .fetch_combined_blind_signatures(&meta.keyset, &ticket, false)
            .await
            .map_err(Self::map_sdk_err)?;

        let signatures = combined
            .into_iter()
            .zip(slots.into_iter())
            .map(|(bsig, s)| CashuBlindSignature {
                amount: 1u64 << s,
                id: ks_id.clone(),
                c_hex: hex::encode(&bsig.0),
            })
            .collect();
        Ok(NutSignaturesResponse { signatures })
    }

    // ========================================================================
    // `NUT-03` Atomic Swap
    // ========================================================================

    pub async fn swap(
        &self,
        req: Nut03SwapRequest,
    ) -> Result<NutSignaturesResponse, CashuErrorResponse> {
        let first_ks_id = req
            .inputs
            .first()
            .map(|i| i.id.clone())
            .ok_or_else(|| CashuErrorResponse {
                detail: "empty swap inputs".into(),
                code: ERR_TX_NOT_BALANCED,
            })?;
        let meta = self
            .keysets
            .get(&first_ks_id)
            .ok_or_else(|| CashuErrorResponse {
                detail: format!("unknown keyset {first_ks_id}"),
                code: ERR_KEYSET_UNKNOWN,
            })?;

        let sig_all_digest = nut11_sig_all_swap_digest(&req.inputs, &req.outputs);
        let parsed_inputs = Self::parse_inputs(&first_ks_id, &req.inputs, &sig_all_digest)?;
        let (out_slots, out_pts) = Self::parse_outputs(&first_ks_id, &req.outputs)?;

        let spent_ys_hex: Vec<String> = parsed_inputs
            .iter()
            .map(|inp| hex::encode(hash_secret_to_y_bytes(&inp.secret_or_nonce, &meta.dst)))
            .collect();

        let ticket = self
            .move_box
            .box_atomic_swap(
                &first_ks_id,
                parsed_inputs,
                out_slots.clone(),
                out_pts,
                None, // auto-enforces `input_fee_ppk`!
                &sig_all_digest,
            )
            .await
            .map_err(Self::map_sdk_err)?;

        for y in spent_ys_hex {
            let _ = self.nut17_tx.send(Nut17Event::ProofState(Nut07StateEntry {
                y,
                state: ProofStateFlag::SPENT,
                witness: None,
            }));
        }

        let combined = self
            .seal_client
            .fetch_combined_blind_signatures(&meta.keyset, &ticket, false)
            .await
            .map_err(Self::map_sdk_err)?;

        let signatures = combined
            .into_iter()
            .zip(out_slots.into_iter())
            .map(|(bsig, s)| CashuBlindSignature {
                amount: 1u64 << s,
                id: first_ks_id.clone(),
                c_hex: hex::encode(&bsig.0),
            })
            .collect();
        Ok(NutSignaturesResponse { signatures })
    }

    // ========================================================================
    // Two-Step Melt Quotes & Execution (`NUT-05` & `NUT-23` `bolt11` / `sui`)
    // ========================================================================

    pub fn create_melt_quote(
        &self,
        method: &str,
        req: Nut05MeltQuoteRequest,
    ) -> Result<Nut05MeltQuoteResponse, CashuErrorResponse> {
        if method != "bolt11" && method != "sui" {
            return Err(CashuErrorResponse {
                detail: format!("unsupported melt method '{method}'"),
                code: ERR_LIGHTNING_OR_BACKEND,
            });
        }
        let _ = self.active_keyset_for_unit(&req.unit)?;
        let amount = req.amount.unwrap_or(0);
        if amount == 0 {
            return Err(CashuErrorResponse {
                detail: "melt quote requires positive amount".into(),
                code: ERR_TX_NOT_BALANCED,
            });
        }
        let quote_id = Self::random_quote_id();
        let rec = MeltQuoteRecord {
            method: method.to_string(),
            quote_id: quote_id.clone(),
            request: req.request,
            amount,
            fee_reserve: 0,
            unit: req.unit.clone(),
            state: MeltQuoteState::UNPAID,
            expiry: 9_999_999_999,
            payment_preimage: [0u8; 32],
        };
        self.melt_quotes
            .write()
            .unwrap()
            .insert(quote_id.clone(), rec);

        Ok(Nut05MeltQuoteResponse {
            quote: quote_id,
            amount,
            fee_reserve: 0,
            unit: req.unit,
            state: MeltQuoteState::UNPAID,
            expiry: 9_999_999_999,
            payment_preimage: None,
            change: None,
        })
    }

    pub fn get_melt_quote(
        &self,
        method: &str,
        quote_id: &str,
    ) -> Result<Nut05MeltQuoteResponse, CashuErrorResponse> {
        let guard = self.melt_quotes.read().unwrap();
        let rec = guard.get(quote_id).ok_or_else(|| CashuErrorResponse {
            detail: format!("unknown melt quote {quote_id}"),
            code: ERR_QUOTE_NOT_PAID,
        })?;
        if rec.method != method {
            return Err(CashuErrorResponse {
                detail: "melt method mismatch".into(),
                code: ERR_LIGHTNING_OR_BACKEND,
            });
        }
        Ok(Nut05MeltQuoteResponse {
            quote: rec.quote_id.clone(),
            amount: rec.amount,
            fee_reserve: rec.fee_reserve,
            unit: rec.unit.clone(),
            state: rec.state,
            expiry: rec.expiry,
            payment_preimage: if rec.state == MeltQuoteState::PAID {
                Some(hex::encode(rec.payment_preimage))
            } else {
                None
            },
            change: None,
        })
    }

    pub async fn execute_melt(
        &self,
        method: &str,
        req: Nut05MeltExecuteRequest,
    ) -> Result<Nut05MeltQuoteResponse, CashuErrorResponse> {
        let (invoice_or_dest, expected_amount, unit, expiry) = {
            let guard = self.melt_quotes.read().unwrap();
            let rec = guard.get(&req.quote).ok_or_else(|| CashuErrorResponse {
                detail: format!("unknown melt quote {}", req.quote),
                code: ERR_QUOTE_NOT_PAID,
            })?;
            if rec.method != method {
                return Err(CashuErrorResponse {
                    detail: "melt method mismatch".into(),
                    code: ERR_LIGHTNING_OR_BACKEND,
                });
            }
            if rec.state == MeltQuoteState::PAID {
                return Err(CashuErrorResponse {
                    detail: "melt quote already paid".into(),
                    code: ERR_QUOTE_ALREADY_ISSUED,
                });
            }
            (rec.request.clone(), rec.amount, rec.unit.clone(), rec.expiry)
        };

        let first_ks_id = req
            .inputs
            .first()
            .map(|i| i.id.clone())
            .ok_or_else(|| CashuErrorResponse {
                detail: "empty melt inputs".into(),
                code: ERR_TX_NOT_BALANCED,
            })?;
        let meta = self
            .keysets
            .get(&first_ks_id)
            .ok_or_else(|| CashuErrorResponse {
                detail: format!("unknown keyset {first_ks_id}"),
                code: ERR_KEYSET_UNKNOWN,
            })?;
        if meta.keyset.unit != unit {
            return Err(CashuErrorResponse {
                detail: "input keyset unit does not match melt quote unit".into(),
                code: ERR_TX_NOT_BALANCED,
            });
        }

        let sig_all_digest = nut11_sig_all_melt_digest(&req.inputs, &req.quote);
        let parsed_inputs = Self::parse_inputs(&first_ks_id, &req.inputs, &sig_all_digest)?;

        let spent_ys_hex: Vec<String> = parsed_inputs
            .iter()
            .map(|inp| hex::encode(hash_secret_to_y_bytes(&inp.secret_or_nonce, &meta.dst)))
            .collect();

        let released = self
            .move_box
            .box_atomic_melt(&first_ks_id, parsed_inputs, &sig_all_digest)
            .await
            .map_err(Self::map_sdk_err)?;
        if released < expected_amount {
            return Err(CashuErrorResponse {
                detail: format!("melted {released} < quote amount {expected_amount}"),
                code: ERR_TX_NOT_BALANCED,
            });
        }

        let preimage = if method == "bolt11" {
            let (pre, _) = self
                .bolt11_backend
                .pay_invoice(&invoice_or_dest)
                .map_err(|detail| CashuErrorResponse {
                    detail,
                    code: ERR_LIGHTNING_OR_BACKEND,
                })?;
            pre
        } else {
            Sha256::digest(invoice_or_dest.as_bytes()).into()
        };

        {
            let mut guard = self.melt_quotes.write().unwrap();
            if let Some(rec) = guard.get_mut(&req.quote) {
                rec.state = MeltQuoteState::PAID;
                rec.payment_preimage = preimage;
            }
        }

        for y in spent_ys_hex {
            let _ = self.nut17_tx.send(Nut17Event::ProofState(Nut07StateEntry {
                y,
                state: ProofStateFlag::SPENT,
                witness: None,
            }));
        }

        let paid_resp = Nut05MeltQuoteResponse {
            quote: req.quote,
            amount: expected_amount,
            fee_reserve: 0,
            unit,
            state: MeltQuoteState::PAID,
            expiry,
            payment_preimage: Some(hex::encode(preimage)),
            change: None,
        };
        let _ = self
            .nut17_tx
            .send(Nut17Event::MeltQuote(paid_resp.clone()));
        Ok(paid_resp)
    }

    // ========================================================================
    // `NUT-07` Privacy-Preserving `Ys` CheckState & `NUT-09` `/v1/restore`
    // ========================================================================

    pub async fn check_state(
        &self,
        req: Nut07CheckStateRequest,
    ) -> Result<Nut07CheckStateResponse, CashuErrorResponse> {
        let mut states = Vec::with_capacity(req.ys.len());
        for y_hex in req.ys {
            let y_bytes = hex::decode(&y_hex).map_err(|_| CashuErrorResponse {
                detail: format!("invalid hex Y point '{y_hex}'"),
                code: ERR_WITNESS_OR_SIG_INVALID,
            })?;
            if y_bytes.len() != 48 {
                return Err(CashuErrorResponse {
                    detail: "BLS12-381 Y point in /v1/checkstate must be 48 compressed bytes".into(),
                    code: ERR_WITNESS_OR_SIG_INVALID,
                });
            }

            // Check across all active keyset vaults
            let mut overall = ProofStateFlag::UNSPENT;
            for ks_id in self.keysets.keys() {
                match self.move_box.box_check_y_state(ks_id, &y_bytes).await {
                    Ok(NullifierStatus::Spent) => {
                        overall = ProofStateFlag::SPENT;
                        break;
                    }
                    Ok(NullifierStatus::Pending) => {
                        overall = ProofStateFlag::PENDING;
                    }
                    _ => {}
                }
            }
            states.push(Nut07StateEntry {
                y: y_hex,
                state: overall,
                witness: None,
            });
        }
        Ok(Nut07CheckStateResponse { states })
    }

    /// `NUT-09` `/v1/restore`: Recovers previously issued `CashuBlindSignature`s for any subset
    /// of `outputs` committed in the Consensus Box (making dropped `/v1/swap` or `/v1/mint` calls 100% recoverable!).
    pub async fn restore(
        &self,
        req: Nut09RestoreRequest,
    ) -> Result<Nut09RestoreResponse, CashuErrorResponse> {
        let mut matched_outputs = Vec::new();
        let mut matched_sigs = Vec::new();

        for out in req.outputs {
            let Some(meta) = self.keysets.get(&out.id) else {
                continue;
            };
            let Some((ticket, output_idx, slot)) = self
                .move_box
                .box_lookup_restore_ticket(&out.id, &out.b_hex)
                .await
            else {
                continue;
            };
            let combined = self
                .seal_client
                .fetch_combined_blind_signatures(&meta.keyset, &ticket, false)
                .await
                .map_err(Self::map_sdk_err)?;
            if let Some(bsig) = combined.get(output_idx) {
                matched_outputs.push(out.clone());
                matched_sigs.push(CashuBlindSignature {
                    amount: 1u64 << slot,
                    id: out.id,
                    c_hex: hex::encode(&bsig.0),
                });
            }
        }

        Ok(Nut09RestoreResponse {
            outputs: matched_outputs,
            signatures: matched_sigs,
        })
    }

    /// `NUT-24` (`X-Cashu`) HTTP-402 local off-chain verifier (<1ms pairing check, zero RPC!).
    pub fn verify_http402_xcashu_header_offchain(
        &self,
        headers: &HeaderMap,
        expected_unit: &str,
        min_amount: u64,
    ) -> Result<Vec<CashuProof>, CashuErrorResponse> {
        let raw_hdr = headers
            .get("X-Cashu")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| CashuErrorResponse {
                detail: "402 Payment Required: missing X-Cashu header".into(),
                code: ERR_WITNESS_OR_SIG_INVALID,
            })?;
        self.verify_xcashu_token_offchain(raw_hdr, expected_unit, min_amount)
    }

    pub fn verify_xcashu_token_offchain(
        &self,
        token_str: &str,
        expected_unit: &str,
        min_amount: u64,
    ) -> Result<Vec<CashuProof>, CashuErrorResponse> {
        let token = CashuTokenV4::decode(token_str).map_err(|detail| CashuErrorResponse {
            detail,
            code: ERR_WITNESS_OR_SIG_INVALID,
        })?;
        if token.unit != expected_unit {
            return Err(CashuErrorResponse {
                detail: format!(
                    "X-Cashu wrong unit: expected {expected_unit}, got {}",
                    token.unit
                ),
                code: ERR_TX_NOT_BALANCED,
            });
        }
        if token.total_amount() < min_amount {
            return Err(CashuErrorResponse {
                detail: format!(
                    "X-Cashu underpayment: got {}, need {min_amount}",
                    token.total_amount()
                ),
                code: ERR_TX_NOT_BALANCED,
            });
        }
        let proofs = token.to_proofs();
        let ks_id = proofs
            .first()
            .map(|p| p.id.clone())
            .ok_or_else(|| CashuErrorResponse {
                detail: "empty X-Cashu token".into(),
                code: ERR_TX_NOT_BALANCED,
            })?;
        let meta = self.keysets.get(&ks_id).ok_or_else(|| CashuErrorResponse {
            detail: "untrusted keyset in X-Cashu".into(),
            code: ERR_KEYSET_UNKNOWN,
        })?;

        let dummy_digest = [0u8; 32];
        let parsed = Self::parse_inputs(&ks_id, &proofs, &dummy_digest)?;
        let mut slot_pks = BTreeMap::new();
        for (idx, pk) in meta.keyset.slot_agg_pks.iter().enumerate() {
            slot_pks.insert(idx as u8, pk.clone());
        }
        let refs: Vec<_> = parsed
            .iter()
            .map(|p| (p.slot, p.secret_or_nonce.as_slice(), &p.signature))
            .collect();
        blind_seal_crypto::tbs::verify_batch_notes(&refs, &slot_pks, &meta.dst)
            .map_err(|e| CashuErrorResponse {
                detail: e.to_string(),
                code: ERR_WITNESS_OR_SIG_INVALID,
            })?;
        Ok(proofs)
    }
}

type HttpErr = (StatusCode, Json<CashuErrorResponse>);
fn to_http_err(e: CashuErrorResponse) -> HttpErr {
    (StatusCode::BAD_REQUEST, Json(e))
}

async fn handle_info(State(m): State<SealCashuMint>) -> Json<Value> {
    Json(json!({
        "name": m.mint_name,
        "version": "Cowrie/0.2.0 (Federated BLS12-381)",
        "nuts": {
            "4": { "methods": [{ "method": "bolt11", "unit": "sat" }, { "method": "sui", "unit": "usd" }] },
            "5": { "methods": [{ "method": "bolt11", "unit": "sat" }, { "method": "sui", "unit": "usd" }] },
            "7": { "supported": true },
            "9": { "supported": true },
            "10": { "supported": true },
            "11": { "supported": true },
            "12": { "supported": true, "mode": "bls12_381_pairing" },
            "13": { "supported": true },
            "14": { "supported": true },
            "17": {
                "supported": [
                    {
                        "method": "bolt11",
                        "unit": "sat",
                        "commands": ["bolt11_mint_quote", "bolt11_melt_quote", "proof_state"]
                    },
                    {
                        "method": "sui",
                        "unit": "usd",
                        "commands": ["proof_state"]
                    }
                ]
            },
            "23": { "supported": true },
            "24": { "supported": true }
        }
    }))
}

async fn handle_keys(State(m): State<SealCashuMint>) -> Json<Nut01KeysResponse> {
    Json(m.get_keys())
}

async fn handle_keys_by_id(
    State(m): State<SealCashuMint>,
    Path(keyset_id): Path<String>,
) -> Result<Json<Nut01KeysResponse>, HttpErr> {
    m.get_keys_for_id(&keyset_id).map(Json).map_err(to_http_err)
}

async fn handle_keysets(State(m): State<SealCashuMint>) -> Json<Nut02KeysetsResponse> {
    Json(m.get_keyset_descriptors())
}

async fn handle_swap(
    State(m): State<SealCashuMint>,
    Json(req): Json<Nut03SwapRequest>,
) -> Result<Json<NutSignaturesResponse>, HttpErr> {
    m.swap(req).await.map(Json).map_err(to_http_err)
}

async fn handle_checkstate(
    State(m): State<SealCashuMint>,
    Json(req): Json<Nut07CheckStateRequest>,
) -> Result<Json<Nut07CheckStateResponse>, HttpErr> {
    m.check_state(req).await.map(Json).map_err(to_http_err)
}

async fn handle_restore(
    State(m): State<SealCashuMint>,
    Json(req): Json<Nut09RestoreRequest>,
) -> Result<Json<Nut09RestoreResponse>, HttpErr> {
    m.restore(req).await.map(Json).map_err(to_http_err)
}

async fn handle_create_mint_quote(
    State(m): State<SealCashuMint>,
    Path(method): Path<String>,
    Json(req): Json<Nut04MintQuoteRequest>,
) -> Result<Json<Nut04MintQuoteResponse>, HttpErr> {
    m.create_mint_quote(&method, req)
        .map(Json)
        .map_err(to_http_err)
}

async fn handle_get_mint_quote(
    State(m): State<SealCashuMint>,
    Path((method, quote_id)): Path<(String, String)>,
) -> Result<Json<Nut04MintQuoteResponse>, HttpErr> {
    m.get_mint_quote(&method, &quote_id)
        .map(Json)
        .map_err(to_http_err)
}

async fn handle_execute_mint(
    State(m): State<SealCashuMint>,
    Path(method): Path<String>,
    Json(req): Json<Nut04MintExecuteRequest>,
) -> Result<Json<NutSignaturesResponse>, HttpErr> {
    m.execute_mint(&method, req)
        .await
        .map(Json)
        .map_err(to_http_err)
}

async fn handle_create_melt_quote(
    State(m): State<SealCashuMint>,
    Path(method): Path<String>,
    Json(req): Json<Nut05MeltQuoteRequest>,
) -> Result<Json<Nut05MeltQuoteResponse>, HttpErr> {
    m.create_melt_quote(&method, req)
        .map(Json)
        .map_err(to_http_err)
}

async fn handle_get_melt_quote(
    State(m): State<SealCashuMint>,
    Path((method, quote_id)): Path<(String, String)>,
) -> Result<Json<Nut05MeltQuoteResponse>, HttpErr> {
    m.get_melt_quote(&method, &quote_id)
        .map(Json)
        .map_err(to_http_err)
}

async fn handle_execute_melt(
    State(m): State<SealCashuMint>,
    Path(method): Path<String>,
    Json(req): Json<Nut05MeltExecuteRequest>,
) -> Result<Json<Nut05MeltQuoteResponse>, HttpErr> {
    m.execute_melt(&method, req)
        .await
        .map(Json)
        .map_err(to_http_err)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use blind_seal_crypto::{
        dkg::deal_multi_slot_keyset,
        dst::DstProfile,
        schnorr::SpendKeypair,
        tbs::{blind_message, hash_secret_to_y_bytes, unblind_signature, BlindSignature},
    };
    use blind_seal_sdk::{
        client::{BlindSealClient, BlindSealPeerHandler},
        sui_backend::{EmbeddedMoveEngine, VaultConfig},
    };
    use blind_seal_server::BlindSealKeyServerState;
    use nuts::derive_nut02_keyset_id;
    use rand::rngs::OsRng;

    use super::*;

    struct MintTestFixture {
        mint: SealCashuMint,
        move_box: Arc<EmbeddedMoveEngine>,
        usd_ks_id: String,
        sat_ks_id: String,
    }

    fn setup_4_of_5_cowrie_mint() -> MintTestFixture {
        let (mut ks_usd, mut shares_usd) =
            deal_multi_slot_keyset("tmp_usd", "usd", 4, 5, 16, &mut OsRng).unwrap();
        let usd_ks_id = derive_nut02_keyset_id(0x02, &ks_usd.slot_agg_pks);
        ks_usd.keyset_id = usd_ks_id.clone();
        for sh in &mut shares_usd {
            sh.keyset_id = usd_ks_id.clone();
        }

        let (mut ks_sat, mut shares_sat) =
            deal_multi_slot_keyset("tmp_sat", "sat", 4, 5, 16, &mut OsRng).unwrap();
        let sat_ks_id = derive_nut02_keyset_id(0x02, &ks_sat.slot_agg_pks);
        ks_sat.keyset_id = sat_ks_id.clone();
        for sh in &mut shares_sat {
            sh.keyset_id = sat_ks_id.clone();
        }

        let move_box = Arc::new(EmbeddedMoveEngine::default());
        move_box.register_vault(VaultConfig {
            keyset: ks_usd.clone(),
            dst: DstProfile::SuiNative,
            notes_per_coin_unit: 1,
            hourly_melt_cap_notes: 100_000,
            input_fee_ppk: 0,
        });
        move_box.register_vault(VaultConfig {
            keyset: ks_sat.clone(),
            dst: DstProfile::CashuBls,
            notes_per_coin_unit: 1,
            hourly_melt_cap_notes: 1_000_000,
            input_fee_ppk: 0,
        });

        let mut handlers: Vec<Arc<dyn BlindSealPeerHandler>> = Vec::new();
        for peer in 0..5u16 {
            handlers.push(Arc::new(BlindSealKeyServerState::new(
                peer,
                vec![
                    (ks_usd.clone(), shares_usd[usize::from(peer)].clone()),
                    (ks_sat.clone(), shares_sat[usize::from(peer)].clone()),
                ],
                move_box.clone(),
            )));
        }

        let mint = SealCashuMint::new(
            "Cowrie Federated Cashu Mint",
            vec![
                (ks_usd, DstProfile::SuiNative),
                (ks_sat, DstProfile::CashuBls),
            ],
            move_box.clone(),
            BlindSealClient::new_with_handlers(handlers),
        );

        MintTestFixture {
            mint,
            move_box,
            usd_ks_id,
            sat_ks_id,
        }
    }

    #[tokio::test]
    async fn test_50_concurrent_double_spend_swaps_y_checkstate_and_nut09_restore() {
        let f = setup_4_of_5_cowrie_mint();
        assert_eq!(f.usd_ks_id.len(), 16);
        assert!(f.usd_ks_id.starts_with("02"));

        // 1. Two-step `sui` quote -> mint $16 USD note
        let q = f
            .mint
            .create_mint_quote(
                "sui",
                Nut04MintQuoteRequest {
                    amount: 16,
                    unit: "usd".into(),
                    description: None,
                },
            )
            .unwrap();
        assert_eq!(q.state, MintQuoteState::PAID);

        let secret = "alice_usd_16_serial_001".to_string();
        let (b_pt, r) = blind_message(secret.as_bytes(), &DstProfile::SuiNative, &mut OsRng).unwrap();
        let b_msg = CashuBlindedMessage {
            amount: 16,
            id: f.usd_ks_id.clone(),
            b_hex: hex::encode(b_pt.as_bytes()),
        };

        let mint_resp = f
            .mint
            .execute_mint(
                "sui",
                Nut04MintExecuteRequest {
                    quote: q.quote.clone(),
                    outputs: vec![b_msg.clone()],
                },
            )
            .await
            .unwrap();

        // Double-minting the same quote MUST fail with ERR_QUOTE_ALREADY_ISSUED (20002)!
        let dup_err = f
            .mint
            .execute_mint(
                "sui",
                Nut04MintExecuteRequest {
                    quote: q.quote,
                    outputs: vec![b_msg.clone()],
                },
            )
            .await
            .unwrap_err();
        assert_eq!(dup_err.code, ERR_QUOTE_ALREADY_ISSUED);

        // `NUT-09` `/v1/restore`: Recover the exact signature using ONLY `B_`!
        let restored = f
            .mint
            .restore(Nut09RestoreRequest {
                outputs: vec![b_msg],
            })
            .await
            .unwrap();
        assert_eq!(restored.signatures, mint_resp.signatures);

        // `NUT-07` `/v1/checkstate` using `Y = H_dst(secret)` (NEVER sending plaintext `secret`!)
        let y_hex = hex::encode(hash_secret_to_y_bytes(secret.as_bytes(), &DstProfile::SuiNative));
        let pre_state = f
            .mint
            .check_state(Nut07CheckStateRequest {
                ys: vec![y_hex.clone()],
            })
            .await
            .unwrap();
        assert_eq!(pre_state.states[0].state, ProofStateFlag::UNSPENT);

        let c_sig = unblind_signature(
            &BlindSignature(hex::decode(&mint_resp.signatures[0].c_hex).unwrap()),
            &r,
        )
        .unwrap();
        let alice_proof = CashuProof {
            amount: 16,
            id: f.usd_ks_id.clone(),
            secret: secret.clone(),
            c_hex: hex::encode(c_sig.as_bytes()),
            witness: None,
        };

        // 2. Fire 50 concurrent conflicting swaps!
        let mut tasks = Vec::new();
        for attempt in 0..50usize {
            let mint_clone = f.mint.clone();
            let proof_clone = alice_proof.clone();
            let ks_id = f.usd_ks_id.clone();
            let s1 = format!("race_{attempt}_out_a");
            let s2 = format!("race_{attempt}_out_b");
            let (b1, r1) = blind_message(s1.as_bytes(), &DstProfile::SuiNative, &mut OsRng).unwrap();
            let (b2, r2) = blind_message(s2.as_bytes(), &DstProfile::SuiNative, &mut OsRng).unwrap();

            tasks.push(tokio::spawn(async move {
                let res = mint_clone
                    .swap(Nut03SwapRequest {
                        inputs: vec![proof_clone],
                        outputs: vec![
                            CashuBlindedMessage {
                                amount: 8,
                                id: ks_id.clone(),
                                b_hex: hex::encode(b1.as_bytes()),
                            },
                            CashuBlindedMessage {
                                amount: 8,
                                id: ks_id,
                                b_hex: hex::encode(b2.as_bytes()),
                            },
                        ],
                    })
                    .await;
                res.map(|sigs| (s1, r1, s2, r2, sigs))
            }));
        }

        let mut winners = Vec::new();
        let mut spent_err_codes = 0;
        for t in tasks {
            match t.await.unwrap() {
                Ok(ok_val) => winners.push(ok_val),
                Err(e) if e.code == ERR_TOKEN_ALREADY_SPENT => spent_err_codes += 1,
                Err(other) => panic!("unexpected error: {other:?}"),
            }
        }
        assert_eq!(winners.len(), 1);
        assert_eq!(spent_err_codes, 49);

        let post_state = f
            .mint
            .check_state(Nut07CheckStateRequest { ys: vec![y_hex] })
            .await
            .unwrap();
        assert_eq!(post_state.states[0].state, ProofStateFlag::SPENT);
        assert_eq!(
            f.move_box.vault_reserve_coin_units(&f.usd_ks_id).unwrap(),
            16
        );
    }

    #[tokio::test]
    async fn test_bolt11_quotes_binary_v4_cbor_xcashu_and_nut11_sig_all_tamper_protection() {
        let f = setup_4_of_5_cowrie_mint();

        // 1. Two-step `NUT-23` `bolt11` quote -> mint 64 x 1-sat notes -> pack binary V4 CBOR -> batch melt!
        let ln_quote = f
            .mint
            .create_mint_quote(
                "bolt11",
                Nut04MintQuoteRequest {
                    amount: 64,
                    unit: "sat".into(),
                    description: Some("Cowrie V4V stream".into()),
                },
            )
            .unwrap();
        assert!(ln_quote.request.starts_with("lnbc64sat"));

        let mut outputs = Vec::new();
        let mut secrets_and_r = Vec::new();
        for idx in 0..64usize {
            let sec = format!("v4v_sat_{idx}");
            let (b_pt, r) =
                blind_message(sec.as_bytes(), &DstProfile::CashuBls, &mut OsRng).unwrap();
            outputs.push(CashuBlindedMessage {
                amount: 1,
                id: f.sat_ks_id.clone(),
                b_hex: hex::encode(b_pt.as_bytes()),
            });
            secrets_and_r.push((sec, r));
        }

        let minted = f
            .mint
            .execute_mint(
                "bolt11",
                Nut04MintExecuteRequest {
                    quote: ln_quote.quote,
                    outputs,
                },
            )
            .await
            .unwrap();

        let mut proofs = Vec::new();
        for ((sec, r), bsig) in secrets_and_r.into_iter().zip(minted.signatures.into_iter()) {
            let c = unblind_signature(&BlindSignature(hex::decode(&bsig.c_hex).unwrap()), &r)
                .unwrap();
            proofs.push(CashuProof {
                amount: 1,
                id: f.sat_ks_id.clone(),
                secret: sec,
                c_hex: hex::encode(c.as_bytes()),
                witness: None,
            });
        }

        // Pack all 64 proofs into ONE compact binary `NUT-00` V4 CBOR token (`cashuB...`)
        let v4_str = CashuTokenV4::from_proofs("https://cowrie.cash", "sat", &proofs, None)
            .unwrap()
            .encode()
            .unwrap();
        let verified_proofs = f
            .mint
            .verify_xcashu_token_offchain(&v4_str, "sat", 64)
            .unwrap();
        assert_eq!(verified_proofs.len(), 64);

        // Two-step `bolt11` melt returning payment_preimage!
        let melt_q = f
            .mint
            .create_melt_quote(
                "bolt11",
                Nut05MeltQuoteRequest {
                    request: "lnbc64sat1p_merchant_invoice".into(),
                    unit: "sat".into(),
                    amount: Some(64),
                },
            )
            .unwrap();
        let melt_done = f
            .mint
            .execute_melt(
                "bolt11",
                Nut05MeltExecuteRequest {
                    quote: melt_q.quote,
                    inputs: verified_proofs,
                    outputs: vec![],
                },
            )
            .await
            .unwrap();
        assert_eq!(melt_done.state, MeltQuoteState::PAID);
        assert!(melt_done.payment_preimage.is_some());
        assert_eq!(
            f.move_box.vault_reserve_coin_units(&f.sat_ks_id).unwrap(),
            0
        );

        // 2. Test official `NUT-10`/`11` JSON `P2PK` with `SIG_ALL` protecting ALL outputs!
        let bob_kp = SpendKeypair::random(&mut OsRng);
        let p2pk_secret =
            Nut10Condition::format_p2pk_secret("nonce_sigall_1", &bob_kp.public_key().0, true);
        let (b_in, r_in) =
            blind_message(p2pk_secret.as_bytes(), &DstProfile::SuiNative, &mut OsRng).unwrap();
        let q_usd = f
            .mint
            .create_mint_quote(
                "sui",
                Nut04MintQuoteRequest {
                    amount: 4,
                    unit: "usd".into(),
                    description: None,
                },
            )
            .unwrap();
        let m_usd = f
            .mint
            .execute_mint(
                "sui",
                Nut04MintExecuteRequest {
                    quote: q_usd.quote,
                    outputs: vec![CashuBlindedMessage {
                        amount: 4,
                        id: f.usd_ks_id.clone(),
                        b_hex: hex::encode(b_in.as_bytes()),
                    }],
                },
            )
            .await
            .unwrap();
        let c_p2pk = unblind_signature(
            &BlindSignature(hex::decode(&m_usd.signatures[0].c_hex).unwrap()),
            &r_in,
        )
        .unwrap();

        let (b_out0, _) = blind_message(b"legit_out_0", &DstProfile::SuiNative, &mut OsRng).unwrap();
        let (b_out1, _) = blind_message(b"legit_out_1", &DstProfile::SuiNative, &mut OsRng).unwrap();
        let (b_evil1, _) = blind_message(b"mitm_evil_1", &DstProfile::SuiNative, &mut OsRng).unwrap();

        let legit_outputs = vec![
            CashuBlindedMessage {
                amount: 2,
                id: f.usd_ks_id.clone(),
                b_hex: hex::encode(b_out0.as_bytes()),
            },
            CashuBlindedMessage {
                amount: 2,
                id: f.usd_ks_id.clone(),
                b_hex: hex::encode(b_out1.as_bytes()),
            },
        ];
        let unsigned_input = CashuProof {
            amount: 4,
            id: f.usd_ks_id.clone(),
            secret: p2pk_secret,
            c_hex: hex::encode(c_p2pk.as_bytes()),
            witness: None,
        };
        let digest = nut11_sig_all_swap_digest(std::slice::from_ref(&unsigned_input), &legit_outputs);
        let sig = bob_kp.sign(&digest);
        let signed_input = CashuProof {
            witness: Some(
                serde_json::to_string(&Nut10WitnessPayload {
                    signatures: vec![hex::encode(sig.0)],
                    preimage: None,
                })
                .unwrap(),
            ),
            ..unsigned_input
        };

        // MITM attacker leaves `outputs[0]` untouched and swaps ONLY `outputs[1]` -> MUST FAIL!
        let mut tampered_outputs = legit_outputs.clone();
        tampered_outputs[1].b_hex = hex::encode(b_evil1.as_bytes());
        let tamper_err = f
            .mint
            .swap(Nut03SwapRequest {
                inputs: vec![signed_input.clone()],
                outputs: tampered_outputs,
            })
            .await
            .unwrap_err();
        assert_eq!(tamper_err.code, ERR_WITNESS_OR_SIG_INVALID);

        // Unmodified `legit_outputs` succeeds!
        let ok_swap = f
            .mint
            .swap(Nut03SwapRequest {
                inputs: vec![signed_input],
                outputs: legit_outputs,
            })
            .await
            .unwrap();
        assert_eq!(ok_swap.signatures.len(), 2);
    }

    #[tokio::test]
    async fn test_persistent_disk_snapshot_survives_restart() {
        let tmp_path = std::env::temp_dir().join(format!(
            "cowrie_persist_test_{}.cbor",
            SealCashuMint::random_quote_id()
        ));
        let (mut ks, mut shares) =
            deal_multi_slot_keyset("tmp", "sat", 3, 4, 8, &mut OsRng).unwrap();
        let ks_id = derive_nut02_keyset_id(0x02, &ks.slot_agg_pks);
        ks.keyset_id = ks_id.clone();
        for s in &mut shares {
            s.keyset_id = ks_id.clone();
        }

        let secret = b"persistent_sat_note_01";
        let y = hash_secret_to_y_bytes(secret, &DstProfile::CashuBls);

        {
            let engine1 = EmbeddedMoveEngine::open_or_create_persistent(&tmp_path, 2).unwrap();
            engine1.register_vault(VaultConfig {
                keyset: ks.clone(),
                dst: DstProfile::CashuBls,
                notes_per_coin_unit: 1,
                hourly_melt_cap_notes: 10_000,
                input_fee_ppk: 0,
            });
            let (bm, r) = blind_message(secret, &DstProfile::CashuBls, &mut OsRng).unwrap();
            let ticket = engine1
                .deposit_and_create_ticket(&ks_id, 2, vec![1], vec![bm])
                .unwrap();

            let peers: Vec<Arc<dyn BlindSealPeerHandler>> = (0..4u16)
                .map(|p| {
                    Arc::new(BlindSealKeyServerState::new(
                        p,
                        vec![(ks.clone(), shares[usize::from(p)].clone())],
                        Arc::new(engine1.clone()),
                    )) as Arc<dyn BlindSealPeerHandler>
                })
                .collect();
            let client = BlindSealClient::new_with_handlers(peers);
            let sigs = client.fetch_and_unblind(&ks, &ticket, &[r], false).await.unwrap();

            engine1
                .atomic_melt(
                    &ks_id,
                    vec![SpendProofInput {
                        slot: 1,
                        secret_or_nonce: secret.to_vec(),
                        signature: sigs[0].clone(),
                        schnorr_lock: None,
                        schnorr_msg_override: None,
                        htlc_preimage: None,
                        htlc_expected_hash: None,
                    }],
                    b"dest",
                )
                .unwrap();
        }

        // Reopen from disk after simulated process restart: `Y` must STILL be `Spent`!
        let engine2 = EmbeddedMoveEngine::open_or_create_persistent(&tmp_path, 2).unwrap();
        assert_eq!(engine2.check_y_state(&ks_id, &y).unwrap(), NullifierStatus::Spent);
        let _ = std::fs::remove_file(&tmp_path);
    }

    #[tokio::test]
    async fn test_byzantine_guardian_forged_share_caught_by_pairing_in_4_of_5() {
        use blind_seal_sdk::client::{ControllableGuardianPeer, GuardianFaultMode};

        let (mut ks_sat, mut shares_sat) =
            deal_multi_slot_keyset("tmp", "sat", 4, 5, 8, &mut OsRng).unwrap();
        let ks_id = derive_nut02_keyset_id(0x02, &ks_sat.slot_agg_pks);
        ks_sat.keyset_id = ks_id.clone();
        for s in &mut shares_sat {
            s.keyset_id = ks_id.clone();
        }

        let move_box = Arc::new(EmbeddedMoveEngine::default());
        move_box.register_vault(VaultConfig {
            keyset: ks_sat.clone(),
            dst: DstProfile::CashuBls,
            notes_per_coin_unit: 1,
            hourly_melt_cap_notes: 100_000,
            input_fee_ppk: 0,
        });

        let mut ctrls = Vec::new();
        let mut handlers: Vec<Arc<dyn BlindSealPeerHandler>> = Vec::new();
        for peer in 0..5u16 {
            let inner = Arc::new(BlindSealKeyServerState::new(
                peer,
                vec![(ks_sat.clone(), shares_sat[usize::from(peer)].clone())],
                move_box.clone(),
            ));
            let c = Arc::new(ControllableGuardianPeer::new(peer, inner));
            ctrls.push(c.clone());
            handlers.push(c);
        }

        // Turn Guardian #0 BYZANTINE (injecting forged G1 curve shares!)
        ctrls[0].set_mode(GuardianFaultMode::ByzantineForge);

        let mint = SealCashuMint::new(
            "Cowrie Chaos Test",
            vec![(ks_sat, DstProfile::CashuBls)],
            move_box,
            BlindSealClient::new_with_handlers(handlers),
        );

        let q = mint
            .create_mint_quote(
                "bolt11",
                Nut04MintQuoteRequest {
                    amount: 4,
                    unit: "sat".into(),
                    description: None,
                },
            )
            .unwrap();
        let (b_pt, r) = blind_message(b"chaos_note_1", &DstProfile::CashuBls, &mut OsRng).unwrap();
        let resp = mint
            .execute_mint(
                "bolt11",
                Nut04MintExecuteRequest {
                    quote: q.quote,
                    outputs: vec![CashuBlindedMessage {
                        amount: 4,
                        id: ks_id.clone(),
                        b_hex: hex::encode(b_pt.as_bytes()),
                    }],
                },
            )
            .await
            .unwrap();

        // Guardian #0's forged share was caught & skipped; Guardians {1, 2, 3, 4} produced a valid sig!
        assert_eq!(ctrls[0].snapshot().byzantine_shares_rejected, 1);
        let _c = unblind_signature(
            &BlindSignature(hex::decode(&resp.signatures[0].c_hex).unwrap()),
            &r,
        )
        .unwrap();

        // Now ALSO take Guardian #1 Offline -> only 3 honest left (< 4 threshold) -> MUST halt!
        ctrls[1].set_mode(GuardianFaultMode::Offline);
        let q2 = mint
            .create_mint_quote(
                "bolt11",
                Nut04MintQuoteRequest {
                    amount: 2,
                    unit: "sat".into(),
                    description: None,
                },
            )
            .unwrap();
        let (b_pt2, _) = blind_message(b"chaos_note_2", &DstProfile::CashuBls, &mut OsRng).unwrap();
        assert!(mint
            .execute_mint(
                "bolt11",
                Nut04MintExecuteRequest {
                    quote: q2.quote,
                    outputs: vec![CashuBlindedMessage {
                        amount: 2,
                        id: ks_id,
                        b_hex: hex::encode(b_pt2.as_bytes()),
                    }],
                },
            )
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_nut13_deterministic_seed_restore_and_nut17_websocket_subscriptions() {
        use blind_seal_crypto::tbs::blind_message_with_factor;
        use nuts::derive_nut13_deterministic_output;
        use ws_nut17::{read_ws_frame, serve_nut17_ws_stream, write_ws_frame};

        let f = setup_4_of_5_cowrie_mint();
        let (client_io, server_io) = tokio::io::duplex(65_536);
        let mint_ws = f.mint.clone();
        tokio::spawn(async move {
            let _ = serve_nut17_ws_stream(mint_ws, server_io).await;
        });
        let mut ws = client_io;

        // 1. Mint 2 deterministic notes (`1 sat` + `4 sat` = `5 sat`) using NUT-13 seed derivation!
        let master_seed = "ocean cowrie chaumian threshold bls12-381 twelve word recovery phrase";
        let q = f
            .mint
            .create_mint_quote(
                "bolt11",
                Nut04MintQuoteRequest {
                    amount: 5,
                    unit: "sat".into(),
                    description: None,
                },
            )
            .unwrap();

        // Subscribe via NUT-17 `/v1/ws` to `bolt11_mint_quote`!
        let sub_q = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "subscribe",
            "params": {
                "kind": "bolt11_mint_quote",
                "subId": "sub_mint_1",
                "filters": [q.quote]
            }
        }))
        .unwrap();
        write_ws_frame(&mut ws, 0x1, &sub_q, Some([1, 2, 3, 4]))
            .await
            .unwrap();
        let (_, ack_bytes) = read_ws_frame(&mut ws).await.unwrap().unwrap();
        let ack_json: Value = serde_json::from_slice(&ack_bytes).unwrap();
        assert_eq!(ack_json.pointer("/result/status").and_then(|v| v.as_str()), Some("OK"));
        // Initial snapshot notification (`PAID`)
        let (_, snap_bytes) = read_ws_frame(&mut ws).await.unwrap().unwrap();
        let snap_json: Value = serde_json::from_slice(&snap_bytes).unwrap();
        assert_eq!(
            snap_json.pointer("/params/payload/state").and_then(|v| v.as_str()),
            Some("PAID")
        );

        let (sec0, r0) = derive_nut13_deterministic_output(master_seed, &f.sat_ks_id, 0);
        let (sec1, r1) = derive_nut13_deterministic_output(master_seed, &f.sat_ks_id, 1);
        let (bm0, _) = blind_message_with_factor(sec0.as_bytes(), &DstProfile::CashuBls, &r0).unwrap();
        let (bm1, _) = blind_message_with_factor(sec1.as_bytes(), &DstProfile::CashuBls, &r1).unwrap();

        let minted = f
            .mint
            .execute_mint(
                "bolt11",
                Nut04MintExecuteRequest {
                    quote: q.quote.clone(),
                    outputs: vec![
                        CashuBlindedMessage {
                            amount: 1,
                            id: f.sat_ks_id.clone(),
                            b_hex: hex::encode(bm0.as_bytes()),
                        },
                        CashuBlindedMessage {
                            amount: 4,
                            id: f.sat_ks_id.clone(),
                            b_hex: hex::encode(bm1.as_bytes()),
                        },
                    ],
                },
            )
            .await
            .unwrap();

        // Real-time NUT-17 push notification (`ISSUED`) arrives immediately on `/v1/ws`!
        let (_, issued_bytes) = read_ws_frame(&mut ws).await.unwrap().unwrap();
        let issued_json: Value = serde_json::from_slice(&issued_bytes).unwrap();
        assert_eq!(
            issued_json.pointer("/params/payload/state").and_then(|v| v.as_str()),
            Some("ISSUED")
        );

        // Subscribe via NUT-17 to `proof_state` of `Y0` (`1 sat` note) and spend `Y0`!
        let y0_hex = hex::encode(hash_secret_to_y_bytes(sec0.as_bytes(), &DstProfile::CashuBls));
        let sub_y = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "subscribe",
            "params": {
                "kind": "proof_state",
                "subId": "sub_y0",
                "filters": [y0_hex]
            }
        }))
        .unwrap();
        write_ws_frame(&mut ws, 0x1, &sub_y, Some([5, 6, 7, 8]))
            .await
            .unwrap();
        let _ = read_ws_frame(&mut ws).await.unwrap(); // OK ack
        let (_, y_snap) = read_ws_frame(&mut ws).await.unwrap().unwrap();
        let y_snap_json: Value = serde_json::from_slice(&y_snap).unwrap();
        assert_eq!(
            y_snap_json.pointer("/params/payload/state").and_then(|v| v.as_str()),
            Some("UNSPENT")
        );

        // Melt the `1 sat` note (`counter 0`), leaving ONLY the `4 sat` note (`counter 1`) unspent!
        let c0 = unblind_signature(
            &BlindSignature(hex::decode(&minted.signatures[0].c_hex).unwrap()),
            &r0,
        )
        .unwrap();
        let mq = f
            .mint
            .create_melt_quote(
                "bolt11",
                Nut05MeltQuoteRequest {
                    request: "lnbc1sat1p_test".into(),
                    unit: "sat".into(),
                    amount: Some(1),
                },
            )
            .unwrap();
        f.mint
            .execute_melt(
                "bolt11",
                Nut05MeltExecuteRequest {
                    quote: mq.quote,
                    inputs: vec![CashuProof {
                        amount: 1,
                        id: f.sat_ks_id.clone(),
                        secret: sec0,
                        c_hex: hex::encode(c0.as_bytes()),
                        witness: None,
                    }],
                    outputs: vec![],
                },
            )
            .await
            .unwrap();

        // Real-time NUT-17 `proof_state` push notification (`SPENT`) arrives on `/v1/ws`!
        let (_, y_spent) = read_ws_frame(&mut ws).await.unwrap().unwrap();
        let y_spent_json: Value = serde_json::from_slice(&y_spent).unwrap();
        assert_eq!(
            y_spent_json.pointer("/params/payload/state").and_then(|v| v.as_str()),
            Some("SPENT")
        );

        // 2. Simulate COMPLETE wallet wipe: recover strictly from `master_seed` via NUT-13 + NUT-09 + NUT-07!
        let mut scan_outputs = Vec::new();
        let mut scan_meta = Vec::new();
        for ctr in 0..8u64 {
            let (s_cand, r_cand) = derive_nut13_deterministic_output(master_seed, &f.sat_ks_id, ctr);
            let (b_cand, _) =
                blind_message_with_factor(s_cand.as_bytes(), &DstProfile::CashuBls, &r_cand)
                    .unwrap();
            scan_outputs.push(CashuBlindedMessage {
                amount: 1, // `/v1/restore` matches by `(keyset_id, B_)` and returns true minted amount!
                id: f.sat_ks_id.clone(),
                b_hex: hex::encode(b_cand.as_bytes()),
            });
            scan_meta.push((s_cand, r_cand, hex::encode(b_cand.as_bytes())));
        }

        let restore_resp = f
            .mint
            .restore(Nut09RestoreRequest {
                outputs: scan_outputs,
            })
            .await
            .unwrap();
        assert_eq!(restore_resp.signatures.len(), 2);

        let mut unspent_recovered_sats = 0u64;
        for (ro, rsig) in restore_resp
            .outputs
            .iter()
            .zip(restore_resp.signatures.iter())
        {
            let (sec, r_fac, _) = scan_meta.iter().find(|(_, _, b)| b == &ro.b_hex).unwrap();
            let y_chk = hex::encode(hash_secret_to_y_bytes(sec.as_bytes(), &DstProfile::CashuBls));
            let cs = f
                .mint
                .check_state(Nut07CheckStateRequest { ys: vec![y_chk] })
                .await
                .unwrap();
            if cs.states[0].state == ProofStateFlag::UNSPENT {
                let c_rec = unblind_signature(
                    &BlindSignature(hex::decode(&rsig.c_hex).unwrap()),
                    r_fac,
                )
                .unwrap();
                let slot = rsig.amount.trailing_zeros() as u8;
                blind_seal_crypto::tbs::verify_unblinded(
                    sec.as_bytes(),
                    &c_rec,
                    f.mint.keysets[&f.sat_ks_id].keyset.slot_pk(slot).unwrap(),
                    &DstProfile::CashuBls,
                )
                .unwrap();
                unspent_recovered_sats += rsig.amount;
            }
        }
        // Exactly the unspent `4 sat` note is recovered!
        assert_eq!(unspent_recovered_sats, 4);

        let _ = write_ws_frame(&mut ws, 0x8, &[], Some([0, 0, 0, 0])).await;
    }
}
