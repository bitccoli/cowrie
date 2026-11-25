use std::{fs, path::PathBuf};

use blind_seal_crypto::{
    dst::DstProfile,
    tbs::{
        blind_message_with_factor, hash_secret_to_y_bytes, unblind_signature, verify_unblinded,
        BlindSignature, PublicKeyG2,
    },
};
use clap::{Parser, Subcommand};
use cowrie_cashu_mintd::nuts::{
    derive_nut13_deterministic_output, CashuBlindedMessage, CashuProof, CashuTokenV4,
    Nut01KeysResponse, Nut03SwapRequest, Nut04MintExecuteRequest, Nut04MintQuoteRequest,
    Nut04MintQuoteResponse, Nut05MeltExecuteRequest, Nut05MeltQuoteRequest, Nut05MeltQuoteResponse,
    Nut07CheckStateRequest, Nut07CheckStateResponse, Nut09RestoreRequest, Nut09RestoreResponse,
    NutSignaturesResponse, ProofStateFlag,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};

#[derive(Parser)]
#[command(name = "cowrie-cli", about = "Cowrie Federated BLS12-381 Cashu CLI Wallet (NUT-13 Deterministic)")]
struct Cli {
    #[arg(long, default_value = "http://127.0.0.1:3338")]
    mint_url: String,
    #[arg(long, default_value = "./cowrie-wallet.json")]
    wallet: PathBuf,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Query mint NUT-06 info and active keysets
    Info,
    /// Show local unspent wallet balance and NUT-13 deterministic counter
    Balance,
    /// Display or set the wallet's NUT-13 deterministic recovery seed
    Seed {
        /// Optional recovery seed string to import
        #[arg(long)]
        set: Option<String>,
    },
    /// Recover unspent proofs from the NUT-13 recovery seed via NUT-09 `/v1/restore` + NUT-07 `/v1/checkstate`
    Restore {
        /// Optional seed override (uses wallet's stored seed if omitted)
        #[arg(long)]
        seed: Option<String>,
        /// Number of deterministic counter positions to scan
        #[arg(long, default_value_t = 64)]
        gap_limit: u64,
    },
    /// Mint `sat` eCash via a two-step NUT-23 `bolt11` quote
    Mint { amount: u64 },
    /// Export `amount` sats as a compact binary NUT-00 V4 CBOR token (`cashuB...`)
    Send { amount: u64 },
    /// Receive & swap an external `cashuB...` V4 token into fresh deterministic wallet proofs
    Receive { token: String },
    /// Privacy-preserving NUT-07 `/v1/checkstate` using 48-byte `Y` curve points
    CheckState,
    /// Melt sats to pay a Lightning `bolt11` invoice
    Melt { amount: u64, bolt11: String },
}

#[derive(Serialize, Deserialize)]
struct LocalWalletStore {
    master_seed: String,
    counter: u64,
    proofs: Vec<CashuProof>,
}

impl Default for LocalWalletStore {
    fn default() -> Self {
        let mut raw = [0u8; 16];
        OsRng.fill_bytes(&mut raw);
        Self {
            master_seed: format!("cowrie-seed-{}", hex::encode(raw)),
            counter: 0,
            proofs: Vec::new(),
        }
    }
}

impl LocalWalletStore {
    fn load(path: &PathBuf) -> Self {
        if let Ok(s) = fs::read_to_string(path) {
            if let Ok(parsed) = serde_json::from_str::<Self>(&s) {
                return parsed;
            }
        }
        let fresh = Self::default();
        let _ = fresh.save(path);
        fresh
    }

    fn save(&self, path: &PathBuf) -> anyhow::Result<()> {
        fs::write(path, serde_json::to_string_pretty(self)?)?;
        Ok(())
    }
}

fn decompose_powers_of_two(mut amount: u64) -> Vec<u64> {
    let mut parts = Vec::new();
    for bit in (0..32).rev() {
        let v = 1u64 << bit;
        while amount >= v {
            parts.push(v);
            amount -= v;
        }
    }
    parts
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let base = cli.mint_url.trim_end_matches('/').to_string();
    let http = reqwest::Client::builder().no_proxy().build()?;
    let mut store = LocalWalletStore::load(&cli.wallet);

    match cli.command {
        Commands::Info => {
            let info: serde_json::Value = http
                .get(format!("{base}/v1/info"))
                .send()
                .await?
                .json()
                .await?;
            println!("{}", serde_json::to_string_pretty(&info)?);
        }
        Commands::Balance => {
            let total: u64 = store.proofs.iter().map(|p| p.amount).sum();
            println!(
                "Balance: {total} sat ({} notes, NUT-13 counter={})",
                store.proofs.len(),
                store.counter
            );
        }
        Commands::Seed { set } => {
            if let Some(new_seed) = set {
                store.master_seed = new_seed;
                store.counter = 0;
                store.save(&cli.wallet)?;
                println!("Updated wallet NUT-13 seed.");
            }
            println!("NUT-13 Recovery Seed: {}", store.master_seed);
        }
        Commands::Restore { seed, gap_limit } => {
            if let Some(s) = seed {
                store.master_seed = s;
            }
            let keys_resp: Nut01KeysResponse = http
                .get(format!("{base}/v1/keys"))
                .send()
                .await?
                .json()
                .await?;
            let sat_ks = keys_resp
                .keysets
                .iter()
                .find(|k| k.unit == "sat")
                .ok_or_else(|| anyhow::anyhow!("mint has no active sat keyset"))?;

            let mut scan_outputs = Vec::with_capacity(gap_limit as usize);
            let mut scan_meta = Vec::with_capacity(gap_limit as usize);
            for ctr in 0..gap_limit {
                let (sec, r) =
                    derive_nut13_deterministic_output(&store.master_seed, &sat_ks.id, ctr);
                let (b_pt, _) =
                    blind_message_with_factor(sec.as_bytes(), &DstProfile::CashuBls, &r)?;
                let b_hex = hex::encode(b_pt.as_bytes());
                scan_outputs.push(CashuBlindedMessage {
                    amount: 1,
                    id: sat_ks.id.clone(),
                    b_hex: b_hex.clone(),
                });
                scan_meta.push((ctr, sec, r, b_hex));
            }

            let restored: Nut09RestoreResponse = http
                .post(format!("{base}/v1/restore"))
                .json(&Nut09RestoreRequest {
                    outputs: scan_outputs,
                })
                .send()
                .await?
                .json()
                .await?;

            let mut candidate_proofs = Vec::new();
            let mut max_ctr = store.counter;
            for (ro, rsig) in restored
                .outputs
                .into_iter()
                .zip(restored.signatures.into_iter())
            {
                if let Some((ctr, sec, r, _)) =
                    scan_meta.iter().find(|(_, _, _, bh)| *bh == ro.b_hex)
                {
                    max_ctr = max_ctr.max(ctr + 1);
                    let c = unblind_signature(&BlindSignature(hex::decode(&rsig.c_hex)?), r)?;
                    if let Some(pk_hex) = sat_ks.keys.get(&rsig.amount) {
                        verify_unblinded(
                            sec.as_bytes(),
                            &c,
                            &PublicKeyG2(hex::decode(pk_hex)?),
                            &DstProfile::CashuBls,
                        )?;
                    }
                    candidate_proofs.push(CashuProof {
                        amount: rsig.amount,
                        id: sat_ks.id.clone(),
                        secret: sec.clone(),
                        c_hex: hex::encode(c.as_bytes()),
                        witness: None,
                    });
                }
            }

            let mut unspent_proofs = Vec::new();
            if !candidate_proofs.is_empty() {
                let ys: Vec<String> = candidate_proofs
                    .iter()
                    .map(|p| {
                        hex::encode(hash_secret_to_y_bytes(
                            p.secret.as_bytes(),
                            &DstProfile::CashuBls,
                        ))
                    })
                    .collect();
                let cs: Nut07CheckStateResponse = http
                    .post(format!("{base}/v1/checkstate"))
                    .json(&Nut07CheckStateRequest { ys })
                    .send()
                    .await?
                    .json()
                    .await?;
                for (proof, st) in candidate_proofs.into_iter().zip(cs.states.into_iter()) {
                    if st.state == ProofStateFlag::UNSPENT {
                        unspent_proofs.push(proof);
                    }
                }
            }

            let recovered_sats: u64 = unspent_proofs.iter().map(|p| p.amount).sum();
            let count = unspent_proofs.len();
            store.proofs = unspent_proofs;
            store.counter = max_ctr;
            store.save(&cli.wallet)?;
            println!(
                "NUT-13 + NUT-09 Restore complete: recovered {recovered_sats} sat ({count} unspent notes, counter={max_ctr})"
            );
        }
        Commands::Mint { amount } => {
            let keys_resp: Nut01KeysResponse = http
                .get(format!("{base}/v1/keys"))
                .send()
                .await?
                .json()
                .await?;
            let sat_ks = keys_resp
                .keysets
                .iter()
                .find(|k| k.unit == "sat")
                .ok_or_else(|| anyhow::anyhow!("mint has no active sat keyset"))?;

            let quote: Nut04MintQuoteResponse = http
                .post(format!("{base}/v1/mint/quote/bolt11"))
                .json(&Nut04MintQuoteRequest {
                    amount,
                    unit: "sat".into(),
                    description: Some("cowrie-cli mint".into()),
                })
                .send()
                .await?
                .json()
                .await?;
            println!("BOLT11 Quote: {} (state: {:?})", quote.request, quote.state);

            let denoms = decompose_powers_of_two(amount);
            let mut outputs = Vec::new();
            let mut secrets_r = Vec::new();
            for amt in denoms {
                let (sec, r) = derive_nut13_deterministic_output(
                    &store.master_seed,
                    &sat_ks.id,
                    store.counter,
                );
                store.counter += 1;
                let (b_pt, _) =
                    blind_message_with_factor(sec.as_bytes(), &DstProfile::CashuBls, &r)?;
                outputs.push(CashuBlindedMessage {
                    amount: amt,
                    id: sat_ks.id.clone(),
                    b_hex: hex::encode(b_pt.as_bytes()),
                });
                secrets_r.push((amt, sec, r));
            }

            let sigs: NutSignaturesResponse = http
                .post(format!("{base}/v1/mint/bolt11"))
                .json(&Nut04MintExecuteRequest {
                    quote: quote.quote,
                    outputs,
                })
                .send()
                .await?
                .json()
                .await?;

            for ((amt, sec, r), bsig) in secrets_r.into_iter().zip(sigs.signatures.into_iter()) {
                let c = unblind_signature(&BlindSignature(hex::decode(&bsig.c_hex)?), &r)?;
                let pk_hex = sat_ks
                    .keys
                    .get(&amt)
                    .ok_or_else(|| anyhow::anyhow!("missing denom key"))?;
                verify_unblinded(
                    sec.as_bytes(),
                    &c,
                    &PublicKeyG2(hex::decode(pk_hex)?),
                    &DstProfile::CashuBls,
                )?;
                store.proofs.push(CashuProof {
                    amount: amt,
                    id: sat_ks.id.clone(),
                    secret: sec,
                    c_hex: hex::encode(c.as_bytes()),
                    witness: None,
                });
            }
            store.save(&cli.wallet)?;
            println!("Minted and verified {amount} sat via deterministic NUT-13 + BLS12-381 pairing!");
        }
        Commands::Send { amount } => {
            let total: u64 = store.proofs.iter().map(|p| p.amount).sum();
            if total < amount {
                anyhow::bail!("insufficient balance: have {total} sat, need {amount} sat");
            }
            let inputs = std::mem::take(&mut store.proofs);
            let ks_id = inputs[0].id.clone();

            let send_denoms = decompose_powers_of_two(amount);
            let change_denoms = decompose_powers_of_two(total - amount);
            let mut outputs = Vec::new();
            let mut meta = Vec::new();

            for (is_send, amt) in send_denoms
                .into_iter()
                .map(|a| (true, a))
                .chain(change_denoms.into_iter().map(|a| (false, a)))
            {
                let (sec, r) =
                    derive_nut13_deterministic_output(&store.master_seed, &ks_id, store.counter);
                store.counter += 1;
                let (b_pt, _) =
                    blind_message_with_factor(sec.as_bytes(), &DstProfile::CashuBls, &r)?;
                outputs.push(CashuBlindedMessage {
                    amount: amt,
                    id: ks_id.clone(),
                    b_hex: hex::encode(b_pt.as_bytes()),
                });
                meta.push((is_send, amt, sec, r));
            }

            let sigs: NutSignaturesResponse = http
                .post(format!("{base}/v1/swap"))
                .json(&Nut03SwapRequest { inputs, outputs })
                .send()
                .await?
                .json()
                .await?;

            let mut send_proofs = Vec::new();
            for ((is_send, amt, sec, r), bsig) in meta.into_iter().zip(sigs.signatures.into_iter())
            {
                let c = unblind_signature(&BlindSignature(hex::decode(&bsig.c_hex)?), &r)?;
                let proof = CashuProof {
                    amount: amt,
                    id: ks_id.clone(),
                    secret: sec,
                    c_hex: hex::encode(c.as_bytes()),
                    witness: None,
                };
                if is_send {
                    send_proofs.push(proof);
                } else {
                    store.proofs.push(proof);
                }
            }
            store.save(&cli.wallet)?;
            let v4 = CashuTokenV4::from_proofs(&base, "sat", &send_proofs, None)
                .and_then(|t| t.encode())
                .map_err(|e| anyhow::anyhow!(e))?;
            println!("{v4}");
        }
        Commands::Receive { token } => {
            let decoded = CashuTokenV4::decode(&token).map_err(|e| anyhow::anyhow!(e))?;
            let inputs = decoded.to_proofs();
            let total: u64 = inputs.iter().map(|p| p.amount).sum();
            let ks_id = inputs[0].id.clone();

            let denoms = decompose_powers_of_two(total);
            let mut outputs = Vec::new();
            let mut meta = Vec::new();
            for amt in denoms {
                let (sec, r) =
                    derive_nut13_deterministic_output(&store.master_seed, &ks_id, store.counter);
                store.counter += 1;
                let (b_pt, _) =
                    blind_message_with_factor(sec.as_bytes(), &DstProfile::CashuBls, &r)?;
                outputs.push(CashuBlindedMessage {
                    amount: amt,
                    id: ks_id.clone(),
                    b_hex: hex::encode(b_pt.as_bytes()),
                });
                meta.push((amt, sec, r));
            }

            let sigs: NutSignaturesResponse = http
                .post(format!("{base}/v1/swap"))
                .json(&Nut03SwapRequest { inputs, outputs })
                .send()
                .await?
                .json()
                .await?;

            for ((amt, sec, r), bsig) in meta.into_iter().zip(sigs.signatures.into_iter()) {
                let c = unblind_signature(&BlindSignature(hex::decode(&bsig.c_hex)?), &r)?;
                store.proofs.push(CashuProof {
                    amount: amt,
                    id: ks_id.clone(),
                    secret: sec,
                    c_hex: hex::encode(c.as_bytes()),
                    witness: None,
                });
            }
            store.save(&cli.wallet)?;
            println!("Received and swapped {total} sat into deterministic NUT-13 BLS proofs!");
        }
        Commands::CheckState => {
            let ys: Vec<String> = store
                .proofs
                .iter()
                .map(|p| {
                    hex::encode(hash_secret_to_y_bytes(
                        p.secret.as_bytes(),
                        &DstProfile::CashuBls,
                    ))
                })
                .collect();
            let resp: Nut07CheckStateResponse = http
                .post(format!("{base}/v1/checkstate"))
                .json(&Nut07CheckStateRequest { ys })
                .send()
                .await?
                .json()
                .await?;
            let unspent = resp
                .states
                .iter()
                .filter(|s| s.state == ProofStateFlag::UNSPENT)
                .count();
            println!(
                "Checked {} proofs privately via Y curve points: {unspent} UNSPENT",
                resp.states.len()
            );
        }
        Commands::Melt { amount, bolt11 } => {
            let q: Nut05MeltQuoteResponse = http
                .post(format!("{base}/v1/melt/quote/bolt11"))
                .json(&Nut05MeltQuoteRequest {
                    request: bolt11,
                    unit: "sat".into(),
                    amount: Some(amount),
                })
                .send()
                .await?
                .json()
                .await?;
            let total: u64 = store.proofs.iter().map(|p| p.amount).sum();
            if total < amount {
                anyhow::bail!("insufficient balance ({total} < {amount})");
            }
            let inputs = std::mem::take(&mut store.proofs);
            let res: Nut05MeltQuoteResponse = http
                .post(format!("{base}/v1/melt/bolt11"))
                .json(&Nut05MeltExecuteRequest {
                    quote: q.quote,
                    inputs,
                    outputs: vec![],
                })
                .send()
                .await?
                .json()
                .await?;
            store.save(&cli.wallet)?;
            println!(
                "Melted! State={:?}, Preimage={}",
                res.state,
                res.payment_preimage.unwrap_or_default()
            );
        }
    }
    Ok(())
}
