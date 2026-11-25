use std::{fs, net::SocketAddr, path::PathBuf, sync::Arc};

use blind_seal_crypto::dkg::{
    deal_multi_slot_keyset, DkgParticipant, DkgRound1Broadcast, GuardianSecretKeyShare,
    PublicKeyset,
};
use blind_seal_sdk::sui_backend::LiveSuiJsonRpcBackend;
use blind_seal_server::{
    BlindSealKeyServerState, DkgFinalizeHttpReq, DkgPushSharesHttpReq, DkgRound1HttpReq,
};
use clap::{Parser, Subcommand};
use rand::rngs::OsRng;

#[derive(Parser)]
#[command(
    name = "blind-seal-server",
    about = "Threshold BLS12-381 Blind-Seal Key Server & Pedersen DKG Tooling"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Coordinates a networked dealer-free 2-round Pedersen DKG across live `blind-seal-server`
    /// URLs; private Round-2 shares flow strictly peer-to-peer between the guardian servers!
    CoordinateHttpDkg {
        #[arg(long)]
        ceremony_id: String,
        #[arg(long)]
        keyset_id: String,
        #[arg(long, default_value = "sat")]
        unit: String,
        #[arg(long, default_value_t = 4)]
        threshold: u16,
        #[arg(long, default_value_t = 32)]
        slots: usize,
        #[arg(long, value_delimiter = ',')]
        peer_urls: Vec<String>,
    },
    /// Executes an in-process 2-round Pedersen DKG ceremony and writes share files.
    PedersenDkg {
        #[arg(long)]
        keyset_id: String,
        #[arg(long, default_value = "sat")]
        unit: String,
        #[arg(long, default_value_t = 4)]
        threshold: u16,
        #[arg(long, default_value_t = 5)]
        peers: u16,
        #[arg(long, default_value_t = 32)]
        slots: usize,
        #[arg(long)]
        out_dir: PathBuf,
    },
    /// Fast single-step Shamir dealing for local devnets.
    DealKeyset {
        #[arg(long)]
        keyset_id: String,
        #[arg(long, default_value = "sat")]
        unit: String,
        #[arg(long, default_value_t = 4)]
        threshold: u16,
        #[arg(long, default_value_t = 5)]
        peers: u16,
        #[arg(long, default_value_t = 32)]
        slots: usize,
        #[arg(long)]
        out_dir: PathBuf,
    },
    /// Runs a live HTTP Blind-Seal Key Server (either pre-loaded with a keyset or ready for HTTP DKG).
    Serve {
        #[arg(long, default_value = "127.0.0.1:3100")]
        bind: SocketAddr,
        #[arg(long, default_value = "http://127.0.0.1:9000")]
        sui_rpc: String,
        #[arg(long, default_value_t = 0)]
        peer_id: u16,
        #[arg(long)]
        public_keyset: Option<PathBuf>,
        #[arg(long)]
        secret_share: Option<PathBuf>,
        #[arg(long)]
        keys_dir: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::CoordinateHttpDkg {
            ceremony_id,
            keyset_id,
            unit,
            threshold,
            slots,
            peer_urls,
        } => {
            let num_peers = peer_urls.len() as u16;
            anyhow::ensure!(
                threshold > 0 && threshold <= num_peers,
                "invalid threshold {threshold} for {num_peers} peers"
            );
            let http = reqwest::Client::builder().no_proxy().build()?;

            // 1. Trigger Round 1 on all remote guardians; collect public G2/G1 Feldman commitments
            let mut broadcasts = Vec::with_capacity(peer_urls.len());
            for url in &peer_urls {
                let b: DkgRound1Broadcast = http
                    .post(format!("{}/v1/dkg/round1", url.trim_end_matches('/')))
                    .json(&DkgRound1HttpReq {
                        ceremony_id: ceremony_id.clone(),
                        threshold,
                        num_peers,
                        num_slots: slots,
                    })
                    .send()
                    .await?
                    .error_for_status()?
                    .json()
                    .await?;
                broadcasts.push(b);
            }

            // 2. Instruct each guardian to push its private Round-2 shares directly peer-to-peer
            for url in &peer_urls {
                http.post(format!("{}/v1/dkg/push_shares", url.trim_end_matches('/')))
                    .json(&DkgPushSharesHttpReq {
                        ceremony_id: ceremony_id.clone(),
                        peer_urls: peer_urls.clone(),
                    })
                    .send()
                    .await?
                    .error_for_status()?;
            }

            // 3. Finalize & verify Feldman commitments on all guardians; assert identical PublicKeyset
            let mut pub_ks_opt: Option<PublicKeyset> = None;
            for url in &peer_urls {
                let pk: PublicKeyset = http
                    .post(format!("{}/v1/dkg/finalize", url.trim_end_matches('/')))
                    .json(&DkgFinalizeHttpReq {
                        ceremony_id: ceremony_id.clone(),
                        keyset_id: keyset_id.clone(),
                        unit: unit.clone(),
                        broadcasts: broadcasts.clone(),
                    })
                    .send()
                    .await?
                    .error_for_status()?
                    .json()
                    .await?;
                if let Some(prev) = &pub_ks_opt {
                    anyhow::ensure!(prev == &pk, "divergent PublicKeyset across guardians");
                } else {
                    pub_ks_opt = Some(pk);
                }
            }
            println!(
                "Networked dealer-free DKG finalized across {num_peers} servers for keyset '{keyset_id}'!"
            );
        }
        Commands::PedersenDkg {
            keyset_id,
            unit,
            threshold,
            peers,
            slots,
            out_dir,
        } => {
            fs::create_dir_all(&out_dir)?;
            let mut participants = Vec::new();
            let mut round1_bcasts = Vec::new();
            for p in 0..peers {
                let (part, bcast) = DkgParticipant::new(p, threshold, peers, slots, &mut OsRng)?;
                participants.push(part);
                round1_bcasts.push(bcast);
            }
            let all_r2: Vec<Vec<_>> = participants.iter().map(|p| p.round2_packages()).collect();

            let mut final_pub: Option<PublicKeyset> = None;
            for p in 0..peers {
                let inbox: Vec<_> = all_r2
                    .iter()
                    .map(|sender_pkgs| sender_pkgs[usize::from(p)].clone())
                    .collect();
                let (pub_ks, sk_share) = participants[usize::from(p)]
                    .finalize(&keyset_id, &unit, &round1_bcasts, &inbox)?;
                if let Some(prev) = &final_pub {
                    anyhow::ensure!(prev == &pub_ks, "DKG public keyset mismatch");
                } else {
                    final_pub = Some(pub_ks);
                }
                let sh_path = out_dir.join(format!("{keyset_id}_guardian_{p}.json"));
                fs::write(&sh_path, serde_json::to_string_pretty(&sk_share)?)?;
            }
            let pub_ks = final_pub.unwrap();
            fs::write(
                out_dir.join(format!("{keyset_id}_public.json")),
                serde_json::to_string_pretty(&pub_ks)?,
            )?;
            println!(
                "Completed dealer-free 2-round Pedersen DKG ({threshold}-of-{peers}, {slots} slots) in {}",
                out_dir.display()
            );
        }
        Commands::DealKeyset {
            keyset_id,
            unit,
            threshold,
            peers,
            slots,
            out_dir,
        } => {
            fs::create_dir_all(&out_dir)?;
            let (pub_ks, shares) =
                deal_multi_slot_keyset(&keyset_id, &unit, threshold, peers, slots, &mut OsRng)?;
            let pub_path = out_dir.join(format!("{keyset_id}_public.json"));
            fs::write(&pub_path, serde_json::to_string_pretty(&pub_ks)?)?;
            for sh in shares {
                let sh_path = out_dir.join(format!("{keyset_id}_guardian_{}.json", sh.peer_id));
                fs::write(&sh_path, serde_json::to_string_pretty(&sh)?)?;
            }
            println!(
                "Generated {threshold}-of-{peers} keyset '{keyset_id}' ({slots} slots) in {}",
                out_dir.display()
            );
        }
        Commands::Serve {
            bind,
            sui_rpc,
            peer_id,
            public_keyset,
            secret_share,
            keys_dir,
        } => {
            let (effective_peer, initial) = match (public_keyset, secret_share) {
                (Some(pk_p), Some(sk_p)) => {
                    let pub_ks: PublicKeyset = serde_json::from_str(&fs::read_to_string(&pk_p)?)?;
                    let sk_share: GuardianSecretKeyShare =
                        serde_json::from_str(&fs::read_to_string(&sk_p)?)?;
                    (sk_share.peer_id, vec![(pub_ks, sk_share)])
                }
                _ => (peer_id, Vec::new()),
            };
            let backend = Arc::new(LiveSuiJsonRpcBackend::new(sui_rpc));
            let state =
                BlindSealKeyServerState::new_with_storage(effective_peer, initial, backend, keys_dir);
            let listener = tokio::net::TcpListener::bind(bind).await?;
            tracing::info!(
                "Blind-Seal Key Server (peer {effective_peer}) listening on http://{bind}"
            );
            axum::serve(listener, state.router()).await?;
        }
    }

    Ok(())
}
