use std::{
    fs,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use blind_seal_crypto::{
    dkg::{deal_multi_slot_keyset, GuardianSecretKeyShare, PublicKeyset},
    dst::DstProfile,
};
use blind_seal_sdk::{
    client::{BlindSealClient, BlindSealPeerHandler, ControllableGuardianPeer},
    ptb::{SuiAddress, SuiEd25519Signer, SuiTypeTag},
    sui_backend::{
        CashuConsensusBox, EmbeddedMoveEngine, LiveSuiJsonRpcBackend, SuiConsensusBackend,
        SuiOnChainDeployment, VaultConfig,
    },
};
use blind_seal_server::BlindSealKeyServerState;
use clap::Parser;
use cowrie_cashu_mintd::{
    dashboard::{attach_demo_routes, DemoPlaygroundState},
    lnbits::LnbitsBolt11Backend,
    nuts::derive_nut02_keyset_id,
    Bolt11Backend, InstantBolt11Backend, KeysetRuntimeMeta, SealCashuMint,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

#[derive(Parser)]
#[command(
    name = "cowried",
    about = "Cowrie: Independent Federated Cashu (BLS12-381) Mint Daemon & V4V Playground"
)]
struct Cli {
    #[arg(long, default_value = "127.0.0.1:3338")]
    bind: SocketAddr,
    #[arg(long, default_value_t = 4)]
    threshold: u16,
    #[arg(long, default_value_t = 5)]
    peers: u16,
    /// Optional directory to persist keysets, guardian shares, and Consensus Box state across restarts.
    #[arg(long)]
    data_dir: Option<PathBuf>,
    /// Optional comma-separated URLs of external `blind-seal-server` guardian processes
    /// (e.g. `http://127.0.0.1:3100,http://127.0.0.1:3101,...`).
    #[arg(long, value_delimiter = ',')]
    seal_urls: Vec<String>,
    /// Optional LNbits instance URL (`https://legend.lnbits.com` / Mutinynet LNbits) for live Bolt11!
    #[arg(long)]
    lnbits_url: Option<String>,
    /// Optional LNbits admin API key paired with `--lnbits-url`.
    #[arg(long)]
    lnbits_key: Option<String>,
    /// Optional Sui fullnode JSON-RPC URL (`http://127.0.0.1:9000` for `sui start` localnet,
    /// or `https://fullnode.testnet.sui.io:443` for Sui Testnet).
    #[arg(long)]
    sui_rpc: Option<String>,
    /// Published `blind_seal` Sui Move package ID (`0x...`) when running against `--sui-rpc`.
    #[arg(long)]
    blind_seal_package_id: Option<String>,
    /// Published `cowrie_cashu` Sui Move package ID (`0x...`) when running against `--sui-rpc`.
    #[arg(long)]
    cowrie_package_id: Option<String>,
    /// Shared `MintVault<Asset>` Sui object ID (`0x...`) when running against `--sui-rpc`.
    #[arg(long)]
    vault_object_id: Option<String>,
    /// Frozen `KeysetInfo` Sui object ID (`0x...`) when running against `--sui-rpc`.
    #[arg(long)]
    keyset_info_id: Option<String>,
    /// Collateral Move coin type tag (defaults to `0x2::sui::SUI`) when running against `--sui-rpc`.
    #[arg(long, default_value = "0x2::sui::SUI")]
    sui_asset_type: String,
    /// Optional Sui operator Ed25519 private key (`suiprivkey1...`, 64-char hex, or keystore base64)
    /// for signing on-chain PTBs via `sui_executeTransactionBlock`.
    #[arg(long)]
    sui_private_key: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct PersistedCommitteeBundle {
    ks_sat: PublicKeyset,
    shares_sat: Vec<GuardianSecretKeyShare>,
    ks_usd: PublicKeyset,
    shares_usd: Vec<GuardianSecretKeyShare>,
}

fn generate_or_load_committee(
    data_dir: Option<&PathBuf>,
    threshold: u16,
    peers: u16,
) -> anyhow::Result<PersistedCommitteeBundle> {
    if let Some(dir) = data_dir {
        fs::create_dir_all(dir)?;
        let keys_file = dir.join("committee_keysets.json");
        if keys_file.exists() {
            let raw = fs::read_to_string(&keys_file)?;
            return Ok(serde_json::from_str(&raw)?);
        }
        let bundle = deal_fresh_bundle(threshold, peers)?;
        fs::write(&keys_file, serde_json::to_string_pretty(&bundle)?)?;
        return Ok(bundle);
    }
    deal_fresh_bundle(threshold, peers)
}

fn deal_fresh_bundle(threshold: u16, peers: u16) -> anyhow::Result<PersistedCommitteeBundle> {
    let (mut ks_sat, mut shares_sat) =
        deal_multi_slot_keyset("tmp_sat", "sat", threshold, peers, 32, &mut OsRng)?;
    let sat_id = derive_nut02_keyset_id(0x02, &ks_sat.slot_agg_pks);
    ks_sat.keyset_id = sat_id.clone();
    for s in &mut shares_sat {
        s.keyset_id = sat_id.clone();
    }

    let (mut ks_usd, mut shares_usd) =
        deal_multi_slot_keyset("tmp_usd", "usd", threshold, peers, 32, &mut OsRng)?;
    let usd_id = derive_nut02_keyset_id(0x02, &ks_usd.slot_agg_pks);
    ks_usd.keyset_id = usd_id.clone();
    for s in &mut shares_usd {
        s.keyset_id = usd_id.clone();
    }

    Ok(PersistedCommitteeBundle {
        ks_sat,
        shares_sat,
        ks_usd,
        shares_usd,
    })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    let bundle = generate_or_load_committee(cli.data_dir.as_ref(), cli.threshold, cli.peers)?;

    let consensus_box = Arc::new(if let Some(dir) = &cli.data_dir {
        EmbeddedMoveEngine::open_or_create_persistent(dir.join("consensus_box.cbor"), 4)?
    } else {
        EmbeddedMoveEngine::default()
    });

    consensus_box.register_vault(VaultConfig {
        keyset: bundle.ks_sat.clone(),
        dst: DstProfile::CashuBls,
        notes_per_coin_unit: 1,
        hourly_melt_cap_notes: 100_000_000,
        input_fee_ppk: 0,
    });
    consensus_box.register_vault(VaultConfig {
        keyset: bundle.ks_usd.clone(),
        dst: DstProfile::SuiNative,
        notes_per_coin_unit: 1,
        hourly_melt_cap_notes: 10_000_000,
        input_fee_ppk: 0,
    });

    let (guardian_consensus_backend, active_cashu_box): (
        Arc<dyn SuiConsensusBackend>,
        Arc<dyn CashuConsensusBox>,
    ) = if let Some(rpc_url) = &cli.sui_rpc {
        let mut live = LiveSuiJsonRpcBackend::new(rpc_url.clone());
        let has_signer = if let Some(raw_sk) = &cli.sui_private_key {
            let signer = SuiEd25519Signer::parse_sui_key(raw_sk)?;
            tracing::info!(
                "Loaded Sui Ed25519 operator key for address {}",
                signer.sui_address()
            );
            live = live.with_operator_signer(signer);
            true
        } else {
            false
        };
        let has_vault = if let Some(vault_hex) = &cli.vault_object_id {
            let vault_id = SuiAddress::from_hex(vault_hex)?;
            let bs_pkg = match &cli.blind_seal_package_id {
                Some(h) => SuiAddress::from_hex(h)?,
                None => SuiAddress::default(),
            };
            let cc_pkg = match &cli.cowrie_package_id {
                Some(h) => SuiAddress::from_hex(h)?,
                None => bs_pkg,
            };
            let ks_info = match &cli.keyset_info_id {
                Some(h) => Some(SuiAddress::from_hex(h)?),
                None => None,
            };
            let asset_type = SuiTypeTag::parse_struct(&cli.sui_asset_type)?;
            tracing::info!(
                "Configured live Sui Consensus Box at {rpc_url} (MintVault={vault_id}, asset={})",
                cli.sui_asset_type
            );
            live = live.with_deployment(SuiOnChainDeployment {
                blind_seal_pkg: bs_pkg,
                cowrie_cashu_pkg: cc_pkg,
                vault_object_id: vault_id,
                keyset_info_id: ks_info,
                asset_type,
            });
            true
        } else {
            tracing::info!("Configured live Sui RPC backend at {rpc_url}");
            false
        };
        let live_arc = Arc::new(live);
        let box_impl: Arc<dyn CashuConsensusBox> = if has_signer && has_vault {
            live_arc.clone()
        } else {
            consensus_box.clone()
        };
        (live_arc, box_impl)
    } else {
        (consensus_box.clone(), consensus_box.clone())
    };

    let mut controllable_peers: Vec<Arc<ControllableGuardianPeer>> = Vec::new();
    let seal_client = if !cli.seal_urls.is_empty() {
        tracing::info!(
            "Connecting to {} external Blind-Seal guardian servers",
            cli.seal_urls.len()
        );
        BlindSealClient::new_http(cli.seal_urls)
    } else {
        let mut handlers: Vec<Arc<dyn BlindSealPeerHandler>> = Vec::new();
        for peer in 0..cli.peers {
            let inner = Arc::new(BlindSealKeyServerState::new(
                peer,
                vec![
                    (
                        bundle.ks_sat.clone(),
                        bundle.shares_sat[usize::from(peer)].clone(),
                    ),
                    (
                        bundle.ks_usd.clone(),
                        bundle.shares_usd[usize::from(peer)].clone(),
                    ),
                ],
                guardian_consensus_backend.clone(),
            ));
            let ctrl = Arc::new(ControllableGuardianPeer::new(peer, inner));
            controllable_peers.push(ctrl.clone());
            handlers.push(ctrl);
        }
        BlindSealClient::new_with_handlers(handlers)
    };

    let bolt11_backend: Arc<dyn Bolt11Backend> =
        if let (Some(url), Some(key)) = (cli.lnbits_url, cli.lnbits_key) {
            tracing::info!("Using live LNbits Bolt11 backend at {url}");
            Arc::new(LnbitsBolt11Backend::new(url, key))
        } else {
            Arc::new(InstantBolt11Backend::default())
        };

    let sat_keyset_id = bundle.ks_sat.keyset_id.clone();
    let mint = SealCashuMint::new_with_bolt11(
        "Cowrie Federated Cashu Mint",
        vec![
            KeysetRuntimeMeta {
                keyset: bundle.ks_sat,
                dst: DstProfile::CashuBls,
                input_fee_ppk: 0,
            },
            KeysetRuntimeMeta {
                keyset: bundle.ks_usd,
                dst: DstProfile::SuiNative,
                input_fee_ppk: 0,
            },
        ],
        active_cashu_box,
        seal_client,
        bolt11_backend,
    );

    let demo = DemoPlaygroundState {
        mint: mint.clone(),
        sat_keyset_id: sat_keyset_id.clone(),
        peers: controllable_peers,
        creator_v4v_buffer: Arc::new(Mutex::new(Vec::new())),
        total_v4v_settled_sats: Arc::new(Mutex::new(0)),
    };
    let app = attach_demo_routes(mint.router(), demo);

    let listener = tokio::net::TcpListener::bind(cli.bind).await?;
    tracing::info!(
        "Cowrie ({}-of-{} BLS12-381 Federated Cashu Mint) listening on http://{} [Dashboard: http://{}]",
        cli.threshold,
        cli.peers,
        cli.bind,
        cli.bind,
    );
    axum::serve(listener, app).await?;
    Ok(())
}
