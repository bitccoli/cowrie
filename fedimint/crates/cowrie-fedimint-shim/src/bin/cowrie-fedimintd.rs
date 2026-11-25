use std::{net::SocketAddr, sync::Arc};

use blind_seal_crypto::{dkg::deal_multi_slot_keyset, dst::DstProfile};
use blind_seal_sdk::{
    client::BlindSealPeerHandler,
    sui_backend::{EmbeddedMoveEngine, VaultConfig},
};
use blind_seal_server::BlindSealKeyServerState;
use clap::Parser;
use cowrie_fedimint_shim::{
    wire::{FedimintClientConfig, InviteCode, IrohPeerEndpoint},
    VirtualGuardianShim,
};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

#[derive(Parser)]
#[command(
    name = "cowrie-fedimintd",
    about = "Cowrie Virtual Fedimint Guardian Daemon (jsonrpsee WebSocket + Bech32 fed11... + Blind-Seal)"
)]
struct Cli {
    /// Base port for spawning Virtual Guardian WebSocket/HTTP RPC servers (`base_port + peer_id`).
    #[arg(long, default_value_t = 8173)]
    base_port: u16,
    #[arg(long, default_value_t = 3)]
    threshold: u16,
    #[arg(long, default_value_t = 4)]
    peers: u16,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    let (pub_ks, shares) = deal_multi_slot_keyset(
        "fedimint_btc_msat_01",
        "msat",
        cli.threshold,
        cli.peers,
        24,
        &mut OsRng,
    )?;

    let move_vault = Arc::new(EmbeddedMoveEngine::new(1));
    move_vault.register_vault(VaultConfig {
        keyset: pub_ks.clone(),
        dst: DstProfile::FedimintTbs,
        notes_per_coin_unit: 1_000,
        hourly_melt_cap_notes: 100_000_000,
        input_fee_ppk: 0,
    });

    let mut g_keys = Vec::new();
    let mut g_pks = Vec::new();
    for _ in 0..cli.peers {
        let sk = SigningKey::generate(&mut OsRng);
        g_pks.push(sk.verifying_key().to_bytes());
        g_keys.push(sk);
    }

    let fed_id = FedimintClientConfig::compute_federation_id(&pub_ks, &g_pks);
    let config = Arc::new(FedimintClientConfig {
        federation_id: fed_id,
        federation_name: "Cowrie Sui-Backed Fedimint".into(),
        active_modules: vec!["fedimint-mint".into(), "fedimint-lnv2".into()],
        mint_tbs_keyset: pub_ks.clone(),
        guardian_ed25519_pks: g_pks.clone(),
    });

    let invite = InviteCode {
        federation_id: fed_id,
        peers: (0..cli.peers)
            .map(|p| (p, format!("ws://127.0.0.1:{}/ws", cli.base_port + p)))
            .collect(),
        api_secret: None,
        iroh_endpoints: (0..cli.peers)
            .map(|p| IrohPeerEndpoint {
                peer_id: p,
                node_id_hex: hex::encode(g_pks[usize::from(p)]),
                relay_url: "https://relay.iroh.network".into(),
                alpn: "fedimint/rpc/0".into(),
            })
            .collect(),
    };

    tracing::info!(
        "Cowrie {}-of-{} Virtual Fedimint Guardians ready!\nInviteCode: {}",
        cli.threshold,
        cli.peers,
        invite.encode().map_err(|e| anyhow::anyhow!(e))?
    );

    let mut tasks = Vec::new();
    for peer in 0..cli.peers {
        let seal_peer: Arc<dyn BlindSealPeerHandler> = Arc::new(BlindSealKeyServerState::new(
            peer,
            vec![(pub_ks.clone(), shares[usize::from(peer)].clone())],
            move_vault.clone(),
        ));
        let shim = VirtualGuardianShim::new(
            peer,
            config.clone(),
            g_keys[usize::from(peer)].clone(),
            seal_peer,
            move_vault.clone(),
        );
        let addr = SocketAddr::from(([127, 0, 0, 1], cli.base_port + peer));
        let listener = tokio::net::TcpListener::bind(addr).await?;
        tracing::info!("Virtual Guardian #{peer} listening on ws://{addr}/ws (HTTP JSON-RPC: http://{addr}/jsonrpc)");
        tasks.push(tokio::spawn(async move {
            axum::serve(listener, shim.router()).await
        }));
    }

    for t in tasks {
        t.await??;
    }
    Ok(())
}
