# 🐚 Cowrie — Independent Federated Cashu (`BLS12-381`) Mint

**Cowrie** is an independent clean-room Rust implementation of **Federated Cashu (`t-of-n` Threshold `BLS12-381`)**, featuring dealer-free 2-round Pedersen DKG, pluggable Consensus Boxes, and zero-`DLEQ` offline pairing verification for **Value4Value `HTTP-402` (`NUT-24` `X-Cashu`)** streaming micropayments.

---

## Highlights

- **4-of-5 Threshold `BLS12-381` (`min-sig`) Signing:** Survives offline guardians **and** actively detects/rejects forged shares from Byzantine guardians in real time via bilinear pairing checks (`e(S'_i, G2) == e(B_, PK_i)`).
- **Zero-`DLEQ` Offline Verification + Batch Settlement (`NUT-24` `X-Cashu`):** Each signature is **48 bytes** (50% smaller than `secp256k1` `BDHKE + NUT-12 DLEQ`), verifies offline in **<1 ms**, and batch-settles 64+ streamed 1-sat notes in **2 pairings** using 128-bit Fiat-Shamir weights.
- **Broad `NUT` Support:** `NUT-00` (compact binary V4 CBOR `cashuB...`), `NUT-01`, `NUT-02` (`02...` hex keyset IDs & `input_fee_ppk`), `NUT-03` (`/v1/swap`), `NUT-04`/`05`/`23` (two-step `bolt11` & `sui` quotes, `InstantBolt11Backend` + live **`LNbits`** backend), `NUT-06`, `NUT-07` (48-byte `Ys`), `NUT-09` (`/v1/restore`), `NUT-10`/`11` (`P2PK` + `SIG_ALL`), `NUT-13` (deterministic seed derivation & wallet restore), `NUT-14` (`HTLC`), `NUT-17` (`/v1/ws` real-time WebSocket subscriptions), and `NUT-24` (`HTTP-402`).
- **Pluggable "Consensus Box" Architecture (`CashuConsensusBox`):** Runs 100% standalone on Bitcoin/Lightning with atomic CBOR disk persistence (`--data-dir`), or settles directly against on-chain Sui Move shared-object vaults (`cashu/move/cowrie_cashu` via `--sui-rpc` + `scripts/deploy-sui-localnet.sh`) with 120-bit Fiat-Shamir batch pairing checks and hourly melt circuit breakers.
- **Non-Custodial Browser WASM Wallet & Guardian Chaos Playground:** Built directly into `cowried` at `http://127.0.0.1:3338/` (`cowrie_bls.wasm` + `localStorage` + `NUT-13` seed wipe/restore + live `NUT-17` WebSocket feed).

See [docs/hackathon-walkthrough.md](docs/hackathon-walkthrough.md) for the 3-minute judge walkthrough & architecture diagram, and [docs/federated-bls-spec-notes.md](docs/federated-bls-spec-notes.md) for protocol specification notes on standardizing `BLS12-381` keysets in `cashubtc/nuts`.

---

## Measured Benchmarks (`cowrie-bench --release`)

- **Client `hash_to_g1` + Blinding (`B_`):** `124.7 µs`
- **`4-of-5` Sign + 4 Pairing Share Checks + Lagrange Combine + Unblind:** `5.98 ms`
- **Single-Note Offline `NUT-24` Pairing Verify:** `1.21 ms`

| Batch Size (Notes) | Cowrie `cashuB` V4 (0B DLEQ) | `secp256k1` + `NUT-12` DLEQ `cashuB` | Token Size Savings | Naive (`2N` Pairings) | Fiat-Shamir Batch (`2` Pairings) | Speedup |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 234 B | 314 B | **25.5%** | 1.24 ms | **1.16 ms** | **1.1x** |
| 16 | 2,714 B | 3,994 B | **32.0%** | 19.48 ms | **5.11 ms** | **3.8x** |
| 64 | 10,652 B | 15,772 B | **32.5%** | 76.49 ms | **16.61 ms** | **4.6x** |
| 256 | 42,397 B | 62,877 B | **32.6%** | 306.70 ms | **63.69 ms** | **4.8x** |

---

## 30-Second Quickstart (Interactive Demo + CLI)

```bash
# 1. Start the 4-of-5 Federated Cashu Mint + Live Web Playground on port 3338
cargo run -p cowrie-cashu-mintd --bin cowried -- --bind 127.0.0.1:3338 --data-dir ./cowrie-data
# -> Open http://127.0.0.1:3338 in your browser to inject Byzantine/Offline guardian faults
#    and stream 1-sat/sec Value4Value HTTP-402 (X-Cashu) notes live!

# 2. Or use the NUT-13 deterministic terminal Cashu wallet (cowrie-cli)
cargo run -p cowrie-cashu-mintd --bin cowrie-cli -- info
cargo run -p cowrie-cashu-mintd --bin cowrie-cli -- seed
cargo run -p cowrie-cashu-mintd --bin cowrie-cli -- mint 64
cargo run -p cowrie-cashu-mintd --bin cowrie-cli -- checkstate
TOKEN=$(cargo run -q -p cowrie-cashu-mintd --bin cowrie-cli -- send 16)
cargo run -p cowrie-cashu-mintd --bin cowrie-cli -- receive "$TOKEN"
cargo run -p cowrie-cashu-mintd --bin cowrie-cli -- restore
cargo run -p cowrie-cashu-mintd --bin cowrie-cli -- melt 64 lnbc64sat1p_demo

# 3. Connect to a live Mutinynet / Signet / Mainnet LNbits node
cargo run -p cowrie-cashu-mintd --bin cowried -- \
  --lnbits-url https://your-lnbits-host \
  --lnbits-key YOUR_ADMIN_KEY

# 4. Connect to a live Sui localnet / Testnet Move Consensus Box (`cowrie_cashu::mint_vault`)
cargo run -p cowrie-cashu-mintd --bin cowried -- \
  --sui-rpc http://127.0.0.1:9000 \
  --blind-seal-package-id 0xYOUR_BLIND_SEAL_PKG \
  --cowrie-package-id 0xYOUR_COWRIE_CASHU_PKG \
  --vault-object-id 0xYOUR_MINT_VAULT_SHARED_OBJ \
  --keyset-info-id 0xYOUR_KEYSET_INFO_IMMUTABLE_OBJ \
  --sui-private-key suiprivkey1...

# 5. Run a 3-of-4 Virtual Fedimint Guardian cluster (`ws://127.0.0.1:8173..8176/ws` + Bech32 `fed11...` InviteCode)
cargo run -p cowrie-fedimint-shim --bin cowrie-fedimintd -- --base-port 8173 --threshold 3 --peers 4

# 6. Run a dealer-free 2-round Batched Pedersen DKG ceremony
cargo run -p blind-seal-server -- pedersen-dkg \
  --keyset-id 02_cowrie_sat --unit sat --threshold 4 --peers 5 --slots 32 --out-dir ./devnet-keys

# 7. Run the full Rust workspace + Sui Move VM test suites
cargo test --workspace
sui move test --path blind-seal/move/blind_seal
sui move test --path cashu/move/cowrie_cashu
sui move test --path fedimint/move/cowrie_fedimint
```

---

## Repository Structure

- **`blind-seal/`** — Shared threshold `BLS12-381` signing, Pedersen DKG, ElGamal transport, IBE/`TPE`, and Sui Move policy primitives (`blind_seal.move`).
- **`cashu/`** — Cowrie Federated Cashu mint (`cowried`), `cowrie-cli` wallet, interactive V4V dashboard, `LNbits` adapter, and `cowrie_cashu` Move Consensus Box.
- **`fedimint/`** — Experimental downstream-compatible Fedimint Virtual Guardian shim (`OOBNotes`, `SessionOutcome` seed recovery, and `LNv2` `TPE` settlement).
