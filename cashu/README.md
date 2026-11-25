# `cashu/` — Cowrie Federated Cashu Mint (`cowried`)

Independent clean-room Rust implementation of **Federated Cashu (`t-of-n` Threshold `BLS12-381`)** built on `../blind-seal`:

- **`crates/cowrie-cashu-mintd` (`cowried` binary):**
  - **`NUT-00`:** Compact binary V4 CBOR (`cashuB...`) multi-unit tokens (`t[].i` raw keyset bytes + `c` raw 48-byte `G1` signatures) and standard `{ "detail", "code" }` error codes (`11001`, `11002`, `11005`, `12001`, `20001`, `20002`).
  - **`NUT-01` & `NUT-02`:** `/v1/keys`, `/v1/keys/{keyset_id}`, `/v1/keysets` with deterministic 16-hex `02...` keyset IDs and `input_fee_ppk` fee calculation.
  - **`NUT-03`:** Atomic `/v1/swap` ordered through the Consensus Box before releasing 4-of-5 `BLS12-381` shares.
  - **`NUT-04`, `NUT-05`, & `NUT-23` (`bolt11` + `sui`):** Full two-step mint and melt quote lifecycles (`/v1/mint/quote/{method}`, `/v1/melt/quote/{method}`).
  - **`NUT-07` & `NUT-09`:** Privacy-preserving 48-byte `Ys` (`H_dst(secret)`) `/v1/checkstate` and stateless `/v1/restore` signature recovery.
  - **`NUT-10`, `NUT-11` (`P2PK`), & `NUT-14` (`HTLC`):** Official JSON-tuple secrets (`["P2PK", {...}]`, `["HTLC", {...}]`) with both `SIG_INPUTS` and full-transaction `SIG_ALL` output tamper protection.
  - **`NUT-24` (`HTTP-402` `X-Cashu`):** Zero-`DLEQ` sub-millisecond offline pairing verification + Fiat-Shamir slot-grouped batch settlement.
- **`move/cowrie_cashu`:** Sui Move 2024 `MintVault<Asset>` indexing fixed 48-byte `Y` nullifiers and grouping `G1` hashes per slot (`<= max_slots` pairings per batch).

## Run Standalone (`cowried`)

```bash
cargo run --offline -p cowrie-cashu-mintd --bin cowried -- \
  --bind 127.0.0.1:3338 \
  --threshold 4 \
  --peers 5 \
  --data-dir ./cowrie-data
```
