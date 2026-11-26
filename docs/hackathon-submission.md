# 🐚 Cowrie — Hackathon Submission Package (Nut November 2026)

## Project Title
**Cowrie** — Independent Federated Cashu (`BLS12-381`) Mint, `CashuConsensusBox`, & Shared `Blind-Seal` Engine

## Tagline (One-Liner)
A clean-room Rust implementation of `4-of-5` threshold `BLS12-381` Federated Cashu with pluggable `CashuConsensusBox` backends, zero-`DLEQ` offline `HTTP-402` streaming, and a shared cryptographic core that powers **both Cashu and Fedimint**.

## Links
- **GitHub Repository:** https://github.com/bitccoli/cowrie
- **Live Fly.io Playground:** `https://cowrie-ecash.fly.dev` *(update after `fly deploy`)*
- **3-Minute Judge Walkthrough:** [docs/hackathon-walkthrough.md](hackathon-walkthrough.md)
- **Protocol Spec Notes (`NUT-BLS`):** [docs/federated-bls-spec-notes.md](federated-bls-spec-notes.md)

---

## Submission Description (Ready to Paste)

### 1. Why Independent Implementations & Client Diversity Matter
Just as Bitcoin relies on client diversity—and just as Fedimint demonstrated multi-implementation guardian interoperability at Ecash Hackday Berlin—**Federated Cashu (`BLS12-381`) cannot rely on a single reference codebase**. If every guardian runs the same implementation, a single cryptographic bug, serialization quirk, or state-machine edge case breaks the entire federation at once.

**Cowrie** is an independent, clean-room Rust implementation built from first principles around `blstrs` / `bls12_381` (`min-sig`), surfacing and solving real protocol subtleties along the way (per-denomination algebraic DKG isolation, 48-byte `NUT-07` `Y` nullifiers, 128-bit Fiat-Shamir batch weights, and zero-`DLEQ` offline pairing verification).

### 2. Why the `CashuConsensusBox` Pattern Is Easier to Operate
Running a classic federated eCash mint normally forces every guardian operator to coordinate a bespoke P2P BFT consensus cluster (AlephBFT / Tendermint) tightly coupled to the mint state machine.

Cowrie decouples **total-order state finality** from **threshold blind signing** via a pluggable `CashuConsensusBox` trait:
- **Zero-Ops Standalone Mode (`EmbeddedMoveEngine`):** Start a `4-of-5` threshold mint with a single binary (`cowried --data-dir ./cowrie-data`) and atomic CBOR disk snapshots—no external consensus cluster required, yet still eliminating split-state note bricking (verified by a 50-way concurrent double-spend race test: 1 winner, 49 `11001` rejections, 0 bricked notes).
- **On-Chain Public Proof-of-Reserves Mode (`LiveSuiJsonRpcBackend`):** Flip `--sui-rpc` and `--vault-object-id` to point the exact same mint and guardians at a Sui Move shared-object `MintVault<Asset>` with on-chain 120-bit Fiat-Shamir `BLS12-381` batch pairing checks and hourly melt circuit breakers.
- **Stateless Guardians (`blind-seal-server`):** Guardians never manage a consensus log; they simply verify finalized `BlindSigningTicket`s and sign blinded `G1` points, surviving offline peers and rejecting Byzantine forged shares in real time.

### 3. One Shared Threshold Core (`blind-seal`) for Both Cashu & Fedimint
Because `blind-seal` signs pre-blinded `G1` points (`B_ = r · H_DST(m)`) agnostically of the hash-to-curve Domain Separation Tag (`DST`), the **exact same `4-of-5` guardian committee** serves two downstream eCash ecosystems simultaneously:
- **`cashu/` (`cowried`, `cowrie-cli`, `cowrie_bls.wasm`):** Standard Cashu REST + `NUT-17` WebSocket (`/v1/ws`), `NUT-00` V4 CBOR (`cashuB...`), `NUT-01..14`, `NUT-23` (`bolt11` + `LNbits`), `NUT-24` (`X-Cashu` `HTTP-402`), and a **100% non-custodial browser WASM wallet** with `NUT-13` deterministic seed recovery.
- **`fedimint/` (`cowrie-fedimintd`):** Downstream-compatible Virtual Guardians speaking `jsonrpsee` WebSockets (`ws://.../ws`), Bech32-checksummed `fed11...` `OOBNotes` & `InviteCode`, `TieredMulti` binary TLV encoding, BIP-39 `SessionOutcome` seed recovery, and `LNv2` `BLS12-381` TPE preimage decryption.

### 4. Measured Results (`cowrie-bench --release`)
- **32.6% smaller** full `NUT-00` V4 `cashuB` tokens (`48B` `BLS12-381` vs `97B` `secp256k1` + `NUT-12` `DLEQ`) with full public offline pairing verification (`1.21 ms`).
- **4.8x faster** batch verification (`63.69 ms` vs `306.70 ms` for 256 streamed notes in just 2 pairings).
- **25/25** automated tests passing (`15` Rust workspace tests + `10` Sui Move VM unit tests) with 0 warnings.

---

## 75-Second Motion Demo Video Script (Subtitles + Background Music)

**Target Format:** `1920x1080`, `30fps`, `75 seconds`, dark editorial aesthetic (`#0b0f17` canvas, `#38bdf8` cyan, `#22c55e` emerald, `#f59e0b` amber), crisp bottom subtitles + warm ambient synth background track.
**Recommended Motion Tooling (Non-React):** **Motion Canvas** (imperative TypeScript coroutine animation — faster and cleaner than Remotion/React Motion) or our self-contained deterministic **SVG/HTML-Canvas + FFmpeg** pipeline in `demo-video/`.

| Time | Scene | Visual Motion | Subtitle |
|---|---|---|---|
| **0:00 – 0:08** | **1. Hook & Title** | Animated cowrie shell icon + glowing `4-of-5 BLS12-381` mesh springs in. | *"Meet Cowrie — an independent clean-room Rust implementation of Federated Cashu (BLS12-381)."* |
| **0:08 – 0:18** | **2. Client Diversity** | Monoculture single-node failure (red ripple) splits into 3 diverse independent guardian implementations staying green. | *"Federation security demands client diversity. One shared codebase means one bug breaks every guardian."* |
| **0:18 – 0:30** | **3. CashuConsensusBox** | Animated architecture diagram: `cowried` cleanly hot-swaps between `EmbeddedMoveEngine` (1-binary CBOR) and `Sui Move MintVault` (on-chain PoR). | *"Cowrie's pluggable CashuConsensusBox separates total-order finality from signing — effortless to operate standalone or on-chain."* |
| **0:30 – 0:42** | **4. 4-of-5 Guardian Chaos** | 5 guardian cards animate live: Guardian #0 flips **Byzantine** (forged share rejected by pairing `e(S'_i, G2) != e(B_, PK_i)`), while `{1,2,3,4}` mint smoothly! | *"Byzantine guardian forging shares? Bilinear pairing checks reject it in real time while 4-of-5 keeps issuing."* |
| **0:42 – 0:54** | **5. Zero-DLEQ V4V & Benchmarks** | Animated bar chart & `X-Cashu` 1-sat/sec pulse: `48B` vs `97B` (**32.6% smaller**), **4.8x faster** Fiat-Shamir batch pairing (`63.7 ms` for 256 notes). | *"No NUT-12 DLEQ bloat: 32.6% smaller cashuB tokens, 1.2ms offline verify, and 4.8x faster batch settlement."* |
| **0:54 – 1:05** | **6. One Core: Cashu + Fedimint** | Shared `blind-seal` threshold core branches upward to **Cashu** (`cashuB...`, WASM wallet, `NUT-13`/`17`) and **Fedimint** (`fed11...`, `jsonrpsee` WS, `LNv2` TPE). | *"One shared Blind-Seal threshold core powers both Cashu and Fedimint — unified guardians, two eCash ecosystems."* |
| **1:05 – 1:15** | **7. Outro & Call to Action** | Clean terminal command (`cargo run --bin cowried` / `fly deploy`), `25/25` tests green badge, GitHub URL `github.com/bitccoli/cowrie`. | *"Open source, 25/25 tests passing, ready to run locally or on Fly.io. Try Cowrie today."* |
