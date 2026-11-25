# `blind-seal/` — Shared Threshold `BLS12-381` Signing & IBE Layer

Shared foundation used by both `../cashu` and `../fedimint`:

- **`crates/blind-seal-crypto`:** Multi-slot `BLS12-381` Shamir dealing + 2-round dealer-free Pedersen DKG (`G2` pubkeys, `G1` blind messages/signatures), offline pairing verification, aggregated batch multi-pairing verification, ElGamal encrypted share transport, and Boneh-Franklin IBE / `TPE`.
- **`crates/blind-seal-sdk`:** Client SDK and pluggable Consensus Box trait (`EmbeddedMoveEngine` for standalone zero-chain operation + `LiveSuiJsonRpcBackend` for Sui `sui_dryRunTransactionBlock` policy enforcement).
- **`crates/blind-seal-server`:** Stateless HTTP threshold Key Server (`/v1/keysets`, `/v1/fetch_blind_sig`, `/v1/fetch_key`) + `deal-keyset` CLI.
- **`move/blind_seal`:** Sui Move 2024 package registering `KeysetInfo` and issuing immutable `BlindSigningTicket` commitments.
