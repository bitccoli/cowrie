# `fedimint/` — Cowrie Fedimint Virtual Guardians

Downstream-compatible Fedimint Virtual Guardian shims backed upstream by `../blind-seal` and Sui Move (`move/cowrie_fedimint`):

- **`crates/cowrie-fedimint-shim`:** Stateless guardian RPC layer serving `ClientConfig` (`fedimint-mint` + `fedimint-lnv2`), `OOBNotes` (`fed11...`), client-side Lagrange share combination, BIP-340 `SpendKey` anti-front-running checks, signed `SessionOutcome` synthesis for 12-word BIP-39 seed recovery, and `LNv2` `TPE` 32-byte Lightning preimage decryption.
