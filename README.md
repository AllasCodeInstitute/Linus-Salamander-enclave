![logo Linus Salamander](https://i.imgur.com/wWwd5q8.png)
# Linus Salamander Enclave System (LSES)

LSES is a cryptographic secret management engine designed for environments requiring zero local persistence. Unlike traditional secret managers that rely on trusted local storage or disks, LSES operates on a "Purge-on-Write" philosophy. 

LSES does not treat GitHub as a trusted environment for plaintext secrets. Instead, GitHub is solely used to store versioned, dual-attested cryptographic envelopes. The cryptographic authority resides entirely within the Enclave/Agent. The local state is strictly ephemeral, meaning plaintext secrets exist only in runtime memory and only during the authorized operational window.

## Documentation

The documentation has been split into dedicated files for better readability and formalization:

- [**SPEC.md**](./SPEC.md): The complete technical specification, including architecture, components, cryptographic models, API surface, flows, and security invariants.
- [**THREAT_MODEL.md**](./THREAT_MODEL.md): The detailed threat model, security assumptions, attacker capabilities, and a comprehensive failure modes table.

## Core Cryptographic Contract

```text
snapshot_id = sha256(canonical_snapshot_body)
signature_input = canonical({ snapshot_id, snapshot_body })

GitHub stores:
{ snapshot_body, snapshot_id, attestations, persistence_receipt }

GitHub never defines cryptographic validity.
```

## Design Goals

- Zero local plaintext persistence.
- Ephemeral runtime secret material.
- Remote encrypted versioned persistence.
- Dual attestation for snapshot validity.
- Replay and rollback resistance.
- Deterministic audit trail.
- Explicit purge lifecycle.
- Separation between storage provider and cryptographic authority.

---
*LSES reduces disk-based forensic exposure by avoiding local plaintext persistence. Runtime memory attacks remain in scope unless hardware-backed isolation is enabled. When hardware enclaves are unavailable, LSES mitigates unauthorized access through encrypted snapshots, dual signatures, and replay guards. This does not replace hardware-backed memory isolation.*

<img src="https://i.imgur.com/eodldQK.png" style="width: 300px;" />
