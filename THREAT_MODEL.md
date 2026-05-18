# Linus Salamander Enclave System (LSES) - Threat Model

## 1. Threat Model

### Trusted Components
- Enclave Service
- Enclave signing key
- Consumer signing identity
- Runtime memory boundary, within the limitations of the host environment

### Untrusted or Semi-Trusted Components
- GitHub repository
- Local filesystem
- Network transport
- CI/CD runner
- Operator workstation

### Attacker Capabilities
- **Attacker reads the GitHub repository:** The attacker gains access to encrypted snapshots but cannot decrypt them without the wrapped Data Encryption Key (DEK) and the Enclave's Key Encryption Key (KEK). They lack the signing keys to forge states.
- **Attacker modifies encrypted snapshots:** Modifications will invalidate the cryptographic signature or the snapshot hash, leading to rejection during recovery or read.
- **Attacker attempts rollback to an old commit:** The system verifies the monotonic epoch and previous snapshot hash, causing rollbacks to be detected and rejected, provided a valid chain head trust anchor exists.
- **Attacker copies local disk:** Disk-based forensics yield no plaintext secrets because plaintext is not intentionally materialized, and temporary artifacts are purged.
- **Attacker intercepts payload in transit:** TLS protects transport-level confidentiality and integrity. AES-256-GCM protects the sealed snapshot payload independently of the transport layer. Even if transport logs or GitHub storage are exposed, the payload remains encrypted as long as envelope keys are protected. TLS is required but not the sole confidentiality boundary.
- **Attacker compromises only the consumer key:** They cannot forge a valid snapshot because the Enclave Service signature is also required (dual attestation).
- **Attacker compromises only the remote repository:** They can delete history (denial of service) but cannot read or forge secrets.
- **Attacker compromises host during runtime:** If an attacker gains full privileges during runtime, they may inspect memory and extract ephemeral secrets (out of scope unless hardware enclaves are used).

### Security Assumptions
- AES-256-GCM is secure when used with unique nonces and correct key management.
- Ed25519 provides secure and unforgeable digital signatures.
- Private keys of the Enclave are never exported or leaked.
- A trusted monotonic epoch or chain head is maintained to prevent replay attacks.
- The system strictly validates signatures, previous hashes, and epochs before accepting any snapshot.

## 2. Failure Modes

| Failure | Detection | Expected Behavior |
|---|---|---|
| Signature over partial envelope | Required fields missing from canonical signed body | Reject snapshot, emit `Secret.signature.invalid` |
| Commit SHA circular dependency | `commit_sha` required before persistence | Move `commit_sha` to persistence receipt |
| Consumer signed request only | Countersignature does not verify against canonical envelope body | Reject snapshot, emit `Secret.signature.invalid` |
| AES-GCM nonce reuse | Same nonce used in same DEK/context | Refute operation, emit `Secret.nonce.reused` |
| Invalid AES-GCM auth tag | Auth tag verification fails | Reject snapshot, emit `Secret.snapshot.auth_tag.invalid` |
| Invalid snapshot hash | `snapshot_id` mismatch | Reject snapshot, emit `Secret.snapshot.hash.invalid` |
| Replay of valid old envelope | Snapshot already seen or not next in chain | Reject snapshot, emit `Secret.replay.detected` |
| GitHub push failure | Persistence adapter error | Keep operation uncommitted, purge temp artifacts |
| Rollback attempt | `epoch <= last_accepted_epoch` | Reject snapshot, emit `Secret.rollback.detected` |
| Chain fork | `previous_snapshot_hash` mismatch | Refuse recovery, emit `Secret.snapshot.chain.invalid` |
| Local purge failure | Purger returns error | Emit critical security event, halt |
| Unauthorized consumer | Policy check failure | Refute request, emit `Secret.access.refuted` |
| Missing wrapped DEK | Envelope schema validation fails | Reject snapshot |
| Wrapped DEK cannot be unwrapped | Key unwrap failure | Reject read/recovery |
| Missing trust anchor during cold start | No `trusted_chain_head` available | Enter recovery-limited mode |
| Plaintext export not authorized | Policy check fails | Return handle-only result or refute request |
| Secure overwrite unsupported | Filesystem capability check or config | Warn and rely on no-plaintext-materialization invariant |
| Stale wrapped key id | `dek_wrapping_key_id` cannot be resolved | Reject recovery until key policy resolves |
| Self-referential snapshot hash | `snapshot_id` included in its own hash input | Reject schema/implementation |
| Signature input mismatch | Enclave and Consumer signatures verify against different byte sequences | Reject snapshot |
| Persistence receipt treated as snapshot identity | `commit_sha` required for `snapshot_id` verification | Reject implementation or move receipt outside snapshot identity |
| Rotation signs partial body | Rotation signature produced before `epoch`, `previous_snapshot_hash`, `sealed_payload`, or `wrapped_dek` are finalized | Reject rotated snapshot |
