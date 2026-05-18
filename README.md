# Linus Salamander Enclave System (LSES)

## 1. Overview
The Linus Salamander Enclave System (LSES) is a cryptographic secret management engine designed for environments requiring zero local persistence. Unlike traditional secret managers that rely on trusted local storage or disks, LSES operates on a "Purge-on-Write" philosophy. 

LSES does not treat GitHub as a trusted environment for plaintext secrets. Instead, GitHub is solely used to store versioned, dual-attested cryptographic envelopes. The cryptographic authority resides entirely within the Enclave/Agent. The local state is strictly ephemeral, meaning plaintext secrets exist only in runtime memory and only during the authorized operational window.

## 2. Design Goals
- Zero local plaintext persistence.
- Ephemeral runtime secret material.
- Remote encrypted versioned persistence.
- Dual attestation for snapshot validity.
- Replay and rollback resistance.
- Deterministic audit trail.
- Explicit purge lifecycle.
- Separation between storage provider and cryptographic authority.

## 3. Non-Goals
- LSES does not promise security against a fully compromised host during runtime.
- It does not replace hardware-backed memory isolation (e.g., SGX/Nitro/TPM) when physical/hardware isolation is mandated.
- It does not guarantee that runtime memory cannot be inspected by an attacker with sufficient (e.g., root/kernel) privileges.
- It does not use GitHub as a trusted storage mechanism for plaintext.
- It does not eliminate the need for regular key rotation and operational security policies.

## 4. Threat Model

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

## 5. Envelope Encryption Model
LSES employs an envelope encryption architecture to ensure that ephemeral keys can be securely recovered without persisting them in plaintext.

Secret plaintext
→ encrypted with per-snapshot Data Encryption Key (DEK)
→ DEK wrapped by Enclave Key Encryption Key (KEK) / KMS / TPM / Nitro / recipient public key
→ `sealed_payload` + `wrapped_dek` persisted to GitHub
→ plaintext DEK purged after operation

**Important Rule:** A DEK is ephemeral in plaintext form, not unrecoverable. It is persisted only as a wrapped key inside the cryptographic envelope. The GitHub repository stores only the `wrapped_dek`, `sealed_payload`, and authenticated metadata. It never stores the plaintext DEK. Recovery and reading are only possible because the Enclave can unwrap the DEK in an authorized manner.

## 6. Runtime Components

### LinusSalamanderEnclave
- **Responsibility:** Orchestrates the core operations, tying together memory storage, cryptographic operations, and persistence.
- **Inputs:** `SecretWriteRequest`, `SecretReadRequest`, `SecretRotationRequest`
- **Outputs:** Operation results, orchestration events.
- **Invariants:** Ensures no operation completes without fulfilling the purge lifecycle and dual attestation constraints.

### EnclaveMemoryStore
- **Responsibility:** Maintains secrets in memory strictly during runtime.
- **Inputs:** `SecretWriteRequest`, `SecretReadRequest`, `SecretRotationRequest`
- **Outputs:** `Secret.memory.loaded`, `Secret.memory.purged`, `Secret.memory.updated`
- **Invariants:** 
  - Never writes plaintext to disk.
  - Never exports secret material without an authorized policy.
  - All sensitive material must have an explicit purge lifecycle.

### SecretSnapshotBuilder
- **Responsibility:** Constructs the state snapshot to be persisted.
- **Inputs:** Current memory state, metadata.
- **Outputs:** Raw snapshot payload.
- **Invariants:** The snapshot must accurately represent the current state and increment the epoch.

### SnapshotCanonicalizer
- **Responsibility:** Produces a deterministic representation of the snapshot for hashing and signing.
- **Inputs:** Raw snapshot payload.
- **Outputs:** `Secret.snapshot.canonicalized` (canonical byte array).
- **Invariants:** The same semantic payload must always produce the exact same byte array.

### SnapshotSealer
- **Responsibility:** Encrypts the canonical snapshot payload using a DEK, and wraps the DEK using a KEK.
- **Inputs:** Canonical snapshot, Ephemeral DEK, Enclave KEK.
- **Outputs:** `Secret.snapshot.sealed` (AES-256-GCM ciphertext, nonce, auth tag, wrapped DEK).
- **Invariants:** Must use a cryptographically secure random nonce and unique DEK for every operation.

### EphemeralKeyManager
- **Responsibility:** Generates and manages the lifecycle of runtime Data Encryption Keys (DEKs).
- **Inputs:** Key generation requests.
- **Outputs:** Ephemeral symmetric keys (DEKs).
- **Invariants:** Plaintext DEKs must be purged from memory immediately after sealing or unsealing operations.

### DualAttestationSigner
- **Responsibility:** Signs the canonical snapshot envelope with the Enclave's identity and coordinates consumer countersigning.
- **Inputs:** Sealed snapshot.
- **Outputs:** `Secret.snapshot.signed_by_enclave`, `Secret.snapshot.countersigned_by_consumer`.
- **Invariants:** Signatures must be applied to the canonicalized envelope.

### ConsumerCountersignatureVerifier
- **Responsibility:** Validates that the consuming system has actively approved the snapshot.
- **Inputs:** Consumer signature, canonical envelope, consumer public key.
- **Outputs:** Verification boolean.
- **Invariants:** Invalid signatures must immediately halt the pipeline.

### GitHubPersistenceAdapter
- **Responsibility:** Commits and pushes the cryptographic envelope to the remote repository.
- **Inputs:** Cryptographic envelope.
- **Outputs:** `Secret.snapshot.persisted.github`
- **Invariants:** Must never transmit plaintext secrets or plaintext DEKs.

### SnapshotReplayGuard & RollbackProtectionGuard
- **Responsibility:** Ensures the snapshot chain is continuous and monotonically increasing against a trusted anchor.
- **Inputs:** `epoch`, `previous_snapshot_hash`.
- **Outputs:** `Secret.rollback.detected`, `Secret.replay.detected`.
- **Invariants:** `epoch > last_accepted_epoch` and `previous_snapshot_hash == trusted_chain_head`.

### LocalArtifactPurger
- **Responsibility:** Minimizes local persistence by deleting temporary artifacts and ensuring the implementation does not intentionally materialize plaintext secrets on disk. Secure overwrite is best-effort and filesystem-dependent.
- **Inputs:** Paths to temporary artifacts.
- **Outputs:** `Secret.local_artifacts.purged`
- **Invariants:** Must execute regardless of whether the preceding operations succeeded or failed.

#### Filesystem and Secure Deletion Limitations
- LSES must avoid creating plaintext files in the first place.
- Delete/overwrite is a mitigation measure, not an absolute guarantee.
- Secure deletion depends heavily on the filesystem, hardware, and environment (e.g., SSD wear-leveling, COW filesystems).
- The primary guarantee relies on not materializing plaintext to disk, rather than deleting it afterward.

### AuditTrailWriter
- **Responsibility:** Records the deterministic audit trail of cryptographic events.
- **Inputs:** System events.
- **Outputs:** Audit logs.
- **Invariants:** Logs must not contain sensitive material.

### SecretAccessPolicyEngine
- **Responsibility:** Validates authorization before granting access to secrets in memory or exporting them.
- **Inputs:** Access requests, consumer identity.
- **Outputs:** `Secret.access.granted`, `Secret.access.refuted`
- **Invariants:** Default deny; explicit authorization required.

## 7. Cryptographic Envelope Format
The canonical JSON structure for a persisted snapshot. It must be canonicalized before signing to avoid signature mismatches for identical semantic content.

```json
{
  "envelope": {
    "schema_version": "lses.snapshot.v1",
    "snapshot_id": "sha256(canonical_envelope_body)",
    "project_id": "allascode",
    "environment": "prod",
    "operation": "write_secret",
    "secret_ref": "sha256(project_id + environment + secret_name)",
    "epoch": 42,
    "previous_snapshot_hash": "sha256(previous_snapshot)",
    "created_at": "2026-05-17T00:00:00Z",
    "algorithm": {
      "content_encryption": "AES-256-GCM",
      "key_wrapping": "X25519-HKDF-A256KW | KMS | TPM | NitroKMS",
      "enclave_signature": "Ed25519",
      "consumer_signature": "Ed25519"
    },
    "aad": {
      "project": "allascode",
      "environment": "prod",
      "snapshot_type": "secret_state",
      "operation": "write_secret",
      "epoch": 42,
      "previous_snapshot_hash": "sha256(previous_snapshot)"
    },
    "nonce": "base64url(random_nonce)",
    "sealed_payload": "base64url(ciphertext)",
    "auth_tag": "base64url(gcm_tag)",
    "wrapped_dek": "base64url(encrypted_data_encryption_key)",
    "dek_wrapping_key_id": "enclave-kek-2026-05",
    "enclave_public_key_id": "enclave-signing-key-2026-05",
    "enclave_signature": "base64url(signature)",
    "consumer_public_key_id": "consumer-key-2026-05",
    "consumer_countersignature": "base64url(countersignature)"
  },
  "persistence_receipt": {
    "provider": "github",
    "repository": "owner/repo",
    "branch": "main",
    "commit_sha": "github_commit_sha",
    "committed_at": "2026-05-17T00:00:05Z"
  }
}
```

- **schema_version**: Protocol version identifier.
- **snapshot_id**: Cryptographic hash of the envelope content (excluding signatures) to uniquely identify the payload. Computed before persistence.
- **operation**: The action that generated this snapshot (e.g., `write_secret`, `rotate_secret`).
- **secret_ref**: A hashed or canonical reference to the secret. It must not leak the raw secret name if the name is considered sensitive.
- **epoch**: Monotonically increasing integer to prevent rollback.
- **previous_snapshot_hash**: Links this snapshot to the previous one, forming a chain.
- **algorithm.key_wrapping**: Specifies how the DEK was wrapped (e.g., via a KMS, TPM, or specific algorithm).
- **aad**: Additional Authenticated Data bound to the AES-GCM encryption.
- **nonce**: The initialization vector for AES-GCM.
- **sealed_payload**: The encrypted state.
- **auth_tag**: AES-GCM authentication tag ensuring ciphertext integrity.
- **wrapped_dek**: The ephemeral Data Encryption Key, encrypted by the KEK.
- **dek_wrapping_key_id**: Identifier for the Key Encryption Key (KEK) used to wrap the DEK.
- **signatures**: Ed25519 signatures from both the Enclave and the Consumer.

**Important Note on Persistence Receipt:**
`commit_sha` is a persistence receipt, not part of the original canonical envelope body. The persistence receipt may be logged, audited, or signed separately if required, but verification of the cryptographic snapshot must not depend on GitHub’s commit SHA.

**Consumer Countersignature Scope:**
The consumer countersigns the *same* finalized canonical envelope body signed by the Enclave, after all security-critical fields are finalized and before persistence. The consumer must not sign merely the request, the plaintext payload, or a partial envelope. This proves the consumer agreed with the final cryptographic state to be persisted.

## 8. Event Model
The internal event system uses a unified naming convention to track the lifecycle of secrets.

### Write Events
- `Secret.write.requested`: Emitted when a write operation begins.
- `Secret.snapshot.created`: Emitted when the in-memory state is snapshotted.
- `Secret.snapshot.canonicalized`: Emitted when the snapshot is deterministic.
- `Secret.snapshot.sealed`: Emitted when AES-GCM encryption and key wrapping finish.
- `Secret.snapshot.signed_by_enclave`: Emitted when the enclave applies its signature.
- `Secret.snapshot.countersigned_by_consumer`: Emitted when the consumer applies its signature.
- `Secret.snapshot.persist.requested`: Emitted to trigger the GitHub adapter.
- `Secret.snapshot.persisted.github`: Emitted on successful remote persistence.
- `Secret.local_artifacts.purge.requested`: Triggered post-persistence to clean up.
- `Secret.local_artifacts.purged`: Confirmation of local cleanup.
- `Secret.write.completed`: Emitted on fully successful end-to-end write.
- `Secret.write.refuted`: Emitted if validation or policy checks fail.

### Read Events
- `Secret.read.requested`: Emitted when a read operation begins.
- `Secret.memory.loaded`: Emitted when state is instantiated in memory.
- `Secret.snapshot.loaded`: Emitted when remote snapshot is fetched.
- `Secret.snapshot.verified`: Emitted when signatures, epoch, and chain validate.
- `Secret.payload.unsealed`: Emitted upon successful AES-GCM decryption and DEK unwrapping.
- `Secret.access.granted`: Emitted when the policy allows reading.
- `Secret.access.refuted`: Emitted on policy or verification failure.
- `Secret.memory.purged`: Emitted when runtime memory is wiped post-read.

### Rotation Events
- `Secret.rotate.requested`: Emitted to trigger a key/secret rotation.
- `Secret.rotation.validated`: Validation of the rotation policy.
- `Secret.rotation.snapshot.created`: A new snapshot reflecting the rotated state.
- `Secret.rotation.completed`: Rotation successfully committed and purged locally.
- `Secret.rotation.refuted`: Rotation failed validation.

### Security/Fault Events
- `Secret.nonce.reused`: Emitted when the system detects nonce reuse for the same key or cryptographic context. Critical for AES-GCM.
- `Secret.replay.detected`: Emitted when a valid or previously seen envelope is presented out of expected sequence.
- `Secret.rollback.detected`: Emitted when `epoch <= last_accepted_epoch`.
- `Secret.snapshot.chain.invalid`: Emitted when `previous_snapshot_hash != trusted_chain_head`.
- `Secret.signature.invalid`: Emitted when the Enclave or Consumer signature does not verify.
- `Secret.snapshot.auth_tag.invalid`: Emitted when AES-GCM authentication fails.
- `Secret.snapshot.hash.invalid`: Emitted when `snapshot_id` does not match the expected canonical hash.

## 9. Implemented Flows

### 9.1 Write Secret Flow
1. Receive `SecretWriteRequest`.
2. Validate consumer identity via `SecretAccessPolicyEngine`.
3. Validate write authorization/policy.
4. Resolve current `trusted_chain_head`.
5. Compute next `epoch`.
6. Attach `previous_snapshot_hash`.
7. Compute `secret_ref`.
8. Build raw snapshot payload from memory state.
9. Canonicalize snapshot payload.
10. Generate per-snapshot DEK via `EphemeralKeyManager`.
11. Seal canonical payload with AES-256-GCM using DEK.
12. Wrap DEK using Enclave's KEK, KMS, TPM, Nitro, or public key.
13. Purge plaintext DEK immediately after sealing.
14. Build canonical envelope body containing metadata, AAD, `sealed_payload`, and `wrapped_dek`.
15. Compute `snapshot_id`.
16. Sign canonical envelope body using the Enclave's Ed25519 key. (Nothing must be signed before the envelope body is complete).
17. Request Consumer countersignature over the same canonical envelope body.
18. Verify both signatures.
19. Persist envelope to GitHub (`GitHubPersistenceAdapter`).
20. Attach or emit persistence receipt containing `commit_sha`.
21. Explicitly purge temporary local artifacts (`LocalArtifactPurger`).
22. Emit `Secret.write.completed`.

### 9.2 Read Secret Flow
1. Receive `SecretReadRequest`.
2. Validate consumer identity and access policy.
3. Fetch the latest snapshot envelope from GitHub.
4. Validate the Enclave's Ed25519 signature and Consumer's countersignature.
5. Validate the `previous_snapshot_hash` against the local chain head.
6. Validate the `epoch` strictly exceeds the last accepted epoch.
7. Unwrap the `wrapped_dek` strictly within the Enclave boundary.
8. Unseal the payload into `EnclaveMemoryStore` using the DEK.
9. Return a `RuntimeSecretHandle` by default. (Plaintext export requires explicit policy authorization).
10. Automatically purge the plaintext DEK and sensitive material from memory after the handle expires or is consumed.

### 9.3 Rotate Secret Flow
1. Receive `SecretRotateRequest`.
2. Validate the current state and rotation policy.
3. Generate new secret material.
4. Generate a new DEK.
5. Create a new snapshot with the updated material.
6. Wrap the new DEK to create a new `wrapped_dek`.
7. Increment the `epoch`.
8. Chain the `previous_snapshot_hash` to the current state.
9. Sign (Enclave) and countersign (Consumer) the envelope.
10. Persist to GitHub.
11. Logically invalidate the previous version.
12. Purge the old material from runtime memory and any local artifacts.

### 9.4 Recovery Flow
To recover state from the remote repository (e.g., upon system restart):
1. Fetch the latest sequence of snapshots from GitHub.
2. Validate the chain recursively using `previous_snapshot_hash`.
3. Verify the chain against the trust anchor.
4. If no trusted chain head exists, enter recovery-limited mode (mitigated trust).
5. Discard any snapshot with an invalid signature, auth tag, or incorrect hash.
6. Detect and reject rollback attempts by verifying `epoch` continuity.
7. Restore the verified state *only* into runtime memory.
8. Never materialize plaintext to disk during the recovery process.

## 10. Chain Head Trust Anchor
Rollback protection is only strong if the system possesses a reliable anchor to compare the remote state against. 

**Possible anchors include:**
- Hardware monotonic counter.
- TPM/Nitro/SGX-backed sealed checkpoint.
- External transparency log.
- Signed remote chain head quorum.
- Operator-pinned genesis/head hash.
- Independent append-only audit log.
- Policy-defined trusted checkpoint.

If LSES cold-starts with no trusted chain head, a malicious repository could present an older but internally consistent snapshot chain. 
- If no `trusted_chain_head` exists, the system must enter **recovery-limited mode**.
- In this mode, it can validate cryptographic integrity and chain consistency, but it cannot assert the complete absence of historical rollbacks.
- For production usage, LSES requires at least one source of trusted chain head or checkpoint.

## 11. Replay and Rollback Protection
LSES enforces strict checks to prevent historical data from being replayed or an older state being forced upon the system.

A snapshot is accepted only if:
- `snapshot_id == sha256(canonical_envelope_body)`
- `verify(enclave_signature, canonical_envelope_body)`
- `verify(consumer_countersignature, canonical_envelope_body)`
- `aes_gcm_auth_tag_valid(sealed_payload, aad, nonce, unwrapped_dek)`
- `previous_snapshot_hash == trusted_chain_head`
- `epoch > last_accepted_epoch`
- `nonce_not_reused(dek_context, nonce)`
- `schema_version is supported`
- `policy_allows(operation, consumer, secret_ref)`

**Protections provided:**
- **Signature verification** detects envelope tampering.
- **AES-GCM tag verification** detects payload/AAD tampering.
- **Epoch** prevents accepting older states.
- **Chain head** prevents accepting old but internally consistent chains.
- **Nonce tracking** prevents AES-GCM misuse.
- **Trust anchor** is required for strong rollback protection after cold start.

## 12. Security Invariants
- **Invariant LSES-001 — No Local Plaintext Persistence:** No plaintext secret may be intentionally written to local disk at any point in the lifecycle.
- **Invariant LSES-002 — Persisted State Must Be Sealed:** Every persisted snapshot must contain an encrypted payload, authenticated metadata, enclave signature, and consumer countersignature.
- **Invariant LSES-003 — Dual Attestation Required:** A snapshot is invalid unless both the Enclave Service and Consuming System signatures verify against the canonical envelope.
- **Invariant LSES-004 — Monotonic Epoch:** A snapshot with an epoch lower than or equal to the last accepted epoch must be rejected.
- **Invariant LSES-005 — Chain Continuity:** A snapshot must reference the currently trusted previous snapshot hash.
- **Invariant LSES-006 — Purge After Persistence:** After a successful write, temporary local artifacts must be queued for deletion (best-effort secure overwrite).
- **Invariant LSES-007 — No GitHub Trust Assumption:** GitHub must never be required to preserve confidentiality or semantic validity.
- **Invariant LSES-008 — Canonical Signature Input:** All signed data must be canonicalized before signing.
- **Invariant LSES-009 — Runtime Exposure Bound:** Plaintext secret material may exist only inside an authorized runtime operation window.
- **Invariant LSES-010 — Refuse on Verification Failure:** Any failure in signature, hash, epoch, schema, or policy validation must immediately refute the operation and purge memory.
- **Invariant LSES-011 — Wrapped DEK Required:** Every persisted encrypted snapshot must include a wrapped DEK or equivalent recoverable key reference. Plaintext DEK must never be persisted.
- **Invariant LSES-012 — Plaintext DEK Runtime Bound:** A plaintext DEK may exist only during an authorized cryptographic operation window.
- **Invariant LSES-013 — Trust Anchor Required for Strong Rollback Protection:** Strong rollback protection requires a trusted chain head, trusted checkpoint, monotonic counter, or equivalent external trust anchor.
- **Invariant LSES-014 — Default Handle-Based Secret Access:** Secret reads must return runtime handles by default. Plaintext export requires explicit policy authorization.
- **Invariant LSES-015 — Best-Effort Local Artifact Deletion:** Local deletion and overwrite are best-effort mitigations. The primary invariant is that plaintext secrets must not be intentionally materialized to local disk.
- **Invariant LSES-016 — Countersignature Scope:** The consumer countersignature must cover the same finalized canonical envelope body signed by the Enclave. Partial, pre-sealing, request-only, or plaintext-only countersignatures are invalid.
- **Invariant LSES-017 — Commit SHA Is Not Snapshot Identity:** Git commit SHA is a persistence receipt and must not be required to compute the cryptographic snapshot identity.
- **Invariant LSES-018 — Security-Critical Fields Before Signing:** All security-critical fields, including epoch, previous_snapshot_hash, AAD, sealed_payload, auth_tag and wrapped_dek, must be finalized before Enclave signature and Consumer countersignature.
- **Invariant LSES-019 — Nonce Reuse Refutation:** AES-GCM nonce reuse within the same key/context must refute the operation and emit `Secret.nonce.reused`.
- **Invariant LSES-020 — Persistence Receipt Separation:** Persistence receipts may be stored and audited, but they are separate from the canonical cryptographic envelope unless explicitly signed in a second-stage receipt signature.

## 13. Failure Modes

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

## 14. GitHub Persistence Contract
GitHub is treated strictly as an untrusted blob store for cryptographic envelopes and persistence receipts.

**GitHub may store:**
- The sealed snapshot envelope.
- Public metadata and schema version.
- Key identifiers (public keys and KEK IDs).
- The AES-GCM encrypted payload.
- The `wrapped_dek`.
- Ed25519 signatures.
- Git commit metadata (as a persistence receipt).

**GitHub must never store:**
- Plaintext secrets.
- Plaintext DEKs.
- Private signing keys.
- Decrypted snapshot data.
- Local memory dumps in plaintext.

**Conventions:**
- Commits are uniquely identified and represent a single, atomic state change.
- A single trunk branch strategy is typically used to represent the linear epoch chain.
- Malicious remote alterations are detected during recovery via cryptographic signature and hash mismatch.

## 15. API Surface
Below is a conceptual TypeScript representation of the minimal API surface for the Enclave:

```typescript
type SecretWriteRequest = {
  projectId: string;
  environment: string;
  secretName: string;
  secretValue: string;
  consumerId: string;
};

type SecretWriteResult = {
  snapshotId: string;
  epoch: number;
  commitSha: string;
  purged: boolean;
};

type SecretReadRequest = {
  projectId: string;
  environment: string;
  secretName: string;
  consumerId: string;
};

type RuntimeSecretHandle = {
  handleId: string;
  expiresAt: string;
  scope: "runtime-only";
};

type SecretReadResult = {
  secretValueRef?: RuntimeSecretHandle;
  secretValue?: string;
  epoch: number;
  expiresAt: string;
  exportPolicy: "handle-only" | "plaintext-export-allowed";
};

interface LinusSalamanderEnclave {
  writeSecret(input: SecretWriteRequest): Promise<SecretWriteResult>;
  readSecret(input: SecretReadRequest): Promise<SecretReadResult>;
  rotateSecret(input: SecretRotateRequest): Promise<SecretRotateResult>;
  verifySnapshot(input: SnapshotVerificationRequest): Promise<SnapshotVerificationResult>;
  recoverLatest(input: RecoveryRequest): Promise<RecoveryResult>;
  purgeLocalArtifacts(): Promise<PurgeResult>;
}
```

## 16. AllasCode Integration
LSES integrates into the broader agentic and event-sourced architecture of AllasCode through dedicated agents. 

The Secret Plane validates invariants and emits semantic events before any state is persisted:
- **LinusSalamanderSecretPlaneAgent**: Orchestrates the overall flow.
- **SecretPlaneValidatorAgent**: Validates schemas and policies.
- **SecretSnapshotPersistenceAgent**: Handles GitHub adapter interactions.
- **SecretPurgeAgent**: Enforces the local cleanup lifecycle.
- **SecretReplayGuardAgent**: Manages epoch and chain continuity.

**Successful Event Flow Example:**
`Secret.write.requested` → `Secret.policy.validated` → `Secret.snapshot.created` → `Secret.snapshot.sealed` → `Secret.snapshot.attested` → `Secret.snapshot.persisted` → `Secret.local_artifacts.purged` → `Secret.write.completed`

**Error Event Flow Example:**
`Secret.snapshot.signature.invalid` → `Secret.write.refuted`

## 17. Testing Strategy
LSES requires a rigorous testing methodology.

### Unit Tests
- `commit_sha` is not included in `snapshot_id`.
- Canonical envelope body is complete before signing.
- Enclave signature fails if `epoch` changes after signing.
- Enclave signature fails if `previous_snapshot_hash` changes after signing.
- Consumer countersignature fails if it was produced over the request instead of canonical envelope body.
- Nonce reuse is detected for the same DEK/context.
- Snapshot canonicalization is fully deterministic.
- AES-256-GCM seal and unseal operations succeed with valid keys.
- Modifying the ciphertext correctly triggers an invalid auth tag failure.
- Ed25519 signatures validate correctly.
- Incorrect public keys fail signature validation.
- The `LocalArtifactPurger` successfully removes temporary files.
- `wrapped_dek` is required for persisted snapshots.
- Plaintext DEK is never serialized.
- DEK unwrap fails with the wrong KEK.
- `secret_ref` does not expose raw secret names.
- `readSecret` returns a handle by default.

### Integration Tests
- Write flow signs only after `sealed_payload`, `wrapped_dek`, `epoch`, `previous_snapshot_hash` and AAD are finalized.
- GitHub persistence returns a separate `persistence_receipt`.
- Recovery verifies envelope without depending on `commit_sha`.
- Replaying an old valid envelope emits `Secret.replay.detected`.
- The `writeSecret` flow properly encrypts the envelope and pushes it via the GitHub adapter, persisting only `sealed_payload` and `wrapped_dek`.
- The `readSecret` flow unwraps DEK only inside the runtime boundary, validates, and decrypts the latest remote snapshot.
- Recovery fails or enters limited mode without a trust anchor.
- Rollback attempts with an internally consistent old chain are detected when the chain head exists.

### Property-Based Tests
- Any mutation to signed security-critical fields invalidates both signatures.
- Any mutation to AAD invalidates AES-GCM authentication.
- Same DEK/context must never accept reused nonce.
- Persistence receipt mutation does not alter cryptographic snapshot identity.
- The exact same canonical payload must always produce the identical hash.
- Any bit modification to the envelope must invalidate the signature.
- The epoch integer must never decrease under any circumstance.
- The `previous_snapshot_hash` must strictly match the current chain head.
- No generated envelope contains the plaintext `secretValue`.
- No generated envelope contains the plaintext DEK.
- Changing `wrapped_dek` invalidates the envelope signature.

### Security Tests
- Partial-envelope signatures are rejected.
- Request-only countersignatures are rejected.
- Old valid snapshot chains are rejected when trusted chain head exists.
- Nonce reuse causes hard failure.
- Scan Git commit contents to assert plaintext secret data never appears.
- Scan Git commit contents to assert plaintext DEK never appears.
- Asserts that the local temporary directory is completely empty after the purge operation.
- Asserts that an invalid or unauthorized consumer cannot successfully countersign a snapshot.
- Assert that plaintext export requires explicit policy authorization.
- Assert that a secret handle expires and cannot be reused after expiration.

## 18. Terminology
- **Enclave**: The trusted runtime boundary where cryptographic operations occur.
- **Snapshot**: A point-in-time representation of the secret state.
- **Data Encryption Key (DEK)**: The ephemeral symmetric key used to seal the payload.
- **Key Encryption Key (KEK)**: The key used to encrypt (wrap) the DEK.
- **Sealed Payload**: Data encrypted via AES-256-GCM using the DEK.
- **Cryptographic Envelope**: The complete JSON structure containing the sealed payload, metadata, signatures, and wrapped DEK.
- **Dual Attestation**: The requirement that a snapshot must be signed by both the Enclave and the Consuming System.
- **Consumer Countersignature**: The signature applied by the system requesting or acknowledging the secret state change.
- **Epoch**: A strictly monotonically increasing integer tracking the sequence of snapshots.
- **Chain Head Trust Anchor**: A trusted checkpoint used to compare the remote snapshot chain and prevent rollbacks.
- **Purge-on-Write**: The architectural pattern of aggressively deleting all local artifacts immediately after remote persistence.
- **Replay**: An attack attempting to reuse a valid cryptographic envelope.
- **Rollback**: An attack attempting to force the system to adopt a historically valid but outdated state.
- **Canonicalization**: The process of formatting a JSON payload into a strict, deterministic byte sequence for hashing and signing.

---
*LSES reduces disk-based forensic exposure by avoiding local plaintext persistence. Runtime memory attacks remain in scope unless hardware-backed isolation is enabled. When hardware enclaves are unavailable, LSES mitigates unauthorized access through encrypted snapshots, dual signatures, and replay guards. This does not replace hardware-backed memory isolation.*
