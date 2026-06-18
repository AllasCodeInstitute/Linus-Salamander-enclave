# LSES Security Vulnerability Report

**Classification:** Confidential — Internal Security Audit  
**Date:** 2026-06-17  
**Scope:** Full codebase — Rust enclave, Zig implementation, BPF/XDP, orchestrator, secure leaks scanner  
**Standard:** OWASP ASVS v4.0, NIST SP 800-57, CWE Top 25

---

## Table of Contents

1. [Critical Vulnerabilities](#1-critical-vulnerabilities)
2. [High Vulnerabilities](#2-high-vulnerabilities)
3. [Medium Vulnerabilities](#3-medium-vulnerabilities)
4. [Low Vulnerabilities](#4-low-vulnerabilities)
5. [Implementation Checklist](#5-implementation-checklist)

---

## 1. Critical Vulnerabilities

---

### CVE-LSES-001 — Static Root Seed Makes All Derived Keys Predictable

**File:** `rust/enclave/src/lib.rs:47-50`, `rust/semantic-behaviors-types/quarkbehaviors/init_enclave_keys/proccess.rs`  
**CWE:** CWE-321 (Use of Hard-coded Cryptographic Key), CWE-330 (Use of Insufficiently Random Values)  
**CVSS Base Score:** 9.8 (Critical)

**Description:**

```rust
const ROOT_SEED_DEFAULT: [u8; 32] = [
    0x53, 0x41, 0x4C, 0x41, 0x4D, 0x41, 0x4E, 0x44, 0x45, 0x52, 0, 0, 0, ...
];
// ASCII: "SALAMANDER\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
```

The `init_enclave_keys()` function always resets the `root_seed` back to this public constant:

```rust
pub extern "C" fn init_enclave_keys() {
    if let Ok(mut guard) = state().lock() {
        guard.signing_key = Some(SigningKey::generate(&mut OsRng));  // ✅ random
        guard.replay_bitmap = [0; 1024];
        guard.root_seed = ROOT_SEED_DEFAULT;  // ❌ always resets to "SALAMANDER"
    }
}
```

`derive_edge_key()` and `generate_agent_key()` both derive keys from `root_seed`. Since this value is always the same public constant, every key ever derived from it — edge keys, agent keys — is fully deterministic and reproducible by any attacker who reads the source code.

**Impact:**
- All `edge_key = HMAC(root_seed, edge_context)` values are predictable → full AEAD break.
- All `agent_key = SHA256(root_seed || ...)` values are predictable → identity forgery.
- Any network observer can pre-compute the encryption keys.

**Fix — Generate random root_seed on every init:**

```rust
// rust/semantic-behaviors-types/quarkbehaviors/init_enclave_keys/proccess.rs
#[no_mangle]
pub extern "C" fn init_enclave_keys() {
    if let Ok(mut guard) = state().lock() {
        guard.signing_key = Some(SigningKey::generate(&mut OsRng));
        guard.replay_bitmap = [0; 1024];
        OsRng.fill_bytes(&mut guard.root_seed);  // ✅ cryptographically random
    }
}
```

**Remove the publicly known constant from production scope:**

```rust
// Keep only for test fallback, never in production path
#[cfg(test)]
const ROOT_SEED_DEFAULT: [u8; 32] = [0u8; 32];
```

---

### CVE-LSES-002 — `getrandom` Configured With WASM/JS Feature for Native Build

**File:** `rust/enclave/Cargo.toml:13`  
**CWE:** CWE-338 (Use of Cryptographically Weak Pseudo-Random Number Generator)  
**CVSS Base Score:** 9.1 (Critical)

**Description:**

```toml
getrandom = { version = "0.2", default-features = false, features = ["js"] }
```

The `js` feature in `getrandom` is designed exclusively for WebAssembly targets running inside a browser (where `window.crypto.getRandomValues()` is the OS entropy source). On a native Linux/macOS/Windows build, enabling `features = ["js"]` with `default-features = false` removes the native OS CSPRNG backend (`getrandom` syscall / `CryptGenRandom`), potentially causing the CSPRNG to panic, use a weaker fallback, or fail silently.

All cryptographic random values — Ed25519 signing keys, AES-GCM nonces, DEKs — are generated via this configuration. A broken CSPRNG makes these values predictable or zero.

**Fix — Use correct getrandom configuration for native targets:**

```toml
# rust/enclave/Cargo.toml
[dependencies]
getrandom = { version = "0.2" }   # use default features: std + os backend

# If you need WASM support too, use target-specific deps:
# [target.'cfg(target_arch = "wasm32")'.dependencies]
# getrandom = { version = "0.2", features = ["js"] }
```

---

### CVE-LSES-003 — Hardcoded KEK in Storage Engine

**File:** `zig/storage.zig:409-411`  
**CWE:** CWE-321 (Use of Hard-coded Cryptographic Key)  
**CVSS Base Score:** 9.8 (Critical)

**Description:**

```zig
.kek_provider = try crypto.LocalDevKekProvider.initFromHex(
    "local-dev-kek-001",
    "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"  // ❌ publicly known
),
```

The Key Encryption Key (KEK), which protects the Data Encryption Key (DEK) inside every snapshot, is a hardcoded public constant. The `enclave.sealed.json` committed to the repository uses `"dek_wrapping_key_id":"local-dev-kek-001"` — the same known key. Any attacker who reads the source code can:

1. Read the `wrapped_dek` from `enclave.sealed.json`.
2. Use the known KEK to unwrap the DEK.
3. Use the DEK to decrypt the `sealed_payload`.

This completely invalidates the envelope encryption model.

**Fix — Load the KEK from a secure out-of-band source:**

```zig
// zig/storage.zig — Load KEK from environment variable, never hardcode
const kek_hex = std.process.getEnvVarOwned(allocator, "LSES_KEK") catch {
    return error.MissingKekEnvVar;
};
defer allocator.free(kek_hex);

var kek: [32]u8 = undefined;
_ = try std.fmt.hexToBytes(&kek, kek_hex);
// Provide via: export LSES_KEK=$(openssl rand -hex 32)
```

For production: integrate with HashiCorp Vault Transit, AWS KMS, or Azure Key Vault as the KEK provider instead of `LocalDevKekProvider`.

---

### CVE-LSES-004 — Replay Bitmap Finite and Lost on Restart

**File:** `rust/enclave/src/lib.rs:52-79`  
**CWE:** CWE-294 (Authentication Bypass by Capture-replay), CWE-362 (Race Condition)  
**CVSS Base Score:** 8.1 (Critical)

**Description:**

The replay protection bitmap stores 65,536 bits (1,024 × 64-bit words):

```rust
replay_bitmap: [u64; 1024],  // tracks 65,536 unique session IDs
```

And maps session IDs via modular reduction:

```rust
let index = (session_id % 65536) as usize;
```

Three problems:

1. **Wrap-around collision:** `session_id = 0` and `session_id = 65536` map to the same bit. An attacker can exhaust the bitmap by submitting 65,536 unique sessions, making all future sessions collide with used bits → Denial of Service.

2. **Lost on restart:** The bitmap is in-process memory. After any process restart, all previously consumed session IDs become reusable — a complete replay protection bypass.

3. **Cleared by re-initialization:** `init_enclave_keys()` resets `replay_bitmap = [0; 1024]`, allowing replay of ALL previous sessions.

**Fix — Use a persistent nonce store and guaranteed-unique session IDs:**

```rust
// Option A: Persist bitmap to sealed storage before shutdown.
// Option B: Require session IDs to be monotonically increasing timestamps (u64 UNIX nanos),
//           stored as last_accepted_nonce. Reject any nonce <= last_accepted_nonce.
// Option C: Use a timestamp + random nonce combo: upper 32 bits = timestamp (seconds),
//           lower 32 bits = CSPRNG. This provides uniqueness without a full bitmap.

struct EnclaveState {
    // ...
    last_accepted_nonce: u64,     // monotonic guard — persisted to sealed state
    nonce_window_start: u64,      // time-based window for late arrivals
}
```

For the short-term fix, add a `INITIALIZED` guard preventing `init_enclave_keys()` from clearing the bitmap after first call:

```rust
static INITIALIZED: AtomicBool = AtomicBool::new(false);

pub extern "C" fn init_enclave_keys() {
    if INITIALIZED.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_err() {
        return;  // Refuse re-initialization; prevents bitmap clear
    }
    // ...
}
```

---

### CVE-LSES-005 — `enclave.sealed.json` With Known-Decryptable Content Committed to Repository

**File:** `zig/enclave.sealed.json`  
**CWE:** CWE-312 (Cleartext Storage of Sensitive Information), CWE-798  
**CVSS Base Score:** 8.8 (Critical)

**Description:**

`enclave.sealed.json` is tracked by git and contains a sealed envelope encrypted with the hardcoded KEK from CVE-LSES-003. The git history preserves it permanently. Combined, these two vulnerabilities allow any person with repository read access to decrypt the stored secret `MY_SECURE_API_TOKEN`.

Additionally `zig/main.zig` stores a demonstration value matching the `linus-secret` detection rule:

```zig
const val = "ls_secret_super_secure_token_12345";
```

**Fix:**

```bash
# Remove from tracking and history
git rm --cached zig/enclave.sealed.json
git filter-repo --invert-paths --path zig/enclave.sealed.json
# Add to .gitignore
echo "zig/enclave.sealed.json" >> .gitignore
echo "*.sealed.json" >> .gitignore
```

Replace the demo value in `main.zig` with a placeholder that does not match detection rules:

```zig
const val = "PLACEHOLDER_REPLACE_WITH_REAL_SECRET_AT_RUNTIME";
```

---

## 2. High Vulnerabilities

---

### CVE-LSES-006 — `choreograph_packet` Uses Stream-XOR, Not Authenticated Encryption

**File:** `rust/semantic-behaviors-types/quarkbehaviors/choreograph_packet/proccess.rs`  
**CWE:** CWE-327 (Use of Broken or Risky Cryptographic Algorithm), CWE-345 (Insufficient Verification of Data Authenticity)  
**CVSS Base Score:** 8.1 (High)

**Description:**

```rust
for (i, b) in data.iter_mut().enumerate() {
    *b ^= key_in[i % 32] ^ key_out[i % 32];
}
```

This is a 32-byte repeating XOR keystream — equivalent to a Vigenère cipher. It provides:
- **No authentication:** Any modification passes undetected.
- **No confidentiality:** Subject to known-plaintext attacks (XOR key recoverable if any plaintext is known).
- **If `key_in == key_out`:** The entire operation is a no-op (payload passes through unchanged).

**Fix — Replace with authenticated AES-256-GCM re-encryption:**

```rust
pub extern "C" fn choreograph_packet(
    in_frame_ptr: *const u8, in_frame_len: usize,
    out_frame_ptr: *mut u8, out_frame_capacity: usize, out_frame_len: *mut usize,
    in_ctx: *const EdgeContext, out_ctx: *const EdgeContext,
    in_session_id: u64, out_session_id: u64,
) -> i32 {
    // 1. Open the inbound packet (AEAD decrypt + authenticate)
    // 2. Re-seal for the outbound edge (AEAD encrypt with out_ctx key)
    // → uses existing open_edge_packet + seal_edge_packet primitives
}
```

---

### CVE-LSES-007 — PQC Session System is a Non-Functional Stub

**File:** `rust/semantic-behaviors-types/quarkbehaviors/init_pqc_session/proccess.rs`, `verify_pqc_handshake/proccess.rs`  
**CWE:** CWE-327, CWE-326  
**CVSS Base Score:** 7.5 (High)

**Description:**

The entire PQC layer is fake:

```rust
guard.pqc_sessions[0] = Some(PQCSession {
    session_id,
    shared_secret: [0u8; 32],   // ❌ zero shared secret
    is_quantum_resistant: true,  // ❌ flag is a lie
});
unsafe { core::ptr::write_bytes(out_pubkey, 0xAA, 1184) };  // ❌ fake pubkey
```

```rust
pub extern "C" fn verify_pqc_handshake(session_id: u64, _peer_ciphertext: *const u8) -> i32 {
    // _peer_ciphertext is never inspected — trivially bypassable
    if session.session_id == session_id { return 0; }
```

Any party claiming a session_id equal to one that was previously registered passes PQC verification — zero cryptographic check.

**Fix — Either implement real PQC (Kyber-768/ML-KEM-768) or remove the false API:**

```toml
# Cargo.toml — add real PQC library
pqcrypto-kyber = "0.7"
# or use NIST-standardized ml-kem crate
ml-kem = "0.2"
```

If PQC is not yet implemented, the API must return a clear error, and the `is_quantum_resistant` flag must be `false`:

```rust
pub extern "C" fn init_pqc_session(_session_id: u64, _out_pubkey: *mut u8) -> i32 {
    ERR_NOT_IMPLEMENTED  // Explicit: PQC is not yet available
}
```

---

### CVE-LSES-008 — Tripartite Identity Uses Non-Constant-Time Comparison

**File:** `rust/semantic-behaviors-types/quarkbehaviors/verify_tripartite_identity/proccess.rs:17-22`  
**CWE:** CWE-203 (Observable Discrepancy), CWE-385 (Covert Timing Channel)  
**CVSS Base Score:** 7.4 (High)

**Description:**

```rust
if result.as_slice() == expected {  // ❌ variable-time comparison
```

Rust slice comparison is NOT constant-time. A timing oracle allows an attacker to learn bytes of `expected` one nibble at a time by measuring response latency.

**Fix — Use constant-time comparison:**

```rust
use subtle::ConstantTimeEq;

if result.ct_eq(expected).into() {
    0
} else {
    ERR_AUTHENTICATION
}
```

```toml
# Cargo.toml
subtle = "2.6"
```

---

### CVE-LSES-009 — BPF XDP Agent Hash Has Trivial Collision Resistance

**File:** `bpf/xdp_agent_router.c:47-50`  
**CWE:** CWE-328 (Use of Weak Hash), CWE-20  
**CVSS Base Score:** 7.5 (High)

**Description:**

```c
__u64 identity_hash = 0;
for(int i=0; i<6; i++) identity_hash ^= ((__u64)eth->h_source[i] << (i*8));
identity_hash ^= ((__u64)ip->saddr << 32);
```

XOR-based hash over MAC + IP. Collisions are trivially engineered:
- `MAC1 XOR MAC2 XOR MAC3 == 0` for any three symmetric MACs.
- Any two MAC addresses where corresponding nibbles differ by the same value produce the same hash.
- This allows unauthorized agents to craft packets that bypass BPF-level identity filtering.

**Fix — Use SipHash-2-4 (the standard in Linux BPF for fast hash tables) or Poly1305:**

```c
// Use BPF's built-in jhash or siphash helper
#include <linux/jhash.h>

__u64 identity_hash = jhash2((__u32 *)eth->h_source, 2, 0) |
                      (((__u64)ip->saddr) << 32);
```

Or compute the SHA256 of the tripartite identity in user-space and store the hash, verifying packets against the pre-computed value rather than re-hashing in the XDP hot path.

---

### CVE-LSES-010 — `generate_agent_key` Uses SHA256 Without Field Separation

**File:** `rust/semantic-behaviors-types/quarkbehaviors/generate_agent_key/proccess.rs`  
**CWE:** CWE-325 (Missing Cryptographic Step), CWE-20  
**CVSS Base Score:** 7.2 (High)

**Description:**

```rust
hasher.update(guard.root_seed);
hasher.update(name_bytes);
hasher.update(caps_bytes);
hasher.update(plane_bytes);
hasher.update(semantics_bytes);
```

There are no length prefixes or separators between variable-length fields. SHA256's `update()` concatenates without delimiters, so `name="AB", caps="C"` produces the same hash as `name="A", caps="BC"`. This is a second-preimage/domain-collision vulnerability:

- An attacker with a legitimate key for `("AB", "C", ...)` can infer the key for `("A", "BC", ...)` — same derivation without the original authorization.
- Also, SHA256 used as a PRF with the seed as prefix (not as HMAC key) is weaker than HKDF.

**Fix — Use HKDF with domain separation and length-prefixed fields:**

```rust
// Use HKDF-SHA256 for proper key derivation
fn derive_agent_key_hkdf(
    root_seed: &[u8; 32],
    name: &[u8], caps: &[u8], plane: &[u8], semantics: &[u8],
) -> [u8; 32] {
    use hkdf::Hkdf;
    let info = build_info_block(name, caps, plane, semantics);
    let hk = Hkdf::<sha2::Sha256>::new(None, root_seed);
    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm).expect("HKDF expand");
    okm
}

fn build_info_block(name: &[u8], caps: &[u8], plane: &[u8], semantics: &[u8]) -> Vec<u8> {
    let mut info = Vec::new();
    info.extend_from_slice(b"LSES-AGENT-KEY-V1\x00");
    encode_field(&mut info, name);
    encode_field(&mut info, caps);
    encode_field(&mut info, plane);
    encode_field(&mut info, semantics);
    info
}

fn encode_field(buf: &mut Vec<u8>, field: &[u8]) {
    let len = (field.len() as u32).to_be_bytes();
    buf.extend_from_slice(&len);  // 4-byte length prefix
    buf.extend_from_slice(field);
}
```

---

### CVE-LSES-011 — `deterministicTestBytes` Exposed in Production Code

**File:** `zig/crypto.zig:67-71`  
**CWE:** CWE-330, CWE-1321  
**CVSS Base Score:** 7.0 (High)

**Description:**

```zig
pub fn deterministicTestBytes(buffer: []u8, seed: u64) void {
    var prng = std.Random.DefaultPrng.init(seed);
    prng.random().bytes(buffer);
}
```

A deterministic PRNG function is publicly exported as part of the production `EnclaveCrypto` struct. If called instead of `randomBytes()` — either by mistake or by a malicious actor — it produces fully predictable key material from a u64 seed. Since it's a `pub` function, any calling code has access to it.

**Fix — Move behind `test` compilation flag:**

```zig
// zig/crypto.zig
// Remove from EnclaveCrypto struct; make test-only
test "deterministicTestBytes" {
    var buf: [32]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(42);
    prng.random().bytes(&buf);
    // ... assertions
}
```

---

### CVE-LSES-012 — Wrap AAD Does Not Bind DEK to Snapshot Context

**File:** `zig/crypto.zig:709`  
**CWE:** CWE-345 (Insufficient Verification of Data Authenticity)  
**CVSS Base Score:** 7.3 (High)

**Description:**

```zig
const wrap_aad = provider.key_id;  // ❌ AAD is only "local-dev-kek-001"
const dek = try provider.unwrap(allocator, wrapped, wrap_aad);
```

The wrapped DEK's AAD is only the KEK's key ID string. This means a `wrapped_dek` from snapshot A (for `project="prod", epoch=5`) is AEAD-valid when used as the `wrapped_dek` in snapshot B (same key_id, different project/epoch). An attacker who can construct a malicious envelope with a legitimate wrapped_dek from another context could potentially cause a DEK transplant attack.

**Fix — Bind the wrapped DEK to the snapshot body via AAD:**

```zig
// Use the canonical AAD of the snapshot as the wrap_aad
const wrap_aad = try crypto.canonicalizeAad(allocator, envelope.snapshot_body.aad);
defer allocator.free(wrap_aad);
const dek = try provider.unwrap(allocator, wrapped, wrap_aad);
```

The same AAD must be used during `wrap` (in `buildPendingSnapshot`) and `unwrap` (in `decryptVerifiedSnapshot`).

---

## 3. Medium Vulnerabilities

---

### CVE-LSES-013 — `generate_agent_key` Has No Upper Bound on Length Parameters

**File:** `rust/semantic-behaviors-types/quarkbehaviors/generate_agent_key/proccess.rs:29-32`  
**CWE:** CWE-119 (Buffer Overflow), CWE-20  
**CVSS Base Score:** 6.5 (Medium)

**Description:**

```rust
hasher.update(unsafe { core::slice::from_raw_parts(name, name_len) });
```

No upper bound is enforced on `name_len`, `caps_len`, `plane_len`, or `semantics_len`. Passing `usize::MAX` causes an out-of-bounds read in the `from_raw_parts` call — undefined behavior that could crash the process or leak adjacent memory.

**Fix:**

```rust
const MAX_FIELD_LEN: usize = 1024;

if name_len > MAX_FIELD_LEN || caps_len > MAX_FIELD_LEN
    || plane_len > MAX_FIELD_LEN || semantics_len > MAX_FIELD_LEN {
    return ERR_NULL_POINTER;  // or a dedicated ERR_INVALID_ARGUMENT
}
```

---

### CVE-LSES-014 — `NonceRegistry` Grows Unboundedly (Memory Exhaustion)

**File:** `zig/crypto.zig:433-472`  
**CWE:** CWE-400 (Uncontrolled Resource Consumption)  
**CVSS Base Score:** 6.5 (Medium)

**Description:**

```zig
pub const NonceRegistry = struct {
    seen: std.AutoHashMap([32]u8, NonceRecord),
    // No max size, no eviction, no TTL
```

In a long-running enclave, the nonce registry accumulates one entry per operation forever. An attacker who can submit many envelopes (even rejected ones whose nonces are checked) can exhaust process memory.

**Fix — Add a capacity cap and eviction policy:**

```zig
pub const MAX_NONCE_REGISTRY_SIZE: usize = 100_000;

pub fn checkAndRecord(...) !void {
    if (self.seen.count() >= MAX_NONCE_REGISTRY_SIZE) {
        return LsesError.NonceReused;  // Fail-safe: deny when full
        // Production alternative: evict oldest entries using an LRU
    }
    // ... existing logic
}
```

---

### CVE-LSES-015 — Hex Encoding Inconsistency in `canonicalizeSignatureInput`

**File:** `zig/crypto.zig:370`  
**CWE:** CWE-706 (Use of Incorrectly-Resolved Name or Reference)  
**CVSS Base Score:** 5.9 (Medium)

**Description:**

```zig
// In canonicalizeSignatureInput:
const hex_id = std.fmt.bufPrint(&hex_id_buf, "{x}", .{snapshot_id}) catch unreachable;
```

`{x}` for a `[32]u8` array in Zig does NOT zero-pad individual bytes. A byte `0x0A` is rendered as `a`, not `0a`, producing a 63-character string for snapshot IDs containing leading-zero bytes. This creates a different byte sequence than `appendHexField()` which uses `{x:0>2}` (zero-padded). The inconsistency corrupts the signature input, causing verification failures for any snapshot_id with zero-prefixed bytes.

Evidence: `enclave.sealed.json` contains a 127-character enclave signature (should be 128) and a 125-character consumer countersignature (should be 128), indicating leading zeros were dropped during hex encoding.

**Fix:**

```zig
var hex_id_buf: [64]u8 = undefined;
for (snapshot_id, 0..) |b, i| {
    _ = std.fmt.bufPrint(hex_id_buf[i*2..i*2+2], "{x:0>2}", .{b}) catch unreachable;
}
const hex_id = hex_id_buf[0..64];
```

---

### CVE-LSES-016 — `AccessPolicy.allows()` Ignores `operation` and `secret_ref`

**File:** `zig/crypto.zig:539-551`  
**CWE:** CWE-863 (Incorrect Authorization), CWE-284  
**CVSS Base Score:** 6.8 (Medium)

**Description:**

```zig
pub fn allows(
    self: AccessPolicy,
    operation: []const u8,
    consumer_id: []const u8,
    secret_ref: [32]u8,
) bool {
    _ = operation;    // ❌ ignored
    _ = secret_ref;  // ❌ ignored
    for (self.allowed_consumers) |c| {
        if (std.mem.eql(u8, c, consumer_id)) return true;
    }
    return false;
}
```

Any authorized consumer can perform any operation on any secret. The policy system does not enforce:
- Per-operation restrictions (e.g., consumer A can read but not rotate).
- Per-secret restrictions (e.g., consumer A can access secret X but not secret Y).

**Fix:**

```zig
pub const PolicyEntry = struct {
    consumer_id: []const u8,
    allowed_operations: []const []const u8,
    allowed_secret_refs: ?[][32]u8,  // null = all secrets
};

pub fn allows(self: AccessPolicy, operation: []const u8, consumer_id: []const u8, secret_ref: [32]u8) bool {
    for (self.entries) |entry| {
        if (!std.mem.eql(u8, entry.consumer_id, consumer_id)) continue;
        const op_ok = for (entry.allowed_operations) |op| {
            if (std.mem.eql(u8, op, operation)) break true;
        } else false;
        if (!op_ok) return false;
        if (entry.allowed_secret_refs) |refs| {
            return for (refs) |ref| {
                if (std.mem.eql(u8, &ref, &secret_ref)) break true;
            } else false;
        }
        return true;
    }
    return false;
}
```

---

### CVE-LSES-017 — `.gitignore` Insufficient — Build Artifacts and Sensitive Files Tracked

**File:** `.gitignore`  
**CWE:** CWE-312, CWE-540  
**CVSS Base Score:** 5.5 (Medium)

**Description:**

The `.gitignore` only contains `.kilo` and `prompts/`. The git history already tracks:
- `rust/enclave/target/` (build artifacts, 200+ files in git status)
- `zig/enclave.sealed.json` (sealed secret)
- `zig/dummy.txt`, `zig/dummy.json` (test artifacts)

Build directories can contain compiled binaries with embedded keys, intermediate object files, and debugging symbols that leak internal structure.

**Fix — Comprehensive `.gitignore`:**

```gitignore
# Build artifacts
target/
zig-out/
zig-cache/
.zig-cache/
build/
dist/

# Enclave state files
*.sealed.json
enclave.state
*.enclave

# Credentials and secrets
.env
.env.*
*.key
*.pem
*.p12
*.jks
*.pfx
secrets.json
credentials.json
LSES_KEK

# Test fixtures with real data
zig/dummy.txt
zig/dummy.json

# IDE
.kilo
.vscode/
.idea/
prompts/
```

---

### CVE-LSES-018 — `readSecret` Sets `last_accepted_epoch = 0` Unconditionally

**File:** `zig/storage.zig:789`  
**CWE:** CWE-345 (Insufficient Verification of Data Authenticity)  
**CVSS Base Score:** 6.1 (Medium)

**Description:**

```zig
var ctx = crypto.VerificationContext{
    .mode = .recovery_limited,
    .trusted_chain_head = self.trusted_chain_head,
    .last_accepted_epoch = 0,   // ❌ always 0, ignores stored state
    ...
```

The verification context for reading always starts with `last_accepted_epoch = 0`. This means a replay attack using an old snapshot with epoch 1 will always pass the epoch check (1 > 0), even if the enclave has already accepted epoch 50. The rollback protection for reads is completely inactive.

**Fix:**

```zig
var ctx = crypto.VerificationContext{
    .mode = if (self.trusted_chain_head != null) .strict else .recovery_limited,
    .trusted_chain_head = self.trusted_chain_head,
    .last_accepted_epoch = self.last_accepted_epoch,  // ✅ use stored epoch
    ...
```

---

## 4. Low Vulnerabilities

---

### CVE-LSES-019 — Root Seed Copy on Stack Not Zeroized

**File:** `rust/semantic-behaviors-types/quarkbehaviors/mark_replay_and_get_root_seed/proccess.rs`  
**CWE:** CWE-226 (Sensitive Information in Resource Not Removed Before Reuse)  
**CVSS Base Score:** 4.0 (Low)

**Description:**

```rust
Ok(guard.root_seed)  // Copy of 32-byte secret placed on stack, never zeroized
```

The 32-byte root seed is returned by value onto the call stack. While Rust does not guarantee stack zeroization, leaving key material on the stack risks exposure if the stack frame is re-used, the process is core-dumped, or memory is scanned.

**Fix — Use zeroizing wrappers:**

```toml
zeroize = { version = "1.8", features = ["derive"] }
```

```rust
use zeroize::Zeroizing;
fn mark_replay_and_get_root_seed(session_id: u64) -> Result<Zeroizing<[u8; 32]>, i32> {
    let mut guard = state().lock().map_err(|_| ERR_STATE)?;
    if !guard.try_mark_replay(session_id) { return Err(ERR_REPLAY); }
    Ok(Zeroizing::new(guard.root_seed))
}
```

---

### CVE-LSES-020 — Hardcoded Git User Identity in `persistEnvelope`

**File:** `zig/storage.zig:607-613`  
**CWE:** CWE-798  
**CVSS Base Score:** 3.1 (Low)

**Description:**

```zig
try sha_args.append(allocator, "-c");
try sha_args.append(allocator, "user.name=AllasCode Worker");
try sha_args.append(allocator, "-c");
try sha_args.append(allocator, "user.email=worker@allascode.com");
```

The git identity is hardcoded, attributing all enclave commits to a single static identity. This prevents auditing which system/operator performed each operation.

**Fix — Load from environment or configuration:**

```zig
const git_user = std.process.getEnvVarOwned(allocator, "LSES_GIT_USER") catch "LSES Enclave";
const git_email = std.process.getEnvVarOwned(allocator, "LSES_GIT_EMAIL") catch "enclave@lses.internal";
```

---

### CVE-LSES-021 — Timestamp is Hardcoded String

**File:** `zig/storage.zig:502, 627, 651`  
**CWE:** CWE-672  
**CVSS Base Score:** 3.5 (Low)

**Description:**

```zig
.created_at = try allocator.dupe(u8, "2026-05-18T00:00:00Z"),
```

The `created_at` field in every snapshot body is the same hardcoded timestamp. This invalidates the audit trail — the timestamp cannot be used to determine when any operation occurred.

**Fix — Use the system clock:**

```zig
var timestamp_buf: [32]u8 = undefined;
const now_secs: i64 = @intCast(@divTrunc(io.vtable.now(io.userdata, .real).nanoseconds, 1_000_000_000));
const ts = formatTimestamp(&timestamp_buf, now_secs);
.created_at = try allocator.dupe(u8, ts),
```

---

### CVE-LSES-022 — `PQCSession` Array Fixed at 16, Only Index 0 Ever Used

**File:** `rust/enclave/src/lib.rs:57`, `init_pqc_session/proccess.rs:12`  
**CWE:** CWE-770 (Allocation of Resources Without Limits)  
**CVSS Base Score:** 3.0 (Low)

**Description:**

```rust
pqc_sessions: [Option<PQCSession>; 16],  // 16 slots

// In init_pqc_session:
guard.pqc_sessions[0] = Some(PQCSession { ... });  // always uses index 0
```

Every call to `init_pqc_session` overwrites index 0, making it impossible to have more than one PQC session active at a time, regardless of the array capacity. Any concurrent session establishment is a race condition.

**Fix — Either implement proper session management or document the single-session limitation.**

---

## 5. Implementation Checklist

| ID | Severity | File | Status |
|---|---|---|---|
| CVE-LSES-001 | Critical | `init_enclave_keys/proccess.rs` | ✅ Fixed |
| CVE-LSES-002 | Critical | `rust/enclave/Cargo.toml` | ✅ Fixed |
| CVE-LSES-003 | Critical | `zig/storage.zig` | ✅ Fixed |
| CVE-LSES-004 | Critical | `lib.rs`, `init_enclave_keys` | ✅ Fixed |
| CVE-LSES-005 | Critical | `.gitignore`, `zig/main.zig` | ✅ Fixed |
| CVE-LSES-006 | High | `choreograph_packet/proccess.rs` | ✅ Fixed |
| CVE-LSES-007 | High | `init_pqc_session/proccess.rs` | ✅ Fixed |
| CVE-LSES-008 | High | `verify_tripartite_identity/proccess.rs` | ✅ Fixed |
| CVE-LSES-009 | High | `bpf/xdp_agent_router.c` | ✅ Fixed |
| CVE-LSES-010 | High | `generate_agent_key/proccess.rs` | ✅ Fixed |
| CVE-LSES-011 | High | `zig/crypto.zig` | ✅ Fixed |
| CVE-LSES-012 | High | `zig/crypto.zig` | ✅ Fixed |
| CVE-LSES-013 | Medium | `generate_agent_key/proccess.rs` | ✅ Fixed |
| CVE-LSES-014 | Medium | `zig/crypto.zig` | ✅ Fixed |
| CVE-LSES-015 | Medium | `zig/crypto.zig` | ✅ Fixed |
| CVE-LSES-016 | Medium | `zig/crypto.zig` | ✅ Fixed |
| CVE-LSES-017 | Medium | `.gitignore` | ✅ Fixed |
| CVE-LSES-018 | Medium | `zig/storage.zig` | ✅ Fixed |
| CVE-LSES-019 | Low | `mark_replay_and_get_root_seed/proccess.rs` | ✅ Fixed |
| CVE-LSES-020 | Low | `zig/storage.zig` | ✅ Fixed |
| CVE-LSES-021 | Low | `zig/storage.zig` | ✅ Fixed |
| CVE-LSES-022 | Low | `lib.rs` | 🔲 Tracked |
