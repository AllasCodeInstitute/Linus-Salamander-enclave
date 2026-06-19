const std = @import("std");
const crypto = std.crypto;
const builtin = @import("builtin");
const Ed25519 = crypto.sign.Ed25519;
const Aes256Gcm = crypto.aead.aes_gcm.Aes256Gcm;



pub const LsesError = error{
    UnsupportedSchemaVersion,
    InvalidSnapshotHash,
    InvalidSignature,
    InvalidConsumerCountersignature,
    InvalidAuthTag,
    MissingWrappedDek,
    MissingWrapNonce,
    MissingWrapAuthTag,
    MissingTrustAnchor,
    ChainHeadMismatch,
    RollbackDetected,
    NonceReused,
    UnauthorizedConsumer,
    PlaintextExportNotAllowed,
    WrongKek,
    StaleKekId,
    PersistenceFailed,
    RecoveryLimitedMode,
    SnapshotBodyMutationDetected,
    SignatureVerificationFailed,
    EpochTooOld,
    ChainMismatch,
    InvalidSchema,
    NoSnapshotsFound,
    ExpiredHandle,
    InvalidHandle,
};

/// Enclave Cryptographic Engine
pub const EnclaveCrypto = struct {
    service_keypair: Ed25519.KeyPair,
    
    pub fn init() !EnclaveCrypto {
        var seed: [32]u8 = undefined;
        randomBytes(&seed);
        return .{
            .service_keypair = try Ed25519.KeyPair.generateDeterministic(seed),
        };
    }

    pub fn randomBytes(buffer: []u8) void {
        if (builtin.os.tag == .windows) {
            const SystemFunction036 = struct {
                extern "advapi32" fn SystemFunction036(RandomBuffer: [*]u8, RandomBufferLength: u32) callconv(.c) u8;
            }.SystemFunction036;
            _ = SystemFunction036(buffer.ptr, @intCast(buffer.len));
        } else {
            if (@hasDecl(std, "posix") and @hasDecl(std.posix, "getrandom")) {
                std.posix.getrandom(buffer) catch unreachable;
            } else if (@hasDecl(std, "os") and @hasDecl(std.os, "getrandom")) {
                std.os.getrandom(buffer) catch unreachable;
            } else {
                @panic("No CSPRNG available for this platform");
            }
        }
    }

    // CVE-LSES-011: NOT pub — deterministic RNG must never be callable by external
    // callers. Exposing it on the public EnclaveCrypto API allows adversaries to
    // generate the same "random" bytes used internally and mount preimage attacks.
    fn deterministicTestBytes(buffer: []u8, seed: u64) void {
        var prng = std.Random.DefaultPrng.init(seed);
        prng.random().bytes(buffer);
    }
};

pub fn secureZero(bytes: []u8) void {
    std.crypto.secureZero(u8, bytes);
}

/// Dynamic KEK Wrapping Interface
pub const KekProvider = struct {
    key_id: []const u8,
    ctx: *anyopaque,
    wrapFn: *const fn (
        ctx: *anyopaque,
        allocator: std.mem.Allocator,
        plaintext_dek: *const [32]u8,
        aad: []const u8,
    ) anyerror!WrappedDek,
    unwrapFn: *const fn (
        ctx: *anyopaque,
        allocator: std.mem.Allocator,
        wrapped: WrappedDek,
        aad: []const u8,
    ) anyerror![32]u8,

    pub fn wrap(
        self: KekProvider,
        allocator: std.mem.Allocator,
        plaintext_dek: *const [32]u8,
        aad: []const u8,
    ) !WrappedDek {
        return self.wrapFn(self.ctx, allocator, plaintext_dek, aad);
    }

    pub fn unwrap(
        self: KekProvider,
        allocator: std.mem.Allocator,
        wrapped: WrappedDek,
        aad: []const u8,
    ) ![32]u8 {
        return self.unwrapFn(self.ctx, allocator, wrapped, aad);
    }
};

pub const WrappedDek = struct {
    key_id: []const u8,
    wrapped_dek: [32]u8,
    wrap_nonce: [12]u8,
    wrap_auth_tag: [16]u8,
    algorithm: []const u8,
};

/// Development-Only KEK Provider (Backed by AES-256-GCM)
pub const LocalDevKekProvider = struct {
    key_id: []const u8,
    kek: [32]u8,

    pub fn initFromHex(key_id: []const u8, hex_key: []const u8) !LocalDevKekProvider {
        var kek: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&kek, hex_key);
        return .{
            .key_id = key_id,
            .kek = kek,
        };
    }

    /// Initialize directly from a 32-byte key (e.g. from sealed_state.unsealKeys).
    /// Preferred over initFromHex because no hex string with key material is
    /// ever allocated in the heap.
    pub fn initFromBytes(key_id: []const u8, key: [32]u8) LocalDevKekProvider {
        return .{ .key_id = key_id, .kek = key };
    }

    pub fn provider(self: *LocalDevKekProvider) KekProvider {
        return .{
            .key_id = self.key_id,
            .ctx = self,
            .wrapFn = wrapShim,
            .unwrapFn = unwrapShim,
        };
    }

    fn wrapShim(
        ctx: *anyopaque,
        allocator: std.mem.Allocator,
        plaintext_dek: *const [32]u8,
        aad: []const u8,
    ) anyerror!WrappedDek {
        _ = allocator;
        const self: *LocalDevKekProvider = @alignCast(@ptrCast(ctx));
        var wrap_nonce: [12]u8 = undefined;
        EnclaveCrypto.randomBytes(&wrap_nonce);

        var wrapped_dek: [32]u8 = undefined;
        var wrap_auth_tag: [16]u8 = undefined;

        Aes256Gcm.encrypt(&wrapped_dek, &wrap_auth_tag, plaintext_dek, aad, wrap_nonce, self.kek);

        return WrappedDek{
            .key_id = self.key_id,
            .wrapped_dek = wrapped_dek,
            .wrap_nonce = wrap_nonce,
            .wrap_auth_tag = wrap_auth_tag,
            .algorithm = "LOCAL-DEV-AES-256-GCM",
        };
    }

    fn unwrapShim(
        ctx: *anyopaque,
        allocator: std.mem.Allocator,
        wrapped: WrappedDek,
        aad: []const u8,
    ) anyerror![32]u8 {
        _ = allocator;
        const self: *LocalDevKekProvider = @alignCast(@ptrCast(ctx));
        if (!std.mem.eql(u8, wrapped.key_id, self.key_id)) return LsesError.StaleKekId;

        var plaintext_dek: [32]u8 = undefined;
        Aes256Gcm.decrypt(&plaintext_dek, &wrapped.wrapped_dek, wrapped.wrap_auth_tag, aad, wrapped.wrap_nonce, self.kek) catch {
            return LsesError.WrongKek;
        };
        return plaintext_dek;
    }
};

/// Core Structures for the Cryptographic Identity and Data Contract
pub const AlgorithmDescriptor = struct {
    content_encryption: []const u8,
    key_wrapping: []const u8,
    enclave_signature: []const u8,
    consumer_signature: []const u8,
};

pub const SnapshotAad = struct {
    project: []const u8,
    environment: []const u8,
    snapshot_type: []const u8,
    operation: []const u8,
    epoch: u64,
    previous_snapshot_hash: [32]u8,
};

pub const SnapshotBody = struct {
    schema_version: []const u8,
    project_id: []const u8,
    environment: []const u8,
    operation: []const u8,
    secret_ref: [32]u8,
    epoch: u64,
    previous_snapshot_hash: [32]u8,
    created_at: []const u8,
    algorithm: AlgorithmDescriptor,
    aad: SnapshotAad,
    nonce: [12]u8,
    sealed_payload: []const u8,
    auth_tag: [16]u8,
    wrapped_dek: []const u8,
    wrap_nonce: [12]u8,
    wrap_auth_tag: [16]u8,
    dek_wrapping_key_id: []const u8,
    enclave_public_key_id: []const u8,
    consumer_public_key_id: []const u8,
};

pub const Attestations = struct {
    enclave_signature: [64]u8,
    consumer_countersignature: [64]u8,
};

pub const PersistenceReceipt = struct {
    provider: []const u8,
    repository: []const u8,
    branch: []const u8,
    commit_sha: ?[]const u8,
    committed_at: ?[]const u8,
};

pub const SnapshotEnvelope = struct {
    snapshot_body: SnapshotBody,
    snapshot_id: [32]u8,
    attestations: Attestations,
    persistence_receipt: ?PersistenceReceipt,
};

/// Standalone AES-256-GCM Seal and Unseal Functions
pub const SealedPayload = struct {
    ciphertext: []u8,
    auth_tag: [16]u8,
};

pub fn sealPayload(
    allocator: std.mem.Allocator,
    plaintext: []const u8,
    dek: *const [32]u8,
    nonce: [12]u8,
    aad: []const u8,
) !SealedPayload {
    const ciphertext = try allocator.alloc(u8, plaintext.len);
    errdefer allocator.free(ciphertext);
    var auth_tag: [16]u8 = undefined;
    Aes256Gcm.encrypt(ciphertext, &auth_tag, plaintext, aad, nonce, dek.*);
    return SealedPayload{
        .ciphertext = ciphertext,
        .auth_tag = auth_tag,
    };
}

pub fn unsealPayload(
    allocator: std.mem.Allocator,
    sealed_payload: []const u8,
    auth_tag: [16]u8,
    dek: *const [32]u8,
    nonce: [12]u8,
    aad: []const u8,
) ![]u8 {
    const plaintext = try allocator.alloc(u8, sealed_payload.len);
    errdefer allocator.free(plaintext);
    Aes256Gcm.decrypt(plaintext, sealed_payload, auth_tag, aad, nonce, dek.*) catch {
        return LsesError.InvalidAuthTag;
    };
    return plaintext;
}

/// Order-Fixed Field Canonicalization
fn appendField(writer: anytype, name: []const u8, value: []const u8) !void {
    try writer.print("{s}={d}:{s};", .{ name, value.len, value });
}

fn appendU64Field(writer: anytype, name: []const u8, value: u64) !void {
    try writer.print("{s}=u64:{d};", .{ name, value });
}

fn appendHexField(writer: anytype, name: []const u8, bytes: []const u8) !void {
    try writer.print("{s}=hex:", .{name});
    for (bytes) |b| {
        try writer.print("{x:0>2}", .{b});
    }
    try writer.writeAll(";");
}

pub fn canonicalizeAad(allocator: std.mem.Allocator, aad: SnapshotAad) ![]u8 {
    var payload_aad_buf = std.Io.Writer.Allocating.init(allocator);
    errdefer payload_aad_buf.deinit();
    const pw = &payload_aad_buf.writer;
    try appendField(pw, "project", aad.project);
    try appendField(pw, "environment", aad.environment);
    try appendField(pw, "snapshot_type", aad.snapshot_type);
    try appendField(pw, "operation", aad.operation);
    try appendU64Field(pw, "epoch", aad.epoch);
    try appendHexField(pw, "previous_snapshot_hash", &aad.previous_snapshot_hash);
    return try payload_aad_buf.toOwnedSlice();
}

pub fn canonicalizeSnapshotBody(
    allocator: std.mem.Allocator,
    body: SnapshotBody,
) ![]u8 {
    var out = std.Io.Writer.Allocating.init(allocator);
    errdefer out.deinit();
    const writer = &out.writer;

    try writer.writeAll("LSES-CANON-V1;");
    try appendField(writer, "schema_version", body.schema_version);
    try appendField(writer, "project_id", body.project_id);
    try appendField(writer, "environment", body.environment);
    try appendField(writer, "operation", body.operation);
    try appendHexField(writer, "secret_ref", &body.secret_ref);
    try appendU64Field(writer, "epoch", body.epoch);
    try appendHexField(writer, "previous_snapshot_hash", &body.previous_snapshot_hash);
    try appendField(writer, "created_at", body.created_at);
    try appendField(writer, "algorithm.content_encryption", body.algorithm.content_encryption);
    try appendField(writer, "algorithm.key_wrapping", body.algorithm.key_wrapping);
    try appendField(writer, "algorithm.enclave_signature", body.algorithm.enclave_signature);
    try appendField(writer, "algorithm.consumer_signature", body.algorithm.consumer_signature);
    try appendField(writer, "aad.project", body.aad.project);
    try appendField(writer, "aad.environment", body.aad.environment);
    try appendField(writer, "aad.snapshot_type", body.aad.snapshot_type);
    try appendField(writer, "aad.operation", body.aad.operation);
    try appendU64Field(writer, "aad.epoch", body.aad.epoch);
    try appendHexField(writer, "aad.previous_snapshot_hash", &body.aad.previous_snapshot_hash);
    try appendHexField(writer, "nonce", &body.nonce);
    try appendField(writer, "sealed_payload", body.sealed_payload);
    try appendHexField(writer, "auth_tag", &body.auth_tag);
    try appendField(writer, "wrapped_dek", body.wrapped_dek);
    try appendHexField(writer, "wrap_nonce", &body.wrap_nonce);
    try appendHexField(writer, "wrap_auth_tag", &body.wrap_auth_tag);
    try appendField(writer, "dek_wrapping_key_id", body.dek_wrapping_key_id);
    try appendField(writer, "enclave_public_key_id", body.enclave_public_key_id);
    try appendField(writer, "consumer_public_key_id", body.consumer_public_key_id);

    return try out.toOwnedSlice();
}

pub fn computeSnapshotId(canonical_body: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    crypto.hash.sha2.Sha256.hash(canonical_body, &out, .{});
    return out;
}

pub fn canonicalizeSignatureInput(
    allocator: std.mem.Allocator,
    snapshot_id: [32]u8,
    body: SnapshotBody,
) ![]u8 {
    const canonical_body = try canonicalizeSnapshotBody(allocator, body);
    defer allocator.free(canonical_body);

    // CVE-LSES-015: Use bytesToHex for deterministic zero-padded 64-char hex.
    // The previous "{x}" format specifier for a [32]u8 array does NOT zero-pad
    // individual bytes, producing variable-length output (e.g. 0x0a → "a" not "0a"),
    // which truncates signatures and breaks verification for bytes < 0x10.
    const hex_id = std.fmt.bytesToHex(snapshot_id, .lower);

    return try std.fmt.allocPrint(allocator, "LSES-SIGNATURE-INPUT-V1;\nsnapshot_id={s};\nsnapshot_body={d}:{s};", .{
        &hex_id,
        canonical_body.len,
        canonical_body,
    });
}

/// Dual Attestation Helpers
pub fn signEd25519(
    signature_input: []const u8,
    private_key: [64]u8,
) ![64]u8 {
    const sk = try Ed25519.SecretKey.fromBytes(private_key);
    const kp = try Ed25519.KeyPair.fromSecretKey(sk);
    const sig = try kp.sign(signature_input, null);
    return sig.toBytes();
}

pub fn verifyEd25519(
    signature_input: []const u8,
    sig_bytes: [64]u8,
    public_key_bytes: [32]u8,
) !void {
    const sig = Ed25519.Signature.fromBytes(sig_bytes);
    const pk = try Ed25519.PublicKey.fromBytes(public_key_bytes);
    sig.verify(signature_input, pk) catch {
        return LsesError.InvalidSignature;
    };
}

pub fn verifyAttestations(
    allocator: std.mem.Allocator,
    body: SnapshotBody,
    snapshot_id: [32]u8,
    attestations: Attestations,
    keys: VerificationKeys,
) !void {
    const signature_input = try canonicalizeSignatureInput(allocator, snapshot_id, body);
    defer allocator.free(signature_input);

    verifyEd25519(signature_input, attestations.enclave_signature, keys.enclave_public_key) catch {
        return LsesError.InvalidSignature;
    };
    verifyEd25519(signature_input, attestations.consumer_countersignature, keys.consumer_public_key) catch {
        return LsesError.InvalidConsumerCountersignature;
    };
}

pub const NonceUseKind = enum {
    payload,
    dek_wrap,
};

pub const NonceRecord = struct {
    snapshot_id: [32]u8,
    kind: NonceUseKind,
    nonce: [12]u8,
    context_hash: [32]u8,
};

// CVE-LSES-014: Hard cap on the registry to prevent unbounded memory growth.
// Without a cap, a caller that sends N unique (nonce, context) pairs can consume
// O(N) heap memory with no bound, enabling a slow-path denial-of-service.
// When the cap is reached, new entries are denied (fail-closed).
const MAX_NONCE_REGISTRY_SIZE: u32 = 100_000;

/// In-Memory Nonce Registry to detect/block nonces reuse
pub const NonceRegistry = struct {
    seen: std.AutoHashMap([32]u8, NonceRecord),

    pub fn init(allocator: std.mem.Allocator) NonceRegistry {
        return .{
            .seen = std.AutoHashMap([32]u8, NonceRecord).init(allocator),
        };
    }

    pub fn deinit(self: *NonceRegistry) void {
        self.seen.deinit();
    }

    pub fn checkAndRecord(
        self: *NonceRegistry,
        snapshot_id: [32]u8,
        kind: NonceUseKind,
        context: []const u8,
        nonce: [12]u8,
    ) !void {
        const key = computeNonceKey(kind, context, nonce);

        if (self.seen.get(key)) |existing| {
            if (std.mem.eql(u8, &existing.snapshot_id, &snapshot_id)) {
                // Idempotent re-verification of the same snapshot is always allowed.
                return;
            }
            return LsesError.NonceReused;
        }

        // Fail-closed: reject new entries once the registry is full.
        // Returning NonceReused causes the caller to refuse the snapshot,
        // which is the safe outcome (deny rather than silently allow).
        if (self.seen.count() >= MAX_NONCE_REGISTRY_SIZE) {
            return LsesError.NonceReused;
        }

        var context_hash: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(context, &context_hash, .{});

        try self.seen.put(key, .{
            .snapshot_id = snapshot_id,
            .kind = kind,
            .nonce = nonce,
            .context_hash = context_hash,
        });
    }
};

pub fn computeNonceKey(
    kind: NonceUseKind,
    context: []const u8,
    nonce: [12]u8,
) [32]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("LSES-NONCE-KEY-V1");
    h.update(if (kind == .payload) "payload" else "dek_wrap");
    h.update(context);
    h.update(&nonce);
    var out: [32]u8 = undefined;
    h.final(&out);
    return out;
}


pub fn payloadNonceContext(
    allocator: std.mem.Allocator,
    body: SnapshotBody,
) ![]u8 {
    var aw = std.Io.Writer.Allocating.init(allocator);
    errdefer aw.deinit();

    const w = &aw.writer;
    try w.writeAll("LSES-PAYLOAD-NONCE-V1");
    try w.writeAll(body.project_id);
    try w.writeAll("\x00");
    try w.writeAll(body.environment);
    try w.writeAll("\x00");
    try w.writeAll(&body.secret_ref);
    try w.writeAll("\x00");
    try w.print("{d}", .{body.epoch});
    return try aw.toOwnedSlice();
}

pub fn wrapNonceContext(
    allocator: std.mem.Allocator,
    body: SnapshotBody,
) ![]u8 {
    var aw = std.Io.Writer.Allocating.init(allocator);
    errdefer aw.deinit();

    const w = &aw.writer;
    try w.writeAll("LSES-WRAP-NONCE-V1");
    try w.writeAll(body.project_id);
    try w.writeAll("\x00");
    try w.writeAll(body.environment);
    try w.writeAll("\x00");
    try w.writeAll(body.dek_wrapping_key_id);
    try w.writeAll("\x00");
    try w.print("{d}", .{body.epoch});
    return try aw.toOwnedSlice();
}

/// Verification Structures and Policies
pub const VerificationMode = enum {
    strict,
    recovery_limited,
};

pub const AccessPolicy = struct {
    allow_plaintext_export: bool,
    allowed_consumers: []const []const u8,

    pub fn allows(
        self: AccessPolicy,
        operation: []const u8,
        consumer_id: []const u8,
        secret_ref: [32]u8,
    ) bool {
        // CVE-LSES-016: Enforce per-operation policy instead of silently ignoring
        // the operation field. Callers that pass "export_plaintext" are denied
        // unless allow_plaintext_export is explicitly set in the policy.
        //
        // Per-secret-ref enforcement (allow/deny individual secrets by their
        // computed HMAC reference) is not yet implemented. Future work: add an
        // optional `allowed_secret_refs: ?[]const [32]u8` field and check it here.
        _ = secret_ref;

        if (std.mem.eql(u8, operation, "export_plaintext") and !self.allow_plaintext_export) {
            return false;
        }

        for (self.allowed_consumers) |c| {
            if (std.mem.eql(u8, c, consumer_id)) return true;
        }
        return false;
    }
};

pub const SigningIdentity = struct {
    key_id: []const u8,
    public_key: [32]u8,
    private_key: ?[64]u8,
};

pub const VerificationKeys = struct {
    enclave_key_id: []const u8,
    enclave_public_key: [32]u8,
    consumer_key_id: []const u8,
    consumer_public_key: [32]u8,
};

pub const KekResolver = struct {
    providers: []const KekProvider,

    pub fn resolve(self: KekResolver, key_id: []const u8) !KekProvider {
        for (self.providers) |provider| {
            if (std.mem.eql(u8, provider.key_id, key_id)) return provider;
        }
        return LsesError.StaleKekId;
    }
};

/// MIASMA-WORM / supply-chain defense: registry of trusted enclave public keys.
///
/// A worm or supply-chain-poisoned enclave binary that generates its own key pair
/// will NOT be in this registry, so consumers that load it would immediately fail
/// `verifySnapshot`. This provides a second authentication factor beyond the
/// chain-of-custody check: even a valid chain signed by a fresh key is rejected
/// unless the operator has explicitly registered that key as trusted.
///
/// Keys in this registry are Ed25519 public keys (32 bytes). Operators add them
/// via the `LSES_TRUSTED_ENCLAVE_KEYS` environment variable (comma-separated hex).
///
/// Comparison uses `std.mem.eql` — public keys are not secret material, so
/// variable-time comparison is acceptable and constant-time is not required.
pub const TrustedKeyRegistry = struct {
    keys: []const [32]u8,

    /// Returns true if `key` is in the trusted set, false otherwise.
    pub fn isTrusted(self: TrustedKeyRegistry, key: [32]u8) bool {
        for (self.keys) |trusted| {
            if (std.mem.eql(u8, &trusted, &key)) return true;
        }
        return false;
    }
};

pub const VerificationContext = struct {
    mode: VerificationMode,
    trusted_chain_head: ?[32]u8,
    last_accepted_epoch: u64,
    verification_keys: VerificationKeys,
    policy: AccessPolicy,
    nonce_registry: *NonceRegistry,
    kek_resolver: *KekResolver,
    /// Optional trusted-key registry. When non-null, the enclave public key used
    /// to sign the snapshot MUST appear in this registry. Null disables the check
    /// (legacy / first-boot mode; operators should enable pinning in production).
    trusted_enclave_keys: ?*const TrustedKeyRegistry,
};

/// Zero-Bypass Snapshot Authenticator
pub fn verifySnapshot(
    allocator: std.mem.Allocator,
    envelope: SnapshotEnvelope,
    ctx: *VerificationContext,
) !void {
    // 1. Validar schema_version
    if (!std.mem.eql(u8, envelope.snapshot_body.schema_version, "lses.snapshot.v1")) {
        return LsesError.UnsupportedSchemaVersion;
    }

    // 2. Validar campos obrigatórios
    if (envelope.snapshot_body.wrapped_dek.len == 0) return LsesError.MissingWrappedDek;
    
    // Validar se nonce de wrap não é totalmente zero
    var all_zero_wrap_nonce = true;
    for (envelope.snapshot_body.wrap_nonce) |b| {
        if (b != 0) { all_zero_wrap_nonce = false; break; }
    }
    if (all_zero_wrap_nonce) return LsesError.MissingWrapNonce;

    // Validar se auth tag de wrap não é totalmente zero
    var all_zero_wrap_auth_tag = true;
    for (envelope.snapshot_body.wrap_auth_tag) |b| {
        if (b != 0) { all_zero_wrap_auth_tag = false; break; }
    }
    if (all_zero_wrap_auth_tag) return LsesError.MissingWrapAuthTag;

    // 3. Canonicalizar snapshot_body
    const canonical_body = try canonicalizeSnapshotBody(allocator, envelope.snapshot_body);
    defer allocator.free(canonical_body);

    // 4. Recomputar snapshot_id
    const computed_id = computeSnapshotId(canonical_body);

    // 5. Comparar recomputado com armazenado
    if (!std.mem.eql(u8, &computed_id, &envelope.snapshot_id)) {
        return LsesError.InvalidSnapshotHash;
    }

    // 5.1. Validar causal lineage no AAD
    if (!std.mem.eql(u8, &envelope.snapshot_body.aad.previous_snapshot_hash, &envelope.snapshot_body.previous_snapshot_hash)) {
        return LsesError.ChainMismatch;
    }

    // 6-8. Verificar assinaturas Enclave e Consumer
    try verifyAttestations(
        allocator,
        envelope.snapshot_body,
        envelope.snapshot_id,
        envelope.attestations,
        ctx.verification_keys,
    );

    // 9. Validar ids das public keys
    if (!std.mem.eql(u8, envelope.snapshot_body.enclave_public_key_id, ctx.verification_keys.enclave_key_id)) {
        return LsesError.UnauthorizedConsumer;
    }
    if (!std.mem.eql(u8, envelope.snapshot_body.consumer_public_key_id, ctx.verification_keys.consumer_key_id)) {
        return LsesError.UnauthorizedConsumer;
    }

    // 9.5. MIASMA-WORM / supply-chain defense: verify the enclave key that
    // signed this snapshot is in the operator-configured trusted registry.
    //
    // Without this check, a worm that injects a fresh key pair at startup
    // (or a supply-chain-poisoned binary that generates its own keys) would
    // produce perfectly valid signatures that pass all prior checks. The
    // registry is the only out-of-band anchor that ties a snapshot to an
    // enclave binary the operator has explicitly trusted.
    if (ctx.trusted_enclave_keys) |registry| {
        if (!registry.isTrusted(ctx.verification_keys.enclave_public_key)) {
            return LsesError.UnauthorizedConsumer;
        }
    }

    // 10. Validar policy
    if (!ctx.policy.allows(envelope.snapshot_body.operation, envelope.snapshot_body.consumer_public_key_id, envelope.snapshot_body.secret_ref)) {
        return LsesError.UnauthorizedConsumer;
    }

    // 11. Validar trusted_chain_head
    if (ctx.trusted_chain_head) |trusted_head| {
        if (!std.mem.eql(u8, &envelope.snapshot_body.previous_snapshot_hash, &trusted_head)) {
            if (envelope.snapshot_body.epoch > 1) {
                return LsesError.ChainHeadMismatch;
            }
        }
    } else {
        switch (ctx.mode) {
            .strict => return LsesError.MissingTrustAnchor,
            .recovery_limited => {},
        }
    }

    // 12. Validar epoch
    if (envelope.snapshot_body.epoch <= ctx.last_accepted_epoch) {
        return LsesError.RollbackDetected;
    }

    // 13. Validar nonce reuse (both payload and dek_wrap)
    const payload_ctx = try payloadNonceContext(allocator, envelope.snapshot_body);
    defer allocator.free(payload_ctx);

    try ctx.nonce_registry.checkAndRecord(
        envelope.snapshot_id,
        .payload,
        payload_ctx,
        envelope.snapshot_body.nonce,
    );

    const wrap_ctx = try wrapNonceContext(allocator, envelope.snapshot_body);
    defer allocator.free(wrap_ctx);

    try ctx.nonce_registry.checkAndRecord(
        envelope.snapshot_id,
        .dek_wrap,
        wrap_ctx,
        envelope.snapshot_body.wrap_nonce,
    );
}

/// Decrypts a verified snapshot using KEK resolver and unseal API
pub fn decryptVerifiedSnapshot(
    allocator: std.mem.Allocator,
    envelope: SnapshotEnvelope,
    ctx: *VerificationContext,
) ![]u8 {
    // 1. Chamar verifySnapshot
    try verifySnapshot(allocator, envelope, ctx);

    // 2. Resolver KEK provider
    const provider = try ctx.kek_resolver.resolve(envelope.snapshot_body.dek_wrapping_key_id);

    // 3. Wrap AAD — must be the same canonical AAD used during sealing so that
    // the AES-256-GCM auth tag over the wrapped DEK covers the full snapshot
    // context. CVE-LSES-012: using only provider.key_id as AAD allows a DEK
    // wrapped for one snapshot to be substituted into any other snapshot that
    // shares the same KEK provider, bypassing the authentication guarantee.
    const wrap_aad = try canonicalizeAad(allocator, envelope.snapshot_body.aad);
    defer allocator.free(wrap_aad);

    // 4. Unwrap DEK
    var hex_wrapped_dek: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&hex_wrapped_dek, envelope.snapshot_body.wrapped_dek);

    const wrapped = WrappedDek{
        .key_id = envelope.snapshot_body.dek_wrapping_key_id,
        .wrapped_dek = hex_wrapped_dek,
        .wrap_nonce = envelope.snapshot_body.wrap_nonce,
        .wrap_auth_tag = envelope.snapshot_body.wrap_auth_tag,
        .algorithm = envelope.snapshot_body.algorithm.key_wrapping,
    };
    var dek = try provider.unwrap(allocator, wrapped, wrap_aad);
    defer secureZero(&dek);

    // 5. Canonicalizar payload AAD
    const canonical_aad = try canonicalizeAad(allocator, envelope.snapshot_body.aad);
    defer allocator.free(canonical_aad);

    // 6-7. Decrypt / unseal payload
    const bin_sealed_payload = try allocator.alloc(u8, envelope.snapshot_body.sealed_payload.len / 2);
    defer allocator.free(bin_sealed_payload);
    _ = try std.fmt.hexToBytes(bin_sealed_payload, envelope.snapshot_body.sealed_payload);

    const plaintext = try unsealPayload(
        allocator,
        bin_sealed_payload,
        envelope.snapshot_body.auth_tag,
        &dek,
        envelope.snapshot_body.nonce,
        canonical_aad,
    );

    return plaintext;
}

/// Derivation of cryptographic reference for secrets to prevent metadata leak
pub fn computeSecretRef(
    project_id: []const u8,
    environment: []const u8,
    secret_name: []const u8,
) [32]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("LSES-SECRET-REF-V1");
    h.update(project_id);
    h.update("\x00");
    h.update(environment);
    h.update("\x00");
    h.update(secret_name);
    var out: [32]u8 = undefined;
    h.final(&out);
    return out;
}

/// Short-Lived Handle-Backed Memory Store
pub const RuntimeSecretEntry = struct {
    secret: []u8,
    expires_at: i64,
    consumed: bool,
};

pub const RuntimeSecretStore = struct {
    entries: std.AutoHashMap([32]u8, RuntimeSecretEntry),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) RuntimeSecretStore {
        return .{
            .entries = std.AutoHashMap([32]u8, RuntimeSecretEntry).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *RuntimeSecretStore) void {
        var it = self.entries.iterator();
        while (it.next()) |entry| {
            secureZero(entry.value_ptr.secret);
            self.allocator.free(entry.value_ptr.secret);
        }
        self.entries.deinit();
    }

    pub fn insert(
        self: *RuntimeSecretStore,
        plaintext: []const u8,
        ttl_seconds: i64,
        now: i64,
    ) !RuntimeSecretHandle {
        var handle_id: [32]u8 = undefined;
        EnclaveCrypto.randomBytes(&handle_id);

        const copy = try self.allocator.dupe(u8, plaintext);
        errdefer self.allocator.free(copy);

        try self.entries.put(handle_id, .{
            .secret = copy,
            .expires_at = now + ttl_seconds,
            .consumed = false,
        });

        return RuntimeSecretHandle{
            .handle_id = handle_id,
            .expires_at = now + ttl_seconds,
            .scope = "runtime-only",
        };
    }

    pub fn consume(
        self: *RuntimeSecretStore,
        handle_id: [32]u8,
        now: i64,
    ) ![]u8 {
        if (self.entries.getPtr(handle_id)) |entry| {
            if (entry.consumed or now > entry.expires_at) {
                secureZero(entry.secret);
                self.allocator.free(entry.secret);
                _ = self.entries.remove(handle_id);
                return LsesError.ExpiredHandle;
            }
            entry.consumed = true;
            const copy = try self.allocator.dupe(u8, entry.secret);
            secureZero(entry.secret);
            self.allocator.free(entry.secret);
            _ = self.entries.remove(handle_id);
            return copy;
        }
        return LsesError.InvalidHandle;
    }

    pub fn get(self: *RuntimeSecretStore, handle_id: [32]u8, now: i64) ?[]const u8 {
        return self.consume(handle_id, now) catch null;
    }

    pub fn purgeExpired(self: *RuntimeSecretStore, now: i64) void {
        var expired_keys = std.ArrayList([32]u8).empty;
        defer expired_keys.deinit(self.allocator);

        var it = self.entries.iterator();
        while (it.next()) |entry| {
            if (now > entry.value_ptr.expires_at) {
                expired_keys.append(self.allocator, entry.key_ptr.*) catch {};
            }
        }

        for (expired_keys.items) |key| {
            if (self.entries.fetchRemove(key)) |removed| {
                secureZero(removed.value.secret);
                self.allocator.free(removed.value.secret);
            }
        }
    }
};

pub const RuntimeSecretHandle = struct {
    handle_id: [32]u8,
    expires_at: i64,
    scope: []const u8 = "runtime-only",
};

pub const SecretReadRequest = struct {
    project_id: []const u8,
    environment: []const u8,
    secret_name: []const u8,
    consumer_id: []const u8,
    export_plaintext: bool = false,
};

pub const SecretReadResult = union(enum) {
    handle: RuntimeSecretHandle,
    plaintext: []u8,
};

pub fn readSecret(
    allocator: std.mem.Allocator,
    request: SecretReadRequest,
    envelope: SnapshotEnvelope,
    ctx: *VerificationContext,
    store: *RuntimeSecretStore,
    now: i64,
) !SecretReadResult {
    const plaintext = try decryptVerifiedSnapshot(allocator, envelope, ctx);
    errdefer {
        secureZero(plaintext);
        allocator.free(plaintext);
    }

    if (request.export_plaintext) {
        if (!ctx.policy.allow_plaintext_export) {
            secureZero(plaintext);
            allocator.free(plaintext);
            return LsesError.PlaintextExportNotAllowed;
        }
        return SecretReadResult{ .plaintext = plaintext };
    }

    const handle = try store.insert(plaintext, 60, now);
    secureZero(plaintext);
    allocator.free(plaintext);

    return SecretReadResult{ .handle = handle };
}

/// Chain events recovery
pub const RecoveryResult = struct {
    latest_snapshot_id: [32]u8,
    latest_epoch: u64,
    limited: bool,
    restored_handle: ?RuntimeSecretHandle,
};

pub fn recoverLatest(
    allocator: std.mem.Allocator,
    envelopes: []const SnapshotEnvelope,
    ctx: *VerificationContext,
    store: *RuntimeSecretStore,
    now: i64,
) !RecoveryResult {
    if (envelopes.len == 0) return LsesError.NoSnapshotsFound;

    if (ctx.mode == .strict and ctx.trusted_chain_head == null) {
        return LsesError.MissingTrustAnchor;
    }

    var sorted = try allocator.alloc(SnapshotEnvelope, envelopes.len);
    defer allocator.free(sorted);
    for (envelopes, 0..) |env, idx| {
        sorted[idx] = env;
    }

    // Bubble sort by epoch
    var i: usize = 0;
    while (i < sorted.len) : (i += 1) {
        var j: usize = i + 1;
        while (j < sorted.len) : (j += 1) {
            if (sorted[i].snapshot_body.epoch > sorted[j].snapshot_body.epoch) {
                const tmp = sorted[i];
                sorted[i] = sorted[j];
                sorted[j] = tmp;
            }
        }
    }

    var expected_prev_hash: ?[32]u8 = null;
    var last_epoch: u64 = 0;

    for (sorted, 0..) |env, idx| {
        try verifySnapshot(allocator, env, ctx);

        if (idx > 0) {
            if (expected_prev_hash) |prev| {
                if (!std.mem.eql(u8, &env.snapshot_body.previous_snapshot_hash, &prev)) {
                    return LsesError.ChainMismatch;
                }
            }
            if (env.snapshot_body.epoch == last_epoch) {
                return LsesError.RollbackDetected;
            }
            if (env.snapshot_body.epoch < last_epoch) {
                return LsesError.RollbackDetected;
            }
        }

        expected_prev_hash = env.snapshot_id;
        last_epoch = env.snapshot_body.epoch;
    }

    const latest_env = sorted[sorted.len - 1];

    if (ctx.mode == .strict) {
        if (ctx.trusted_chain_head) |anchor| {
            if (!std.mem.eql(u8, &latest_env.snapshot_id, &anchor)) {
                return LsesError.ChainHeadMismatch;
            }
        }
    }

    const limited = (ctx.trusted_chain_head == null and ctx.mode == .recovery_limited);

    const plaintext = try decryptVerifiedSnapshot(allocator, latest_env, ctx);
    defer {
        secureZero(plaintext);
        allocator.free(plaintext);
    }

    const handle = try store.insert(plaintext, 3600, now);

    return RecoveryResult{
        .latest_snapshot_id = latest_env.snapshot_id,
        .latest_epoch = latest_env.snapshot_body.epoch,
        .limited = limited,
        .restored_handle = handle,
    };
}
