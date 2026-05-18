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

    pub fn deterministicTestBytes(buffer: []u8, seed: u64) void {
        var prng = std.Random.DefaultPrng.init(seed);
        prng.random().bytes(buffer);
    }
};

/// Volatile Secure Memory Zeroing to prevent compiler optimizations
pub fn secureZero(bytes: []u8) void {
    @memset(bytes, 0);
    for (bytes) |*b| {
        asm volatile ("" : : [ptr] "r" (b) : "memory");
    }
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
pub const SnapshotBody = struct {
    schema_version: []const u8,
    project_id: []const u8,
    environment: []const u8,
    operation: []const u8,
    secret_ref: [32]u8,
    epoch: u64,
    previous_snapshot_hash: [32]u8,
    created_at: []const u8,
    algorithm: AlgorithmSpec,
    aad: AadSpec,
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

pub const AlgorithmSpec = struct {
    content_encryption: []const u8,
    key_wrapping: []const u8,
    enclave_signature: []const u8,
    consumer_signature: []const u8,
};

pub const AadSpec = struct {
    project: []const u8,
    environment: []const u8,
    snapshot_type: []const u8,
    operation: []const u8,
    epoch: u64,
    previous_snapshot_hash: [32]u8,
};

pub const Attestations = struct {
    enclave_signature: [64]u8,
    consumer_countersignature: [64]u8,
};

pub const PersistenceReceipt = struct {
    provider: []const u8,
    repository: []const u8,
    branch: []const u8,
    commit_sha: []const u8,
    committed_at: ?[]const u8,
};

pub const CryptographicEnvelope = struct {
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
    try writer.print("{d}:{s}={d}:{s};\n", .{
        name.len,
        name,
        value.len,
        value,
    });
}

fn appendHexField(writer: anytype, name: []const u8, bytes: []const u8) !void {
    try writer.print("{d}:{s}={d}:", .{ name.len, name, bytes.len * 2 });
    for (bytes) |b| {
        try writer.print("{x:0>2}", .{b});
    }
    try writer.writeAll(";\n");
}

pub fn canonicalizeSnapshotBody(
    allocator: std.mem.Allocator,
    body: SnapshotBody,
) ![]u8 {
    var out = std.Io.Writer.Allocating.init(allocator);
    errdefer out.deinit();
    const writer = &out.writer;

    try writer.writeAll("LSES-CANON-V1\n");
    try appendField(writer, "schema_version", body.schema_version);
    try appendField(writer, "project_id", body.project_id);
    try appendField(writer, "environment", body.environment);
    try appendField(writer, "operation", body.operation);
    try appendHexField(writer, "secret_ref", &body.secret_ref);
    try writer.print("epoch={d};\n", .{body.epoch});
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
    try writer.print("aad.epoch={d};\n", .{body.aad.epoch});
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
    
    const hex_id = std.fmt.bytesToHex(snapshot_id, .lower);
    return try std.fmt.allocPrint(allocator, "{s}:{s}", .{ hex_id, canonical_body });
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

/// In-Memory Nonce Registry to detect/block nonces reuse
pub const NonceRegistry = struct {
    seen: std.StringHashMap(void),

    pub fn init(allocator: std.mem.Allocator) NonceRegistry {
        return .{
            .seen = std.StringHashMap(void).init(allocator),
        };
    }

    pub fn deinit(self: *NonceRegistry) void {
        var it = self.seen.keyIterator();
        const allocator = self.seen.allocator;
        while (it.next()) |key| {
            allocator.free(key.*);
        }
        self.seen.deinit();
    }

    pub fn checkAndRecord(
        self: *NonceRegistry,
        allocator: std.mem.Allocator,
        dek_context: []const u8,
        nonce: [12]u8,
    ) !void {
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(dek_context);
        hasher.update(&nonce);
        var hash: [32]u8 = undefined;
        hasher.final(&hash);

        const hex = try std.fmt.allocPrint(allocator, "{x}", .{hash});
        errdefer allocator.free(hex);

        if (self.seen.contains(hex)) {
            return LsesError.NonceReused;
        }
        try self.seen.put(hex, {});
    }
};

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
        _ = operation;
        _ = secret_ref;
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

pub const VerificationContext = struct {
    mode: VerificationMode,
    trusted_chain_head: ?[32]u8,
    last_accepted_epoch: u64,
    verification_keys: VerificationKeys,
    policy: AccessPolicy,
    nonce_registry: *NonceRegistry,
    kek_resolver: *KekResolver,
};

/// Zero-Bypass Snapshot Authenticator
pub fn verifySnapshot(
    allocator: std.mem.Allocator,
    envelope: CryptographicEnvelope,
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

    // 13. Validar nonce reuse
    try ctx.nonce_registry.checkAndRecord(
        allocator,
        envelope.snapshot_body.dek_wrapping_key_id,
        envelope.snapshot_body.nonce,
    );
}

/// Decrypts a verified snapshot using KEK resolver and unseal API
pub fn decryptVerifiedSnapshot(
    allocator: std.mem.Allocator,
    envelope: CryptographicEnvelope,
    ctx: *VerificationContext,
) ![]u8 {
    // 1. Chamar verifySnapshot
    try verifySnapshot(allocator, envelope, ctx);

    // 2. Resolver KEK provider
    const provider = try ctx.kek_resolver.resolve(envelope.snapshot_body.dek_wrapping_key_id);

    // 3. Wrap AAD
    const wrap_aad = provider.key_id;

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
    var payload_aad_buf = std.io.Writer.Allocating.init(allocator);
    defer payload_aad_buf.deinit();
    const pw = payload_aad_buf.writer();
    try appendField(pw, "project", envelope.snapshot_body.aad.project);
    try appendField(pw, "environment", envelope.snapshot_body.aad.environment);
    try appendField(pw, "snapshot_type", envelope.snapshot_body.aad.snapshot_type);
    try appendField(pw, "operation", envelope.snapshot_body.aad.operation);
    try pw.print("epoch={d};\n", .{envelope.snapshot_body.aad.epoch});
    try appendHexField(pw, "previous_snapshot_hash", &envelope.snapshot_body.aad.previous_snapshot_hash);
    const canonical_aad = try payload_aad_buf.toOwnedSlice();
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

/// Short-Lived Handle-Backed Memory Store
pub const SecretStoreEntry = struct {
    secret_material: []u8,
    expires_at: i64,
};

pub const RuntimeSecretStore = struct {
    store: std.StringHashMap(SecretStoreEntry),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) RuntimeSecretStore {
        return .{
            .store = std.StringHashMap(SecretStoreEntry).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *RuntimeSecretStore) void {
        var it = self.store.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.secret_material);
        }
        self.store.deinit();
    }

    pub fn put(self: *RuntimeSecretStore, handle_id: [32]u8, secret: []const u8, expires_at: i64) !void {
        const hex = try std.fmt.allocPrint(self.allocator, "{x}", .{handle_id});
        errdefer self.allocator.free(hex);
        const secret_copy = try self.allocator.dupe(u8, secret);
        errdefer self.allocator.free(secret_copy);

        try self.store.put(hex, .{
            .secret_material = secret_copy,
            .expires_at = expires_at,
        });
    }

    pub fn get(self: *RuntimeSecretStore, handle_id: [32]u8, now: i64) ?[]const u8 {
        var hex_buf: [128]u8 = undefined;
        const hex = std.fmt.bufPrint(&hex_buf, "{x}", .{handle_id}) catch unreachable;

        if (self.store.get(hex)) |entry| {
            if (now > entry.expires_at) return null;
            return entry.secret_material;
        }
        return null;
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
    envelope: CryptographicEnvelope,
    ctx: *VerificationContext,
    store: *RuntimeSecretStore,
    now: i64,
) !SecretReadResult {
    const plaintext = try decryptVerifiedSnapshot(allocator, envelope, ctx);
    errdefer allocator.free(plaintext);

    if (request.export_plaintext) {
        if (!ctx.policy.allow_plaintext_export) {
            return LsesError.PlaintextExportNotAllowed;
        }
        return SecretReadResult{ .plaintext = plaintext };
    }

    var handle_id: [32]u8 = undefined;
    EnclaveCrypto.randomBytes(&handle_id);

    const expires_at = now + 3600;
    try store.put(handle_id, plaintext, expires_at);
    allocator.free(plaintext);

    return SecretReadResult{
        .handle = .{
            .handle_id = handle_id,
            .expires_at = expires_at,
            .scope = "runtime-only",
        },
    };
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
    envelopes: []const CryptographicEnvelope,
    ctx: *VerificationContext,
    store: *RuntimeSecretStore,
    now: i64,
) !RecoveryResult {
    if (envelopes.len == 0) return LsesError.NoSnapshotsFound;

    var indices = try allocator.alloc(usize, envelopes.len);
    defer allocator.free(indices);
    for (indices, 0..) |*ind, i| {
        ind.* = i;
    }

    var i: usize = 0;
    while (i < envelopes.len) : (i += 1) {
        var j: usize = i + 1;
        while (j < envelopes.len) : (j += 1) {
            if (envelopes[indices[i]].snapshot_body.epoch > envelopes[indices[j]].snapshot_body.epoch) {
                const tmp = indices[i];
                indices[i] = indices[j];
                indices[j] = tmp;
            }
        }
    }

    var expected_hash: ?[32]u8 = null;
    var last_epoch: u64 = 0;

    for (indices) |idx| {
        const env = envelopes[idx];
        try verifySnapshot(allocator, env, ctx);

        if (expected_hash) |expected| {
            if (!std.mem.eql(u8, &env.snapshot_body.previous_snapshot_hash, &expected)) {
                return LsesError.ChainHeadMismatch;
            }
        }
        if (env.snapshot_body.epoch <= last_epoch) {
            return LsesError.RollbackDetected;
        }

        expected_hash = env.snapshot_id;
        last_epoch = env.snapshot_body.epoch;
    }

    const latest_env = envelopes[indices[envelopes.len - 1]];
    const limited = (ctx.trusted_chain_head == null and ctx.mode == .recovery_limited);

    const plaintext = try decryptVerifiedSnapshot(allocator, latest_env, ctx);
    defer allocator.free(plaintext);

    var handle_id: [32]u8 = undefined;
    EnclaveCrypto.randomBytes(&handle_id);
    const expires_at = now + 3600;
    try store.put(handle_id, plaintext, expires_at);

    return RecoveryResult{
        .latest_snapshot_id = latest_env.snapshot_id,
        .latest_epoch = latest_env.snapshot_body.epoch,
        .limited = limited,
        .restored_handle = RuntimeSecretHandle{
            .handle_id = handle_id,
            .expires_at = expires_at,
            .scope = "runtime-only",
        },
    };
}
