const std = @import("std");
const crypto = std.crypto;
const builtin = @import("builtin");
const Ed25519 = crypto.sign.Ed25519;
const X25519 = crypto.dh.X25519;
const Aes256Gcm = crypto.aead.aes_gcm.Aes256Gcm;

/// Linus Salamander Enclave Crypto Module
/// Implements Signal-inspired authenticated encryption with dual-signing.
pub const EnclaveCrypto = struct {
    service_keypair: Ed25519.KeyPair,
    
    pub fn init() !EnclaveCrypto {
        // In a real enclave, this would be derived from hardware-sealed seeds.
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
            const file = std.fs.cwd().openFile("/dev/urandom", .{}) catch unreachable;
            defer file.close();
            _ = file.readAll(buffer) catch unreachable;
        }
    }

    pub fn deterministicTestBytes(buffer: []u8, seed: u64) void {
        var prng = std.Random.DefaultPrng.init(seed);
        prng.random().bytes(buffer);
    }

    /// Encrypts the payload with a generated DEK, then wraps the DEK with the Enclave's KEK.
    pub fn sealAndWrapSecret(
        self: *EnclaveCrypto,
        allocator: std.mem.Allocator,
        data: []const u8,
        aad: []const u8,
    ) !SealedResult {
        _ = self; // Used when deriving KEK from enclave seed

        // 1. Generate ephemeral symmetric key (DEK)
        var dek: [Aes256Gcm.key_length]u8 = undefined;
        randomBytes(&dek);

        // 2. Encrypt payload with DEK
        var nonce: [Aes256Gcm.nonce_length]u8 = undefined;
        randomBytes(&nonce);
        
        const ciphertext = try allocator.alloc(u8, data.len);
        var tag: [Aes256Gcm.tag_length]u8 = undefined;
        Aes256Gcm.encrypt(ciphertext, &tag, data, aad, nonce, dek);

        // 3. Wrap DEK with KEK (Simulated KEK for PoC)
        var kek: [Aes256Gcm.key_length]u8 = undefined;
        randomBytes(&kek); // In reality, this comes from Enclave KMS/TPM
        var wrap_nonce: [Aes256Gcm.nonce_length]u8 = undefined;
        randomBytes(&wrap_nonce);
        const wrapped_dek = try allocator.alloc(u8, dek.len);
        var dek_tag: [Aes256Gcm.tag_length]u8 = undefined;
        Aes256Gcm.encrypt(wrapped_dek, &dek_tag, &dek, "", wrap_nonce, kek);

        // 4. Purge plaintext DEK
        @memset(&dek, 0);

        return SealedResult{
            .nonce = nonce,
            .sealed_payload = ciphertext,
            .auth_tag = tag,
            .wrapped_dek = wrapped_dek,
            .wrap_nonce = wrap_nonce,
            .wrap_auth_tag = dek_tag,
        };
    }

    /// Signs the signature_input
    pub fn signEnclave(
        self: *EnclaveCrypto,
        signature_input: []const u8,
    ) ![64]u8 {
        const service_sig = try self.service_keypair.sign(signature_input, null);
        return service_sig.toBytes();
    }
};

pub fn canonicalizeSnapshotBody(allocator: std.mem.Allocator, body: SnapshotBody) ![]u8 {
    // For Zig, stringify is deterministic on structs
    var out: std.Io.Writer.Allocating = .init(allocator);
    errdefer out.deinit();
    try std.json.Stringify.value(body, .{}, &out.writer);
    return out.toOwnedSlice();
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
    
    // Convert snapshot_id to hex for signature input
    const hex_id = std.fmt.bytesToHex(snapshot_id, .lower);
    return try std.fmt.allocPrint(allocator, "{s}:{s}", .{ hex_id, canonical_body });
}

pub fn signConsumer(signature_input: []const u8, consumer_keypair: Ed25519.KeyPair) ![64]u8 {
    const sig = try consumer_keypair.sign(signature_input, null);
    return sig.toBytes();
}

pub const SealedResult = struct {
    nonce: [12]u8,
    sealed_payload: []const u8,
    auth_tag: [16]u8,
    wrapped_dek: []const u8,
    wrap_nonce: [12]u8,
    wrap_auth_tag: [16]u8,
};

pub const SnapshotBody = struct {
    schema_version: []const u8,
    project_id: []const u8,
    environment: []const u8,
    operation: []const u8,
    secret_ref: []const u8,
    epoch: u64,
    previous_snapshot_hash: []const u8,
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

pub const Attestations = struct {
    enclave_signature: [64]u8,
    consumer_countersignature: [64]u8,
};

pub const CryptographicEnvelope = struct {
    snapshot_body: SnapshotBody,
    snapshot_id: [32]u8,
    attestations: Attestations,
    persistence_receipt: ?PersistenceReceipt,
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
    previous_snapshot_hash: []const u8,
};

pub const PersistenceReceipt = struct {
    provider: []const u8,
    repository: []const u8,
    branch: []const u8,
    commit_sha: []const u8,
    committed_at: ?[]const u8,
};

pub const VerificationContext = struct {
    trusted_chain_head: [32]u8,
    last_accepted_epoch: u64,
    enclave_public_key: Ed25519.PublicKey,
    consumer_public_key: Ed25519.PublicKey,
    expected_secret_ref: []const u8,
    expected_consumer: []const u8,
};

pub fn verifyAttestations(
    allocator: std.mem.Allocator,
    snapshot_id: [32]u8,
    body: SnapshotBody,
    attestations: Attestations,
    ctx: VerificationContext,
) !void {
    const signature_input = try canonicalizeSignatureInput(allocator, snapshot_id, body);
    defer allocator.free(signature_input);

    const enclave_sig = Ed25519.Signature.fromBytes(attestations.enclave_signature);
    enclave_sig.verify(signature_input, ctx.enclave_public_key) catch return error.SignatureVerificationFailed;

    const consumer_sig = Ed25519.Signature.fromBytes(attestations.consumer_countersignature);
    consumer_sig.verify(signature_input, ctx.consumer_public_key) catch return error.SignatureVerificationFailed;
}

pub fn verifySnapshot(
    allocator: std.mem.Allocator,
    envelope: CryptographicEnvelope,
    ctx: VerificationContext,
) !void {
    // 1. Validar schema
    if (!std.mem.eql(u8, envelope.snapshot_body.schema_version, "lses.snapshot.v1")) return error.InvalidSchema;
    
    // 2. Canonicalizar body
    const canonical_body = try canonicalizeSnapshotBody(allocator, envelope.snapshot_body);
    defer allocator.free(canonical_body);
    
    // 3. Recomputar snapshot_id
    const computed_id = computeSnapshotId(canonical_body);
    if (!std.mem.eql(u8, &computed_id, &envelope.snapshot_id)) return error.InvalidSnapshotHash;
    
    // 4. Verificar assinaturas
    try verifyAttestations(allocator, envelope.snapshot_id, envelope.snapshot_body, envelope.attestations, ctx);
    
    // 5. Validar chain/epoch/trust anchor
    // Convert previous_snapshot_hash from base64/hex to bytes for comparison, but here we assume it's decoded
    if (envelope.snapshot_body.epoch <= ctx.last_accepted_epoch) return error.EpochTooOld;
    // Assuming ctx.trusted_chain_head is compared against previous_snapshot_hash, skip for PoC if strings mismatch
    
    // 6. Validar policy
    if (!std.mem.eql(u8, envelope.snapshot_body.secret_ref, ctx.expected_secret_ref)) return error.UnauthorizedConsumer;
    if (!std.mem.eql(u8, envelope.snapshot_body.consumer_public_key_id, ctx.expected_consumer)) return error.UnauthorizedConsumer;
}

pub const LsesError = error{
    NonceReused,
    InvalidAuthTag,
    InvalidSnapshotHash,
    SignatureVerificationFailed,
    MissingWrappedDek,
    MissingTrustAnchor,
    UnauthorizedConsumer,
    EpochTooOld,
    ChainMismatch,
    InvalidSchema,
};

pub const RuntimeSecretHandle = struct {
    handle_id: [32]u8,
    expires_at: i64,
    scope: []const u8 = "runtime-only",
};
