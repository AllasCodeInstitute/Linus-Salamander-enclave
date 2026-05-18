const std = @import("std");
const crypto = std.crypto;
const Ed25519 = crypto.sign.Ed25519;
const X25519 = crypto.dh.X25519;
const Aes256Gcm = crypto.aead.aes_gcm.Aes256Gcm;

/// Linus Salamander Enclave Crypto Module
/// Implements Signal-inspired authenticated encryption with dual-signing.
pub const EnclaveCrypto = struct {
    service_keypair: Ed25519.KeyPair,
    
    pub fn init() !EnclaveCrypto {
        // In a real enclave, this would be derived from hardware-sealed seeds.
        return .{
            .service_keypair = try Ed25519.KeyPair.create(null),
        };
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
        crypto.random.bytes(&dek);

        // 2. Encrypt payload with DEK
        var nonce: [Aes256Gcm.nonce_length]u8 = undefined;
        crypto.random.bytes(&nonce);
        
        const ciphertext = try allocator.alloc(u8, data.len);
        var tag: [Aes256Gcm.tag_length]u8 = undefined;
        Aes256Gcm.encrypt(ciphertext, &tag, data, aad, nonce, dek);

        // 3. Wrap DEK with KEK (Simulated KEK for PoC)
        var kek: [Aes256Gcm.key_length]u8 = undefined;
        crypto.random.bytes(&kek); // In reality, this comes from Enclave KMS/TPM
        var wrap_nonce: [Aes256Gcm.nonce_length]u8 = undefined;
        crypto.random.bytes(&wrap_nonce);
        var wrapped_dek = try allocator.alloc(u8, dek.len);
        var dek_tag: [Aes256Gcm.tag_length]u8 = undefined;
        Aes256Gcm.encrypt(wrapped_dek, &dek_tag, &dek, "", wrap_nonce, kek);

        // 4. Purge plaintext DEK
        @memset(&dek, 0);

        return SealedResult{
            .nonce = nonce,
            .sealed_payload = ciphertext,
            .auth_tag = tag,
            .wrapped_dek = wrapped_dek,
        };
    }

    /// Signs the canonical envelope body
    pub fn signEnvelope(
        self: *EnclaveCrypto,
        allocator: std.mem.Allocator,
        signature_input: []const u8,
    ) ![]const u8 {
        const service_sig = try self.service_keypair.sign(signature_input, null);
        var sig_bytes = try allocator.alloc(u8, service_sig.toBytes().len);
        @memcpy(sig_bytes, &service_sig.toBytes());
        return sig_bytes;
    }
};

pub const SealedResult = struct {
    nonce: [12]u8,
    sealed_payload: []const u8,
    auth_tag: [16]u8,
    wrapped_dek: []const u8,
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
    nonce: []const u8,
    sealed_payload: []const u8,
    auth_tag: []const u8,
    wrapped_dek: []const u8,
    dek_wrapping_key_id: []const u8,
    enclave_public_key_id: []const u8,
    consumer_public_key_id: []const u8,
};

pub const Attestations = struct {
    enclave_signature: []const u8,
    consumer_countersignature: []const u8,
};

pub const CryptographicEnvelope = struct {
    snapshot_body: SnapshotBody,
    snapshot_id: []const u8,
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
    committed_at: []const u8,
};
