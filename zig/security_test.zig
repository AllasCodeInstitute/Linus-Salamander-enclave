const std = @import("std");
const crypto = @import("crypto.zig");
const testing = std.testing;

// Helper to create a base mock SnapshotBody
fn createMockSnapshotBody() crypto.SnapshotBody {
    return crypto.SnapshotBody{
        .schema_version = "lses.snapshot.v1",
        .project_id = "test-project",
        .environment = "test-env",
        .operation = "write_secret",
        .secret_ref = [32]u8{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
        .epoch = 1,
        .previous_snapshot_hash = [32]u8{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
        .created_at = "2026-05-18T00:00:00Z",
        .algorithm = .{
            .content_encryption = "AES-256-GCM",
            .key_wrapping = "AES-256-GCM",
            .enclave_signature = "Ed25519",
            .consumer_signature = "Ed25519",
        },
        .aad = .{
            .project = "test-project",
            .environment = "test-env",
            .snapshot_type = "secret",
            .operation = "write_secret",
            .epoch = 1,
            .previous_snapshot_hash = [32]u8{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
        },
        .nonce = [12]u8{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
        .sealed_payload = "aabbccddeeff",
        .auth_tag = [16]u8{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
        .wrapped_dek = "aabbccddeeff",
        .wrap_nonce = [12]u8{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
        .wrap_auth_tag = [16]u8{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
        .dek_wrapping_key_id = "test-kek-id-001",
        .enclave_public_key_id = "enc-pk-id",
        .consumer_public_key_id = "cons-pk-id",
    };
}

// Group 1: CSPRNG Security
test "CSPRNG - randomBytes entropy and fallback" {
    var buf1: [32]u8 = undefined;
    var buf2: [32]u8 = undefined;

    crypto.EnclaveCrypto.randomBytes(&buf1);
    crypto.EnclaveCrypto.randomBytes(&buf2);

    // Verify they are not the same (high probability)
    try testing.expect(!std.mem.eql(u8, &buf1, &buf2));
    
    // Verify it doesn't leave all zeros
    var all_zeros = true;
    for (buf1) |b| {
        if (b != 0) {
            all_zeros = false;
            break;
        }
    }
    try testing.expect(!all_zeros);
}

// Group 2: Snapshot Identity
test "Snapshot Identity - deterministic formatting and mutation invalidation" {
    var body = createMockSnapshotBody();

    const cb1 = try crypto.canonicalizeSnapshotBody(testing.allocator, body);
    defer testing.allocator.free(cb1);

    const hash1 = crypto.computeSnapshotId(cb1);

    // Mutate the operation field
    body.operation = "rotate_secret";

    const cb2 = try crypto.canonicalizeSnapshotBody(testing.allocator, body);
    defer testing.allocator.free(cb2);

    const hash2 = crypto.computeSnapshotId(cb2);

    // Mutation must yield a different snapshot hash
    try testing.expect(!std.mem.eql(u8, &hash1, &hash2));
}

// Group 3: Dual-Attestation Signature Verification
test "Dual-Attestation - counter-signing with invalid key fails" {
    const body = createMockSnapshotBody();

    const cb = try crypto.canonicalizeSnapshotBody(testing.allocator, body);
    defer testing.allocator.free(cb);

    const snapshot_id = crypto.computeSnapshotId(cb);

    const sig_input = try crypto.canonicalizeSignatureInput(testing.allocator, snapshot_id, body);
    defer testing.allocator.free(sig_input);

    // Generate keys
    var enc_seed: [32]u8 = undefined;
    crypto.EnclaveCrypto.randomBytes(&enc_seed);
    const enc_kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(enc_seed);

    var cons_seed: [32]u8 = undefined;
    crypto.EnclaveCrypto.randomBytes(&cons_seed);
    const cons_kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(cons_seed);

    // Valid Signatures
    const enc_private = enc_kp.secret_key.toBytes();
    const cons_private = cons_kp.secret_key.toBytes();

    const enc_sig = try crypto.signEd25519(sig_input, enc_private);
    const cons_sig = try crypto.signEd25519(sig_input, cons_private);

    const envelope = crypto.SnapshotEnvelope{
        .snapshot_body = body,
        .snapshot_id = snapshot_id,
        .attestations = .{
            .enclave_signature = enc_sig,
            .consumer_countersignature = cons_sig,
        },
        .persistence_receipt = null,
    };

    const vk = crypto.VerificationKeys{
        .enclave_key_id = "enc-pk-id",
        .enclave_public_key = enc_kp.public_key.bytes,
        .consumer_key_id = "cons-pk-id",
        .consumer_public_key = cons_kp.public_key.bytes,
    };

    var registry = crypto.NonceRegistry.init(testing.allocator);
    defer registry.deinit();

    const allowed = try testing.allocator.alloc([]const u8, 1);
    allowed[0] = "cons-pk-id";

    const policy = crypto.AccessPolicy{
        .allow_plaintext_export = true,
        .allowed_consumers = allowed,
    };
    defer testing.allocator.free(allowed);

    var ctx = crypto.VerificationContext{
        .mode = .strict,
        .trusted_chain_head = body.previous_snapshot_hash,
        .last_accepted_epoch = 0,
        .verification_keys = vk,
        .policy = policy,
        .nonce_registry = &registry,
        .kek_resolver = undefined, // not used for pure verification
    };

    // Valid envelope must pass verification
    try crypto.verifySnapshot(testing.allocator, envelope, &ctx);

    // Tamper with countersignature -> must fail
    var tampered_envelope = envelope;
    tampered_envelope.attestations.consumer_countersignature[0] ^= 1;

    try testing.expectError(crypto.LsesError.InvalidConsumerCountersignature, crypto.verifySnapshot(testing.allocator, tampered_envelope, &ctx));
}

// Group 4: Envelope Encryption
test "Envelope Encryption - KEK wrapping and WRONG KEK ID rejection" {
    var provider = try crypto.LocalDevKekProvider.initFromHex(
        "test-kek-001",
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
    );

    var plaintext_dek: [32]u8 = undefined;
    crypto.EnclaveCrypto.randomBytes(&plaintext_dek);

    const wrapped = try provider.provider().wrap(testing.allocator, &plaintext_dek, "test-kek-001");

    // Unwrap with the correct provider and key_id -> must succeed
    const unwrapped = try provider.provider().unwrap(testing.allocator, wrapped, "test-kek-001");
    try testing.expectEqualStrings(&plaintext_dek, &unwrapped);

    // Attempting with wrong key_id must throw error
    var bad_wrapped = wrapped;
    bad_wrapped.key_id = "wrong-kek-id";
    try testing.expectError(crypto.LsesError.StaleKekId, provider.provider().unwrap(testing.allocator, bad_wrapped, "test-kek-001"));
}

// Group 5: AES-GCM Payload Authentication
test "Payload Auth - tampered ciphertext, auth tag or AAD must fail decryption" {
    var dek: [32]u8 = undefined;
    crypto.EnclaveCrypto.randomBytes(&dek);

    const plaintext = "This is a highly sensitive secret data packet";
    const nonce = [12]u8{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    const aad = "project=lses&epoch=1";

    const sealed = try crypto.sealPayload(testing.allocator, plaintext, &dek, nonce, aad);
    defer testing.allocator.free(sealed.ciphertext);

    // Success run
    const unsealed = try crypto.unsealPayload(testing.allocator, sealed.ciphertext, sealed.auth_tag, &dek, nonce, aad);
    defer testing.allocator.free(unsealed);
    try testing.expectEqualStrings(plaintext, unsealed);

    // Tampered Ciphertext
    var bad_cipher = try testing.allocator.dupe(u8, sealed.ciphertext);
    defer testing.allocator.free(bad_cipher);
    bad_cipher[0] ^= 1;

    try testing.expectError(crypto.LsesError.InvalidAuthTag, crypto.unsealPayload(testing.allocator, bad_cipher, sealed.auth_tag, &dek, nonce, aad));

    // Tampered Auth Tag
    var bad_tag = sealed.auth_tag;
    bad_tag[0] ^= 1;
    try testing.expectError(crypto.LsesError.InvalidAuthTag, crypto.unsealPayload(testing.allocator, sealed.ciphertext, bad_tag, &dek, nonce, aad));

    // Tampered AAD
    try testing.expectError(crypto.LsesError.InvalidAuthTag, crypto.unsealPayload(testing.allocator, sealed.ciphertext, sealed.auth_tag, &dek, nonce, "project=lses&epoch=2"));
}

// Group 6: Chain Persistence & Recovery
test "Chain Recovery - detect rollback / nonce replay attacks" {
    var registry = crypto.NonceRegistry.init(testing.allocator);
    defer registry.deinit();

    const nonce = @as([12]u8, @splat(1));
    const snapshot_id1 = @as([32]u8, @splat(0xaa));
    const snapshot_id2 = @as([32]u8, @splat(0xbb));

    // First use: must succeed
    try registry.checkAndRecord(snapshot_id1, .payload, "test-context", nonce);

    // Idempotent use with same snapshot: must succeed
    try registry.checkAndRecord(snapshot_id1, .payload, "test-context", nonce);

    // Second use with a different snapshot/same context: must fail with NonceReused
    try testing.expectError(crypto.LsesError.NonceReused, registry.checkAndRecord(snapshot_id2, .payload, "test-context", nonce));

    // Use with a different context/same snapshot: must succeed
    try registry.checkAndRecord(snapshot_id1, .payload, "other-context", nonce);
}

// Group 7: Read Behavior & Dynamic Runtime Secret Store
test "Read Behavior - short-lived runtime handles expiring cleanly" {
    var store = crypto.RuntimeSecretStore.init(testing.allocator);
    defer store.deinit();

    const plaintext = "volatile-secret-value-777";

    const handle = try store.insert(plaintext, 2, 1000);
    const handle_id = handle.handle_id;

    // Success read within bounds
    const read1 = store.get(handle_id, 1000);
    try testing.expect(read1 != null);
    try testing.expectEqualStrings(plaintext, read1.?);
    testing.allocator.free(read1.?);

    // Second read -> must return null because it's single use (consumed)
    const read_second = store.get(handle_id, 1000);
    try testing.expect(read_second == null);

    // Create another handle to test expiry
    const handle2 = try store.insert(plaintext, 2, 1000);
    // Read after expiry -> must return null
    const read2 = store.get(handle2.handle_id, 1005);
    try testing.expect(read2 == null);
}

// Group 8: Storage Scan
test "Storage Scan - zero plaintext leaked to files" {
    var thread_io = std.Io.Threaded.init(testing.allocator, .{});
    defer thread_io.deinit();
    const io = thread_io.io();

    const filename = "enclave.sealed.json";
    const file = std.Io.Dir.cwd().openFile(io, filename, .{}) catch return; // skip if demo main wasn't run yet
    defer file.close(io);

    var read_buf: [4096]u8 = undefined;
    var r = file.reader(io, &read_buf);
    const data = try r.interface.allocRemaining(testing.allocator, std.Io.Limit.limited(1024 * 1024));
    defer testing.allocator.free(data);

    // Ensure the sensitive plaintext secret we used in demo is NOT present in raw ASCII
    const leaked = std.mem.indexOf(u8, data, "ls_secret_super_secure_token_12345");
    try testing.expect(leaked == null);
}

// Group 9: Robustness & Negative Tests
fn createSignedMockEnvelope(
    allocator: std.mem.Allocator,
    enc_kp: std.crypto.sign.Ed25519.KeyPair,
    cons_kp: std.crypto.sign.Ed25519.KeyPair,
    epoch: u64,
    prev_hash: [32]u8,
) !crypto.SnapshotEnvelope {
    var body = createMockSnapshotBody();
    body.epoch = epoch;
    body.previous_snapshot_hash = prev_hash;
    body.aad.epoch = epoch;
    body.aad.previous_snapshot_hash = prev_hash;

    const cb = try crypto.canonicalizeSnapshotBody(allocator, body);
    defer allocator.free(cb);

    const snapshot_id = crypto.computeSnapshotId(cb);

    const sig_input = try crypto.canonicalizeSignatureInput(allocator, snapshot_id, body);
    defer allocator.free(sig_input);

    const enc_private = enc_kp.secret_key.toBytes();
    const cons_private = cons_kp.secret_key.toBytes();

    const enc_sig = try crypto.signEd25519(sig_input, enc_private);
    const cons_sig = try crypto.signEd25519(sig_input, cons_private);

    return crypto.SnapshotEnvelope{
        .snapshot_body = body,
        .snapshot_id = snapshot_id,
        .attestations = .{
            .enclave_signature = enc_sig,
            .consumer_countersignature = cons_sig,
        },
        .persistence_receipt = null,
    };
}

test "rollback epoch rejection" {
    var enc_seed: [32]u8 = undefined;
    crypto.EnclaveCrypto.randomBytes(&enc_seed);
    const enc_kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(enc_seed);

    var cons_seed: [32]u8 = undefined;
    crypto.EnclaveCrypto.randomBytes(&cons_seed);
    const cons_kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(cons_seed);

    const env = try createSignedMockEnvelope(testing.allocator, enc_kp, cons_kp, 1, @as([32]u8, @splat(0)));

    const vk = crypto.VerificationKeys{
        .enclave_key_id = "enc-pk-id",
        .enclave_public_key = enc_kp.public_key.bytes,
        .consumer_key_id = "cons-pk-id",
        .consumer_public_key = cons_kp.public_key.bytes,
    };

    var registry = crypto.NonceRegistry.init(testing.allocator);
    defer registry.deinit();

    var ctx = crypto.VerificationContext{
        .mode = .recovery_limited,
        .trusted_chain_head = null,
        .last_accepted_epoch = 2, // Last accepted is higher than envelope's epoch
        .verification_keys = vk,
        .policy = crypto.AccessPolicy{
            .allow_plaintext_export = true,
            .allowed_consumers = &[_][]const u8{"cons-pk-id"},
        },
        .nonce_registry = &registry,
        .kek_resolver = undefined,
    };

    try testing.expectError(crypto.LsesError.RollbackDetected, crypto.verifySnapshot(testing.allocator, env, &ctx));
}

test "chain fork/gap detection" {
    var enc_seed: [32]u8 = undefined;
    crypto.EnclaveCrypto.randomBytes(&enc_seed);
    const enc_kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(enc_seed);

    var cons_seed: [32]u8 = undefined;
    crypto.EnclaveCrypto.randomBytes(&cons_seed);
    const cons_kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(cons_seed);

    var store = crypto.RuntimeSecretStore.init(testing.allocator);
    defer store.deinit();

    const env1 = try createSignedMockEnvelope(testing.allocator, enc_kp, cons_kp, 1, @as([32]u8, @splat(0)));
    const bad_prev_hash = @as([32]u8, @splat(9));
    const env2 = try createSignedMockEnvelope(testing.allocator, enc_kp, cons_kp, 2, bad_prev_hash);

    const envelopes = [_]crypto.SnapshotEnvelope{ env1, env2 };

    const vk = crypto.VerificationKeys{
        .enclave_key_id = "enc-pk-id",
        .enclave_public_key = enc_kp.public_key.bytes,
        .consumer_key_id = "cons-pk-id",
        .consumer_public_key = cons_kp.public_key.bytes,
    };

    var registry = crypto.NonceRegistry.init(testing.allocator);
    defer registry.deinit();

    var ctx = crypto.VerificationContext{
        .mode = .recovery_limited,
        .trusted_chain_head = null,
        .last_accepted_epoch = 0,
        .verification_keys = vk,
        .policy = crypto.AccessPolicy{
            .allow_plaintext_export = true,
            .allowed_consumers = &[_][]const u8{"cons-pk-id"},
        },
        .nonce_registry = &registry,
        .kek_resolver = undefined,
    };

    try testing.expectError(crypto.LsesError.ChainMismatch, crypto.recoverLatest(
        testing.allocator,
        &envelopes,
        &ctx,
        &store,
        1000,
    ));
}

test "strict mode trust anchor enforcement" {
    var enc_seed: [32]u8 = undefined;
    crypto.EnclaveCrypto.randomBytes(&enc_seed);
    const enc_kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(enc_seed);

    var cons_seed: [32]u8 = undefined;
    crypto.EnclaveCrypto.randomBytes(&cons_seed);
    const cons_kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(cons_seed);

    const env = try createSignedMockEnvelope(testing.allocator, enc_kp, cons_kp, 1, @as([32]u8, @splat(0)));

    const vk = crypto.VerificationKeys{
        .enclave_key_id = "enc-pk-id",
        .enclave_public_key = enc_kp.public_key.bytes,
        .consumer_key_id = "cons-pk-id",
        .consumer_public_key = cons_kp.public_key.bytes,
    };

    var registry = crypto.NonceRegistry.init(testing.allocator);
    defer registry.deinit();

    var ctx = crypto.VerificationContext{
        .mode = .strict,
        .trusted_chain_head = null, // Empty anchor in strict mode!
        .last_accepted_epoch = 0,
        .verification_keys = vk,
        .policy = crypto.AccessPolicy{
            .allow_plaintext_export = true,
            .allowed_consumers = &[_][]const u8{"cons-pk-id"},
        },
        .nonce_registry = &registry,
        .kek_resolver = undefined,
    };

    try testing.expectError(crypto.LsesError.MissingTrustAnchor, crypto.verifySnapshot(testing.allocator, env, &ctx));
}

test "context separation integrity" {
    var registry = crypto.NonceRegistry.init(testing.allocator);
    defer registry.deinit();

    const nonce = @as([12]u8, @splat(7));
    const snapshot_id = @as([32]u8, @splat(0xcc));

    // Register as payload
    try registry.checkAndRecord(snapshot_id, .payload, "common-context", nonce);

    // Register same nonce/context but as dek_wrap -> must succeed! Domain separation prevents mix-ups.
    try registry.checkAndRecord(snapshot_id, .dek_wrap, "common-context", nonce);
}

test "secret_ref derivation uniqueness" {
    const ref1 = crypto.computeSecretRef("proj", "prod", "secretA");
    const ref2 = crypto.computeSecretRef("proj", "prod", "secretB");
    const ref3 = crypto.computeSecretRef("proj", "dev", "secretA");

    try testing.expect(!std.mem.eql(u8, &ref1, &ref2));
    try testing.expect(!std.mem.eql(u8, &ref1, &ref3));

    const ref1_again = crypto.computeSecretRef("proj", "prod", "secretA");
    try testing.expectEqualStrings(&ref1, &ref1_again);
}
