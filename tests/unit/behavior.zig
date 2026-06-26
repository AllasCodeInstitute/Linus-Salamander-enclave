// tests/unit/behavior.zig — Unified LSES + OWASP LLM unit tests
// Build: zig test -Mbehavior=tests/unit/behavior.zig
//               --dep crypto -Mcrypto=zig/crypto.zig
const std   = @import("std");
const crypto = @import("crypto");
const testing = std.testing;

// ─── Group 1: CSPRNG ───────────────────────────────────────────────────────
test "CSPRNG - randomBytes entropy and fallback" {
    var buf1: [32]u8 = undefined;
    var buf2: [32]u8 = undefined;
    crypto.EnclaveCrypto.randomBytes(&buf1);
    crypto.EnclaveCrypto.randomBytes(&buf2);
    try testing.expect(!std.mem.eql(u8, &buf1, &buf2));
    try testing.expect(!std.mem.allEqual(u8, &buf1, 0));
}

// ─── Group 2: Snapshot Identity ────────────────────────────────────────────
test "Snapshot Identity - deterministic formatting and mutation invalidation" {
    var body = mockBody();
    const cb1 = try crypto.canonicalizeSnapshotBody(testing.allocator, body);
    defer testing.allocator.free(cb1);
    const h1 = crypto.computeSnapshotId(cb1);
    body.operation = "rotate_secret";
    const cb2 = try crypto.canonicalizeSnapshotBody(testing.allocator, body);
    defer testing.allocator.free(cb2);
    const h2 = crypto.computeSnapshotId(cb2);
    try testing.expect(!std.mem.eql(u8, &h1, &h2));
}

// ─── Group 3: Dual-Attestation ─────────────────────────────────────────────
test "Dual-Attestation - counter-signing with invalid key fails" {
    const body = mockBody();
    const cb = try crypto.canonicalizeSnapshotBody(testing.allocator, body);
    defer testing.allocator.free(cb);
    const sid = crypto.computeSnapshotId(cb);
    const si = try crypto.canonicalizeSignatureInput(testing.allocator, sid, body);
    defer testing.allocator.free(si);
    var e_seed: [32]u8 = undefined; crypto.EnclaveCrypto.randomBytes(&e_seed);
    var c_seed: [32]u8 = undefined; crypto.EnclaveCrypto.randomBytes(&c_seed);
    const ekp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(e_seed);
    const ckp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(c_seed);
    const esig = try crypto.signEd25519(si, ekp.secret_key.toBytes());
    const csig = try crypto.signEd25519(si, ckp.secret_key.toBytes());
    const env = crypto.SnapshotEnvelope{ .snapshot_body = body, .snapshot_id = sid,
        .attestations = .{ .enclave_signature = esig, .consumer_countersignature = csig },
        .persistence_receipt = null };
    const vk = crypto.VerificationKeys{ .enclave_key_id = "ek", .enclave_public_key = ekp.public_key.bytes,
        .consumer_key_id = "ck", .consumer_public_key = ckp.public_key.bytes };
    var reg = crypto.NonceRegistry.init(testing.allocator); defer reg.deinit();
    const allowed = try testing.allocator.alloc([]const u8, 1);
    allowed[0] = "ck"; defer testing.allocator.free(allowed);
    var ctx = crypto.VerificationContext{ .mode = .strict,
        .trusted_chain_head = body.previous_snapshot_hash, .last_accepted_epoch = 0,
        .verification_keys = vk, .policy = .{ .allow_plaintext_export = true, .allowed_consumers = allowed },
        .nonce_registry = &reg, .kek_resolver = undefined, .trusted_enclave_keys = null };
    try crypto.verifySnapshot(testing.allocator, env, &ctx);
    var tampered = env;
    tampered.attestations.consumer_countersignature[0] ^= 1;
    try testing.expectError(crypto.LsesError.InvalidConsumerCountersignature, crypto.verifySnapshot(testing.allocator, tampered, &ctx));
}

// ─── Group 4: Envelope Encryption ─────────────────────────────────────────
test "Envelope Encryption - KEK wrapping and WRONG KEK ID rejection" {
    var prov = try crypto.LocalDevKekProvider.initFromHex("test-kek-001",
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
    var pdek: [32]u8 = undefined; crypto.EnclaveCrypto.randomBytes(&pdek);
    const wrapped = try prov.provider().wrap(testing.allocator, &pdek, "test-kek-001");
    const unwrapped = try prov.provider().unwrap(testing.allocator, wrapped, "test-kek-001");
    try testing.expectEqualStrings(&pdek, &unwrapped);
    var bad = wrapped; bad.key_id = "wrong";
    try testing.expectError(crypto.LsesError.StaleKekId, prov.provider().unwrap(testing.allocator, bad, "test-kek-001"));
}

// ─── Group 5: AES-GCM Auth ─────────────────────────────────────────────────
test "Payload Auth - tampered ciphertext auth tag or AAD must fail" {
    var dek: [32]u8 = undefined; crypto.EnclaveCrypto.randomBytes(&dek);
    const pt = "sensitive-payload"; const nonce = [12]u8{1,2,3,4,5,6,7,8,9,10,11,12}; const aad = "aad-v1";
    const sealed = try crypto.sealPayload(testing.allocator, pt, &dek, nonce, aad);
    defer testing.allocator.free(sealed.ciphertext);
    const uns = try crypto.unsealPayload(testing.allocator, sealed.ciphertext, sealed.auth_tag, &dek, nonce, aad);
    defer testing.allocator.free(uns);
    try testing.expectEqualStrings(pt, uns);
    var bad_c = try testing.allocator.dupe(u8, sealed.ciphertext); defer testing.allocator.free(bad_c);
    bad_c[0] ^= 1;
    try testing.expectError(crypto.LsesError.InvalidAuthTag, crypto.unsealPayload(testing.allocator, bad_c, sealed.auth_tag, &dek, nonce, aad));
    var bad_t = sealed.auth_tag; bad_t[0] ^= 1;
    try testing.expectError(crypto.LsesError.InvalidAuthTag, crypto.unsealPayload(testing.allocator, sealed.ciphertext, bad_t, &dek, nonce, aad));
    try testing.expectError(crypto.LsesError.InvalidAuthTag, crypto.unsealPayload(testing.allocator, sealed.ciphertext, sealed.auth_tag, &dek, nonce, "bad-aad"));
}

// ─── Group 6: Nonce Replay ─────────────────────────────────────────────────
test "Chain Recovery - detect rollback / nonce replay attacks" {
    var reg = crypto.NonceRegistry.init(testing.allocator); defer reg.deinit();
    const nonce = @as([12]u8, @splat(1));
    const sid1 = @as([32]u8, @splat(0xaa)); const sid2 = @as([32]u8, @splat(0xbb));
    try reg.checkAndRecord(sid1, .payload, "ctx", nonce);
    try reg.checkAndRecord(sid1, .payload, "ctx", nonce); // idempotent
    try testing.expectError(crypto.LsesError.NonceReused, reg.checkAndRecord(sid2, .payload, "ctx", nonce));
    try reg.checkAndRecord(sid1, .payload, "other-ctx", nonce); // different context ok
}

// ─── Group 7: Runtime Secret Store ─────────────────────────────────────────
test "Read Behavior - short-lived runtime handles expiring cleanly" {
    var store = crypto.RuntimeSecretStore.init(testing.allocator); defer store.deinit();
    const pt = "volatile-secret-777";
    const h = try store.insert(pt, 2, 1000);
    const r1 = store.get(h.handle_id, 1000);
    try testing.expect(r1 != null); try testing.expectEqualStrings(pt, r1.?); testing.allocator.free(r1.?);
    try testing.expect(store.get(h.handle_id, 1000) == null); // consumed
    const h2 = try store.insert(pt, 2, 1000);
    try testing.expect(store.get(h2.handle_id, 1005) == null); // expired
}

// ─── Group 8: Rollback epoch ───────────────────────────────────────────────
test "Rollback epoch rejection" {
    var e_s: [32]u8 = undefined; crypto.EnclaveCrypto.randomBytes(&e_s);
    var c_s: [32]u8 = undefined; crypto.EnclaveCrypto.randomBytes(&c_s);
    const ekp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(e_s);
    const ckp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(c_s);
    const env = try signedEnvelope(testing.allocator, ekp, ckp, 1, @as([32]u8, @splat(0)));
    const vk = crypto.VerificationKeys{ .enclave_key_id = "ek", .enclave_public_key = ekp.public_key.bytes,
        .consumer_key_id = "ck", .consumer_public_key = ckp.public_key.bytes };
    var reg = crypto.NonceRegistry.init(testing.allocator); defer reg.deinit();
    var ctx = crypto.VerificationContext{ .mode = .recovery_limited, .trusted_chain_head = null,
        .last_accepted_epoch = 2, .verification_keys = vk,
        .policy = .{ .allow_plaintext_export = true, .allowed_consumers = &[_][]const u8{"ck"} },
        .nonce_registry = &reg, .kek_resolver = undefined, .trusted_enclave_keys = null };
    try testing.expectError(crypto.LsesError.RollbackDetected, crypto.verifySnapshot(testing.allocator, env, &ctx));
}

// ─── Group 9: Missing trust anchor ────────────────────────────────────────
test "Strict mode trust anchor enforcement" {
    var e_s: [32]u8 = undefined; crypto.EnclaveCrypto.randomBytes(&e_s);
    var c_s: [32]u8 = undefined; crypto.EnclaveCrypto.randomBytes(&c_s);
    const ekp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(e_s);
    const ckp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(c_s);
    const env = try signedEnvelope(testing.allocator, ekp, ckp, 1, @as([32]u8, @splat(0)));
    const vk = crypto.VerificationKeys{ .enclave_key_id = "ek", .enclave_public_key = ekp.public_key.bytes,
        .consumer_key_id = "ck", .consumer_public_key = ckp.public_key.bytes };
    var reg = crypto.NonceRegistry.init(testing.allocator); defer reg.deinit();
    var ctx = crypto.VerificationContext{ .mode = .strict, .trusted_chain_head = null, .last_accepted_epoch = 0,
        .verification_keys = vk, .policy = .{ .allow_plaintext_export = true, .allowed_consumers = &[_][]const u8{"ck"} },
        .nonce_registry = &reg, .kek_resolver = undefined, .trusted_enclave_keys = null };
    try testing.expectError(crypto.LsesError.MissingTrustAnchor, crypto.verifySnapshot(testing.allocator, env, &ctx));
}

// ─── Group 10: Context separation ─────────────────────────────────────────
test "Context separation integrity" {
    var reg = crypto.NonceRegistry.init(testing.allocator); defer reg.deinit();
    const nonce = @as([12]u8, @splat(7)); const sid = @as([32]u8, @splat(0xcc));
    try reg.checkAndRecord(sid, .payload, "ctx", nonce);
    try reg.checkAndRecord(sid, .dek_wrap, "ctx", nonce); // different domain = ok
}

// ─── Group 11: SecretRef uniqueness ───────────────────────────────────────
test "SecretRef derivation uniqueness" {
    const r1 = crypto.computeSecretRef("proj", "prod", "secretA");
    const r2 = crypto.computeSecretRef("proj", "prod", "secretB");
    const r3 = crypto.computeSecretRef("proj", "dev",  "secretA");
    try testing.expect(!std.mem.eql(u8, &r1, &r2));
    try testing.expect(!std.mem.eql(u8, &r1, &r3));
    try testing.expectEqualSlices(u8, &r1, &crypto.computeSecretRef("proj", "prod", "secretA"));
}

// ─── Helpers ───────────────────────────────────────────────────────────────
fn mockBody() crypto.SnapshotBody {
    return .{
        .schema_version = "lses.snapshot.v1", .project_id = "p", .environment = "e",
        .operation = "write_secret",
        .secret_ref = [32]u8{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32},
        .epoch = 1, .previous_snapshot_hash = @as([32]u8, @splat(0)),
        .created_at = "2026-06-01T00:00:00Z",
        .algorithm = .{ .content_encryption = "AES-256-GCM", .key_wrapping = "AES-256-GCM",
            .enclave_signature = "Ed25519", .consumer_signature = "Ed25519" },
        .aad = .{ .project = "p", .environment = "e", .snapshot_type = "secret",
            .operation = "write_secret", .epoch = 1, .previous_snapshot_hash = @as([32]u8, @splat(0)) },
        .nonce = [12]u8{1,2,3,4,5,6,7,8,9,10,11,12},
        .sealed_payload = "aabbccdd", .auth_tag = @as([16]u8, @splat(1)),
        .wrapped_dek = "aabbccdd", .wrap_nonce = [12]u8{1,2,3,4,5,6,7,8,9,10,11,12},
        .wrap_auth_tag = @as([16]u8, @splat(1)), .dek_wrapping_key_id = "k",
        .enclave_public_key_id = "ek", .consumer_public_key_id = "ck",
    };
}

fn signedEnvelope(
    alloc: std.mem.Allocator,
    ekp: std.crypto.sign.Ed25519.KeyPair,
    ckp: std.crypto.sign.Ed25519.KeyPair,
    epoch: u64,
    prev: [32]u8,
) !crypto.SnapshotEnvelope {
    var body = mockBody(); body.epoch = epoch; body.previous_snapshot_hash = prev;
    body.aad.epoch = epoch; body.aad.previous_snapshot_hash = prev;
    const cb = try crypto.canonicalizeSnapshotBody(alloc, body); defer alloc.free(cb);
    const sid = crypto.computeSnapshotId(cb);
    const si = try crypto.canonicalizeSignatureInput(alloc, sid, body); defer alloc.free(si);
    return .{ .snapshot_body = body, .snapshot_id = sid, .persistence_receipt = null,
        .attestations = .{
            .enclave_signature = try crypto.signEd25519(si, ekp.secret_key.toBytes()),
            .consumer_countersignature = try crypto.signEd25519(si, ckp.secret_key.toBytes()),
        }};
}
