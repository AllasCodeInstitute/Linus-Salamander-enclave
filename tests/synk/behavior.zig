// tests/synk/behavior.zig — LSES synchronization / state-isolation tests
// Focus: invariants that matter under concurrent access (state independence,
//        no shared mutable globals, deterministic derivation, nonce uniqueness)
const std     = @import("std");
const crypto  = @import("crypto");
const testing = std.testing;

fn mockBody(epoch: u64, prev: [32]u8) crypto.SnapshotBody {
    return .{
        .schema_version = "lses.snapshot.v1", .project_id = "test-project",
        .environment = "test-env", .operation = "write_secret",
        .secret_ref = [32]u8{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32},
        .epoch = epoch, .previous_snapshot_hash = prev,
        .created_at = "2026-05-18T00:00:00Z",
        .algorithm = .{ .content_encryption = "AES-256-GCM", .key_wrapping = "AES-256-GCM",
            .enclave_signature = "Ed25519", .consumer_signature = "Ed25519" },
        .aad = .{ .project = "test-project", .environment = "test-env", .snapshot_type = "secret",
            .operation = "write_secret", .epoch = epoch, .previous_snapshot_hash = prev },
        .nonce = [12]u8{1,2,3,4,5,6,7,8,9,10,11,12},
        .sealed_payload = "aabbccddeeff", .auth_tag = @as([16]u8, @splat(1)),
        .wrapped_dek = "aabbccddeeff", .wrap_nonce = [12]u8{1,2,3,4,5,6,7,8,9,10,11,12},
        .wrap_auth_tag = @as([16]u8, @splat(1)), .dek_wrapping_key_id = "test-kek-id-001",
        .enclave_public_key_id = "enc-pk-id", .consumer_public_key_id = "cons-pk-id",
    };
}

fn signedEnvelope(
    alloc: std.mem.Allocator,
    ekp: std.crypto.sign.Ed25519.KeyPair, ckp: std.crypto.sign.Ed25519.KeyPair,
    epoch: u64, prev: [32]u8,
) !crypto.SnapshotEnvelope {
    var body = mockBody(epoch, prev);
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

// ── SYNK 1: NonceRegistry state isolation ────────────────────────────────────
// Two independent registries must NOT share nonce state — each is self-contained.
// If they shared state: reg2.checkAndRecord(sid2, nonce) would fail because reg1
// already has (nonce, ctx) → sid1, and sid2 ≠ sid1 → NonceReused.
test "Synk: two NonceRegistry instances share no state" {
    var reg1 = crypto.NonceRegistry.init(testing.allocator); defer reg1.deinit();
    var reg2 = crypto.NonceRegistry.init(testing.allocator); defer reg2.deinit();
    const nonce = @as([12]u8, @splat(0xAB));
    const sid1  = @as([32]u8, @splat(1));
    const sid2  = @as([32]u8, @splat(2));
    try reg1.checkAndRecord(sid1, .payload, "ctx", nonce); // reg1 now knows (nonce,ctx)→sid1
    // Isolation proof: reg2 has no knowledge of reg1's entries, so sid2 succeeds:
    try reg2.checkAndRecord(sid2, .payload, "ctx", nonce);
    // Each registry correctly enforces its OWN state:
    try testing.expectError(crypto.LsesError.NonceReused,
        reg1.checkAndRecord(sid2, .payload, "ctx", nonce)); // reg1 had sid1, rejects sid2
    try testing.expectError(crypto.LsesError.NonceReused,
        reg2.checkAndRecord(sid1, .payload, "ctx", nonce)); // reg2 had sid2, rejects sid1
}

// ── SYNK 2: RuntimeSecretStore handle isolation ───────────────────────────────
// Two handles inside the same store pointing to DIFFERENT secrets must be fully
// isolated: reading handle A must not affect or expose handle B's data.
test "Synk: RuntimeSecretStore - handles are isolated from each other" {
    var store = crypto.RuntimeSecretStore.init(testing.allocator); defer store.deinit();
    const h1 = try store.insert("secret-A", 5, 1000);
    const h2 = try store.insert("secret-B", 5, 1000);
    // Read handle 1 — must return "secret-A", not "secret-B"
    const r1 = store.get(h1.handle_id, 500);
    try testing.expect(r1 != null);
    try testing.expectEqualStrings("secret-A", r1.?);
    testing.allocator.free(r1.?);
    // Read handle 2 — must return "secret-B", unaffected by prior read
    const r2 = store.get(h2.handle_id, 500);
    try testing.expect(r2 != null);
    try testing.expectEqualStrings("secret-B", r2.?);
    testing.allocator.free(r2.?);
    // Handles never cross-contaminate
    try testing.expect(!std.mem.eql(u8, &h1.handle_id, &h2.handle_id));
}

// ── SYNK 3: CSPRNG sequential uniqueness ─────────────────────────────────────
// 10 consecutive CSPRNG fills must all be pairwise-distinct (no PRNG reset or
// shared seed across calls — critical for nonce generation safety).
test "Synk: CSPRNG - 10 sequential samples are pairwise unique" {
    var bufs: [10][32]u8 = undefined;
    for (&bufs) |*b| crypto.EnclaveCrypto.randomBytes(b);
    var i: usize = 0;
    while (i < bufs.len) : (i += 1) {
        var j: usize = i + 1;
        while (j < bufs.len) : (j += 1) {
            try testing.expect(!std.mem.eql(u8, &bufs[i], &bufs[j]));
        }
    }
}

// ── SYNK 4: SecretRef determinism and cross-project isolation ─────────────────
// computeSecretRef must be purely functional — same inputs always produce the
// same output, and different project/env combinations produce distinct refs.
test "Synk: SecretRef - deterministic derivation and cross-project isolation" {
    const r_a1 = crypto.computeSecretRef("proj-A", "prod", "db-pass");
    const r_a2 = crypto.computeSecretRef("proj-A", "prod", "db-pass"); // same → must match
    const r_b  = crypto.computeSecretRef("proj-B", "prod", "db-pass"); // different proj
    const r_a_dev = crypto.computeSecretRef("proj-A", "dev",  "db-pass"); // different env
    const r_a_key = crypto.computeSecretRef("proj-A", "prod", "api-key"); // different key
    try testing.expectEqualSlices(u8, &r_a1, &r_a2);
    try testing.expect(!std.mem.eql(u8, &r_a1, &r_b));
    try testing.expect(!std.mem.eql(u8, &r_a1, &r_a_dev));
    try testing.expect(!std.mem.eql(u8, &r_a1, &r_a_key));
}

// ── SYNK 5: Chain fork detection ─────────────────────────────────────────────
// recoverLatest must detect when envelope[1].previous_snapshot_hash doesn't match
// the computed ID of envelope[0], i.e., a forked chain.
test "Synk: recoverLatest - chain fork/gap detected as ChainMismatch" {
    var es: [32]u8 = undefined; crypto.EnclaveCrypto.randomBytes(&es);
    var cs: [32]u8 = undefined; crypto.EnclaveCrypto.randomBytes(&cs);
    const ekp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(es);
    const ckp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(cs);
    const env1 = try signedEnvelope(testing.allocator, ekp, ckp, 1, @as([32]u8, @splat(0)));
    // Envelope 2 points to a WRONG previous hash (9s instead of env1's ID)
    const env2 = try signedEnvelope(testing.allocator, ekp, ckp, 2, @as([32]u8, @splat(9)));
    const envelopes = [_]crypto.SnapshotEnvelope{ env1, env2 };
    const vk = crypto.VerificationKeys{ .enclave_key_id = "enc-pk-id",
        .enclave_public_key = ekp.public_key.bytes, .consumer_key_id = "cons-pk-id",
        .consumer_public_key = ckp.public_key.bytes };
    var store = crypto.RuntimeSecretStore.init(testing.allocator); defer store.deinit();
    var reg = crypto.NonceRegistry.init(testing.allocator); defer reg.deinit();
    var ctx = crypto.VerificationContext{ .mode = .recovery_limited, .trusted_chain_head = null,
        .last_accepted_epoch = 0, .verification_keys = vk,
        .policy = .{ .allow_plaintext_export = true, .allowed_consumers = &[_][]const u8{"cons-pk-id"} },
        .nonce_registry = &reg, .kek_resolver = undefined, .trusted_enclave_keys = null };
    try testing.expectError(crypto.LsesError.ChainMismatch,
        crypto.recoverLatest(testing.allocator, &envelopes, &ctx, &store, 1000));
}

// ── SYNK 6: Idempotent re-verification via shared NonceRegistry ───────────────
// Verifying the SAME envelope twice with a shared NonceRegistry must succeed
// (the registry's idempotent path: same snapshot_id + same nonce = ok).
// This proves the registry doesn't corrupt its own state on repeat calls.
test "Synk: shared NonceRegistry is idempotent for repeated same-envelope verification" {
    var es: [32]u8 = undefined; crypto.EnclaveCrypto.randomBytes(&es);
    var cs: [32]u8 = undefined; crypto.EnclaveCrypto.randomBytes(&cs);
    const ekp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(es);
    const ckp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(cs);
    // Key IDs must match mockBody's public key ID fields ("enc-pk-id", "cons-pk-id")
    const vk = crypto.VerificationKeys{
        .enclave_key_id = "enc-pk-id", .enclave_public_key = ekp.public_key.bytes,
        .consumer_key_id = "cons-pk-id", .consumer_public_key = ckp.public_key.bytes,
    };
    var reg = crypto.NonceRegistry.init(testing.allocator); defer reg.deinit();
    const env = try signedEnvelope(testing.allocator, ekp, ckp, 1, @as([32]u8, @splat(0)));
    const allowed = &[_][]const u8{"cons-pk-id"};
    // First verification
    var ctx1 = crypto.VerificationContext{ .mode = .recovery_limited, .trusted_chain_head = null,
        .last_accepted_epoch = 0, .verification_keys = vk,
        .policy = .{ .allow_plaintext_export = true, .allowed_consumers = allowed },
        .nonce_registry = &reg, .kek_resolver = undefined, .trusted_enclave_keys = null };
    try crypto.verifySnapshot(testing.allocator, env, &ctx1);
    // Second verification of SAME envelope — must succeed (idempotent nonce path)
    var ctx2 = crypto.VerificationContext{ .mode = .recovery_limited, .trusted_chain_head = null,
        .last_accepted_epoch = 0, .verification_keys = vk,
        .policy = .{ .allow_plaintext_export = true, .allowed_consumers = allowed },
        .nonce_registry = &reg, .kek_resolver = undefined, .trusted_enclave_keys = null };
    try crypto.verifySnapshot(testing.allocator, env, &ctx2);
}
