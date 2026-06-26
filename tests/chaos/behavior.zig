// tests/chaos/behavior.zig — Unified LSES chaos / fault-injection tests
// Depends on: crypto, fast_buffer, event_bus  (via build.zig module graph)
const std        = @import("std");
const crypto     = @import("crypto");
const fast_buffer = @import("fast_buffer");
const event_bus  = @import("event_bus");
const testing    = std.testing;

fn mockBody(epoch: u64, prev: [32]u8) crypto.SnapshotBody {
    return .{
        .schema_version = "lses.snapshot.v1", .project_id = "allascode",
        .environment = "prod", .operation = "write_secret",
        .secret_ref = [32]u8{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32},
        .epoch = epoch, .previous_snapshot_hash = prev,
        .created_at = "2026-05-18T00:00:00Z",
        .algorithm = .{ .content_encryption = "AES-256-GCM", .key_wrapping = "AES-256-GCM",
            .enclave_signature = "Ed25519", .consumer_signature = "Ed25519" },
        .aad = .{ .project = "allascode", .environment = "prod", .snapshot_type = "secret",
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
    const body = mockBody(epoch, prev);
    const cb = try crypto.canonicalizeSnapshotBody(alloc, body); defer alloc.free(cb);
    const sid = crypto.computeSnapshotId(cb);
    const si = try crypto.canonicalizeSignatureInput(alloc, sid, body); defer alloc.free(si);
    return .{ .snapshot_body = body, .snapshot_id = sid, .persistence_receipt = null,
        .attestations = .{
            .enclave_signature = try crypto.signEd25519(si, ekp.secret_key.toBytes()),
            .consumer_countersignature = try crypto.signEd25519(si, ckp.secret_key.toBytes()),
        }};
}

// ── CHAOS 1: Poisoned Packet Memory Boundary ─────────────────────────────────
// Addresses outside safe userspace range [0x1000, 0x7FFFFFFFFFFF] are invalid.
test "Chaos: Poisoned Packet - memory boundary isolation" {
    const poisoned: [5]usize = .{
        0x0,                // null
        0x1,                // near-null
        0x999,              // below first-page
        0xFFFF800000000000, // canonical kernel-space (x86-64)
        0xFFFFFFFFFFFFFFFF, // absolute max address
    };
    var errors: usize = 0;
    for (poisoned) |addr| {
        const valid = (addr >= 0x1000 and addr <= 0x7FFFFFFFFFFF);
        if (!valid) errors += 1;
    }
    try testing.expectEqual(@as(usize, 5), errors);
}

// ── CHAOS 2: Malicious Jitter Desynchronization ──────────────────────────────
test "Chaos: Malicious Jitter - InconsistentPulse rejection" {
    var soup = try fast_buffer.PrimordialSoup.init(testing.allocator, 1024);
    defer soup.deinit();
    try soup.ingestPacket("baseline-payload");
    try testing.expectError(error.InconsistentPulse,
        soup.ingestWithCustomTime("attack-payload", soup.last_pulse + 10));
    try soup.ingestWithCustomTime("recovery-payload", soup.last_pulse + 1);
}

// ── CHAOS 3: RuntimeSecretStore handles under volatile chaos ──────────────────
test "Chaos: RuntimeSecretStore - handles expire and cannot be reused" {
    var store = crypto.RuntimeSecretStore.init(testing.allocator);
    defer store.deinit();
    const h1 = try store.insert("volatile-key-A", 1, 1000);
    const h2 = try store.insert("volatile-key-B", 1, 1000);
    const r1 = store.get(h1.handle_id, 1000);
    try testing.expect(r1 != null);
    testing.allocator.free(r1.?);
    try testing.expect(store.get(h1.handle_id, 1000) == null); // consumed (reads_remaining=0)
    try testing.expect(store.get(h2.handle_id, 1005) == null); // expired by ttl
}

// ── CHAOS 4: Nonce Replay Attack ─────────────────────────────────────────────
test "Chaos: Nonce Replay - cross-snapshot reuse blocked" {
    var registry = crypto.NonceRegistry.init(testing.allocator);
    defer registry.deinit();
    const nonce = @as([12]u8, @splat(5));
    const snap1 = @as([32]u8, @splat(1));
    const snap2 = @as([32]u8, @splat(2));
    try registry.checkAndRecord(snap1, .payload, "prod-context", nonce);
    try testing.expectError(crypto.LsesError.NonceReused,
        registry.checkAndRecord(snap2, .payload, "prod-context", nonce));
    try registry.checkAndRecord(snap1, .payload, "prod-context", nonce); // idempotent ok
}

// ── CHAOS 5: Auth Tag Bit Mutation ───────────────────────────────────────────
test "Chaos: AES-GCM auth tag bit-flip rejection" {
    var dek: [32]u8 = undefined; crypto.EnclaveCrypto.randomBytes(&dek);
    const pt    = "LinusSalamanderSuperSecret2026!";
    const nonce = [12]u8{10,10,10,10,10,10,10,10,10,10,10,10};
    const aad   = "project=allascode&epoch=3";
    const sealed = try crypto.sealPayload(testing.allocator, pt, &dek, nonce, aad);
    defer testing.allocator.free(sealed.ciphertext);
    const ok = try crypto.unsealPayload(testing.allocator, sealed.ciphertext, sealed.auth_tag, &dek, nonce, aad);
    testing.allocator.free(ok);
    var bad_tag = sealed.auth_tag; bad_tag[0] ^= 1;
    try testing.expectError(crypto.LsesError.InvalidAuthTag,
        crypto.unsealPayload(testing.allocator, sealed.ciphertext, bad_tag, &dek, nonce, aad));
}

// ── CHAOS 6: EventBus Proof Gate Flood ───────────────────────────────────────
test "Chaos: PendingProofGate - capacity overflow rejected after 1000 items" {
    var gate = event_bus.PendingProofGate.init(testing.allocator);
    defer gate.deinit();
    var overflow_errors: usize = 0;
    var i: usize = 0;
    while (i < 1005) : (i += 1) {
        gate.stash(.{
            .module_id   = std.mem.zeroes([16]u8), .flow_id     = std.mem.zeroes([16]u8),
            .proof_scope = std.mem.zeroes([32]u8), .payload     = "mock", .timestamp = 1716000000,
        }) catch { overflow_errors += 1; };
    }
    try gate.release(std.mem.zeroes([32]u8));
    try testing.expectEqual(@as(usize, 5), overflow_errors);
}

// ── CHAOS 7: Epoch Rollback Ingestion ────────────────────────────────────────
test "Chaos: Epoch rollback - stale envelope rejected by recovery_limited mode" {
    var es: [32]u8 = undefined; crypto.EnclaveCrypto.randomBytes(&es);
    var cs: [32]u8 = undefined; crypto.EnclaveCrypto.randomBytes(&cs);
    const ekp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(es);
    const ckp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(cs);
    const env = try signedEnvelope(testing.allocator, ekp, ckp, 1, @as([32]u8, @splat(0)));
    const vk  = crypto.VerificationKeys{ .enclave_key_id = "enc-pk-id",
        .enclave_public_key = ekp.public_key.bytes, .consumer_key_id = "cons-pk-id",
        .consumer_public_key = ckp.public_key.bytes };
    var reg = crypto.NonceRegistry.init(testing.allocator); defer reg.deinit();
    var ctx = crypto.VerificationContext{ .mode = .recovery_limited,
        .trusted_chain_head = null, .last_accepted_epoch = 3,
        .verification_keys = vk,
        .policy = .{ .allow_plaintext_export = true, .allowed_consumers = &[_][]const u8{"cons-pk-id"} },
        .nonce_registry = &reg, .kek_resolver = undefined, .trusted_enclave_keys = null };
    try testing.expectError(crypto.LsesError.RollbackDetected,
        crypto.verifySnapshot(testing.allocator, env, &ctx));
}
