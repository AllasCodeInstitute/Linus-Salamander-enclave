// tests/stress/behavior.zig — LSES throughput / stress tests
// Validates that crypto primitives scale to expected workloads with no panics,
// memory leaks, or correctness regressions under repeated sequential load.
const std     = @import("std");
const crypto  = @import("crypto");
const testing = std.testing;

// ── STRESS 1: AES-256-GCM 1 000 seal+unseal ──────────────────────────────────
test "Stress: AES-256-GCM - 1000 seal/unseal cycles" {
    var dek: [32]u8 = undefined; crypto.EnclaveCrypto.randomBytes(&dek);
    const pt    = "stress-test-secret-payload-lses";
    const nonce = [12]u8{1,2,3,4,5,6,7,8,9,10,11,12};
    const aad   = "stress-aad-v1";
    var i: usize = 0;
    while (i < 1000) : (i += 1) {
        const sealed = try crypto.sealPayload(testing.allocator, pt, &dek, nonce, aad);
        defer testing.allocator.free(sealed.ciphertext);
        const plain = try crypto.unsealPayload(testing.allocator, sealed.ciphertext, sealed.auth_tag, &dek, nonce, aad);
        defer testing.allocator.free(plain);
        try testing.expectEqualStrings(pt, plain);
    }
}

// ── STRESS 2: NonceRegistry flood — 500 unique nonces ────────────────────────
test "Stress: NonceRegistry - 500 unique nonces registered without collision" {
    var reg = crypto.NonceRegistry.init(testing.allocator); defer reg.deinit();
    const sid = @as([32]u8, @splat(0xDD));
    var i: usize = 0;
    while (i < 500) : (i += 1) {
        var nonce: [12]u8 = undefined;
        // Build a unique nonce from the iteration index
        const idx: u64 = @intCast(i);
        @memcpy(nonce[0..8], std.mem.asBytes(&idx));
        @memset(nonce[8..], 0);
        try reg.checkAndRecord(sid, .payload, "flood-ctx", nonce);
    }
}

// ── STRESS 3: CSPRNG 10 000 fills ────────────────────────────────────────────
test "Stress: CSPRNG - 10000 random fills complete without error" {
    var buf: [32]u8 = undefined;
    var i: usize = 0;
    while (i < 10_000) : (i += 1) {
        crypto.EnclaveCrypto.randomBytes(&buf);
        // Each call must produce non-zero output (all-zero would be RNG failure)
        const all_zero = std.mem.allEqual(u8, &buf, 0);
        try testing.expect(!all_zero);
    }
}

// ── STRESS 4: SHA-256 snapshot IDs — 500 computes ────────────────────────────
test "Stress: computeSnapshotId - 500 hash computations are deterministic" {
    const data = "canonical-snapshot-body-for-stress-testing";
    const expected = crypto.computeSnapshotId(data);
    var i: usize = 0;
    while (i < 500) : (i += 1) {
        const result = crypto.computeSnapshotId(data);
        try testing.expectEqualSlices(u8, &expected, &result);
    }
}

// ── STRESS 5: RuntimeSecretStore — 100 handles inserted and read ──────────────
test "Stress: RuntimeSecretStore - 100 handles inserted and consumed correctly" {
    var store = crypto.RuntimeSecretStore.init(testing.allocator); defer store.deinit();
    const secret = "stress-handle-secret";
    var handles: [100]crypto.RuntimeSecretHandle = undefined;
    // Insert 100 handles
    var i: usize = 0;
    while (i < 100) : (i += 1) {
        handles[i] = try store.insert(secret, 1, 9999);
    }
    // Read all — each must succeed exactly once (reads_remaining=1)
    i = 0;
    while (i < 100) : (i += 1) {
        const r = store.get(handles[i].handle_id, 1000);
        try testing.expect(r != null);
        try testing.expectEqualStrings(secret, r.?);
        testing.allocator.free(r.?);
    }
    // Second read of any handle must return null (consumed)
    const r2 = store.get(handles[0].handle_id, 1000);
    try testing.expect(r2 == null);
}
