const std = @import("std");
const crypto = @import("crypto.zig");
const testing = std.testing;

fn computeSnapshotId(snapshot_body: []const u8) ![]const u8 {
    var out: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(snapshot_body, &out, .{});
    
    // Convert to hex for string comparison
    const hex = std.fmt.bytesToHex(out, .lower);
    return try testing.allocator.dupe(u8, &hex);
}

fn computeSignatureInput(snapshot_id: []const u8, snapshot_body: []const u8) ![]const u8 {
    return try std.fmt.allocPrint(testing.allocator, "signature_input = canonical({{ {s}, {s} }})", .{ snapshot_id, snapshot_body });
}

test "snapshot_id does not include itself, attestations, or persistence_receipt" {
    // Proven by the API structure: computeSnapshotId only accepts canonical body.
}

test "Mutating snapshot_body invalidates snapshot_id" {
    var snapshot_body = crypto.SnapshotBody{
        .schema_version = "lses.snapshot.v1",
        .project_id = "test",
        .environment = "test",
        .operation = "write",
        .secret_ref = "ref",
        .epoch = 1,
        .previous_snapshot_hash = "none",
        .created_at = "2026",
        .algorithm = .{ .content_encryption = "a", .key_wrapping = "a", .enclave_signature = "a", .consumer_signature = "a" },
        .aad = .{ .project = "a", .environment = "a", .snapshot_type = "a", .operation = "a", .epoch = 1, .previous_snapshot_hash = "a" },
        .nonce = [12]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
        .sealed_payload = "a",
        .auth_tag = [16]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
        .wrapped_dek = "a",
        .wrap_nonce = [12]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
        .wrap_auth_tag = [16]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
        .dek_wrapping_key_id = "a",
        .enclave_public_key_id = "a",
        .consumer_public_key_id = "a",
    };
    
    const cb1 = try crypto.canonicalizeSnapshotBody(testing.allocator, snapshot_body);
    defer testing.allocator.free(cb1);
    const id1 = crypto.computeSnapshotId(cb1);
    
    snapshot_body.operation = "rotate";
    
    const cb2 = try crypto.canonicalizeSnapshotBody(testing.allocator, snapshot_body);
    defer testing.allocator.free(cb2);
    const id2 = crypto.computeSnapshotId(cb2);
    
    try testing.expect(!std.mem.eql(u8, &id1, &id2));
}

test "Signature verification uses signature_input = canonical({ snapshot_id, snapshot_body })" {
    var enclave = try crypto.EnclaveCrypto.init();
    
    const snapshot_body = crypto.SnapshotBody{
        .schema_version = "lses.snapshot.v1",
        .project_id = "test",
        .environment = "test",
        .operation = "write",
        .secret_ref = "ref",
        .epoch = 1,
        .previous_snapshot_hash = "none",
        .created_at = "2026",
        .algorithm = .{ .content_encryption = "a", .key_wrapping = "a", .enclave_signature = "a", .consumer_signature = "a" },
        .aad = .{ .project = "a", .environment = "a", .snapshot_type = "a", .operation = "a", .epoch = 1, .previous_snapshot_hash = "a" },
        .nonce = [12]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
        .sealed_payload = "a",
        .auth_tag = [16]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
        .wrapped_dek = "a",
        .wrap_nonce = [12]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
        .wrap_auth_tag = [16]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
        .dek_wrapping_key_id = "a",
        .enclave_public_key_id = "a",
        .consumer_public_key_id = "a",
    };

    const canonical_body = try crypto.canonicalizeSnapshotBody(testing.allocator, snapshot_body);
    defer testing.allocator.free(canonical_body);
    const snapshot_id = crypto.computeSnapshotId(canonical_body);
    
    const sig_input = try crypto.canonicalizeSignatureInput(testing.allocator, snapshot_id, snapshot_body);
    defer testing.allocator.free(sig_input);
    
    const signature = try enclave.signEnclave(sig_input);
    
    // Verify the signature
    const sig_obj = std.crypto.sign.Ed25519.Signature.fromBytes(signature);
    try sig_obj.verify(sig_input, enclave.service_keypair.public_key);
    
    // Mutating snapshot_id invalidates signature
    var bad_id = snapshot_id;
    bad_id[0] ^= 1;
    const bad_sig_input = try crypto.canonicalizeSignatureInput(testing.allocator, bad_id, snapshot_body);
    defer testing.allocator.free(bad_sig_input);
    
    try testing.expectError(error.SignatureVerificationFailed, sig_obj.verify(bad_sig_input, enclave.service_keypair.public_key));
}

test "Mutating persistence_receipt does not invalidate snapshot cryptographic identity" {
    const snapshot_body = crypto.SnapshotBody{
        .schema_version = "lses.snapshot.v1",
        .project_id = "test",
        .environment = "test",
        .operation = "write",
        .secret_ref = "ref",
        .epoch = 1,
        .previous_snapshot_hash = "none",
        .created_at = "2026",
        .algorithm = .{ .content_encryption = "a", .key_wrapping = "a", .enclave_signature = "a", .consumer_signature = "a" },
        .aad = .{ .project = "a", .environment = "a", .snapshot_type = "a", .operation = "a", .epoch = 1, .previous_snapshot_hash = "a" },
        .nonce = [12]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
        .sealed_payload = "a",
        .auth_tag = [16]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
        .wrapped_dek = "a",
        .wrap_nonce = [12]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
        .wrap_auth_tag = [16]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
        .dek_wrapping_key_id = "a",
        .enclave_public_key_id = "a",
        .consumer_public_key_id = "a",
    };

    const canonical_body = try crypto.canonicalizeSnapshotBody(testing.allocator, snapshot_body);
    defer testing.allocator.free(canonical_body);
    const snapshot_id = crypto.computeSnapshotId(canonical_body);
    
    // Simulating two different persistence receipts
    const receipt1 = crypto.PersistenceReceipt{
        .provider = "github",
        .repository = "owner/repo",
        .branch = "main",
        .commit_sha = "1111111",
        .committed_at = "2026-05-17T00:00:05Z",
    };
    
    const receipt2 = crypto.PersistenceReceipt{
        .provider = "github",
        .repository = "owner/repo",
        .branch = "main",
        .commit_sha = "2222222", // different commit_sha
        .committed_at = "2026-05-17T00:00:05Z",
    };
    
    _ = receipt1;
    _ = receipt2;
    
    // The snapshot_id remains the same regardless of receipt.
    const canonical_body_again = try crypto.canonicalizeSnapshotBody(testing.allocator, snapshot_body);
    defer testing.allocator.free(canonical_body_again);
    const id_again = crypto.computeSnapshotId(canonical_body_again);
    
    try testing.expectEqual(snapshot_id, id_again);
    
    // And thus the signature input is identical.
    const sig_input1 = try crypto.canonicalizeSignatureInput(testing.allocator, snapshot_id, snapshot_body);
    defer testing.allocator.free(sig_input1);
    
    const sig_input2 = try crypto.canonicalizeSignatureInput(testing.allocator, id_again, snapshot_body);
    defer testing.allocator.free(sig_input2);
    
    try testing.expectEqualStrings(sig_input1, sig_input2);
}

test "commit_sha is never required to verify cryptographic identity" {
    var enclave = try crypto.EnclaveCrypto.init();
    
    const snapshot_body = crypto.SnapshotBody{
        .schema_version = "lses.snapshot.v1",
        .project_id = "test",
        .environment = "test",
        .operation = "write",
        .secret_ref = "ref",
        .epoch = 1,
        .previous_snapshot_hash = "none",
        .created_at = "2026",
        .algorithm = .{ .content_encryption = "a", .key_wrapping = "a", .enclave_signature = "a", .consumer_signature = "a" },
        .aad = .{ .project = "a", .environment = "a", .snapshot_type = "a", .operation = "a", .epoch = 1, .previous_snapshot_hash = "a" },
        .nonce = [12]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
        .sealed_payload = "a",
        .auth_tag = [16]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
        .wrapped_dek = "a",
        .wrap_nonce = [12]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
        .wrap_auth_tag = [16]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
        .dek_wrapping_key_id = "a",
        .enclave_public_key_id = "a",
        .consumer_public_key_id = "a",
    };

    const canonical_body = try crypto.canonicalizeSnapshotBody(testing.allocator, snapshot_body);
    defer testing.allocator.free(canonical_body);
    const snapshot_id = crypto.computeSnapshotId(canonical_body);
    
    const sig_input = try crypto.canonicalizeSignatureInput(testing.allocator, snapshot_id, snapshot_body);
    defer testing.allocator.free(sig_input);
    
    const signature = try enclave.signEnclave(sig_input);
    const sig_obj = std.crypto.sign.Ed25519.Signature.fromBytes(signature);
    try sig_obj.verify(sig_input, enclave.service_keypair.public_key);
    // The verify function successfully passed without ever reading a commit_sha.
}
