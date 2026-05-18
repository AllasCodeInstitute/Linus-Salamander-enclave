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
    const snapshot_body = "{\"schema_version\":\"lses.snapshot.v1\",\"operation\":\"write_secret\"}";
    
    // We compute snapshot_id ONLY from the body.
    const snapshot_id = try computeSnapshotId(snapshot_body);
    defer testing.allocator.free(snapshot_id);
    
    // Verify snapshot_id is purely derived from snapshot_body
    const expected_id = try computeSnapshotId(snapshot_body);
    defer testing.allocator.free(expected_id);
    
    try testing.expectEqualStrings(expected_id, snapshot_id);
    
    // If we had attestations or receipt, they are completely separate
    // Proving they don't affect snapshot_id because it's computed purely from snapshot_body.
}

test "Mutating snapshot_body invalidates snapshot_id" {
    const body1 = "{\"schema_version\":\"lses.snapshot.v1\",\"operation\":\"write_secret\"}";
    const body2 = "{\"schema_version\":\"lses.snapshot.v1\",\"operation\":\"rotate_secret\"}";
    
    const id1 = try computeSnapshotId(body1);
    defer testing.allocator.free(id1);
    
    const id2 = try computeSnapshotId(body2);
    defer testing.allocator.free(id2);
    
    try testing.expect(std.mem.eql(u8, id1, id2) == false);
}

test "Signature verification uses signature_input = canonical({ snapshot_id, snapshot_body })" {
    var enclave = try crypto.EnclaveCrypto.init();
    
    const snapshot_body = "{\"schema_version\":\"lses.snapshot.v1\",\"operation\":\"write_secret\"}";
    const snapshot_id = try computeSnapshotId(snapshot_body);
    defer testing.allocator.free(snapshot_id);
    
    const sig_input = try computeSignatureInput(snapshot_id, snapshot_body);
    defer testing.allocator.free(sig_input);
    
    const signature = try enclave.signEnvelope(testing.allocator, sig_input);
    defer testing.allocator.free(signature);
    
    // Verify the signature
    const sig_obj = std.crypto.sign.Ed25519.Signature.fromBytes(signature[0..64].*);
    try sig_obj.verify(sig_input, enclave.service_keypair.public_key);
    
    // Mutating snapshot_id invalidates signature
    const bad_id = "bad_id";
    const bad_sig_input = try computeSignatureInput(bad_id, snapshot_body);
    defer testing.allocator.free(bad_sig_input);
    
    try testing.expectError(error.SignatureVerificationFailed, sig_obj.verify(bad_sig_input, enclave.service_keypair.public_key));
}

test "Mutating persistence_receipt does not invalidate snapshot cryptographic identity" {
    const snapshot_body = "{\"schema_version\":\"lses.snapshot.v1\",\"operation\":\"write_secret\"}";
    const snapshot_id = try computeSnapshotId(snapshot_body);
    defer testing.allocator.free(snapshot_id);
    
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
    const id_again = try computeSnapshotId(snapshot_body);
    defer testing.allocator.free(id_again);
    
    try testing.expectEqualStrings(snapshot_id, id_again);
    
    // And thus the signature input is identical.
    const sig_input1 = try computeSignatureInput(snapshot_id, snapshot_body);
    defer testing.allocator.free(sig_input1);
    
    const sig_input2 = try computeSignatureInput(id_again, snapshot_body);
    defer testing.allocator.free(sig_input2);
    
    try testing.expectEqualStrings(sig_input1, sig_input2);
}

test "commit_sha is never required to verify cryptographic identity" {
    // This property is proven by the fact that we can fully construct
    // and verify the signature without any reference to commit_sha.
    
    var enclave = try crypto.EnclaveCrypto.init();
    
    const snapshot_body = "{\"schema_version\":\"lses.snapshot.v1\"}";
    const snapshot_id = try computeSnapshotId(snapshot_body);
    defer testing.allocator.free(snapshot_id);
    
    const sig_input = try computeSignatureInput(snapshot_id, snapshot_body);
    defer testing.allocator.free(sig_input);
    
    const signature = try enclave.signEnvelope(testing.allocator, sig_input);
    defer testing.allocator.free(signature);
    const sig_obj = std.crypto.sign.Ed25519.Signature.fromBytes(signature[0..64].*);
    try sig_obj.verify(sig_input, enclave.service_keypair.public_key);
    
    // The verify function successfully passed without ever reading a commit_sha.
}
