const std = @import("std");
const crypto = @import("crypto.zig");
const storage = @import("storage.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("====================================================\n", .{});
    std.debug.print(" LINUS SALAMANDER ENCLAVE SYSTEM (LSES) DEMO IN ZIG\n", .{});
    std.debug.print("====================================================\n\n", .{});

    // 1. Initialize Enclave
    std.debug.print("[LSES] Initializing Storage Enclave...\n", .{});
    var enclave = try storage.StorageEnclave.init(allocator, "./");
    defer enclave.deinit();

    std.debug.print("[LSES] Enclave public key: {s}\n", .{std.fmt.fmtSliceHexLower(&enclave.enclave_identity.public_key)});
    std.debug.print("[LSES] Consumer public key: {s}\n", .{std.fmt.fmtSliceHexLower(&enclave.consumer_identity.public_key)});

    // 2. Put a secret
    const key = "MY_SECURE_API_TOKEN";
    const val = "ls_secret_super_secure_token_12345";
    std.debug.print("[LSES] Storing secret. Key: '{s}' (Plaintext will NOT be persisted to disk!)\n", .{key});
    
    try enclave.putSecret(key, val);
    std.debug.print("[LSES] Secret sealed, enveloped, countersigned and successfully snapshotted!\n\n", .{});

    // 3. Read secret (Generates short-lived dynamic handle)
    std.debug.print("[LSES] Simulating read request from Consumer...\n", .{});
    const handle = try enclave.readSecret("consumer_pk_1");
    
    std.debug.print("[LSES] Successfully generated dynamic runtime handle!\n", .{});
    std.debug.print("  - Handle ID: {s}\n", .{std.fmt.fmtSliceHexLower(&handle.handle_id)});
    std.debug.print("  - Scope: {s}\n", .{handle.scope});
    std.debug.print("  - Expires at: {d}\n\n", .{handle.expires_at});

    // 4. Retrieve value securely using the dynamic handle store
    std.debug.print("[LSES] Resolving plaintext from handle store using active handle...\n", .{});
    const resolved = try enclave.runtime_store.readSecret(handle.handle_id, std.time.timestamp());
    
    std.debug.print("  > [DEMO ALERT] Plaintext recovered: {s}\n", .{resolved});
    std.debug.print("  > [SECURITY NOTICE] Plaintext only lives in volatile heap memory.\n\n", .{});

    std.debug.print("[LSES] Demonstration completed successfully. Enclave resources purged.\n", .{});
}
