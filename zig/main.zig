const std = @import("std");
const crypto = @import("crypto.zig");
const storage = @import("storage.zig");

pub fn main() !void {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("====================================================\n", .{});
    std.debug.print(" LINUS SALAMANDER ENCLAVE SYSTEM (LSES) DEMO IN ZIG\n", .{});
    std.debug.print("====================================================\n\n", .{});

    // 1. Initialize Enclave
    std.debug.print("[LSES] Initializing Storage Enclave...\n", .{});
    var thread_io = std.Io.Threaded.init(allocator, .{});
    defer thread_io.deinit();
    const io = thread_io.io();

    var enclave = try storage.StorageEnclave.init(allocator, io, "./");
    defer enclave.deinit();

    const enc_pk_hex = std.fmt.bytesToHex(&enclave.enclave_identity.public_key, .lower);
    const cons_pk_hex = std.fmt.bytesToHex(&enclave.consumer_identity.public_key, .lower);
    std.debug.print("[LSES] Enclave public key: {s}\n", .{&enc_pk_hex});
    std.debug.print("[LSES] Consumer public key: {s}\n", .{&cons_pk_hex});

    // 2. Put a secret
    const key = "MY_SECURE_API_TOKEN";
    const val = "ls_secret_super_secure_token_12345";
    std.debug.print("[LSES] Storing secret. Key: '{s}' (Plaintext will NOT be persisted to disk!)\n", .{key});
    
    try enclave.putSecret(key, val);
    std.debug.print("[LSES] Secret sealed, enveloped, countersigned and successfully snapshotted!\n\n", .{});

    // 3. Read secret (Generates short-lived dynamic handle)
    std.debug.print("[LSES] Simulating read request from Consumer...\n", .{});
    const handle = try enclave.readSecret("consumer_pk_1");
    
    const handle_id_hex = std.fmt.bytesToHex(&handle.handle_id, .lower);
    std.debug.print("[LSES] Successfully generated dynamic runtime handle!\n", .{});
    std.debug.print("  - Handle ID: {s}\n", .{&handle_id_hex});
    std.debug.print("  - Scope: {s}\n", .{handle.scope});
    std.debug.print("  - Expires at: {d}\n\n", .{handle.expires_at});

    // 4. Retrieve value securely using the dynamic handle store (verifying it exists without logging the sensitive plaintext)
    std.debug.print("[LSES] Resolving plaintext from handle store using active handle...\n", .{});
    const resolved = enclave.runtime_store.get(handle.handle_id, @intCast(@divTrunc(io.vtable.now(io.userdata, .real).nanoseconds, 1_000_000_000))) orelse return error.SecretNotFound;
    defer allocator.free(resolved);
    
    std.debug.print("  > [SECURITY NOTICE] Plaintext recovered successfully (verified length: {d} bytes).\n", .{resolved.len});
    std.debug.print("  > [SECURITY NOTICE] Plaintext lives strictly in volatile heap memory and was NOT printed.\n\n", .{});

    std.debug.print("[LSES] Demonstration completed successfully. Enclave resources purged.\n", .{});
}
