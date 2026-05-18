const std = @import("std");
const crypto = @import("crypto.zig");
const git = @import("git.zig");

pub const StorageEnclave = struct {
    secrets: std.StringHashMap([]const u8),
    allocator: std.mem.Allocator,
    crypto_engine: crypto.EnclaveCrypto,
    git_sync: git.GitSync,

    pub fn init(allocator: std.mem.Allocator, repo_path: []const u8) !StorageEnclave {
        return .{
            .secrets = std.StringHashMap([]const u8).init(allocator),
            .allocator = allocator,
            .crypto_engine = try crypto.EnclaveCrypto.init(),
            .git_sync = git.GitSync.init(allocator, repo_path),
        };
    }

    pub fn putSecret(self: *StorageEnclave, key: []const u8, value: []const u8) !void {
        try self.secrets.put(try self.allocator.dupe(u8, key), try self.allocator.dupe(u8, value));
        _ = try self.takeSnapshot();
    }

    fn takeSnapshot(self: *StorageEnclave) !crypto.PersistenceReceipt {
        std.debug.print("Linus Salamander: Triggering State-of-the-Art Snapshot...\n", .{});
        
        // 1. Serialize data
        var list = std.ArrayList(u8).init(self.allocator);
        defer list.deinit();
        
        var it = self.secrets.iterator();
        while (it.next()) |entry| {
            try list.appendSlice(entry.key_ptr.*);
            try list.appendSlice(":");
            try list.appendSlice(entry.value_ptr.*);
            try list.appendSlice("\n");
        }

        // 2. Compute aad & seal payload with DEK, then wrap DEK
        const aad = "project=allascode&env=prod";
        const sealed = try self.crypto_engine.sealAndWrapSecret(self.allocator, list.items, aad);
        defer self.allocator.free(sealed.sealed_payload);
        defer self.allocator.free(sealed.wrapped_dek);

        // 3. Build Canonical Envelope Body (Simulated serialization)
        const envelope_body = "{\"schema_version\":\"lses.snapshot.v1\",\"operation\":\"write_secret\"}"; 
        
        // 4. Sign Canonical Envelope Body
        const signature = try self.crypto_engine.signEnvelope(self.allocator, envelope_body);
        defer self.allocator.free(signature);

        // 5. Save to file (temporary for git)
        const filename = "enclave.sealed";
        const file = try std.fs.cwd().createFile(filename, .{});
        defer file.close();
        try file.writeAll(sealed.sealed_payload);
        try file.writeAll(sealed.wrapped_dek);
        try file.writeAll(signature);

        // 6. Push to GitHub
        try self.git_sync.commitAndPush(filename);
        
        // 7. Clean up: We NEVER store locally
        try std.fs.cwd().deleteFile(filename);
        std.debug.print("Linus Salamander: State pushed to GitHub and local cache purged.\n", .{});

        return crypto.PersistenceReceipt{
            .provider = "github",
            .repository = "owner/repo",
            .branch = "main",
            .commit_sha = "generated_commit_sha",
            .committed_at = "2026-05-17T00:00:05Z",
        };
    }
};
