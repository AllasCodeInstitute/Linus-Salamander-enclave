const std = @import("std");

pub const GitSync = struct {
    repo_path: []const u8,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, path: []const u8) GitSync {
        return .{
            .repo_path = path,
            .allocator = allocator,
        };
    }

    pub fn commitAndPush(self: *GitSync, filename: []const u8) !void {
        const timestamp = std.time.timestamp();
        var msg_buf: [128]u8 = undefined;
        const msg = try std.fmt.bufPrint(&msg_buf, "Snapshot enclave update: {d}", .{timestamp});

        // 1. git add
        _ = try self.runGit(&.{ "add", filename });
        
        // 2. git commit
        _ = try self.runGit(&.{ "commit", "-m", msg });

        // 3. git push
        _ = try self.runGit(&.{ "push", "origin", "main" });
    }

    fn runGit(self: *GitSync, args: []const []const u8) !void {
        var full_args = std.ArrayList([]const u8).init(self.allocator);
        defer full_args.deinit();
        try full_args.append("git");
        for (args) |arg| try full_args.append(arg);

        var child = std.process.Child.init(full_args.items, self.allocator);
        child.cwd = self.repo_path;
        
        const term = try child.spawnAndWait();
        if (term.Exited != 0) return error.GitCommandFailed;
    }
};
