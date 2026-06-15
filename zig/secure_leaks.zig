const std = @import("std");

const Finding = struct {
    source: []const u8,
    path: []const u8,
    line: usize,
    kind: []const u8,
    severity: []const u8,
    preview: []const u8,
};

const prefixes = [_]struct { name: []const u8, severity: []const u8, values: []const []const u8 }{
    .{ .name = "AWS access key", .severity = "High", .values = &.{ "AKIA", "ASIA" } },
    .{ .name = "GitHub token", .severity = "High", .values = &.{ "ghp_", "gho_", "ghu_", "ghs_", "github_pat_" } },
    .{ .name = "Slack token", .severity = "High", .values = &.{ "xoxb-", "xoxp-", "xoxa-", "xoxr-" } },
    .{ .name = "Stripe key", .severity = "High", .values = &.{ "sk_live_", "rk_live_" } },
    .{ .name = "Google API key", .severity = "High", .values = &.{"AIza"} },
    .{ .name = "Linus secret", .severity = "High", .values = &.{"ls_secret_"} },
};

const keywords = [_][]const u8{ "api_key", "apikey", "access_token", "auth_token", "secret", "client_secret", "private_key", "password", "passwd", "bearer", "jwt", "token" };

pub fn main() !u8 {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();
    _ = args.next();
    const maybe_path = args.next() orelse {
        std.debug.print("usage: secure_leaks <path>\n", .{});
        return 2;
    };

    const root = try gitOneLine(allocator, maybe_path, &.{ "rev-parse", "--show-toplevel" });
    defer allocator.free(root);

    var findings = std.ArrayList(Finding){};
    defer {
        for (findings.items) |f| allocator.free(f.preview);
        findings.deinit(allocator);
    }

    const files_out = try gitOutput(allocator, root, &.{ "ls-files", "-co", "--exclude-standard", "--", maybe_path });
    defer allocator.free(files_out);

    var files = std.ArrayList([]const u8){};
    defer {
        for (files.items) |f| allocator.free(f);
        files.deinit(allocator);
    }
    var it = std.mem.tokenizeScalar(u8, files_out, '\n');
    while (it.next()) |file| try files.append(allocator, try allocator.dupe(u8, file));

    for (files.items) |file| {
        const full = try std.fs.path.join(allocator, &.{ root, file });
        defer allocator.free(full);
        const data = std.fs.cwd().readFileAlloc(allocator, full, 4 * 1024 * 1024) catch continue;
        defer allocator.free(data);
        if (!isBinary(data)) try scanText(allocator, &findings, "worktree", file, data);
    }

    const commits_out = try gitOutput(allocator, root, &.{ "rev-list", "--all" });
    defer allocator.free(commits_out);
    var commits = std.mem.tokenizeScalar(u8, commits_out, '\n');
    while (commits.next()) |commit| {
        const short = commit[0..@min(commit.len, 12)];
        for (files.items) |file| {
            const spec = try std.fmt.allocPrint(allocator, "{s}:{s}", .{ commit, file });
            defer allocator.free(spec);
            const data = gitOutput(allocator, root, &.{ "show", spec }) catch continue;
            defer allocator.free(data);
            if (!isBinary(data)) try scanText(allocator, &findings, short, file, data);
        }
    }

    const out = std.io.getStdOut().writer();
    try out.print("linus secure_leaks zig deep scan: {d} finding(s)\n", .{findings.items.len});
    for (findings.items) |f| try out.print("{s}\t{s}\t{s}:{d}\t{s}\t{s}\n", .{ f.severity, f.source, f.path, f.line, f.kind, f.preview });
    return if (findings.items.len == 0) 0 else 1;
}

fn scanText(allocator: std.mem.Allocator, findings: *std.ArrayList(Finding), source: []const u8, path: []const u8, text: []const u8) !void {
    var lines = std.mem.splitScalar(u8, text, '\n');
    var line_no: usize = 1;
    while (lines.next()) |line| : (line_no += 1) {
        for (prefixes) |rule| for (rule.values) |p| if (std.mem.indexOf(u8, line, p) != null) try addFinding(allocator, findings, source, path, line_no, rule.name, rule.severity, line);
        const lower = try std.ascii.allocLowerString(allocator, line);
        defer allocator.free(lower);
        for (keywords) |kw| if (std.mem.indexOf(u8, lower, kw) != null and hasAssignmentSecret(line)) {
            try addFinding(allocator, findings, source, path, line_no, "sensitive assignment", "Medium", line);
            break;
        };
        if (std.mem.indexOf(u8, line, "-----BEGIN ") != null and std.mem.indexOf(u8, line, "PRIVATE KEY-----") != null) try addFinding(allocator, findings, source, path, line_no, "private key block", "High", line);
    }
}

fn addFinding(allocator: std.mem.Allocator, findings: *std.ArrayList(Finding), source: []const u8, path: []const u8, line: usize, kind: []const u8, severity: []const u8, raw: []const u8) !void {
    try findings.append(allocator, .{ .source = source, .path = path, .line = line, .kind = kind, .severity = severity, .preview = try redact(allocator, raw) });
}

fn hasAssignmentSecret(line: []const u8) bool {
    const pos = std.mem.indexOfAny(u8, line, "=:") orelse return false;
    const value = std.mem.trim(u8, line[pos + 1 ..], " '\",;");
    if (value.len < 12) return false;
    var has_digit = false; var has_alpha = false;
    for (value) |c| { has_digit = has_digit or std.ascii.isDigit(c); has_alpha = has_alpha or std.ascii.isAlphabetic(c); }
    return has_digit and has_alpha;
}

fn redact(allocator: std.mem.Allocator, raw: []const u8) ![]const u8 {
    const trimmed = std.mem.trim(u8, raw, " \t\r\n");
    if (trimmed.len <= 16) return allocator.dupe(u8, "[redacted]");
    return std.fmt.allocPrint(allocator, "{s}…{s}", .{ trimmed[0..@min(8, trimmed.len)], trimmed[trimmed.len - @min(4, trimmed.len)..] });
}

fn isBinary(bytes: []const u8) bool { return std.mem.indexOfScalar(u8, bytes[0..@min(bytes.len, 8192)], 0) != null; }

fn gitOneLine(allocator: std.mem.Allocator, cwd: []const u8, args: []const []const u8) ![]u8 {
    const out = try gitOutputCwd(allocator, cwd, args);
    defer allocator.free(out);
    return allocator.dupe(u8, std.mem.trim(u8, out, "\n\r "));
}
fn gitOutput(allocator: std.mem.Allocator, root: []const u8, args: []const []const u8) ![]u8 { return gitOutputCwd(allocator, root, args); }
fn gitOutputCwd(allocator: std.mem.Allocator, cwd: []const u8, args: []const []const u8) ![]u8 {
    var argv = std.ArrayList([]const u8){}; defer argv.deinit(allocator);
    try argv.append(allocator, "git"); try argv.appendSlice(allocator, args);
    const result = try std.process.Child.run(.{ .allocator = allocator, .argv = argv.items, .cwd = cwd, .max_output_bytes = 16 * 1024 * 1024 });
    allocator.free(result.stderr);
    switch (result.term) {
        .Exited => |code| if (code != 0) return error.GitFailed,
        else => return error.GitFailed,
    }
    return result.stdout;
}
