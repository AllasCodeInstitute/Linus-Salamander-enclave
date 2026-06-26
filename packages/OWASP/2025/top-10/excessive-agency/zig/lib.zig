const std = @import("std");
pub const blocked_patterns = [_][]const u8{ "delete all", "transfer money", "send email", "run command", "drop table", "shutdown" };
pub const replacement = "[REMOVED]";

pub fn normalize_payload(allocator: std.mem.Allocator, payload: []const u8) ![]u8 {
    const no_nulls = try std.mem.replaceOwned(u8, allocator, payload, "\x00", "");
    defer allocator.free(no_nulls);
    return std.mem.replaceOwned(u8, allocator, no_nulls, "\r\n", "\n");
}

pub fn remove_blocked_patterns(allocator: std.mem.Allocator, normalized_payload: []const u8) ![]u8 {
    var out = try allocator.dupe(u8, normalized_payload);
    for (blocked_patterns) |pattern| {
        const next = try std.mem.replaceOwned(u8, allocator, out, pattern, replacement);
        allocator.free(out);
        out = next;
    }
    return out;
}

pub fn escape_output(allocator: std.mem.Allocator, cleaned_payload: []const u8) ![]u8 {
    const subs = [_][2][]const u8{
        .{ "&", "&amp;" }, .{ "<", "&lt;" }, .{ ">", "&gt;" },
        .{ "\"", "&quot;" }, .{ "'", "&#39;" }, .{ "`", "&#96;" },
    };
    var out = try allocator.dupe(u8, cleaned_payload);
    for (subs) |sub| {
        const next = try std.mem.replaceOwned(u8, allocator, out, sub[0], sub[1]);
        allocator.free(out);
        out = next;
    }
    return out;
}

pub fn clean(allocator: std.mem.Allocator, threat: []const u8, payload: []const u8) ![]u8 {
    _ = threat;
    const normalized = try normalize_payload(allocator, payload);
    defer allocator.free(normalized);
    const cleaned = try remove_blocked_patterns(allocator, normalized);
    defer allocator.free(cleaned);
    return escape_output(allocator, cleaned);
}

pub const LLM_1ntruder = struct {
    pub fn clean(allocator: std.mem.Allocator, threat: []const u8, payload: []const u8) ![]u8 {
        return @import("lib.zig").clean(allocator, threat, payload);
    }
};
