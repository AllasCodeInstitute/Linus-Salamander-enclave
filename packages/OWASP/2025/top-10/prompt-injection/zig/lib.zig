const std = @import("std");

pub const blocked_patterns = [_][]const u8{
    "ignore previous instructions", "disregard all instructions",
    "system prompt", "developer message", "jailbreak", "reveal hidden",
};
pub const poetry_indicators = [_][]const u8{ "ignore", "system", "developer", "reveal" };
pub const replacement = "[REMOVED]";

pub fn normalize_payload(allocator: std.mem.Allocator, payload: []const u8) ![]u8 {
    const no_nulls = try std.mem.replaceOwned(u8, allocator, payload, "\x00", "");
    defer allocator.free(no_nulls);
    return std.mem.replaceOwned(u8, allocator, no_nulls, "\r\n", "\n");
}

// Zig 0.17: ArrayList is unmanaged — allocator passed per-call.
pub fn extract_poetry_acrostic(allocator: std.mem.Allocator, normalized_payload: []const u8) ![]u8 {
    var acrostic = std.ArrayList(u8){};
    defer acrostic.deinit(allocator);
    var lines = std.mem.splitScalar(u8, normalized_payload, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trimLeft(u8, line, " \t");
        if (trimmed.len > 0) {
            try acrostic.append(allocator, std.ascii.toLower(trimmed[0]));
        }
    }
    return acrostic.toOwnedSlice(allocator);
}

pub fn detect_poetry_prompt_injection(allocator: std.mem.Allocator, normalized_payload: []const u8) !bool {
    var line_count: usize = 0;
    var lines = std.mem.splitScalar(u8, normalized_payload, '\n');
    while (lines.next()) |line| {
        if (std.mem.trim(u8, line, " \t\r").len > 0) line_count += 1;
    }
    if (line_count < 3) return false;
    const acrostic = try extract_poetry_acrostic(allocator, normalized_payload);
    defer allocator.free(acrostic);
    for (poetry_indicators) |indicator| {
        if (std.mem.indexOf(u8, acrostic, indicator) != null) return true;
    }
    return false;
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

pub fn neutralize_poetry_prompt_injection(
    allocator: std.mem.Allocator,
    cleaned_payload: []const u8,
    normalized_payload: []const u8,
) ![]u8 {
    if (try detect_poetry_prompt_injection(allocator, normalized_payload)) {
        return allocator.dupe(u8, replacement);
    }
    return allocator.dupe(u8, cleaned_payload);
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
    const poetry_safe = try neutralize_poetry_prompt_injection(allocator, cleaned, normalized);
    defer allocator.free(poetry_safe);
    return escape_output(allocator, poetry_safe);
}

pub const LLM_1ntruder = struct {
    pub fn clean(allocator: std.mem.Allocator, threat: []const u8, payload: []const u8) ![]u8 {
        return @import("lib.zig").clean(allocator, threat, payload);
    }
};
