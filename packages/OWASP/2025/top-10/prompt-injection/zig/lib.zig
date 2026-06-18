const std = @import("std");
pub const blocked_patterns = [_][]const u8{ "ignore previous instructions", "disregard all instructions", "system prompt", "developer message", "jailbreak", "reveal hidden" };
pub const poetry_indicators = [_][]const u8{ "ignore", "system", "developer", "reveal" };
pub const replacement = "[REMOVED]";

pub fn normalize_payload(allocator: std.mem.Allocator, payload: []const u8) ![]u8 {
    const without_nulls = try std.mem.replaceOwned(u8, allocator, payload, "\x00", "");
    return std.mem.replaceOwned(u8, allocator, without_nulls, "\r\n", "\n");
}

pub fn extract_poetry_acrostic(allocator: std.mem.Allocator, normalized_payload: []const u8) ![]u8 {
    var poetry_acrostic = std.ArrayList(u8).init(allocator);
    var payload_lines = std.mem.splitScalar(u8, normalized_payload, '\n');
    while (payload_lines.next()) |payload_line| {
        const trimmed_payload_line = std.mem.trimLeft(u8, payload_line, " \t");
        if (trimmed_payload_line.len > 0) {
            try poetry_acrostic.append(std.ascii.toLower(trimmed_payload_line[0]));
        }
    }
    return poetry_acrostic.toOwnedSlice();
}

pub fn detect_poetry_prompt_injection(allocator: std.mem.Allocator, normalized_payload: []const u8) !bool {
    var payload_line_count: usize = 0;
    var payload_lines = std.mem.splitScalar(u8, normalized_payload, '\n');
    while (payload_lines.next()) |payload_line| {
        if (std.mem.trim(u8, payload_line, " \t\r").len > 0) payload_line_count += 1;
    }
    if (payload_line_count < 3) return false;
    const poetry_acrostic = try extract_poetry_acrostic(allocator, normalized_payload);
    for (poetry_indicators) |poetry_indicator| {
        if (std.mem.indexOf(u8, poetry_acrostic, poetry_indicator) != null) return true;
    }
    return false;
}

pub fn remove_blocked_patterns(allocator: std.mem.Allocator, normalized_payload: []const u8) ![]u8 {
    var cleaned_payload = try allocator.dupe(u8, normalized_payload);
    for (blocked_patterns) |blocked_pattern| {
        cleaned_payload = try std.mem.replaceOwned(u8, allocator, cleaned_payload, blocked_pattern, replacement);
    }
    return cleaned_payload;
}

pub fn neutralize_poetry_prompt_injection(allocator: std.mem.Allocator, cleaned_payload: []const u8, normalized_payload: []const u8) ![]u8 {
    if (try detect_poetry_prompt_injection(allocator, normalized_payload)) {
        return allocator.dupe(u8, replacement);
    }
    return allocator.dupe(u8, cleaned_payload);
}

pub fn escape_output(allocator: std.mem.Allocator, cleaned_payload: []const u8) ![]u8 {
    var output = try std.mem.replaceOwned(u8, allocator, cleaned_payload, "&", "&amp;");
    output = try std.mem.replaceOwned(u8, allocator, output, "<", "&lt;");
    output = try std.mem.replaceOwned(u8, allocator, output, ">", "&gt;");
    output = try std.mem.replaceOwned(u8, allocator, output, "\"", "&quot;");
    output = try std.mem.replaceOwned(u8, allocator, output, "'", "&#39;");
    return std.mem.replaceOwned(u8, allocator, output, "`", "&#96;");
}

pub fn clean(allocator: std.mem.Allocator, threat: []const u8, payload: []const u8) ![]u8 {
    _ = threat;
    const normalized_payload = try normalize_payload(allocator, payload);
    const cleaned_payload = try remove_blocked_patterns(allocator, normalized_payload);
    const poetry_safe_payload = try neutralize_poetry_prompt_injection(allocator, cleaned_payload, normalized_payload);
    return escape_output(allocator, poetry_safe_payload);
}

pub const LLM_1ntruder = struct {
    pub fn clean(allocator: std.mem.Allocator, threat: []const u8, payload: []const u8) ![]u8 {
        return @import("lib.zig").clean(allocator, threat, payload);
    }
};
