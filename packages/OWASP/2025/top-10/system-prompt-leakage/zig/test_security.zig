const std = @import("std"); const lib = @import("lib.zig"); const vulnerable = @import("vulnerable.zig");
test "vulnerability" { try std.testing.expect(std.mem.indexOf(u8, vulnerable.vulnerable_scenario("x system prompt"), "system prompt") != null); }
test "defense" { const cleaned = try lib.LLM_1ntruder.clean(std.testing.allocator, "System Prompt Leakage", "x system prompt"); try std.testing.expect(std.mem.indexOf(u8, cleaned, "system prompt") == null); }
