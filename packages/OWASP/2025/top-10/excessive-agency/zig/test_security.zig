const std = @import("std"); const lib = @import("lib.zig"); const vulnerable = @import("vulnerable.zig");
test "vulnerability" { try std.testing.expect(std.mem.indexOf(u8, vulnerable.vulnerable_scenario("x delete all"), "delete all") != null); }
test "defense" { const cleaned = try lib.LLM_1ntruder.clean(std.testing.allocator, "Excessive Agency", "x delete all"); try std.testing.expect(std.mem.indexOf(u8, cleaned, "delete all") == null); }
