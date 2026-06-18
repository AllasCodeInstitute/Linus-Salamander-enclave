const std = @import("std"); const lib = @import("lib.zig"); const vulnerable = @import("vulnerable.zig");
test "vulnerability" { try std.testing.expect(std.mem.indexOf(u8, vulnerable.vulnerable_scenario("x password="), "password=") != null); }
test "defense" { const cleaned = try lib.LLM_1ntruder.clean(std.testing.allocator, "Sensitive Information Disclosure", "x password="); try std.testing.expect(std.mem.indexOf(u8, cleaned, "password=") == null); }
