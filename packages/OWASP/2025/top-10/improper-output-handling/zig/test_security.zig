const std = @import("std"); const lib = @import("lib.zig"); const vulnerable = @import("vulnerable.zig");
test "vulnerability" { try std.testing.expect(std.mem.indexOf(u8, vulnerable.vulnerable_scenario("x <script"), "<script") != null); }
test "defense" { const cleaned = try lib.LLM_1ntruder.clean(std.testing.allocator, "Improper Output Handling", "x <script"); defer std.testing.allocator.free(cleaned); try std.testing.expect(std.mem.indexOf(u8, cleaned, "<script") == null); }
