const std = @import("std");
const sealed_state = @import("sealed_state.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    try sealed_state.bootstrap(allocator);
}
