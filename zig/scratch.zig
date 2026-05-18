const std = @import("std");

pub fn main() void {
    std.debug.print("--- std.time Decls ---\n", .{});
    inline for (@typeInfo(std.time).@"struct".decls) |decl| {
        std.debug.print("time: {s}\n", .{decl.name});
    }
}
