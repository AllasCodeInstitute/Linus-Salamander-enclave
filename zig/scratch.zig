const std = @import("std");

pub fn main() !void {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    var thread_io = std.Io.Threaded.init(allocator, .{});
    defer thread_io.deinit();
    const io = thread_io.io();
    
    const now = io.vtable.now(io.userdata, .real);
    std.debug.print("now: {d}\n", .{now.nanoseconds});
}
