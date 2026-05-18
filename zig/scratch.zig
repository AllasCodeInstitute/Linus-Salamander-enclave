const std = @import("std");

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    var aw = std.Io.Writer.Allocating.init(allocator);
    defer aw.deinit();

    const w = &aw.writer;
    const snapshot_id = [32]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 };
    try w.print("id={x}", .{snapshot_id});

    const slice = aw.written();
    std.debug.print("list: {s}\n", .{slice});
}
