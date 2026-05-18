const std = @import("std");
const crypto = @import("crypto.zig");

pub fn main() !void {
    var out: [32]u8 = undefined;
    crypto.EnclaveCrypto.randomBytes(&out);
    const hex = std.fmt.bytesToHex(out, .lower);
    std.debug.print("Random hex: {s}\n", .{hex});
}
