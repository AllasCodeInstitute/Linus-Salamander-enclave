const std = @import("std");
const crypto = @import("crypto.zig");

pub fn main() !void {
    var seed: [32]u8 = undefined;
    crypto.EnclaveCrypto.randomBytes(&seed);
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed);
    _ = kp;
    std.debug.print("Ed25519 KeyPair generated successfully.\n", .{});
}
