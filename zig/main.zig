const std = @import("std");
const storage = @import("storage.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    std.debug.print("Initializing Linus Salamander Enclave System...\n", .{});

    var enclave = try storage.StorageEnclave.init(allocator, "./");
    
    // Simulating secret storage
    const demo_secret_name = "DEMO_API_KEY";
    const demo_secret_value = "demo_value_not_a_real_secret";
    try enclave.putSecret(demo_secret_name, demo_secret_value);

    std.debug.print("System operational. All secrets sealed and pushed to remote repository.\n", .{});
}
