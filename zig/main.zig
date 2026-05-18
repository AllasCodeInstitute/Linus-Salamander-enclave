const std = @import("std");
const storage = @import("storage.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    std.debug.print("Initializing Linus Salamander Enclave System...\n", .{});

    var enclave = try storage.StorageEnclave.init(allocator, "./");
    
    // Simulating secret storage
    try enclave.putSecret("API_KEY", "sk_live_51P2factorDigital");
    try enclave.putSecret("DB_PASSWORD", "resilient_zig_2024");

    std.debug.print("System operational. All secrets sealed and pushed to remote repository.\n", .{});
}
