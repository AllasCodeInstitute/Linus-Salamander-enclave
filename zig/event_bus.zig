const std = @import("std");

pub const Message = struct {
    module_id:   [16]u8,
    flow_id:     [16]u8,
    proof_scope: [32]u8,
    payload:     []const u8,
    timestamp:   u64,
};

// Zig 0.17: ArrayList is unmanaged — allocator passed per-call, not stored inside.
pub const PendingProofGate = struct {
    allocator: std.mem.Allocator,
    items: std.ArrayList(Message),

    const CAPACITY: usize = 1000;

    pub fn init(allocator: std.mem.Allocator) PendingProofGate {
        return .{
            .allocator = allocator,
            .items = std.ArrayList(Message).empty,
        };
    }

    pub fn deinit(self: *PendingProofGate) void {
        self.items.deinit(self.allocator);
    }

    pub fn stash(self: *PendingProofGate, msg: Message) !void {
        if (self.items.items.len >= CAPACITY) return error.GateOverflow;
        try self.items.append(self.allocator, msg);
    }

    pub fn release(self: *PendingProofGate, scope: [32]u8) !void {
        var i: usize = 0;
        while (i < self.items.items.len) {
            if (std.mem.eql(u8, &self.items.items[i].proof_scope, &scope)) {
                _ = self.items.swapRemove(i);
            } else {
                i += 1;
            }
        }
    }
};
