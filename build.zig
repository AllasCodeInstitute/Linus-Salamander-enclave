const std = @import("std");

pub fn build(b: *std.Build) void {
    const target   = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // ── Enclave principal ───────────────────────────────────────────────────
    const exe = b.addExecutable(.{
        .name        = "lses",
        .root_module = b.createModule(.{
            .root_source_file = b.path("zig/main.zig"),
            .target           = target,
            .optimize         = optimize,
        }),
    });
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);
    const run_step = b.step("run", "Executar o enclave LSES");
    run_step.dependOn(&run_cmd.step);

    // ── Bootstrap ───────────────────────────────────────────────────────────
    const bootstrap_exe = b.addExecutable(.{
        .name        = "lses-bootstrap",
        .root_module = b.createModule(.{
            .root_source_file = b.path("zig/bootstrap_main.zig"),
            .target           = target,
            .optimize         = optimize,
        }),
    });
    b.installArtifact(bootstrap_exe);
    const bootstrap_run  = b.addRunArtifact(bootstrap_exe);
    bootstrap_run.step.dependOn(b.getInstallStep());
    const bootstrap_step = b.step("bootstrap", "Inicializar o armazenamento selado de chaves");
    bootstrap_step.dependOn(&bootstrap_run.step);

    // ── Core modules ────────────────────────────────────────────────────────
    const crypto_mod = b.addModule("crypto", .{
        .root_source_file = b.path("zig/crypto.zig"),
        .target           = target,
    });
    const fast_buffer_mod = b.addModule("fast_buffer", .{
        .root_source_file = b.path("zig/fast_buffer.zig"),
        .target           = target,
    });
    const event_bus_mod = b.addModule("event_bus", .{
        .root_source_file = b.path("zig/event_bus.zig"),
        .target           = target,
    });

    // ── test-unit  (tests/unit/behavior.zig) ───────────────────────────────
    const unit_mod = b.createModule(.{
        .root_source_file = b.path("tests/unit/behavior.zig"),
        .target           = target,
        .optimize         = optimize,
    });
    unit_mod.addImport("crypto", crypto_mod);
    const run_unit = b.addRunArtifact(b.addTest(.{ .root_module = unit_mod }));
    b.step("test-unit", "Unit tests (LSES security)").dependOn(&run_unit.step);

    // ── test-chaos (tests/chaos/behavior.zig) ──────────────────────────────
    const chaos_mod = b.createModule(.{
        .root_source_file = b.path("tests/chaos/behavior.zig"),
        .target           = target,
        .optimize         = optimize,
    });
    chaos_mod.addImport("crypto",      crypto_mod);
    chaos_mod.addImport("fast_buffer", fast_buffer_mod);
    chaos_mod.addImport("event_bus",   event_bus_mod);
    const run_chaos = b.addRunArtifact(b.addTest(.{ .root_module = chaos_mod }));
    b.step("test-chaos", "Chaos / fault-injection tests").dependOn(&run_chaos.step);

    // ── test-synk  (tests/synk/behavior.zig) ───────────────────────────────
    const synk_mod = b.createModule(.{
        .root_source_file = b.path("tests/synk/behavior.zig"),
        .target           = target,
        .optimize         = optimize,
    });
    synk_mod.addImport("crypto", crypto_mod);
    const run_synk = b.addRunArtifact(b.addTest(.{ .root_module = synk_mod }));
    b.step("test-synk", "Concurrency / sync tests").dependOn(&run_synk.step);

    // ── test-stress (tests/stress/behavior.zig) ─────────────────────────────
    const stress_mod = b.createModule(.{
        .root_source_file = b.path("tests/stress/behavior.zig"),
        .target           = target,
        .optimize         = optimize,
    });
    stress_mod.addImport("crypto", crypto_mod);
    const run_stress = b.addRunArtifact(b.addTest(.{ .root_module = stress_mod }));
    b.step("test-stress", "Throughput / stress tests").dependOn(&run_stress.step);

    // ── test  (all behavior tests) ──────────────────────────────────────────
    const all_step = b.step("test", "Run all behavior tests");
    all_step.dependOn(&run_unit.step);
    all_step.dependOn(&run_chaos.step);
    all_step.dependOn(&run_synk.step);
    all_step.dependOn(&run_stress.step);
}
