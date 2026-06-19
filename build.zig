const std = @import("std");

pub fn build(b: *std.Build) void {
    const target   = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // ── Enclave principal ───────────────────────────────────────────────────
    const exe = b.addExecutable(.{
        .name             = "lses",
        .root_source_file = b.path("zig/main.zig"),
        .target           = target,
        .optimize         = optimize,
    });
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);
    const run_step = b.step("run", "Executar o enclave LSES");
    run_step.dependOn(&run_cmd.step);

    // ── Bootstrap — geração de chaves dentro do enclave ────────────────────
    // Execute UMA VEZ antes de iniciar o serviço:
    //   zig build bootstrap
    // Ou via script:
    //   ./scripts/lses-init.sh
    const bootstrap_exe = b.addExecutable(.{
        .name             = "lses-bootstrap",
        .root_source_file = b.path("zig/bootstrap_main.zig"),
        .target           = target,
        .optimize         = optimize,
    });
    b.installArtifact(bootstrap_exe);

    const bootstrap_run = b.addRunArtifact(bootstrap_exe);
    bootstrap_run.step.dependOn(b.getInstallStep());
    const bootstrap_step = b.step("bootstrap", "Inicializar o armazenamento selado de chaves");
    bootstrap_step.dependOn(&bootstrap_run.step);

    // ── Testes ─────────────────────────────────────────────────────────────
    const unit_tests = b.addTest(.{
        .root_source_file = b.path("zig/crypto.zig"),
        .target           = target,
        .optimize         = optimize,
    });
    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Executar testes unitários");
    test_step.dependOn(&run_unit_tests.step);
}
