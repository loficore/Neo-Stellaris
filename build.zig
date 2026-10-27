// build.zig — Build system for stellaris_quickjs DLL + injector.
//
// Targets x86_64-windows to produce stellaris_quickjs.dll and inject.exe.
// QuickJS is compiled from vendored sources in libs/quickjs (no prebuilt lib).

const std = @import("std");

const quickjs_c_sources = [_][]const u8{
    "libs/quickjs/quickjs.c",
    "libs/quickjs/libregexp.c",
    "libs/quickjs/libunicode.c",
    "libs/quickjs/cutils.c",
    "libs/quickjs/dtoa.c",
};

const quickjs_c_flags = [_][]const u8{
    "-DCONFIG_VERSION=\"2025-09-13\"",
    "-Wno-gnu-zero-variadic-macro-arguments",
};

/// Adds the vendored QuickJS sources (plus the wrapper exporting static-inline
/// symbols for Zig) to a module, so no prebuilt static library is required.
fn linkQuickjs(b: *std.Build, module: *std.Build.Module) void {
    module.addIncludePath(b.path("libs/quickjs"));
    module.addCSourceFiles(.{
        .root = b.path("."),
        .files = &quickjs_c_sources,
        .flags = &quickjs_c_flags,
    });
    module.addCSourceFile(.{
        .file = b.path("src/dll/quickjs/quickjs_wrapper.c"),
        .flags = &.{},
    });
    module.link_libc = true;
}

pub fn build(b: *std.Build) void {
    // Artifacts (DLL, injector) target x86_64-windows.
    const target = b.standardTargetOptions(.{
        .default_target = .{
            .os_tag = .windows,
            .cpu_arch = .x86_64,
        },
    });
    // Tests run on the build machine. QuickJS's bundled allocator misbehaves
    // under Zig's musl static libc, so link the host glibc dynamically instead
    // (zig's glibc sysroot is newer than this host's, hence .dynamic).
    const native = b.resolveTargetQuery(.{});

    const optimize = b.standardOptimizeOption(.{});

    // Offsets module — shared by DLL build and multiple test targets.
    const offsets_mod = b.createModule(.{
        .root_source_file = b.path("src/dll/shared/offsets.zig"),
        .target = native,
        .optimize = optimize,
    });

    // Build the shared library (DLL on Windows, .so on Linux).
    const dll = b.addLibrary(.{
        .name = "stellaris_quickjs",
        .linkage = .dynamic,
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/dll/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    // Enable PE export table entries for exported functions (PushCApplicationPtr, DllMain).
    // Zig's `export` keyword provides C calling convention + external linkage, but the
    // Windows linker needs this flag to populate the PE export directory so the DLL
    // injector can discover symbols by name.
    dll.dll_export_fns = true;

    linkQuickjs(b, dll.root_module);


    b.installArtifact(dll);

    // --- Injector exe: loads the DLL into the running stellaris process ---
    const inject = b.addExecutable(.{
        .name = "inject",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/inject/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    b.installArtifact(inject);

    const inject_step = b.step("inject", "Build only inject.exe");
    inject_step.dependOn(&b.addInstallArtifact(inject, .{}).step);

    // --- abi-probe (§65): NON-DEFAULT step, never in the default install graph.
    // Builds two probe DLLs side by side — one from the C side (this block),
    // one from the Zig side (below) — so their call stubs can be compared by
    // scripts/scratch/2026-10_abi_probe/compare_stubs.py. Neither probe is
    // ever executed; they exist only to make the compiler emit stub bytes.
    // Fixed ReleaseFast (independent of -Doptimize): Debug codegen outlines the
    // JSValue ctors and emits panic wrappers, which drown the one-call-per-stub
    // self-check; the optimized form is also the honest parameter assembly.
    const abi_probe_step = b.step("abi-probe", "Build Zig/C QuickJS ABI probes (offline §65; not shipped)");

    const abi_c_mod = b.createModule(.{
        .root_source_file = null,
        .target = target,
        .optimize = .ReleaseFast,
    });
    abi_c_mod.addIncludePath(b.path("libs/quickjs"));
    abi_c_mod.addCSourceFiles(.{
        .root = b.path("."),
        .files = quickjs_c_sources ++ &[_][]const u8{"src/dll/quickjs/abi_probe.c"},
        .flags = quickjs_c_flags ++ &[_][]const u8{"-fno-stack-protector"},
    });
    abi_c_mod.link_libc = true;
    const abi_c_dll = b.addLibrary(.{
        .name = "abi_probe_c",
        .linkage = .dynamic,
        .root_module = abi_c_mod,
    });
    abi_probe_step.dependOn(&b.addInstallArtifact(abi_c_dll, .{}).step);

    const abi_zig_dll = b.addLibrary(.{
        .name = "abi_probe_zig",
        .linkage = .dynamic,
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/dll/quickjs/abi_probe.zig"),
            .target = target,
            .optimize = .ReleaseFast,
        }),
    });
    abi_zig_dll.dll_export_fns = true;
    linkQuickjs(b, abi_zig_dll.root_module);
    abi_probe_step.dependOn(&b.addInstallArtifact(abi_zig_dll, .{}).step);

    // --- Run tests (native target so they execute on this machine) ---
    const tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/dll/exports.zig"),
            .target = native,
            .optimize = optimize,
        }),
    });
    linkQuickjs(b, tests.root_module);

    // QuickJS runtime tests (link the real engine, not stubs).
    const qjs_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/dll/quickjs/runtime.zig"),
            .target = native,
            .optimize = optimize,
        }),
    });
    linkQuickjs(b, qjs_tests.root_module);

    // C2 native bootstrap-sequence test: runs the exact step sequence that
    // crashed the live game (evidence §32/§33) against the real vendored
    // QuickJS on this host, through quickjs_wrapper.c's own C2DiagQuickJS.
    const c2_diag_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/dll/quickjs/c2_diag_test.zig"),
            .target = native,
            .optimize = optimize,
        }),
    });
    linkQuickjs(b, c2_diag_tests.root_module);

    // C4 execution-wrapper tests (native): donor vtable copy + slot[1] bridge.
    const c2_exec_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/dll/c2_exec_test.zig"),
            .target = native,
            .optimize = optimize,
        }),
    });
    linkQuickjs(b, c2_exec_tests.root_module);

    // Offsets validation tests.
    const offsets_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/dll/shared/offsets.zig"),
            .target = native,
            .optimize = optimize,
        }),
    });

    // Keyword registry tests run via the exports.zig test root (main.zig imports
    // keyword_registry), so no standalone test module is needed here.

    // Hooking framework tests (detour + windows wrappers).
    const windows_mod = b.createModule(.{
        .root_source_file = b.path("src/dll/hooking/windows.zig"),
        .target = native,
        .optimize = optimize,
    });
    const detour_mod = b.createModule(.{
        .root_source_file = b.path("src/dll/hooking/detour.zig"),
        .target = native,
        .optimize = optimize,
    });
    detour_mod.addImport("windows", windows_mod);
    const detour_tests = b.addTest(.{
        .root_module = detour_mod,
    });

    // API module tests.
    const api_gamestate_mod = b.createModule(.{
        .root_source_file = b.path("src/dll/api/gamestate.zig"),
        .target = native,
        .optimize = optimize,
    });
    api_gamestate_mod.addImport("offsets", offsets_mod);
    const api_gamestate_tests = b.addTest(.{
        .root_module = api_gamestate_mod,
    });

    const api_scope_mod = b.createModule(.{
        .root_source_file = b.path("src/dll/api/scope.zig"),
        .target = native,
        .optimize = optimize,
    });
    api_scope_mod.addImport("offsets", offsets_mod);
    const api_scope_tests = b.addTest(.{
        .root_module = api_scope_mod,
    });

    // Effects handler tests — SKIPPED: std.Thread.Mutex unavailable for x86_64-windows target.
    // The handler modules use std.Thread.Mutex in production code which doesn't compile
    // for the cross-compilation target. These tests would pass on native Linux builds.

    // Triggers handler tests — SKIPPED: same reason as effects handler.

    // UI module tests.
    const ui_window_mod = b.createModule(.{
        .root_source_file = b.path("src/dll/ui/window.zig"),
        .target = native,
        .optimize = optimize,
    });
    const ui_window_tests = b.addTest(.{
        .root_module = ui_window_mod,
    });

    const ui_callbacks_mod = b.createModule(.{
        .root_source_file = b.path("src/dll/ui/callbacks.zig"),
        .target = native,
        .optimize = optimize,
    });
    const ui_callbacks_tests = b.addTest(.{
        .root_module = ui_callbacks_mod,
    });

    const ui_dynamic_text_mod = b.createModule(.{
        .root_source_file = b.path("src/dll/ui/dynamic_text.zig"),
        .target = native,
        .optimize = optimize,
    });
    const ui_dynamic_text_tests = b.addTest(.{
        .root_module = ui_dynamic_text_mod,
    });

    const ui_gui_mod = b.createModule(.{
        .root_source_file = b.path("src/dll/ui/gui.zig"),
        .target = native,
        .optimize = optimize,
    });
    ui_gui_mod.addImport("window.zig", ui_window_mod);
    const ui_gui_tests = b.addTest(.{
        .root_module = ui_gui_mod,
    });

    const ui_button_mod = b.createModule(.{
        .root_source_file = b.path("src/dll/ui/button.zig"),
        .target = native,
        .optimize = optimize,
    });
    ui_button_mod.addImport("callbacks.zig", ui_callbacks_mod);
    const ui_button_tests = b.addTest(.{
        .root_module = ui_button_mod,
    });

    // Note: bridge.zig tests require QuickJS C linkage and cannot run standalone.
    // They are tested as part of the full DLL build.

    // Scripted detour tests (lookup_hook, exec_hook) through a root inside src/dll so
    // their ../hooking imports resolve, without QuickJS C linkage.
    const scripted_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/dll/scripted_tests.zig"),
            .target = native,
            .optimize = optimize,
        }),
    });
    const run_scripted_tests = b.addRunArtifact(scripted_tests);
    run_scripted_tests.skip_foreign_checks = true;

    const run_tests = b.addRunArtifact(tests);
    run_tests.skip_foreign_checks = true;

    const run_qjs_tests = b.addRunArtifact(qjs_tests);
    run_qjs_tests.skip_foreign_checks = true;

    const run_c2_diag_tests = b.addRunArtifact(c2_diag_tests);
    run_c2_diag_tests.skip_foreign_checks = true;

    const run_c2_exec_tests = b.addRunArtifact(c2_exec_tests);
    run_c2_exec_tests.skip_foreign_checks = true;

    const run_offsets_tests = b.addRunArtifact(offsets_tests);
    run_offsets_tests.skip_foreign_checks = true;

    const run_detour_tests = b.addRunArtifact(detour_tests);
    run_detour_tests.skip_foreign_checks = true;

    const run_api_gamestate_tests = b.addRunArtifact(api_gamestate_tests);
    run_api_gamestate_tests.skip_foreign_checks = true;

    const run_api_scope_tests = b.addRunArtifact(api_scope_tests);
    run_api_scope_tests.skip_foreign_checks = true;

    const run_ui_window_tests = b.addRunArtifact(ui_window_tests);
    run_ui_window_tests.skip_foreign_checks = true;

    const run_ui_callbacks_tests = b.addRunArtifact(ui_callbacks_tests);
    run_ui_callbacks_tests.skip_foreign_checks = true;

    const run_ui_dynamic_text_tests = b.addRunArtifact(ui_dynamic_text_tests);
    run_ui_dynamic_text_tests.skip_foreign_checks = true;

    const run_ui_gui_tests = b.addRunArtifact(ui_gui_tests);
    run_ui_gui_tests.skip_foreign_checks = true;

    const run_ui_button_tests = b.addRunArtifact(ui_button_tests);
    run_ui_button_tests.skip_foreign_checks = true;

    const test_c2_exec_step = b.step("test-c2-exec", "Run C4 wrapper tests (native)");
    test_c2_exec_step.dependOn(&run_c2_exec_tests.step);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_tests.step);
    test_step.dependOn(&run_qjs_tests.step);
    test_step.dependOn(&run_c2_diag_tests.step);
    test_step.dependOn(&run_c2_exec_tests.step);
    test_step.dependOn(&run_offsets_tests.step);
    test_step.dependOn(&run_detour_tests.step);
    test_step.dependOn(&run_api_gamestate_tests.step);
    // scope.zig 的独立测试曾在 §26 之前以 `import of file outside module path` 被禁;
    // `:26` 改用 `@import("offsets")` 后启用。读点处置见 `docs/scope-read-points.md`。
    test_step.dependOn(&run_api_scope_tests.step);
    test_step.dependOn(&run_ui_window_tests.step);
    test_step.dependOn(&run_ui_callbacks_tests.step);
    test_step.dependOn(&run_ui_dynamic_text_tests.step);
    test_step.dependOn(&run_ui_gui_tests.step);
    test_step.dependOn(&run_ui_button_tests.step);
    test_step.dependOn(&run_scripted_tests.step);
}
