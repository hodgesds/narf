//! Build narf-testbin (the Rust user binary) and expose its ELF
//! bytes to the kernel_test harness via a compile-time env var.
//!
//! Gated by the `user-mode-testbin` cargo feature so default builds
//! (and `user-mode-e2e` smoke-only builds) don't pay the cost. When
//! the feature is off, we still set `NARF_TESTBIN_ELF_*` to an
//! empty-string placeholder so `env!()` resolves cleanly; the gated
//! test body checks the byte-length and skips if empty.
//!
//! Why this lives here and not in `userspace/testbin/build.rs`:
//! the verification crate is the one that embeds the bytes via
//! `include_bytes!`, so the build-order dependency is
//! `verification -> testbin`, and the env var has to land in
//! verification's build context.

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=../userspace/testbin/src/main.rs");
    println!("cargo:rerun-if-changed=../userspace/testbin/testbin.ld");
    println!("cargo:rerun-if-changed=../userspace/testbin/Cargo.toml");
    println!("cargo:rerun-if-changed=../narf-libc/src/lib.rs");
    println!("cargo:rerun-if-changed=../narf-libc/src/arch.rs");
    println!("cargo:rerun-if-changed=../narf-libc/src/startup.rs");
    println!("cargo:rerun-if-changed=../narf-libc/src/io.rs");
    println!("cargo:rerun-if-changed=../narf-libc/src/process.rs");
    println!("cargo:rerun-if-changed=../narf-libc/src/heap.rs");
    println!("cargo:rerun-if-changed=../narf-libc/src/errno.rs");
    println!("cargo:rerun-if-changed=../narf-libc/src/string.rs");
    println!("cargo:rerun-if-changed=../narf-libc/validate/src/main.rs");
    println!("cargo:rerun-if-changed=../narf-libc/validate/validate.ld");
    println!("cargo:rerun-if-changed=../narf-libc/validate/Cargo.toml");
    // narf-libc (and thus every boot-init user binary) links narf_user_runtime;
    // its sources must invalidate the embedded ELFs too, else a fix in the
    // runtime's syscall wrappers (e.g. nanosleep's ABI) is served stale.
    println!("cargo:rerun-if-changed=../user-runtime/src/lib.rs");
    println!("cargo:rerun-if-changed=../user-runtime/src/graphics.rs");
    println!("cargo:rerun-if-changed=../user-runtime/src/shmem.rs");
    // boot-init feature: init + shell binaries.
    println!("cargo:rerun-if-changed=../userspace/init/src/main.rs");
    println!("cargo:rerun-if-changed=../userspace/init/init.ld");
    println!("cargo:rerun-if-changed=../userspace/init/Cargo.toml");
    println!("cargo:rerun-if-changed=../userspace/shell/src/main.rs");
    println!("cargo:rerun-if-changed=../userspace/shell/src/exec.rs");
    println!("cargo:rerun-if-changed=../userspace/shell/src/parser.rs");
    println!("cargo:rerun-if-changed=../userspace/shell/shell.ld");
    println!("cargo:rerun-if-changed=../userspace/shell/Cargo.toml");
    println!("cargo:rerun-if-changed=../userspace/getty/src/main.rs");
    println!("cargo:rerun-if-changed=../userspace/getty/getty.ld");
    println!("cargo:rerun-if-changed=../userspace/getty/Cargo.toml");
    println!("cargo:rerun-if-changed=../userspace/login-core/src/lib.rs");
    println!("cargo:rerun-if-changed=../userspace/login-core/src/sha256.rs");
    println!("cargo:rerun-if-changed=../userspace/login-core/Cargo.toml");
    // Wave-49: coreutils baked alongside init/shell so the
    // boot-init path can seed /bin/<name> in a kernel-side MemFs
    // (no Limine initramfs CPIO module is delivered under
    // `qemu -kernel`).
    for name in ["echo", "pwd", "cat", "ls", "ps"] {
        println!("cargo:rerun-if-changed=../userspace/coreutils/{name}/src/main.rs");
        println!("cargo:rerun-if-changed=../userspace/coreutils/{name}/{name}.ld");
        println!("cargo:rerun-if-changed=../userspace/coreutils/{name}/Cargo.toml");
    }

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let workspace = manifest_dir.parent().unwrap().to_path_buf();
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    let testbin_enabled = env::var_os("CARGO_FEATURE_USER_MODE_TESTBIN").is_some();
    let boot_init_enabled = env::var_os("CARGO_FEATURE_BOOT_INIT").is_some();
    let testbin_dir = workspace.join("userspace").join("testbin");

    // testbin: built only for the dedicated testbin runner.
    if testbin_enabled {
        build_arch(
            &testbin_dir,
            &out_dir.join("testbin-target-x86_64"),
            "x86_64-unknown-none",
            &testbin_dir.join("testbin.ld"),
            // `code-model=large` because the user vaddr is past the
            // 2-GiB reach of small-model relocations.
            Some("code-model=large"),
            "NARF_TESTBIN_ELF_X86_64",
            "narf-testbin",
        );
        build_arch(
            &testbin_dir,
            &out_dir.join("testbin-target-aarch64"),
            "aarch64-unknown-none",
            &testbin_dir.join("testbin-aarch64.ld"),
            // aarch64 large code-model is the default; no extra flag.
            None,
            "NARF_TESTBIN_ELF_AARCH64",
            "narf-testbin",
        );
    } else {
        println!("cargo:rustc-env=NARF_TESTBIN_ELF_X86_64=/dev/null");
        println!("cargo:rustc-env=NARF_TESTBIN_ELF_AARCH64=/dev/null");
    }

    // init + shell: built whenever the kernel intends to actually
    // boot a userspace (boot-init), and ALSO under user-mode-testbin
    // so the testbin runner can opt into init-style smokes if it
    // wants. Both features yield the same env vars.
    if boot_init_enabled || testbin_enabled {
        let init_dir = workspace.join("userspace").join("init");
        build_arch(
            &init_dir,
            &out_dir.join("init-target-x86_64"),
            "x86_64-unknown-none",
            &init_dir.join("init.ld"),
            Some("code-model=large"),
            "NARF_INIT_ELF_X86_64",
            "init",
        );
        build_arch(
            &init_dir,
            &out_dir.join("init-target-aarch64"),
            "aarch64-unknown-none",
            &testbin_dir.join("testbin-aarch64.ld"),
            None,
            "NARF_INIT_ELF_AARCH64",
            "init",
        );

        let shell_dir = workspace.join("userspace").join("shell");
        build_arch(
            &shell_dir,
            &out_dir.join("shell-target-x86_64"),
            "x86_64-unknown-none",
            &shell_dir.join("shell.ld"),
            Some("code-model=large"),
            "NARF_SHELL_ELF_X86_64",
            "shell",
        );
        build_arch(
            &shell_dir,
            &out_dir.join("shell-target-aarch64"),
            "aarch64-unknown-none",
            &testbin_dir.join("testbin-aarch64.ld"),
            None,
            "NARF_SHELL_ELF_AARCH64",
            "shell",
        );

        // getty/login — spawned in place of the shell; establishes the
        // session + controlling tty + foreground pgrp, then execs the shell.
        let getty_dir = workspace.join("userspace").join("getty");
        build_arch(
            &getty_dir,
            &out_dir.join("getty-target-x86_64"),
            "x86_64-unknown-none",
            &getty_dir.join("getty.ld"),
            Some("code-model=large"),
            "NARF_GETTY_ELF_X86_64",
            "getty",
        );
        build_arch(
            &getty_dir,
            &out_dir.join("getty-target-aarch64"),
            "aarch64-unknown-none",
            &testbin_dir.join("testbin-aarch64.ld"),
            None,
            "NARF_GETTY_ELF_AARCH64",
            "getty",
        );

        // Wave-49: coreutils — per-arch env vars
        // NARF_COREUTIL_<UPPER>_ELF_<ARCH>. The kernel includes the
        // bytes via include_bytes! in lib.rs and seeds /bin/<name>
        // at boot.
        for name in ["echo", "pwd", "cat", "ls", "ps"] {
            let crate_dir = workspace.join("userspace").join("coreutils").join(name);
            let upper = name.to_uppercase();
            build_arch(
                &crate_dir,
                &out_dir.join(format!("coreutil-{name}-target-x86_64")),
                "x86_64-unknown-none",
                &crate_dir.join(format!("{name}.ld")),
                Some("code-model=large"),
                &format!("NARF_COREUTIL_{upper}_ELF_X86_64"),
                name,
            );
            // aarch64 reuses testbin's linker; the env var must
            // resolve to something cargo can stat, hence the build.
            build_arch(
                &crate_dir,
                &out_dir.join(format!("coreutil-{name}-target-aarch64")),
                "aarch64-unknown-none",
                &testbin_dir.join("testbin-aarch64.ld"),
                None,
                &format!("NARF_COREUTIL_{upper}_ELF_AARCH64"),
                name,
            );
        }
    } else {
        // Placeholders so include_bytes!() on the consumer side
        // resolves cleanly even when neither feature is enabled.
        println!("cargo:rustc-env=NARF_INIT_ELF_X86_64=/dev/null");
        println!("cargo:rustc-env=NARF_INIT_ELF_AARCH64=/dev/null");
        println!("cargo:rustc-env=NARF_SHELL_ELF_X86_64=/dev/null");
        println!("cargo:rustc-env=NARF_SHELL_ELF_AARCH64=/dev/null");
        for upper in ["ECHO", "PWD", "CAT", "LS", "PS"] {
            println!("cargo:rustc-env=NARF_COREUTIL_{upper}_ELF_X86_64=/dev/null");
            println!("cargo:rustc-env=NARF_COREUTIL_{upper}_ELF_AARCH64=/dev/null");
        }
    }

    // Wave-78: pre-built linux-compat demo binary. Direct-syscall
    // hello-world built from `data/musl-demo/hello_static_x86_64.S`
    // with stock binutils — no Rust crate, no cargo build, no libc.
    // The bytes are always available (checked into the tree); the
    // kernel-side include is gated on the same boot-init feature
    // that gates init/shell/coreutils so non-boot kernel builds
    // don't pay the include cost.
    println!("cargo:rerun-if-changed=data/musl-demo/hello_static_x86_64.S");
    println!("cargo:rerun-if-changed=data/musl-demo/hello_static_x86_64");
    let hello_static = manifest_dir.join("data/musl-demo/hello_static_x86_64");
    println!(
        "cargo:rustc-env=NARF_HELLO_STATIC_ELF_X86_64={}",
        hello_static.display()
    );
    // aarch64 demo binary not built yet; placeholder so include_bytes
    // resolves under cross-arch builds.
    println!("cargo:rustc-env=NARF_HELLO_STATIC_ELF_AARCH64=/dev/null");

    // Wave-78 follow-up 2: real musl-static demo binary. Built via
    // `data/musl-demo/REGEN_musl.sh` (requires musl-gcc); the
    // prebuilt artefact is checked in so the kernel build doesn't
    // need musl on the host.
    println!("cargo:rerun-if-changed=data/musl-demo/hello_musl_x86_64.c");
    println!("cargo:rerun-if-changed=data/musl-demo/hello_musl_x86_64");
    let hello_musl = manifest_dir.join("data/musl-demo/hello_musl_x86_64");
    println!(
        "cargo:rustc-env=NARF_HELLO_MUSL_ELF_X86_64={}",
        hello_musl.display()
    );
    println!("cargo:rustc-env=NARF_HELLO_MUSL_ELF_AARCH64=/dev/null");

    // Wave-78 follow-up 3: dynamic-linked musl demo binary + the
    // ld-musl interpreter it depends on. The binary's PT_INTERP
    // points at `/lib/ld-musl-x86_64.so.1`; NARF stages ld-musl
    // into a kernel-side MemFs mounted at /lib so the loader's
    // VFS-backed PT_INTERP lookup (Wave-75) resolves at exec
    // time.
    println!("cargo:rerun-if-changed=data/musl-demo/hello_musl_dyn_x86_64.c");
    println!("cargo:rerun-if-changed=data/musl-demo/hello_musl_dyn_x86_64");
    let hello_musl_dyn = manifest_dir.join("data/musl-demo/hello_musl_dyn_x86_64");
    println!(
        "cargo:rustc-env=NARF_HELLO_MUSL_DYN_ELF_X86_64={}",
        hello_musl_dyn.display()
    );
    println!("cargo:rustc-env=NARF_HELLO_MUSL_DYN_ELF_AARCH64=/dev/null");

    // Unmodified redis-server (Alpine-style musl build: 7.2.x,
    // `make MALLOC=libc BUILD_TLS=no`, stripped). A real third-party
    // server daemon — dynamic-PIE musl, PT_INTERP=/lib/ld-musl, single
    // DT_NEEDED libc.so. Committed prebuilt (the kernel build doesn't
    // rebuild redis); see data/musl-demo/REGEN_redis.sh for the recipe.
    println!("cargo:rerun-if-changed=data/musl-demo/redis_server_x86_64");
    let redis_server = manifest_dir.join("data/musl-demo/redis_server_x86_64");
    println!(
        "cargo:rustc-env=NARF_REDIS_SERVER_ELF_X86_64={}",
        redis_server.display()
    );
    println!("cargo:rustc-env=NARF_REDIS_SERVER_ELF_AARCH64=/dev/null");

    // mt-echo — multithreaded SO_REUSEPORT TCP echo server. N pthreads,
    // each its own listener (one kernel Listen TCB per worker) on the
    // same port; the stack steers distinct flows to distinct workers so
    // RX is consumed in parallel across cores — the multi-queue/RSS
    // benchmark workload redis (single-threaded) can't be. Committed
    // prebuilt static-musl ELF; recipe in userspace/mt-echo/build.sh.
    println!("cargo:rerun-if-changed=data/musl-demo/mt_echo_server_x86_64");
    let mt_echo = manifest_dir.join("data/musl-demo/mt_echo_server_x86_64");
    println!(
        "cargo:rustc-env=NARF_MT_ECHO_ELF_X86_64={}",
        mt_echo.display()
    );
    println!("cargo:rustc-env=NARF_MT_ECHO_ELF_AARCH64=/dev/null");

    // modetest — libdrm's standard KMS test tool, a real third-party DRM
    // client. Static-musl build of libdrm 2.4.134 + tests/modetest
    // (xf86drm*.c + tests/util + tests/modetest, musl-gcc -static); see
    // data/musl-demo/REGEN_modetest.sh. Exercises /dev/dri/card0 through
    // the actual libdrm ioctl encodings — the Rung 4 desktop-Linux probe.
    println!("cargo:rerun-if-changed=data/musl-demo/modetest_x86_64");
    let modetest = manifest_dir.join("data/musl-demo/modetest_x86_64");
    println!(
        "cargo:rustc-env=NARF_MODETEST_ELF_X86_64={}",
        modetest.display()
    );
    println!("cargo:rustc-env=NARF_MODETEST_ELF_AARCH64=/dev/null");

    // wl_handshake — a libwayland client+server registry handshake over a
    // socketpair (libwayland 1.23 + libffi, static-musl). Rung 7: proves the
    // Wayland wire protocol + transport work on NARF. Recipe: REGEN_wl_handshake.sh.
    println!("cargo:rerun-if-changed=data/musl-demo/wl_handshake_x86_64");
    let wl = manifest_dir.join("data/musl-demo/wl_handshake_x86_64");
    println!(
        "cargo:rustc-env=NARF_WL_HANDSHAKE_ELF_X86_64={}",
        wl.display()
    );
    println!("cargo:rustc-env=NARF_WL_HANDSHAKE_ELF_AARCH64=/dev/null");

    // wl_shm — libwayland wl_shm pool over the Wayland fd-passing path
    // (memfd marshalled via SCM_RIGHTS, server mmaps it). Rung 7.
    println!("cargo:rerun-if-changed=data/musl-demo/wl_shm_x86_64");
    let wlshm = manifest_dir.join("data/musl-demo/wl_shm_x86_64");
    println!("cargo:rustc-env=NARF_WL_SHM_ELF_X86_64={}", wlshm.display());
    println!("cargo:rustc-env=NARF_WL_SHM_ELF_AARCH64=/dev/null");

    // mini_compositor — a minimal Wayland compositor that blits a client's
    // wl_shm buffer onto /dev/fb0. The convergence of the desktop rungs.
    println!("cargo:rerun-if-changed=data/musl-demo/mini_compositor_x86_64");
    let mc = manifest_dir.join("data/musl-demo/mini_compositor_x86_64");
    println!(
        "cargo:rustc-env=NARF_MINI_COMPOSITOR_ELF_X86_64={}",
        mc.display()
    );
    println!("cargo:rustc-env=NARF_MINI_COMPOSITOR_ELF_AARCH64=/dev/null");

    // wl_2proc — two-process Wayland: fork() a compositor (named socket) +
    // an independent client. Cross-process named-socket + SCM_RIGHTS. Rung 7.
    println!("cargo:rerun-if-changed=data/musl-demo/wl_2proc_x86_64");
    let wl2 = manifest_dir.join("data/musl-demo/wl_2proc_x86_64");
    println!("cargo:rustc-env=NARF_WL_2PROC_ELF_X86_64={}", wl2.display());
    println!("cargo:rustc-env=NARF_WL_2PROC_ELF_AARCH64=/dev/null");

    // wl_multi — two independent Wayland client processes composited side by
    // side by one compositor. Multi-window desktop capability. Rung 7.
    println!("cargo:rerun-if-changed=data/musl-demo/wl_multi_x86_64");
    let wlm = manifest_dir.join("data/musl-demo/wl_multi_x86_64");
    println!("cargo:rustc-env=NARF_WL_MULTI_ELF_X86_64={}", wlm.display());
    println!("cargo:rustc-env=NARF_WL_MULTI_ELF_AARCH64=/dev/null");

    // wl_xdg — xdg-shell window mapping (xdg_wm_base/xdg_surface/xdg_toplevel),
    // the protocol every real GUI toolkit uses to map a window. Rung 8.
    println!("cargo:rerun-if-changed=data/musl-demo/wl_xdg_x86_64");
    let wlx = manifest_dir.join("data/musl-demo/wl_xdg_x86_64");
    println!("cargo:rustc-env=NARF_WL_XDG_ELF_X86_64={}", wlx.display());
    println!("cargo:rustc-env=NARF_WL_XDG_ELF_AARCH64=/dev/null");

    // wl_input — wl_seat/wl_keyboard/wl_pointer input delivery to a mapped
    // window; keymap fd travels compositor->client (reverse SCM_RIGHTS). Rung 9.
    println!("cargo:rerun-if-changed=data/musl-demo/wl_input_x86_64");
    let wli = manifest_dir.join("data/musl-demo/wl_input_x86_64");
    println!("cargo:rustc-env=NARF_WL_INPUT_ELF_X86_64={}", wli.display());
    println!("cargo:rustc-env=NARF_WL_INPUT_ELF_AARCH64=/dev/null");

    // wl_kms — present client buffers via DRM/KMS page-flip (dumb buffer +
    // ADDFB2 + PAGE_FLIP) instead of a direct fbdev blit. Rung 10.
    println!("cargo:rerun-if-changed=data/musl-demo/wl_kms_x86_64");
    let wlk = manifest_dir.join("data/musl-demo/wl_kms_x86_64");
    println!("cargo:rustc-env=NARF_WL_KMS_ELF_X86_64={}", wlk.display());
    println!("cargo:rustc-env=NARF_WL_KMS_ELF_AARCH64=/dev/null");

    // wl_evdev — real evdev->wl_seat input bridge: compositor creates a
    // /dev/uinput keyboard, reads the resulting /dev/input/eventN, and
    // forwards the keypress over wl_keyboard. Rung 11.
    println!("cargo:rerun-if-changed=data/musl-demo/wl_evdev_x86_64");
    let wle = manifest_dir.join("data/musl-demo/wl_evdev_x86_64");
    println!("cargo:rustc-env=NARF_WL_EVDEV_ELF_X86_64={}", wle.display());
    println!("cargo:rustc-env=NARF_WL_EVDEV_ELF_AARCH64=/dev/null");

    // simple_shm — UNMODIFIED weston 9.0 clients/simple-shm.c, launched by
    // /bin/wl_app. The first real off-the-shelf GUI client. Rung 12.
    println!("cargo:rerun-if-changed=data/musl-demo/simple_shm_x86_64");
    let ssh = manifest_dir.join("data/musl-demo/simple_shm_x86_64");
    println!(
        "cargo:rustc-env=NARF_SIMPLE_SHM_ELF_X86_64={}",
        ssh.display()
    );
    println!("cargo:rustc-env=NARF_SIMPLE_SHM_ELF_AARCH64=/dev/null");

    // wl_app — compositor that fork+execve's /bin/simple_shm and composites
    // its first real frame. Rung 12.
    println!("cargo:rerun-if-changed=data/musl-demo/wl_app_x86_64");
    let wla = manifest_dir.join("data/musl-demo/wl_app_x86_64");
    println!("cargo:rustc-env=NARF_WL_APP_ELF_X86_64={}", wla.display());
    println!("cargo:rustc-env=NARF_WL_APP_ELF_AARCH64=/dev/null");

    // distro_init — chroot into a real Alpine rootfs (mounted at /mnt from
    // the virtio-blk ext2 image) and exec Alpine's own busybox. Distro boot.
    println!("cargo:rerun-if-changed=data/musl-demo/distro_init_x86_64");
    let dist = manifest_dir.join("data/musl-demo/distro_init_x86_64");
    println!(
        "cargo:rustc-env=NARF_DISTRO_INIT_ELF_X86_64={}",
        dist.display()
    );
    println!("cargo:rustc-env=NARF_DISTRO_INIT_ELF_AARCH64=/dev/null");

    // distro_desktop — chroot into the Alpine rootfs and run the Wayland
    // compositor (+ weston-simple-shm) from inside the distro. Desktop in distro.
    println!("cargo:rerun-if-changed=data/musl-demo/distro_desktop_x86_64");
    let dd = manifest_dir.join("data/musl-demo/distro_desktop_x86_64");
    println!(
        "cargo:rustc-env=NARF_DISTRO_DESKTOP_ELF_X86_64={}",
        dd.display()
    );
    println!("cargo:rustc-env=NARF_DISTRO_DESKTOP_ELF_AARCH64=/dev/null");

    // chroot_run — generic Alpine-chroot launcher running /probe.sh (input/
    // compositor bring-up "run real software, see what breaks" harness).
    println!("cargo:rerun-if-changed=data/musl-demo/chroot_run_x86_64");
    let crun = manifest_dir.join("data/musl-demo/chroot_run_x86_64");
    println!(
        "cargo:rustc-env=NARF_CHROOT_RUN_ELF_X86_64={}",
        crun.display()
    );
    println!("cargo:rustc-env=NARF_CHROOT_RUN_ELF_AARCH64=/dev/null");

    // pthread demo binary — exercises clone3 + futex + per-thread
    // TLS end-to-end. Same dynamic-musl shape as hello_musl_dyn but
    // with -pthread (pulls libpthread, on musl that's libc itself).
    println!("cargo:rerun-if-changed=data/musl-demo/hello_pthread_x86_64.c");
    println!("cargo:rerun-if-changed=data/musl-demo/hello_pthread_x86_64");
    let hello_pthread = manifest_dir.join("data/musl-demo/hello_pthread_x86_64");
    println!(
        "cargo:rustc-env=NARF_HELLO_PTHREAD_ELF_X86_64={}",
        hello_pthread.display()
    );
    println!("cargo:rustc-env=NARF_HELLO_PTHREAD_ELF_AARCH64=/dev/null");

    // Wave-PTY: PTY smoke. Exercises /dev/ptmx open + TIOCSPTLCK
    // + TIOCGPTN + open(/dev/pts/N) + master↔slave round-trip (incl.
    // ECHO mirror). Built from `pty_smoke_x86_64.c` via the uniform
    // static-PIE recipe in the loop below (added to that list), so the
    // `.c` is the single source of truth — no committed binary to drift.

    println!("cargo:rerun-if-changed=data/musl-demo/net_smoke_x86_64");
    let net_smoke = manifest_dir.join("data/musl-demo/net_smoke_x86_64");
    println!(
        "cargo:rustc-env=NARF_NET_SMOKE_ELF_X86_64={}",
        net_smoke.display()
    );
    println!("cargo:rustc-env=NARF_NET_SMOKE_ELF_AARCH64=/dev/null");

    println!("cargo:rerun-if-changed=data/musl-demo/net6_smoke_x86_64");
    let net6_smoke = manifest_dir.join("data/musl-demo/net6_smoke_x86_64");
    println!(
        "cargo:rustc-env=NARF_NET6_SMOKE_ELF_X86_64={}",
        net6_smoke.display()
    );
    println!("cargo:rustc-env=NARF_NET6_SMOKE_ELF_AARCH64=/dev/null");

    println!("cargo:rerun-if-changed=data/musl-demo/unix_smoke_x86_64");
    let unix_smoke = manifest_dir.join("data/musl-demo/unix_smoke_x86_64");
    println!(
        "cargo:rustc-env=NARF_UNIX_SMOKE_ELF_X86_64={}",
        unix_smoke.display()
    );
    println!("cargo:rustc-env=NARF_UNIX_SMOKE_ELF_AARCH64=/dev/null");

    // These smokes all share one uniform static-PIE compile recipe
    // (musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large). Rather than commit
    // the prebuilt ELFs, we build each from its checked-in `.c` source
    // into OUT_DIR when musl-gcc is on PATH (the musl-demo CI job installs
    // musl-tools). When it isn't, we fall back to an empty placeholder
    // (/dev/null) — only `boot-init` builds embed these, and only the
    // musl-demo job actually runs them, so the other jobs are unaffected.
    // The `REGEN_<name>.sh` scripts document the same recipe for manual
    // regeneration. The remaining non-uniform smokes (hello_musl* / pthread)
    // keep their committed binaries and individual handling above.
    let musl_gcc = which("musl-gcc");
    if musl_gcc.is_none() {
        println!(
            "cargo:warning=musl-demo: musl-gcc not on PATH; smokes use empty \
             placeholders (run via the musl-demo job, which installs musl-tools)"
        );
    }

    // GCC ≥ 16's musl-gcc link spec emits an `-latomic_asneeded`
    // placeholder library that does not exist on disk, so every
    // musl-demo compile below fails at link with `cannot find
    // -latomic_asneeded` on bleeding-edge toolchains (Arch/CachyOS).
    // Older GCC (Ubuntu CI's musl-tools) never emits it. Drop an empty
    // archive of that exact name into OUT_DIR and feed an explicit
    // `-L OUT_DIR`: ld searches command-line `-L` dirs ahead of the
    // spec's system dirs, so it resolves the placeholder to our empty
    // archive where the spec emits it, and the flag is inert everywhere
    // else. (An explicit `-L` is honoured even though the musl specs
    // drop `LIBRARY_PATH`; an empty archive is a valid archive ld links
    // zero members from.) The build script depends only on `ar`, which
    // ships with the same binutils as the linker.
    let atomic_stub_l: Option<String> = musl_gcc.as_ref().map(|_| {
        let stub = out_dir.join("libatomic_asneeded.a");
        let _ = std::fs::remove_file(&stub);
        let ok = Command::new("ar")
            .arg("rcs")
            .arg(&stub)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            panic!(
                "musl-demo: failed to create the libatomic_asneeded link stub at {} \
                 (is `ar` on PATH?)",
                stub.display()
            );
        }
        format!("-L{}", out_dir.display())
    });
    for test in [
        "fork_pipe_smoke",
        "epoll_smoke",
        "signal_smoke",
        "fs_smoke",
        "eventfd_smoke",
        "getrandom_smoke",
        "sockpair_smoke",
        "accept4_smoke",
        "mremap_smoke",
        "sendfile_smoke",
        "creds_smoke",
        "waitid_smoke",
        "ppoll_smoke",
        "sysinfo_smoke",
        "splice_smoke",
        "barrier_smoke",
        "closerange_smoke",
        "sched_smoke",
        "mcore_smoke",
        "sync_smoke",
        "dup3fam_smoke",
        "robust_smoke",
        "renameat2_smoke",
        "pidfdsig_smoke",
        "host_smoke",
        "mmsg_smoke",
        "openat2_smoke",
        "pv_smoke",
        "cap_smoke",
        "itimer_smoke",
        "xattr_smoke",
        "perf_smoke",
        "fhint_smoke",
        "mq_smoke",
        "inotify_smoke",
        "pkey_smoke",
        "pvm_smoke",
        "mempolicy_smoke",
        "schedattr_smoke",
        "adjtimex_smoke",
        "introspect_smoke",
        "vio_smoke",
        "sysvipc_smoke",
        "shm_smoke",
        "xattr2_smoke",
        "fsmisc_smoke",
        "creds2_smoke",
        "sig2_smoke",
        "mem2_smoke",
        "psched_smoke",
        "futex2_smoke",
        "futex_contend_smoke",
        "keyring_smoke",
        "inotify2_smoke",
        "fanotify_smoke",
        "landlock_smoke",
        "lsm_smoke",
        "vdso_smoke",
        "fhandle_smoke",
        "mountapi_smoke",
        "jobctl_smoke",
        "jobctl2_smoke",
        "navfs_smoke",
        "oci_smoke",
        "netserve_smoke",
        "pipeof_smoke",
        "relpaths_smoke",
        "consoletty_smoke",
        "alarmloop_smoke",
        "preemptsched_smoke",
        "procfs2_smoke",
        "pty_smoke",
        "numa_smoke",
        "fb_smoke",
        "scm_smoke",
        "drm_smoke",
        "tfd_epoll_smoke",
    ] {
        let src = manifest_dir.join(format!("data/musl-demo/{test}_x86_64.c"));
        println!("cargo:rerun-if-changed={}", src.display());
        let x86_path = match &musl_gcc {
            Some(cc) => {
                let out = out_dir.join(format!("{test}_x86_64"));
                let mut cmd = Command::new(cc);
                cmd.args(["-O2", "-Wall", "-fPIE", "-pie", "-mcmodel=large"]);
                if let Some(l) = &atomic_stub_l {
                    cmd.arg(l);
                }
                let output = cmd.arg(&src).arg("-o").arg(&out).output();
                match output {
                    Ok(o) if o.status.success() => out.display().to_string(),
                    // musl-gcc IS present but the source failed to compile —
                    // that's a real bug, not a missing-toolchain fallback.
                    // Hard-fail the build with the compiler's stderr so it
                    // surfaces here, not as an "exec failed" + 900s timeout in
                    // the musl-demo run. (A placeholder is only legitimate when
                    // musl-gcc is absent — the `None` arm below.)
                    Ok(o) => panic!(
                        "musl-demo: failed to compile {test} ({}):\n{}",
                        src.display(),
                        String::from_utf8_lossy(&o.stderr)
                    ),
                    Err(e) => panic!("musl-demo: could not invoke musl-gcc for {test}: {e}"),
                }
            }
            None => "/dev/null".to_string(),
        };
        let upper = test.to_uppercase();
        println!("cargo:rustc-env=NARF_{upper}_ELF_X86_64={x86_path}");
        println!("cargo:rustc-env=NARF_{upper}_ELF_AARCH64=/dev/null");
    }

    // ── vDSO: real linux-vdso.so.1 for each arch ────────────────────
    // A PIC shared object (clang + lld, no libc) the kernel maps into every
    // process; its __vdso_* / __kernel_* functions read the CPU counter and
    // the kernel-published vvar page to serve clock_gettime without a
    // syscall. Built for BOTH arches (both are embedded via cfg in lib.rs).
    // When clang/lld is absent the image is an empty placeholder and the
    // kernel simply doesn't advertise a vDSO (libc falls back to syscalls).
    {
        let vdso_src = manifest_dir.join("data/vdso/vdso.c");
        println!("cargo:rerun-if-changed={}", vdso_src.display());
        let clang = which("clang");
        let have_lld = which("ld.lld").is_some();
        for (arch, triple) in [
            ("X86_64", "x86_64-unknown-linux-gnu"),
            ("AARCH64", "aarch64-unknown-linux-gnu"),
        ] {
            let lds = manifest_dir.join(format!("data/vdso/vdso_{}.lds", arch.to_lowercase()));
            println!("cargo:rerun-if-changed={}", lds.display());
            let path = match (&clang, have_lld) {
                (Some(cc), true) => {
                    let out = out_dir.join(format!("vdso_{}.so", arch.to_lowercase()));
                    let o = Command::new(cc)
                        .args([
                            &format!("--target={triple}"),
                            "-nostdlib",
                            "-shared",
                            "-fPIC",
                            "-fno-stack-protector",
                            "-fcf-protection=none",
                            "-O2",
                            "-ffreestanding",
                        ])
                        .arg(format!("-Wl,-T,{}", lds.display()))
                        .args([
                            "-Wl,--soname=linux-vdso.so.1",
                            "-Wl,--no-undefined",
                            "-Wl,-z,max-page-size=4096",
                            "-Wl,--hash-style=both",
                            "-Wl,-Bsymbolic",
                            "-fuse-ld=lld",
                        ])
                        .arg(&vdso_src)
                        .arg("-o")
                        .arg(&out)
                        .output();
                    match o {
                        Ok(o) if o.status.success() => out.display().to_string(),
                        // clang IS present but the build broke — real bug.
                        Ok(o) => panic!(
                            "vdso: failed to build {arch} ({}):\n{}",
                            vdso_src.display(),
                            String::from_utf8_lossy(&o.stderr)
                        ),
                        Err(e) => panic!("vdso: could not invoke clang for {arch}: {e}"),
                    }
                }
                _ => "/dev/null".to_string(),
            };
            println!("cargo:rustc-env=NARF_VDSO_ELF_{arch}={path}");
        }
    }

    // ── multi-DSO dynamic-linking test (x86_64) ─────────────────────
    // liba.so (leaf) + libb.so (needs liba) + the dynamic main (dso_smoke,
    // needs libb + liba + libc). The kernel seeds liba/libb into /lib so
    // ld-musl resolves the two-deep DT_NEEDED chain via file-backed mmap.
    {
        let dso_dir = manifest_dir.join("data/dsotest");
        for f in ["liba.c", "libb.c", "dso_smoke.c"] {
            println!("cargo:rerun-if-changed={}", dso_dir.join(f).display());
        }
        let (liba, libb, main) = match which("musl-gcc") {
            Some(cc) => {
                let liba = out_dir.join("liba.so");
                let libb = out_dir.join("libb.so");
                let main = out_dir.join("dso_smoke_x86_64");
                let outs = out_dir.display().to_string();
                let run = |args: &[&str], what: &str| {
                    let o = Command::new(&cc)
                        .current_dir(&dso_dir)
                        .args(args)
                        .output()
                        .unwrap_or_else(|e| panic!("dsotest: spawn musl-gcc for {what}: {e}"));
                    if !o.status.success() {
                        panic!(
                            "dsotest: {what} failed:\n{}",
                            String::from_utf8_lossy(&o.stderr)
                        );
                    }
                };
                run(
                    &[
                        "-shared",
                        "-fPIC",
                        "-O2",
                        "-Wl,-soname,liba.so",
                        "liba.c",
                        "-o",
                        &liba.display().to_string(),
                    ],
                    "liba.so",
                );
                run(
                    &[
                        "-shared",
                        "-fPIC",
                        "-O2",
                        "-Wl,-soname,libb.so",
                        "libb.c",
                        "-L",
                        &outs,
                        "-la",
                        "-Wl,-rpath,/lib",
                        "-o",
                        &libb.display().to_string(),
                    ],
                    "libb.so",
                );
                run(
                    &[
                        "-O2",
                        "-fPIE",
                        "-pie",
                        "-mcmodel=large",
                        "dso_smoke.c",
                        "-L",
                        &outs,
                        "-lb",
                        "-la",
                        "-Wl,-rpath,/lib",
                        "-o",
                        &main.display().to_string(),
                    ],
                    "dso_smoke",
                );
                (
                    liba.display().to_string(),
                    libb.display().to_string(),
                    main.display().to_string(),
                )
            }
            None => (
                "/dev/null".to_string(),
                "/dev/null".to_string(),
                "/dev/null".to_string(),
            ),
        };
        println!("cargo:rustc-env=NARF_LIBA_SO={liba}");
        println!("cargo:rustc-env=NARF_LIBB_SO={libb}");
        println!("cargo:rustc-env=NARF_DSO_SMOKE_ELF_X86_64={main}");
        println!("cargo:rustc-env=NARF_DSO_SMOKE_ELF_AARCH64=/dev/null");
    }

    // ── per-DSO TLS test (x86_64) ───────────────────────────────────
    // libtls.so carries thread-local state reached via general-dynamic TLS
    // (__tls_get_addr); tls_smoke links it dynamically. The kernel seeds
    // libtls.so into /lib so ld-musl loads it (file-backed mmap) and sets
    // up the per-module TLS block at runtime.
    {
        let tls_dir = manifest_dir.join("data/tlstest");
        for f in ["libtls.c", "tls_smoke.c"] {
            println!("cargo:rerun-if-changed={}", tls_dir.join(f).display());
        }
        let (libtls, main) = match which("musl-gcc") {
            Some(cc) => {
                let libtls = out_dir.join("libtls.so");
                let main = out_dir.join("tls_smoke_x86_64");
                let outs = out_dir.display().to_string();
                let run = |args: &[&str], what: &str| {
                    let o = Command::new(&cc)
                        .current_dir(&tls_dir)
                        .args(args)
                        .output()
                        .unwrap_or_else(|e| panic!("tlstest: spawn musl-gcc for {what}: {e}"));
                    if !o.status.success() {
                        panic!(
                            "tlstest: {what} failed:\n{}",
                            String::from_utf8_lossy(&o.stderr)
                        );
                    }
                };
                run(
                    &[
                        "-shared",
                        "-fPIC",
                        "-O2",
                        "-Wl,-soname,libtls.so",
                        "libtls.c",
                        "-o",
                        &libtls.display().to_string(),
                    ],
                    "libtls.so",
                );
                run(
                    &[
                        "-O2",
                        "-fPIE",
                        "-pie",
                        "-mcmodel=large",
                        "tls_smoke.c",
                        "-L",
                        &outs,
                        "-ltls",
                        "-Wl,-rpath,/lib",
                        "-o",
                        &main.display().to_string(),
                    ],
                    "tls_smoke",
                );
                (libtls.display().to_string(), main.display().to_string())
            }
            None => ("/dev/null".to_string(), "/dev/null".to_string()),
        };
        println!("cargo:rustc-env=NARF_LIBTLS_SO={libtls}");
        println!("cargo:rustc-env=NARF_TLS_SMOKE_ELF_X86_64={main}");
        println!("cargo:rustc-env=NARF_TLS_SMOKE_ELF_AARCH64=/dev/null");
    }

    // ld-musl interpreter. Read from $LDMUSL_PATH if set, else
    // /lib/ld-musl-x86_64.so.1 (Arch's path; same default xtask
    // image uses). If absent on the host, point at /dev/null so
    // include_bytes!() resolves to an empty slice — the consumer
    // skips the /lib mount when the slice is empty.
    println!("cargo:rerun-if-env-changed=LDMUSL_PATH");
    // Try `$LDMUSL_PATH` first, then a list of common distro
    // locations. Arch puts the dynamic linker at `/lib/ld-musl-*.so.1`;
    // Ubuntu's `musl-tools` package ships the same file at
    // `/usr/lib/x86_64-linux-musl/libc.so` (libc.so IS the dynamic
    // linker for musl) and at `/lib/x86_64-linux-musl/libc.so.1`. The
    // first path that canonicalises wins; we fall back to /dev/null
    // (empty NARF_LD_MUSL slice → /lib mount skipped → dyn binaries
    // fail to exec).
    let ld_musl_candidates: Vec<String> = {
        let mut v = Vec::new();
        if let Ok(env_path) = env::var("LDMUSL_PATH") {
            v.push(env_path);
        }
        v.extend(
            [
                "/lib/ld-musl-x86_64.so.1",
                "/usr/lib/ld-musl-x86_64.so.1",
                "/usr/lib/x86_64-linux-musl/libc.so",
                "/lib/x86_64-linux-musl/libc.so.1",
                "/lib/x86_64-linux-musl/libc.so",
            ]
            .into_iter()
            .map(String::from),
        );
        v
    };
    let (ld_musl_canonical, ld_musl_source) = ld_musl_candidates
        .iter()
        .find_map(|p| {
            std::fs::canonicalize(p)
                .ok()
                .map(|c| (c.display().to_string(), p.clone()))
        })
        .unwrap_or_else(|| ("/dev/null".into(), "/dev/null".into()));
    let ld_musl_path = ld_musl_source;
    println!(
        "cargo:rerun-if-changed={}",
        if ld_musl_canonical == "/dev/null" {
            ld_musl_path.as_str()
        } else {
            ld_musl_canonical.as_str()
        }
    );
    println!("cargo:rustc-env=NARF_LD_MUSL_X86_64={}", ld_musl_canonical);
    println!("cargo:rustc-env=NARF_LD_MUSL_AARCH64=/dev/null");

    let libc_validate_enabled = env::var_os("CARGO_FEATURE_NARF_LIBC_VALIDATE").is_some();
    if libc_validate_enabled {
        let validate_dir = workspace.join("narf-libc").join("validate");
        build_arch(
            &validate_dir,
            &out_dir.join("narf-libc-validate-target-x86_64"),
            "x86_64-unknown-none",
            &validate_dir.join("validate.ld"),
            Some("code-model=large"),
            "NARF_LIBC_VALIDATE_ELF_X86_64",
            "narf-libc-validate",
        );
    } else {
        println!("cargo:rustc-env=NARF_LIBC_VALIDATE_ELF_X86_64=/dev/null");
    }
}

/// Locate an executable on `PATH`, returning its full path. Used to
/// gate musl-gcc-dependent smoke compilation (mirrors the busybox
/// build's gate).
fn which(prog: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    env::split_paths(&path)
        .map(|dir| dir.join(prog))
        .find(|full| full.is_file())
}

fn build_arch(
    testbin_dir: &PathBuf,
    target_dir: &std::path::Path,
    triple: &str,
    linker_script: &std::path::Path,
    extra_flag: Option<&str>,
    env_var: &str,
    bin_name: &str,
) {
    let mut flags: Vec<String> = vec![
        "-C".into(),
        format!("link-arg=-T{}", linker_script.display()),
        "-C".into(),
        "relocation-model=static".into(),
    ];
    if let Some(f) = extra_flag {
        flags.push("-C".into());
        flags.push(f.into());
    }
    let encoded_rustflags = flags.join("\x1f");

    let status = Command::new(env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
        .arg("build")
        .arg("--release")
        .arg("--target")
        .arg(triple)
        .arg("--target-dir")
        .arg(target_dir)
        .arg("-Zbuild-std=core")
        .arg("-Zbuild-std-features=")
        .current_dir(testbin_dir)
        .env("CARGO_ENCODED_RUSTFLAGS", &encoded_rustflags)
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_TARGET_DIR")
        .status()
        .unwrap_or_else(|e| panic!("spawn cargo for narf-testbin {triple}: {e}"));
    if !status.success() {
        panic!("narf-testbin {triple} build failed with {status}");
    }

    let bin = target_dir.join(triple).join("release").join(bin_name);
    assert!(
        bin.exists(),
        "{bin_name} output missing for {triple}: {}",
        bin.display()
    );
    println!("cargo:rustc-env={}={}", env_var, bin.display());
}
