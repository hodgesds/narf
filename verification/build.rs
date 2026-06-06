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
    // boot-init feature: init + shell binaries.
    println!("cargo:rerun-if-changed=../userspace/init/src/main.rs");
    println!("cargo:rerun-if-changed=../userspace/init/init.ld");
    println!("cargo:rerun-if-changed=../userspace/init/Cargo.toml");
    println!("cargo:rerun-if-changed=../userspace/shell/src/main.rs");
    println!("cargo:rerun-if-changed=../userspace/shell/src/exec.rs");
    println!("cargo:rerun-if-changed=../userspace/shell/src/parser.rs");
    println!("cargo:rerun-if-changed=../userspace/shell/shell.ld");
    println!("cargo:rerun-if-changed=../userspace/shell/Cargo.toml");
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

    // Wave-PTY: PTY smoke demo source + REGEN script live in
    // `data/musl-demo/` and document the musl-side flow
    // (open /dev/ptmx → TIOCSPTLCK → TIOCGPTN → open /dev/pts/N →
    // round-trip). The binary is NOT wired into the build today —
    // musl's `open()` issues a Linux-ABI `(cstr, flags, mode)`
    // syscall but NARF's `sys_open` still uses the legacy
    // `(ptr, len, mnt_ptr, mnt_len, flags)` shape (mirror of the
    // execve(2)/stat(2) cutover that already landed). Once
    // `sys_open` is cut to Linux ABI, re-add the env line below
    // and the corresponding seeding in `bare_main.rs` + the
    // musl-demo case in xtask. Until then the demo lives as a
    // documented C source so the integration story is clear.
    println!("cargo:rerun-if-changed=data/musl-demo/pty_smoke_x86_64.c");

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

fn build_arch(
    testbin_dir: &PathBuf,
    target_dir: &PathBuf,
    triple: &str,
    linker_script: &PathBuf,
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
