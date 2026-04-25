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

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let workspace = manifest_dir.parent().unwrap().to_path_buf();
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    let testbin_enabled = env::var_os("CARGO_FEATURE_USER_MODE_TESTBIN").is_some();
    if testbin_enabled {
        let testbin_dir = workspace.join("userspace").join("testbin");
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
        // Feature off — placeholders so both `env!()`-based
        // `include_bytes!` sites compile cleanly.
        println!("cargo:rustc-env=NARF_TESTBIN_ELF_X86_64=/dev/null");
        println!("cargo:rustc-env=NARF_TESTBIN_ELF_AARCH64=/dev/null");
    }

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
        .arg("--target").arg(triple)
        .arg("--target-dir").arg(target_dir)
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

    let bin = target_dir
        .join(triple)
        .join("release")
        .join(bin_name);
    assert!(bin.exists(), "{bin_name} output missing for {triple}: {}", bin.display());
    println!("cargo:rustc-env={}={}", env_var, bin.display());
}
