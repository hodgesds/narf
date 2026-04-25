//! Build narf-testbin (the Rust user binary) and expose its ELF
//! bytes to the kernel_test harness via a compile-time env var.
//!
//! Gated by the `user-mode-e2e` cargo feature so default builds
//! don't pay the cost. When the feature is off, we still set
//! `NARF_TESTBIN_ELF` to an empty-string placeholder so
//! `env!()` resolves cleanly; the gated test body checks the
//! byte-length and skips if empty.
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

    let enabled = env::var_os("CARGO_FEATURE_USER_MODE_E2E").is_some();
    if !enabled {
        // Feature off — placeholders so both `env!()`-based
        // `include_bytes!` sites compile cleanly.
        println!("cargo:rustc-env=NARF_TESTBIN_ELF_X86_64=/dev/null");
        println!("cargo:rustc-env=NARF_TESTBIN_ELF_AARCH64=/dev/null");
        return;
    }

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let workspace = manifest_dir.parent().unwrap().to_path_buf();
    let testbin_dir = workspace.join("userspace").join("testbin");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    build_arch(
        &testbin_dir,
        &out_dir.join("testbin-target-x86_64"),
        "x86_64-unknown-none",
        &testbin_dir.join("testbin.ld"),
        // `code-model=large` because the user vaddr is past the
        // 2-GiB reach of small-model relocations.
        Some("code-model=large"),
        "NARF_TESTBIN_ELF_X86_64",
    );
    build_arch(
        &testbin_dir,
        &out_dir.join("testbin-target-aarch64"),
        "aarch64-unknown-none",
        &testbin_dir.join("testbin-aarch64.ld"),
        // aarch64 large code-model is the default; no extra flag.
        None,
        "NARF_TESTBIN_ELF_AARCH64",
    );
}

fn build_arch(
    testbin_dir: &PathBuf,
    target_dir: &PathBuf,
    triple: &str,
    linker_script: &PathBuf,
    extra_flag: Option<&str>,
    env_var: &str,
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
        .join("narf-testbin");
    assert!(bin.exists(), "narf-testbin output missing for {triple}: {}", bin.display());
    println!("cargo:rustc-env={}={}", env_var, bin.display());
}
