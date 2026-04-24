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
        // Feature off — put a harmless placeholder path so
        // `env!("NARF_TESTBIN_ELF")` still compiles on the gated
        // `include_bytes!` site.
        println!("cargo:rustc-env=NARF_TESTBIN_ELF=/dev/null");
        return;
    }

    // Find the workspace root (parent of `verification`).
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let workspace = manifest_dir.parent().unwrap().to_path_buf();
    let testbin_dir = workspace.join("userspace").join("testbin");

    // OUT_DIR to isolate the testbin's target directory from the
    // host workspace's target — avoids LTO / build-std collisions.
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let target_dir = out_dir.join("testbin-target");

    // Link-arg that feeds our script through the kernel-target
    // rustc invocation. `-T` picks up the linker script.
    let linker_script = testbin_dir.join("testbin.ld");
    // Use CARGO_ENCODED_RUSTFLAGS so nothing from the outer
    // workspace's `.cargo/config.toml` leaks through (its
    // `[target.x86_64-unknown-none].rustflags` carries the
    // kernel linker script + `code-model=kernel`, both wrong for
    // user code). Encoded form is unit-separator-delimited.
    let encoded_rustflags = [
        "-C",
        &format!("link-arg=-T{}", linker_script.display()),
        "-C",
        "relocation-model=static",
        // The testbin links at 0x0000_0080_0000_1000 — well above
        // the 2-GiB reach of code-model=small's R_X86_64_32S
        // relocations. Large model uses 64-bit MOVABS for rodata
        // references (slower, but correct for this vaddr).
        "-C",
        "code-model=large",
    ].join("\x1f");

    let status = Command::new(env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
        .arg("build")
        .arg("--release")
        .arg("--target").arg("x86_64-unknown-none")
        .arg("--target-dir").arg(&target_dir)
        // Nightly-only: build `core` from source for the
        // `x86_64-unknown-none` target (rustup doesn't ship a
        // precompiled `core` for the triple).
        .arg("-Zbuild-std=core")
        .arg("-Zbuild-std-features=")
        // Run from the testbin dir so cargo's config walk-up
        // finds `userspace/testbin/.cargo/config.toml` (which
        // clears the outer kernel-flags) instead of the outer
        // workspace config. `--manifest-path` isn't enough — the
        // config resolution follows CWD, not manifest location.
        .current_dir(&testbin_dir)
        .env("CARGO_ENCODED_RUSTFLAGS", &encoded_rustflags)
        .env_remove("RUSTFLAGS")
        // Clear the outer workspace's CARGO_TARGET_DIR so the
        // nested invocation doesn't race on locks.
        .env_remove("CARGO_TARGET_DIR")
        .status()
        .expect("spawn cargo for narf-testbin");
    if !status.success() {
        panic!("narf-testbin build failed with {status}");
    }

    let bin = target_dir
        .join("x86_64-unknown-none")
        .join("release")
        .join("narf-testbin");
    assert!(bin.exists(), "narf-testbin output missing: {}", bin.display());
    println!("cargo:rustc-env=NARF_TESTBIN_ELF={}", bin.display());
}
