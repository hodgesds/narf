//! Assemble the libc-free x86_64 guests the adapter's kernel tests run.
//!
//! The guests are built only for an x86_64 target with the `kernel-test`
//! feature on, so ordinary builds need no binutils. Each guest is a static,
//! stripped ELF linked at `0x80_0000_1000`; the canonical guest is the same
//! file the Linux cells of the Narf/Linux parity comparison execute.

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

const GUESTS: [(&str, &str); 16] = [
    ("canonical", "REVERIE_NARF_GUEST_CANONICAL"),
    ("probe", "REVERIE_NARF_GUEST_PROBE"),
    ("fork", "REVERIE_NARF_GUEST_FORK"),
    ("pipe", "REVERIE_NARF_GUEST_PIPE"),
    ("exec", "REVERIE_NARF_GUEST_EXEC"),
    ("vfork", "REVERIE_NARF_GUEST_VFORK"),
    ("ring", "REVERIE_NARF_GUEST_RING"),
    ("badframe", "REVERIE_NARF_GUEST_BADFRAME"),
    ("reaper", "REVERIE_NARF_GUEST_REAPER"),
    ("vdso", "REVERIE_NARF_GUEST_VDSO"),
    ("mtexit", "REVERIE_NARF_GUEST_MTEXIT"),
    ("rich", "REVERIE_NARF_GUEST_RICH"),
    ("window", "REVERIE_NARF_GUEST_WINDOW"),
    ("sigpark", "REVERIE_NARF_GUEST_SIGPARK"),
    ("execfail", "REVERIE_NARF_GUEST_EXECFAIL"),
    ("nointerp", "REVERIE_NARF_GUEST_NOINTERP"),
];

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let x86_64 = env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("x86_64");
    let kernel_test = env::var_os("CARGO_FEATURE_KERNEL_TEST").is_some();
    for (name, var) in GUESTS {
        let source = manifest_dir.join(format!("guests/{name}_x86_64.S"));
        println!("cargo:rerun-if-changed={}", source.display());
        if x86_64 && kernel_test {
            let binary = build_guest(&source, &out_dir, name);
            println!("cargo:rustc-env={var}={}", binary.display());
        }
    }
}

fn build_guest(source: &Path, out_dir: &Path, name: &str) -> PathBuf {
    let object = out_dir.join(format!("{name}-guest.o"));
    let binary = out_dir.join(format!("{name}-guest"));
    run(
        Command::new("as")
            .args(["--64", "-o"])
            .arg(&object)
            .arg(source),
        "as",
    );
    run(
        Command::new("ld")
            .args([
                "-static",
                "-nostdlib",
                "-z",
                "noexecstack",
                "-Ttext-segment=0x8000001000",
                "-o",
            ])
            .arg(&binary)
            .arg(&object),
        "ld",
    );
    run(
        Command::new("strip").arg("--strip-all").arg(&binary),
        "strip",
    );
    binary
}

fn run(command: &mut Command, tool: &str) {
    let status = command
        .status()
        .unwrap_or_else(|error| panic!("reverie-narf-adapter guests need GNU {tool}: {error}"));
    assert!(
        status.success(),
        "{tool} failed for a reverie-narf-adapter guest: {status}"
    );
}
