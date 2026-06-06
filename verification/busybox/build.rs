//! Download + build BusyBox at NARF's PML4[1] user vaddr.
//!
//! Steps (skipped entirely if musl-gcc isn't on PATH):
//!   1. Download `busybox-<VERSION>.tar.bz2` to `OUT_DIR/` if not
//!      already cached.
//!   2. Verify SHA-256 against the pinned hash.
//!   3. Unpack into `OUT_DIR/busybox-<VERSION>/`.
//!   4. `make defconfig` + override `CONFIG_STATIC=y` so the
//!      resulting binary doesn't need a dynamic linker.
//!   5. `make` with custom `EXTRA_LDFLAGS` so the program loads at
//!      `0x8000001000` (PML4[1], same range narf-libc uses; NARF's
//!      ELF loader maps PT_LOAD with U=1 only in PML4[1+]).
//!   6. Copy the resulting `busybox` ELF to a stable path and
//!      publish its location via `cargo:rustc-env`.
//!
//! All artefacts live under `OUT_DIR` so Cargo's standard
//! incremental-build machinery handles caching: the build runs
//! ONCE per `cargo clean` cycle. The download is conditioned on
//! file existence so subsequent rebuilds skip it even after
//! `cargo clean` if the tarball is already in `OUT_DIR/cache/`
//! (which we use as a non-cleaned cache hint).

use std::path::{Path, PathBuf};
use std::process::Command;

const BB_VERSION: &str = "1.36.1";
const BB_SHA256: &str = "b8cc24c9574d809e7279c3be349795c5d5ceb6fdf19ca709f80cde50e47de314";

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();

    // aarch64: not built; fall back to /dev/null so include_bytes!
    // resolves but produces an empty slice.
    if target_arch != "x86_64" {
        println!("cargo:rustc-env=NARF_BUSYBOX_X86_64=/dev/null");
        println!("cargo:rustc-env=NARF_BUSYBOX_AARCH64=/dev/null");
        return;
    }

    // Always set the aarch64 fallback regardless — the const
    // include_bytes! for it still needs to resolve.
    println!("cargo:rustc-env=NARF_BUSYBOX_AARCH64=/dev/null");

    // musl-gcc gate: without it the build can't run. Fall back to
    // /dev/null and let the kernel-side consumer skip seeding
    // /bin/busybox; the demo just won't work until musl is
    // installed.
    if which("musl-gcc").is_none() {
        eprintln!(
            "narf-busybox build: musl-gcc not on PATH; /bin/busybox \
             will not be seeded. Install musl-tools (Ubuntu) or musl \
             (Arch) to enable the busybox demo."
        );
        println!("cargo:rustc-env=NARF_BUSYBOX_X86_64=/dev/null");
        return;
    }
    // make + tar + curl|wget are standard; bail loudly if missing.
    for tool in ["make", "tar"] {
        if which(tool).is_none() {
            panic!(
                "narf-busybox build: `{}` not on PATH — install build tooling",
                tool
            );
        }
    }
    let downloader = if which("curl").is_some() {
        "curl"
    } else if which("wget").is_some() {
        "wget"
    } else {
        panic!("narf-busybox build: neither curl nor wget on PATH");
    };

    let out_bin = out_dir.join("busybox_x86_64");
    if out_bin.exists() {
        publish(&out_bin);
        return;
    }

    let cache = out_dir.join("cache");
    std::fs::create_dir_all(&cache).expect("mkdir cache");
    let tarball = cache.join(format!("busybox-{}.tar.bz2", BB_VERSION));
    let src = out_dir.join(format!("busybox-{}", BB_VERSION));

    if !tarball.exists() {
        download(downloader, &tarball);
    }
    verify_sha256(&tarball);

    if !src.exists() {
        eprintln!("narf-busybox: unpacking {}", tarball.display());
        let status = Command::new("tar")
            .args(["xjf", tarball.to_str().unwrap()])
            .current_dir(&out_dir)
            .status()
            .expect("spawn tar");
        if !status.success() {
            panic!("narf-busybox: tar exit {status}");
        }
    }

    // make defconfig — produces a reasonable .config to start.
    run_make(&src, &["defconfig"]);

    // Force static linking. defconfig is dynamic-by-default; we
    // can't use dynamic-musl on the kernel-side seed because the
    // dyn-linker path is per-target (works for hello_musl_dyn via
    // /lib MemFs, but busybox is a single static demo).
    enable_config(&src.join(".config"), "CONFIG_STATIC", "y");
    // The default CONFIG_TC=y enables `tc` which references kernel
    // headers not always present on host build systems; the rest
    // of busybox builds without it.
    enable_config(&src.join(".config"), "CONFIG_TC", "n");
    // Re-resolve config (resolves any dependencies we toggled).
    run_make(&src, &["oldconfig"]);

    // The big one — actually build. `EXTRA_LDFLAGS` lands the
    // binary at 0x8000001000 (NARF's PML4[1] user range, matching
    // what hello_static + hello_musl use). `--defsym=_DYNAMIC=...`
    // satisfies the PC32 reloc against `_DYNAMIC` that
    // musl-gcc's Scrt1.o emits even in static builds — the symbol
    // is never used but the relocation needs to be encodable
    // within ±2 GiB of .text.
    let nproc = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(2)
        .to_string();
    run_make(
        &src,
        &[
            "-j",
            &nproc,
            "CC=musl-gcc",
            // musl-gcc uses -nostdinc + -isystem /usr/lib/musl/include,
            // so the standard /usr/include path isn't searched.
            // BusyBox needs `linux/*` UAPI headers (kd.h, etc.) that
            // ship with the host's linux-api-headers package, NOT
            // with musl. `-idirafter` adds /usr/include AFTER
            // musl's search dirs so a plain `#include <stdio.h>`
            // still finds musl's, but `#include <linux/kd.h>`
            // (which musl doesn't ship) falls through to the
            // system path.
            "EXTRA_CFLAGS=-idirafter /usr/include",
            "EXTRA_LDFLAGS=-Wl,-L/usr/lib -Wl,-Ttext-segment=0x8000001000 \
             -Wl,--defsym=_DYNAMIC=0x8000001000",
        ],
    );

    // Strip + copy out.
    let built = src.join("busybox");
    if !built.exists() {
        panic!(
            "narf-busybox: build completed but {} not found",
            built.display()
        );
    }
    std::fs::copy(&built, &out_bin).expect("copy busybox");
    let _ = Command::new("strip")
        .args(["--strip-all", out_bin.to_str().unwrap()])
        .status();

    publish(&out_bin);
}

fn publish(path: &Path) {
    println!("cargo:rustc-env=NARF_BUSYBOX_X86_64={}", path.display());
    println!(
        "narf-busybox: ready at {} ({} bytes)",
        path.display(),
        std::fs::metadata(path).map(|m| m.len()).unwrap_or(0)
    );
}

fn which(tool: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let p = dir.join(tool);
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

fn download(downloader: &str, dst: &Path) {
    let url = format!(
        "https://busybox.net/downloads/busybox-{}.tar.bz2",
        BB_VERSION
    );
    eprintln!("narf-busybox: downloading {} → {}", url, dst.display());
    let status = match downloader {
        "curl" => Command::new("curl")
            .args(["-L", "--fail", "-o", dst.to_str().unwrap(), &url])
            .status(),
        "wget" => Command::new("wget")
            .args(["-q", "-O", dst.to_str().unwrap(), &url])
            .status(),
        _ => unreachable!(),
    };
    if !status.map(|s| s.success()).unwrap_or(false) {
        let _ = std::fs::remove_file(dst);
        panic!("narf-busybox: download failed");
    }
}

fn verify_sha256(path: &Path) {
    // sha256sum is on every reasonable Linux box; if it's not
    // present, skip the check rather than fail the build.
    if which("sha256sum").is_none() {
        eprintln!("narf-busybox: sha256sum not on PATH; skipping checksum verify");
        return;
    }
    let out = Command::new("sha256sum")
        .arg(path)
        .output()
        .expect("sha256sum");
    let got = String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .next()
        .map(String::from)
        .unwrap_or_default();
    if got != BB_SHA256 {
        let _ = std::fs::remove_file(path);
        panic!(
            "narf-busybox: SHA-256 mismatch for {}\n  expected {}\n       got {}",
            path.display(),
            BB_SHA256,
            got
        );
    }
}

fn run_make(src: &Path, args: &[&str]) {
    eprintln!("narf-busybox: make {}", args.join(" "));
    let status = Command::new("make")
        .args(args)
        .current_dir(src)
        .status()
        .expect("spawn make");
    if !status.success() {
        panic!("narf-busybox: make {} → exit {}", args.join(" "), status);
    }
}

fn enable_config(config: &Path, key: &str, value: &str) {
    let body = std::fs::read_to_string(config).expect("read .config");
    let mut out = String::with_capacity(body.len() + 32);
    let mut hit = false;
    let needle_eq = format!("{}=", key);
    let needle_unset = format!("# {} is not set", key);
    for line in body.lines() {
        if line.starts_with(&needle_eq) || line == needle_unset {
            if value == "n" {
                out.push_str(&format!("# {} is not set\n", key));
            } else {
                out.push_str(&format!("{}={}\n", key, value));
            }
            hit = true;
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    if !hit {
        if value == "n" {
            out.push_str(&format!("# {} is not set\n", key));
        } else {
            out.push_str(&format!("{}={}\n", key, value));
        }
    }
    std::fs::write(config, out).expect("write .config");
}
