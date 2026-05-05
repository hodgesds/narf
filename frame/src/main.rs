//! narf-frame — kernel TCB binary.
//!
//! Real builds are kernel-target only and go through
//! `cargo xtask --arch=x86_64|aarch64`, which builds with
//! `target_os = "none"`. The bare-metal entry point + the rest
//! of the kernel live in `bare_main.rs`, included here as a
//! module under the `target_os = "none"` cfg.
//!
//! On any other target (host `cargo build --workspace` for
//! tooling), this file collapses to an inert stub so workspace-
//! wide commands don't try to link a kernel image against the
//! host C runtime.

#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

#[cfg(target_os = "none")]
#[path = "bare_main.rs"]
mod bare;

// Re-export the per-arch modules at crate root so the existing
// `crate::x86_64::…` / `crate::aarch64::…` paths inside the
// kernel keep resolving after the `bare` wrapping.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub use bare::x86_64;
#[cfg(all(target_os = "none", target_arch = "aarch64"))]
pub use bare::aarch64;

#[cfg(not(target_os = "none"))]
fn main() {
    eprintln!("narf-frame is a kernel image; build via `cargo xtask --arch=…`.");
    std::process::exit(1);
}
