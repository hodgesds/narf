//! Host-only definitions for the arch hooks the FDT lib-test binary
//! links against (#2151).
//!
//! On a kernel target `arch/src/lib.rs` defines the `#[no_mangle]`
//! `narf_arch_cpu_id` / `narf_arch_current_domain` hooks (the
//! per-arch CPU-id read and the current-domain byte), and `narf-lib`
//! calls them through the `extern "Rust"` declarations in
//! `lib/src/percpu.rs` and `lib/src/assert.rs`. The host `cargo test`
//! binary has no `narf-arch` in its dependency closure — this crate
//! depends only on `narf-lib` and `narf-kernel-test` — but the link
//! still pulls in the referencing code: `narf-lib`'s `mod tests`
//! (`lib/src/lib.rs`) is compiled unconditionally, so its
//! `smoke_lib_current_domain_hook`,
//! `smoke_lib_assert_in_domain_passes_on_frame`, and `smoke_percpu_*`
//! smokes are present in the `rlib` and call the hooks. In a
//! dependency (non-`test`) build of `narf-lib` the `#[cfg(not(test))]`
//! `extern "Rust"` declarations are active, so the symbols must exist
//! at link time.
//!
//! This module supplies inert stand-ins so the link succeeds. It is
//! test-only (`#[cfg(test)]` in `lib.rs`): it is never compiled into
//! the kernel firmware parser, so it cannot collide with `arch`'s
//! definitions at kernel link time, and it changes no production
//! behavior. Values mirror the Stage-2 single-CPU behavior `arch`
//! reports — CPU id 0 (BSP; `arch/src/lib.rs::narf_arch_cpu_id`) and
//! domain 0 (`DomainId::FRAME`, the initial `CURRENT_DOMAIN` value
//! `arch/src/lib.rs::narf_arch_current_domain` returns) — the same
//! values `narf-lib`'s own `#[cfg(test)]` hook bodies return
//! (`lib/src/percpu.rs::narf_arch_cpu_id_hook`,
//! `lib/src/assert.rs::current_domain`).
//!
//! The `__kernel_phys_bounds` / `__text_start` pair from the issue's
//! earlier-tip evidence needs no stand-in here: this closure pulls in
//! neither `narf-memory`'s text-poke/KASLR paths nor
//! `narf-filesystem`'s sysfs readers, so the link reports only the two
//! arch hooks. This is the same technique as
//! `drivers/usb/src/host_test_shims.rs` (#2139/#2150), except that
//! crate's shim does not cover fdt — each lib-test binary links its
//! own copy.
//!
//! None of the FDT unit tests execute the referencing paths (they are
//! `narf-lib` smokes the FDT tests never call); the definitions exist
//! only to satisfy the linker.

#![allow(dead_code)]

/// ID of the CPU currently executing this code. Single-CPU host:
/// 0 (the BSP), as `arch` reports before AP bring-up populates
/// per-CPU ids.
#[no_mangle]
extern "Rust" fn narf_arch_cpu_id() -> usize {
    0
}

/// The domain byte this CPU is currently reporting. No domain scopes
/// on host: 0 (`DomainId::FRAME`), as `arch` reports from its
/// zero-initialised `CURRENT_DOMAIN` table.
#[no_mangle]
extern "Rust" fn narf_arch_current_domain() -> u8 {
    0
}
