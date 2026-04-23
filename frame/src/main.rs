//! narf-frame — the TCB bin crate. Contains `_start`, BSP bring-up, and
//! the panic path. Stage 1 is deliberately minimal: do the boot-loader
//! handoff, initialise the serial console, print a hello line, and halt.
//!
//! Spec: `frame/specification/spec.md`. Full BSP responsibilities
//! (GDT/IDT/TSS with IST slots on x86_64, EL1 vector table on aarch64,
//! trap-prologue PKRS save scaffolding) land alongside Wave 2's memory
//! bring-up.

#![no_std]
#![no_main]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

use core::fmt::Write;
use core::panic::PanicInfo;

use narf_boot::{RawBootInfo};
use narf_console::{self as console, UartKind};
use narf_memory::PhysAddr;

#[cfg(target_arch = "x86_64")]
mod x86_64;

#[cfg(target_arch = "aarch64")]
mod aarch64;

/// Called from the arch-specific boot stub once the CPU is in a state
/// capable of executing Rust: stack set up, appropriate privilege level,
/// long mode (on x86_64), and a `RawBootInfo` packed from the bootloader's
/// handoff registers.
///
/// # Safety
/// - `raw` must describe a real bootloader handoff (the arch stub
///   constructed it from the machine registers, so this holds by
///   construction).
/// - MMU / TLB / interrupt controller are in the bootloader-documented
///   state.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _start_rust(raw: RawBootInfo) -> ! {
    // Step 1: bring up the early serial console before doing anything else,
    // so any failure from here on is visible.
    #[cfg(target_arch = "x86_64")]
    {
        // 16550A COM1 at I/O port 0x3F8 — hard-coded default. Real detection
        // lands with the ACPI/FDT parse in Wave 2.
        console::early_init(PhysAddr::new(0x3F8), UartKind::Uart16550);
    }
    #[cfg(target_arch = "aarch64")]
    {
        // PL011 at QEMU virt's MMIO base.
        console::early_init(PhysAddr::new(0x0900_0000), UartKind::Pl011);
    }

    let _ = writeln!(console::Writer, "NARF Stage 1 Wave 1 — hello from a bare kernel.");
    let arch_name = if cfg!(target_arch = "x86_64") { "x86_64" }
                    else if cfg!(target_arch = "aarch64") { "aarch64" }
                    else { "unknown" };
    let _ = writeln!(console::Writer,
        "  arch: {} | backend: {:?}", arch_name, narf_arch::BACKEND);

    // Step 2: parse the bootloader handoff into a validated BootInfo.
    // SAFETY: the raw struct came from the arch stub; bootloader contract.
    let boot_result = unsafe {
        #[cfg(target_arch = "x86_64")]
        { narf_boot::x86_64::parse_raw(&raw) }
        #[cfg(target_arch = "aarch64")]
        { narf_boot::aarch64::parse_raw(&raw) }
    };

    match boot_result {
        Ok(info) => {
            let _ = writeln!(console::Writer,
                "  boot info: {} memory region(s), uart_phys={:?}",
                info.memory_map.len(), info.uart_phys);
            let mut usable_bytes: u64 = 0;
            for r in info.memory_map {
                if r.kind == narf_boot::MemRegionKind::Usable {
                    usable_bytes = usable_bytes.saturating_add(r.len);
                }
            }
            let _ = writeln!(console::Writer,
                "  usable RAM: {} MiB", usable_bytes / (1024 * 1024));
        }
        Err(e) => {
            let _ = writeln!(console::Writer, "  boot parse failed: {e:?}");
        }
    }

    let _ = writeln!(console::Writer, "  halting — Wave 2 lands the MMU + async executor.");
    narf_arch::halt_forever();
}

#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    console::panic_sink(info)
}
