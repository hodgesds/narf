//! Intel LPSS UART driver — DesignWare 8250 core + LPSS private regs.
//!
//! Targets the Intel PCH LPSS UART controllers as found on:
//! - Tiger Lake / Alder Lake / Raptor Lake: INT344C, INT344D
//! - Skylake / Kaby Lake: INT3446, INT3447
//! - Haswell / Broadwell: INT33C4, INT33C5
//!
//! # References
//! - Intel "Tiger Lake Platform Controller Hub EDS Vol 2" — LPSS
//!   private register layout (offset 0x200).
//! - Synopsys "DW_apb_uart Databook" — DesignWare 8250 register map.
//! - Linux `drivers/tty/serial/8250/8250_lpss.c` — community-based
//!   initialization and clock gating.

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use core::fmt::Write as _;

use narf_aml::resource::ResourceItem;
use narf_memory::PhysAddr;

use crate::uart_8250::Uart8250;

// ── ACPI HIDs we recognise ─────────────────────────────────────────

pub const LPSS_UART_HIDS: &[&str] = &[
    "INT33C4", "INT33C5", // Haswell / Broadwell
    "INT3434", "INT3435", // Broadwell
    "INT344C", "INT344D",  // Skylake+
    "INTC1008", // Lakefield
];

// ── LPSS Private Registers ─────────────────────────────────────────
const LPSS_PRIV_OFFSET: u64 = 0x200;
const LPSS_PRIV_RESETS: u64 = LPSS_PRIV_OFFSET + 0x04;
const LPSS_PRIV_REMAP_ADDR: u64 = LPSS_PRIV_OFFSET + 0x40;

/// One Intel LPSS UART controller.
pub struct IntelLpssUart {
    pub name: String,
    pub uart: Arc<narf_lib::sync::IrqSafeSpinLock<Uart8250>>,
    pub mmio_base: PhysAddr,
    pub mmio_len: u64,
}

impl core::fmt::Debug for IntelLpssUart {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IntelLpssUart")
            .field("name", &self.name)
            .field("mmio_base", &self.mmio_base)
            .finish()
    }
}

impl IntelLpssUart {
    pub fn new(name: String, mmio_base: PhysAddr, mmio_len: u64, irq: Option<u8>) -> Self {
        // DesignWare UARTs on Intel PCH typically use 100MHz or 120MHz clock.
        // TGL/ADL use 100MHz.
        let uart = Uart8250::new_mmio(mmio_base, irq, 2, 100_000_000);
        Self {
            name,
            uart: Arc::new(narf_lib::sync::IrqSafeSpinLock::new(uart)),
            mmio_base,
            mmio_len,
        }
    }

    /// Ungate the LPSS core and initialize the DesignWare 8250.
    pub fn init(&self, baud: u32) -> bool {
        // SAFETY: exclusive access during probe.
        unsafe {
            // Un-gate LPSS core.
            narf_arch::mmio::write32(self.mmio_base.raw() + LPSS_PRIV_RESETS, 0);
            narf_arch::mmio::write32(self.mmio_base.raw() + LPSS_PRIV_RESETS, 0x7); // FUNC | APB | IDMA
                                                                                    // Program Remap Address.
            narf_arch::mmio::write32(
                self.mmio_base.raw() + LPSS_PRIV_REMAP_ADDR,
                (self.mmio_base.raw() & 0xFFFFFFFF) as u32,
            );
            narf_arch::mmio::write32(
                self.mmio_base.raw() + LPSS_PRIV_REMAP_ADDR + 4,
                (self.mmio_base.raw() >> 32) as u32,
            );
        }

        let mut u = self.uart.lock();
        if !u.init(baud) {
            return false;
        }
        true
    }
}

// ── Discovery ──────────────────────────────────────────────────────

pub fn probe_all() -> usize {
    let mut count = 0usize;
    for &hid in LPSS_UART_HIDS {
        for node in narf_aml::find_all_devices_by_hid(hid) {
            if probe_one(&node.path).is_some() {
                count += 1;
            }
        }
    }
    count
}

fn probe_one(path: &str) -> Option<()> {
    let items = narf_aml::prt_crs::evaluate_crs_for(path).ok()?;
    let mut mmio: Option<(u64, u64)> = None;
    let mut gsi: Option<u32> = None;

    for item in items {
        match item {
            ResourceItem::Memory32Fixed { base, length, .. } if mmio.is_none() => {
                mmio = Some((base as u64, length as u64));
            }
            ResourceItem::Memory32 { min, length, .. } if mmio.is_none() => {
                mmio = Some((min as u64, length as u64));
            }
            ResourceItem::ExtendedIrq { gsis, .. } if gsi.is_none() => {
                gsi = gsis.first().copied();
            }
            _ => {}
        }
    }

    let (base, len) = mmio?;

    // IRQ routing.
    let irq_vec = gsi.and_then(|g| try_route_gsi(g));

    let drv = IntelLpssUart::new(path.to_string(), PhysAddr::new(base), len, irq_vec);

    if !drv.init(115_200) {
        let _ = writeln!(
            narf_console::Writer,
            "  lpss-uart: {} init failed at {:#x}",
            path,
            base
        );
        return None;
    }

    let utype = drv.uart.lock().uart_type;
    let _ = writeln!(
        narf_console::Writer,
        "  lpss-uart: detected at MMIO={:#x}+{:#x} {} irq={} {:?}",
        base,
        len,
        path,
        irq_vec
            .map(|v| v.to_string())
            .unwrap_or_else(|| "polled".into()),
        utype
    );

    // Register in global registry.
    // Leak the path string for the static registry.
    let static_name: &'static str = Box::leak(path.to_string().into_boxed_str());
    crate::registry::register(crate::registry::UartInfo {
        io_base: (base & 0xFFFF) as u16, // Compatibility shim for old registry
        irq: irq_vec,
        name: static_name,
        baud: 115_200,
    });

    Some(())
}

fn try_route_gsi(gsi: u32) -> Option<u8> {
    #[cfg(target_arch = "x86_64")]
    {
        let v = narf_interrupts::vector::alloc().ok()?;
        // Default: Active High, Level Triggered for PCH devices.
        if unsafe {
            narf_acpi::ioapic::route_gsi_to_vector(
                gsi,
                v,
                0,
                narf_acpi::ioapic::POLARITY_HIGH | narf_acpi::ioapic::TRIGGER_LEVEL,
            )
        } {
            narf_interrupts::install_handler(v, || {});
            Some(v)
        } else {
            let _ = narf_interrupts::vector::free(v);
            None
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = gsi;
        None
    }
}
