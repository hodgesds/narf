//! Realtek RTL8168-family suspend / resume register plans (issue
//! #793).
//!
//! The register conversation every chip's `suspend` / `resume` runs,
//! factored over a minimal bank so fixtures drive the exact program
//! against a fake bank (end-to-end register writes, no silicon)
//! while the live path runs it against BAR2 via [`MmioBank`]. Same
//! shape as ixgbe's `pm` plans.
//!
//! Grounding: the whole family shares the Command register layout
//! (CR @ 0x37, TE bit 2, RE bit 3 — datasheet §2.3 Table 3, and the
//! identical `REG_CR` / `CR_TE` / `CR_RE` constants in
//! `r8169.rs`, `rtl8125.rs`, `rtl8126.rs` and `rtl8127.rs`); only
//! the interrupt-mask port differs — the 8168/8169 16-bit IMR @
//! 0x3C / ISR @ 0x3E, versus the 8125/8126/8127 32-bit IMR @ 0x38 /
//! ISR @ 0x3C (the 8125 promoted the port to u32 to make room for
//! the high-half bits). The caller passes its chip's port as an
//! [`ImrPort`]; no new register values are invented here.
//!
//! * Suspend: mask interrupts (IMR = 0), acknowledge pending causes
//!   (ISR = all-ones, write-1-to-clear), then stop the TX/RX DMA
//!   engines by clearing CR TE|RE, preserving the other CR bits.
//!   The descriptor rings and their programmed bases (TNPDS/RDSAR)
//!   persist — only the EN bits gate DMA.
//! * Resume: re-enable TX/RX DMA (CR TE|RE), then re-arm the
//!   interrupt mask with the chip's bring-up word — only when a
//!   vector is bound (polled devices keep the all-masked state
//!   bring-up left them in). The PHY re-negotiation itself (BMCR
//!   AN-restart via `phy_access`) lives in each chip's `resume`
//!   method, next to its `phy_status` link re-read: it needs a
//!   live MDIO read, which the register plan does not do.
//!
//! Deliberate deltas: no PHY power-down — the PHY stays powered,
//! so its autoneg advertisement persists and resume re-links
//! without a power cycle (e1000's delta); no WoL arming — WoL
//! lands as its own item; no PCI power-state transition — the bus
//! layer owns PCI config.

use narf_bus::MmioRegion;

/// Command register (CR) offset — shared across the family.
pub const REG_CR: u64 = 0x37;
/// CR Transmit Enable (datasheet §2.3 Table 3).
pub const CR_TE: u8 = 1 << 2;
/// CR Receive Enable.
pub const CR_RE: u8 = 1 << 3;

/// Which interrupt-mask port this chip uses.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ImrPort {
    /// IMR offset.
    pub imr: u64,
    /// ISR offset (write-1-to-clear).
    pub isr: u64,
    /// True for the 32-bit port (8125/8126/8127), false for the
    /// 16-bit port (8168/8169).
    pub wide: bool,
}

/// 16-bit IMR @ 0x3C / ISR @ 0x3E (RTL8168/8169).
pub const IMR_LEGACY: ImrPort = ImrPort {
    imr: 0x3C,
    isr: 0x3E,
    wide: false,
};

/// 32-bit IMR @ 0x38 / ISR @ 0x3C (RTL8125/8126/8127).
pub const IMR_WIDE: ImrPort = ImrPort {
    imr: 0x38,
    isr: 0x3C,
    wide: true,
};

/// Minimal register-bank abstraction so the register conversation
/// can be exercised against a fake bank in fixtures and against
/// real MMIO in the driver via [`MmioBank`].
pub trait RegBank {
    fn read8(&self, offset: u64) -> u8;
    fn write8(&self, offset: u64, value: u8);
    fn read16(&self, offset: u64) -> u16;
    fn write16(&self, offset: u64, value: u16);
    fn read32(&self, offset: u64) -> u32;
    fn write32(&self, offset: u64, value: u32);
}

/// [`RegBank`] over a real BAR2 mapping.
#[derive(Debug)]
pub struct MmioBank<'a> {
    mmio: &'a MmioRegion,
}

impl<'a> MmioBank<'a> {
    pub fn new(mmio: &'a MmioRegion) -> Self {
        Self { mmio }
    }
}

impl RegBank for MmioBank<'_> {
    fn read8(&self, offset: u64) -> u8 {
        // SAFETY: the driver owns BAR2 exclusively; the caller
        // guarantees `offset` is a valid device register.
        unsafe { self.mmio.read8(offset) }
    }
    fn write8(&self, offset: u64, value: u8) {
        // SAFETY: same as above.
        unsafe { self.mmio.write8(offset, value) }
    }
    fn read16(&self, offset: u64) -> u16 {
        // SAFETY: same as above.
        unsafe { self.mmio.read16(offset) }
    }
    fn write16(&self, offset: u64, value: u16) {
        // SAFETY: same as above.
        unsafe { self.mmio.write16(offset, value) }
    }
    fn read32(&self, offset: u64) -> u32 {
        // SAFETY: same as above.
        unsafe { self.mmio.read32(offset) }
    }
    fn write32(&self, offset: u64, value: u32) {
        // SAFETY: same as above.
        unsafe { self.mmio.write32(offset, value) }
    }
}

/// Suspend register program: mask interrupts, acknowledge pending
/// causes, stop the TX/RX DMA engines.
pub fn suspend_plan(bank: &impl RegBank, imr: ImrPort) {
    if imr.wide {
        bank.write32(imr.imr, 0);
        bank.write32(imr.isr, 0xFFFF_FFFF);
    } else {
        bank.write16(imr.imr, 0);
        bank.write16(imr.isr, 0xFFFF);
    }
    let cr = bank.read8(REG_CR);
    bank.write8(REG_CR, cr & !(CR_TE | CR_RE));
}

/// Resume register program: re-enable the TX/RX DMA engines, then
/// re-arm the interrupt mask with the chip's bring-up word — only
/// when a vector is bound. Returns the live CR word so the caller
/// can confirm the engines came back on.
pub fn resume_plan(bank: &impl RegBank, imr: ImrPort, imr_word: u32, irq_bound: bool) -> u8 {
    let cr = bank.read8(REG_CR) | CR_TE | CR_RE;
    bank.write8(REG_CR, cr);
    if irq_bound {
        if imr.wide {
            bank.write32(imr.imr, imr_word);
        } else {
            bank.write16(imr.imr, imr_word as u16);
        }
    }
    cr
}

#[cfg(any(test, feature = "builtin"))]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// In-memory register bank for the PM fixtures: 256 bytes of
    /// BAR2 window, covering CR (0x37), the legacy IMR/ISR
    /// (0x3C/0x3E) and the wide IMR/ISR (0x38/0x3C).
    struct FakeBank {
        regs: core::cell::RefCell<[u8; 256]>,
    }

    impl FakeBank {
        fn new() -> Self {
            Self {
                regs: core::cell::RefCell::new([0u8; 256]),
            }
        }
        fn read_at(&self, offset: u64) -> u8 {
            self.regs
                .borrow()
                .get(offset as usize)
                .copied()
                .unwrap_or(0)
        }
    }

    impl RegBank for FakeBank {
        fn read8(&self, offset: u64) -> u8 {
            self.read_at(offset)
        }
        fn write8(&self, offset: u64, value: u8) {
            if let Some(slot) = self.regs.borrow_mut().get_mut(offset as usize) {
                *slot = value;
            }
        }
        fn read16(&self, offset: u64) -> u16 {
            u16::from_le_bytes([self.read_at(offset), self.read_at(offset + 1)])
        }
        fn write16(&self, offset: u64, value: u16) {
            for (i, b) in value.to_le_bytes().iter().enumerate() {
                self.write8(offset + i as u64, *b);
            }
        }
        fn read32(&self, offset: u64) -> u32 {
            u32::from_le_bytes([
                self.read_at(offset),
                self.read_at(offset + 1),
                self.read_at(offset + 2),
                self.read_at(offset + 3),
            ])
        }
        fn write32(&self, offset: u64, value: u32) {
            for (i, b) in value.to_le_bytes().iter().enumerate() {
                self.write8(offset + i as u64, *b);
            }
        }
    }

    fn smoke_rtl_pm_suspend_stops_dma_both_ports() -> TestResult {
        for imr in [IMR_LEGACY, IMR_WIDE] {
            let bank = FakeBank::new();
            // Bring-up state: engines on, interrupts armed.
            bank.write8(REG_CR, CR_TE | CR_RE);
            if imr.wide {
                bank.write32(imr.imr, 0xA5);
            } else {
                bank.write16(imr.imr, 0xA5);
            }
            suspend_plan(&bank, imr);
            if bank.read8(REG_CR) & (CR_TE | CR_RE) != 0 {
                return TestResult::Fail("rtl suspend did not stop TX/RX DMA");
            }
            if imr.wide {
                if bank.read32(imr.imr) != 0 || bank.read32(imr.isr) != 0xFFFF_FFFF {
                    return TestResult::Fail("rtl suspend did not mask/ack the wide port");
                }
            } else if bank.read16(imr.imr) != 0 || bank.read16(imr.isr) != 0xFFFF {
                return TestResult::Fail("rtl suspend did not mask/ack the legacy port");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/net/realtek",
        smoke_rtl_pm_suspend_stops_dma_both_ports
    );

    fn smoke_rtl_pm_resume_restores_and_rearms() -> TestResult {
        for (imr, word) in [(IMR_LEGACY, 0xA5u32), (IMR_WIDE, 0xA5u32)] {
            let bank = FakeBank::new();
            suspend_plan(&bank, imr);
            let cr = resume_plan(&bank, imr, word, true);
            if cr & (CR_TE | CR_RE) != CR_TE | CR_RE {
                return TestResult::Fail("rtl resume did not re-enable TX/RX DMA");
            }
            if imr.wide {
                if bank.read32(imr.imr) != word {
                    return TestResult::Fail("rtl resume did not re-arm the wide mask");
                }
            } else if bank.read16(imr.imr) != word as u16 {
                return TestResult::Fail("rtl resume did not re-arm the legacy mask");
            }
            // Polled device: no vector bound, mask stays as suspend left it.
            let polled = FakeBank::new();
            suspend_plan(&polled, imr);
            let _ = resume_plan(&polled, imr, word, false);
            if imr.wide {
                if polled.read32(imr.imr) != 0 {
                    return TestResult::Fail("rtl resume armed the wide mask on a polled device");
                }
            } else if polled.read16(imr.imr) != 0 {
                return TestResult::Fail("rtl resume armed the legacy mask on a polled device");
            }
            // Suspend → resume → suspend is stable.
            suspend_plan(&bank, imr);
            if bank.read8(REG_CR) & (CR_TE | CR_RE) != 0 {
                return TestResult::Fail("rtl second suspend drifted from the first");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/net/realtek",
        smoke_rtl_pm_resume_restores_and_rearms
    );
}
