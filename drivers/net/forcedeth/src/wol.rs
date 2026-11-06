//! Wake-on-LAN for the NVIDIA nForce (`forcedeth`) family (issue #792).
//!
//! Linux reference: `drivers/net/ethernet/nvidia/forcedeth.c`
//! (`nv_get_wol` / `nv_set_wol`, `nv_init_nic`, `nv_close`) and
//! `include/uapi/linux/ethtool.h` (`WAKE_*`) /
//! `include/uapi/linux/mii.h` (`BMCR_PDOWN`).
//!
//! The family wakes on magic packet only: `nv_get_wol` reports
//! `supported = WAKE_MAGIC`, and `nv_set_wol` honours exactly the
//! `WAKE_MAGIC` bit — `wolopts == 0` clears the enable,
//! `wolopts & WAKE_MAGIC` sets it, and any other non-zero word
//! leaves the stored enable unchanged (returning 0 either way).
//! The wake filter itself is one register, `NvRegWakeUpFlags`
//! (`0x200`): `NVREG_WAKEUPFLAGS_ENABLE` (`0x1111`) arms
//! `ACCEPT_MAGPAT` (`0x01`) in each D-state nibble (D0 shift 0, D1
//! shift 4, D2 shift 8, D3 shift 12).
//!
//! Suspend (Linux `nv_close`) arms the receive path when WoL is
//! enabled *or* when the `phy_power_down` module parameter is off
//! (its default: `static int phy_power_down;` — zero-initialised):
//! `PFF_ALWAYS | PFF_MYADDR` into the packet filter, then
//! `nv_start_rx`. Only the `phy_power_down = 1` variant powers the
//! PHY down instead (`BMCR |= BMCR_PDOWN`, read-modify-write).
//! NARF has no such module parameter, so the live suspend always
//! takes the default path (`phy_power_down = false`); the pure
//! program takes the flag as a parameter so the fixture covers
//! both branches.
//!
//! Two deliberate deviations from Linux, both documented:
//! - `nv_set_wol` writes `flags` (0) to `WakeUpFlags` when the
//!   word is non-zero but carries no `WAKE_MAGIC`, even when the
//!   stored enable stays 1 — leaving the register incoherent with
//!   the flag. NARF writes the *stored* enable instead, so a
//!   magic-less set leaves both the flag and the register untouched.
//! - `nv_txrx_gate` (the `PowerState2` clock gate) is skipped:
//!   Linux only applies it on `DEV_HAS_POWER_CNTRL` parts when the
//!   MAC is not in use, neither of which NARF models.

use narf_driver_runtime::MmioRegion;

// ── ethtool WAKE_* (include/uapi/linux/ethtool.h) ───────────────────

/// Wake on magic packet — the only filter this family arms.
pub const WAKE_MAGIC: u32 = 1 << 5;

// ── Registers (forcedeth.c `enum {...}` / `NvReg*`) ─────────────────

/// `NvRegWakeUpFlags`.
pub const REG_WAKEUP_FLAGS: u64 = 0x200;
/// `NvRegPacketFilterFlags`.
pub const REG_PACKET_FILTER: u64 = 0x08c;
/// `NvRegReceiverControl`.
pub const REG_RCV_CTL: u64 = 0x094;
/// `NvRegTransmitterControl`.
pub const REG_XMIT_CTL: u64 = 0x084;

// ── WakeUpFlags bits ────────────────────────────────────────────────

/// `NVREG_WAKEUPFLAGS_ENABLE` — `ACCEPT_MAGPAT` in every D-state
/// nibble (`0x1111`).
pub const WAKEUPFLAGS_ENABLE: u32 = 0x1111;
/// `NVREG_WAKEUPFLAGS_ACCEPT_MAGPAT` — per-nibble magic-pattern
/// accept bit (`0x01`).
pub const WAKEUPFLAGS_ACCEPT_MAGPAT: u32 = 0x01;

// ── Packet-filter / RX / TX bits (mirrored in `forcedeth.rs`) ───────

/// `NVREG_PFF_ALWAYS`.
pub const PFF_ALWAYS: u32 = 0x7F0000;
/// `NVREG_PFF_MYADDR`.
pub const PFF_MYADDR: u32 = 0x20;
/// `NVREG_RCVCTL_RX_PATH_EN`.
pub const RCV_CTL_RX_PATH_EN: u32 = 0x01000000;
/// `NVREG_RCVCTL_START`.
pub const RCV_CTL_START: u32 = 0x01;
/// `NVREG_XMITCTL_TX_PATH_EN`.
pub const XMIT_CTL_TX_PATH_EN: u32 = 0x01000000;
/// `NVREG_XMITCTL_START`.
pub const XMIT_CTL_START: u32 = 0x01;

// ── MII bits (include/uapi/linux/mii.h) ─────────────────────────────

/// `BMCR_PDOWN` — enable low-power state.
pub const BMCR_PDOWN: u16 = 0x0800;

// ── Register-bank abstraction (fixture + live share the program) ────

/// Minimal 32-bit register bank, mirroring ixgbe's `queues::RegBank`.
pub trait RegBank {
    fn read32(&self, offset: u64) -> u32;
    fn write32(&mut self, offset: u64, value: u32);
}

/// Live `RegBank` over an `MmioRegion`.
pub struct MmioRegBank<'a>(pub &'a MmioRegion);

impl RegBank for MmioRegBank<'_> {
    fn read32(&self, offset: u64) -> u32 {
        // SAFETY: the caller owns the BAR0 mapping behind this bank.
        unsafe { self.0.read32(offset) }
    }
    fn write32(&mut self, offset: u64, value: u32) {
        // SAFETY: same.
        unsafe { self.0.write32(offset, value) }
    }
}

// ── ethtool surface (nv_get_wol / nv_set_wol, pure) ─────────────────

/// The `ethtool` `supported` mask for this family: magic only
/// (Linux `nv_get_wol`: `supported = WAKE_MAGIC`).
pub const fn wol_supported_opts() -> u32 {
    WAKE_MAGIC
}

/// Map the stored enable to `ethtool` `wolopts`.
pub const fn wol_opts(wolenabled: bool) -> u32 {
    if wolenabled {
        WAKE_MAGIC
    } else {
        0
    }
}

/// Transcribe `nv_set_wol`'s enable update: `wolopts == 0` clears,
/// `wolopts & WAKE_MAGIC` sets, anything else leaves the stored
/// enable unchanged. Only the magic bit is honoured; every other
/// bit is silently ignored (Linux returns 0 either way).
pub const fn set_wol(wolopts: u32, current: bool) -> bool {
    if wolopts == 0 {
        false
    } else if wolopts & WAKE_MAGIC != 0 {
        true
    } else {
        current
    }
}

/// The `WakeUpFlags` word for a stored enable.
pub const fn wakeup_flags(wolenabled: bool) -> u32 {
    if wolenabled {
        WAKEUPFLAGS_ENABLE
    } else {
        0
    }
}

// ── Suspend program (nv_close WoL block, pure) ──────────────────────

/// What `nv_close` programs on the WoL / power-down branch.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SuspendProgram {
    /// `NvRegWakeUpFlags` word (re-asserted from the stored enable).
    pub wakeup_flags: u32,
    /// `NvRegPacketFilterFlags` word, when the receive path is armed
    /// for wake filtering. `None` on the PHY power-down branch,
    /// where Linux leaves the filter untouched.
    pub packet_filter: Option<u32>,
    /// `NvRegReceiverControl` word.
    pub rcv_ctl: u32,
    /// `NvRegTransmitterControl` word (TX is stopped in both branches).
    pub xmit_ctl: u32,
    /// Whether the PHY must be powered down (`BMCR |= BMCR_PDOWN`,
    /// read-modify-write) instead of leaving the receiver armed.
    pub power_down_phy: bool,
}

/// Transcribe the `nv_close` WoL decision: arm the receiver
/// (`PFF_ALWAYS | PFF_MYADDR` + `RCV_CTL` start) when WoL is
/// enabled or the PHY is left powered (`!phy_power_down`); power
/// the PHY down and stop both paths otherwise. TX is stopped in
/// both branches — `nv_close` has already stopped the TX unit
/// before this block runs.
pub const fn suspend_program(wolenabled: bool, phy_power_down: bool) -> SuspendProgram {
    if wolenabled || !phy_power_down {
        SuspendProgram {
            wakeup_flags: wakeup_flags(wolenabled),
            packet_filter: Some(PFF_ALWAYS | PFF_MYADDR),
            rcv_ctl: RCV_CTL_RX_PATH_EN | RCV_CTL_START,
            xmit_ctl: 0,
            power_down_phy: false,
        }
    } else {
        SuspendProgram {
            wakeup_flags: 0,
            packet_filter: None,
            rcv_ctl: 0,
            xmit_ctl: 0,
            power_down_phy: true,
        }
    }
}

/// Apply a suspend program in `nv_close` order: WakeUpFlags, packet
/// filter (when armed), receiver control, transmitter control. The
/// PHY power-down is the caller's job (an MDIO read-modify-write,
/// not an MMIO word).
pub fn apply_suspend(bank: &mut impl RegBank, program: &SuspendProgram) {
    bank.write32(REG_WAKEUP_FLAGS, program.wakeup_flags);
    if let Some(pff) = program.packet_filter {
        bank.write32(REG_PACKET_FILTER, pff);
    }
    bank.write32(REG_RCV_CTL, program.rcv_ctl);
    bank.write32(REG_XMIT_CTL, program.xmit_ctl);
}

// ── Resume words ────────────────────────────────────────────────────

/// The datapath words resume restores — the same words bring-up
/// programs (`PFF_ALWAYS | PFF_MYADDR`, `RX_PATH_EN | START`,
/// `TX_PATH_EN | START`). Linux's resume re-runs `nv_init_nic`,
/// which re-programs the same filter + RX/TX start.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ResumeWords {
    pub packet_filter: u32,
    pub rcv_ctl: u32,
    pub xmit_ctl: u32,
}

/// The resume datapath words, as literals (fixture-independent).
pub const fn resume_words() -> ResumeWords {
    ResumeWords {
        packet_filter: 0x7F0020,
        rcv_ctl: 0x01000001,
        xmit_ctl: 0x01000001,
    }
}

#[cfg(target_arch = "x86_64")]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    struct FakeBank {
        regs: alloc::vec::Vec<u32>,
    }

    impl FakeBank {
        fn new() -> Self {
            Self {
                regs: alloc::vec![0u32; 0x300 / 4],
            }
        }
    }

    impl RegBank for FakeBank {
        fn read32(&self, offset: u64) -> u32 {
            if offset % 4 != 0 {
                return 0;
            }
            self.regs.get((offset / 4) as usize).copied().unwrap_or(0)
        }
        fn write32(&mut self, offset: u64, value: u32) {
            if offset % 4 != 0 {
                return;
            }
            if let Some(slot) = self.regs.get_mut((offset / 4) as usize) {
                *slot = value;
            }
        }
    }

    fn smoke_forcedeth_wol_set() -> TestResult {
        if wol_supported_opts() != 0x20 {
            return TestResult::Fail("supported mask is not WAKE_MAGIC (0x20)");
        }
        // Zero clears, magic sets, anything else leaves the stored state.
        if set_wol(0, true) {
            return TestResult::Fail("zero wolopts did not clear the enable");
        }
        if !set_wol(WAKE_MAGIC, false) {
            return TestResult::Fail("WAKE_MAGIC did not set the enable");
        }
        if !set_wol(WAKE_MAGIC | 0x01, false) {
            return TestResult::Fail("WAKE_MAGIC|other did not set the enable");
        }
        if set_wol(0x01, true) != true || set_wol(0x01, false) != false {
            return TestResult::Fail("non-magic wolopts changed the stored enable");
        }
        if wol_opts(true) != WAKE_MAGIC || wol_opts(false) != 0 {
            return TestResult::Fail("wolopts mapping wrong");
        }
        if wakeup_flags(true) != 0x1111 || wakeup_flags(false) != 0 {
            return TestResult::Fail("WakeUpFlags word wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/forcedeth", smoke_forcedeth_wol_set);

    fn smoke_forcedeth_wol_suspend() -> TestResult {
        // WoL enabled: receiver armed, PHY stays up.
        let armed = suspend_program(true, false);
        if armed.wakeup_flags != 0x1111 {
            return TestResult::Fail("armed suspend did not set WakeUpFlags ENABLE");
        }
        if armed.packet_filter != Some(0x7F0020) {
            return TestResult::Fail("armed suspend packet filter is not ALWAYS|MYADDR");
        }
        if armed.rcv_ctl != 0x01000001 || armed.xmit_ctl != 0 || armed.power_down_phy {
            return TestResult::Fail("armed suspend RX/TX words wrong");
        }
        // WoL off, PHY left powered (the Linux default): receiver
        // still armed for the (non-wake) link, PHY stays up, but
        // WakeUpFlags is 0.
        let idle = suspend_program(false, false);
        if idle.wakeup_flags != 0 || idle.power_down_phy {
            return TestResult::Fail("idle suspend must not arm WakeUpFlags or power down the PHY");
        }
        if idle.packet_filter != Some(0x7F0020) || idle.rcv_ctl != 0x01000001 {
            return TestResult::Fail("idle suspend must still arm the receiver");
        }
        // WoL off, phy_power_down=1: both paths stopped, PHY down.
        let down = suspend_program(false, true);
        if down.wakeup_flags != 0 || down.packet_filter.is_some() {
            return TestResult::Fail("power-down suspend touched WakeUpFlags or the filter");
        }
        if down.rcv_ctl != 0 || down.xmit_ctl != 0 || !down.power_down_phy {
            return TestResult::Fail("power-down suspend did not stop both paths");
        }
        // The register conversation for the armed branch.
        let mut bank = FakeBank::new();
        apply_suspend(&mut bank, &armed);
        if bank.read32(REG_WAKEUP_FLAGS) != 0x1111 {
            return TestResult::Fail("apply did not land WakeUpFlags ENABLE");
        }
        if bank.read32(REG_PACKET_FILTER) != 0x7F0020 {
            return TestResult::Fail("apply did not land PFF_ALWAYS|MYADDR");
        }
        if bank.read32(REG_RCV_CTL) != 0x01000001 || bank.read32(REG_XMIT_CTL) != 0 {
            return TestResult::Fail("apply did not land the RX/TX words");
        }
        // The power-down branch leaves the filter register untouched.
        let mut bank = FakeBank::new();
        bank.write32(REG_PACKET_FILTER, 0x7F0020);
        apply_suspend(&mut bank, &down);
        if bank.read32(REG_PACKET_FILTER) != 0x7F0020 {
            return TestResult::Fail("power-down apply touched the packet filter");
        }
        if bank.read32(REG_RCV_CTL) != 0 || bank.read32(REG_WAKEUP_FLAGS) != 0 {
            return TestResult::Fail("power-down apply did not stop RX / clear WakeUpFlags");
        }
        // Resume words are the bring-up words.
        let r = resume_words();
        if r.packet_filter != 0x7F0020 || r.rcv_ctl != 0x01000001 || r.xmit_ctl != 0x01000001 {
            return TestResult::Fail("resume words are not the bring-up words");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/forcedeth", smoke_forcedeth_wol_suspend);
}
