//! ixgbe suspend / resume / detach quiesce.
//!
//! This is the driver-local power-management surface (the platform
//! PM layer owns PCI PMCSR D-state transitions; this module owns
//! the device-side sequence the datasheet requires around them).
//! Grounding: 82599 Datasheet §8.2.3.8.10 (RXCTRL.RXEN bit 0),
//! §8.2.3.8.6 (RXDCTL ENABLE bit 25), §8.2.3.9.10 (TXDCTL ENABLE
//! bit 25), §8.2 (EIMC 0x00888 mask-clear-all), §8.2.3.1.2
//! (CTRL_EXT.DRV_LOAD bit 28 — cleared on detach so firmware
//! knows the driver is gone), §8.2.3.24 (WUS clear on suspend).
//!
//! Order matters and is the whole point of this module:
//! * Suspend: mask interrupts → stop RX (RXEN = 0) → disable the
//!   TX/RX queues → clear stale wake status → arm WoL (if any) →
//!   mark quiesced. The datapath checks the quiesced flag and
//!   refuses new TX / reports no RX while it is set, so the pumps
//!   (which the driver cannot cancel — they hold `Arc` clones)
//!   spin harmlessly instead of feeding a stopped device.
//! * Resume: clear the quiesced flag → re-enable queue 0 (the only
//!   live ring) → re-enable RX → unmask the misc vector → re-read
//!   LINKS. Ring contents are NOT rebuilt here: a suspend that
//!   lost DMA state needs a full re-probe, which is the caller's
//!   decision (documented, not silently attempted).
//! * Detach: the suspend sequence with no WoL, plus clearing
//!   CTRL_EXT.DRV_LOAD, plus (in `detach_controller`, ixgbe.rs) the
//!   framework steps — clear the CONTROLLER slot, clear the RX
//!   mirror note for the published name, and unregister the iface
//!   — so a re-probe under a recycled `eth%d` name starts clean
//!   (see net spec §3, issue #789).

use super::queues::{rx_queue_regs, tx_queue_regs, RegBank};
use super::wol::WolConfig;

/// RXCTRL register + RXEN bit (datasheet §8.2.3.8.10).
pub const REG_RXCTRL: u64 = 0x03000;
pub const RXCTRL_RXEN: u32 = 1 << 0;
/// EIMC: write-all-ones masks every extended cause.
pub const REG_EIMC_PM: u64 = 0x00888;
/// CTRL_EXT + DRV_LOAD (datasheet §8.2.3.1.2).
pub const REG_CTRL_EXT_PM: u64 = 0x00018;
pub const CTRL_EXT_DRV_LOAD_PM: u32 = 1 << 28;
/// Queue-enable bits (RXDCTL/TXDCTL bit 25).
pub const XDCTL_ENABLE_PM: u32 = 1 << 25;
/// EIMS unmask value for the shared misc vector (vector 0).
pub const EIMS_MISC_VECTOR: u32 = 1;
pub const REG_EIMS_PM: u64 = 0x00880;

/// Quiesce the datapath for suspend or detach. `wol` arms wake-up
/// (suspend only); detach passes `None`.
pub fn suspend_plan(bank: &mut impl RegBank, wol: Option<WolConfig>) {
    // 1. Mask all extended interrupts.
    bank.write32(REG_EIMC_PM, 0xFFFF_FFFF);
    // 2. Stop the receiver at the master enable.
    bank.clear_bits(REG_RXCTRL, RXCTRL_RXEN);
    // 3. Disable queue 0 (the only live ring).
    if let Some(tx) = tx_queue_regs(0) {
        bank.clear_bits(tx.txdctl, XDCTL_ENABLE_PM);
    }
    if let Some(rx) = rx_queue_regs(0) {
        bank.clear_bits(rx.rxdctl, XDCTL_ENABLE_PM);
    }
    // 4. Wake-up: arm, or leave the filter set cleared.
    match wol {
        Some(cfg) => cfg.arm(bank),
        None => WolConfig::disarm(bank),
    }
}

/// Re-enable the queue-0 datapath after resume.
pub fn resume_plan(bank: &mut impl RegBank) {
    // 1. Re-enable queue 0.
    if let Some(tx) = tx_queue_regs(0) {
        bank.set_bits(tx.txdctl, XDCTL_ENABLE_PM);
    }
    if let Some(rx) = rx_queue_regs(0) {
        bank.set_bits(rx.rxdctl, XDCTL_ENABLE_PM);
    }
    // 2. Re-enable the receiver.
    bank.set_bits(REG_RXCTRL, RXCTRL_RXEN);
    // 3. Unmask the shared misc vector.
    bank.write32(REG_EIMS_PM, EIMS_MISC_VECTOR);
}

/// Detach extras, after [`suspend_plan`] with no WoL: tell
/// firmware the driver is gone.
pub fn detach_plan(bank: &mut impl RegBank) {
    suspend_plan(bank, None);
    bank.clear_bits(REG_CTRL_EXT_PM, CTRL_EXT_DRV_LOAD_PM);
}
