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
//! * Resume: REBUILD the DMA rings in place, then unquiesce (see
//!   `resume_rebuild_plan` and spec §13l for the decision): clear
//!   queue enables → reprogram ring bases, lengths, heads, tails
//!   from the retained host buffers, one entry per configured
//!   queue → re-arm the RX filter + master enable → unmask the
//!   misc vector. The rebuild is unconditional and idempotent —
//!   it is correct whether or not the suspend actually lost
//!   device state — and fail-closed: any validation failure
//!   returns before a single register is written, so the device
//!   stays quiesced and the caller may re-probe instead.
//! * Detach: the suspend sequence with no WoL, plus clearing
//!   CTRL_EXT.DRV_LOAD, plus (in `detach_controller`, ixgbe.rs) the
//!   framework steps — clear the CONTROLLER slot, clear the RX
//!   mirror note for the published name, and unregister the iface
//!   — so a re-probe under a recycled `eth%d` name starts clean
//!   (see net spec §3, issue #789).

use super::queues::{rx_queue_regs, tx_queue_regs, QueueConfig, RegBank};
use super::wol::WolConfig;
use super::{FCTRL_BAM, FCTRL_MPE, FCTRL_UPE, REG_FCTRL, SRRCTL_DESCTYPE_ADV_ONEBUF};

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

/// Rebuild the DMA datapath after resume, in place, from the
/// retained host ring buffers — the §13l decision (rebuild, not
/// re-probe). `tx_bases` / `rx_bases` hold one DMA base address
/// per configured queue, in queue order; on main that is one entry
/// each (the 1/1 bring-up), and a multi-queue bring-up passes one
/// entry per live queue, so this loop — never a hardcoded queue 0
/// — is what composes with per-queue rings.
///
/// Sequence mirrors Linux `ixgbe_configure_tx_ring` /
/// `ixgbe_configure_rx_ring` (clear the queue-enable bit, program
/// base / length / head / tail, then set enable) and NARF's own
/// bring-up values (RX tail = ring_len - 1 after all descriptors
/// are armed, SRRCTL 2K advanced one-buffer, FCTRL BAM|UPE|MPE, RXCTRL RXEN).
/// The caller (`Ixgbe::resume`) zeroes the TX ring memory and
/// re-arms the RX descriptors from the retained slot buffers
/// before calling this; this plan only programs registers.
/// `srrctl_bsize` is the SRRCTL.BSIZEPKT value (1 KiB units) for
/// the programmed MTU (issue #802) — 2 at the 1500 default, 10 at
/// 9710. The caller owns MAXFRS: `Ixgbe::resume` reprograms it
/// from the stored MTU after this plan runs.
pub fn resume_rebuild_plan(
    bank: &mut impl RegBank,
    cfg: &QueueConfig,
    tx_bases: &[u64],
    rx_bases: &[u64],
    srrctl_bsize: u32,
) -> Result<(), &'static str> {
    cfg.validate().map_err(|_| "invalid queue config")?;
    if tx_bases.len() != cfg.num_tx {
        return Err("tx base count != tx queue count");
    }
    if rx_bases.len() != cfg.num_rx {
        return Err("rx base count != rx queue count");
    }
    // 1. TX queues: disable, reprogram, re-enable.
    for (q, base) in tx_bases.iter().enumerate() {
        let tx = tx_queue_regs(q).ok_or("tx queue registers unresolvable")?;
        bank.clear_bits(tx.txdctl, XDCTL_ENABLE_PM);
        bank.write32(tx.tdbal, *base as u32);
        bank.write32(tx.tdbah, (*base >> 32) as u32);
        bank.write32(tx.tdlen, (cfg.ring_len * 16) as u32);
        bank.write32(tx.tdh, 0);
        bank.write32(tx.tdt, 0);
        bank.set_bits(tx.txdctl, XDCTL_ENABLE_PM);
    }
    // 2. RX queues: disable, reprogram, re-enable. Tail =
    // ring_len - 1: every descriptor was re-armed by the caller,
    // so all of them belong to the device again.
    for (q, base) in rx_bases.iter().enumerate() {
        let rx = rx_queue_regs(q).ok_or("rx queue registers unresolvable")?;
        bank.clear_bits(rx.rxdctl, XDCTL_ENABLE_PM);
        bank.write32(rx.rdbal, *base as u32);
        bank.write32(rx.rdbah, (*base >> 32) as u32);
        bank.write32(rx.rdlen, (cfg.ring_len * 16) as u32);
        bank.write32(rx.rdh, 0);
        bank.write32(rx.rdt, (cfg.ring_len - 1) as u32);
        bank.write32(rx.srrctl, srrctl_bsize | SRRCTL_DESCTYPE_ADV_ONEBUF);
        bank.set_bits(rx.rxdctl, XDCTL_ENABLE_PM);
    }
    // 3. Restore the bring-up receive filter + master enable,
    // then unmask the shared misc vector.
    bank.write32(REG_FCTRL, FCTRL_BAM | FCTRL_UPE | FCTRL_MPE);
    bank.set_bits(REG_RXCTRL, RXCTRL_RXEN);
    bank.write32(REG_EIMS_PM, EIMS_MISC_VECTOR);
    Ok(())
}

/// Detach extras, after [`suspend_plan`] with no WoL: tell
/// firmware the driver is gone.
pub fn detach_plan(bank: &mut impl RegBank) {
    suspend_plan(bank, None);
    bank.clear_bits(REG_CTRL_EXT_PM, CTRL_EXT_DRV_LOAD_PM);
}
