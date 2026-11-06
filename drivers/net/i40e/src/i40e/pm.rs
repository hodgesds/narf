//! i40e suspend / resume register plans (issue #793).
//!
//! The register conversation `Hardware::suspend` / `Hardware::resume`
//! run, factored over a minimal bank so fixtures drive the exact
//! program against a fake bank (end-to-end register writes, no
//! silicon) while the live path runs it against BAR0 via
//! [`MmioBank`]. Same shape as ixgbe's `pm` plans and igc's
//! `hardware::Registers` (read/write/wait over `&self`, so a wait
//! predicate can read the bank it polls).
//!
//! Grounding: every offset and bit is the driver's existing
//! constant — `ring::{reg_qtx_ena, reg_qrx_ena, QENA_REQ, QENA_STAT,
//! pre_tx_queue_cfg}` for the queue handshake (Linux polls
//! `QENA_STAT` after `QENA_REQ`, `I40E_QTX_ENA_WAIT_COUNT`), and
//! `irq::{REG_PFINT_ICR0_ENA, REG_PFINT_DYN_CTL0,
//! reg_pfint_dyn_ctln}` + the `interrupts::Shared::mask` /
//! `Interrupts::enable` re-arm program for interrupt masking. No new
//! register values are invented here.
//!
//! Order mirrors the live helpers (`QueuePair::disable` /
//! `QueuePair::enable`, `Interrupts::quiesce` / `enable`):
//! * Suspend: mask interrupts (ICR0_ENA = 0, dynamic controls to
//!   MASK) → per queue, RX first then TX: wait settled, clear
//!   `QENA_REQ`, wait `QENA_STAT` clear; TX also clears the
//!   `GLLAN_TXPRE_QDIS` bit first (`pre_tx_queue_cfg` disable).
//! * Resume: refuse when the cause register reports a fatal
//!   condition (the `enable` check) → per queue, TX first then RX:
//!   clear the TXPRE disable, wait settled, zero the TX head, set
//!   `QENA_REQ`, wait `QENA_STAT` set, then RX the same way and
//!   hand the device the RX ring tail → re-arm interrupts
//!   (ICR0_ENA = ADMINQ | FATAL, dynamic controls to ARM).
//!
//! Deliberate deltas: no PF reset and no Admin Queue teardown on
//! either side — the AQ rings, HMC contexts and VSI state persist
//! across suspend (only the LAN queue enables gate DMA), so resume
//! is a re-enable, not a bring-up replay; a D3 transition that
//! actually loses PF state is recovered by the existing recovery
//! pump (`recover()` runs a full PF reset + rebuild when the IRQ
//! layer reports failed). No PCI power-state transition — the bus
//! layer owns PCI config. Link state is not re-read by AQ here (a
//! PM handler cannot block on an Admin Queue completion with
//! interrupts gated); the ARQ pump refreshes it from link-status
//! events once interrupts re-arm, and resume republishes the cached
//! sample meanwhile.

use super::irq::{
    reg_pfint_dyn_ctln, ITR_IDX_NONE, REG_PFINT_DYN_CTL0, REG_PFINT_ICR0, REG_PFINT_ICR0_ENA,
};
use super::ring::{
    reg_gllan_txpre_qdis, reg_qrx_ena, reg_qrx_tail, reg_qtx_ena, reg_qtx_head, QENA_REQ,
    QENA_STAT, QUEUE_ENA_TIMEOUT_MS, RX_TAIL_INIT, TXPRE_QDIS_CLEAR_QDIS, TXPRE_QDIS_QINDX_MASK,
    TXPRE_QDIS_SET_QDIS,
};
use super::{interrupts::ADMINQ, interrupts::FATAL};
use narf_bus::MmioRegion;

/// Mask value for a dynamic interrupt control: no ITR bank selected,
/// preserving programmed moderation (`interrupts::MASK`).
const MASK: u32 = (ITR_IDX_NONE as u32) << 3;
/// Re-arm value for a dynamic interrupt control (`interrupts::ARM`).
const ARM: u32 = 1 | 2 | MASK;

/// Minimal register-bank abstraction so the register conversation
/// can be exercised against a fake bank in fixtures and against
/// real MMIO in the driver via [`MmioBank`].
pub trait RegBank {
    fn read32(&self, offset: u64) -> u32;
    fn write32(&self, offset: u64, value: u32);
    /// Bounded wait for `ready` to become true. Live banks spin to
    /// the deadline; fixtures evaluate the predicate once (the fake
    /// models the device acking `QENA_STAT` on the `QENA_REQ` write).
    fn wait(&self, us: u64, ready: impl FnMut() -> bool) -> bool;
}

/// [`RegBank`] over a real BAR0 mapping.
#[derive(Debug)]
pub struct MmioBank<'a> {
    csr: &'a MmioRegion,
}

impl<'a> MmioBank<'a> {
    pub fn new(csr: &'a MmioRegion) -> Self {
        Self { csr }
    }
}

impl RegBank for MmioBank<'_> {
    fn read32(&self, offset: u64) -> u32 {
        // SAFETY: the driver owns BAR0 exclusively; the caller
        // guarantees `offset` is a valid device register.
        unsafe { self.csr.read32(offset) }
    }
    fn write32(&self, offset: u64, value: u32) {
        // SAFETY: same as above.
        unsafe { self.csr.write32(offset, value) }
    }
    fn wait(&self, us: u64, ready: impl FnMut() -> bool) -> bool {
        narf_scheduler::responsive_spin_until(ready, narf_time::Deadline::after_us(us))
    }
}

/// Set or clear a queue's `QENA_REQ` bit, preserving the rest
/// (`ring::set_queue_enable` over the bank).
fn set_queue_enable(bank: &impl RegBank, reg: u64, enable: bool) {
    let mut val = bank.read32(reg);
    if enable {
        val |= QENA_REQ;
    } else {
        val &= !QENA_REQ;
    }
    bank.write32(reg, val);
}

/// Wait for `QENA_STAT` to catch up with whatever `QENA_REQ`
/// already holds, so a fresh request is not written over an
/// in-flight one (`ring::wait_queue_settled` over the bank). The
/// result is deliberately discarded: like Linux's loop, this falls
/// through on timeout and lets the subsequent state wait report
/// the real failure, which names the queue direction.
fn wait_queue_settled(bank: &impl RegBank, reg: u64) {
    let _ = bank.wait(QUEUE_ENA_TIMEOUT_MS * 1000, || {
        let v = bank.read32(reg);
        (v & QENA_REQ != 0) == (v & QENA_STAT != 0)
    });
}

/// Wait for `QENA_STAT` to match the requested state
/// (`ring::wait_queue_state` over the bank).
fn wait_queue_state(bank: &impl RegBank, reg: u64, enabled: bool) -> bool {
    bank.wait(QUEUE_ENA_TIMEOUT_MS * 1000, || {
        (bank.read32(reg) & QENA_STAT != 0) == enabled
    })
}

/// `ring::pre_tx_queue_cfg` over the bank: set or clear the
/// `GLLAN_TXPRE_QDIS` disable for one absolute queue.
fn pre_tx_queue_cfg(bank: &impl RegBank, base_queue: u16, pf_q: u16, enable: bool) {
    let abs = base_queue as u32 + pf_q as u32;
    let block = abs / 128;
    let index = abs % 128;
    let mut val = bank.read32(reg_gllan_txpre_qdis(block));
    val &= !TXPRE_QDIS_QINDX_MASK;
    val |= index & TXPRE_QDIS_QINDX_MASK;
    val |= if enable {
        TXPRE_QDIS_CLEAR_QDIS
    } else {
        TXPRE_QDIS_SET_QDIS
    };
    bank.write32(reg_gllan_txpre_qdis(block), val);
}

/// Suspend register program: mask interrupts, then disable every
/// LAN queue (RX first, then TX — `QueuePair::disable` order).
/// `queues` holds the PF-relative queue indices, in order. Disable
/// errors are swallowed, mirroring `QueuePair::disable`: this runs
/// on the teardown path where there is nothing useful to do with
/// them.
pub fn suspend_plan(bank: &impl RegBank, base_queue: u16, queues: &[u16]) {
    // 1. Mask PCI/device delivery (`Interrupts::Shared::mask`).
    bank.write32(REG_PFINT_ICR0_ENA, 0);
    bank.write32(REG_PFINT_DYN_CTL0, MASK);
    for q in 0..queues.len() {
        bank.write32(reg_pfint_dyn_ctln(q as u16), MASK);
    }
    let _ = bank.read32(REG_PFINT_ICR0_ENA);
    // 2. Disable the queues, RX before TX.
    for &pf_q in queues {
        wait_queue_settled(bank, reg_qrx_ena(pf_q));
        set_queue_enable(bank, reg_qrx_ena(pf_q), false);
        let _ = wait_queue_state(bank, reg_qrx_ena(pf_q), false);
        pre_tx_queue_cfg(bank, base_queue, pf_q, false);
        wait_queue_settled(bank, reg_qtx_ena(pf_q));
        set_queue_enable(bank, reg_qtx_ena(pf_q), false);
        let _ = wait_queue_state(bank, reg_qtx_ena(pf_q), false);
    }
}

/// Resume register program: re-enable every LAN queue (TX first,
/// then RX — `QueuePair::enable` order), then re-arm interrupts.
/// `Err` names the queue direction whose `QENA_STAT` never
/// followed the request; on `Err` the device stays quiesced and
/// the caller may re-probe or fail the PF into recovery.
pub fn resume_plan(
    bank: &impl RegBank,
    base_queue: u16,
    queues: &[u16],
) -> Result<(), &'static str> {
    // Refuse a fatally wedged PF (`Interrupts::enable` check);
    // ICR0 is read-to-clear, so this also drains stale causes.
    if bank.read32(REG_PFINT_ICR0) & FATAL != 0 {
        return Err("fatal interrupt cause set");
    }
    for &pf_q in queues {
        pre_tx_queue_cfg(bank, base_queue, pf_q, true);
        // Let any enable/disable already in flight finish before
        // asking for a new state — a REQ written while STAT is
        // still catching up is lost.
        wait_queue_settled(bank, reg_qtx_ena(pf_q));
        bank.write32(reg_qtx_head(pf_q), 0);
        set_queue_enable(bank, reg_qtx_ena(pf_q), true);
        if !wait_queue_state(bank, reg_qtx_ena(pf_q), true) {
            return Err("tx queue enable timeout");
        }
        wait_queue_settled(bank, reg_qrx_ena(pf_q));
        set_queue_enable(bank, reg_qrx_ena(pf_q), true);
        if !wait_queue_state(bank, reg_qrx_ena(pf_q), true) {
            return Err("rx queue enable timeout");
        }
        // Hand the device the RX ring, less the one slot that
        // keeps a full ring distinguishable from an empty one.
        bank.write32(reg_qrx_tail(pf_q), RX_TAIL_INIT as u32);
    }
    // Re-arm interrupts (`Interrupts::enable` re-arm program,
    // minus the setup-only chain rebuild + MSI-X table programming,
    // which persist across suspend).
    bank.write32(REG_PFINT_ICR0_ENA, ADMINQ | FATAL);
    bank.write32(REG_PFINT_DYN_CTL0, ARM);
    for q in 0..queues.len() {
        bank.write32(reg_pfint_dyn_ctln(q as u16), ARM);
    }
    Ok(())
}
