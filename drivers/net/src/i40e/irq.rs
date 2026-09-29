//! i40e MSI-X interrupt wiring.
//!
//! The X710 does not associate a queue with an interrupt vector by
//! writing a vector number into the queue. It builds a **linked list**
//! per vector, threaded through the queue interrupt-control
//! registers, and that shape is the thing worth getting right.
//!
//! For each vector, `PFINT_LNKLSTN` names the first queue in its
//! chain. Every queue's `QINT_RQCTL` / `QINT_TQCTL` then carries a
//! `NEXTQ_INDX` and a `NEXTQ_TYPE` naming the next link. A ring pair
//! contributes two links: the RX control points at the TX queue of
//! the same pair, and the TX control points at the RX queue of the
//! *next* pair — or at [`QUEUE_END_OF_LIST`] if it is the last.
//!
//! Two consequences follow, and both are silent when violated:
//!
//! - A chain that is not terminated runs off into whatever the
//!   register file happens to hold, so the device walks queues that
//!   were never configured.
//! - The vector number written into each queue and the register index
//!   used for `LNKLSTN` and `ITRN` are *not the same number*. The
//!   per-queue field is the MSI-X vector as the PCI capability
//!   numbers it, where 0 is the miscellaneous/admin vector; the
//!   register arrays are indexed from the first queue vector, so they
//!   take `vector - 1`. Linux notes this explicitly because it is
//!   easy to write a consistent-looking off-by-one that lands every
//!   interrupt on the wrong vector.
//!
//! ## References (GPL-2.0-or-later, post 2026-05-20 relicense)
//!
//! - `i40e_register.h` — `I40E_PFINT_*`, `I40E_QINT_*` offsets and
//!   field shifts.
//! - `i40e_main.c` — `i40e_vsi_configure_msix` (the chain above),
//!   `i40e_enable_misc_int_causes`.
//! - `i40e_txrx.h` — `I40E_QUEUE_END_OF_LIST`, the ITR constants.
//! - `i40e_type.h` — `i40e_queue_type`.

#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;

// ── Register offsets ────────────────────────────────────────────────

/// `I40E_PFINT_ICR0` — vector 0's interrupt cause register.
pub const REG_PFINT_ICR0: u64 = 0x0003_8780;
/// `I40E_PFINT_ICR0_ENA` — which causes may raise vector 0.
pub const REG_PFINT_ICR0_ENA: u64 = 0x0003_8800;
/// `I40E_PFINT_DYN_CTL0` — vector 0's dynamic control.
pub const REG_PFINT_DYN_CTL0: u64 = 0x0003_8480;
/// `I40E_PFINT_LNKLST0` — vector 0's queue-chain head.
pub const REG_PFINT_LNKLST0: u64 = 0x0003_8500;

/// `I40E_PFINT_DYN_CTLN(n)` — dynamic control for queue vector `n`,
/// which is MSI-X vector `n + 1`.
pub const fn reg_pfint_dyn_ctln(n: u16) -> u64 {
    0x0003_4800 + (n as u64) * 4
}

/// `I40E_PFINT_LNKLSTN(n)` — queue-chain head for queue vector `n`.
pub const fn reg_pfint_lnklstn(n: u16) -> u64 {
    0x0003_5000 + (n as u64) * 4
}

/// `I40E_PFINT_ITRN(itr, n)` — throttle register `itr` for queue
/// vector `n`. The three throttle banks are 2 KiB apart.
pub const fn reg_pfint_itrn(itr: u8, n: u16) -> u64 {
    0x0003_0000 + (itr as u64) * 2048 + (n as u64) * 4
}

/// `I40E_PFINT_ITR0(itr)` — throttle register `itr` for vector 0.
pub const fn reg_pfint_itr0(itr: u8) -> u64 {
    0x0003_8000 + (itr as u64) * 128
}

/// `I40E_QINT_RQCTL(q)` — RX queue `q`'s interrupt control.
pub const fn reg_qint_rqctl(q: u16) -> u64 {
    0x0003_A000 + (q as u64) * 4
}

/// `I40E_QINT_TQCTL(q)` — TX queue `q`'s interrupt control.
pub const fn reg_qint_tqctl(q: u16) -> u64 {
    0x0003_C000 + (q as u64) * 4
}

// ── Field layout ────────────────────────────────────────────────────

/// MSI-X vector index, 8 bits at 0, in both `QINT_*CTL` registers.
pub const QINT_CTL_MSIX_INDX_SHIFT: u32 = 0;
/// Mask for the MSI-X vector index.
pub const QINT_CTL_MSIX_INDX_MASK: u32 = 0xFF;
/// Throttle-bank index, 2 bits at 11.
pub const QINT_CTL_ITR_INDX_SHIFT: u32 = 11;
/// Mask for the throttle-bank index.
pub const QINT_CTL_ITR_INDX_MASK: u32 = 0x3;
/// Next queue in the chain, 11 bits at 16.
pub const QINT_CTL_NEXTQ_INDX_SHIFT: u32 = 16;
/// Mask for the next-queue index.
pub const QINT_CTL_NEXTQ_INDX_MASK: u32 = 0x7FF;
/// Next queue's type, 1 bit at 27.
pub const QINT_CTL_NEXTQ_TYPE_SHIFT: u32 = 27;
/// Enable this queue as an interrupt cause, bit 30.
pub const QINT_CTL_CAUSE_ENA: u32 = 1 << 30;

/// First queue in a vector's chain, 11 bits at 0 of `PFINT_LNKLSTN`.
pub const LNKLST_FIRSTQ_INDX_SHIFT: u32 = 0;
/// Mask for the first-queue index.
pub const LNKLST_FIRSTQ_INDX_MASK: u32 = 0x7FF;
/// First queue's type, 1 bit at 11.
pub const LNKLST_FIRSTQ_TYPE_SHIFT: u32 = 11;

/// `I40E_QUEUE_END_OF_LIST` — written as the next-queue index to
/// terminate a chain. All eleven bits set.
pub const QUEUE_END_OF_LIST: u32 = 0x7FF;

/// `i40e_queue_type` — which register a chain link refers to.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum QueueType {
    /// The link names a receive queue, so `QINT_RQCTL`.
    Rx = 0,
    /// The link names a transmit queue, so `QINT_TQCTL`.
    Tx = 1,
}

// ── Interrupt throttling ────────────────────────────────────────────

/// `I40E_RX_ITR` — throttle bank 0, conventionally receive.
pub const ITR_IDX_RX: u8 = 0;
/// `I40E_TX_ITR` — throttle bank 1, conventionally transmit.
pub const ITR_IDX_TX: u8 = 1;
/// `I40E_SW_ITR` — throttle bank 2, used for software interrupts.
pub const ITR_IDX_SW: u8 = 2;
/// Throttle index meaning "no throttling"; the field is two bits, so
/// 3 is the only value that is not a bank.
pub const ITR_IDX_NONE: u8 = 3;

/// `I40E_ITR_20K` — roughly 20,000 interrupts/s, in 2 µs units.
pub const ITR_20K: u16 = 50;
/// `I40E_ITR_8K`.
pub const ITR_8K: u16 = 122;
/// `I40E_ITR_MASK` — writable bits of a throttle register.
pub const ITR_MASK: u16 = 0x1FFE;

/// Encode an interval for `PFINT_ITRN`.
///
/// The register takes the interval in 4 µs units while the constants
/// above are in 2 µs, which is why Linux writes `target_itr >> 1`.
/// Folding the shift in here keeps the one halving in a single place
/// rather than at every write site.
pub const fn itr_reg_value(interval_2us: u16) -> u32 {
    ((interval_2us & ITR_MASK) >> 1) as u32
}

// ── Chain construction ──────────────────────────────────────────────

/// One register write in a vector's interrupt configuration.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RegWrite {
    /// Byte offset into BAR0.
    pub reg: u64,
    /// Value to write.
    pub value: u32,
}

/// Value for a `QINT_RQCTL` / `QINT_TQCTL` register.
pub const fn qint_ctl_value(vector: u16, itr_idx: u8, next_q: u32, next_type: QueueType) -> u32 {
    QINT_CTL_CAUSE_ENA
        | ((vector as u32 & QINT_CTL_MSIX_INDX_MASK) << QINT_CTL_MSIX_INDX_SHIFT)
        | ((itr_idx as u32 & QINT_CTL_ITR_INDX_MASK) << QINT_CTL_ITR_INDX_SHIFT)
        | ((next_q & QINT_CTL_NEXTQ_INDX_MASK) << QINT_CTL_NEXTQ_INDX_SHIFT)
        | ((next_type as u32) << QINT_CTL_NEXTQ_TYPE_SHIFT)
}

/// Value for a `PFINT_LNKLSTN` register.
pub const fn lnklst_value(first_q: u32, first_type: QueueType) -> u32 {
    ((first_q & LNKLST_FIRSTQ_INDX_MASK) << LNKLST_FIRSTQ_INDX_SHIFT)
        | ((first_type as u32) << LNKLST_FIRSTQ_TYPE_SHIFT)
}

/// Why a vector's chain could not be built.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IrqError {
    /// A chain must contain at least one ring pair, or the vector
    /// would be armed with nothing to point at.
    NoRingPairs,
    /// A queue index does not fit the 11-bit chain field, or would
    /// collide with the end-of-list sentinel.
    QueueIndexOutOfRange(u16),
    /// The MSI-X vector does not fit the 8-bit field.
    VectorOutOfRange(u16),
    /// Vector 0 is the miscellaneous cause vector and has its own
    /// registers; a queue chain cannot be hung off it here.
    VectorZeroReserved,
}

/// Build every register write that binds `n_pairs` ring pairs
/// starting at `base_queue` to MSI-X `vector`.
///
/// `vector` is the MSI-X vector number, so the `PFINT_*N` register
/// arrays are indexed with `vector - 1`. The returned writes are in
/// the order they must be applied: the chain head first, then each
/// pair's RX and TX links, with the final TX link terminated.
pub fn build_vector_chain(
    vector: u16,
    base_queue: u16,
    n_pairs: u16,
) -> Result<Vec<RegWrite>, IrqError> {
    if n_pairs == 0 {
        return Err(IrqError::NoRingPairs);
    }
    if vector == 0 {
        return Err(IrqError::VectorZeroReserved);
    }
    if vector as u32 > QINT_CTL_MSIX_INDX_MASK {
        return Err(IrqError::VectorOutOfRange(vector));
    }
    // The last queue this chain names must still be a legal index and
    // must not be the terminator value.
    let last = (base_queue as u32) + (n_pairs as u32) - 1;
    if last >= QUEUE_END_OF_LIST {
        return Err(IrqError::QueueIndexOutOfRange(last as u16));
    }

    let n = vector - 1;
    let mut out = Vec::with_capacity(2 * n_pairs as usize + 1);

    // The chain starts at the first pair's RX queue.
    out.push(RegWrite {
        reg: reg_pfint_lnklstn(n),
        value: lnklst_value(base_queue as u32, QueueType::Rx),
    });

    for i in 0..n_pairs {
        let qp = base_queue + i;
        // RX links to the TX queue of the same pair.
        out.push(RegWrite {
            reg: reg_qint_rqctl(qp),
            value: qint_ctl_value(vector, ITR_IDX_RX, qp as u32, QueueType::Tx),
        });
        // TX links to the RX queue of the next pair, or terminates.
        let next = if i + 1 == n_pairs {
            QUEUE_END_OF_LIST
        } else {
            (qp + 1) as u32
        };
        out.push(RegWrite {
            reg: reg_qint_tqctl(qp),
            value: qint_ctl_value(vector, ITR_IDX_TX, next, QueueType::Rx),
        });
    }
    Ok(out)
}

/// Throttle-register writes for a vector: receive, transmit, and the
/// software bank Linux pins at 20K.
pub fn build_vector_itr(vector: u16, rx_2us: u16, tx_2us: u16) -> Result<Vec<RegWrite>, IrqError> {
    if vector == 0 {
        return Err(IrqError::VectorZeroReserved);
    }
    let n = vector - 1;
    Ok(alloc::vec![
        RegWrite {
            reg: reg_pfint_itrn(ITR_IDX_RX, n),
            value: itr_reg_value(rx_2us),
        },
        RegWrite {
            reg: reg_pfint_itrn(ITR_IDX_TX, n),
            value: itr_reg_value(tx_2us),
        },
        RegWrite {
            reg: reg_pfint_itrn(ITR_IDX_SW, n),
            value: itr_reg_value(ITR_20K),
        },
    ])
}
