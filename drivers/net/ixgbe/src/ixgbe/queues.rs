//! ixgbe multi-queue register addressing — the keystone for the
//! Ethernet full-support stream.
//!
//! Grounding (STRICT, per the lane brief): every offset and bit in
//! this module comes from the public Intel 82599 10 GbE Controller
//! Datasheet (rev. 2.0, §8.2 register summary + §8.2.3.5/.8/.9
//! field tables). No Linux ixgbe source was consulted for any value
//! here; Linux is only the feature-set comparison (queue counts,
//! feature names). Where the pre-existing in-tree code or spec
//! disagreed with the datasheet, the datasheet wins and the fix is
//! called out in the commit message:
//!
//! * RX queue blocks: `RDBAL[n]` at `0x01000 + 0x40*n` for n = 0..63
//!   and `0x0D000 + 0x40*(n-64)` for n = 64..127 (§8.2). The old
//!   spec table's `0x02100+` row was the SRRCTL alias range, not the
//!   descriptor-base range.
//! * TX queue blocks: `TDBAL[n]` at `0x06000 + 0x40*n`, n = 0..127.
//! * `IVAR[n]` at `0x00900 + 4*n`, n = 0..63 (§8.2.3.5.16) — NOT
//!   `0x01000`, which is `RDBAL[0]`. The old code wrote its MSI-X
//!   routing into the RX descriptor-base registers.
//! * `IVAR_MISC` at `0x00A00` (§8.2.3.5.17) — NOT `0x011E0`. The
//!   OTHER-cause field is bits 14:8 + valid bit 15, so routing the
//!   misc cause to vector 0 is `0x8000`, not the old `0x80` (which
//!   set the TCP-timer valid bit instead).
//! * `GPIE` at `0x00898` (§8.2.3.5.18) — NOT `0x00A50`.
//! * `EIAM` at `0x00890` and `EIAC` at `0x00810` (§8.2) — NOT
//!   `0x00A90` (that is `EICS[1]`).
//!
//! Scope: this module addresses queues 0..127 (the full datasheet
//! range) but the bring-up [`QueueConfig`] caps the live queue count
//! at 64: with MTQC = 0 (non-DCB, non-virtualized) the datasheet's
//! MTQC table gives TX queues 0..63, and RSS mode (MRQE = 0001) is a
//! single 16-queue set (see `rss.rs`). Queues 64..127 need DCB or
//! virtualization modes and stay a sequenced follow-up.

use narf_bus::MmioRegion;

/// Per-queue register-block stride (datasheet §8.2).
pub const QUEUE_STRIDE: u64 = 0x40;

/// Live bring-up cap: queues 0..63 (MTQC non-DCB/non-VT row).
pub const MAX_LIVE_QUEUES: usize = 64;
/// Full datasheet queue range (addressable; needs DCB/VT past 63).
pub const MAX_RX_QUEUES: usize = 128;
/// Full datasheet TX queue range.
pub const MAX_TX_QUEUES: usize = 128;

/// Interrupt-vector allocation registers (datasheet §8.2.3.5.16/.17).
pub const REG_IVAR_BASE: u64 = 0x00900;
pub const REG_IVAR_MISC: u64 = 0x00A00;

/// Minimal 32-bit register-bank abstraction so the register
/// conversation can be exercised against a fake bank in fixtures
/// (end-to-end register writes, no silicon) and against real MMIO
/// in the driver via [`MmioBank`].
pub trait RegBank {
    fn read32(&self, offset: u64) -> u32;
    fn write32(&mut self, offset: u64, value: u32);
    fn set_bits(&mut self, offset: u64, mask: u32) {
        let v = self.read32(offset);
        self.write32(offset, v | mask);
    }
}

/// [`RegBank`] over a real BAR0 mapping.
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
    fn read32(&self, offset: u64) -> u32 {
        // SAFETY: the driver owns BAR0 exclusively; the caller
        // guarantees `offset` is a valid device register.
        unsafe { self.mmio.read32(offset) }
    }
    fn write32(&mut self, offset: u64, value: u32) {
        // SAFETY: same as above.
        unsafe { self.mmio.write32(offset, value) }
    }
}

/// RX queue register block for queue `q` (datasheet §8.2).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RxQueueRegs {
    pub q: usize,
    pub rdbal: u64,
    pub rdbah: u64,
    pub rdlen: u64,
    pub rdh: u64,
    pub rdt: u64,
    pub srrctl: u64,
    pub rxdctl: u64,
}

/// TX queue register block for queue `q` (datasheet §8.2).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TxQueueRegs {
    pub q: usize,
    pub tdbal: u64,
    pub tdbah: u64,
    pub tdlen: u64,
    pub tdh: u64,
    pub tdt: u64,
    pub txdctl: u64,
}

/// RX queue block, or `None` for an out-of-range queue. Queues
/// 0..63 live at `0x01000 + 0x40*q`; queues 64..127 at
/// `0x0D000 + 0x40*(q-64)`.
pub fn rx_queue_regs(q: usize) -> Option<RxQueueRegs> {
    if q >= MAX_RX_QUEUES {
        return None;
    }
    let base = if q < 64 {
        0x01000 + QUEUE_STRIDE * q as u64
    } else {
        0x0D000 + QUEUE_STRIDE * (q - 64) as u64
    };
    Some(RxQueueRegs {
        q,
        rdbal: base,
        rdbah: base + 0x04,
        rdlen: base + 0x08,
        rdh: base + 0x10,
        rdt: base + 0x18,
        srrctl: base + 0x14,
        rxdctl: base + 0x28,
    })
}

/// TX queue block, or `None` for an out-of-range queue
/// (`0x06000 + 0x40*q`, q = 0..127).
pub fn tx_queue_regs(q: usize) -> Option<TxQueueRegs> {
    if q >= MAX_TX_QUEUES {
        return None;
    }
    let base = 0x06000 + QUEUE_STRIDE * q as u64;
    Some(TxQueueRegs {
        q,
        tdbal: base,
        tdbah: base + 0x04,
        tdlen: base + 0x08,
        tdh: base + 0x10,
        tdt: base + 0x18,
        txdctl: base + 0x28,
    })
}

/// IVAR register holding queue `q`'s routing (two queues per
/// register: IVAR[q/2]).
pub fn ivar_reg(q: usize) -> Option<u64> {
    if q >= 128 {
        return None;
    }
    Some(REG_IVAR_BASE + 4 * (q / 2) as u64)
}

/// Pack one queue's field into an IVAR word. Per §8.2.3.5.16 /
/// Fig. 8.1, IVAR[N] holds Rx 2N (bits 5:0 + valid 7), Tx 2N
/// (bits 13:8 + valid 15), Rx 2N+1 (bits 21:16 + valid 23) and
/// Tx 2N+1 (bits 29:24 + valid 31).
///
/// `is_tx` selects the TX field of the pair; the returned word has
/// only this queue's field + valid bit set, so callers OR it into a
/// read-modify-write (see [`route_queue_vector`]).
pub fn ivar_field(q: usize, vector: u8, is_tx: bool) -> u32 {
    let vec = (vector as u32) & 0x3F;
    // q % 2 is 0 or 1 by construction; branch on parity explicitly
    // so the match stays exhaustive without a dead arm.
    let (shift, valid) = if q % 2 == 0 {
        if is_tx {
            (8, 15)
        } else {
            (0, 7)
        }
    } else if is_tx {
        (24, 31)
    } else {
        (16, 23)
    };
    (vec << shift) | (1 << valid)
}

/// Route one queue's RX and TX causes to `vector` (read-modify-
/// write, preserving the sibling queue in the same IVAR).
pub fn route_queue_vector(bank: &mut impl RegBank, q: usize, vector: u8) -> bool {
    let Some(reg) = ivar_reg(q) else {
        return false;
    };
    let cur = bank.read32(reg);
    let field = ivar_field(q, vector, false) | ivar_field(q, vector, true);
    // Clear this queue's old fields first (value + valid bits), then
    // set the new routing, so a re-route never leaves stale bits.
    let clear = match q % 2 {
        0 => 0x0000_FFFFu32,
        _ => 0xFFFF_0000u32,
    };
    bank.write32(reg, (cur & !clear) | field);
    true
}

/// Route the OTHER (misc: link-state etc.) cause to `vector`
/// (IVAR_MISC bits 14:8 + valid bit 15, §8.2.3.5.17).
pub fn route_misc_vector(bank: &mut impl RegBank, vector: u8) -> u32 {
    let word = (((vector as u32) & 0x7F) << 8) | (1 << 15);
    bank.write32(REG_IVAR_MISC, word);
    word
}

/// Bring-up queue configuration. The datapath still runs on queue
/// 0's live rings; `num_tx`/`num_rx` record how many queues the
/// device was configured for (register addressing + IVAR routing
/// cover all of them) and gate RSS/VLAN programming, which needs
/// the queue count to stay in its hardware mode's range.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct QueueConfig {
    pub num_tx: usize,
    pub num_rx: usize,
    pub ring_len: usize,
}

impl QueueConfig {
    /// The Stage-6 shape: one TX queue, one RX queue, 32-entry rings.
    pub const fn single() -> Self {
        Self {
            num_tx: 1,
            num_rx: 1,
            ring_len: 32,
        }
    }

    pub fn validate(&self) -> Result<(), QueueError> {
        if self.num_tx == 0 || self.num_rx == 0 {
            return Err(QueueError::ZeroQueues);
        }
        if self.num_tx > MAX_LIVE_QUEUES || self.num_rx > MAX_LIVE_QUEUES {
            return Err(QueueError::TooManyQueues);
        }
        if self.ring_len < 32 || self.ring_len > 4096 || !self.ring_len.is_power_of_two() {
            return Err(QueueError::BadRingLen);
        }
        Ok(())
    }
}

/// [`QueueConfig::validate`] failure.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum QueueError {
    /// A queue count was zero.
    ZeroQueues,
    /// A queue count exceeded [`MAX_LIVE_QUEUES`] (64).
    TooManyQueues,
    /// Ring length outside 32..=4096 or not a power of two.
    BadRingLen,
}
