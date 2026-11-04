//! ixgbe DCB programming — MTQC mode + packet-buffer partitioning +
//! RX/TX arbiters + PFC + TC statistics.
//!
//! Grounding: Linux ixgbe @ cbbddb6 — `ixgbe_dcb_82599.c` (all five
//! arbiter/PFC/stats sequences), `ixgbe_dcb.c` (`ixgbe_ieee_credits`,
//! `ixgbe_dcb_hw_config` unpacking), `ixgbe_dcb_82599.h` (arbiter bit
//! defines), `ixgbe_type.h` (register addresses), `ixgbe_main.c`
//! `ixgbe_setup_mtqc` (MTQC rows + SECTXMINIFG), `ixgbe_common.c`
//! packet-buffer setup (EQUAL strategy), and the per-device
//! `get_invariants` functions (RX packet-buffer sizes).
//!
//! ⚠️ NOT datasheet-grounded. Issue #1263 asks for datasheet grounding
//! for the DCB/TC registers + MTQC DCB rows, and no 82599/X540/X550
//! datasheet copy exists in this workspace (searched; the original
//! #1259 lane's datasheet is not on disk here). Every address, bit,
//! and sequence below is therefore Linux-transcribed, marked as such
//! in the PR body, with ONE exception: MTQC's address 0x08120, which
//! the in-tree spec §3 table already carries. Re-grounding this module
//! against the datasheet is a named follow-up; until then the
//! Linux-only status must stay in the PR body, not be laundered into
//! a datasheet claim.
//!
//! Scope notes (all documented, not silently decided):
//! - MTQC VT rows are NOT programmed here: SR-IOV is #1398's
//!   (unmerged) territory, and Linux's VT+DCB combos
//!   (VT_ENA|RT_ENA|8TC_8TQ, VT_ENA|RT_ENA|4TC_4TQ) belong in a single
//!   reconciled MTQC setup once both land. This module programs the
//!   non-VT rows only.
//! - The CEE bandwidth-group credit path (`ixgbe_dcb_calculate_tc_credits`)
//!   is NOT ported: NARF has no DCB netlink consumer, so the config
//!   struct carries explicit per-TC credits. The IEEE ETS credit helper
//!   (`ieee_credits`, pure) IS ported for callers that start from
//!   bandwidth percentages.
//! - DCBx negotiation (LLDP state machine) is NOT implemented.
//! - No DCB disable path: re-probe restores non-DCB mode.
//! - Composition with RSS is unvalidated: RSS's 16-queue set and DCB's
//!   TC queue layout make different queue-layout assumptions, and no
//!   silicon run has combined them. Callers must pick one mode.
//! - With NARF's 1/1 probe, queue 0 belongs to TC0 in every mode.
//!   Multi-TC queue-plan integration (a TC-aware bring-up config) is
//!   a follow-up; the arbiter/credit/PFC programming here is valid
//!   for the TCs regardless of how many queues are instantiated.

use super::queues::RegBank;
use super::{IXGBE_DEV_82599EB, IXGBE_DEV_X540, IXGBE_DEV_X550, IXGBE_DEV_X550EM_X};

// ── Registers (Linux ixgbe_type.h) ─────────────────────────────────

/// MTQC (in-tree spec §3 already carries 0x08120).
pub const REG_MTQC: u64 = 0x08120;
/// TX descriptor arbiter control.
pub const REG_RTTDCS: u64 = 0x04900;
/// Security TX minimum IFG.
pub const REG_SECTXMINIFG: u64 = 0x08810;
/// RX packet-buffer size base (8 of these).
pub const REG_RXPBSIZE_BASE: u64 = 0x03C00;
/// TX packet-buffer size base (8 of these).
pub const REG_TXPBSIZE_BASE: u64 = 0x0CC00;
/// TX packet-buffer threshold base (8 of these).
pub const REG_TXPBTHRESH_BASE: u64 = 0x04950;
/// RX packet arbiter control/status.
pub const REG_RTRPCS: u64 = 0x02430;
/// RX user-priority → traffic-class map.
pub const REG_RTRUP2TC: u64 = 0x03020;
/// RX per-TC credit base (8 of these).
pub const REG_RTRPT4C_BASE: u64 = 0x02140;
/// TX descriptor arbiter queue select.
pub const REG_RTTDQSEL: u64 = 0x04904;
/// TX descriptor arbiter per-queue credit.
pub const REG_RTTDT1C: u64 = 0x04908;
/// TX descriptor arbiter per-TC credit base (8 of these).
pub const REG_RTTDT2C_BASE: u64 = 0x04910;
/// TX packet arbiter control/status.
pub const REG_RTTPCS: u64 = 0x0CD00;
/// TX user-priority → traffic-class map.
pub const REG_RTTUP2TC: u64 = 0x0C800;
/// TX packet arbiter per-TC credit base (8 of these).
pub const REG_RTTPT2C_BASE: u64 = 0x0CD20;
/// Flow-control configuration.
pub const REG_FCCFG: u64 = 0x03D00;
/// MAC flow-control.
pub const REG_MFLCN: u64 = 0x04294;
/// Per-TC RX flow-control low watermark base (8 of these).
pub const REG_FCRTL_BASE: u64 = 0x03220;
/// Per-TC RX flow-control high watermark base (8 of these).
pub const REG_FCRTH_BASE: u64 = 0x03260;
/// Per-TC pause-time base (4 of these, 2 TCs each).
pub const REG_FCTTV_BASE: u64 = 0x03200;
/// Flow-control refresh threshold.
pub const REG_FCRTV: u64 = 0x032A0;
/// RX queue → statistics mapping base (32 of these).
pub const REG_RQSMR_BASE: u64 = 0x02300;
/// TX queue → statistics mapping base (32 of these).
pub const REG_TQSM_BASE: u64 = 0x08600;

// ── MTQC (Linux ixgbe_setup_mtqc, non-VT rows only) ─────────────────

/// DCB enable.
pub const MTQC_RT_ENA: u32 = 0x1;
/// 8 TCs (with RT_ENA) / 8 TX queues per pool (with VT_ENA).
pub const MTQC_8TC_8TQ: u32 = 0xC;
/// 4 TCs (with RT_ENA) / 4 TX queues per pool (with VT_ENA).
pub const MTQC_4TC_4TQ: u32 = 0x8;

// ── Arbiter bits (Linux ixgbe_dcb_82599.h) ──────────────────────────

/// TX descriptor arbiter: weighted strict priority.
pub const RTTDCS_TDPAC: u32 = 0x0000_0001;
/// TX descriptor arbiter: recycle mode.
pub const RTTDCS_TDRM: u32 = 0x0000_0010;
/// TX descriptor arbiter: disable.
pub const RTTDCS_ARBDIS: u32 = 0x0000_0040;
/// Security TX buffer IFG for DCB mode.
pub const SECTX_DCB: u32 = 0x0000_1F00;
/// RX arbiter: recycle mode.
pub const RTRPCS_RRM: u32 = 0x0000_0002;
/// RX arbiter: arbitration control (0 round-robin, 1 DFP).
pub const RTRPCS_RAC: u32 = 0x0000_0004;
/// RX arbiter: disable.
pub const RTRPCS_ARBDIS: u32 = 0x0000_0040;
/// UP → TC field shift (3 bits per user priority, both directions).
pub const UP2TC_UP_SHIFT: u32 = 3;
/// Per-TC credit: max-credit-limit field shift.
pub const PT4C_MCL_SHIFT: u32 = 12;
/// Per-TC credit: bandwidth-group field shift.
pub const PT4C_BWG_SHIFT: u32 = 9;
/// Per-TC credit: group strict priority.
pub const PT4C_GSP: u32 = 0x4000_0000;
/// Per-TC credit: link strict priority.
pub const PT4C_LSP: u32 = 0x8000_0000;
/// TX packet arbiter: strict priority (vs round-robin).
pub const RTTPCS_TPPAC: u32 = 0x0000_0020;
/// TX packet arbiter: disable.
pub const RTTPCS_ARBDIS: u32 = 0x0000_0040;
/// TX packet arbiter: recycle mode.
pub const RTTPCS_TPRM: u32 = 0x0000_0100;
/// TX packet arbiter: arbitration-delay field shift.
pub const RTTPCS_ARBD_SHIFT: u32 = 22;
/// TX packet arbiter: DCB-mode arbitration delay.
pub const RTTPCS_ARBD_DCB: u32 = 0x4;

// ── Flow control (Linux ixgbe_type.h) ───────────────────────────────

/// TX priority flow control enable.
pub const FCCFG_TFCE_PRIORITY: u32 = 0x0000_0010;
/// MAC flow control: discard pause frames.
pub const MFLCN_DPF: u32 = 0x0000_0002;
/// MAC flow control: receive priority FC enable (single bit).
pub const MFLCN_RPFCE: u32 = 0x0000_0004;
/// MAC flow control: receive FC enable.
pub const MFLCN_RFCE: u32 = 0x0000_0008;
/// MAC flow control: per-TC receive priority FC mask (X540+).
pub const MFLCN_RPFCE_MASK: u32 = 0x0000_0FF4;
/// MAC flow control: per-TC receive priority FC shift (X540+).
pub const MFLCN_RPFCE_SHIFT: u32 = 4;
/// RX flow-control low watermark: XON enable.
pub const FCRTL_XONE: u32 = 0x8000_0000;
/// RX flow-control high watermark: packet-buffer FC enable.
pub const FCRTH_FCEN: u32 = 0x8000_0000;
/// Disabled-TC high-water guard: RXPBSIZE minus 24 KiB, so the TX
/// switch keeps functioning under heavy RX workloads (Linux comment).
pub const PFC_DISABLED_GUARD_BYTES: u32 = 24_576;

// ── Packet buffers (Linux ixgbe_common.c + per-device invariants) ───

/// RXPBSIZE field shift: register value = KiB << 10 (= bytes).
pub const RXPBSIZE_SHIFT: u32 = 10;
/// Total TX packet-buffer space (bytes).
pub const TXPBSIZE_MAX: u32 = 0x0002_8000;
/// Largest TX packet, in KiB units, subtracted from TXPBTHRESH.
pub const TXPKT_SIZE_MAX_KB: u32 = 10;
/// Maximum traffic classes.
pub const MAX_TRAFFIC_CLASS: usize = 8;
/// Maximum user priorities.
pub const MAX_USER_PRIORITY: usize = 8;
/// DCB credit quantum (bytes).
pub const DCB_CREDIT_QUANTUM: u32 = 64;
/// Maximum refill credit (0x1FF * 64 B).
pub const MAX_CREDIT_REFILL: u16 = 511;
/// Maximum credit (256 KiB * 1204 / 64 B, per Linux comment).
pub const MAX_CREDIT: u16 = 4095;

/// RX packet-buffer size in KiB, by device (Linux per-device
/// `get_invariants`: 82599 → 512, X540 family → 384; X550/X550EM_X
/// use the X540 invariants). `None` for ungrounded devices.
pub fn rx_pb_size_kb(did: u16) -> Option<u32> {
    match did {
        IXGBE_DEV_82599EB => Some(512),
        IXGBE_DEV_X540 | IXGBE_DEV_X550 | IXGBE_DEV_X550EM_X => Some(384),
        _ => None,
    }
}

/// Per-TC receive PFC bits exist only on X540 and later (Linux
/// `ixgbe_dcb_config_pfc_82599`: `mac.type >= ixgbe_mac_X540`).
/// On 82599 only the single RPFCE bit is programmed.
pub fn per_tc_pfc_supported(did: u16) -> bool {
    matches!(did, IXGBE_DEV_X540 | IXGBE_DEV_X550 | IXGBE_DEV_X550EM_X)
}

/// Strict-priority type (Linux `strict_prio_type`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PrioType {
    /// No strict priority (ETS bandwidth sharing).
    None,
    /// Group strict priority.
    Group,
    /// Link strict priority.
    Link,
}

/// Per-traffic-class arbiter credits (Linux `tc_bw_alloc` data-credit
/// fields, without the CEE bandwidth-group percentages — NARF
/// callers supply explicit credits, e.g. via [`ieee_credits`]).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TcCredits {
    /// Credit refill amount, in 64-byte units (≤ 511).
    pub refill: u16,
    /// Max credits, in 64-byte units (≤ 4095).
    pub max: u16,
    /// Bandwidth-group index (< 8).
    pub bwg_id: u8,
    /// Strict-priority type.
    pub prio_type: PrioType,
}

/// DCB configuration, programmed by [`DcbConfig::apply`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DcbConfig {
    /// Traffic-class count: exactly 4 or 8 (Linux rounds tcs > 4
    /// to 8 and tcs > 1 to 4; NARF refuses to silently round).
    pub num_tcs: u8,
    /// Per-TC credits; only the first `num_tcs` entries are used.
    pub tc: [TcCredits; MAX_TRAFFIC_CLASS],
    /// User-priority → traffic-class map; every entry < `num_tcs`.
    pub prio_to_tc: [u8; MAX_USER_PRIORITY],
    /// PFC enable mask over user priorities (Linux `pfc_en` is a
    /// UP bitmask; the per-TC enable derives from `prio_to_tc`).
    pub pfc_enable: u8,
    /// Per-TC RX flow-control high watermarks, in KiB units
    /// (register value = watermark << 10); first `num_tcs` used.
    pub high_water: [u32; MAX_TRAFFIC_CLASS],
    /// Per-TC RX flow-control low watermarks, in KiB units.
    pub low_water: [u32; MAX_TRAFFIC_CLASS],
    /// Pause time (FCTTV = pause * 0x00010001 per register pair,
    /// FCRTV = pause / 2).
    pub pause_time: u16,
}

/// [`DcbConfig::apply`] failure.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DcbError {
    /// `num_tcs` is not 4 or 8.
    NumTcs,
    /// A `prio_to_tc` entry is ≥ `num_tcs`.
    TcIndex,
    /// A `bwg_id` is ≥ 8.
    BwgId,
    /// A refill credit exceeds 511.
    Refill,
    /// A max credit exceeds 4095.
    Max,
    /// A watermark does not fit after the << 10 shift.
    Water,
    /// Device has no grounded packet-buffer size.
    Device,
}

/// MTQC word for `num_tcs` (non-VT rows only).
pub const fn mtqc_word(num_tcs: u8) -> u32 {
    match num_tcs {
        8 => MTQC_RT_ENA | MTQC_8TC_8TQ,
        _ => MTQC_RT_ENA | MTQC_4TC_4TQ,
    }
}

/// Pack the UP → TC map into an RTRUP2TC/RTTUP2TC word
/// (3 bits per user priority).
pub fn up2tc_word(prio_to_tc: &[u8; MAX_USER_PRIORITY]) -> u32 {
    let mut word = 0u32;
    for (up, tc) in prio_to_tc.iter().enumerate() {
        word |= (*tc as u32) << (up as u32 * UP2TC_UP_SHIFT);
    }
    word
}

/// Pack an RX per-TC credit word (RTRPT4C: LSP only, never GSP —
/// Linux's RX arbiter sets LSP for `prio_link` and no bit for
/// `prio_group`).
pub fn rtrpt4c_word(c: &TcCredits) -> u32 {
    let mut word = c.refill as u32 | ((c.max as u32) << PT4C_MCL_SHIFT);
    word |= (c.bwg_id as u32) << PT4C_BWG_SHIFT;
    if c.prio_type == PrioType::Link {
        word |= PT4C_LSP;
    }
    word
}

/// Pack a TX descriptor per-TC credit word (RTTDT2C: GSP for
/// `prio_group`, LSP for `prio_link`).
pub fn rttdt2c_word(c: &TcCredits) -> u32 {
    let mut word = (c.max as u32) << PT4C_MCL_SHIFT;
    word |= c.refill as u32;
    word |= (c.bwg_id as u32) << PT4C_BWG_SHIFT;
    if c.prio_type == PrioType::Group {
        word |= PT4C_GSP;
    }
    if c.prio_type == PrioType::Link {
        word |= PT4C_LSP;
    }
    word
}

/// Pack a TX packet per-TC credit word (RTTPT2C: same bit layout
/// as RTTDT2C, refill in the low bits).
pub fn rttpt2c_word(c: &TcCredits) -> u32 {
    let mut word = c.refill as u32;
    word |= (c.max as u32) << PT4C_MCL_SHIFT;
    word |= (c.bwg_id as u32) << PT4C_BWG_SHIFT;
    if c.prio_type == PrioType::Group {
        word |= PT4C_GSP;
    }
    if c.prio_type == PrioType::Link {
        word |= PT4C_LSP;
    }
    word
}

/// TX queue counts per traffic class in the 8-TC hardware layout
/// (Linux `ixgbe_dcb_config_tc_stats_82599` TQSM comment:
/// 32, 32, 16, 16, 8, 8, 8, 8). The RX layout is 16 queues per TC.
/// These are the hardware plans, not NARF's instantiated queues.
pub const TX_QUEUES_PER_TC: [usize; MAX_TRAFFIC_CLASS] = [32, 32, 16, 16, 8, 8, 8, 8];
/// RX queues per traffic class in the hardware layout.
pub const RX_QUEUES_PER_TC: usize = 16;

/// IEEE 802.1Qaz credit computation (Linux `ixgbe_ieee_credits`,
/// pure): per-TC bandwidth percentages → (refill, max) credit pairs
/// in 64-byte units. `max_frame` is the maximum frame size in bytes.
/// TCs with zero bandwidth still get the minimum credit.
pub fn ieee_credits(bw: &[u8; MAX_TRAFFIC_CLASS], max_frame: u32) -> ([u16; 8], [u16; 8]) {
    let min_credit = ((max_frame / 2) + DCB_CREDIT_QUANTUM - 1) / DCB_CREDIT_QUANTUM;
    let mut min_percent: u32 = 100;
    for i in 0..MAX_TRAFFIC_CLASS {
        let b = bw[i] as u32;
        if b != 0 && b < min_percent {
            min_percent = b;
        }
    }
    let multiplier = min_credit / min_percent + 1;
    let mut refill = [0u16; MAX_TRAFFIC_CLASS];
    let mut max = [0u16; MAX_TRAFFIC_CLASS];
    for i in 0..MAX_TRAFFIC_CLASS {
        let b = bw[i] as u32;
        let mut val = b * multiplier;
        if val > MAX_CREDIT_REFILL as u32 {
            val = MAX_CREDIT_REFILL as u32;
        }
        if val < min_credit {
            val = min_credit;
        }
        refill[i] = val as u16;
        max[i] = if b != 0 {
            (b * MAX_CREDIT as u32 / 100) as u16
        } else {
            min_credit as u16
        };
    }
    (refill, max)
}

/// Packet-buffer words for the EQUAL strategy (Linux packet-buffer
/// setup): RX word per TC = (rx KiB / num) << 10, TX word =
/// TXPBSIZE_MAX / num, TX threshold = (TX word / 1024) - 10.
pub fn pb_words(num_tcs: u8, rx_pb_kb: u32) -> (u32, u32, u32) {
    let num = num_tcs as u32;
    let rx = (rx_pb_kb / num) << RXPBSIZE_SHIFT;
    let tx = TXPBSIZE_MAX / num;
    let thresh = tx / 1024 - TXPKT_SIZE_MAX_KB;
    (rx, tx, thresh)
}

impl DcbConfig {
    /// Validate the config (including device support). [`apply`]
    /// re-validates, so callers may skip this and read the error
    /// from `apply` instead.
    pub fn validate(&self, did: u16) -> Result<(), DcbError> {
        if self.num_tcs != 4 && self.num_tcs != 8 {
            return Err(DcbError::NumTcs);
        }
        if rx_pb_size_kb(did).is_none() {
            return Err(DcbError::Device);
        }
        let n = self.num_tcs as usize;
        for up in 0..MAX_USER_PRIORITY {
            if self.prio_to_tc[up] as usize >= n {
                return Err(DcbError::TcIndex);
            }
        }
        for i in 0..n {
            let c = &self.tc[i];
            if c.bwg_id as usize >= MAX_TRAFFIC_CLASS {
                return Err(DcbError::BwgId);
            }
            if c.refill > MAX_CREDIT_REFILL {
                return Err(DcbError::Refill);
            }
            if c.max > MAX_CREDIT {
                return Err(DcbError::Max);
            }
            // Watermarks shift left by 10 into a u32.
            if self.high_water[i] > 0x003F_FFFF || self.low_water[i] > 0x003F_FFFF {
                return Err(DcbError::Water);
            }
        }
        Ok(())
    }

    /// Program MTQC mode + packet buffers + RX arbiter + TX
    /// descriptor arbiter + TX packet arbiter + PFC + TC statistics,
    /// in that order (mode and buffers first: PFC's disabled-TC guard
    /// reads the newly programmed RXPBSIZE).
    ///
    /// Caller contract: call before bringing up traffic. The
    /// arbiter sequences self-disable around their own writes, but
    /// the MTQC write reinterprets the queue layout and is not
    /// traffic-safe under live queues — same class of note as
    /// `configure_rss`'s RX-disabled requirement.
    pub fn apply(&self, bank: &mut impl RegBank, did: u16) -> Result<(), DcbError> {
        self.validate(did)?;
        let rx_pb_kb = rx_pb_size_kb(did).ok_or(DcbError::Device)?;
        let n = self.num_tcs as usize;

        // 1. MTQC mode, with the TX descriptor arbiter disabled
        // around the write (Linux ixgbe_setup_mtqc: the restore
        // clears ARBDIS from the originally read value).
        let rttdcs = bank.read32(REG_RTTDCS);
        bank.write32(REG_RTTDCS, rttdcs | RTTDCS_ARBDIS);
        bank.write32(REG_MTQC, mtqc_word(self.num_tcs));
        bank.set_bits(REG_SECTXMINIFG, SECTX_DCB);
        bank.write32(REG_RTTDCS, rttdcs & !RTTDCS_ARBDIS);

        // 2. Packet-buffer partitioning, EQUAL strategy.
        let (rx_word, tx_word, thresh) = pb_words(self.num_tcs, rx_pb_kb);
        for i in 0..n {
            bank.write32(REG_RXPBSIZE_BASE + 4 * i as u64, rx_word);
        }
        for i in 0..n {
            bank.write32(REG_TXPBSIZE_BASE + 4 * i as u64, tx_word);
            bank.write32(REG_TXPBTHRESH_BASE + 4 * i as u64, thresh);
        }
        for i in n..MAX_TRAFFIC_CLASS {
            bank.write32(REG_RXPBSIZE_BASE + 4 * i as u64, 0);
            bank.write32(REG_TXPBSIZE_BASE + 4 * i as u64, 0);
            bank.write32(REG_TXPBTHRESH_BASE + 4 * i as u64, 0);
        }

        // 3. RX packet arbiter: disable, UP map, per-TC credits, enable.
        bank.write32(REG_RTRPCS, RTRPCS_RRM | RTRPCS_RAC | RTRPCS_ARBDIS);
        bank.write32(REG_RTRUP2TC, up2tc_word(&self.prio_to_tc));
        for i in 0..MAX_TRAFFIC_CLASS {
            bank.write32(REG_RTRPT4C_BASE + 4 * i as u64, rtrpt4c_word(&self.tc[i]));
        }
        bank.write32(REG_RTRPCS, RTRPCS_RRM | RTRPCS_RAC);

        // 4. TX descriptor arbiter: clear per-queue credits (per-TC
        // credits are used instead), per-TC credits, enable.
        for q in 0..128u64 {
            bank.write32(REG_RTTDQSEL, q as u32);
            bank.write32(REG_RTTDT1C, 0);
        }
        for i in 0..MAX_TRAFFIC_CLASS {
            bank.write32(REG_RTTDT2C_BASE + 4 * i as u64, rttdt2c_word(&self.tc[i]));
        }
        bank.write32(REG_RTTDCS, RTTDCS_TDPAC | RTTDCS_TDRM);

        // 5. TX packet arbiter: disable, UP map, per-TC credits, enable.
        bank.write32(
            REG_RTTPCS,
            RTTPCS_TPPAC | RTTPCS_TPRM | (RTTPCS_ARBD_DCB << RTTPCS_ARBD_SHIFT) | RTTPCS_ARBDIS,
        );
        bank.write32(REG_RTTUP2TC, up2tc_word(&self.prio_to_tc));
        for i in 0..MAX_TRAFFIC_CLASS {
            bank.write32(REG_RTTPT2C_BASE + 4 * i as u64, rttpt2c_word(&self.tc[i]));
        }
        bank.write32(
            REG_RTTPCS,
            RTTPCS_TPPAC | RTTPCS_TPRM | (RTTPCS_ARBD_DCB << RTTPCS_ARBD_SHIFT),
        );

        // 6. PFC: TX priority FC, RX per-TC/single-bit FC, per-TC
        // thresholds, pause time, refresh threshold.
        bank.write32(REG_FCCFG, FCCFG_TFCE_PRIORITY);
        let mut mflcn = bank.read32(REG_MFLCN);
        mflcn |= MFLCN_DPF;
        mflcn &= !(MFLCN_RPFCE_MASK | MFLCN_RFCE);
        if per_tc_pfc_supported(did) {
            mflcn |= (self.pfc_enable as u32) << MFLCN_RPFCE_SHIFT;
        }
        if self.pfc_enable != 0 {
            mflcn |= MFLCN_RPFCE;
        }
        bank.write32(REG_MFLCN, mflcn);
        // Highest TC named by the UP map.
        let mut max_tc = 0usize;
        for up in 0..MAX_USER_PRIORITY {
            let tc = self.prio_to_tc[up] as usize;
            if tc > max_tc {
                max_tc = tc;
            }
        }
        for i in 0..=max_tc {
            let enabled = (0..MAX_USER_PRIORITY)
                .any(|up| self.prio_to_tc[up] as usize == i && (self.pfc_enable & (1 << up)) != 0);
            if enabled {
                bank.write32(
                    REG_FCRTL_BASE + 4 * i as u64,
                    (self.low_water[i] << 10) | FCRTL_XONE,
                );
                bank.write32(
                    REG_FCRTH_BASE + 4 * i as u64,
                    (self.high_water[i] << 10) | FCRTH_FCEN,
                );
            } else {
                // Disabled TC: high water = buffer size minus the
                // 24 KiB TX-switch guard; low water 0.
                let rxpbsize = bank.read32(REG_RXPBSIZE_BASE + 4 * i as u64);
                bank.write32(REG_FCRTL_BASE + 4 * i as u64, 0);
                bank.write32(
                    REG_FCRTH_BASE + 4 * i as u64,
                    rxpbsize - PFC_DISABLED_GUARD_BYTES,
                );
            }
        }
        for i in max_tc + 1..MAX_TRAFFIC_CLASS {
            bank.write32(REG_FCRTL_BASE + 4 * i as u64, 0);
            bank.write32(REG_FCRTH_BASE + 4 * i as u64, 0);
        }
        let pause = self.pause_time as u32;
        for i in 0..(MAX_TRAFFIC_CLASS / 2) {
            bank.write32(REG_FCTTV_BASE + 4 * i as u64, pause * 0x0001_0001);
        }
        bank.write32(REG_FCRTV, pause / 2);

        // 7. TC statistics: RX 16 queues per TC, TX 32/32/16/16/
        // 8/8/8/8 (Linux programs this mapping unconditionally).
        for i in 0..32u64 {
            bank.write32(REG_RQSMR_BASE + 4 * i, 0x0101_0101 * (i / 4) as u32);
        }
        for i in 0..32u64 {
            let word = match i {
                0..=7 => 0x0000_0000,
                8..=15 => 0x0101_0101,
                16..=19 => 0x0202_0202,
                20..=23 => 0x0303_0303,
                24..=25 => 0x0404_0404,
                26..=27 => 0x0505_0505,
                28..=29 => 0x0606_0606,
                _ => 0x0707_0707,
            };
            bank.write32(REG_TQSM_BASE + 4 * i, word);
        }

        Ok(())
    }
}

/// Decode the RX UP → TC map from RTRUP2TC
/// (Linux `ixgbe_dcb_read_rtrup2tc_82599`).
pub fn read_up_to_tc(bank: &impl RegBank) -> [u8; MAX_USER_PRIORITY] {
    let reg = bank.read32(REG_RTRUP2TC);
    let mut map = [0u8; MAX_USER_PRIORITY];
    for up in 0..MAX_USER_PRIORITY {
        map[up] = ((reg >> (up as u32 * UP2TC_UP_SHIFT)) & 0x7) as u8;
    }
    map
}
