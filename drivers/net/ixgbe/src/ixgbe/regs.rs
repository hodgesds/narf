//! ixgbe RSS/VMDq register-map authority — MRQC / RSSRK / RETA.
//!
//! Single source of truth for the three registers, shared by the RSS
//! path (`rss.rs`) and — once it lands — the VMDq path (`vmdq.rs`,
//! PR #1398). Both modules must import these constants, never
//! redefine the addresses: issue #1397 was filed because the two
//! paths each carried their own literals and disagreed.
//!
//! The #1397 verdict (CONCLUSIVE): neither path programmed a wrong
//! register. The Intel 82599 Datasheet (rev. 2.6, 322429-007)
//! dual-maps all three registers — the 0x0E block is the native
//! address, the 0x05 block is the 82598-compatibility alias of the
//! SAME physical register:
//! - MRQC §8.2.3.7.12: "MRQC (0x0EC80 / 0x05818; RW)" — "MRQC is
//!   also mapped to address 0x05818 to maintain compatibility
//!   with the 82598."
//! - RSSRK §8.2.3.7.14: "RSSRK (0x0EB80 + 4*n / 0x05C80 + 4*n;
//!   RW)" — "also mapped to addresses 0x05C80-0x05CA4 ... 82598."
//! - RETA §8.2.3.7.15: "RETA[n] (0x0EB00 + 4*n / 0x05C00 + 4*n;
//!   RW)" — "also mapped to addresses 0x05C00-0x05C7C ... 82598."
//!   Linux's shipping ixgbe programs the 0x05 block on 82599
//!   (ixgbe_type.h:376/:417/:419; used by ixgbe_main.c:4219/:4274/
//!   :4427/:4441), which is the silicon proof for the alias side.
//!   The addresses themselves come from the datasheet; Linux is
//!   cited only as the shipping cross-check for which alias to
//!   program, not as copied code.
//!
//! Canonical choice: this module programs the 0x05 (Linux/compat)
//! addresses. Rationale: Linux is the shipping reference on 82599
//! silicon; the VMDq path already uses them; and the compat alias
//! is the address shared with 82598, so one map serves both
//! generations. The native aliases are kept as constants (not
//! programmed) so the pairing is pinned by the fixture test and
//! nobody "fixes" the canonical addresses back on the belief that
//! Linux is wrong — it is not; the datasheet says both are valid.
//!
//! MRQE mode values (§8.2.3.7.12, matching Linux ixgbe_type.h
//! :2332-:2334): 0001b RSS-only, 1000b VMDq 64 pools no RSS,
//! 1010b VMDq 32 pools + RSS, 1011b VMDq 64 pools + RSS. The
//! VMDq+RSS composition (MRQE 0xB + per-pool RETA) is a follow-up
//! on the VMDq path, not part of this map fix: the addresses were
//! never the blocker, the mode value + per-pool tables are.
//!
//! Scope note: the verdict is for 82599 (the datasheet read).
//! Linux's MRQC/RETA/RSSRK defines are shared across ixgbe MAC
//! types with no per-type variant in ixgbe_type.h, but this
//! module makes no X540/X550 datasheet claim.

/// MRQC — canonical (Linux/compat-alias) address, programmed.
pub const REG_MRQC: u64 = 0x05818;
/// MRQC — datasheet-native alias of the same register.
/// NOT programmed; pinned by the fixture test so the pairing
/// cannot silently drift.
pub const REG_MRQC_NATIVE: u64 = 0x0EC80;
/// RETA base — canonical (Linux/compat-alias) address, programmed.
pub const REG_RETA_BASE: u64 = 0x05C00;
/// RETA base — datasheet-native alias of the same block.
/// NOT programmed; pinned by the fixture test.
pub const REG_RETA_BASE_NATIVE: u64 = 0x0EB00;
/// RSSRK base — canonical (Linux/compat-alias) address, programmed.
pub const REG_RSSRK_BASE: u64 = 0x05C80;
/// RSSRK base — datasheet-native alias of the same block.
/// NOT programmed; pinned by the fixture test.
pub const REG_RSSRK_BASE_NATIVE: u64 = 0x0EB80;

/// RETA register count (128 entries in 32 registers).
pub const RETA_REGS: usize = 32;
/// RSSRK register count (40-byte key in 10 registers).
pub const RSSRK_REGS: usize = 10;
/// Register stride for the RETA/RSSRK arrays.
pub const REG_STRIDE: u64 = 4;

/// MRQE value for RSS-only mode (single 16-queue set).
pub const MRQE_RSS_ONLY: u32 = 0x0001;
/// MRQE value for VMDq, 64 pools, no RSS.
pub const MRQE_VMDQ_64_NO_RSS: u32 = 0x0008;
/// MRQE value for VMDq, 32 pools, with RSS.
pub const MRQE_VMDQ_32_RSS: u32 = 0x000A;
/// MRQE value for VMDq, 64 pools, with RSS.
pub const MRQE_VMDQ_64_RSS: u32 = 0x000B;

// ── EEE control/status (issue #1265) ─────────────────────────────────
// X550 Datasheet rev. 2.7 (333369-009), Table 8-26 (PF Power
// Management Registers Summary) + §5.3.6 (EEE functional
// description). The 82599 Datasheet rev. 2.6 has NO EEE block
// at all, and no X540 EEE registers were found — this section
// is X550 only.
//
// ⚠️ ERRATA: the X550 Specification Update (rev. 2.9) says
// "Energy Efficient Ethernet (EEE) is not enabled in the
// X550. The X550 does not negotiate to or transition to EEE
// mode with a EEE-capable link partner." The registers below
// exist and are readable (the status/counter surface), but
// programming EEER.TX_LPI_EN does not enable EEE on X550
// silicon, and Linux never programs this block. The live EEE
// paths are the FW-PHY (X550EM_A) and ACI (E610) transports
// in `hic.rs` / `aci.rs` / `eee.rs`.
//
// FORCE_TLPI (§5.3.6.1 prose: force Tx LPI even with
// TX_LPI_EN clear, or mid-packet) has NO defined bit
// position in the EEER table — it is deliberately absent
// here and must never be programmed.

/// Tx LPI entry-event counter (X550 §8.2.2.23.4). Counts
/// Tx LPI entries (only while Tx and EEE are enabled);
/// cleared on read; does not wrap at 0xFFFFFFFF.
pub const REG_EEE_TLPIC: u64 = 0x0000_41F4;
/// Rx LPI entry-event counter (X550 §8.2.2.23.5). Counts
/// Rx LPI entries (partner entry detected, only while Rx
/// and EEE are enabled); cleared on read; no wrap.
pub const REG_EEE_RLPIC: u64 = 0x0000_41F8;
/// EEE setup register (X550 §8.2.2.23.6).
pub const REG_EEE_SU: u64 = 0x0000_4380;
/// EEE status register (X550 §8.2.2.23.7).
pub const REG_EEE_STAT: u64 = 0x0000_4398;
/// EEE control register (X550 §8.2.2.23.8).
pub const REG_EEER: u64 = 0x0000_43A0;

/// EEE_SU: DTW_MIN [7:0] — added delay to the clause
/// 78.5 minimum Tw_sys_tx, 0.1 µs resolution. Clause
/// minima: 1000BASE-T 16.5 µs, 100BASE-TX 30 µs,
/// 10GBASE-T 7.36 µs (Case-1) / 4.48 µs (Case-2).
pub const EEE_SU_DTW_MIN_MASK: u32 = 0x0000_00FF;
/// EEE_SU: TW_WAKE_MIN [21:16] — minimum time between an
/// LPI-enter request and a return-to-active request, 1 µs
/// resolution.
pub const EEE_SU_TW_WAKE_MIN_SHIFT: u32 = 16;
pub const EEE_SU_TW_WAKE_MIN_MASK: u32 = 0x003F_0000;
/// EEE_SU: TX_LU_LPI_DLY [25:24] — delay to EEE entry
/// after link-up: 00 = no delay, 01 = 10 ms, 10 = 100 ms,
/// 11 = 1 s (init 11b; clause 78.1.2.1 requires 1 s).
pub const EEE_SU_TX_LU_LPI_DLY_SHIFT: u32 = 24;
pub const EEE_SU_TX_LU_LPI_DLY_MASK: u32 = 0x0300_0000;
pub const EEE_SU_TX_LU_LPI_DLY_1S: u32 = 0x3 << 24;
/// EEE_SU: TEEE_DLY [31:26] — delay to EEE entry once the
/// entry conditions are detected, 1 µs resolution
/// (init 0x2).
pub const EEE_SU_TEEE_DLY_SHIFT: u32 = 26;
pub const EEE_SU_TEEE_DLY_MASK: u32 = 0xFC00_0000;

/// EEE_STAT: EEE negotiated on the link (RO).
pub const EEE_STAT_EEE_NEG: u32 = 1 << 29;
/// EEE_STAT: partner in Rx LPI (RO).
pub const EEE_STAT_RX_LPI_STATUS: u32 = 1 << 30;
/// EEE_STAT: this port in Tx LPI (RO).
pub const EEE_STAT_TX_LPI_STATUS: u32 = 1 << 31;

/// EEER: TW_SYSTEM [15:0] — negotiated Tw_system in µs
/// (via EEE LLDP; defaults to the clause 78.5 minimum if
/// lower; returns to default on link disconnect/autoneg).
/// Flow-control frames wait only Tw_sys_txmin, not this.
pub const EEER_TW_SYSTEM_MASK: u32 = 0x0000_FFFF;
/// EEER: Tx LPI enable (RW, init 0b). No Tx LPI for ≥1 s
/// after link_status→OK (clause 78.1.2.1); only when EEE
/// was negotiated at the link speed.
pub const EEER_TX_LPI_EN: u32 = 1 << 16;
/// EEER: Rx LPI enable (RW, init 1b). Only when EEE was
/// negotiated.
pub const EEER_RX_LPI_EN: u32 = 1 << 17;
/// EEER: force EEE in the MAC logic even when the partner
/// lacks EEE (RW, init 0b; MAC-loopback testing).
pub const EEER_EEE_FRC_AN: u32 = 1 << 28;
