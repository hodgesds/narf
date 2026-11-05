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
