//! ixgbe Flow Director (FDIR) — signature + perfect-match filters, ATR primitive.
//!
//! Grounding: Intel 82599 Datasheet rev. 2.6 (322429-007, Dec 2010,
//! public mirror) §7.1.2.7 (Flow Director Filters) + §8.2.3.21
//! (FDIR registers) + §8.2.3.24.6 (IP6AT), cross-checked against
//! Linux ixgbe @ cbbddb6 (`ixgbe_type.h` register block +
//! `ixgbe_82599.c`: `ixgbe_fdir_enable_82599`,
//! `ixgbe_init_fdir_signature_82599`, `ixgbe_init_fdir_perfect_82599`,
//! `ixgbe_atr_compute_sig_hash_82599`, `ixgbe_fdir_add_signature_filter_82599`,
//! `ixgbe_atr_compute_perfect_hash_82599`, `ixgbe_fdir_set_input_mask_82599`,
//! `ixgbe_fdir_write_perfect_filter_82599`,
//! `ixgbe_fdir_erase_perfect_filter_82599`,
//! `ixgbe_reinit_fdir_tables_82599`). Where the two disagree the
//! datasheet wins; the one disagreement found is called out under
//! "Endianness" below. Every register address, bit, key, and
//! sequence below is transcribed from those sources, not invented.
//!
//! Scope notes (read before extending):
//! - This lane programs ONLY the 0x0EE00 FDIR block. It never touches
//!   MRQC / RETA / RSSRK: verified by grep, no FDIR function in Linux
//!   writes those registers (they live in `ixgbe_setup_mrqc`, the RSS
//!   path). The issue's "ATR interacts with RSS" is steering semantics
//!   (an FDIR-steered flow bypasses RSS indirection), not a register
//!   dependency — so the #1397 MRQC-map conflict does not block this
//!   lane, and this lane does not pick a side in it.
//! - Endianness — read carefully, the first version of this module
//!   got the address registers wrong. The pure/hash functions take
//!   WIRE-ORDER NUMERICS (an IPv4 address as the dotted-quad u32,
//!   an IPv6 dword as `u32::from_be_bytes` of its four wire bytes,
//!   ports as host u16): that is what the hash input stream
//!   (datasheet Table 7.8) is built from, and the bucket oracles
//!   pin it. The 32-bit IP address/mask REGISTERS take the opposite
//!   byte order: the register's LS byte is the first byte on the
//!   wire (datasheet §8.2.3.21.16: "the LS byte of FDIRSIPv6[0] is
//!   first on the wire"; §8.2.3.21.17/.18, same for FDIRIPSA /
//!   FDIRIPDA; §8.2.3.21.4/.5, "The LS bit of this register matches
//!   the first byte on the wire" for the masks), so a register write
//!   is the numeric value byte-swapped (`value.swap_bytes()`, i.e.
//!   `u32::from_le_bytes` of the wire bytes). Linux agrees:
//!   `ixgbe_fdir_write_perfect_filter_82599` issues
//!   `WRITE_REG_BE32`, which on little-endian writes the LE-loaded
//!   `__be32` unchanged — the byte-swapped numeric. The first
//!   version wrote the numerics verbatim to the address/mask
//!   registers; on silicon the filter would have matched the
//!   byte-reversed address and never fired. Corrected here (see
//!   `add_perfect` / `mask_words`); the hash is untouched. Ports,
//!   VLAN, FDIRHASH and FDIRCMD words are numerics, as before
//!   (Linux's `be16_to_cpu` / `ntohs` compositions reduce to them
//!   on LE).
//! - The perfect-bucket hash dropped the common accumulator (see
//!   `perfect_bucket_hash`): Linux's perfect-hash path uses only the
//!   bucket macro with the raw key, so the common-key bits — which
//!   the shared `hash_iter` routes to `com`, as in the signature
//!   path — belong in the bucket. The first version discarded them,
//!   putting filters in the wrong bucket (the IPv4 control vector
//!   hashed to 0x01b4 instead of the pinned 0x1f6c). Corrected here
//!   (fold `com` back into `buck`, the same final fold as
//!   `sig_hash`).
//! - The signature-add path in Linux issues ONE 64-bit write to
//!   FDIRHASH (low dword = hash, high dword = FDIRCMD at +4). `RegBank`
//!   is 32-bit, so this module issues two writes, hash first then
//!   command, matching the 64-bit write's dword order.
//! - Perfect-match IPv6 IS implemented (`add_perfect_ipv6`), per the
//!   datasheet — Linux never implemented it (its write path comments
//!   IPv6 as unsupported and its input mask forces `FDIRM_DIPv6`).
//!   The hardware model is asymmetric, so read §7.1.2.7 before
//!   extending: the SOURCE IPv6 gets a full 128-bit per-filter
//!   match (FDIRSIPv6[0..2] + FDIRIPSA, masked per byte by
//!   FDIRIP6M.SIPM), but there is NO per-filter destination-IPv6
//!   register — the destination is compared as a whole, with no
//!   range support, against the single global IP6AT entry
//!   (datasheet §7.1.2.7: "the destination IPv6 address can only
//!   be compared as a whole (with no range support) to the IP6AT"),
//!   gated by FDIRM.DIPv6 (clear = compare meaningful) and the
//!   per-filter FDIRCMD.IPv6DMatch bit (set = must match IP6AT,
//!   clear = must NOT match). IP6AT is the WoL table
//!   (§8.2.3.24.6, shared with directed-IPv6 wake-up), so
//!   programming it for FDIR also changes the WoL address —
//!   `wol::program_ipv6` is the single writer for that reason.
//!   FDIRIP6M.DIPM is meaningful only for the hash function and
//!   signature filters, never for the perfect-match destination
//!   compare (§8.2.3.21.8). The bucket hash DOES cover the full
//!   destination address (Table 7.8), so `dst_ip` is still part of
//!   the hashed tuple even though the match compares it via IP6AT.
//! - The TX sampling hook (Linux `ixgbe_atr`: parse a TX frame, sample
//!   SYN / every Nth packet, add a signature filter) is NOT here: the
//!   driver has no TX packet-parse point, and the sample rate + queue
//!   binding are policy decisions for a follow-up. What IS here is the
//!   ATR primitive itself: signature-hash computation + signature-filter
//!   add, callable once a TX hook exists.
//! - Persistent filter state IS kept (`FdirState`): `configure_fdir`
//!   / `configure_fdir_mask` / the add methods record what was
//!   programmed, and `restore` replays it (init + masks + IP6AT +
//!   filters, in order) after a table reinit, reset, or resume —
//!   which otherwise clears programmed filters. `replay` is the
//!   no-init half, used after `reinit_tables` (which preserves the
//!   FDIRCTRL mode). The store replays exactly what was recorded;
//!   filters recorded without a config are not replayed (nothing
//!   was ever initialized to replay into).
//! - Cloud / MACVLAN filter modes (`FDIRCTRL_FILTERMODE`, Linux
//!   `ixgbe_type.h` bits 23:21, values 001b/010b) do NOT exist on
//!   the 82599: the datasheet says bits 23:21 are Reserved, in
//!   rev. 2.6 §8.2.3.21.1 AND in rev. 3.4 (Nov 2019) §8.2.3.21.1,
//!   and neither string ("Filter Mode", "MACVLAN", "Cloud") appears
//!   anywhere in either revision; Linux never programs the field
//!   on any 82599 path (the defines are dead — no use in the whole
//!   tree). This driver therefore never sets those bits, and the
//!   `FDIRCTRL_RESERVED_MASK` fixture pins that. If a later part
//!   (X550 family) needs the modes, that belongs to its lane.

use alloc::vec::Vec;

use super::queues::RegBank;

// ── FDIR register block (Linux ixgbe_type.h) ─────────────────────────

/// Flow Director control.
pub const REG_FDIRCTRL: u64 = 0x0EE00;
/// Flow Director IPv6 source (3 regs, 0-2).
pub const REG_FDIRSIPV6_BASE: u64 = 0x0EE0C;
/// Flow Director IPv4 source.
pub const REG_FDIRIPSA: u64 = 0x0EE18;
/// Flow Director IPv4 destination.
pub const REG_FDIRIPDA: u64 = 0x0EE1C;
/// Flow Director ports (src low, dst high).
pub const REG_FDIRPORT: u64 = 0x0EE20;
/// Flow Director VLAN + flex bytes.
pub const REG_FDIRVLAN: u64 = 0x0EE24;
/// Flow Director hash (bucket + soft-id).
pub const REG_FDIRHASH: u64 = 0x0EE28;
/// Flow Director command.
pub const REG_FDIRCMD: u64 = 0x0EE2C;
/// Flow Director free / collision counts.
pub const REG_FDIRFREE: u64 = 0x0EE38;
/// Flow Director IPv4 destination mask.
pub const REG_FDIRDIP4M: u64 = 0x0EE3C;
/// Flow Director IPv4 source mask.
pub const REG_FDIRSIP4M: u64 = 0x0EE40;
/// Flow Director TCP port mask.
pub const REG_FDIRTCPM: u64 = 0x0EE44;
/// Flow Director UDP port mask.
pub const REG_FDIRUDPM: u64 = 0x0EE48;
/// Flow Director max-length / bucket length.
pub const REG_FDIRLEN: u64 = 0x0EE4C;
/// Flow Director unmatched / collision statistics (read to clear).
pub const REG_FDIRUSTAT: u64 = 0x0EE50;
/// Flow Director matched statistics (read to clear).
pub const REG_FDIRFSTAT: u64 = 0x0EE54;
/// Flow Director match count (read to clear).
pub const REG_FDIRMATCH: u64 = 0x0EE58;
/// Flow Director miss count (read to clear).
pub const REG_FDIRMISS: u64 = 0x0EE5C;
/// Flow Director bucket-hash key.
pub const REG_FDIRHKEY: u64 = 0x0EE68;
/// Flow Director signature-hash key.
pub const REG_FDIRSKEY: u64 = 0x0EE6C;
/// Flow Director input mask.
pub const REG_FDIRM: u64 = 0x0EE70;
/// Flow Director IPv6 destination mask.
pub const REG_FDIRIP6M: u64 = 0x0EE74;
/// FDIRIP6M: source-IPv6 mask field shift (bits 15:0; datasheet
/// §8.2.3.21.8). Bit i masks wire byte i of the source address
/// (bit 0 = first byte on the wire); set = byte ignored.
pub const FDIRIP6M_SIPM_SHIFT: u32 = 0;
/// FDIRIP6M: destination-IPv6 mask field shift (bits 31:16).
/// Meaningful only for the hash function and signature filters —
/// never for the perfect-match destination compare (that is
/// FDIRM.DIPv6; datasheet §8.2.3.21.8).
pub const FDIRIP6M_DIPM_SHIFT: u32 = 16;
/// Flow Director SCTP port mask.
pub const REG_FDIRSCTPM: u64 = 0x0EE78;

// ── FDIRCTRL bits ────────────────────────────────────────────────────

/// Packet-buffer allocation: no FDIR buffers.
pub const FDIR_PBALLOC_NONE: u32 = 0;
/// Packet-buffer allocation: 64K filters.
pub const FDIR_PBALLOC_64K: u32 = 1;
/// Packet-buffer allocation: 128K filters.
pub const FDIR_PBALLOC_128K: u32 = 2;
/// Packet-buffer allocation: 256K filters.
pub const FDIR_PBALLOC_256K: u32 = 3;
/// FDIRCTRL: init done (set by hardware).
pub const FDIRCTRL_INIT_DONE: u32 = 0x0000_0008;
/// FDIRCTRL: perfect-match mode.
pub const FDIRCTRL_PERFECT_MATCH: u32 = 0x0000_0010;
/// FDIRCTRL: drop-queue field shift.
pub const FDIRCTRL_DROP_Q_SHIFT: u32 = 8;
/// FDIRCTRL: flex-bytes field shift (ethertype = 6 words).
pub const FDIRCTRL_FLEX_SHIFT: u32 = 16;
/// FDIRCTRL: max filters per bucket field shift.
pub const FDIRCTRL_MAX_LENGTH_SHIFT: u32 = 24;
/// FDIRCTRL: full-threshold field shift (interrupt at 16 * value left).
pub const FDIRCTRL_FULL_THRESH_SHIFT: u32 = 28;
/// FDIRCTRL bits 23:21: Reserved on the 82599 (datasheet rev. 2.6
/// §8.2.3.21.1 and rev. 3.4 §8.2.3.21.1 agree). Linux's
/// `IXGBE_FDIRCTRL_FILTERMODE_*` defines live in these bits but have
/// no 82599 datasheet basis and are never programmed by Linux; this
/// driver never sets them (pinned by fixture).
pub const FDIRCTRL_RESERVED_MASK: u32 = 0x00E0_0000;
/// Polls for INIT_DONE / command completion (Linux `FDIRCMD_CMD_POLL`
/// and `FDIR_INIT_DONE_POLL` are both 10).
pub const FDIR_POLL: u32 = 10;
/// Queue index used for drop filters (Linux `FDIR_DROP_QUEUE`).
pub const FDIR_DROP_QUEUE: u8 = 127;

// ── FDIRCMD bits ─────────────────────────────────────────────────────

/// FDIRCMD command field mask.
pub const FDIRCMD_CMD_MASK: u32 = 0x0000_0003;
/// FDIRCMD: add flow.
pub const FDIRCMD_CMD_ADD_FLOW: u32 = 0x0000_0001;
/// FDIRCMD: remove flow.
pub const FDIRCMD_CMD_REMOVE_FLOW: u32 = 0x0000_0002;
/// FDIRCMD: query + remove if present.
pub const FDIRCMD_CMD_QUERY_REM_FILT: u32 = 0x0000_0003;
/// FDIRCMD: filter valid (read-back).
pub const FDIRCMD_FILTER_VALID: u32 = 0x0000_0004;
/// FDIRCMD: filter update.
pub const FDIRCMD_FILTER_UPDATE: u32 = 0x0000_0008;
/// FDIRCMD: L4 type UDP.
pub const FDIRCMD_L4TYPE_UDP: u32 = 0x0000_0020;
/// FDIRCMD: L4 type TCP.
pub const FDIRCMD_L4TYPE_TCP: u32 = 0x0000_0040;
/// FDIRCMD: L4 type SCTP.
pub const FDIRCMD_L4TYPE_SCTP: u32 = 0x0000_0060;
/// FDIRCMD: IPv6 (bit 7 of the flow-type field).
pub const FDIRCMD_IPV6: u32 = 0x0000_0080;
/// FDIRCMD: IPv6 destination match to IP6AT (bit 4; datasheet
/// §8.2.3.21.22). Meaningful only for perfect-match IPv6 filters:
/// set = the destination IPv6 address must match the IP6AT entry,
/// clear = it must NOT match. Must be clear for all other filters.
/// "This field can never match local VM to VM traffic."
pub const FDIRCMD_IPV6DMATCH: u32 = 0x0000_0010;
/// FDIRCMD: clear hash table (reinit toggle).
pub const FDIRCMD_CLEARHT: u32 = 0x0000_0100;
/// FDIRCMD: drop (drop-queue filters).
pub const FDIRCMD_DROP: u32 = 0x0000_0200;
/// FDIRCMD: last filter in the sequence.
pub const FDIRCMD_LAST: u32 = 0x0000_0800;
/// FDIRCMD: queue enable.
pub const FDIRCMD_QUEUE_EN: u32 = 0x0000_8000;
/// FDIRCMD: flow-type field shift.
pub const FDIRCMD_FLOW_TYPE_SHIFT: u32 = 5;
/// FDIRCMD: RX queue field shift.
pub const FDIRCMD_RX_QUEUE_SHIFT: u32 = 16;
/// FDIRCMD: VT pool field shift (perfect filters).
pub const FDIRCMD_VT_POOL_SHIFT: u32 = 24;
/// FDIRCMD: tunnel filter.
pub const FDIRCMD_TUNNEL_FILTER: u32 = 0x0080_0000;

// ── FDIRHASH / FDIRPORT / FDIRVLAN fields ────────────────────────────

/// FDIRHASH: software-index (soft-id) field shift.
pub const FDIRHASH_SIG_SW_INDEX_SHIFT: u32 = 16;
/// FDIRPORT: destination-port field shift.
pub const FDIRPORT_DESTINATION_SHIFT: u32 = 16;
/// FDIRVLAN: flex-bytes field shift.
pub const FDIRVLAN_FLEX_SHIFT: u32 = 16;

// ── FDIRM bits ───────────────────────────────────────────────────────

/// FDIRM: mask VLAN ID.
pub const FDIRM_VLANID: u32 = 0x0000_0001;
/// FDIRM: mask VLAN priority.
pub const FDIRM_VLANP: u32 = 0x0000_0002;
/// FDIRM: mask VM pool.
pub const FDIRM_POOL: u32 = 0x0000_0004;
/// FDIRM: mask L4 protocol.
pub const FDIRM_L4P: u32 = 0x0000_0008;
/// FDIRM: mask flex bytes.
pub const FDIRM_FLEX: u32 = 0x0000_0010;
/// FDIRM: mask IPv6 destination (always set: IPv6 never matches).
pub const FDIRM_DIPV6: u32 = 0x0000_0020;

// ── ATR hash keys / flow types ───────────────────────────────────────

/// ATR bucket-hash key (Linux `IXGBE_ATR_BUCKET_HASH_KEY`).
pub const ATR_BUCKET_HASH_KEY: u32 = 0x3DAD_14E2;
/// ATR signature-hash key (Linux `IXGBE_ATR_SIGNATURE_HASH_KEY`).
pub const ATR_SIGNATURE_HASH_KEY: u32 = 0x174D_3614;
/// ATR hash mask (15 bits: bucket and signature halves).
pub const ATR_HASH_MASK: u32 = 0x7FFF;
/// Perfect-filter bucket mask (13 bits: max 8K buckets).
pub const PERFECT_BUCKET_MASK: u32 = 0x1FFF;
/// Flow type: IPv4, no L4 (rejected by signature add).
pub const FLOW_TYPE_IPV4: u8 = 0x0;
/// Flow type: UDP over IPv4.
pub const FLOW_TYPE_UDPV4: u8 = 0x1;
/// Flow type: TCP over IPv4.
pub const FLOW_TYPE_TCPV4: u8 = 0x2;
/// Flow type: SCTP over IPv4.
pub const FLOW_TYPE_SCTPV4: u8 = 0x3;
/// Flow type: IPv6, no L4 (rejected by signature add).
pub const FLOW_TYPE_IPV6: u8 = 0x4;
/// Flow type: UDP over IPv6.
pub const FLOW_TYPE_UDPV6: u8 = 0x5;
/// Flow type: TCP over IPv6.
pub const FLOW_TYPE_TCPV6: u8 = 0x6;
/// Flow type: SCTP over IPv6.
pub const FLOW_TYPE_SCTPV6: u8 = 0x7;
/// L4-type field mask within a flow type.
pub const L4TYPE_MASK: u8 = 0x3;
/// Flow-type IPv6 bit.
pub const L4TYPE_IPV6_BIT: u8 = 0x4;
/// Flow-type tunnel bit (stripped before the type switch).
pub const L4TYPE_TUNNEL_BIT: u8 = 0x10;

// ── Errors ───────────────────────────────────────────────────────────

/// Flow Director programming errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FdirError {
    /// Flow type rejected (signature: bare IPv4/IPv6 or unknown type;
    /// IPv4 perfect path: IPv6 bit set — use `add_perfect_ipv6`;
    /// IPv6 perfect path: not an IPv6 flow type).
    BadFlowType,
    /// Input-mask field rejected; the string names the field.
    BadInputMask(&'static str),
    /// RX queue index out of range (> 127).
    BadQueue,
    /// FDIRCMD command field never cleared.
    CmdIncomplete,
    /// Table reinit never observed INIT_DONE.
    ReinitTimeout,
}

impl FdirError {
    /// Static message for `IxgbeError::Other` mapping.
    pub const fn as_str(self) -> &'static str {
        match self {
            FdirError::BadFlowType => "bad FDIR flow type",
            FdirError::BadInputMask(_) => "bad FDIR input mask",
            FdirError::BadQueue => "bad FDIR queue",
            FdirError::CmdIncomplete => "FDIR command incomplete",
            FdirError::ReinitTimeout => "FDIR reinit timeout",
        }
    }
}

// ── Configuration types ──────────────────────────────────────────────

/// Flow Director operating mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FdirMode {
    /// Signature filters (ATR): hash-computed, no input mask.
    Signature,
    /// Perfect-match filters: full tuple + input mask.
    Perfect,
}

/// Packet-buffer allocation (filter-table size).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FdirPballoc {
    /// No FDIR buffers.
    None,
    /// 64K filters (Linux default).
    K64,
    /// 128K filters.
    K128,
    /// 256K filters.
    K256,
}

impl FdirPballoc {
    /// The FDIRCTRL field value (bits [1:0]).
    pub const fn bits(self) -> u32 {
        match self {
            FdirPballoc::None => FDIR_PBALLOC_NONE,
            FdirPballoc::K64 => FDIR_PBALLOC_64K,
            FdirPballoc::K128 => FDIR_PBALLOC_128K,
            FdirPballoc::K256 => FDIR_PBALLOC_256K,
        }
    }
}

/// Flow Director configuration for `configure_fdir`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FdirConfig {
    /// Signature or perfect mode.
    pub mode: FdirMode,
    /// Filter-table size.
    pub pballoc: FdirPballoc,
}

impl Default for FdirConfig {
    fn default() -> Self {
        Self {
            mode: FdirMode::Signature,
            pballoc: FdirPballoc::K64,
        }
    }
}

/// Perfect-filter input-mask fields, host order.
///
/// The mask convention follows Linux's ethtool path: a field value
/// below selects which parts are IGNORED during matching (the FDIRM
/// bits mean "mask this field"), and the port/IP mask registers hold
/// the bitwise inverse of the computed mask words.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FdirMask {
    /// VM-pool mask byte: 0x00 masks the pool, 0x7F matches it.
    pub vm_pool: u8,
    /// Flow-type mask: 0x00 masks L4, 0x03 matches it.
    pub flow_type: u8,
    /// VLAN mask (host order): 0x0000 masks ID+priority, 0x0FFF
    /// masks priority only, 0xE000 masks ID only, 0xEFFF matches all.
    pub vlan_id: u16,
    /// Source-port mask (host order); must be 0 when L4 is masked.
    pub src_port: u16,
    /// Destination-port mask (host order); must be 0 when L4 is masked.
    pub dst_port: u16,
    /// Flex-bytes mask: 0x0000 masks them, 0xFFFF matches them.
    pub flex_bytes: u16,
    /// Source IPv4 mask (host order).
    pub src_ip: u32,
    /// Destination IPv4 mask (host order).
    pub dst_ip: u32,
    /// Destination-IPv6 match: true clears FDIRM.DIPv6, making the
    /// compare of the destination IPv6 address against the global
    /// IP6AT entry meaningful for perfect-match IPv6 filters
    /// (datasheet §8.2.3.21.9); false keeps Linux's behavior
    /// (DIPv6 set: destination IPv6 never matches).
    pub dst_ipv6_match: bool,
}

/// Perfect-filter tuple, host order.
///
/// IPv4 only (see module docs). `bkt_hash` must already hold the
/// value from [`perfect_bucket_hash`] for this tuple under the
/// programmed input mask. Addresses are wire-order numerics; the
/// register writes byte-swap them (see module docs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FdirPerfectInput {
    /// VM pool (VT pool for the FDIRCMD word).
    pub vm_pool: u8,
    /// Flow type (IPv4 types 0..3 only).
    pub flow_type: u8,
    /// VLAN ID (host order).
    pub vlan_id: u16,
    /// Source IPv4 address (host order).
    pub src_ip: u32,
    /// Destination IPv4 address (host order).
    pub dst_ip: u32,
    /// Source port (host order).
    pub src_port: u16,
    /// Destination port (host order).
    pub dst_port: u16,
    /// Flex bytes (host order).
    pub flex_bytes: u16,
    /// Bucket hash from [`perfect_bucket_hash`] (13 bits).
    pub bkt_hash: u16,
}

/// Perfect-filter IPv6 tuple.
///
/// Source IPv6 gets a full 128-bit per-filter match (FDIRSIPv6[0..2]
/// + FDIRIPSA, masked per byte by FDIRIP6M.SIPM). Destination IPv6
/// has NO per-filter register: the match compares it as a whole
/// against the single global IP6AT entry (see module docs), so
/// `dst_ip` is used ONLY for the bucket hash (datasheet Table 7.8
/// includes the full destination in the hash stream) and
/// `dst_matches_ip6at` selects the FDIRCMD.IPv6DMatch sense.
/// Addresses are wire-order byte arrays (byte 0 first on the wire);
/// the hash words are their `from_be_bytes` numerics, while the
/// register writes use the LE-loaded form (see module docs).
/// `bkt_hash` must already hold the value from
/// [`perfect_bucket_hash`] over [`perfect_stream6`] for this tuple
/// under the programmed input masks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FdirPerfectInput6 {
    /// VM pool (VT pool for the FDIRCMD word).
    pub vm_pool: u8,
    /// Flow type (IPv6 types 4..7 only).
    pub flow_type: u8,
    /// VLAN ID (host order).
    pub vlan_id: u16,
    /// Source IPv6 address (wire order).
    pub src_ip: [u8; 16],
    /// Destination IPv6 address (wire order; hash only).
    pub dst_ip: [u8; 16],
    /// Source port (host order).
    pub src_port: u16,
    /// Destination port (host order).
    pub dst_port: u16,
    /// Flex bytes (host order).
    pub flex_bytes: u16,
    /// Bucket hash from [`perfect_bucket_hash`] (13 bits).
    pub bkt_hash: u16,
    /// FDIRCMD.IPv6DMatch: true = destination must match IP6AT,
    /// false = destination must NOT match IP6AT. Meaningful only
    /// when FDIRM.DIPv6 is clear (`FdirMask::dst_ipv6_match`).
    pub dst_matches_ip6at: bool,
}

/// Flow Director statistics (all registers read to clear).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FdirStats {
    /// Matched-filter count.
    pub matched: u32,
    /// Missed-filter count.
    pub missed: u32,
    /// Unmatched / collision statistic.
    pub ustat: u32,
    /// Matched-filter statistic.
    pub fstat: u32,
    /// Longest bucket length.
    pub len: u32,
    /// Free-filter / collision word (raw).
    pub free: u32,
}

impl FdirStats {
    /// Free-filter count (low 16 bits of FDIRFREE).
    pub const fn free_count(self) -> u32 {
        self.free & 0xFFFF
    }

    /// Collision count (bits [30:16] of FDIRFREE).
    pub const fn collision_count(self) -> u32 {
        (self.free >> 16) & 0x7FFF
    }
}

// ── Pure word builders ───────────────────────────────────────────────

/// FDIRCTRL word for signature mode (Linux
/// `ixgbe_init_fdir_signature_82599`): pballoc + flex shift 6
/// (ethertype) + max 0xA filters per bucket + full threshold 4
/// (interrupt at 64 filters left).
pub const fn fdirctrl_signature(pballoc: FdirPballoc) -> u32 {
    pballoc.bits()
        | (0x6 << FDIRCTRL_FLEX_SHIFT)
        | (0xA << FDIRCTRL_MAX_LENGTH_SHIFT)
        | (4 << FDIRCTRL_FULL_THRESH_SHIFT)
}

/// FDIRCTRL word for perfect mode (Linux
/// `ixgbe_init_fdir_perfect_82599`): the signature word plus
/// perfect-match enable and the drop queue.
pub const fn fdirctrl_perfect(pballoc: FdirPballoc) -> u32 {
    fdirctrl_signature(pballoc)
        | FDIRCTRL_PERFECT_MATCH
        | ((FDIR_DROP_QUEUE as u32) << FDIRCTRL_DROP_Q_SHIFT)
}

/// FDIRPORT word: destination port high, source port low (host order).
pub const fn port_word(src_port: u16, dst_port: u16) -> u32 {
    ((dst_port as u32) << FDIRPORT_DESTINATION_SHIFT) | (src_port as u32)
}

/// FDIRVLAN word: flex bytes high, VLAN ID low (host order).
pub const fn vlan_word(vlan_id: u16, flex_bytes: u16) -> u32 {
    ((flex_bytes as u32) << FDIRVLAN_FLEX_SHIFT) | (vlan_id as u32)
}

/// FDIRHASH word: bucket hash low, software index high.
pub const fn hash_word(bkt_hash: u16, soft_id: u16) -> u32 {
    ((soft_id as u32) << FDIRHASH_SIG_SW_INDEX_SHIFT) | (bkt_hash as u32)
}

/// FDIRCMD word for a perfect-filter add (Linux
/// `ixgbe_fdir_write_perfect_filter_82599`).
pub const fn perfect_add_cmd(flow_type: u8, queue: u8, vm_pool: u8) -> u32 {
    let mut cmd = FDIRCMD_CMD_ADD_FLOW | FDIRCMD_FILTER_UPDATE | FDIRCMD_LAST | FDIRCMD_QUEUE_EN;
    if queue == FDIR_DROP_QUEUE {
        cmd |= FDIRCMD_DROP;
    }
    cmd | ((flow_type as u32) << FDIRCMD_FLOW_TYPE_SHIFT)
        | ((queue as u32) << FDIRCMD_RX_QUEUE_SHIFT)
        | ((vm_pool as u32) << FDIRCMD_VT_POOL_SHIFT)
}

/// FDIRCMD word for a signature-filter add (Linux
/// `ixgbe_fdir_add_signature_filter_82599`). `flow_type` is the
/// base type (tunnel bit already stripped); `queue` is the RX queue.
pub const fn signature_add_cmd(flow_type: u8, queue: u8, tunnel: bool) -> u32 {
    let mut cmd = FDIRCMD_CMD_ADD_FLOW | FDIRCMD_FILTER_UPDATE | FDIRCMD_LAST | FDIRCMD_QUEUE_EN;
    if tunnel {
        cmd |= FDIRCMD_TUNNEL_FILTER;
    }
    cmd | ((flow_type as u32) << FDIRCMD_FLOW_TYPE_SHIFT)
        | ((queue as u32) << FDIRCMD_RX_QUEUE_SHIFT)
}

/// Bit-reverse a 32-bit word (Linux `ixgbe_get_fdirtcpm_82599`
/// reverses the combined port mask bit by bit).
pub const fn bit_reverse32(mut x: u32) -> u32 {
    x = ((x & 0x5555_5555) << 1) | ((x & 0xAAAA_AAAA) >> 1);
    x = ((x & 0x3333_3333) << 2) | ((x & 0xCCCC_CCCC) >> 2);
    x = ((x & 0x0F0F_0F0F) << 4) | ((x & 0xF0F0_F0F0) >> 4);
    x = ((x & 0x00FF_00FF) << 8) | ((x & 0xFF00_FF00) >> 8);
    ((x & 0x0000_FFFF) << 16) | ((x & 0xFFFF_0000) >> 16)
}

/// TCP/UDP port-mask word (before inversion): bit-reversed
/// combination of the destination (high) and source (low) masks.
pub const fn port_mask_word(src_port: u16, dst_port: u16) -> u32 {
    bit_reverse32(((dst_port as u32) << 16) | (src_port as u32))
}

// ── Hashes ───────────────────────────────────────────────────────────

/// One iteration of the ATR hash core, transcribed from Linux's
/// `IXGBE_COMPUTE_SIG_HASH_ITERATION` / `IXGBE_COMPUTE_BKT_HASH_ITERATION`
/// macros. Bit `n` of the key selects the low-word contribution,
/// bit `n + 16` the high-word contribution; the common key wins over
/// the bucket key, which wins over the signature key (signature only).
fn hash_iter(
    n: u32,
    lo: u32,
    hi: u32,
    sig: &mut u32,
    buck: &mut u32,
    common: &mut u32,
    signature: bool,
) {
    let common_key = ATR_BUCKET_HASH_KEY & ATR_SIGNATURE_HASH_KEY;
    if common_key & (1 << n) != 0 {
        *common ^= lo >> n;
    } else if ATR_BUCKET_HASH_KEY & (1 << n) != 0 {
        *buck ^= lo >> n;
    } else if signature && ATR_SIGNATURE_HASH_KEY & (1 << n) != 0 {
        *sig ^= lo << (16 - n);
    }
    if common_key & (1 << (n + 16)) != 0 {
        *common ^= hi >> n;
    } else if ATR_BUCKET_HASH_KEY & (1 << (n + 16)) != 0 {
        *buck ^= hi >> n;
    } else if signature && ATR_SIGNATURE_HASH_KEY & (1 << (n + 16)) != 0 {
        *sig ^= hi << (16 - n);
    }
}

/// ATR signature hash (Linux `ixgbe_atr_compute_sig_hash_82599`).
///
/// `input` is the flow/vm/VLAN word (`vm_pool << 24 | flow_type << 16
/// | vlan_id`, host order) and `common` the compressed dword (IP XOR
/// in the high half, port XOR in the low half, as Linux's `ixgbe_atr`
/// builds it), both in the post-`ntohl` host-order form. Returns the
/// combined signature (high 15 bits) + bucket (low 15 bits) hash.
pub fn sig_hash(input: u32, common: u32) -> u32 {
    let flow_vm_vlan = input;
    let mut hi = common;
    // Low dword is the word-swapped common dword.
    let mut lo = hi.rotate_left(16);
    // Apply flow ID / VM pool / VLAN bits to the high word.
    hi ^= flow_vm_vlan ^ (flow_vm_vlan >> 16);
    let mut sig = 0u32;
    let mut buck = 0u32;
    let mut com = 0u32;
    // Bit 0 is processed BEFORE the low word gets the VLAN bits:
    // bit 0 of the stream must not see them (Linux comment).
    hash_iter(0, lo, hi, &mut sig, &mut buck, &mut com, true);
    lo ^= flow_vm_vlan ^ (flow_vm_vlan << 16);
    for n in 1..16 {
        hash_iter(n, lo, hi, &mut sig, &mut buck, &mut com, true);
    }
    // Combine: bucket takes the common hash, signature takes it shifted.
    buck ^= com;
    buck &= ATR_HASH_MASK;
    sig ^= com << 16;
    sig &= ATR_HASH_MASK << 16;
    sig ^ buck
}

/// Perfect-filter bucket hash (Linux
/// `ixgbe_atr_compute_perfect_hash_82599`, hash half only).
///
/// `words` is the 11-word input stream with the input mask already
/// applied: word 0 is the flow/vm/VLAN word, words 1..10 are the
/// remaining tuple words (source address, destination address, ports,
/// flex bytes, bucket placeholder). Word order within words 1..10
/// does not affect the result: they are XOR-folded before hashing.
/// Returns the 13-bit bucket hash.
pub fn perfect_bucket_hash(words: &[u32; 11]) -> u16 {
    let flow_vm_vlan = words[0];
    let mut hi = 0u32;
    for w in &words[1..] {
        hi ^= *w;
    }
    let mut lo = hi.rotate_left(16);
    hi ^= flow_vm_vlan ^ (flow_vm_vlan >> 16);
    let mut sig = 0u32;
    let mut buck = 0u32;
    let mut com = 0u32;
    hash_iter(0, lo, hi, &mut sig, &mut buck, &mut com, false);
    lo ^= flow_vm_vlan ^ (flow_vm_vlan << 16);
    for n in 1..16 {
        hash_iter(n, lo, hi, &mut sig, &mut buck, &mut com, false);
    }
    // Fold the common accumulator back in: Linux's perfect-hash path
    // uses ONLY the bucket macro with the raw bucket key, so the
    // common-key bits (which `hash_iter` routes to `com`, as in the
    // signature path) belong in the bucket. Dropping `com` — as the
    // first version of this function did — puts filters in the wrong
    // bucket (the IPv4 control vector hashes to 0x01b4 instead of
    // 0x1f6c). Same final fold as `sig_hash`.
    buck ^= com;
    // The perfect hash keeps only the bucket half, limited to 13 bits
    // (max 8K buckets).
    (buck & PERFECT_BUCKET_MASK) as u16
}

/// Apply an input mask to an 11-word perfect-filter stream, word by
/// word (Linux `ixgbe_atr_compute_perfect_hash_82599` first loop).
pub fn apply_mask(words: &[u32; 11], mask: &[u32; 11]) -> [u32; 11] {
    let mut out = [0u32; 11];
    for i in 0..11 {
        out[i] = words[i] & mask[i];
    }
    out
}

/// Build the 11-word perfect-hash stream for an IPv4 tuple, host
/// order: word 0 = flow/vm/VLAN, words 1..4 = source address + zeros,
/// words 5..8 = destination address + zeros, word 9 = ports, word 10
/// = flex bytes + zero bucket placeholder.
pub fn perfect_stream(input: &FdirPerfectInput) -> [u32; 11] {
    [
        ((input.vm_pool as u32) << 24) | ((input.flow_type as u32) << 16) | (input.vlan_id as u32),
        input.src_ip,
        0,
        0,
        0,
        input.dst_ip,
        0,
        0,
        0,
        ((input.src_port as u32) << 16) | (input.dst_port as u32),
        (input.flex_bytes as u32) << 16,
    ]
}

/// Build the 11-word perfect-hash stream for an IPv6 tuple
/// (datasheet Table 7.8: VLAN, 16-byte source, 16-byte destination,
/// ports, flex, pool, type): word 0 = flow/vm/VLAN, words 1..4 =
/// source IPv6 dwords (MS first), words 5..8 = destination IPv6
/// dwords (MS first), word 9 = ports, word 10 = flex bytes + zero
/// bucket placeholder. Words are wire-order numerics
/// (`u32::from_be_bytes`), the same convention as
/// [`perfect_stream`], so [`perfect_bucket_hash`] applies unchanged.
pub fn perfect_stream6(input: &FdirPerfectInput6) -> [u32; 11] {
    let d = |b: &[u8]| u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
    [
        ((input.vm_pool as u32) << 24) | ((input.flow_type as u32) << 16) | (input.vlan_id as u32),
        d(&input.src_ip[0..4]),
        d(&input.src_ip[4..8]),
        d(&input.src_ip[8..12]),
        d(&input.src_ip[12..16]),
        d(&input.dst_ip[0..4]),
        d(&input.dst_ip[4..8]),
        d(&input.dst_ip[8..12]),
        d(&input.dst_ip[12..16]),
        ((input.src_port as u32) << 16) | (input.dst_port as u32),
        (input.flex_bytes as u32) << 16,
    ]
}

/// One dword of an 11-word-stream IPv6 address mask: wire byte
/// `4*j+k` of the address contributes 0xFF at byte position `k`
/// (MS first) when its FDIRIP6M bit is clear (meaningful), 0x00
/// when set (masked). Bit i of the mask covers wire byte i
/// (datasheet §8.2.3.21.8).
const fn ip6_mask_dword(mask: u16, j: usize) -> u32 {
    let mut word = 0u32;
    let mut k = 0;
    while k < 4 {
        let bit = 4 * j + k;
        if mask & (1u16 << bit) == 0 {
            word |= 0xFFu32 << (24 - 8 * k);
        }
        k += 1;
    }
    word
}

/// Convert the per-byte FDIRIP6M masks into the 11-word-stream mask
/// words for the source (words 1..4) and destination (words 5..8)
/// IPv6 addresses, for use with [`apply_mask`] before
/// [`perfect_bucket_hash`]. A mask bit set means that wire byte is
/// ignored by the match — and by the hash, since the hash input is
/// the masked stream. Note DIPM only affects the hash and signature
/// filters, never the perfect-match destination compare.
pub const fn ip6_mask_words(sipm: u16, dipm: u16) -> ([u32; 4], [u32; 4]) {
    (
        [
            ip6_mask_dword(sipm, 0),
            ip6_mask_dword(sipm, 1),
            ip6_mask_dword(sipm, 2),
            ip6_mask_dword(sipm, 3),
        ],
        [
            ip6_mask_dword(dipm, 0),
            ip6_mask_dword(dipm, 1),
            ip6_mask_dword(dipm, 2),
            ip6_mask_dword(dipm, 3),
        ],
    )
}

/// FDIRCMD word for an IPv6 perfect-filter add: the IPv4 word, whose
/// flow-type shift already carries FDIRCMD.IPV6 for v6 types
/// (bit 7), plus FDIRCMD.IPv6DMatch when the destination must match
/// the IP6AT entry.
pub const fn perfect_add_cmd6(
    flow_type: u8,
    queue: u8,
    vm_pool: u8,
    dst_matches_ip6at: bool,
) -> u32 {
    let mut cmd = perfect_add_cmd(flow_type, queue, vm_pool);
    if dst_matches_ip6at {
        cmd |= FDIRCMD_IPV6DMATCH;
    }
    cmd
}

// ── Input mask ───────────────────────────────────────────────────────

/// Compute the FDIRM word + port/IP mask words for an input mask
/// (Linux `ixgbe_fdir_set_input_mask_82599`), without writing.
/// Returns `(fdirm, port_mask, src_ip_mask, dst_ip_mask)` where the
/// port/IP masks are the values the registers take (already inverted
/// from the ethtool mask convention, and byte-swapped: the IP mask
/// registers' LS bit matches the first byte on the wire, datasheet
/// §8.2.3.21.4/.5 — see `add_perfect`).
pub fn mask_words(mask: &FdirMask) -> Result<(u32, u32, u32, u32), FdirError> {
    // Destination IPv6 is masked unless the caller asked for the
    // IP6AT compare (FDIRM.DIPv6 clear = compare meaningful).
    let mut fdirm = if mask.dst_ipv6_match { 0 } else { FDIRM_DIPV6 };
    match mask.vm_pool & 0x7F {
        0x00 => fdirm |= FDIRM_POOL,
        0x7F => {}
        _ => return Err(FdirError::BadInputMask("vm_pool")),
    }
    match mask.flow_type & L4TYPE_MASK {
        0x00 => {
            fdirm |= FDIRM_L4P;
            if mask.dst_port != 0 || mask.src_port != 0 {
                return Err(FdirError::BadInputMask("ports with masked L4"));
            }
        }
        0x03 => {}
        _ => return Err(FdirError::BadInputMask("flow_type")),
    }
    match mask.vlan_id & 0xEFFF {
        0x0000 => fdirm |= FDIRM_VLANID | FDIRM_VLANP,
        0x0FFF => fdirm |= FDIRM_VLANP,
        0xE000 => fdirm |= FDIRM_VLANID,
        0xEFFF => {}
        _ => return Err(FdirError::BadInputMask("vlan_id")),
    }
    match mask.flex_bytes {
        0x0000 => fdirm |= FDIRM_FLEX,
        0xFFFF => {}
        _ => return Err(FdirError::BadInputMask("flex_bytes")),
    }
    // Port masks are bit-reversed, then inverted for the register.
    let port = !port_mask_word(mask.src_port, mask.dst_port);
    // IP masks are inverted for the register and byte-swapped (the
    // mask registers' LS bit matches the first byte on the wire —
    // same swap as the address registers, see `add_perfect`).
    Ok((
        fdirm,
        port,
        (!mask.src_ip).swap_bytes(),
        (!mask.dst_ip).swap_bytes(),
    ))
}

/// Program an input mask (Linux `ixgbe_fdir_set_input_mask_82599`).
/// `sctp` selects the X550-family SCTP mask register (Linux writes
/// it only for X550 / X550EM_x / e610).
pub fn set_input_mask(
    bank: &mut impl RegBank,
    mask: &FdirMask,
    sctp: bool,
) -> Result<(), FdirError> {
    let (fdirm, port, src_ip, dst_ip) = mask_words(mask)?;
    bank.write32(REG_FDIRM, fdirm);
    bank.write32(REG_FDIRTCPM, port);
    bank.write32(REG_FDIRUDPM, port);
    if sctp {
        bank.write32(REG_FDIRSCTPM, port);
    }
    bank.write32(REG_FDIRSIP4M, src_ip);
    bank.write32(REG_FDIRDIP4M, dst_ip);
    Ok(())
}

/// Program the IPv6 mask register (FDIRIP6M, datasheet §8.2.3.21.8):
/// `sipm` masks the source IPv6 address per byte (bit i = wire byte
/// i, set = ignored), `dipm` the destination per byte. DIPM is
/// meaningful only for the hash function and signature filters —
/// it never gates the perfect-match destination compare (that is
/// FDIRM.DIPv6, via `FdirMask::dst_ipv6_match`).
pub fn set_ip6_mask(bank: &mut impl RegBank, sipm: u16, dipm: u16) {
    bank.write32(
        REG_FDIRIP6M,
        ((dipm as u32) << FDIRIP6M_DIPM_SHIFT) | ((sipm as u32) << FDIRIP6M_SIPM_SHIFT),
    );
}

// ── Bank sequences ───────────────────────────────────────────────────

/// PCIe-write flush: Linux `IXGBE_WRITE_FLUSH` reads STATUS.
fn flush(bank: &mut impl RegBank) {
    let _ = bank.read32(super::REG_STATUS);
}

/// Poll FDIRCMD until its command field clears (Linux
/// `ixgbe_fdir_check_cmd_complete`, 10 polls).
fn poll_cmd_complete(bank: &mut impl RegBank) -> Result<u32, FdirError> {
    for _ in 0..FDIR_POLL {
        let cmd = bank.read32(REG_FDIRCMD);
        if cmd & FDIRCMD_CMD_MASK == 0 {
            return Ok(cmd);
        }
    }
    Err(FdirError::CmdIncomplete)
}

/// Poll FDIRCTRL until hardware sets INIT_DONE (best-effort, as in
/// Linux `ixgbe_fdir_enable_82599`, which only debugs on timeout).
fn poll_init_done(bank: &mut impl RegBank) -> bool {
    for _ in 0..FDIR_POLL {
        if bank.read32(REG_FDIRCTRL) & FDIRCTRL_INIT_DONE != 0 {
            return true;
        }
    }
    false
}

/// Prime the hash keys and write FDIRCTRL (Linux
/// `ixgbe_fdir_enable_82599`). Returns whether INIT_DONE was observed.
fn fdir_enable(bank: &mut impl RegBank, fdirctrl: u32) -> bool {
    bank.write32(REG_FDIRHKEY, ATR_BUCKET_HASH_KEY);
    bank.write32(REG_FDIRSKEY, ATR_SIGNATURE_HASH_KEY);
    bank.write32(REG_FDIRCTRL, fdirctrl);
    flush(bank);
    poll_init_done(bank)
}

/// Initialize signature-filter mode (Linux
/// `ixgbe_init_fdir_signature_82599`). Returns whether INIT_DONE was
/// observed; a missed poll is not an error (Linux debugs only).
pub fn init_signature(bank: &mut impl RegBank, pballoc: FdirPballoc) -> bool {
    fdir_enable(bank, fdirctrl_signature(pballoc))
}

/// Initialize perfect-match mode (Linux
/// `ixgbe_init_fdir_perfect_82599`). Returns whether INIT_DONE was
/// observed; a missed poll is not an error (Linux debugs only).
pub fn init_perfect(bank: &mut impl RegBank, pballoc: FdirPballoc) -> bool {
    fdir_enable(bank, fdirctrl_perfect(pballoc))
}

/// Add a perfect-match filter (Linux
/// `ixgbe_fdir_write_perfect_filter_82599`). IPv4 only; the IPv6
/// source registers take the IPv4 address + zeros, matching Linux's
/// IPv4 inputs. Rejects flow types with the IPv6 bit set and queue
/// indices above the drop queue (NARF guards, documented above).
///
/// Byte order: the address registers take the LE-loaded form — the
/// register's LS byte is the first byte on the wire (datasheet
/// §8.2.3.21.16/.17/.18) — i.e. the numeric host-order address
/// byte-swapped, exactly what Linux's `WRITE_REG_BE32` writes.
/// (The first version of this module wrote the numerics verbatim;
/// that byte-reverses the address on silicon.)
pub fn add_perfect(
    bank: &mut impl RegBank,
    input: &FdirPerfectInput,
    soft_id: u16,
    queue: u8,
) -> Result<(), FdirError> {
    if input.flow_type & L4TYPE_IPV6_BIT != 0 {
        return Err(FdirError::BadFlowType);
    }
    if queue > FDIR_DROP_QUEUE {
        return Err(FdirError::BadQueue);
    }
    // IPv6 source registers: IPv4 address + zeros (Linux writes
    // src_ip[0..2]; the remaining words are zero for IPv4 inputs).
    bank.write32(REG_FDIRSIPV6_BASE, input.src_ip.swap_bytes());
    bank.write32(REG_FDIRSIPV6_BASE + 4, 0);
    bank.write32(REG_FDIRSIPV6_BASE + 8, 0);
    bank.write32(REG_FDIRIPSA, input.src_ip.swap_bytes());
    bank.write32(REG_FDIRIPDA, input.dst_ip.swap_bytes());
    bank.write32(REG_FDIRPORT, port_word(input.src_port, input.dst_port));
    bank.write32(REG_FDIRVLAN, vlan_word(input.vlan_id, input.flex_bytes));
    bank.write32(REG_FDIRHASH, hash_word(input.bkt_hash, soft_id));
    flush(bank);
    bank.write32(
        REG_FDIRCMD,
        perfect_add_cmd(input.flow_type, queue, input.vm_pool),
    );
    poll_cmd_complete(bank)?;
    Ok(())
}

/// Add an IPv6 perfect-match filter (datasheet §7.1.2.7.13 Table 7.7
/// + §8.2.3.21.16/.17/.22). Writes the source IPv6 as its MS three
/// dwords (FDIRSIPv6[0..2]) plus its LS dword (FDIRIPSA), FDIRIPDA
/// = 0 (an IPv4-only register, not meaningful for IPv6 — the
/// destination matches against the global IP6AT entry instead),
/// then ports / VLAN / hash and FDIRCMD with IPV6 (+ IPv6DMatch
/// when `dst_matches_ip6at`). The address words are the LE-loaded
/// form (LS byte first on the wire), as in [`add_perfect`].
/// Rejects non-IPv6 flow types (exact match on 4..7, so no stray
/// flow-type bit can leak into FDIRCMD) and queue indices above the
/// drop queue. The destination-IPv6 compare is meaningful only when
/// FDIRM.DIPv6 is clear (`FdirMask::dst_ipv6_match`) and IP6AT
/// holds the address to match (`wol::program_ipv6` programs it).
pub fn add_perfect_ipv6(
    bank: &mut impl RegBank,
    input: &FdirPerfectInput6,
    soft_id: u16,
    queue: u8,
) -> Result<(), FdirError> {
    match input.flow_type {
        FLOW_TYPE_IPV6 | FLOW_TYPE_UDPV6 | FLOW_TYPE_TCPV6 | FLOW_TYPE_SCTPV6 => {}
        _ => return Err(FdirError::BadFlowType),
    }
    if queue > FDIR_DROP_QUEUE {
        return Err(FdirError::BadQueue);
    }
    let le = |b: &[u8]| u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    bank.write32(REG_FDIRSIPV6_BASE, le(&input.src_ip[0..4]));
    bank.write32(REG_FDIRSIPV6_BASE + 4, le(&input.src_ip[4..8]));
    bank.write32(REG_FDIRSIPV6_BASE + 8, le(&input.src_ip[8..12]));
    bank.write32(REG_FDIRIPSA, le(&input.src_ip[12..16]));
    bank.write32(REG_FDIRIPDA, 0);
    bank.write32(REG_FDIRPORT, port_word(input.src_port, input.dst_port));
    bank.write32(REG_FDIRVLAN, vlan_word(input.vlan_id, input.flex_bytes));
    bank.write32(REG_FDIRHASH, hash_word(input.bkt_hash, soft_id));
    flush(bank);
    bank.write32(
        REG_FDIRCMD,
        perfect_add_cmd6(
            input.flow_type,
            queue,
            input.vm_pool,
            input.dst_matches_ip6at,
        ),
    );
    poll_cmd_complete(bank)?;
    Ok(())
}

/// Erase a perfect-match filter (Linux
/// `ixgbe_fdir_erase_perfect_filter_82599`): query first, remove
/// only if the filter is present. The remove itself is not polled
/// (Linux returns immediately after issuing it).
pub fn erase_perfect(
    bank: &mut impl RegBank,
    bkt_hash: u16,
    soft_id: u16,
) -> Result<(), FdirError> {
    bank.write32(REG_FDIRHASH, hash_word(bkt_hash, soft_id));
    flush(bank);
    bank.write32(REG_FDIRCMD, FDIRCMD_CMD_QUERY_REM_FILT);
    let cmd = poll_cmd_complete(bank)?;
    if cmd & FDIRCMD_FILTER_VALID != 0 {
        bank.write32(REG_FDIRHASH, hash_word(bkt_hash, soft_id));
        flush(bank);
        bank.write32(REG_FDIRCMD, FDIRCMD_CMD_REMOVE_FLOW);
    }
    Ok(())
}

/// Add a signature filter — the ATR primitive (Linux
/// `ixgbe_fdir_add_signature_filter_82599`). `input` is the
/// flow/vm/VLAN word and `common` the compressed dword (see
/// [`sig_hash`]); `flow_type` carries the tunnel bit (0x10), which
/// is stripped before the type check. Accepted base types are the
/// TCP/UDP/SCTP v4+v6 types; bare IPv4/IPv6 and unknown types are
/// rejected. No completion poll: Linux returns immediately after the
/// hash+command write pair.
pub fn add_signature(
    bank: &mut impl RegBank,
    input: u32,
    common: u32,
    flow_type: u8,
    queue: u8,
) -> Result<(), FdirError> {
    if queue > FDIR_DROP_QUEUE {
        return Err(FdirError::BadQueue);
    }
    let tunnel = flow_type & L4TYPE_TUNNEL_BIT != 0;
    let base = flow_type & (L4TYPE_TUNNEL_BIT - 1);
    match base {
        FLOW_TYPE_UDPV4 | FLOW_TYPE_TCPV4 | FLOW_TYPE_SCTPV4 | FLOW_TYPE_UDPV6
        | FLOW_TYPE_TCPV6 | FLOW_TYPE_SCTPV6 => {}
        _ => return Err(FdirError::BadFlowType),
    }
    let hash = sig_hash(input, common);
    // The 64-bit FDIRHASH write, split across the 32-bit bank:
    // hash first, then the command (see module docs).
    bank.write32(REG_FDIRHASH, hash);
    bank.write32(REG_FDIRCMD, signature_add_cmd(base, queue, tunnel));
    Ok(())
}

/// Reinitialize the Flow Director tables (Linux
/// `ixgbe_reinit_fdir_tables_82599`): clear INIT_DONE, wait for any
/// in-flight command, clear the hash table, rewrite FDIRCTRL, poll
/// INIT_DONE (an error here, unlike init), and clear the statistics.
/// NOTE: programmed filters do not survive a reinit; use [`replay`]
/// (or [`restore`]) afterwards to re-program the recorded state.
pub fn reinit_tables(bank: &mut impl RegBank) -> Result<(), FdirError> {
    let mut fdirctrl = bank.read32(REG_FDIRCTRL);
    fdirctrl &= !FDIRCTRL_INIT_DONE;
    poll_cmd_complete(bank)?;
    bank.write32(REG_FDIRFREE, 0);
    // Toggle CLEARHT: set, then clear (Linux read-modify-writes).
    let cmd = bank.read32(REG_FDIRCMD);
    bank.write32(REG_FDIRCMD, cmd | FDIRCMD_CLEARHT);
    let cmd = bank.read32(REG_FDIRCMD);
    bank.write32(REG_FDIRCMD, cmd & !FDIRCMD_CLEARHT);
    // Clear any leftover hash, then rewrite FDIRCTRL.
    bank.write32(REG_FDIRHASH, 0);
    bank.write32(REG_FDIRCTRL, fdirctrl);
    flush(bank);
    if !poll_init_done(bank) {
        return Err(FdirError::ReinitTimeout);
    }
    // Clear statistics registers (read to clear).
    let _ = bank.read32(REG_FDIRUSTAT);
    let _ = bank.read32(REG_FDIRFSTAT);
    let _ = bank.read32(REG_FDIRMATCH);
    let _ = bank.read32(REG_FDIRMISS);
    let _ = bank.read32(REG_FDIRLEN);
    Ok(())
}

// ── Persistent filter state ──────────────────────────────────────────

/// One recorded Flow Director filter, for re-programming after the
/// tables were cleared (reinit / reset / resume). The recorded form
/// is exactly what the add call took, so a replay issues the same
/// register conversation as the original add.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordedFilter {
    /// IPv4 perfect filter (`add_perfect` arguments).
    Perfect {
        /// Tuple (including the precomputed bucket hash).
        input: FdirPerfectInput,
        /// Software index.
        soft_id: u16,
        /// RX queue (127 = drop).
        queue: u8,
    },
    /// IPv6 perfect filter (`add_perfect_ipv6` arguments).
    Perfect6 {
        /// Tuple (including the precomputed bucket hash).
        input: FdirPerfectInput6,
        /// Software index.
        soft_id: u16,
        /// RX queue (127 = drop).
        queue: u8,
    },
    /// Signature filter (`add_signature` arguments).
    Signature {
        /// Flow/vm/VLAN word.
        input: u32,
        /// Compressed dword.
        common: u32,
        /// Flow type (tunnel bit included).
        flow_type: u8,
        /// RX queue.
        queue: u8,
    },
}

/// Persistent Flow Director state: everything `restore` needs to
/// rebuild the tables from scratch after they were cleared —
/// the init config, the input masks, the IPv6 destination-match
/// address, and the recorded filters in add order.
///
/// The store replays exactly what was recorded; it never invents
/// state. Filters recorded without a config are not replayed
/// (nothing was ever initialized to replay into).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FdirState {
    /// Init config from `configure_fdir` (`None` = never configured).
    pub config: Option<FdirConfig>,
    /// Input mask from `configure_fdir_mask` (`None` = never set).
    pub mask: Option<FdirMask>,
    /// IPv6 mask from `configure_fdir_ip6_mask`: `(sipm, dipm)`.
    pub ip6_mask: Option<(u16, u16)>,
    /// Destination-IPv6 match address (IP6AT) from
    /// `configure_fdir_ipv6_dst` (`None` = never set).
    pub ip6at: Option<[u8; 16]>,
    /// Recorded filters, in add order.
    pub filters: Vec<RecordedFilter>,
}

impl FdirState {
    /// Record an IPv4 perfect filter (call after a successful add).
    pub fn record_perfect(&mut self, input: FdirPerfectInput, soft_id: u16, queue: u8) {
        self.filters.push(RecordedFilter::Perfect {
            input,
            soft_id,
            queue,
        });
    }

    /// Record an IPv6 perfect filter (call after a successful add).
    pub fn record_perfect6(&mut self, input: FdirPerfectInput6, soft_id: u16, queue: u8) {
        self.filters.push(RecordedFilter::Perfect6 {
            input,
            soft_id,
            queue,
        });
    }

    /// Record a signature filter (call after a successful add).
    pub fn record_signature(&mut self, input: u32, common: u32, flow_type: u8, queue: u8) {
        self.filters.push(RecordedFilter::Signature {
            input,
            common,
            flow_type,
            queue,
        });
    }

    /// Forget a perfect filter by its (bucket hash, software index)
    /// — the erase key. Removes the first match only: software
    /// indices are unique per the datasheet (§7.1.2.7.13), so at
    /// most one recorded filter can carry a key.
    pub fn forget_perfect(&mut self, bkt_hash: u16, soft_id: u16) {
        if let Some(pos) = self.filters.iter().position(|f| match f {
            RecordedFilter::Perfect {
                input, soft_id: s, ..
            } => input.bkt_hash == bkt_hash && *s == soft_id,
            RecordedFilter::Perfect6 {
                input, soft_id: s, ..
            } => input.bkt_hash == bkt_hash && *s == soft_id,
            RecordedFilter::Signature { .. } => false,
        }) {
            self.filters.remove(pos);
        }
    }

    /// Number of recorded filters.
    pub fn len(&self) -> usize {
        self.filters.len()
    }

    /// Whether any filter is recorded.
    pub fn is_empty(&self) -> bool {
        self.filters.is_empty()
    }
}

/// Re-program the recorded input masks, IP6AT address, and filters
/// — the no-init half of [`restore`], for use after
/// [`reinit_tables`] (which preserves the FDIRCTRL mode but clears
/// the tables). Mask registers and IP6AT survive a reinit, so
/// re-applying them is a harmless rewrite of the same values.
/// Returns the first error; a partial replay leaves the earlier
/// filters programmed, and re-adding an identical filter is
/// idempotent (datasheet §7.1.2.7.6: discarded silently as a
/// success), so callers may retry.
pub fn replay(bank: &mut impl RegBank, state: &FdirState, sctp: bool) -> Result<(), FdirError> {
    if let Some(mask) = &state.mask {
        set_input_mask(bank, mask, sctp)?;
    }
    if let Some((sipm, dipm)) = state.ip6_mask {
        set_ip6_mask(bank, sipm, dipm);
    }
    if let Some(addr) = state.ip6at {
        super::wol::program_ipv6(bank, addr);
    }
    for f in &state.filters {
        match *f {
            RecordedFilter::Perfect {
                input,
                soft_id,
                queue,
            } => add_perfect(bank, &input, soft_id, queue)?,
            RecordedFilter::Perfect6 {
                input,
                soft_id,
                queue,
            } => add_perfect_ipv6(bank, &input, soft_id, queue)?,
            RecordedFilter::Signature {
                input,
                common,
                flow_type,
                queue,
            } => add_signature(bank, input, common, flow_type, queue)?,
        }
    }
    Ok(())
}

/// Rebuild the Flow Director tables from the recorded state after
/// they were cleared (reset / resume): re-init in the recorded mode
/// (which re-creates the empty tables), then [`replay`] the masks,
/// IP6AT, and filters. A missed INIT_DONE poll is not an error
/// (same treatment as `configure_fdir`); a failed filter add
/// surfaces as its error. No-op when no config was recorded.
pub fn restore(bank: &mut impl RegBank, state: &FdirState, sctp: bool) -> Result<(), FdirError> {
    match state.config {
        None => Ok(()),
        Some(cfg) => {
            match cfg.mode {
                FdirMode::Signature => {
                    init_signature(bank, cfg.pballoc);
                }
                FdirMode::Perfect => {
                    init_perfect(bank, cfg.pballoc);
                }
            }
            replay(bank, state, sctp)
        }
    }
}

/// Read Flow Director statistics (all registers read to clear — call
/// sparingly; a read consumes the counts).
pub fn stats(bank: &mut impl RegBank) -> FdirStats {
    FdirStats {
        matched: bank.read32(REG_FDIRMATCH),
        missed: bank.read32(REG_FDIRMISS),
        ustat: bank.read32(REG_FDIRUSTAT),
        fstat: bank.read32(REG_FDIRFSTAT),
        len: bank.read32(REG_FDIRLEN),
        free: bank.read32(REG_FDIRFREE),
    }
}
