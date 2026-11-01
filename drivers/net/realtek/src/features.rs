//! Shared Realtek feature model — one pure, testable description of
//! the offload / WoL / EEE / jumbo / RSS register conversations that
//! Linux's `drivers/net/ethernet/realtek/r8169_main.c` performs, used
//! by all four drivers in this family (`r8169`, `rtl8125`, `rtl8126`,
//! `rtl8127`) so the four bring-up paths cannot drift apart.
//!
//! ## Reference
//!
//! Linux `r8169_main.c` (GPL-2.0; NARF is GPL-2.0-or-later so
//! adaptation is permitted), at the `~/workspace/scratch/ethernet/linux2`
//! checkout unless noted otherwise:
//!
//! - `CPlusCmd` bits (`RxVlan` / `RxChkSum`, `CPCMD_MASK`) and
//!   `rtl_set_rx_config_features` — the RX offload toggles.
//! - `rtl8169_tx_vlan_tag` / `rtl8169_rx_vlan_tag` — TX insertion
//!   (`TxVlanTag | swab16(tag)`) and RX strip (`RxVlanTag` in word1).
//! - `__rtl8169_set_wol` / `rtl8169_get_wol` — `WAKE_ANY` =
//!   `WAKE_PHY | WAKE_MAGIC | WAKE_UCAST | WAKE_BCAST | WAKE_MCAST`,
//!   programmed through `Config3` (MagicPacket / LinkUp), `Config5`
//!   (UWF / BWF / MWF / LanWake) and the PME register (`Config1`
//!   `PMEnable` on VER_02..06, `Config2` `PME_SIGNAL` on VER_34,
//!   VER_37 and VER_39..LAST). The magic-packet bit itself is
//!   chip-class specific: `Config3` on legacy 8168, the MAC-OCP
//!   register `0xc0b6` bit 0 on the 8125 family, and ERI `0x0dc`
//!   `MagicPacket_v2` on 8168evl — see [`WolMagic`].
//! - `rtl_supports_eee` / `rtl8169_get_lpi_caps` /
//!   `rtl_set_eee_txidle_timer` — EEE is supported from
//!   `RTL_GIGA_MAC_VER_34` except VER_37 / VER_39, advertises
//!   100FD + 1000FD, plus 2500FD from VER_63, 5000FD from VER_70
//!   and 10000FD on VER_80 only (VER_61 notably does *not* get
//!   2500FD); the TX LPI idle timer on the 8125 family is
//!   `EEE_TXIDLE_TIMER_8125` (0x6048) = `mtu + ETH_HLEN + 0x20`.
//! - `rtl_jumbo_max` / `rtl_jumbo_config` — jumbo maxima by MAC
//!   version (7K on VER_02..06, 4K on VER_17, 6K on VER_18..24,
//!   16K on VER_61..LAST, 9K default) and the 8168-only
//!   `Config3`/`Config4` jumbo-enable bits.
//! - `rtl_hw_support_rss` (true only on VER_80), `rtl8169_init_rss`,
//!   `rtl8169_set_rss_hash_opt`, `rtl8169_store_rss_key`,
//!   `rtl8169_store_reta`, `rtl8125_set_rx_q_num` — RSS is a
//!   VER_80-only feature: a 40-byte key at `RSS_KEY_REG` (0x4600),
//!   a 128-entry indirection table at `RSS_INDIRECTION_TBL_REG`
//!   (0x4700), a control word at `RSS_CTRL_8125` (0x4500) carrying
//!   the queue count and hash options, the queue count at
//!   `Q_NUM_CTRL_8125` (0x4800, bits 4:2), and the RSS descriptor
//!   type at `RTL_DESC_TYPE_CTRL` (0xD8, bit 1).
//!
//! ## What this module is not
//!
//! The register *values* here are pure functions, and the register
//! *sequences* are written through [`RegFile`] so a [`RegLog`]
//! fixture can replay the exact conversation a driver performs and
//! assert every write in order. Production drivers call the same
//! `apply_*` functions through the [`MmioRegs`] adapter, so the
//! fixture and the driver cannot disagree about the sequence —
//! except for the WoL magic step on the 8125 family and 8168evl,
//! which lives on the OCP/ERI windows rather than the plain MMIO
//! map and is therefore reported back to the caller as a
//! [`WolMagic`] step instead of being written here.
//!
//! Where Linux and a datasheet disagree, the datasheet wins and the
//! conflict is flagged in the PR body; no such conflict was found
//! for the registers modelled here.

use alloc::vec::Vec;
use narf_driver_runtime::MmioRegion;

// ── Shared register offsets ─────────────────────────────────────────

/// `CPlusCmd` — C+ Command, VLAN / checksum offload toggles.
pub const REG_CPLUSCR: u64 = 0xE0;
/// `Config1` — PME enable lives here on VER_02..06.
pub const REG_CONFIG1: u64 = 0x52;
/// `Config2` — PME signal lives here on VER_34+.
pub const REG_CONFIG2: u64 = 0x53;
/// `Config3` — MagicPacket / LinkUp / Jumbo_En0.
pub const REG_CONFIG3: u64 = 0x54;
/// `Config4` — Jumbo_En1 / bit 0 (VER_17 jumbo).
pub const REG_CONFIG4: u64 = 0x55;
/// `Config5` — UWF / BWF / MWF / LanWake.
pub const REG_CONFIG5: u64 = 0x56;
/// `RxMaxSize` — RX max packet size (14-bit).
pub const REG_RMS: u64 = 0xDA;
/// `MaxTxPacketSize` — units of 128 bytes.
pub const REG_MTPS: u64 = 0xEC;
/// `EEE_TXIDLE_TIMER_8125` — TX LPI idle timer, 8125 family only.
pub const REG_EEE_TXIDLE_TIMER_8125: u64 = 0x6048;
/// `RSS_CTRL_8125` — RSS control word (VER_80 only).
pub const REG_RSS_CTRL_8125: u64 = 0x4500;
/// `RSS_KEY_REG` — RSS Toeplitz key, 40 bytes as 10 little-endian words.
pub const REG_RSS_KEY: u64 = 0x4600;
/// `RSS_INDIRECTION_TBL_REG` — RSS indirection table, 128 entries.
pub const REG_RSS_INDIR: u64 = 0x4700;
/// `Q_NUM_CTRL_8125` — RX queue count selector, bits 4:2.
pub const REG_Q_NUM_CTRL_8125: u64 = 0x4800;
/// `RTL_DESC_TYPE_CTRL` — descriptor type; bit 1 selects RSS format.
pub const REG_DESC_TYPE_CTRL: u64 = 0xD8;

// ── Register-file abstraction ───────────────────────────────────────

/// A byte/word/dword register window. The methods are `unsafe`
/// because a write lands on hardware; the [`MmioRegs`] adapter
/// forwards to the caller's exclusively-owned BAR mapping, and the
/// [`RegLog`] fixture records instead of touching hardware.
///
/// # Safety
///
/// Implementors must only perform register accesses the caller is
/// authorised for: the [`MmioRegs`] adapter requires the caller to
/// own the device's BAR exclusively, and [`RegLog`] performs no
/// hardware access at all.
pub unsafe trait RegFile {
    /// # Safety
    /// `offset` must be in range for a byte read.
    unsafe fn read8(&self, offset: u64) -> u8;
    /// # Safety
    /// `offset` must be in range for a word read.
    unsafe fn read16(&self, offset: u64) -> u16;
    /// # Safety
    /// `offset` must be in range for a dword read.
    unsafe fn read32(&self, offset: u64) -> u32;
    /// # Safety
    /// `offset` must be in range for a byte write.
    unsafe fn write8(&mut self, offset: u64, value: u8);
    /// # Safety
    /// `offset` must be in range for a word write.
    unsafe fn write16(&mut self, offset: u64, value: u16);
    /// # Safety
    /// `offset` must be in range for a dword write.
    unsafe fn write32(&mut self, offset: u64, value: u32);
}

/// Adapter over a live BAR mapping. Construct it only where the
/// caller already owns the device's BAR exclusively (every
/// `bring_up` in this family asserts exactly that).
pub struct MmioRegs<'a>(pub &'a MmioRegion);

impl core::fmt::Debug for MmioRegs<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MmioRegs").finish_non_exhaustive()
    }
}

// SAFETY: the adapter forwards to a BAR mapping the caller owns
// exclusively; every method's own safety contract is that mapping.
unsafe impl RegFile for MmioRegs<'_> {
    unsafe fn read8(&self, offset: u64) -> u8 {
        // SAFETY: forwarded to the exclusively-owned BAR mapping.
        unsafe { self.0.read8(offset) }
    }
    unsafe fn read16(&self, offset: u64) -> u16 {
        // SAFETY: forwarded to the exclusively-owned BAR mapping.
        unsafe { self.0.read16(offset) }
    }
    unsafe fn read32(&self, offset: u64) -> u32 {
        // SAFETY: forwarded to the exclusively-owned BAR mapping.
        unsafe { self.0.read32(offset) }
    }
    unsafe fn write8(&mut self, offset: u64, value: u8) {
        // SAFETY: forwarded to the exclusively-owned BAR mapping.
        unsafe { self.0.write8(offset, value) }
    }
    unsafe fn write16(&mut self, offset: u64, value: u16) {
        // SAFETY: forwarded to the exclusively-owned BAR mapping.
        unsafe { self.0.write16(offset, value) }
    }
    unsafe fn write32(&mut self, offset: u64, value: u32) {
        // SAFETY: forwarded to the exclusively-owned BAR mapping.
        unsafe { self.0.write32(offset, value) }
    }
}

/// One recorded register write, for fixture assertions.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RegWrite {
    /// Register offset.
    pub offset: u64,
    /// Width in bytes: 1, 2 or 4.
    pub width: u8,
    /// Value written (low `width` bytes significant).
    pub value: u32,
}

/// In-memory register file for fixtures: reads return the last
/// value written (0 if never written) and every write is logged in
/// order, so a test can replay a driver's register conversation and
/// assert it write for write.
#[derive(Clone, Debug, Default)]
pub struct RegLog {
    cells: Vec<(u64, u32)>,
    /// Ordered write log.
    pub log: Vec<RegWrite>,
}

impl RegLog {
    /// Create an empty log.
    pub fn new() -> Self {
        Self::default()
    }

    fn get(&self, offset: u64) -> u32 {
        for (off, val) in self.cells.iter().rev() {
            if *off == offset {
                return *val;
            }
        }
        0
    }

    fn put(&mut self, offset: u64, value: u32, width: u8) {
        let mask: u32 = match width {
            1 => 0xFF,
            2 => 0xFFFF,
            _ => 0xFFFF_FFFF,
        };
        let value = value & mask;
        let mut found = false;
        for (off, val) in self.cells.iter_mut() {
            if *off == offset {
                *val = value;
                found = true;
            }
        }
        if !found {
            self.cells.push((offset, value));
        }
        self.log.push(RegWrite {
            offset,
            width,
            value,
        });
    }

    /// The writes to `offset`, in order.
    pub fn writes_to(&self, offset: u64) -> Vec<RegWrite> {
        self.log
            .iter()
            .copied()
            .filter(|w| w.offset == offset)
            .collect()
    }

    /// The last value written to `offset`, if any.
    pub fn last_write_to(&self, offset: u64) -> Option<RegWrite> {
        self.log.iter().copied().rev().find(|w| w.offset == offset)
    }
}

// SAFETY: RegLog performs no hardware access; its methods only
// record into memory, so the register-window contract is vacuous.
unsafe impl RegFile for RegLog {
    unsafe fn read8(&self, offset: u64) -> u8 {
        self.get(offset) as u8
    }
    unsafe fn read16(&self, offset: u64) -> u16 {
        self.get(offset) as u16
    }
    unsafe fn read32(&self, offset: u64) -> u32 {
        self.get(offset)
    }
    unsafe fn write8(&mut self, offset: u64, value: u8) {
        self.put(offset, value as u32, 1);
    }
    unsafe fn write16(&mut self, offset: u64, value: u16) {
        self.put(offset, value as u32, 2);
    }
    unsafe fn write32(&mut self, offset: u64, value: u32) {
        self.put(offset, value, 4);
    }
}

// ── C+ Command: RX VLAN strip + RX checksum ─────────────────────────

/// `CPlusCmd` RX VLAN-detag enable (bit 6).
pub const CPLUS_RXVLAN: u16 = 1 << 6;
/// `CPlusCmd` RX checksum enable (bit 5).
pub const CPLUS_RXCHKSUM: u16 = 1 << 5;
/// `CPlusCmd` Normal_mode (bit 13) — preserved, never set here.
pub const CPLUS_NORMAL: u16 = 1 << 13;
/// `CPlusCmd` interrupt-mitigation mask (bits 1:0) — preserved.
pub const CPLUS_INTT_MASK: u16 = 0x0003;
/// Bits Linux's `CPCMD_MASK` preserves across a feature change.
pub const CPLUS_PRESERVE_MASK: u16 = CPLUS_NORMAL | CPLUS_INTT_MASK;

/// Compute the `CPlusCmd` value for a feature change: preserve the
/// `CPCMD_MASK` bits of `prev`, set/clear `RxVlan` and `RxChkSum`
/// per the requested RX offloads. Matches
/// `rtl_set_rx_config_features` (which ORs `RxChkSum` for
/// `NETIF_F_RXCSUM` and `RxVlan` for `NETIF_F_HW_VLAN_CTAG_RX`).
pub const fn cplus_cmd(prev: u16, rx_vlan: bool, rx_csum: bool) -> u16 {
    let mut v = prev & CPLUS_PRESERVE_MASK;
    if rx_vlan {
        v |= CPLUS_RXVLAN;
    }
    if rx_csum {
        v |= CPLUS_RXCHKSUM;
    }
    v
}

/// Program `CPlusCmd` from the live register value: read, compute,
/// write. Returns the value written.
///
/// # Safety
///
/// The caller must own the register window exclusively.
pub unsafe fn apply_cplus<R: RegFile>(regs: &mut R, rx_vlan: bool, rx_csum: bool) -> u16 {
    // SAFETY: caller owns the register window (see [`RegFile`]).
    let prev = unsafe { regs.read16(REG_CPLUSCR) };
    let next = cplus_cmd(prev, rx_vlan, rx_csum);
    // SAFETY: as above.
    unsafe { regs.write16(REG_CPLUSCR, next) };
    next
}

// ── VLAN: TX insertion + RX strip ───────────────────────────────────

/// TX descriptor word1: VLAN-tag-insert bit (bit 17).
pub const TX_VLAN_TAG_BIT: u32 = 1 << 17;
/// RX descriptor word1: VLAN tag available (bit 16).
pub const RX_VLAN_TAG_BIT: u32 = 1 << 16;

/// Build the TX descriptor word1 VLAN field for `tag`
/// (12-bit VID + PCP/CFI as carried in `TxMeta::vlan_tag`):
/// `TxVlanTag | swab16(tag)`, or 0 when no insertion is requested.
/// The tag occupies the low 16 bits; the csum/TSO bits live at
/// bits 25..31 and the MSS field at bits 28:18, so OR-ing this
/// into a csum/TSO word1 is collision-free. Matches
/// `rtl8169_tx_vlan_tag`.
pub const fn tx_vlan_word(tag: Option<u16>) -> u32 {
    match tag {
        Some(t) => TX_VLAN_TAG_BIT | (t.swap_bytes() as u32),
        None => 0,
    }
}

/// Decode the stripped VLAN tag from an RX descriptor word1:
/// `Some(swab16(opts2 & 0xffff))` when `RxVlanTag` is set, else
/// `None`. Matches `rtl8169_rx_vlan_tag`.
pub const fn rx_vlan_tag(opts2: u32) -> Option<u16> {
    if opts2 & RX_VLAN_TAG_BIT != 0 {
        Some((opts2 as u16).swap_bytes())
    } else {
        None
    }
}

// ── Wake-on-LAN ─────────────────────────────────────────────────────

/// Wake-on-LAN options, using Linux ethtool `WAKE_*` bit values so
/// a future ethtool surface can pass them through unchanged.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct WolOpts(pub u8);

impl WolOpts {
    /// Wake on link-up (`WAKE_PHY`).
    pub const PHY: WolOpts = WolOpts(1 << 0);
    /// Wake on unicast frame (`WAKE_UCAST`).
    pub const UCAST: WolOpts = WolOpts(1 << 1);
    /// Wake on multicast frame (`WAKE_MCAST`).
    pub const MCAST: WolOpts = WolOpts(1 << 2);
    /// Wake on broadcast frame (`WAKE_BCAST`).
    pub const BCAST: WolOpts = WolOpts(1 << 3);
    /// Wake on magic packet (`WAKE_MAGIC`).
    pub const MAGIC: WolOpts = WolOpts(1 << 5);
    /// Every mode Linux's `rtl8169_get_wol` reports as supported.
    pub const ANY: WolOpts = WolOpts(0x01 | 0x02 | 0x04 | 0x08 | 0x20);

    /// `true` if `opt` is set.
    pub const fn contains(self, opt: WolOpts) -> bool {
        self.0 & opt.0 == opt.0
    }

    /// `true` if no unknown bits are set (i.e. the value is within
    /// `WAKE_ANY`); Linux's `rtl8169_set_wol` rejects anything else
    /// with `-EINVAL`.
    pub const fn is_valid(self) -> bool {
        self.0 & !Self::ANY.0 == 0
    }
}

impl core::ops::BitOr for WolOpts {
    type Output = WolOpts;
    fn bitor(self, rhs: WolOpts) -> Self {
        WolOpts(self.0 | rhs.0)
    }
}

/// Where the magic-packet wake bit lives on this chip class.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum WolMagic {
    /// Legacy 8168: `Config3` bit 5 (`MagicPacket`).
    Config3Bit,
    /// 8125 family: MAC-OCP register `0xc0b6` bit 0. Written by the
    /// caller through its OCP accessor (see the 8127 `PhyAccess`
    /// `mac_ocp_write`); this module cannot write it because the
    /// OCP window is not a plain MMIO register.
    MacOcpC0b6,
    /// 8168evl: ERI register `0x0dc` bit 16 (`MagicPacket_v2`).
    /// No NARF driver covers an evl-only path today, so this step is
    /// reported, never silently skipped, when it applies.
    Eri0dc,
}

/// Which register carries the PME enable for this chip class.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum WolPmeReg {
    /// `Config1` bit 0 (`PMEnable`) — VER_02..06.
    Config1,
    /// `Config2` bit 0 (`PME_SIGNAL`) — VER_34, VER_37, VER_39..LAST.
    Config2,
    /// No PME register is programmed for this class (Linux's
    /// default arm); WoL still programs `Config3`/`Config5`.
    None,
}

/// `Config3` bits used by WoL.
pub const CONFIG3_MAGIC_PACKET: u8 = 1 << 5;
/// `Config3` LinkUp wake bit.
pub const CONFIG3_LINKUP: u8 = 1 << 4;
/// `Config5` unicast wake frame bit.
pub const CONFIG5_UWF: u8 = 1 << 4;
/// `Config5` multicast wake frame bit.
pub const CONFIG5_MWF: u8 = 1 << 5;
/// `Config5` broadcast wake frame bit.
pub const CONFIG5_BWF: u8 = 1 << 6;
/// `Config5` LanWake enable bit.
pub const CONFIG5_LANWAKE: u8 = 1 << 1;
/// `Config1` PME enable / `Config2` PME signal bit (both bit 0).
pub const CONFIG_PME_BIT: u8 = 1 << 0;

/// The magic-packet step `apply_wol` could not perform on the plain
/// MMIO map, returned so the caller performs it on the right window
/// instead of dropping it.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum WolPendingMagic {
    /// No out-of-band magic step is needed (`Config3Bit` was written).
    None,
    /// Set MAC-OCP `0xc0b6` bit 0 iff the bool is true, else clear it.
    MacOcpC0b6(bool),
    /// Set ERI `0x0dc` bit 16 iff the bool is true, else clear it.
    Eri0dc(bool),
}

/// Program the plain-MMIO half of a WoL configuration, in Linux's
/// `__rtl8169_set_wol` order: `Config3` (LinkUp, plus MagicPacket
/// when the magic bit lives there), `Config5` (UWF/BWF/MWF/
/// LanWake), then the PME register. Callers must have unlocked the
/// config registers first (9346CR write-enable); this family never
/// enters that mode at bring-up, so WoL is programmed by a control
/// path that takes the lock itself — see each driver's
/// `set_wol_opts`. Returns the pending out-of-band magic step.
///
/// # Safety
///
/// The caller must own the register window exclusively and must
/// have unlocked the config registers first.
pub unsafe fn apply_wol<R: RegFile>(
    regs: &mut R,
    opts: WolOpts,
    magic: WolMagic,
    pme: WolPmeReg,
) -> WolPendingMagic {
    // SAFETY: caller owns the register window (see [`RegFile`]).
    let mut c3 = unsafe { regs.read8(REG_CONFIG3) };
    if opts.contains(WolOpts::PHY) {
        c3 |= CONFIG3_LINKUP;
    } else {
        c3 &= !CONFIG3_LINKUP;
    }
    let mut pending = WolPendingMagic::None;
    match magic {
        WolMagic::Config3Bit => {
            if opts.contains(WolOpts::MAGIC) {
                c3 |= CONFIG3_MAGIC_PACKET;
            } else {
                c3 &= !CONFIG3_MAGIC_PACKET;
            }
        }
        WolMagic::MacOcpC0b6 => {
            pending = WolPendingMagic::MacOcpC0b6(opts.contains(WolOpts::MAGIC))
        }
        WolMagic::Eri0dc => pending = WolPendingMagic::Eri0dc(opts.contains(WolOpts::MAGIC)),
    }
    // SAFETY: as above.
    unsafe { regs.write8(REG_CONFIG3, c3) };

    // SAFETY: as above.
    let mut c5 = unsafe { regs.read8(REG_CONFIG5) };
    for (opt, bit) in [
        (WolOpts::UCAST, CONFIG5_UWF),
        (WolOpts::BCAST, CONFIG5_BWF),
        (WolOpts::MCAST, CONFIG5_MWF),
    ] {
        if opts.contains(opt) {
            c5 |= bit;
        } else {
            c5 &= !bit;
        }
    }
    if opts.0 != 0 {
        c5 |= CONFIG5_LANWAKE;
    } else {
        c5 &= !CONFIG5_LANWAKE;
    }
    // SAFETY: as above.
    unsafe { regs.write8(REG_CONFIG5, c5) };

    let (reg, do_pme) = match pme {
        WolPmeReg::Config1 => (REG_CONFIG1, true),
        WolPmeReg::Config2 => (REG_CONFIG2, true),
        WolPmeReg::None => (REG_CONFIG1, false),
    };
    if do_pme {
        // SAFETY: as above.
        let mut v = unsafe { regs.read8(reg) };
        if opts.0 != 0 {
            v |= CONFIG_PME_BIT;
        } else {
            v &= !CONFIG_PME_BIT;
        }
        // SAFETY: as above.
        unsafe { regs.write8(reg, v) };
    }
    pending
}

// ── EEE (802.3az) ───────────────────────────────────────────────────

/// EEE link-partner capability set, mirroring Linux's
/// `rtl8169_get_lpi_caps` return (MAC_* LPI bits, expressed here as
/// speeds so no phylib type leaks into this family).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct EeeCaps {
    /// 100BASE-TX full duplex.
    pub fd_100: bool,
    /// 1000BASE-T full duplex.
    pub fd_1000: bool,
    /// 2500BASE-T full duplex (VER_63+, not VER_61).
    pub fd_2500: bool,
    /// 5000BASE-T full duplex (VER_70+).
    pub fd_5000: bool,
    /// 10000BASE-T full duplex (VER_80 only).
    pub fd_10000: bool,
}

/// EEE support gate (`rtl_supports_eee`): MAC version >= 34 except
/// 37 and 39. Versions below 34 (including every 8169 and 8168b/c
/// cut) do not support EEE at all.
pub const fn eee_supported(mac_version: u32) -> bool {
    mac_version >= 34 && mac_version != 37 && mac_version != 39
}

/// LPI capabilities for a MAC version, or all-false when EEE is not
/// supported. Matches `rtl8169_get_lpi_caps` (including its
/// VER_61 carve-out: 8125A advertises 100/1000 only).
pub const fn eee_lpi_caps(mac_version: u32) -> EeeCaps {
    if !eee_supported(mac_version) {
        return EeeCaps {
            fd_100: false,
            fd_1000: false,
            fd_2500: false,
            fd_5000: false,
            fd_10000: false,
        };
    }
    EeeCaps {
        fd_100: true,
        fd_1000: true,
        fd_2500: mac_version >= 63,
        fd_5000: mac_version >= 70,
        fd_10000: mac_version == 80,
    }
}

/// TX LPI idle-timer value for the 8125 family
/// (`rtl_set_eee_txidle_timer`, VER_61..LAST arm):
/// `mtu + ETH_HLEN (14) + 0x20`.
pub const fn eee_txidle_timer(mtu: u32) -> u16 {
    (mtu + 14 + 0x20) as u16
}

/// Program the 8125-family TX LPI idle timer. No-op on other
/// families (their timer lives on the OCP window or not at all).
///
/// # Safety
///
/// The caller must own the register window exclusively.
pub unsafe fn apply_eee_txidle<R: RegFile>(regs: &mut R, mtu: u32) {
    // SAFETY: caller owns the register window (see [`RegFile`]).
    unsafe { regs.write16(REG_EEE_TXIDLE_TIMER_8125, eee_txidle_timer(mtu)) };
}

// ── Jumbo frames ────────────────────────────────────────────────────

/// Ethernet header + FCS overhead used by Linux's `JUMBO_*`
/// constants (`N * SZ_1K - VLAN_ETH_HLEN - ETH_FCS_LEN`).
pub const JUMBO_OVERHEAD: u32 = 18 + 4;

/// Maximum IP MTU by MAC-version class (`rtl_jumbo_max`).
/// The returned value already has the header/FCS overhead removed,
/// i.e. it is the `max_mtu` Linux assigns to the net device.
pub const fn jumbo_max_mtu(mac_version: u32) -> u32 {
    match mac_version {
        2..=6 => 7 * 1024 - JUMBO_OVERHEAD,
        17 => 4 * 1024 - JUMBO_OVERHEAD,
        18..=24 => 6 * 1024 - JUMBO_OVERHEAD,
        61..=u32::MAX => 16 * 1024 - JUMBO_OVERHEAD,
        _ => 9 * 1024 - JUMBO_OVERHEAD,
    }
}

/// Wire frame size for an IP MTU (untagged: +14 header +4 FCS).
pub const fn frame_for_mtu(mtu: u32) -> u32 {
    mtu + 18
}

/// `MTPS` value for a wire frame: units of 128 bytes, rounded up.
/// A frame of 16384 bytes needs exactly 128 units; anything larger
/// does not fit this register and must be rejected by the caller.
pub const fn mtps_for_frame(frame: u32) -> u8 {
    frame.div_ceil(128) as u8
}

/// `RMS` value for a wire frame: the register is 14 bits, so frames
/// above 16383 bytes are capped there (the RX buffer bound — see
/// [`RX_BUF_LEN`] in each driver, which Linux fixes at
/// `SZ_16K - 1` for this whole family).
pub const fn rms_for_frame(frame: u32) -> u16 {
    if frame > 16383 {
        16383
    } else {
        frame as u16
    }
}

/// 8168-only jumbo-enable bits (`rtl_jumbo_config`). Returns
/// `(config3_set, config3_clear, config4_set, config4_clear,
/// mtps_override)`: `mtps_override` is `Some` only for VER_31..33,
/// where Linux forces `MTPS` to `0x24` in jumbo mode. Other
/// versions — including the whole 8125 family — need no Config
/// writes for jumbo at all.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct JumboConfig {
    pub config3_set: u8,
    pub config3_clear: u8,
    pub config4_set: u8,
    pub config4_clear: u8,
    pub mtps_override: Option<u8>,
}

/// `Config3` Jumbo_En0 bit (bit 2, 8168 only).
pub const CONFIG3_JUMBO_EN0: u8 = 1 << 2;
/// `Config4` Jumbo_En1 bit (bit 1, 8168 only).
pub const CONFIG4_JUMBO_EN1: u8 = 1 << 1;
/// `Config4` bit 0 (VER_17 and VER_31..33 jumbo enable).
pub const CONFIG4_BIT0: u8 = 1 << 0;

pub const fn jumbo_config(mac_version: u32, jumbo: bool) -> JumboConfig {
    let (c3s, c3c, c4s, c4c, mtps) = match mac_version {
        17 => (
            0,
            0,
            if jumbo { CONFIG4_BIT0 } else { 0 },
            if jumbo { 0 } else { CONFIG4_BIT0 },
            None,
        ),
        18..=26 => (
            if jumbo { CONFIG3_JUMBO_EN0 } else { 0 },
            if jumbo { 0 } else { CONFIG3_JUMBO_EN0 },
            if jumbo { CONFIG4_JUMBO_EN1 } else { 0 },
            if jumbo { 0 } else { CONFIG4_JUMBO_EN1 },
            None,
        ),
        28 => (
            if jumbo { CONFIG3_JUMBO_EN0 } else { 0 },
            if jumbo { 0 } else { CONFIG3_JUMBO_EN0 },
            0,
            0,
            None,
        ),
        31..=33 => (
            if jumbo { CONFIG3_JUMBO_EN0 } else { 0 },
            if jumbo { 0 } else { CONFIG3_JUMBO_EN0 },
            if jumbo { CONFIG4_BIT0 } else { 0 },
            if jumbo { 0 } else { CONFIG4_BIT0 },
            Some(if jumbo { 0x24 } else { 0x3F }),
        ),
        _ => (0, 0, 0, 0, None),
    };
    JumboConfig {
        config3_set: c3s,
        config3_clear: c3c,
        config4_set: c4s,
        config4_clear: c4c,
        mtps_override: mtps,
    }
}

/// Program the 8168 jumbo Config bits (read-modify-write on both
/// registers; skipped entirely when the class needs no bits).
/// `MTPS` itself is programmed by bring-up, honouring
/// `mtps_override` when present.
///
/// # Safety
///
/// The caller must own the register window exclusively and must
/// have unlocked the config registers first.
pub unsafe fn apply_jumbo_config<R: RegFile>(regs: &mut R, mac_version: u32, jumbo: bool) {
    let cfg = jumbo_config(mac_version, jumbo);
    if cfg.config3_set != 0 || cfg.config3_clear != 0 {
        // SAFETY: caller owns the register window (see [`RegFile`]).
        let mut v = unsafe { regs.read8(REG_CONFIG3) };
        v = (v & !cfg.config3_clear) | cfg.config3_set;
        // SAFETY: as above.
        unsafe { regs.write8(REG_CONFIG3, v) };
    }
    if cfg.config4_set != 0 || cfg.config4_clear != 0 {
        // SAFETY: caller owns the register window (see [`RegFile`]).
        let mut v = unsafe { regs.read8(REG_CONFIG4) };
        v = (v & !cfg.config4_clear) | cfg.config4_set;
        // SAFETY: as above.
        unsafe { regs.write8(REG_CONFIG4, v) };
    }
}

// ── RSS (VER_80 only) ───────────────────────────────────────────────

/// Maximum RX queues on VER_80 (`R8169_MAX_RX_QUEUES`).
pub const RSS_MAX_QUEUES: usize = 8;
/// Indirection-table entries on VER_80
/// (`RTL_MAX_INDIRECTION_TABLE_ENTRIES`).
pub const RSS_INDIR_ENTRIES: usize = 128;
/// RSS key size in bytes (`RTL_RSS_KEY_SIZE`).
pub const RSS_KEY_LEN: usize = 40;

/// `RSS_CTRL` hash-option bits (`rtl8169_set_rss_hash_opt`).
pub const RSS_CTRL_TCP_IPV4: u32 = 1 << 0;
/// `RSS_CTRL` IPv4 bit.
pub const RSS_CTRL_IPV4: u32 = 1 << 1;
/// `RSS_CTRL` TCP-over-IPv6 bit.
pub const RSS_CTRL_TCP_IPV6: u32 = 1 << 2;
/// `RSS_CTRL` IPv6 bit.
pub const RSS_CTRL_IPV6: u32 = 1 << 3;
/// `RSS_CTRL` IPv6-extension bit.
pub const RSS_CTRL_IPV6_EXT: u32 = 1 << 4;
/// `RSS_CTRL` TCP-over-IPv6-extension bit.
pub const RSS_CTRL_TCP_IPV6_EXT: u32 = 1 << 5;
/// `RSS_CTRL` UDP-over-IPv4 bit.
pub const RSS_CTRL_UDP_IPV4: u32 = 1 << 11;
/// `RSS_CTRL` UDP-over-IPv6 bit.
pub const RSS_CTRL_UDP_IPV6: u32 = 1 << 12;
/// All hash options Linux enables together.
pub const RSS_CTRL_HASH_OPTS: u32 = RSS_CTRL_TCP_IPV4
    | RSS_CTRL_IPV4
    | RSS_CTRL_TCP_IPV6
    | RSS_CTRL_IPV6
    | RSS_CTRL_IPV6_EXT
    | RSS_CTRL_TCP_IPV6_EXT
    | RSS_CTRL_UDP_IPV4
    | RSS_CTRL_UDP_IPV6;

/// Queue-count field in `RSS_CTRL` (bits 18:16, `RSS_CPU_NUM_MASK`).
pub const RSS_CTRL_CPU_NUM_SHIFT: u32 = 16;
/// Indirection-size field in `RSS_CTRL` (bits 10:8, `RSS_HASH_MASK`).
pub const RSS_CTRL_HASH_SHIFT: u32 = 8;
/// Queue-count field in `Q_NUM_CTRL_8125` (bits 4:2).
pub const Q_NUM_CTRL_SHIFT: u32 = 2;
/// `RTL_DESC_TYPE_CTRL` RSS-format bit.
pub const DESC_TYPE_RSS: u8 = 1 << 1;

/// `true` iff `queues` is a usable RSS queue count: a power of two
/// in `[1, RSS_MAX_QUEUES]` (Linux rounds the default queue count
/// down to a power of two and caps it at the hardware maximum).
pub const fn rss_queues_valid(queues: usize) -> bool {
    queues >= 1 && queues <= RSS_MAX_QUEUES && (queues & (queues - 1)) == 0
}

/// `log2(queues)` for a valid queue count, else 0.
pub const fn rss_log2_queues(queues: usize) -> u32 {
    let mut n = queues;
    let mut log = 0u32;
    while n > 1 {
        n >>= 1;
        log += 1;
    }
    log
}

/// Build the `RSS_CTRL` word for `queues` queues over
/// `indir_entries` indirection entries. Returns `None` when the
/// queue count is invalid (see [`rss_queues_valid`]).
pub const fn rss_ctrl_word(queues: usize, indir_entries: usize) -> Option<u32> {
    if !rss_queues_valid(queues) {
        return None;
    }
    let mut log = 0u32;
    let mut n = indir_entries;
    while n > 1 {
        n >>= 1;
        log += 1;
    }
    Some(
        (rss_log2_queues(queues) << RSS_CTRL_CPU_NUM_SHIFT)
            | RSS_CTRL_HASH_OPTS
            | (log << RSS_CTRL_HASH_SHIFT),
    )
}

/// Build the `Q_NUM_CTRL_8125` value from `prev` for `queues`
/// queues (bits 4:2 = `log2(queues)`, everything else preserved).
/// Matches `rtl8125_set_rx_q_num`.
pub const fn q_num_ctrl_value(prev: u16, queues: usize) -> u16 {
    (prev & !0x001Cu16) | ((rss_log2_queues(queues) as u16) << Q_NUM_CTRL_SHIFT)
}

/// Program the full VER_80 RSS register sequence, in Linux's
/// `rtl_hw_start_8125_common` + `rtl_set_rss_config` order:
/// clear `RSS_CTRL` and `Q_NUM_CTRL`, select the RSS descriptor
/// type, set the queue count, store the indirection table (4
/// entries per dword, little-endian packing of the queue bytes),
/// store the 40-byte key (10 dwords), then write the control word.
/// `key` must be exactly [`RSS_KEY_LEN`] bytes and `indir`
/// exactly [`RSS_INDIR_ENTRIES`] entries each below `queues`;
/// returns `false` (writing nothing) when either is malformed, so a
/// bad table can never half-program the steering hardware.
///
/// # Safety
///
/// The caller must own the register window exclusively.
pub unsafe fn apply_rss<R: RegFile>(regs: &mut R, queues: usize, key: &[u8], indir: &[u8]) -> bool {
    if !rss_queues_valid(queues) || key.len() != RSS_KEY_LEN || indir.len() != RSS_INDIR_ENTRIES {
        return false;
    }
    for q in indir {
        if (*q as usize) >= queues {
            return false;
        }
    }
    let Some(ctrl) = rss_ctrl_word(queues, RSS_INDIR_ENTRIES) else {
        return false;
    };
    // SAFETY: caller owns the register window (see [`RegFile`]).
    unsafe { regs.write32(REG_RSS_CTRL_8125, 0) };
    // SAFETY: as above.
    unsafe { regs.write16(REG_Q_NUM_CTRL_8125, 0) };
    // SAFETY: as above.
    let mut dtype = unsafe { regs.read8(REG_DESC_TYPE_CTRL) };
    dtype |= DESC_TYPE_RSS;
    // SAFETY: as above.
    unsafe { regs.write8(REG_DESC_TYPE_CTRL, dtype) };
    // SAFETY: as above.
    let prev_q = unsafe { regs.read16(REG_Q_NUM_CTRL_8125) };
    // SAFETY: as above.
    unsafe { regs.write16(REG_Q_NUM_CTRL_8125, q_num_ctrl_value(prev_q, queues)) };
    let mut i = 0;
    while i < RSS_INDIR_ENTRIES {
        let packed = (indir[i] as u32)
            | ((indir[i + 1] as u32) << 8)
            | ((indir[i + 2] as u32) << 16)
            | ((indir[i + 3] as u32) << 24);
        // SAFETY: as above.
        unsafe { regs.write32(REG_RSS_INDIR + i as u64, packed) };
        i += 4;
    }
    let mut k = 0;
    while k < RSS_KEY_LEN {
        let word = (key[k] as u32)
            | ((key[k + 1] as u32) << 8)
            | ((key[k + 2] as u32) << 16)
            | ((key[k + 3] as u32) << 24);
        // SAFETY: as above.
        unsafe { regs.write32(REG_RSS_KEY + k as u64, word) };
        k += 4;
    }
    // SAFETY: as above.
    unsafe { regs.write32(REG_RSS_CTRL_8125, ctrl) };
    true
}

/// Program the single-queue RSS state Linux writes when a VER_80
/// chip runs with one ring: `RSS_CTRL` held at 0 (steering off).
/// Callers with a multi-ring datapath use [`apply_rss`] instead.
///
/// # Safety
///
/// The caller must own the register window exclusively.
pub unsafe fn apply_rss_single_queue<R: RegFile>(regs: &mut R) {
    // SAFETY: caller owns the register window (see [`RegFile`]).
    unsafe { regs.write32(REG_RSS_CTRL_8125, 0) };
}

// ── RX checksum decode (default descriptor type) ────────────────────

/// RX word0 protocol-ID bit for TCP (PID0, bit 17).
pub const RX_PID_TCP: u32 = 1 << 17;
/// RX word0 protocol-ID bit for UDP (PID1, bit 18).
pub const RX_PID_UDP: u32 = 1 << 18;
/// RX word0 IP checksum-failed bit (bit 16).
pub const RX_FAIL_IP: u32 = 1 << 16;
/// RX word0 UDP checksum-failed bit (bit 15).
pub const RX_FAIL_UDP: u32 = 1 << 15;
/// RX word0 TCP checksum-failed bit (bit 14).
pub const RX_FAIL_TCP: u32 = 1 << 14;

/// Decoded RX checksum verification for one chip-returned descriptor.
///
/// This corrects the previous in-tree decode, which read bits 5/6/7
/// of word0 as protocol-OK bits. Those bits are inside the
/// 14-bit frame-length field; Linux's `rtl8169_rx_csum` instead
/// masks word0 with the protocol-ID bits (17/18) and the fail bits
/// (14/15/16) and trusts the checksum only when the PID is exactly
/// TCP or exactly UDP with no fail bit set.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct RxCsum {
    /// The chip verified the IP header checksum and it passed.
    pub l3_ok: bool,
    /// The chip verified the L4 checksum and it passed.
    pub l4_ok: bool,
}

/// Decode the RX checksum result from a chip-returned word0.
pub const fn rx_csum_decode(flags_len: u32) -> RxCsum {
    let fail = flags_len & (RX_FAIL_IP | RX_FAIL_UDP | RX_FAIL_TCP);
    let pid = flags_len & (RX_PID_TCP | RX_PID_UDP);
    RxCsum {
        l3_ok: fail & RX_FAIL_IP == 0 && pid != 0,
        l4_ok: fail == 0 && (pid == RX_PID_TCP || pid == RX_PID_UDP),
    }
}

// ── TX frame parsing: transport offset + IP version ─────────────────

/// IP version of a frame's network header, as parsed by
/// [`parse_transport`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IpVersion {
    V4,
    V6,
}

/// Where the transport header starts in a frame, for the TX
/// offload descriptor fields (`TCPHO` / `GTTCPHO`): the offset is
/// measured from the start of the Ethernet frame, exactly as
/// Linux's `skb_transport_offset` measures it.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TransportInfo {
    /// Network-header version.
    pub ip: IpVersion,
    /// Byte offset of the transport header from the frame start.
    pub offset: u16,
}

fn be16(frame: &[u8], at: usize) -> Option<u16> {
    if at + 2 <= frame.len() {
        Some(u16::from_be_bytes([frame[at], frame[at + 1]]))
    } else {
        None
    }
}

/// Parse a frame far enough to fill a TX offload descriptor:
/// skip up to two VLAN tags, then the IP header (IPv4 IHL, or the
/// IPv6 fixed header plus extension headers). Returns `None` when
/// the frame is not an unfragmented IPv4/IPv6 packet, is
/// truncated, or carries an extension header the chip cannot be
/// told about (ESP, or an unknown next-header value) — the caller
/// must then reject the offload request rather than program a
/// descriptor with a guessed offset.
pub fn parse_transport(frame: &[u8]) -> Option<TransportInfo> {
    if frame.len() < 14 {
        return None;
    }
    let mut ethertype = be16(frame, 12)?;
    let mut pos = 14usize;
    let mut tags = 0;
    while ethertype == 0x8100 || ethertype == 0x88A8 {
        if tags >= 2 || pos + 4 > frame.len() {
            return None;
        }
        ethertype = be16(frame, pos + 2)?;
        pos += 4;
        tags += 1;
    }
    match ethertype {
        0x0800 => {
            if pos + 20 > frame.len() {
                return None;
            }
            let ihl = (frame[pos] as usize & 0x0F) * 4;
            if ihl < 20 || pos + ihl > frame.len() {
                return None;
            }
            let frag = be16(frame, pos + 6)?;
            if frag & 0x2000 != 0 || frag & 0x1FFF != 0 {
                return None;
            }
            let offset = pos + ihl;
            if offset >= frame.len() {
                return None;
            }
            Some(TransportInfo {
                ip: IpVersion::V4,
                offset: offset as u16,
            })
        }
        0x86DD => {
            if pos + 40 > frame.len() {
                return None;
            }
            let mut next = frame[pos + 6];
            let mut off = pos + 40;
            let mut hops = 0;
            loop {
                match next {
                    6 | 17 => {
                        if off >= frame.len() || off > u16::MAX as usize {
                            return None;
                        }
                        return Some(TransportInfo {
                            ip: IpVersion::V6,
                            offset: off as u16,
                        });
                    }
                    0 | 43 | 60 | 135 => {
                        if off + 2 > frame.len() {
                            return None;
                        }
                        let hdr_len = (frame[off + 1] as usize + 1) * 8;
                        next = frame[off];
                        off += hdr_len;
                        if off > frame.len() {
                            return None;
                        }
                    }
                    44 => {
                        if off + 8 > frame.len() {
                            return None;
                        }
                        let frag = be16(frame, off + 2)?;
                        if frag >> 3 != 0 || frag & 1 != 0 {
                            return None;
                        }
                        next = frame[off];
                        off += 8;
                    }
                    51 => {
                        if off + 2 > frame.len() {
                            return None;
                        }
                        let hdr_len = (frame[off + 1] as usize + 2) * 4;
                        next = frame[off];
                        off += hdr_len;
                        if off > frame.len() {
                            return None;
                        }
                    }
                    _ => return None,
                }
                hops += 1;
                if hops > 8 {
                    return None;
                }
            }
        }
        _ => None,
    }
}

// ── TX offload descriptor words (corrected placement) ───────────────

/// TX word0: v2 giant-send enable, IPv4 (bit 26).
pub const TD1_GTSENV4: u32 = 1 << 26;
/// TX word0: v2 giant-send enable, IPv6 (bit 25).
pub const TD1_GTSENV6: u32 = 1 << 25;
/// TX word0 (TSO) / word1 (csum): header-offset shift (bits 24:18
/// for `GTTCPHO`, bits 27:18 for `TCPHO`).
pub const TCPHO_SHIFT: u32 = 18;
/// Maximum `GTTCPHO` value (TSO case, 7 bits).
pub const GTTCPHO_MAX: u16 = 0x7F;
/// Maximum `TCPHO` value (csum case, 10 bits).
pub const TCPHO_MAX: u16 = 0x3FF;
/// TX word1: v2 MSS shift (bits 28:18, 11 bits).
pub const TD1_MSS_SHIFT: u32 = 18;
/// Maximum MSS encodable in a v2/v1 descriptor (11 bits).
pub const MSS_MAX: u16 = 0x7FF;
/// TX word1: v2 IPv6 header-checksum bit (bit 28).
pub const TD1_IPV6_CS: u32 = 1 << 28;
/// TX word1: v2 IPv4 header-checksum bit (bit 29).
pub const TD1_IPV4_CS: u32 = 1 << 29;
/// TX word1: v2 TCP checksum bit (bit 30).
pub const TD1_TCP_CS: u32 = 1 << 30;
/// TX word1: v2 UDP checksum bit (bit 31).
pub const TD1_UDP_CS: u32 = 1 << 31;

/// TX word0: v1 large-send enable (bit 27).
pub const TD_LSO: u32 = 1 << 27;
/// TX word0: v1 MSS shift (bits 26:16, 11 bits).
pub const TD0_MSS_SHIFT: u32 = 16;
/// TX word0: v1 TCP checksum bit (bit 16).
pub const TD0_TCP_CS: u32 = 1 << 16;
/// TX word0: v1 UDP checksum bit (bit 17).
pub const TD0_UDP_CS: u32 = 1 << 17;
/// TX word0: v1 IP checksum bit (bit 18).
pub const TD0_IP_CS: u32 = 1 << 18;

/// The two offload-carrying words of a TX descriptor (word0 =
/// `flags_len` extras without OWN/FS/LS/length; word1 = `vlan`
/// word). The caller ORs `word0` into its flags word and `word1`
/// into its vlan word, alongside the VLAN-insert field from
/// [`tx_vlan_word`] — the fields do not overlap.
///
/// Placement correction: the previous in-tree v2 builders put
/// `GTSENV` in word1. Linux's `rtl_tx_desc_bit_1` enum labels
/// `GTSENV`/`GTTCPHO` the *first* doubleword (word0) and
/// `MSS`/`IP_CS`/`TCP_CS`/`UDP_CS`/`TCPHO` the *second* (word1);
/// `rtl8169_start_xmit` confirms it (`opts[0]` → `opts1`,
/// `opts[1]` → `opts2`). A word1 `GTSENV` bit would have landed
/// inside the MSS field and no TSO would ever have engaged.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct OffloadWords {
    /// Extra bits for word0 (flags word).
    pub word0: u32,
    /// Word1 (vlan word).
    pub word1: u32,
}

fn v2_ip_cs(ip: IpVersion) -> u32 {
    match ip {
        IpVersion::V4 => TD1_IPV4_CS,
        IpVersion::V6 => TD1_IPV6_CS,
    }
}

fn v2_l4_cs(kind: narf_net::L4CsumKind) -> Option<u32> {
    match kind {
        narf_net::L4CsumKind::Tcp => Some(TD1_TCP_CS),
        narf_net::L4CsumKind::Udp => Some(TD1_UDP_CS),
        narf_net::L4CsumKind::Sctp => None,
    }
}

/// Build the v2 checksum-offload words for a frame whose transport
/// header is at `tcpho` (from [`parse_transport`]). `None` when
/// the offset does not fit the 10-bit `TCPHO` field, or the L4
/// kind is SCTP (no hardware support on this family).
pub fn v2_csum_words(
    kind: narf_net::L4CsumKind,
    ip: IpVersion,
    tcpho: u16,
    vlan: Option<u16>,
) -> Option<OffloadWords> {
    if tcpho > TCPHO_MAX {
        return None;
    }
    Some(OffloadWords {
        word0: 0,
        word1: v2_ip_cs(ip)
            | v2_l4_cs(kind)?
            | ((tcpho as u32) << TCPHO_SHIFT)
            | tx_vlan_word(vlan),
    })
}

/// Build the v2 TSO words: `GTSENV` + `GTTCPHO` in word0, MSS +
/// IP/TCP checksum bits in word1. Mirrors
/// `rtl8169_tso_csum_v2`, including its OR of the IPv6 checksum
/// bit into the MSS field for IPv6 (the bit doubles as MSS bit
/// 10 there; Linux ORs it unconditionally, so this builder does
/// too rather than inventing a different layout). `None` when
/// `mss` exceeds [`MSS_MAX`] or `gt_tcpho` exceeds
/// [`GTTCPHO_MAX`].
pub fn v2_tso_words(
    ip: IpVersion,
    mss: u16,
    gt_tcpho: u16,
    vlan: Option<u16>,
) -> Option<OffloadWords> {
    if mss > MSS_MAX || gt_tcpho > GTTCPHO_MAX {
        return None;
    }
    let gtsenv = match ip {
        IpVersion::V4 => TD1_GTSENV4,
        IpVersion::V6 => TD1_GTSENV6,
    };
    Some(OffloadWords {
        word0: gtsenv | ((gt_tcpho as u32) << TCPHO_SHIFT),
        word1: v2_ip_cs(ip) | TD1_TCP_CS | ((mss as u32) << TD1_MSS_SHIFT) | tx_vlan_word(vlan),
    })
}

/// Build the v1 checksum-offload words (word0 carries the csum
/// bits on pre-csum-v2 chips). `None` for SCTP.
pub fn v1_csum_words(kind: narf_net::L4CsumKind, vlan: Option<u16>) -> Option<OffloadWords> {
    let l4 = match kind {
        narf_net::L4CsumKind::Tcp => TD0_TCP_CS,
        narf_net::L4CsumKind::Udp => TD0_UDP_CS,
        narf_net::L4CsumKind::Sctp => return None,
    };
    Some(OffloadWords {
        word0: TD0_IP_CS | l4,
        word1: tx_vlan_word(vlan),
    })
}

/// Build the v1 TSO words (word0: `LSO` + MSS). `None` when `mss`
/// exceeds [`MSS_MAX`].
pub fn v1_tso_words(mss: u16, vlan: Option<u16>) -> Option<OffloadWords> {
    if mss > MSS_MAX {
        return None;
    }
    Some(OffloadWords {
        word0: TD_LSO | ((mss as u32) << TD0_MSS_SHIFT),
        word1: tx_vlan_word(vlan),
    })
}

// ── Fixtures ────────────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
mod tests {
    use narf_kernel_test::{kernel_test_in, TestResult};

    use super::*;

    fn smoke_features_cplus_cmd() -> TestResult {
        // Preserve Normal + INTT, set both offload bits.
        if cplus_cmd(0x2003, true, true) != 0x2000 | 0x0003 | CPLUS_RXVLAN | CPLUS_RXCHKSUM {
            return TestResult::Fail("cplus_cmd did not preserve CPCMD_MASK bits");
        }
        // Clear both: only the preserved bits survive.
        if cplus_cmd(0xFFFF, false, false) != 0x2003 {
            return TestResult::Fail("cplus_cmd did not clear RxVlan/RxChkSum");
        }
        // apply_cplus round-trips through a fixture register file.
        let mut regs = RegLog::new();
        // SAFETY: RegLog fixture — no hardware is touched.
        let written = unsafe { apply_cplus(&mut regs, true, false) };
        if written != CPLUS_RXVLAN {
            return TestResult::Fail("apply_cplus wrote the wrong CPlusCmd value");
        }
        match regs.last_write_to(REG_CPLUSCR) {
            Some(w) if w.width == 2 && w.value == CPLUS_RXVLAN as u32 => {}
            _ => return TestResult::Fail("apply_cplus did not log a 16-bit CPlusCmd write"),
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/realtek-features", smoke_features_cplus_cmd);

    fn smoke_features_vlan_words() -> TestResult {
        // Tag 0x0123 (VID 0x123) inserts as TxVlanTag | swab16.
        if tx_vlan_word(Some(0x0123)) != TX_VLAN_TAG_BIT | 0x2301 {
            return TestResult::Fail("tx_vlan_word did not byte-swap the tag");
        }
        if tx_vlan_word(None) != 0 {
            return TestResult::Fail("tx_vlan_word(None) was not 0");
        }
        // RX strip is the inverse, gated on the available bit.
        if rx_vlan_tag(RX_VLAN_TAG_BIT | 0x2301) != Some(0x0123) {
            return TestResult::Fail("rx_vlan_tag did not recover the tag");
        }
        if rx_vlan_tag(0x2301).is_some() {
            return TestResult::Fail("rx_vlan_tag decoded a tag without RxVlanTag");
        }
        // VLAN bits never collide with the csum/TSO word1 fields.
        let combined = tx_vlan_word(Some(0x0ABC)) | (1 << 29) | (1 << 30) | (1460u32 << 18);
        if combined & TX_VLAN_TAG_BIT == 0 || (combined >> 18) & 0x7FF != 1460 {
            return TestResult::Fail("VLAN word collided with TSO MSS field");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/realtek-features", smoke_features_vlan_words);

    fn smoke_features_wol_conversation() -> TestResult {
        let mut regs = RegLog::new();
        let opts = WolOpts::PHY | WolOpts::MAGIC | WolOpts::UCAST | WolOpts::BCAST;
        let pending =
        // SAFETY: RegLog fixture — no hardware is touched.
            unsafe { apply_wol(&mut regs, opts, WolMagic::Config3Bit, WolPmeReg::Config2) };
        if pending != WolPendingMagic::None {
            return TestResult::Fail("Config3Bit magic must not leave a pending step");
        }
        // Config3: LinkUp + MagicPacket.
        match regs.last_write_to(REG_CONFIG3) {
            Some(w) if w.value == (CONFIG3_LINKUP | CONFIG3_MAGIC_PACKET) as u32 => {}
            _ => return TestResult::Fail("Config3 did not get LinkUp|MagicPacket"),
        }
        // Config5: UWF + BWF + LanWake, MWF clear.
        match regs.last_write_to(REG_CONFIG5) {
            Some(w) if w.value == (CONFIG5_UWF | CONFIG5_BWF | CONFIG5_LANWAKE) as u32 => {}
            _ => return TestResult::Fail("Config5 did not get UWF|BWF|LanWake"),
        }
        // Config2 PME set; Config1 untouched.
        match regs.last_write_to(REG_CONFIG2) {
            Some(w) if w.value == CONFIG_PME_BIT as u32 => {}
            _ => return TestResult::Fail("Config2 did not get PME_SIGNAL"),
        }
        if regs.last_write_to(REG_CONFIG1).is_some() {
            return TestResult::Fail("Config1 must not be touched for a Config2 class");
        }
        // Clearing all opts clears LanWake + PME.
        let mut regs2 = RegLog::new();
        // SAFETY: RegLog fixture — no hardware is touched.
        let pending2 = unsafe {
            apply_wol(
                &mut regs2,
                WolOpts::default(),
                WolMagic::MacOcpC0b6,
                WolPmeReg::Config2,
            )
        };
        if pending2 != WolPendingMagic::MacOcpC0b6(false) {
            return TestResult::Fail("8125 magic-off step was not reported");
        }
        match regs2.last_write_to(REG_CONFIG5) {
            Some(w) if w.value == 0 => {}
            _ => return TestResult::Fail("empty WolOpts must clear Config5"),
        }
        if WolOpts(0xFF).is_valid() || !WolOpts::ANY.is_valid() {
            return TestResult::Fail("WolOpts validity check is inverted");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/net/realtek-features",
        smoke_features_wol_conversation
    );

    fn smoke_features_eee_caps() -> TestResult {
        if eee_supported(33) || eee_supported(37) || eee_supported(39) {
            return TestResult::Fail("eee_supported admitted a non-EEE version");
        }
        if !eee_supported(34) || !eee_supported(80) {
            return TestResult::Fail("eee_supported rejected a supported version");
        }
        let caps61 = eee_lpi_caps(61);
        if !caps61.fd_100 || !caps61.fd_1000 || caps61.fd_2500 {
            return TestResult::Fail("VER_61 must advertise 100/1000 only");
        }
        let caps63 = eee_lpi_caps(63);
        if !caps63.fd_2500 || caps63.fd_5000 {
            return TestResult::Fail("VER_63 must advertise 2500, not 5000");
        }
        let caps70 = eee_lpi_caps(70);
        if !caps70.fd_5000 || caps70.fd_10000 {
            return TestResult::Fail("VER_70 must advertise 5000, not 10000");
        }
        let caps80 = eee_lpi_caps(80);
        if !caps80.fd_10000 {
            return TestResult::Fail("VER_80 must advertise 10000");
        }
        if eee_txidle_timer(1500) != 1500 + 14 + 0x20 {
            return TestResult::Fail("eee_txidle_timer formula is wrong");
        }
        let mut regs = RegLog::new();
        // SAFETY: RegLog fixture — no hardware is touched.
        unsafe { apply_eee_txidle(&mut regs, 1500) };
        match regs.last_write_to(REG_EEE_TXIDLE_TIMER_8125) {
            Some(w) if w.width == 2 && w.value == 1534 => {}
            _ => return TestResult::Fail("EEE timer write missing or wrong"),
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/realtek-features", smoke_features_eee_caps);

    fn smoke_features_jumbo() -> TestResult {
        if jumbo_max_mtu(17) != 4 * 1024 - 22 {
            return TestResult::Fail("VER_17 jumbo max is not 4K");
        }
        if jumbo_max_mtu(61) != 16 * 1024 - 22 {
            return TestResult::Fail("VER_61+ jumbo max is not 16K");
        }
        if jumbo_max_mtu(99) != 9 * 1024 - 22 {
            return TestResult::Fail("default jumbo max is not 9K");
        }
        if mtps_for_frame(9216) != 72 || mtps_for_frame(16384) != 128 {
            return TestResult::Fail("mtps_for_frame rounding is wrong");
        }
        if rms_for_frame(16384) != 16383 || rms_for_frame(9216) != 9216 {
            return TestResult::Fail("rms_for_frame cap is wrong");
        }
        // VER_18..26 jumbo sets both Config bits; VER_61 needs none.
        let cfg = jumbo_config(20, true);
        if cfg.config3_set != CONFIG3_JUMBO_EN0 || cfg.config4_set != CONFIG4_JUMBO_EN1 {
            return TestResult::Fail("VER_20 jumbo Config bits are wrong");
        }
        let cfg61 = jumbo_config(61, true);
        if cfg61.config3_set != 0 || cfg61.config4_set != 0 || cfg61.mtps_override.is_some() {
            return TestResult::Fail("VER_61 must not program jumbo Config bits");
        }
        let cfg31 = jumbo_config(31, true);
        if cfg31.mtps_override != Some(0x24) {
            return TestResult::Fail("VER_31 jumbo must force MTPS 0x24");
        }
        let mut regs = RegLog::new();
        // SAFETY: RegLog fixture — no hardware is touched.
        unsafe { apply_jumbo_config(&mut regs, 20, true) };
        match regs.last_write_to(REG_CONFIG3) {
            Some(w) if w.value == CONFIG3_JUMBO_EN0 as u32 => {}
            _ => return TestResult::Fail("jumbo Config3 write missing"),
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/realtek-features", smoke_features_jumbo);

    fn smoke_features_rss_ver80() -> TestResult {
        if !rss_queues_valid(8) || rss_queues_valid(3) || rss_queues_valid(16) {
            return TestResult::Fail("rss_queues_valid admitted a bad count");
        }
        // Linux hash-opts word for 8 queues over 128 entries:
        // CPU_NUM = log2(8) = 3 at bits 18:16, HASH = log2(128) = 7
        // at bits 10:8, plus the eight hash-option bits.
        let ctrl = match rss_ctrl_word(8, 128) {
            Some(c) => c,
            None => return TestResult::Fail("rss_ctrl_word rejected 8 queues"),
        };
        if ctrl != (3 << 16) | RSS_CTRL_HASH_OPTS | (7 << 8) {
            return TestResult::Fail("rss_ctrl_word does not match the Linux layout");
        }
        if q_num_ctrl_value(0xFFFF, 8) != 0xFFEF {
            return TestResult::Fail("q_num_ctrl_value did not place log2(queues)");
        }
        // Full sequence through the fixture, in Linux order.
        let mut regs = RegLog::new();
        let mut key = [0u8; 40];
        let mut i = 0;
        while i < 40 {
            key[i] = i as u8;
            i += 1;
        }
        let mut indir = [0u8; 128];
        let mut j = 0;
        while j < 128 {
            indir[j] = (j % 8) as u8;
            j += 1;
        }
        // SAFETY: RegLog fixture — no hardware is touched.
        let ok = unsafe { apply_rss(&mut regs, 8, &key, &indir) };
        if !ok {
            return TestResult::Fail("apply_rss rejected a well-formed table");
        }
        match regs.last_write_to(REG_RSS_CTRL_8125) {
            Some(w) if w.value == ctrl => {}
            _ => return TestResult::Fail("RSS_CTRL final write is not the control word"),
        }
        match regs.last_write_to(REG_Q_NUM_CTRL_8125) {
            Some(w) if w.value == (3 << 2) as u32 => {}
            _ => return TestResult::Fail("Q_NUM_CTRL final write is not log2(8)"),
        }
        // First key word packs key[0..4] little-endian; first indir
        // word packs queues 0,1,2,3.
        match regs.last_write_to(REG_RSS_KEY) {
            Some(w) if w.value == 0x0302_0100 => {}
            _ => return TestResult::Fail("RSS key packing is wrong"),
        }
        match regs.last_write_to(REG_RSS_INDIR) {
            Some(w) if w.value == 0x0302_0100 => {}
            _ => return TestResult::Fail("RSS indirection packing is wrong"),
        }
        // Malformed tables write nothing at all.
        let mut regs2 = RegLog::new();
        // SAFETY: RegLog fixture — no hardware is touched.
        let bad = unsafe { apply_rss(&mut regs2, 8, &key[..39], &indir) };
        if bad || !regs2.log.is_empty() {
            return TestResult::Fail("malformed RSS table half-programmed the device");
        }
        // Single-queue state is RSS_CTRL = 0.
        let mut regs3 = RegLog::new();
        // SAFETY: RegLog fixture — no hardware is touched.
        unsafe { apply_rss_single_queue(&mut regs3) };
        match regs3.last_write_to(REG_RSS_CTRL_8125) {
            Some(w) if w.value == 0 => {}
            _ => return TestResult::Fail("single-queue RSS_CTRL is not 0"),
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/realtek-features", smoke_features_rss_ver80);

    fn eth_ipv4_frame() -> [u8; 60] {
        // Ethernet (dst/src/type 0x0800) + IPv4 IHL 5 + TCP header.
        let mut f = [0u8; 60];
        f[12] = 0x08;
        f[13] = 0x00;
        f[14] = 0x45;
        f[23] = 0x06; // protocol TCP (not read by the parser, but realistic)
        f
    }

    fn smoke_features_transport_parse() -> TestResult {
        let f = eth_ipv4_frame();
        match parse_transport(&f) {
            Some(t) if t.ip == IpVersion::V4 && t.offset == 34 => {}
            _ => return TestResult::Fail("IPv4/TCP transport offset is not 34"),
        }
        // One VLAN tag shifts the offset by 4.
        let mut v = [0u8; 64];
        v[12] = 0x81;
        v[13] = 0x00;
        v[16] = 0x08;
        v[17] = 0x00;
        v[18] = 0x45;
        match parse_transport(&v) {
            Some(t) if t.offset == 38 => {}
            _ => return TestResult::Fail("VLAN-tagged IPv4 offset is not 38"),
        }
        // IPv4 options (IHL 6) shift it by 4 more.
        let mut o = eth_ipv4_frame();
        o[14] = 0x46;
        match parse_transport(&o) {
            Some(t) if t.offset == 38 => {}
            _ => return TestResult::Fail("IPv4-options offset is not 38"),
        }
        // IPv6 fixed header: offset 54.
        let mut v6 = [0u8; 74];
        v6[12] = 0x86;
        v6[13] = 0xDD;
        v6[20] = 0x06; // next header TCP
        match parse_transport(&v6) {
            Some(t) if t.ip == IpVersion::V6 && t.offset == 54 => {}
            _ => return TestResult::Fail("IPv6/TCP transport offset is not 54"),
        }
        // IPv6 hop-by-hop (length byte 0 => 8 bytes): offset 62.
        let mut hbh = [0u8; 82];
        hbh[12] = 0x86;
        hbh[13] = 0xDD;
        hbh[20] = 0x00; // next header: hop-by-hop
        hbh[54] = 0x06; // hop-by-hop's next: TCP
        hbh[55] = 0x00; // hop-by-hop length byte: 0 => 8 bytes
        match parse_transport(&hbh) {
            Some(t) if t.offset == 62 => {}
            _ => return TestResult::Fail("IPv6 hop-by-hop offset is not 62"),
        }
        // Fragmented IPv4 (MF set) and non-IP frames are rejected.
        let mut frag = eth_ipv4_frame();
        frag[20] = 0x20;
        frag[21] = 0x00;
        if parse_transport(&frag).is_some() {
            return TestResult::Fail("fragmented IPv4 must not parse");
        }
        let mut arp = [0u8; 60];
        arp[12] = 0x08;
        arp[13] = 0x06;
        if parse_transport(&arp).is_some() {
            return TestResult::Fail("non-IP frame must not parse");
        }
        if parse_transport(&[0u8; 10]).is_some() {
            return TestResult::Fail("truncated frame must not parse");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/net/realtek-features",
        smoke_features_transport_parse
    );

    fn smoke_features_rx_csum_decode() -> TestResult {
        // TCP-only PID, no fails: both verified.
        let ok = rx_csum_decode(RX_PID_TCP);
        if !ok.l3_ok || !ok.l4_ok {
            return TestResult::Fail("TCP PID without fails must verify");
        }
        // UDP-only PID, no fails: both verified.
        let uok = rx_csum_decode(RX_PID_UDP);
        if !uok.l3_ok || !uok.l4_ok {
            return TestResult::Fail("UDP PID without fails must verify");
        }
        // Any fail bit voids the L4 result; an IP fail voids L3 too.
        let bad = rx_csum_decode(RX_PID_TCP | RX_FAIL_TCP);
        if bad.l3_ok || bad.l4_ok {
            return TestResult::Fail("TCP fail must void the checksum result");
        }
        let ipbad = rx_csum_decode(RX_PID_UDP | RX_FAIL_IP);
        if ipbad.l3_ok || ipbad.l4_ok {
            return TestResult::Fail("IP fail must void the checksum result");
        }
        // Both PID bits (IP-only, no L4): L3 verified, L4 not.
        let iponly = rx_csum_decode(RX_PID_TCP | RX_PID_UDP);
        if !iponly.l3_ok || iponly.l4_ok {
            return TestResult::Fail("IP-only frame must verify L3 only");
        }
        // No PID bits: nothing verified.
        let none = rx_csum_decode(0x1234);
        if none.l3_ok || none.l4_ok {
            return TestResult::Fail("non-IP status must verify nothing");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/net/realtek-features",
        smoke_features_rx_csum_decode
    );

    fn smoke_features_offload_words() -> TestResult {
        use narf_net::L4CsumKind;
        // v2 csum, IPv4/TCP, transport offset 34: word0 empty,
        // word1 = IPv4 + TCP + (34 << 18).
        let c = match v2_csum_words(L4CsumKind::Tcp, IpVersion::V4, 34, None) {
            Some(w) => w,
            None => return TestResult::Fail("v2_csum_words rejected a valid request"),
        };
        if c.word0 != 0 || c.word1 != TD1_IPV4_CS | TD1_TCP_CS | (34u32 << 18) {
            return TestResult::Fail("v2 csum words misplaced a field");
        }
        // v2 TSO, IPv4, MSS 1460, offset 34: GTSENV4 + offset in
        // word0; MSS + csum bits in word1.
        let t = match v2_tso_words(IpVersion::V4, 1460, 34, None) {
            Some(w) => w,
            None => return TestResult::Fail("v2_tso_words rejected a valid request"),
        };
        if t.word0 != TD1_GTSENV4 | (34u32 << 18) {
            return TestResult::Fail("v2 TSO word0 must carry GTSENV4 + GTTCPHO");
        }
        if t.word1 != TD1_IPV4_CS | TD1_TCP_CS | (1460u32 << 18) {
            return TestResult::Fail("v2 TSO word1 must carry MSS + csum bits");
        }
        // SCTP and out-of-range values are rejected, never guessed.
        if v2_csum_words(L4CsumKind::Sctp, IpVersion::V4, 34, None).is_some() {
            return TestResult::Fail("SCTP csum must be rejected");
        }
        if v2_csum_words(L4CsumKind::Tcp, IpVersion::V4, 0x400, None).is_some() {
            return TestResult::Fail("TCPHO overflow must be rejected");
        }
        if v2_tso_words(IpVersion::V4, 0x800, 34, None).is_some() {
            return TestResult::Fail("MSS overflow must be rejected");
        }
        if v2_tso_words(IpVersion::V4, 1460, 0x80, None).is_some() {
            return TestResult::Fail("GTTCPHO overflow must be rejected");
        }
        // v1 csum UDP: IP + UDP bits in word0; v1 TSO: LSO + MSS.
        let v1c = match v1_csum_words(L4CsumKind::Udp, None) {
            Some(w) => w,
            None => return TestResult::Fail("v1_csum_words rejected UDP"),
        };
        if v1c.word0 != TD0_IP_CS | TD0_UDP_CS {
            return TestResult::Fail("v1 csum word0 is wrong");
        }
        let v1t = match v1_tso_words(1460, None) {
            Some(w) => w,
            None => return TestResult::Fail("v1_tso_words rejected a valid MSS"),
        };
        if v1t.word0 != TD_LSO | (1460u32 << 16) {
            return TestResult::Fail("v1 TSO word0 is wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/realtek-features", smoke_features_offload_words);
}
