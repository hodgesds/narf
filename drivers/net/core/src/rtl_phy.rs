//! RTL8125 / RTL8168 RX descriptor + PHY/EEPROM auxiliary codec
//! (clean-room).
//!
//! References (public-only):
//! - Realtek "RTL8125 Series 2.5 Gigabit Ethernet Controller —
//!   Registers Datasheet" Rev. 1.0. Public document.
//!   §2.10 PHYAR — PHY Access Register layout. §3.1.2 Receive
//!   Descriptor Format. §2.18 ERIDR / ERIAR (extended-register
//!   indirect access). §2.20 EPHY_AR — Ethernet PHY indirect
//!   registers.
//! - Realtek "RTL8111B/RTL8168B Integrated Gigabit Ethernet
//!   Controller — Registers Datasheet" Rev. 1.0 (Jan 2006). The
//!   "B" PHYAR / receive-descriptor layout that the RTL8125
//!   inherits unchanged.
//! - IEEE 802.3 Clause 22 — public MII MDIO frame format. PHYAR is
//!   Realtek's MMIO-shaped wrapper around a Clause 22 transaction.
//!   <https://standards.ieee.org/ieee/802.3/7071/>
//!
//! No GPL Linux source consulted.
//!
//! ## RX descriptor (§3.1.2)
//!
//! Same 16-byte shape as the TX side, but with different flag bits:
//!
//! ```text
//!   word0:  flags (OWN/EOR/FS/LS/MAR/PAM/BAR/RES/...) | length[13:0]
//!   word1:  vlan
//!   word2:  buffer phys addr lo
//!   word3:  buffer phys addr hi
//! ```
//!
//! The flag layout flips meaning between *prepare* (host gives the
//! buffer to the chip — sets OWN+EOR-on-last) and *consume* (chip
//! returns the buffer with FS/LS/MAR/PAM/BAR/RES status bits and
//! length set; OWN cleared).
//!
//! ## PHY access (§2.10)
//!
//! ```text
//!   PHYAR (32-bit MMIO at offset 0x60):
//!     bit 31     = Flag (1 = transaction in progress; chip clears
//!                  on completion)
//!     bits 30..27 reserved
//!     bits 26..21 = Register address (5 bits in Clause 22, padded)
//!     bits 20..16 reserved
//!     bits 15..0  = Data
//! ```
//!
//! Read: write `(reg << 21)`, poll bit 31 for clear, read low 16
//! bits. Write: write `(1<<31) | (reg << 21) | data`, poll bit 31
//! for clear.

/// PHY Access Register MMIO offset (§2.10).
pub const REG_PHYAR: u64 = 0x60;

/// Set when the transaction is in flight (Flag bit, §2.10). The chip
/// clears it on completion. For *writes* the host *sets* this bit
/// when issuing the transaction; for *reads* the host writes 0 and
/// waits for the chip to set+clear it as it returns data.
pub const PHYAR_FLAG: u32 = 1 << 31;

/// Build the PHYAR write to start a *read* of MII register `reg`.
/// Returns the 32-bit value the driver writes to MMIO offset 0x60.
pub const fn phyar_read_request(reg: u8) -> u32 {
    ((reg as u32) & 0x1F) << 16
}

/// Build the PHYAR write to start a *write* of `data` into MII
/// register `reg`.
pub const fn phyar_write_request(reg: u8, data: u16) -> u32 {
    PHYAR_FLAG | (((reg as u32) & 0x1F) << 16) | (data as u32)
}

/// Extract the 16-bit data field from a PHYAR readback.
pub const fn phyar_data(value: u32) -> u16 {
    (value & 0xFFFF) as u16
}

/// `true` if a PHYAR transaction has completed (the chip cleared the
/// Flag bit).
pub const fn phyar_done(value: u32) -> bool {
    (value & PHYAR_FLAG) == 0
}

// ── EEPROM via 9346CR (§2.9) ───────────────────────────────────────

/// 9346CR offset (§2.9).
pub const REG_9346CR: u64 = 0x50;

/// 9346CR EEPROM-Mode (EEM) field — top 2 bits of the byte.
pub const EEM_NORMAL: u8 = 0x00;
pub const EEM_AUTOLOAD: u8 = 0x40;
pub const EEM_PROGRAM: u8 = 0x80;
pub const EEM_CONFIG_WRITE: u8 = 0xC0;

// ── RX descriptor (§3.1.2) ─────────────────────────────────────────

/// Descriptor count per ring; matches `RING_LEN` in `rtl8125.rs`.
pub const RING_LEN: usize = 256;

/// RX descriptor word0 flag bits (§3.1.2 Table 3-2).
pub const RXD_OWN: u32 = 1 << 31;
pub const RXD_EOR: u32 = 1 << 30;
pub const RXD_FS: u32 = 1 << 29;
pub const RXD_LS: u32 = 1 << 28;
pub const RXD_MAR: u32 = 1 << 27; // multicast match
pub const RXD_PAM: u32 = 1 << 26; // physical address match
pub const RXD_BAR: u32 = 1 << 25; // broadcast match
pub const RXD_RES: u32 = 1 << 21; // RX error summary
pub const RXD_LEN_MASK: u32 = 0x3FFF;

/// 16-byte RX descriptor — same in-memory shape as the TX descriptor.
#[repr(C, align(16))]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct RxDesc {
    pub flags_len: u32,
    pub vlan: u32,
    pub addr_lo: u32,
    pub addr_hi: u32,
}
const _: () = assert!(core::mem::size_of::<RxDesc>() == 16);
const _: () = assert!(core::mem::align_of::<RxDesc>() == 16);

/// Prepare an RX descriptor for the chip to fill: gives the chip
/// ownership (OWN=1) and a `buf_size`-byte buffer. The EOR bit is
/// set on the last slot so the chip wraps to slot 0.
pub const fn prepare_rx_desc(slot: usize, phys: u64, buf_size: u32) -> RxDesc {
    let mut flags = RXD_OWN | (buf_size & RXD_LEN_MASK);
    if slot == RING_LEN - 1 {
        flags |= RXD_EOR;
    }
    RxDesc {
        flags_len: flags,
        vlan: 0,
        addr_lo: phys as u32,
        addr_hi: (phys >> 32) as u32,
    }
}

/// Decoded RX descriptor returned by the chip.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct RxStatus {
    /// Frame length in bytes (low 14 bits of word0). Includes the
    /// 4-byte CRC; the driver typically subtracts that.
    pub length: u16,
    pub fs: bool,
    pub ls: bool,
    pub multicast: bool,
    pub physical_match: bool,
    pub broadcast: bool,
    pub error: bool,
}

impl RxStatus {
    /// Decode word0 of a chip-returned RX descriptor (i.e. one whose
    /// OWN bit is now 0).
    pub const fn parse(flags_len: u32) -> Self {
        Self {
            length: (flags_len & RXD_LEN_MASK) as u16,
            fs: (flags_len & RXD_FS) != 0,
            ls: (flags_len & RXD_LS) != 0,
            multicast: (flags_len & RXD_MAR) != 0,
            physical_match: (flags_len & RXD_PAM) != 0,
            broadcast: (flags_len & RXD_BAR) != 0,
            error: (flags_len & RXD_RES) != 0,
        }
    }
}

// ── Common MII (Clause 22) registers ───────────────────────────────

pub const MII_BMCR: u8 = 0x00; // Basic Mode Control
pub const MII_BMSR: u8 = 0x01; // Basic Mode Status
pub const MII_PHYSID1: u8 = 0x02;
pub const MII_PHYSID2: u8 = 0x03;
pub const MII_ADVERTISE: u8 = 0x04;
pub const MII_LPA: u8 = 0x05;
pub const MII_GBCR: u8 = 0x09; // 1000BASE-T Control (Clause 40)
pub const MII_GBSR: u8 = 0x0A; // 1000BASE-T Status

// BMCR bits.
pub const BMCR_RESET: u16 = 1 << 15;
pub const BMCR_LOOPBACK: u16 = 1 << 14;
pub const BMCR_SPEED100: u16 = 1 << 13;
pub const BMCR_AUTONEG_EN: u16 = 1 << 12;
pub const BMCR_POWERDOWN: u16 = 1 << 11;
pub const BMCR_ISOLATE: u16 = 1 << 10;
pub const BMCR_RESTART_AUTONEG: u16 = 1 << 9;
pub const BMCR_FULL_DUPLEX: u16 = 1 << 8;
pub const BMCR_SPEED1000: u16 = 1 << 6;

// BMSR bits.
pub const BMSR_100_T4: u16 = 1 << 15;
pub const BMSR_100_FD: u16 = 1 << 14;
pub const BMSR_100_HD: u16 = 1 << 13;
pub const BMSR_10_FD: u16 = 1 << 12;
pub const BMSR_10_HD: u16 = 1 << 11;
pub const BMSR_AUTONEG_COMPLETE: u16 = 1 << 5;
pub const BMSR_LINK_UP: u16 = 1 << 2;
