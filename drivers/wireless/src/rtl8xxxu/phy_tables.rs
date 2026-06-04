//! Shared PHY/RF/MAC register-init table representation used by every
//! per-chip integration module.
//!
//! Linux defines three table-row structs in `rtl8xxxu.h`:
//!
//! ```c
//! struct rtl8xxxu_reg8val  { u16 reg; u8  val; };  // MAC init
//! struct rtl8xxxu_reg32val { u16 reg; u32 val; };  // PHY/BB + AGC init
//! struct rtl8xxxu_rfregval { u8  reg; u32 val; };  // RF (LSSI) init
//! ```
//!
//! All three terminate with a sentinel row whose `reg` field is 0xFF or
//! 0xFFFF and whose `val` field is all-ones. The Rust ports use the same
//! convention via the `is_sentinel` predicate so the apply-loop logic is
//! identical across chips.
//!
//! ## References (GPL-2.0-or-later)
//!
//! - `drivers/net/wireless/realtek/rtl8xxxu/rtl8xxxu.h` lines ~1100–1140
//! - `drivers/net/wireless/realtek/rtl8xxxu/core.c::rtl8xxxu_init_mac`
//! - `drivers/net/wireless/realtek/rtl8xxxu/core.c::rtl8xxxu_init_phy_regs`
//! - `drivers/net/wireless/realtek/rtl8xxxu/core.c::rtl8xxxu_init_phy_rf`

#![allow(dead_code)]

use super::phy::Reg32Val;

/// 8-bit MAC table row.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MacRow {
    pub reg: u16,
    pub val: u8,
}

impl MacRow {
    /// Sentinel terminating row — Linux uses `{0xFFFF, 0xFF}`.
    pub const SENTINEL: Self = Self {
        reg: 0xFFFF,
        val: 0xFF,
    };

    pub const fn is_sentinel(&self) -> bool {
        self.reg == 0xFFFF
    }
}

/// 5-bit-RF-address × 20-bit-data row used by RF init tables.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RfRow {
    /// RF register address (5 bits, but stored as u8).
    pub reg: u8,
    /// 20-bit data field; high bits 0.
    pub val: u32,
}

impl RfRow {
    /// Sentinel — Linux uses `{0xFF, 0xFFFFFFFF}`.
    pub const SENTINEL: Self = Self {
        reg: 0xFF,
        val: 0xFFFFFFFF,
    };

    pub const fn is_sentinel(&self) -> bool {
        self.reg == 0xFF
    }
}

/// Re-export the `Reg32Val` row from `phy.rs` so callers can keep a
/// single table-row vocabulary.
pub type PhyRow = Reg32Val;

/// Count rows in a table up to (but not including) the sentinel.
pub fn live_rows_mac(table: &[MacRow]) -> usize {
    table.iter().take_while(|r| !r.is_sentinel()).count()
}

/// Count rows in a PHY/BB/AGC table up to the sentinel.
pub fn live_rows_phy(table: &[PhyRow]) -> usize {
    table.iter().take_while(|r| **r != PhyRow::SENTINEL).count()
}

/// Count rows in an RF table up to the sentinel.
pub fn live_rows_rf(table: &[RfRow]) -> usize {
    table.iter().take_while(|r| !r.is_sentinel()).count()
}

/// Apply a MAC table by invoking `write8(reg, val)` for each non-sentinel
/// row.
///
/// Source: `core.c::rtl8xxxu_init_mac` ~L2187..L2230. The Linux loop:
///
/// ```c
/// for (i = 0; ; i++) {
///     if (array[i].reg == 0xffff && array[i].val == 0xff)
///         break;
///     rtl8xxxu_write8(priv, array[i].reg, array[i].val);
/// }
/// ```
pub fn apply_mac_table<W: FnMut(u16, u8)>(table: &[MacRow], mut write8: W) -> usize {
    let mut n = 0;
    for row in table {
        if row.is_sentinel() {
            break;
        }
        write8(row.reg, row.val);
        n += 1;
    }
    n
}

/// Apply a PHY/BB or AGC table by invoking `write32(reg, val)`.
///
/// Source: `core.c::rtl8xxxu_init_phy_regs` ~L2230.
pub fn apply_phy_table<W: FnMut(u16, u32)>(table: &[PhyRow], mut write32: W) -> usize {
    let mut n = 0;
    for row in table {
        if *row == PhyRow::SENTINEL {
            break;
        }
        write32(row.reg, row.val);
        n += 1;
    }
    n
}

/// Apply an RF table by invoking `write_rfreg(path, reg, val)`.
///
/// Source: `core.c::rtl8xxxu_init_phy_rf` ~L2310. The RF path is
/// determined by the caller (`RF_A` or `RF_B`).
pub fn apply_rf_table<W: FnMut(u8, u32)>(table: &[RfRow], mut write_rfreg: W) -> usize {
    let mut n = 0;
    for row in table {
        if row.is_sentinel() {
            break;
        }
        write_rfreg(row.reg, row.val);
        n += 1;
    }
    n
}

// ──────────────────────────────────────────────────────────────────────
// RTL8188EU — concrete register-init tables.
//
// Ported verbatim from Linux v6.13 source
// `drivers/net/wireless/realtek/rtl8xxxu/8188e.c`. Row counts include
// the trailing sentinel; the apply-loop above stops on it.
// ──────────────────────────────────────────────────────────────────────

/// 8188EU MAC init table — `rtl8188e_mac_init_table[]` L19..L44 (92 rows + sentinel).
pub const MAC_REGS_8188E: &[MacRow] = &[
    MacRow {
        reg: 0x026,
        val: 0x41,
    },
    MacRow {
        reg: 0x027,
        val: 0x35,
    },
    MacRow {
        reg: 0x040,
        val: 0x00,
    },
    MacRow {
        reg: 0x421,
        val: 0x0f,
    },
    MacRow {
        reg: 0x428,
        val: 0x0a,
    },
    MacRow {
        reg: 0x429,
        val: 0x10,
    },
    MacRow {
        reg: 0x430,
        val: 0x00,
    },
    MacRow {
        reg: 0x431,
        val: 0x01,
    },
    MacRow {
        reg: 0x432,
        val: 0x02,
    },
    MacRow {
        reg: 0x433,
        val: 0x04,
    },
    MacRow {
        reg: 0x434,
        val: 0x05,
    },
    MacRow {
        reg: 0x435,
        val: 0x06,
    },
    MacRow {
        reg: 0x436,
        val: 0x07,
    },
    MacRow {
        reg: 0x437,
        val: 0x08,
    },
    MacRow {
        reg: 0x438,
        val: 0x00,
    },
    MacRow {
        reg: 0x439,
        val: 0x00,
    },
    MacRow {
        reg: 0x43a,
        val: 0x01,
    },
    MacRow {
        reg: 0x43b,
        val: 0x02,
    },
    MacRow {
        reg: 0x43c,
        val: 0x04,
    },
    MacRow {
        reg: 0x43d,
        val: 0x05,
    },
    MacRow {
        reg: 0x43e,
        val: 0x06,
    },
    MacRow {
        reg: 0x43f,
        val: 0x07,
    },
    MacRow {
        reg: 0x440,
        val: 0x5d,
    },
    MacRow {
        reg: 0x441,
        val: 0x01,
    },
    MacRow {
        reg: 0x442,
        val: 0x00,
    },
    MacRow {
        reg: 0x444,
        val: 0x15,
    },
    MacRow {
        reg: 0x445,
        val: 0xf0,
    },
    MacRow {
        reg: 0x446,
        val: 0x0f,
    },
    MacRow {
        reg: 0x447,
        val: 0x00,
    },
    MacRow {
        reg: 0x458,
        val: 0x41,
    },
    MacRow {
        reg: 0x459,
        val: 0xa8,
    },
    MacRow {
        reg: 0x45a,
        val: 0x72,
    },
    MacRow {
        reg: 0x45b,
        val: 0xb9,
    },
    MacRow {
        reg: 0x460,
        val: 0x66,
    },
    MacRow {
        reg: 0x461,
        val: 0x66,
    },
    MacRow {
        reg: 0x480,
        val: 0x08,
    },
    MacRow {
        reg: 0x4c8,
        val: 0xff,
    },
    MacRow {
        reg: 0x4c9,
        val: 0x08,
    },
    MacRow {
        reg: 0x4cc,
        val: 0xff,
    },
    MacRow {
        reg: 0x4cd,
        val: 0xff,
    },
    MacRow {
        reg: 0x4ce,
        val: 0x01,
    },
    MacRow {
        reg: 0x4d3,
        val: 0x01,
    },
    MacRow {
        reg: 0x500,
        val: 0x26,
    },
    MacRow {
        reg: 0x501,
        val: 0xa2,
    },
    MacRow {
        reg: 0x502,
        val: 0x2f,
    },
    MacRow {
        reg: 0x503,
        val: 0x00,
    },
    MacRow {
        reg: 0x504,
        val: 0x28,
    },
    MacRow {
        reg: 0x505,
        val: 0xa3,
    },
    MacRow {
        reg: 0x506,
        val: 0x5e,
    },
    MacRow {
        reg: 0x507,
        val: 0x00,
    },
    MacRow {
        reg: 0x508,
        val: 0x2b,
    },
    MacRow {
        reg: 0x509,
        val: 0xa4,
    },
    MacRow {
        reg: 0x50a,
        val: 0x5e,
    },
    MacRow {
        reg: 0x50b,
        val: 0x00,
    },
    MacRow {
        reg: 0x50c,
        val: 0x4f,
    },
    MacRow {
        reg: 0x50d,
        val: 0xa4,
    },
    MacRow {
        reg: 0x50e,
        val: 0x00,
    },
    MacRow {
        reg: 0x50f,
        val: 0x00,
    },
    MacRow {
        reg: 0x512,
        val: 0x1c,
    },
    MacRow {
        reg: 0x514,
        val: 0x0a,
    },
    MacRow {
        reg: 0x516,
        val: 0x0a,
    },
    MacRow {
        reg: 0x525,
        val: 0x4f,
    },
    MacRow {
        reg: 0x550,
        val: 0x10,
    },
    MacRow {
        reg: 0x551,
        val: 0x10,
    },
    MacRow {
        reg: 0x559,
        val: 0x02,
    },
    MacRow {
        reg: 0x55d,
        val: 0xff,
    },
    MacRow {
        reg: 0x605,
        val: 0x30,
    },
    MacRow {
        reg: 0x608,
        val: 0x0e,
    },
    MacRow {
        reg: 0x609,
        val: 0x2a,
    },
    MacRow {
        reg: 0x620,
        val: 0xff,
    },
    MacRow {
        reg: 0x621,
        val: 0xff,
    },
    MacRow {
        reg: 0x622,
        val: 0xff,
    },
    MacRow {
        reg: 0x623,
        val: 0xff,
    },
    MacRow {
        reg: 0x624,
        val: 0xff,
    },
    MacRow {
        reg: 0x625,
        val: 0xff,
    },
    MacRow {
        reg: 0x626,
        val: 0xff,
    },
    MacRow {
        reg: 0x627,
        val: 0xff,
    },
    MacRow {
        reg: 0x63c,
        val: 0x08,
    },
    MacRow {
        reg: 0x63d,
        val: 0x08,
    },
    MacRow {
        reg: 0x63e,
        val: 0x0c,
    },
    MacRow {
        reg: 0x63f,
        val: 0x0c,
    },
    MacRow {
        reg: 0x640,
        val: 0x40,
    },
    MacRow {
        reg: 0x652,
        val: 0x20,
    },
    MacRow {
        reg: 0x66e,
        val: 0x05,
    },
    MacRow {
        reg: 0x700,
        val: 0x21,
    },
    MacRow {
        reg: 0x701,
        val: 0x43,
    },
    MacRow {
        reg: 0x702,
        val: 0x65,
    },
    MacRow {
        reg: 0x703,
        val: 0x87,
    },
    MacRow {
        reg: 0x708,
        val: 0x21,
    },
    MacRow {
        reg: 0x709,
        val: 0x43,
    },
    MacRow {
        reg: 0x70a,
        val: 0x65,
    },
    MacRow {
        reg: 0x70b,
        val: 0x87,
    },
    MacRow::SENTINEL,
];

/// 8188EU PHY/BB init table — `rtl8188eu_phy_init_table[]` L46..L144 (192 rows + sentinel).
pub const BB_REGS_8188E: &[PhyRow] = &[
    PhyRow {
        reg: 0x800,
        val: 0x80040000,
    },
    PhyRow {
        reg: 0x804,
        val: 0x00000003,
    },
    PhyRow {
        reg: 0x808,
        val: 0x0000fc00,
    },
    PhyRow {
        reg: 0x80c,
        val: 0x0000000a,
    },
    PhyRow {
        reg: 0x810,
        val: 0x10001331,
    },
    PhyRow {
        reg: 0x814,
        val: 0x020c3d10,
    },
    PhyRow {
        reg: 0x818,
        val: 0x02200385,
    },
    PhyRow {
        reg: 0x81c,
        val: 0x00000000,
    },
    PhyRow {
        reg: 0x820,
        val: 0x01000100,
    },
    PhyRow {
        reg: 0x824,
        val: 0x00390204,
    },
    PhyRow {
        reg: 0x828,
        val: 0x00000000,
    },
    PhyRow {
        reg: 0x82c,
        val: 0x00000000,
    },
    PhyRow {
        reg: 0x830,
        val: 0x00000000,
    },
    PhyRow {
        reg: 0x834,
        val: 0x00000000,
    },
    PhyRow {
        reg: 0x838,
        val: 0x00000000,
    },
    PhyRow {
        reg: 0x83c,
        val: 0x00000000,
    },
    PhyRow {
        reg: 0x840,
        val: 0x00010000,
    },
    PhyRow {
        reg: 0x844,
        val: 0x00000000,
    },
    PhyRow {
        reg: 0x848,
        val: 0x00000000,
    },
    PhyRow {
        reg: 0x84c,
        val: 0x00000000,
    },
    PhyRow {
        reg: 0x850,
        val: 0x00000000,
    },
    PhyRow {
        reg: 0x854,
        val: 0x00000000,
    },
    PhyRow {
        reg: 0x858,
        val: 0x569a11a9,
    },
    PhyRow {
        reg: 0x85c,
        val: 0x01000014,
    },
    PhyRow {
        reg: 0x860,
        val: 0x66f60110,
    },
    PhyRow {
        reg: 0x864,
        val: 0x061f0649,
    },
    PhyRow {
        reg: 0x868,
        val: 0x00000000,
    },
    PhyRow {
        reg: 0x86c,
        val: 0x27272700,
    },
    PhyRow {
        reg: 0x870,
        val: 0x07000760,
    },
    PhyRow {
        reg: 0x874,
        val: 0x25004000,
    },
    PhyRow {
        reg: 0x878,
        val: 0x00000808,
    },
    PhyRow {
        reg: 0x87c,
        val: 0x00000000,
    },
    PhyRow {
        reg: 0x880,
        val: 0xb0000c1c,
    },
    PhyRow {
        reg: 0x884,
        val: 0x00000001,
    },
    PhyRow {
        reg: 0x888,
        val: 0x00000000,
    },
    PhyRow {
        reg: 0x88c,
        val: 0xccc000c0,
    },
    PhyRow {
        reg: 0x890,
        val: 0x00000800,
    },
    PhyRow {
        reg: 0x894,
        val: 0xfffffffe,
    },
    PhyRow {
        reg: 0x898,
        val: 0x40302010,
    },
    PhyRow {
        reg: 0x89c,
        val: 0x00706050,
    },
    PhyRow {
        reg: 0x900,
        val: 0x00000000,
    },
    PhyRow {
        reg: 0x904,
        val: 0x00000023,
    },
    PhyRow {
        reg: 0x908,
        val: 0x00000000,
    },
    PhyRow {
        reg: 0x90c,
        val: 0x81121111,
    },
    PhyRow {
        reg: 0x910,
        val: 0x00000002,
    },
    PhyRow {
        reg: 0x914,
        val: 0x00000201,
    },
    PhyRow {
        reg: 0xa00,
        val: 0x00d047c8,
    },
    PhyRow {
        reg: 0xa04,
        val: 0x80ff800c,
    },
    PhyRow {
        reg: 0xa08,
        val: 0x8c838300,
    },
    PhyRow {
        reg: 0xa0c,
        val: 0x2e7f120f,
    },
    PhyRow {
        reg: 0xa10,
        val: 0x9500bb7e,
    },
    PhyRow {
        reg: 0xa14,
        val: 0x1114d028,
    },
    PhyRow {
        reg: 0xa18,
        val: 0x00881117,
    },
    PhyRow {
        reg: 0xa1c,
        val: 0x89140f00,
    },
    PhyRow {
        reg: 0xa20,
        val: 0x1a1b0000,
    },
    PhyRow {
        reg: 0xa24,
        val: 0x090e1317,
    },
    PhyRow {
        reg: 0xa28,
        val: 0x00000204,
    },
    PhyRow {
        reg: 0xa2c,
        val: 0x00d30000,
    },
    PhyRow {
        reg: 0xa70,
        val: 0x101fbf00,
    },
    PhyRow {
        reg: 0xa74,
        val: 0x00000007,
    },
    PhyRow {
        reg: 0xa78,
        val: 0x00000900,
    },
    PhyRow {
        reg: 0xa7c,
        val: 0x225b0606,
    },
    PhyRow {
        reg: 0xa80,
        val: 0x218075b1,
    },
    PhyRow {
        reg: 0xb2c,
        val: 0x80000000,
    },
    PhyRow {
        reg: 0xc00,
        val: 0x48071d40,
    },
    PhyRow {
        reg: 0xc04,
        val: 0x03a05611,
    },
    PhyRow {
        reg: 0xc08,
        val: 0x000000e4,
    },
    PhyRow {
        reg: 0xc0c,
        val: 0x6c6c6c6c,
    },
    PhyRow {
        reg: 0xc10,
        val: 0x08800000,
    },
    PhyRow {
        reg: 0xc14,
        val: 0x40000100,
    },
    PhyRow {
        reg: 0xc18,
        val: 0x08800000,
    },
    PhyRow {
        reg: 0xc1c,
        val: 0x40000100,
    },
    PhyRow {
        reg: 0xc20,
        val: 0x00000000,
    },
    PhyRow {
        reg: 0xc24,
        val: 0x00000000,
    },
    PhyRow {
        reg: 0xc28,
        val: 0x00000000,
    },
    PhyRow {
        reg: 0xc2c,
        val: 0x00000000,
    },
    PhyRow {
        reg: 0xc30,
        val: 0x69e9ac47,
    },
    PhyRow {
        reg: 0xc34,
        val: 0x469652af,
    },
    PhyRow {
        reg: 0xc38,
        val: 0x49795994,
    },
    PhyRow {
        reg: 0xc3c,
        val: 0x0a97971c,
    },
    PhyRow {
        reg: 0xc40,
        val: 0x1f7c403f,
    },
    PhyRow {
        reg: 0xc44,
        val: 0x000100b7,
    },
    PhyRow {
        reg: 0xc48,
        val: 0xec020107,
    },
    PhyRow {
        reg: 0xc4c,
        val: 0x007f037f,
    },
    PhyRow {
        reg: 0xc50,
        val: 0x69553420,
    },
    PhyRow {
        reg: 0xc54,
        val: 0x43bc0094,
    },
    PhyRow {
        reg: 0xc58,
        val: 0x00013169,
    },
    PhyRow {
        reg: 0xc5c,
        val: 0x00250492,
    },
    PhyRow {
        reg: 0xc60,
        val: 0x00000000,
    },
    PhyRow {
        reg: 0xc64,
        val: 0x7112848b,
    },
    PhyRow {
        reg: 0xc68,
        val: 0x47c00bff,
    },
    PhyRow {
        reg: 0xc6c,
        val: 0x00000036,
    },
    PhyRow {
        reg: 0xc70,
        val: 0x2c7f000d,
    },
    PhyRow {
        reg: 0xc74,
        val: 0x020610db,
    },
    PhyRow {
        reg: 0xc78,
        val: 0x0000001f,
    },
    PhyRow {
        reg: 0xc7c,
        val: 0x00b91612,
    },
    PhyRow {
        reg: 0xc80,
        val: 0x390000e4,
    },
    PhyRow {
        reg: 0xc84,
        val: 0x21f60000,
    },
    PhyRow {
        reg: 0xc88,
        val: 0x40000100,
    },
    PhyRow {
        reg: 0xc8c,
        val: 0x20200000,
    },
    PhyRow {
        reg: 0xc90,
        val: 0x00091521,
    },
    PhyRow {
        reg: 0xc94,
        val: 0x00000000,
    },
    PhyRow {
        reg: 0xc98,
        val: 0x00121820,
    },
    PhyRow {
        reg: 0xc9c,
        val: 0x00007f7f,
    },
    PhyRow {
        reg: 0xca0,
        val: 0x00000000,
    },
    PhyRow {
        reg: 0xca4,
        val: 0x000300a0,
    },
    PhyRow {
        reg: 0xca8,
        val: 0x00000000,
    },
    PhyRow {
        reg: 0xcac,
        val: 0x00000000,
    },
    PhyRow {
        reg: 0xcb0,
        val: 0x00000000,
    },
    PhyRow {
        reg: 0xcb4,
        val: 0x00000000,
    },
    PhyRow {
        reg: 0xcb8,
        val: 0x00000000,
    },
    PhyRow {
        reg: 0xcbc,
        val: 0x28000000,
    },
    PhyRow {
        reg: 0xcc0,
        val: 0x00000000,
    },
    PhyRow {
        reg: 0xcc4,
        val: 0x00000000,
    },
    PhyRow {
        reg: 0xcc8,
        val: 0x00000000,
    },
    PhyRow {
        reg: 0xccc,
        val: 0x00000000,
    },
    PhyRow {
        reg: 0xcd0,
        val: 0x00000000,
    },
    PhyRow {
        reg: 0xcd4,
        val: 0x00000000,
    },
    PhyRow {
        reg: 0xcd8,
        val: 0x64b22427,
    },
    PhyRow {
        reg: 0xcdc,
        val: 0x00766932,
    },
    PhyRow {
        reg: 0xce0,
        val: 0x00222222,
    },
    PhyRow {
        reg: 0xce4,
        val: 0x00000000,
    },
    PhyRow {
        reg: 0xce8,
        val: 0x37644302,
    },
    PhyRow {
        reg: 0xcec,
        val: 0x2f97d40c,
    },
    PhyRow {
        reg: 0xd00,
        val: 0x00000740,
    },
    PhyRow {
        reg: 0xd04,
        val: 0x00020401,
    },
    PhyRow {
        reg: 0xd08,
        val: 0x0000907f,
    },
    PhyRow {
        reg: 0xd0c,
        val: 0x20010201,
    },
    PhyRow {
        reg: 0xd10,
        val: 0xa0633333,
    },
    PhyRow {
        reg: 0xd14,
        val: 0x3333bc43,
    },
    PhyRow {
        reg: 0xd18,
        val: 0x7a8f5b6f,
    },
    PhyRow {
        reg: 0xd2c,
        val: 0xcc979975,
    },
    PhyRow {
        reg: 0xd30,
        val: 0x00000000,
    },
    PhyRow {
        reg: 0xd34,
        val: 0x80608000,
    },
    PhyRow {
        reg: 0xd38,
        val: 0x00000000,
    },
    PhyRow {
        reg: 0xd3c,
        val: 0x00127353,
    },
    PhyRow {
        reg: 0xd40,
        val: 0x00000000,
    },
    PhyRow {
        reg: 0xd44,
        val: 0x00000000,
    },
    PhyRow {
        reg: 0xd48,
        val: 0x00000000,
    },
    PhyRow {
        reg: 0xd4c,
        val: 0x00000000,
    },
    PhyRow {
        reg: 0xd50,
        val: 0x6437140a,
    },
    PhyRow {
        reg: 0xd54,
        val: 0x00000000,
    },
    PhyRow {
        reg: 0xd58,
        val: 0x00000282,
    },
    PhyRow {
        reg: 0xd5c,
        val: 0x30032064,
    },
    PhyRow {
        reg: 0xd60,
        val: 0x4653de68,
    },
    PhyRow {
        reg: 0xd64,
        val: 0x04518a3c,
    },
    PhyRow {
        reg: 0xd68,
        val: 0x00002101,
    },
    PhyRow {
        reg: 0xd6c,
        val: 0x2a201c16,
    },
    PhyRow {
        reg: 0xd70,
        val: 0x1812362e,
    },
    PhyRow {
        reg: 0xd74,
        val: 0x322c2220,
    },
    PhyRow {
        reg: 0xd78,
        val: 0x000e3c24,
    },
    PhyRow {
        reg: 0xe00,
        val: 0x2d2d2d2d,
    },
    PhyRow {
        reg: 0xe04,
        val: 0x2d2d2d2d,
    },
    PhyRow {
        reg: 0xe08,
        val: 0x0390272d,
    },
    PhyRow {
        reg: 0xe10,
        val: 0x2d2d2d2d,
    },
    PhyRow {
        reg: 0xe14,
        val: 0x2d2d2d2d,
    },
    PhyRow {
        reg: 0xe18,
        val: 0x2d2d2d2d,
    },
    PhyRow {
        reg: 0xe1c,
        val: 0x2d2d2d2d,
    },
    PhyRow {
        reg: 0xe28,
        val: 0x00000000,
    },
    PhyRow {
        reg: 0xe30,
        val: 0x1000dc1f,
    },
    PhyRow {
        reg: 0xe34,
        val: 0x10008c1f,
    },
    PhyRow {
        reg: 0xe38,
        val: 0x02140102,
    },
    PhyRow {
        reg: 0xe3c,
        val: 0x681604c2,
    },
    PhyRow {
        reg: 0xe40,
        val: 0x01007c00,
    },
    PhyRow {
        reg: 0xe44,
        val: 0x01004800,
    },
    PhyRow {
        reg: 0xe48,
        val: 0xfb000000,
    },
    PhyRow {
        reg: 0xe4c,
        val: 0x000028d1,
    },
    PhyRow {
        reg: 0xe50,
        val: 0x1000dc1f,
    },
    PhyRow {
        reg: 0xe54,
        val: 0x10008c1f,
    },
    PhyRow {
        reg: 0xe58,
        val: 0x02140102,
    },
    PhyRow {
        reg: 0xe5c,
        val: 0x28160d05,
    },
    PhyRow {
        reg: 0xe60,
        val: 0x00000048,
    },
    PhyRow {
        reg: 0xe68,
        val: 0x001b25a4,
    },
    PhyRow {
        reg: 0xe6c,
        val: 0x00c00014,
    },
    PhyRow {
        reg: 0xe70,
        val: 0x00c00014,
    },
    PhyRow {
        reg: 0xe74,
        val: 0x01000014,
    },
    PhyRow {
        reg: 0xe78,
        val: 0x01000014,
    },
    PhyRow {
        reg: 0xe7c,
        val: 0x01000014,
    },
    PhyRow {
        reg: 0xe80,
        val: 0x01000014,
    },
    PhyRow {
        reg: 0xe84,
        val: 0x00c00014,
    },
    PhyRow {
        reg: 0xe88,
        val: 0x01000014,
    },
    PhyRow {
        reg: 0xe8c,
        val: 0x00c00014,
    },
    PhyRow {
        reg: 0xed0,
        val: 0x00c00014,
    },
    PhyRow {
        reg: 0xed4,
        val: 0x00c00014,
    },
    PhyRow {
        reg: 0xed8,
        val: 0x00c00014,
    },
    PhyRow {
        reg: 0xedc,
        val: 0x00000014,
    },
    PhyRow {
        reg: 0xee0,
        val: 0x00000014,
    },
    PhyRow {
        reg: 0xee8,
        val: 0x21555448,
    },
    PhyRow {
        reg: 0xeec,
        val: 0x01c00014,
    },
    PhyRow {
        reg: 0xf14,
        val: 0x00000003,
    },
    PhyRow {
        reg: 0xf4c,
        val: 0x00000000,
    },
    PhyRow {
        reg: 0xf00,
        val: 0x00000300,
    },
    PhyRow::SENTINEL,
];

/// 8188EU AGC table — `rtl8188e_agc_table[]` L146..L213 (130 rows + sentinel).
pub const AGC_REGS_8188E: &[PhyRow] = &[
    PhyRow {
        reg: 0xc78,
        val: 0xfb000001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0xfb010001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0xfb020001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0xfb030001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0xfb040001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0xfb050001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0xfa060001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0xf9070001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0xf8080001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0xf7090001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0xf60a0001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0xf50b0001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0xf40c0001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0xf30d0001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0xf20e0001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0xf10f0001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0xf0100001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0xef110001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0xee120001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0xed130001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0xec140001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0xeb150001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0xea160001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0xe9170001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0xe8180001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0xe7190001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0xe61a0001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0xe51b0001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0xe41c0001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0xe31d0001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0xe21e0001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0xe11f0001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0x8a200001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0x89210001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0x88220001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0x87230001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0x86240001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0x85250001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0x84260001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0x83270001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0x82280001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0x6b290001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0x6a2a0001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0x692b0001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0x682c0001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0x672d0001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0x662e0001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0x652f0001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0x64300001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0x63310001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0x62320001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0x61330001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0x46340001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0x45350001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0x44360001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0x43370001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0x42380001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0x41390001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0x403a0001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0x403b0001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0x403c0001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0x403d0001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0x403e0001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0x403f0001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0xfb400001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0xfb410001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0xfb420001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0xfb430001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0xfb440001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0xfb450001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0xfb460001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0xfb470001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0xfb480001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0xfa490001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0xf94a0001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0xf84b0001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0xf74c0001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0xf64d0001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0xf54e0001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0xf44f0001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0xf3500001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0xf2510001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0xf1520001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0xf0530001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0xef540001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0xee550001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0xed560001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0xec570001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0xeb580001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0xea590001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0xe95a0001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0xe85b0001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0xe75c0001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0xe65d0001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0xe55e0001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0xe45f0001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0xe3600001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0xe2610001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0xc3620001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0xc2630001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0xc1640001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0x8b650001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0x8a660001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0x89670001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0x88680001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0x87690001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0x866a0001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0x856b0001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0x846c0001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0x676d0001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0x666e0001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0x656f0001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0x64700001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0x63710001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0x62720001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0x61730001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0x60740001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0x46750001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0x45760001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0x44770001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0x43780001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0x42790001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0x417a0001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0x407b0001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0x407c0001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0x407d0001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0x407e0001,
    },
    PhyRow {
        reg: 0xc78,
        val: 0x407f0001,
    },
    PhyRow {
        reg: 0xc50,
        val: 0x69553422,
    },
    PhyRow {
        reg: 0xc50,
        val: 0x69553420,
    },
    PhyRow::SENTINEL,
];

/// 8188EU RF path-A init table — `rtl8188eu_radioa_init_table[]`
/// L215..L265 (95 rows + sentinel).
pub const RF_A_REGS_8188E: &[RfRow] = &[
    RfRow {
        reg: 0x00,
        val: 0x00030000,
    },
    RfRow {
        reg: 0x08,
        val: 0x00084000,
    },
    RfRow {
        reg: 0x18,
        val: 0x00000407,
    },
    RfRow {
        reg: 0x19,
        val: 0x00000012,
    },
    RfRow {
        reg: 0x1e,
        val: 0x00080009,
    },
    RfRow {
        reg: 0x1f,
        val: 0x00000880,
    },
    RfRow {
        reg: 0x2f,
        val: 0x0001a060,
    },
    RfRow {
        reg: 0x3f,
        val: 0x00000000,
    },
    RfRow {
        reg: 0x42,
        val: 0x000060c0,
    },
    RfRow {
        reg: 0x57,
        val: 0x000d0000,
    },
    RfRow {
        reg: 0x58,
        val: 0x000be180,
    },
    RfRow {
        reg: 0x67,
        val: 0x00001552,
    },
    RfRow {
        reg: 0x83,
        val: 0x00000000,
    },
    RfRow {
        reg: 0xb0,
        val: 0x000ff8fc,
    },
    RfRow {
        reg: 0xb1,
        val: 0x00054400,
    },
    RfRow {
        reg: 0xb2,
        val: 0x000ccc19,
    },
    RfRow {
        reg: 0xb4,
        val: 0x00043003,
    },
    RfRow {
        reg: 0xb6,
        val: 0x0004953e,
    },
    RfRow {
        reg: 0xb7,
        val: 0x0001c718,
    },
    RfRow {
        reg: 0xb8,
        val: 0x000060ff,
    },
    RfRow {
        reg: 0xb9,
        val: 0x00080001,
    },
    RfRow {
        reg: 0xba,
        val: 0x00040000,
    },
    RfRow {
        reg: 0xbb,
        val: 0x00000400,
    },
    RfRow {
        reg: 0xbf,
        val: 0x000c0000,
    },
    RfRow {
        reg: 0xc2,
        val: 0x00002400,
    },
    RfRow {
        reg: 0xc3,
        val: 0x00000009,
    },
    RfRow {
        reg: 0xc4,
        val: 0x00040c91,
    },
    RfRow {
        reg: 0xc5,
        val: 0x00099999,
    },
    RfRow {
        reg: 0xc6,
        val: 0x000000a3,
    },
    RfRow {
        reg: 0xc7,
        val: 0x00088820,
    },
    RfRow {
        reg: 0xc8,
        val: 0x00076c06,
    },
    RfRow {
        reg: 0xc9,
        val: 0x00000000,
    },
    RfRow {
        reg: 0xca,
        val: 0x00080000,
    },
    RfRow {
        reg: 0xdf,
        val: 0x00000180,
    },
    RfRow {
        reg: 0xef,
        val: 0x000001a0,
    },
    RfRow {
        reg: 0x51,
        val: 0x0006b27d,
    },
    RfRow {
        reg: 0x52,
        val: 0x0007e49d,
    },
    RfRow {
        reg: 0x53,
        val: 0x00000073,
    },
    RfRow {
        reg: 0x56,
        val: 0x00051ff3,
    },
    RfRow {
        reg: 0x35,
        val: 0x00000086,
    },
    RfRow {
        reg: 0x35,
        val: 0x00000186,
    },
    RfRow {
        reg: 0x35,
        val: 0x00000286,
    },
    RfRow {
        reg: 0x36,
        val: 0x00001c25,
    },
    RfRow {
        reg: 0x36,
        val: 0x00009c25,
    },
    RfRow {
        reg: 0x36,
        val: 0x00011c25,
    },
    RfRow {
        reg: 0x36,
        val: 0x00019c25,
    },
    RfRow {
        reg: 0xb6,
        val: 0x00048538,
    },
    RfRow {
        reg: 0x18,
        val: 0x00000c07,
    },
    RfRow {
        reg: 0x5a,
        val: 0x0004bd00,
    },
    RfRow {
        reg: 0x19,
        val: 0x000739d0,
    },
    RfRow {
        reg: 0x34,
        val: 0x0000adf3,
    },
    RfRow {
        reg: 0x34,
        val: 0x00009df0,
    },
    RfRow {
        reg: 0x34,
        val: 0x00008ded,
    },
    RfRow {
        reg: 0x34,
        val: 0x00007dea,
    },
    RfRow {
        reg: 0x34,
        val: 0x00006de7,
    },
    RfRow {
        reg: 0x34,
        val: 0x000054ee,
    },
    RfRow {
        reg: 0x34,
        val: 0x000044eb,
    },
    RfRow {
        reg: 0x34,
        val: 0x000034e8,
    },
    RfRow {
        reg: 0x34,
        val: 0x0000246b,
    },
    RfRow {
        reg: 0x34,
        val: 0x00001468,
    },
    RfRow {
        reg: 0x34,
        val: 0x0000006d,
    },
    RfRow {
        reg: 0x00,
        val: 0x00030159,
    },
    RfRow {
        reg: 0x84,
        val: 0x00068200,
    },
    RfRow {
        reg: 0x86,
        val: 0x000000ce,
    },
    RfRow {
        reg: 0x87,
        val: 0x00048a00,
    },
    RfRow {
        reg: 0x8e,
        val: 0x00065540,
    },
    RfRow {
        reg: 0x8f,
        val: 0x00088000,
    },
    RfRow {
        reg: 0xef,
        val: 0x000020a0,
    },
    RfRow {
        reg: 0x3b,
        val: 0x000f02b0,
    },
    RfRow {
        reg: 0x3b,
        val: 0x000ef7b0,
    },
    RfRow {
        reg: 0x3b,
        val: 0x000d4fb0,
    },
    RfRow {
        reg: 0x3b,
        val: 0x000cf060,
    },
    RfRow {
        reg: 0x3b,
        val: 0x000b0090,
    },
    RfRow {
        reg: 0x3b,
        val: 0x000a0080,
    },
    RfRow {
        reg: 0x3b,
        val: 0x00090080,
    },
    RfRow {
        reg: 0x3b,
        val: 0x0008f780,
    },
    RfRow {
        reg: 0x3b,
        val: 0x000722b0,
    },
    RfRow {
        reg: 0x3b,
        val: 0x0006f7b0,
    },
    RfRow {
        reg: 0x3b,
        val: 0x00054fb0,
    },
    RfRow {
        reg: 0x3b,
        val: 0x0004f060,
    },
    RfRow {
        reg: 0x3b,
        val: 0x00030090,
    },
    RfRow {
        reg: 0x3b,
        val: 0x00020080,
    },
    RfRow {
        reg: 0x3b,
        val: 0x00010080,
    },
    RfRow {
        reg: 0x3b,
        val: 0x0000f780,
    },
    RfRow {
        reg: 0xef,
        val: 0x000000a0,
    },
    RfRow {
        reg: 0x00,
        val: 0x00010159,
    },
    RfRow {
        reg: 0x18,
        val: 0x0000f407,
    },
    RfRow {
        reg: 0xFE,
        val: 0x00000000,
    },
    RfRow {
        reg: 0xFE,
        val: 0x00000000,
    },
    RfRow {
        reg: 0x1F,
        val: 0x00080003,
    },
    RfRow {
        reg: 0xFE,
        val: 0x00000000,
    },
    RfRow {
        reg: 0xFE,
        val: 0x00000000,
    },
    RfRow {
        reg: 0x1E,
        val: 0x00000001,
    },
    RfRow {
        reg: 0x1F,
        val: 0x00080000,
    },
    RfRow {
        reg: 0x00,
        val: 0x00033e60,
    },
    RfRow::SENTINEL,
];
