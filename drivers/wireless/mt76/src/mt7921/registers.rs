//! Checked CONNAC2/CONNAC3 PCI register accesses.
//!
//! Fixed windows and L1 programming follow Linux mt76 at ecd997b0189a:
//! mt7921/pci.c::__mt7921_reg_addr and mt7921/mt7921.h::mt7921_reg_map_l1.
//! The MT7925 (CONNAC3) fixed windows follow upstream
//! `default_fixed_map` in mt7925/pci.c::__mt7925_reg_addr at
//! torvalds/linux 8d7fe9885c62 (pci.c:178-232). The sibling
//! `mt7928_fixed_map` (pci.c:235-315, selected by `is_mt7928()`) is a
//! different chip's map and is NOT used here. `plan()` selects the
//! table by device id: MT7925 ids (0x7925, 0x0717) use the CONNAC3
//! table, everything else keeps the CONNAC2 table.
//! L1 transactions preserve the unrelated selector bits, flush the posted
//! selector write before accessing the window, and restore the prior selector.
use super::regs::*;
use narf_bus::MmioRegion;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    Alignment,
    Unsupported,
    Bounds,
    DeviceGone,
    RemapRejected,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Plan {
    pub offset: u32,
    pub page: Option<u16>,
}

// (chip address, BAR0 offset, length); end-exclusive, including all four
// bytes of a register. Never fall through from a fixed window's tail to L1.
const FIXED: &[(u32, u32, u32)] = &[
    (0x820d0000, 0x30000, 0x10000),
    (0x820ed000, 0x24800, 0x00800),
    (0x820e4000, 0x21000, 0x00400),
    (0x820e7000, 0x21e00, 0x00200),
    (0x820eb000, 0x24200, 0x00400),
    (0x820e2000, 0x20800, 0x00400),
    (0x820e3000, 0x20c00, 0x00400),
    (0x820e5000, 0x21400, 0x00800),
    (0x00400000, 0x80000, 0x10000),
    (0x00410000, 0x90000, 0x10000),
    (0x40000000, 0x70000, 0x10000),
    (0x54000000, 0x02000, 0x01000),
    (0x55000000, 0x03000, 0x01000),
    (0x58000000, 0x06000, 0x01000),
    (0x59000000, 0x07000, 0x01000),
    (0x7c000000, 0xf0000, 0x10000),
    (0x7c020000, 0xd0000, 0x10000),
    (0x7c060000, 0xe0000, 0x10000),
    (0x80020000, 0xb0000, 0x10000),
    (0x81020000, 0xc0000, 0x10000),
    (0x820c0000, 0x08000, 0x04000),
    (0x820c8000, 0x0c000, 0x02000),
    (0x820cc000, 0x0e000, 0x01000),
    (0x820cd000, 0x0f000, 0x01000),
    (0x74030000, 0x10000, 0x10000),
    (0x820ce000, 0x21c00, 0x00200),
    (0x820cf000, 0x22000, 0x01000),
    (0x820e0000, 0x20000, 0x00400),
    (0x820e1000, 0x20400, 0x00200),
    (0x820e9000, 0x23400, 0x00200),
    (0x820ea000, 0x24000, 0x00200),
    (0x820ec000, 0x24600, 0x00200),
    (0x820f0000, 0xa0000, 0x00400),
    (0x820f1000, 0xa0600, 0x00200),
    (0x820f2000, 0xa0800, 0x00400),
    (0x820f3000, 0xa0c00, 0x00400),
    (0x820f4000, 0xa1000, 0x00400),
    (0x820f5000, 0xa1400, 0x00800),
    (0x820f7000, 0xa1e00, 0x00200),
    (0x820f9000, 0xa3400, 0x00200),
    (0x820fa000, 0xa4000, 0x00200),
    (0x820fb000, 0xa4200, 0x00400),
    (0x820fc000, 0xa4600, 0x00200),
    (0x820fd000, 0xa4800, 0x00800),
];

// MT7925 (CONNAC3) fixed windows, in upstream order: Linux
// `default_fixed_map` in mt7925/pci.c::__mt7925_reg_addr at
// torvalds/linux 8d7fe9885c62 (pci.c:178-232). The sibling
// `mt7928_fixed_map` (pci.c:235-315) is a different chip's map and is
// NOT in this table. Deltas vs the CONNAC2 table above: new windows
// 0x830c0000, 0x56000000, 0x57000000, 0x820ca000, 0x820c4000,
// 0x820b0000, 0x70020000, 0x7c500000; PP (0x820cc000) length 0x1000
// -> 0x2000; PCIe MAC (0x74030000) length 0x10000 -> 0x1000; the
// CONNAC2 window 0x820cd000 has no MT7925 counterpart (dropped).
// The 0x7c500000 remap window is 0x200000 bytes (2 MiB).
// Visible to the sibling golden test (`registers_tests`).
pub(super) const FIXED_MT7925: &[(u32, u32, u32)] = &[
    (0x830c0000, 0x000000, 0x0001000), // WF_MCU_BUS_CR_REMAP
    (0x54000000, 0x002000, 0x0001000), // WFDMA PCIE0 MCU DMA0
    (0x55000000, 0x003000, 0x0001000), // WFDMA PCIE0 MCU DMA1
    (0x56000000, 0x004000, 0x0001000), // WFDMA reserved
    (0x57000000, 0x005000, 0x0001000), // WFDMA MCU wrap CR
    (0x58000000, 0x006000, 0x0001000), // WFDMA PCIE1 MCU DMA0 (MEM_DMA)
    (0x59000000, 0x007000, 0x0001000), // WFDMA PCIE1 MCU DMA1
    (0x820c0000, 0x008000, 0x0004000), // WF_UMAC_TOP (PLE)
    (0x820c8000, 0x00c000, 0x0002000), // WF_UMAC_TOP (PSE)
    (0x820cc000, 0x00e000, 0x0002000), // WF_UMAC_TOP (PP)
    (0x74030000, 0x010000, 0x0001000), // PCIe MAC
    (0x820e0000, 0x020000, 0x0000400), // WF_LMAC_TOP BN0 (WF_CFG)
    (0x820e1000, 0x020400, 0x0000200), // WF_LMAC_TOP BN0 (WF_TRB)
    (0x820e2000, 0x020800, 0x0000400), // WF_LMAC_TOP BN0 (WF_AGG)
    (0x820e3000, 0x020c00, 0x0000400), // WF_LMAC_TOP BN0 (WF_ARB)
    (0x820e4000, 0x021000, 0x0000400), // WF_LMAC_TOP BN0 (WF_TMAC)
    (0x820e5000, 0x021400, 0x0000800), // WF_LMAC_TOP BN0 (WF_RMAC)
    (0x820ce000, 0x021c00, 0x0000200), // WF_LMAC_TOP (WF_SEC)
    (0x820e7000, 0x021e00, 0x0000200), // WF_LMAC_TOP BN0 (WF_DMA)
    (0x820cf000, 0x022000, 0x0001000), // WF_LMAC_TOP (WF_PF)
    (0x820e9000, 0x023400, 0x0000200), // WF_LMAC_TOP BN0 (WF_WTBLOFF)
    (0x820ea000, 0x024000, 0x0000200), // WF_LMAC_TOP BN0 (WF_ETBF)
    (0x820eb000, 0x024200, 0x0000400), // WF_LMAC_TOP BN0 (WF_LPON)
    (0x820ec000, 0x024600, 0x0000200), // WF_LMAC_TOP BN0 (WF_INT)
    (0x820ed000, 0x024800, 0x0000800), // WF_LMAC_TOP BN0 (WF_MIB)
    (0x820ca000, 0x026000, 0x0002000), // WF_LMAC_TOP BN0 (WF_MUCOP)
    (0x820d0000, 0x030000, 0x0010000), // WF_LMAC_TOP (WF_WTBLON)
    (0x40000000, 0x070000, 0x0010000), // WF_UMAC_SYSRAM
    (0x00400000, 0x080000, 0x0010000), // WF_MCU_SYSRAM
    (0x00410000, 0x090000, 0x0010000), // WF_MCU_SYSRAM (configure register)
    (0x820f0000, 0x0a0000, 0x0000400), // WF_LMAC_TOP BN1 (WF_CFG)
    (0x820f1000, 0x0a0600, 0x0000200), // WF_LMAC_TOP BN1 (WF_TRB)
    (0x820f2000, 0x0a0800, 0x0000400), // WF_LMAC_TOP BN1 (WF_AGG)
    (0x820f3000, 0x0a0c00, 0x0000400), // WF_LMAC_TOP BN1 (WF_ARB)
    (0x820f4000, 0x0a1000, 0x0000400), // WF_LMAC_TOP BN1 (WF_TMAC)
    (0x820f5000, 0x0a1400, 0x0000800), // WF_LMAC_TOP BN1 (WF_RMAC)
    (0x820f7000, 0x0a1e00, 0x0000200), // WF_LMAC_TOP BN1 (WF_DMA)
    (0x820f9000, 0x0a3400, 0x0000200), // WF_LMAC_TOP BN1 (WF_WTBLOFF)
    (0x820fa000, 0x0a4000, 0x0000200), // WF_LMAC_TOP BN1 (WF_ETBF)
    (0x820fb000, 0x0a4200, 0x0000400), // WF_LMAC_TOP BN1 (WF_LPON)
    (0x820fc000, 0x0a4600, 0x0000200), // WF_LMAC_TOP BN1 (WF_INT)
    (0x820fd000, 0x0a4800, 0x0000800), // WF_LMAC_TOP BN1 (WF_MIB)
    (0x820c4000, 0x0a8000, 0x0004000), // WF_LMAC_TOP BN1 (WF_MUCOP)
    (0x820b0000, 0x0ae000, 0x0001000), // [APB2] WFSYS_ON
    (0x80020000, 0x0b0000, 0x0010000), // WF_TOP_MISC_OFF
    (0x81020000, 0x0c0000, 0x0010000), // WF_TOP_MISC_ON
    (0x7c020000, 0x0d0000, 0x0010000), // CONN_INFRA, wfdma
    (0x7c060000, 0x0e0000, 0x0010000), // CONN_INFRA, conn_host_csr_top
    (0x7c000000, 0x0f0000, 0x0010000), // CONN_INFRA
    (0x70020000, 0x1f0000, 0x0010000), // Reserved for CBTOP, can't switch
    (0x7c500000, 0x060000, 0x200000),  // remap (2 MiB, not 0x2000000)
];

/// `true` if `did` selects the MT7925 (CONNAC3) fixed windows: the
/// 0x7925 PCI id and its 0x0717 alias, per upstream
/// `mt7925_pci_device_table`.
pub(super) const fn is_mt7925(did: u16) -> bool {
    matches!(did, MTK_DEV_MT7925 | MTK_DEV_MT7925_ALT)
}

/// Map a chip address to a BAR0 offset for `did`.
///
/// `did` is the PCI device id at probe time (before the chip-id gate
/// runs there is no effective id yet) and the effective device id
/// (`Mt7921Device::effective_did`) afterwards. The two agree on the
/// table for every registered id: the 7961→7920 re-tag stays inside
/// CONNAC2, and both MT7925 ids select the CONNAC3 table whatever
/// `MT_HW_CHIPID` reads (Q1, #2494).
pub(super) fn plan(did: u16, addr: u32, len: u64) -> Result<Plan, Error> {
    if addr & 3 != 0 {
        return Err(Error::Alignment);
    }
    let mut mapped = None;
    if addr < 0x100000 {
        mapped = Some(Plan {
            offset: addr,
            page: None,
        });
    } else {
        // Per-chip fixed windows: MT7925 (CONNAC3) uses its own table;
        // every other registered id keeps the CONNAC2 table. Unknown ids
        // fall back to CONNAC2, matching `firmware_blobs_for`'s default arm.
        let fixed = if is_mt7925(did) { FIXED_MT7925 } else { FIXED };
        // A fixed window owns its tail word (`delta == size`): upstream
        // treats it as a fixed-map hit (`ofs > size` skips, so `ofs ==
        // size` matches in `__mt7925_reg_addr`), never as an L1
        // address. NARF maps windows end-exclusively, so the tail word
        // is rejected instead of mapped one word past the window — and
        // it must not fall through to L1, whose ranges overlap the
        // fixed windows (0x74030000 sits inside 0x70000000..0x78000000).
        let mut tail = false;
        for &(base, offset, size) in fixed {
            if let Some(delta) = addr.checked_sub(base) {
                if delta < size {
                    mapped = Some(Plan {
                        offset: offset + delta,
                        page: None,
                    });
                    break;
                }
                if delta == size {
                    tail = true;
                }
            }
        }
        if mapped.is_none() && tail {
            return Err(Error::Unsupported);
        }
    }
    let mapped = mapped
        .or_else(|| {
            if (0x18000000..0x18c00000).contains(&addr)
                || (0x70000000..0x78000000).contains(&addr)
                || (0x7c000000..0x7c400000).contains(&addr)
            {
                Some(Plan {
                    offset: MT_HIF_REMAP_BASE_L1 + (addr & 0xffff),
                    page: Some((addr >> 16) as u16),
                })
            } else {
                None
            }
        })
        .ok_or(Error::Unsupported)?;
    if u64::from(mapped.offset) + 4 > len
        || (mapped.page.is_some() && u64::from(MT_HIF_REMAP_L1) + 4 > len)
    {
        return Err(Error::Bounds);
    }
    Ok(mapped)
}

/// Implementations perform only accesses validated against len().
pub(super) trait Io {
    fn len(&self) -> u64;
    fn read(&mut self, offset: u32) -> u32;
    fn write(&mut self, offset: u32, value: u32);
}
struct Hardware<'a>(&'a MmioRegion);
impl Io for Hardware<'_> {
    fn len(&self) -> u64 {
        self.0.len
    }
    fn read(&mut self, offset: u32) -> u32 {
        // SAFETY: transaction validated the complete word before any I/O.
        unsafe { self.0.read32(u64::from(offset)) }
    }
    fn write(&mut self, offset: u32, value: u32) {
        // SAFETY: transaction validated the complete word before any I/O.
        unsafe { self.0.write32(u64::from(offset), value) }
    }
}

pub(super) fn transaction<I: Io>(
    did: u16,
    io: &mut I,
    addr: u32,
    write: Option<u32>,
) -> Result<u32, Error> {
    let mapped = plan(did, addr, io.len())?;
    let saved = if let Some(page) = mapped.page {
        let saved = io.read(MT_HIF_REMAP_L1);
        if saved == u32::MAX {
            return Err(Error::DeviceGone);
        }
        // FIELD_PREP(GENMASK(15, 0), addr >> 16), not addr & 0xffff0000.
        io.write(
            MT_HIF_REMAP_L1,
            (saved & !MT_HIF_REMAP_L1_MASK) | u32::from(page),
        );
        let selected = io.read(MT_HIF_REMAP_L1); // push the posted selector write
        if selected == u32::MAX {
            return Err(Error::DeviceGone);
        }
        if selected & MT_HIF_REMAP_L1_MASK != u32::from(page) {
            io.write(MT_HIF_REMAP_L1, saved);
            let _ = io.read(MT_HIF_REMAP_L1);
            return Err(Error::RemapRejected);
        }
        Some(saved)
    } else {
        None
    };
    let result = if let Some(value) = write {
        io.write(mapped.offset, value);
        // Complete the window write before changing its address selection.
        if saved.is_some() {
            let _ = io.read(MT_HIF_REMAP_L1);
        }
        value
    } else {
        io.read(mapped.offset)
    };
    if let Some(saved) = saved {
        io.write(MT_HIF_REMAP_L1, saved);
        let _ = io.read(MT_HIF_REMAP_L1);
    }
    Ok(result)
}

/// # Safety
/// Caller exclusively owns BAR0 and its L1 latch for the entire transaction.
pub(super) unsafe fn read32(did: u16, mmio: &MmioRegion, addr: u32) -> Result<u32, Error> {
    transaction(did, &mut Hardware(mmio), addr, None)
}
/// # Safety
/// Caller exclusively owns BAR0/latch; device tolerates this register write.
pub(super) unsafe fn write32(
    did: u16,
    mmio: &MmioRegion,
    addr: u32,
    value: u32,
) -> Result<(), Error> {
    transaction(did, &mut Hardware(mmio), addr, Some(value)).map(|_| ())
}
