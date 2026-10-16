//! Checked CONNAC2 PCI register accesses.
//!
//! Fixed windows and L1 programming follow Linux mt76 at ecd997b0189a:
//! mt7921/pci.c::__mt7921_reg_addr and mt7921/mt7921.h::mt7921_reg_map_l1.
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

pub(super) fn plan(addr: u32, len: u64) -> Result<Plan, Error> {
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
        for &(base, offset, size) in FIXED {
            if let Some(delta) = addr.checked_sub(base) {
                if delta < size {
                    mapped = Some(Plan {
                        offset: offset + delta,
                        page: None,
                    });
                    break;
                }
            }
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

pub(super) fn transaction<I: Io>(io: &mut I, addr: u32, write: Option<u32>) -> Result<u32, Error> {
    let mapped = plan(addr, io.len())?;
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
pub(super) unsafe fn read32(mmio: &MmioRegion, addr: u32) -> Result<u32, Error> {
    transaction(&mut Hardware(mmio), addr, None)
}
/// # Safety
/// Caller exclusively owns BAR0/latch; device tolerates this register write.
pub(super) unsafe fn write32(mmio: &MmioRegion, addr: u32, value: u32) -> Result<(), Error> {
    transaction(&mut Hardware(mmio), addr, Some(value)).map(|_| ())
}
