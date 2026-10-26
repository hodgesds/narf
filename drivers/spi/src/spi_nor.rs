//! SPI-NOR flash client (DT programme step 6) — binds
//! `jedec,spi-nor` child devices of DT-bound SPI controllers as
//! MTD devices in the storage MTD core registry.
//!
//! Protocol: the standard SPI-NOR command set — RDID (0x9F)
//! identification against a small JEDEC table, status polling
//! (0x05, WIP), write-enable (0x06), read (0x03), page program
//! (0x02, 256-byte pages, AND semantics), 64 KiB block erase
//! (0xD8). Parts outside the table are not bound: an unknown
//! JEDEC ID means the geometry would be a guess, and guessing
//! at flash geometry destroys data. SFDP parsing is the named
//! follow-on that generalises the table.
//!
//! The MTD device's partitions: v1 registers the device whole.
//! The NOR node's `fixed-partitions` grandchildren are reachable
//! through the recursive `narf_bus::dt::DtChild` decode (step
//! 5a) — partition attachment for SPI-NOR is a follow-on that
//! mirrors the CFI probe's rebase logic.

use alloc::string::String;
use alloc::sync::Arc;

use narf_drivers_storage_mtd::{MtdDevice, MtdError};
use narf_lib::sync::IrqSafeSpinLock;

use crate::dt::SpiChild;
use crate::{SpiBus, SpiError};

const OP_WREN: u8 = 0x06;
const OP_RDSR: u8 = 0x05;
const OP_READ: u8 = 0x03;
const OP_PP: u8 = 0x02;
const OP_SE_64K: u8 = 0xD8;
const OP_RDID: u8 = 0x9F;

const SR_WIP: u8 = 0x01;

const PAGE_SIZE: u64 = 256;
const ERASE_SIZE: u32 = 0x1_0000;
const POLL_BUDGET: u32 = 1_000_000;
const READ_CHUNK: usize = 4096;

struct JedecInfo {
    name: &'static str,
    size: u64,
}

/// Known JEDEC IDs: [manufacturer, memory type, capacity].
/// Every part here has uniform 64 KiB blocks and 256-byte pages.
fn jedec_lookup(id: [u8; 3]) -> Option<JedecInfo> {
    let info = match id {
        [0xEF, 0x40, 0x15] => JedecInfo {
            name: "Winbond W25Q16",
            size: 2 << 20,
        },
        [0xEF, 0x40, 0x16] => JedecInfo {
            name: "Winbond W25Q32",
            size: 4 << 20,
        },
        [0xEF, 0x40, 0x17] => JedecInfo {
            name: "Winbond W25Q64",
            size: 8 << 20,
        },
        [0xEF, 0x40, 0x18] => JedecInfo {
            name: "Winbond W25Q128",
            size: 16 << 20,
        },
        [0xC2, 0x20, 0x18] => JedecInfo {
            name: "Macronix MX25L128",
            size: 16 << 20,
        },
        [0x20, 0xBA, 0x18] => JedecInfo {
            name: "Micron N25Q128",
            size: 16 << 20,
        },
        _ => return None,
    };
    Some(info)
}

/// One bound SPI-NOR device.
pub struct SpiNor {
    name: String,
    part: &'static str,
    bus: Arc<dyn SpiBus>,
    cs: u8,
    size: u64,
    lock: IrqSafeSpinLock<()>,
}

impl core::fmt::Debug for SpiNor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SpiNor")
            .field("name", &self.name)
            .field("part", &self.part)
            .finish_non_exhaustive()
    }
}

fn spi_err(_: SpiError) -> MtdError {
    MtdError::ProgramFailed
}

impl SpiNor {
    fn select(&self) -> Result<(), MtdError> {
        self.bus.set_cs(self.cs).map_err(spi_err)
    }

    fn cmd(&self, bytes: &[u8]) -> Result<(), MtdError> {
        self.select()?;
        let mut sink: [u8; 0] = [];
        self.bus.transfer(bytes, &mut sink).map_err(spi_err)
    }

    fn status(&self) -> Result<u8, MtdError> {
        self.select()?;
        let mut rx = [0u8; 2];
        self.bus.transfer(&[OP_RDSR, 0], &mut rx).map_err(spi_err)?;
        Ok(rx[1])
    }

    fn write_enable(&self) -> Result<(), MtdError> {
        self.cmd(&[OP_WREN])
    }

    fn wait_ready(&self) -> Result<(), MtdError> {
        for _ in 0..POLL_BUDGET {
            if self.status()? & SR_WIP == 0 {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(MtdError::ProgramFailed)
    }

    fn bounds(&self, off: u64, len: u64) -> Result<(), MtdError> {
        if off > self.size || len > self.size - off {
            return Err(MtdError::OutOfBounds);
        }
        Ok(())
    }
}

impl MtdDevice for SpiNor {
    fn name(&self) -> &str {
        &self.name
    }

    fn size(&self) -> u64 {
        self.size
    }

    fn erase_size(&self) -> u32 {
        ERASE_SIZE
    }

    fn write_size(&self) -> u32 {
        PAGE_SIZE as u32
    }

    fn read(&self, off: u64, buf: &mut [u8]) -> Result<(), MtdError> {
        self.bounds(off, buf.len() as u64)?;
        let _guard = self.lock.lock();
        let mut done = 0usize;
        while done < buf.len() {
            let addr = off + done as u64;
            let n = READ_CHUNK.min(buf.len() - done);
            let mut rx = alloc::vec![0u8; 4 + n];
            // transfer clocks max(tx, rx); the tail beyond the
            // 4 command bytes is the read data.
            let mut full_tx = alloc::vec![0u8; 4 + n];
            full_tx[0] = OP_READ;
            full_tx[1] = (addr >> 16) as u8;
            full_tx[2] = (addr >> 8) as u8;
            full_tx[3] = addr as u8;
            self.select()?;
            self.bus.transfer(&full_tx, &mut rx).map_err(spi_err)?;
            buf[done..done + n].copy_from_slice(&rx[4..]);
            done += n;
        }
        Ok(())
    }

    fn write(&self, off: u64, buf: &[u8]) -> Result<(), MtdError> {
        self.bounds(off, buf.len() as u64)?;
        let _guard = self.lock.lock();
        let mut done = 0usize;
        while done < buf.len() {
            let addr = off + done as u64;
            // Page program must not cross a 256-byte page.
            let page_room = (PAGE_SIZE - (addr % PAGE_SIZE)) as usize;
            let n = page_room.min(buf.len() - done);
            self.write_enable()?;
            let mut tx = alloc::vec![0u8; 4 + n];
            tx[0] = OP_PP;
            tx[1] = (addr >> 16) as u8;
            tx[2] = (addr >> 8) as u8;
            tx[3] = addr as u8;
            tx[4..].copy_from_slice(&buf[done..done + n]);
            self.select()?;
            let mut sink: [u8; 0] = [];
            self.bus.transfer(&tx, &mut sink).map_err(spi_err)?;
            self.wait_ready()?;
            done += n;
        }
        Ok(())
    }

    fn erase(&self, off: u64, len: u64) -> Result<(), MtdError> {
        let es = ERASE_SIZE as u64;
        if off % es != 0 || len % es != 0 {
            return Err(MtdError::BadGeometry);
        }
        self.bounds(off, len)?;
        let _guard = self.lock.lock();
        let mut addr = off;
        while addr < off + len {
            self.write_enable()?;
            self.cmd(&[OP_SE_64K, (addr >> 16) as u8, (addr >> 8) as u8, addr as u8])?;
            self.wait_ready().map_err(|_| MtdError::EraseFailed)?;
            addr += es;
        }
        Ok(())
    }
}

/// Try to bind one published SPI child as an MTD SPI-NOR device:
/// the compatible must name `jedec,spi-nor`, the RDID must
/// answer, and the JEDEC ID must be in the known table. On
/// success the device is registered in the MTD core registry
/// and returned.
pub fn try_bind(bus: &Arc<dyn SpiBus>, child: &SpiChild) -> Option<Arc<dyn MtdDevice>> {
    if !narf_firmware_fdt::compatible_matches(&child.compatible, "jedec,spi-nor") {
        return None;
    }
    let cs = u8::try_from(child.cs).ok()?;
    if child.max_hz > 0 {
        // Best effort: a controller that cannot reach the
        // child's rated maximum still clocks it slower.
        let _ = bus.set_freq(child.max_hz);
    }
    // RDID: command byte + 3 ID bytes clocked out.
    bus.set_cs(cs).ok()?;
    let mut rx = [0u8; 4];
    let mut tx = [0u8; 4];
    tx[0] = OP_RDID;
    bus.transfer(&tx, &mut rx).ok()?;
    let id = [rx[1], rx[2], rx[3]];
    if id == [0xFF, 0xFF, 0xFF] || id == [0x00, 0x00, 0x00] {
        return None; // nothing answering on this chip-select
    }
    let info = jedec_lookup(id)?;
    let dev = SpiNor {
        name: alloc::format!("spi-nor@{}.{}", bus.name(), child.cs),
        part: info.name,
        bus: bus.clone(),
        cs,
        size: info.size,
        lock: IrqSafeSpinLock::new(()),
    };
    let arc: Arc<dyn MtdDevice> = Arc::new(dev);
    narf_drivers_storage_mtd::registry::register_unique(arc.clone());
    Some(arc)
}
