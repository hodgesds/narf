// SPDX-License-Identifier: GPL-2.0-or-later
//! Exact RTL8188EE linked PCI descriptor/FIFO prerequisite. Linux hw.c/trx.h.
//! Ordinary DMA/MAC remain closed; this is below RF and station admission.
use super::firmware_transport::{Error as AccessError, Io};
use alloc::vec::Vec;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Geometry,
    Address,
    Memory,
    Access(AccessError),
    State,
    LltTimeout,
    Readback,
    Radio(super::radio::Error),
}
impl From<AccessError> for Error {
    fn from(error: AccessError) -> Self {
        Self::Access(error)
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Allocated,
    Prepared,
    RadioConfigured,
    Failed,
}
/// # Safety
/// The reported DMA extent is exclusively backed by this allocation, valid
/// for the retained device, and sync publishes all prior stores with device
/// ordering. Drop releases it only when the outer owner permits reclamation.
pub unsafe trait Memory: Send {
    fn address(&self) -> u64;
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    fn write32(&mut self, offset: usize, value: u32) -> Result<(), Error>;
    fn sync(&self);
}
const TX_BYTES: usize = 64;
const RX_BYTES: usize = 32;
const RX_BUFFER: usize = 4096;
// Descriptor-base registers follow mac.rs's named register map
// (source: rtl8192ee/reg.h:143..165): TX queues BCNQ..BKQ occupy
// 0x308..0x330, RX sits at 0x338 (REG_RX_DESA), and the high-priority
// TX queue is at 0x340 (REG_HQ0_DESA) — after RX, not in sequence.
// The bases are taken from mac.rs so this publication path and the
// dma.rs programming path can never diverge. Every queue gets a
// distinct, valid linked ring, including presently idle queues.
const TX_BASES: [u16; 7] = [
    super::mac::REG_BCNQ_DESA as u16,
    super::mac::REG_MGQ_DESA as u16,
    super::mac::REG_VOQ_DESA as u16,
    super::mac::REG_VIQ_DESA as u16,
    super::mac::REG_BEQ_DESA as u16,
    super::mac::REG_BKQ_DESA as u16,
    super::mac::REG_HQ0_DESA as u16,
];
const RX_BASE: u16 = super::mac::REG_RX_DESA as u16;
fn extent(memory: &impl Memory, needed: usize, alignment: u64) -> Result<u32, Error> {
    let base = memory.address();
    if needed == 0
        || memory.len() < needed
        || base & (alignment - 1) != 0
        || base
            .checked_add(needed as u64 - 1)
            .is_none_or(|end| end > u64::from(u32::MAX))
    {
        return Err(Error::Address);
    }
    Ok(base as u32)
}
pub struct Prepared<I: Io, M: Memory> {
    io: I,
    tx: Vec<M>,
    receive: Option<M>,
    buffers: Vec<M>,
    depth: usize,
    phase: Phase,
    published: bool,
    radio: Option<super::radio::Report>,
}
impl<I: Io, M: Memory> core::fmt::Debug for Prepared<I, M> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rtl8188eePrepared")
            .field("phase", &self.phase)
            .field("depth", &self.depth)
            .finish_non_exhaustive()
    }
}
impl<I: Io, M: Memory> Prepared<I, M> {
    /// Allocation/validation and descriptor construction precede every BAR
    /// side effect. The caller retains exclusive PCI authority with BME off.
    pub fn allocate(
        io: I,
        depth: usize,
        mut allocate: impl FnMut(usize) -> Result<M, Error>,
    ) -> Result<Self, Error> {
        if !(4..=256).contains(&depth) || !depth.is_power_of_two() {
            return Err(Error::Geometry);
        }
        let mut tx = Vec::new();
        tx.try_reserve_exact(7).map_err(|_| Error::Memory)?;
        let mut ranges = Vec::new();
        ranges
            .try_reserve_exact(depth + 8)
            .map_err(|_| Error::Memory)?;
        let mut reserve = |needed, alignment| -> Result<M, Error> {
            let block = allocate(needed)?;
            let address = extent(&block, needed, alignment)?;
            let end = u64::from(address) + needed as u64;
            if ranges
                .iter()
                .any(|&(a, b)| u64::from(address) < b && a < end)
            {
                return Err(Error::Address);
            }
            ranges.push((u64::from(address), end));
            Ok(block)
        };
        for _ in TX_BASES {
            let mut ring = reserve(depth * TX_BYTES, 256)?;
            let base = extent(&ring, depth * TX_BYTES, 256)?;
            for slot in 0..depth {
                for word in 0..TX_BYTES / 4 {
                    ring.write32(slot * TX_BYTES + word * 4, 0)?;
                }
                // Linux txdesc.next_desc_address at DW10; never alias queues
                // or use another family's TXBD count-register convention.
                let next = base + (((slot + 1) % depth) * TX_BYTES) as u32;
                ring.write32(slot * TX_BYTES + 40, next)?;
            }
            ring.sync();
            tx.push(ring);
        }
        let mut receive = reserve(depth * RX_BYTES, 256)?;
        let mut buffers = Vec::new();
        buffers
            .try_reserve_exact(depth)
            .map_err(|_| Error::Memory)?;
        for slot in 0..depth {
            let buffer = reserve(RX_BUFFER, 4)?;
            for word in 0..RX_BYTES / 4 {
                receive.write32(slot * RX_BYTES + word * 4, 0)?;
            }
            receive.write32(slot * RX_BYTES + 24, extent(&buffer, RX_BUFFER, 4)?)?;
            buffer.sync();
            let end = if slot == depth - 1 { 1 << 30 } else { 0 };
            receive.write32(slot * RX_BYTES, RX_BUFFER as u32 | end | (1 << 31))?;
            buffers.push(buffer);
        }
        receive.sync();
        Ok(Self {
            io,
            tx,
            receive: Some(receive),
            buffers,
            depth,
            phase: Phase::Allocated,
            published: false,
            radio: None,
        })
    }
    pub fn phase(&self) -> Phase {
        self.phase
    }
    pub fn radio_report(&self) -> Option<&super::radio::Report> {
        self.radio.as_ref()
    }

    /// Continue the same retained PacketIo/ring owner through exact EE radio
    /// tables and calibration. Cancellation is terminal before the first wait;
    /// published DMA remains owned even when no report can be committed.
    pub async fn configure_radio(&mut self, profile: super::radio::Profile) -> Result<(), Error> {
        if self.phase != Phase::Prepared {
            return Err(Error::State);
        }
        self.phase = Phase::Failed;
        let report = super::radio::configure(&self.io, profile)
            .await
            .map_err(Error::Radio)?;
        self.radio = Some(report);
        self.phase = Phase::RadioConfigured;
        Ok(())
    }
    /// Prepare internal SRAM and masked, inactive native rings. The native
    /// Io validates current PCI authority/BME at each actual access. No helper
    /// here can enable PCI bus mastering or release host/MAC packet gates.
    pub async fn prepare(&mut self) -> Result<(), Error> {
        if self.phase != Phase::Allocated {
            return Err(Error::State);
        }
        // Install terminal state before the first await. A cancelled LLT
        // command cannot later resume/retry against its uncertain SRAM state.
        self.phase = Phase::Failed;
        let result = self.prepare_inner().await;
        match result {
            Ok(()) => self.phase = Phase::Prepared,
            Err(_) => self.phase = Phase::Failed,
        }
        result
    }
    async fn prepare_inner(&mut self) -> Result<(), Error> {
        // Linux poweroff stops PCIe DMA through this byte. Preparing never
        // reopens it; BME remains off independently in the native adapter.
        self.io.write8(0x301, 0xff)?;
        if self.io.read8(0x301)? != 0xff {
            return Err(Error::Readback);
        }
        let cr = self.io.read8(0x100)?;
        self.io.write8(0x100, cr & !0xcf)?;
        if self.io.read8(0x100)? & 0xcf != 0 {
            return Err(Error::Readback);
        }
        for address in [0xb0, 0xb8] {
            self.io.write32(address, 0)?;
            if self.io.read32(address)? != 0 {
                return Err(Error::Readback);
            }
        }
        self.llt().await?;
        // The owner marks all resources retained before the first potentially
        // visible BAR base write. Even ambiguous publication pins every page.
        self.published = true;
        for (address, ring) in TX_BASES.iter().zip(&self.tx) {
            let base = extent(ring, self.depth * TX_BYTES, 256)?;
            self.io.write32(*address, base)?;
            if self.io.read32(*address)? != base {
                return Err(Error::Readback);
            }
        }
        let base = extent(
            self.receive.as_ref().ok_or(Error::State)?,
            self.depth * RX_BYTES,
            256,
        )?;
        self.io.write32(RX_BASE, base)?;
        if self.io.read32(RX_BASE)? != base {
            return Err(Error::Readback);
        }
        // Ordinary DMA, IRQ and MAC gates remain independently closed.
        if self.io.read8(0x301)? != 0xff || self.io.read8(0x100)? & 0xcf != 0 {
            return Err(Error::Readback);
        }
        Ok(())
    }
    async fn llt(&self) -> Result<(), Error> {
        // Exact _rtl88ee_llt_table_init: TX0..170 ends atff; 171..175
        // forms the reserved ring. This is 0xab/0xaf, not 0xe0/0xff.
        self.io.write8(0x214, 1)?;
        self.io.write32(0x200, 0x80730d29)?;
        self.io.write32(0x114, 0x25ff00ab)?;
        for address in [0x209, 0x424, 0x425, 0x45d] {
            self.io.write8(address, 0xab)?;
        }
        self.io.write8(0x104, 0x11)?;
        self.io.write8(0x60f, 4)?;
        for address in 0u8..176 {
            let next = match address {
                170 => 255,
                175 => 171,
                _ => address + 1,
            };
            self.io.write32(
                0x1e0,
                (1 << 30) | (u32::from(address) << 8) | u32::from(next),
            )?;
            let mut complete = false;
            for _ in 0..24 {
                let value = self.io.read32(0x1e0)?;
                if value == u32::MAX {
                    return Err(Error::Access(AccessError::Gone));
                }
                if value >> 30 == 0 {
                    complete = true;
                    break;
                }
                self.io.delay_us(5).await;
            }
            if !complete {
                return Err(Error::LltTimeout);
            }
        }
        Ok(())
    }
}
impl<I: Io, M: Memory> Drop for Prepared<I, M> {
    fn drop(&mut self) {
        if self.published {
            // Clearing BME/revoking authority alone is not a prefetch fence.
            // A future reset/quiescence owner must prove reclamation first.
            core::mem::forget(core::mem::take(&mut self.tx));
            core::mem::forget(self.receive.take());
            core::mem::forget(core::mem::take(&mut self.buffers));
        }
    }
}
/// Retain the complete owner before the first device-visible base write.
/// This is the actual native worker's shared storage/await boundary. An async
/// mutex, unlike an IRQ-disabling guard, may span the self-driven LLT wait.
pub(super) async fn retain_and_prepare<I: Io, M: Memory>(
    retained: &narf_lib::mutex::Mutex<Option<Prepared<I, M>>>,
    prepared: Prepared<I, M>,
) -> Result<(), Error> {
    let mut storage = retained.lock().await;
    if storage.is_some() {
        return Err(Error::State);
    }
    *storage = Some(prepared);
    storage.as_mut().ok_or(Error::State)?.prepare().await
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "prepare_tests.rs"]
mod tests;
