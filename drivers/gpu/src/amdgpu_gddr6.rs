//! Navi22/Navi48 cold-boot GDDR6 training (Linux psp_v{11,14}_0).
//! Long training overwrites the bottom 32 MiB of VRAM. Its preimage and the
//! training cache live in the owner, including across cancelled futures.
use alloc::vec::Vec;
use core::sync::atomic::{fence, Ordering};
use narf_bus::{BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, CapError, CapOp, Write};

use crate::{amdgpu::AmdGpu, amdgpu_vram_boot::Training};

const STATUS: u32 = 0x63; // MP0 C2PMSG35, base index 0
const ADDRESS: u32 = 0x64; // C2PMSG36: VRAM-relative MiB, not GPU/PCI address
const SOS: u32 = 0x91; // C2PMSG81
const DONE: u32 = 1 << 31;
const LONG_TRAIN: u32 = 0x10_0000;
const SHORT_TRAIN: u32 = 0x20_0000; // PSP_BL__DRAM_SHORT_TRAIN
const ENCROACHED: usize = 32 << 20;
const CHUNK: usize = 4096;
const SIGNATURE: u32 = 0x5453_4942;
const HDP_HOLE: u64 = 0x7f000;
const RUNTIME_DB_OFFSET: u64 = 1 << 20;
/// psp_v11_0_memory_training_send_msg: MEM_TRAIN_SEND_MSG_TIMEOUT_US (3 s)
/// split into 30 psp_wait_for rounds of usec_timeout polls, each poll an MMIO
/// read plus udelay(1): at least 3 s, in practice longer. Allow twice that.
const TRAINING_TIMEOUT_MS: u64 = 6000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    Invalid,
    Allocation,
    Revoked,
    Busy,
    Timeout,
    DeviceGone,
    Rejected(u32),
    InvalidTrainingData,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Prepared,
    Saving,
    Training,
    Restoring,
    SavingResult,
    Ready,
    ResidentSos,
    Disabled,
    Failed,
}
trait Io {
    fn read(&mut self, reg: u32) -> u32;
    fn write(&mut self, reg: u32, value: u32);
    fn setup(&mut self) -> bool;
    fn training_enabled(&mut self) -> Result<bool, Error>;
    fn read_prefix(&mut self, offset: usize, bytes: &mut [u8]);
    fn write_prefix(&mut self, offset: usize, bytes: &[u8]);
    fn flush(&mut self);
    fn read_result(&mut self, offset: u64, bytes: &mut [u8]) -> Result<(), Error>;
    /// Write the training cache back to C2P and flush it past HDP
    /// (PSP_MEM_TRAIN_RESTORE's amdgpu_device_vram_access write).
    fn write_exchange(&mut self, offset: u64, bytes: &[u8]) -> Result<(), Error>;
}
struct Op<F>(F);
impl<F: FnOnce() -> T, T> CapOp<BusDeviceCap, Write> for Op<F> {
    type Output = T;
    fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<T, CapError> {
        Ok((self.0)())
    }
}
#[derive(Debug)]
struct Mmio {
    regs: MmioRegion,
    vram: MmioRegion,
    size: u64,
    mp0: u64,
    nbio: u64,
    invalidate_reg: Option<u64>,
}
impl Io for Mmio {
    fn read(&mut self, reg: u32) -> u32 {
        // SAFETY: constructor bounds MP0 through SOS, the highest read.
        unsafe { self.regs.read32(self.mp0 + reg as u64 * 4) }
    }
    fn write(&mut self, reg: u32, value: u32) {
        // SAFETY: exclusive PSP boot mailbox, same bounded bank.
        unsafe { self.regs.write32(self.mp0 + reg as u64 * 4, value) };
    }
    fn setup(&mut self) -> bool {
        // SAFETY: bounded NBIO/HDP5 banks, exclusive remap ownership. Invalidate
        // before backing up memory that firmware may have written through HDP.
        unsafe {
            self.regs.write32(self.nbio + 0x12d * 4, HDP_HOLE as u32);
            if self.regs.read32(self.nbio + 0x12d * 4) != HDP_HOLE as u32 {
                return false;
            }
            if let Some(reg) = self.invalidate_reg {
                self.regs.write32(reg, 1);
                self.regs.read32(reg);
            }
        }
        fence(Ordering::SeqCst);
        true
    }
    fn training_enabled(&mut self) -> Result<bool, Error> {
        let base = self
            .size
            .checked_sub(RUNTIME_DB_OFFSET)
            .ok_or(Error::Invalid)?;
        // SAFETY: current PCI invocation owns mappings and shared index latch.
        let mut reader =
            unsafe { crate::amdgpu_vram_access::MmioReader::new(&self.vram, &self.regs) };
        training_policy(|offset, bytes| {
            crate::amdgpu_vram_access::read(&mut reader, self.size, base + offset as u64, bytes)
                .map_err(|_| Error::Invalid)
        })
    }
    fn read_prefix(&mut self, offset: usize, bytes: &mut [u8]) {
        for (index, word) in bytes.chunks_exact_mut(4).enumerate() {
            // SAFETY: complete 32 MiB prefix bounded at construction; aligned
            // reads are internal to the bounded backup loop under live authority.
            word.copy_from_slice(
                &unsafe { self.vram.read32((offset + index * 4) as u64) }.to_le_bytes(),
            );
        }
    }
    fn write_prefix(&mut self, offset: usize, bytes: &[u8]) {
        for (index, word) in bytes.chunks_exact(4).enumerate() {
            // SAFETY: same bounds; acknowledged completion ended PSP's writes.
            unsafe {
                self.vram.write32(
                    (offset + index * 4) as u64,
                    u32::from_le_bytes(word.try_into().unwrap()),
                )
            };
        }
    }
    fn flush(&mut self) {
        fence(Ordering::SeqCst);
        // SAFETY: remap verified before backup/command, bounded MEMSIZE read
        // drains the posted HDP flush after restoring the prefix.
        unsafe {
            self.regs.write32(HDP_HOLE, 0);
            self.regs.read32(self.nbio + 0xc3 * 4);
        }
        fence(Ordering::SeqCst);
    }
    fn read_result(&mut self, offset: u64, bytes: &mut [u8]) -> Result<(), Error> {
        // SAFETY: optional HDP5 invalidate bank; HDP6 has no invalidate step.
        unsafe {
            if let Some(reg) = self.invalidate_reg {
                self.regs.write32(reg, 1);
                self.regs.read32(reg);
            }
        }
        fence(Ordering::SeqCst);
        // SAFETY: caller's live PCI invocation and exclusive index latch.
        let mut reader =
            unsafe { crate::amdgpu_vram_access::MmioReader::new(&self.vram, &self.regs) };
        crate::amdgpu_vram_access::read(&mut reader, self.size, offset, bytes)
            .map_err(|_| Error::Invalid)
    }
    fn write_exchange(&mut self, offset: u64, bytes: &[u8]) -> Result<(), Error> {
        // SAFETY: current PCI invocation owns mappings and shared index latch.
        let mut writer =
            unsafe { crate::amdgpu_vram_access::MmioReader::new(&self.vram, &self.regs) };
        crate::amdgpu_vram_access::write(&mut writer, self.size, offset, bytes)
            .map_err(|_| Error::Invalid)?;
        self.flush();
        Ok(())
    }
}
#[derive(Debug)]
struct Engine<I: Io> {
    io: I,
    authority: Cap<BusDeviceCap, Write>,
    exchange: Training,
    backup: Vec<u8>,
    cache: Vec<u8>,
    state: State,
}
impl<I: Io> Engine<I> {
    fn access<T>(&mut self, f: impl FnOnce(&mut I) -> T) -> Result<T, Error> {
        let io = &mut self.io;
        self.authority
            .invoke(Op(|| f(io)))
            .map_err(|_| Error::Revoked)
    }
    async fn response(&mut self) -> Result<u32, Error> {
        let deadline = narf_time::Deadline::after_ms(TRAINING_TIMEOUT_MS);
        loop {
            let status = self.access(|io| io.read(STATUS))?;
            if status == u32::MAX {
                return Err(Error::DeviceGone);
            }
            if status & DONE != 0 {
                return Ok(status);
            }
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            narf_time::SleepUntil::new(narf_time::Deadline::after_ms(1).as_instant()).await;
        }
    }
    /// The common preamble: Ok(false) when no training applies (resident
    /// SOS or disabled by the PSP runtime DB), with the state recorded.
    async fn prepare(&mut self) -> Result<bool, Error> {
        match self.access(|io| io.read(SOS))? {
            u32::MAX => return Err(Error::DeviceGone),
            0 => {}
            _ => {
                self.state = State::ResidentSos;
                return Ok(false);
            }
        }
        if !self.access(|io| io.training_enabled())?? {
            self.state = State::Disabled;
            return Ok(false);
        }
        // Verify the bootloader is idle before touching VRAM or its address latch.
        self.response().await?;
        if !self.access(|io| io.setup())? {
            return Err(Error::Invalid);
        }
        Ok(true)
    }
    async fn inner(&mut self) -> Result<(), Error> {
        if !self.prepare().await? {
            return Ok(());
        }
        self.long_train().await?;
        self.save().await?;
        self.state = State::Ready;
        Ok(())
    }
    /// PSP_MEM_TRAIN_SEND_LONG_MSG with the encroached 32 MiB preserved.
    async fn long_train(&mut self) -> Result<(), Error> {
        for (index, chunk) in self.backup.chunks_mut(CHUNK).enumerate() {
            let io = &mut self.io;
            self.authority
                .invoke(Op(|| io.read_prefix(index * CHUNK, chunk)))
                .map_err(|_| Error::Revoked)?;
            narf_scheduler::yield_now().await;
        }
        self.state = State::Training;
        let address = (self.exchange.c2p >> 20) as u32;
        self.access(|io| {
            io.write(ADDRESS, address);
            io.write(STATUS, LONG_TRAIN);
        })?;
        let response = self.response().await?;
        // Only a terminal reply permits restoring memory; timeout/removal/
        // revocation/cancellation must never race an uncompleted PSP writer.
        self.state = State::Restoring;
        for (index, chunk) in self.backup.chunks(CHUNK).enumerate() {
            let io = &mut self.io;
            self.authority
                .invoke(Op(|| io.write_prefix(index * CHUNK, chunk)))
                .map_err(|_| Error::Revoked)?;
            narf_scheduler::yield_now().await;
        }
        self.access(|io| io.flush())?;
        // psp_v11_0_memory_training_send_msg waits on bit 31 alone and treats
        // it as success; the low status bits are only reported.
        if response & 0xffff != 0 {
            use core::fmt::Write;
            let _ = writeln!(
                narf_console::Writer,
                "amdgpu: gddr6 long training status {response:#x}"
            );
        }
        Ok(())
    }
    /// PSP_MEM_TRAIN_SAVE: P2C into the system cache.
    async fn save(&mut self) -> Result<(), Error> {
        self.state = State::SavingResult;
        let io = &mut self.io;
        let cache = &mut self.cache;
        let offset = self.exchange.p2c;
        self.authority
            .invoke(Op(|| io.read_result(offset, cache)))
            .map_err(|_| Error::Revoked)??;
        // Linux PSP_MEM_TRAIN_SAVE copies P2C unconditionally after long
        // training; the "BIST" signature only decides reuse on resume. A
        // missing signature therefore leaves the boot running but exposes
        // no training cache (`training_data`).
        if !self.cache_valid() {
            use core::fmt::Write;
            let _ = writeln!(
                narf_console::Writer,
                "amdgpu: gddr6 training cache lacks the BIST signature"
            );
        }
        Ok(())
    }
    /// psp_v14_0_memory_training(PSP_MEM_TRAIN_RESUME) after the ASIC lost
    /// its trained state (mode1 reset or S3): short training from the
    /// restored cache, escalating to save and long training exactly as
    /// Linux does when the cache or P2C result is missing or stale.
    async fn resume_inner(&mut self) -> Result<(), Error> {
        if !self.prepare().await? {
            return Ok(());
        }
        let mut p2c = buffer(self.exchange.size as usize)?;
        {
            let io = &mut self.io;
            let offset = self.exchange.p2c;
            self.authority
                .invoke(Op(|| io.read_result(offset, &mut p2c)))
                .map_err(|_| Error::Revoked)??;
        }
        let signed = |b: &[u8]| u32::from_le_bytes(b[..4].try_into().unwrap()) == SIGNATURE;
        let p2c_valid = signed(&p2c);
        // SEND_SHORT implies RESTORE; RESTORE needs a valid cache (SAVE).
        let (mut short, restore) = (true, true);
        let mut save = !self.cache_valid();
        if p2c_valid && !(self.cache_valid() && self.cache[12..16] == p2c[12..16]) {
            save = true;
        }
        let long = save && !p2c_valid;
        if long {
            short = false;
            save = true;
        }
        if long {
            self.long_train().await?;
        }
        if save {
            self.save().await?;
        }
        if restore {
            // NARF tightening: never hand PSP an unsigned cache to train from.
            if short && !self.cache_valid() {
                return Err(Error::InvalidTrainingData);
            }
            self.state = State::Restoring;
            let io = &mut self.io;
            let (offset, cache) = (self.exchange.c2p, &self.cache);
            self.authority
                .invoke(Op(|| io.write_exchange(offset, cache)))
                .map_err(|_| Error::Revoked)??;
        }
        if short {
            self.state = State::Training;
            let address = (self.exchange.c2p >> 20) as u32;
            self.access(|io| {
                io.write(ADDRESS, address);
                io.write(STATUS, SHORT_TRAIN);
            })?;
            let response = self.response().await?;
            if response & 0xffff != 0 {
                use core::fmt::Write;
                let _ = writeln!(
                    narf_console::Writer,
                    "amdgpu: gddr6 short training status {response:#x}"
                );
            }
        }
        self.state = State::Ready;
        Ok(())
    }
    async fn resume(&mut self) -> Result<(), Error> {
        if !matches!(
            self.state,
            State::Ready | State::ResidentSos | State::Disabled
        ) {
            return Err(Error::Busy);
        }
        self.state = State::Saving;
        let result = self.resume_inner().await;
        if result.is_err() {
            self.state = State::Failed;
        }
        result
    }
    fn cache_valid(&self) -> bool {
        u32::from_le_bytes(self.cache[..4].try_into().unwrap()) == SIGNATURE
    }
    async fn run(&mut self) -> Result<(), Error> {
        if self.state != State::Prepared {
            return Err(Error::Busy);
        }
        self.state = State::Saving;
        let result = self.inner().await;
        if result.is_err() {
            self.state = State::Failed;
        }
        result
    }
}
/// PSP runtime DB, amdgpu_psp.h: 4-byte header, padded u16 count, then at
/// most 63 eight-byte directory entries. As psp_get_runtime_db_entry, any
/// malformed database or entry is "absent", which preserves the Linux
/// enable default.
fn training_policy(read: impl FnMut(usize, &mut [u8]) -> Result<(), Error>) -> Result<bool, Error> {
    let entry = runtime_entry::<8>(read, 5)?;
    Ok(entry.is_none_or(|entry| u32::from_le_bytes(entry[..4].try_into().unwrap()) & 2 != 0))
}
/// Bounded PSP runtime DB lookup shared by training and SMU power policy.
/// psp_get_runtime_db_entry: no version check, an entry count of 64 or more
/// or an undersized entry means "no entry", and the first match wins. An
/// entry outside the 64 KiB window (which Linux would read blindly) is
/// likewise treated as absent. Only a failed VRAM read is an error.
pub(crate) fn runtime_entry<const N: usize>(
    mut read: impl FnMut(usize, &mut [u8]) -> Result<(), Error>,
    kind: u32,
) -> Result<Option<[u8; N]>, Error> {
    let mut header = [0; 8];
    read(0, &mut header)?;
    let word = |bytes: &[u8]| u16::from_le_bytes(bytes.try_into().unwrap()) as usize;
    if word(&header[..2]) != 0xed5 {
        return Ok(None);
    }
    let count = word(&header[4..6]);
    if count >= 64 {
        return Ok(None);
    }
    let end = 8 + count * 8;
    let mut directory = [0; 63 * 8];
    read(8, &mut directory[..count * 8])?;
    let Some(entry) = directory[..count * 8]
        .chunks_exact(8)
        .find(|entry| u32::from_le_bytes(entry[..4].try_into().unwrap()) == kind)
    else {
        return Ok(None);
    };
    let offset = word(&entry[4..6]);
    let size = word(&entry[6..8]);
    if offset < end || offset % 4 != 0 || size < N || offset + size > 0x10000 {
        return Ok(None);
    }
    let mut entry = [0; N];
    read(offset, &mut entry)?;
    Ok(Some(entry))
}
fn buffer(size: usize) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(size)
        .map_err(|_| Error::Allocation)?;
    bytes.resize(size, 0);
    Ok(bytes)
}
fn validate_exchange(size: u64, visible: u64, exchange: Training) -> Result<(), Error> {
    if visible < ENCROACHED as u64
        || visible > size
        || exchange.size != 4096
        || exchange.p2c.checked_add(0x8000) != Some(size)
        || exchange.c2p < ENCROACHED as u64
        || exchange.c2p % (1 << 20) != 0
        || exchange.c2p >> 20 > u32::MAX as u64
        || exchange
            .c2p
            .checked_add(exchange.size)
            .is_none_or(|end| end > exchange.p2c)
    {
        return Err(Error::Invalid);
    }
    Ok(())
}
#[derive(Debug)]
pub struct Trainer {
    engine: Engine<Mmio>,
}
impl Trainer {
    /// Allocates the complete preimage/cache before any device access.
    ///
    /// # Safety
    /// Caller exclusively owns a physical Navi22, its PSP/HDP/NBIO/index latch,
    /// reset/power controls and permanent mappings. Exchange buffers must come
    /// from this GPU's current boot Plan and remain permanently excluded from
    /// every allocator. Stop every other GPU/CPU VRAM writer (including the
    /// framebuffer console/pumps) before run; no software client may read the
    /// bottom 32 MiB until successful completion. Inventoried scanout/cursor
    /// readers may remain active but can display transient training pixels.
    /// Live firmware code/data must not overlap this prefix. This follows the
    /// PSP11 cold-training-before-display-init ordering; it is not resume or
    /// arbitrary retraining. On failure/cancellation retain this owner and
    /// require independent reset/recovery before handing memory back to clients.
    /// Drop never restores memory, resets hardware or retries a command.
    pub unsafe fn new(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        exchange: Training,
    ) -> Result<Self, Error> {
        use crate::{amdgpu_discovery as ip, amdgpu_psp_ring as psp};
        psp::validate_rdna2_layout(gpu).map_err(|_| Error::Unsupported)?;
        validate_exchange(
            gpu.vram.size,
            gpu.fb_bar.len.min(gpu.vram.visible_size),
            exchange,
        )?;
        authority.invoke(Op(|| ())).map_err(|_| Error::Revoked)?;
        let profile = crate::amdgpu_rdna2::for_pci_id(gpu.chip.vid, gpu.chip.did)
            .ok_or(Error::Unsupported)?;
        let mp0 = psp::bank(gpu, ip::HW_ID_MP0, &[profile.psp_version], 0, SOS)
            .map_err(|_| Error::Unsupported)?;
        let nbio = psp::bank(
            gpu,
            ip::HW_ID_NBIF,
            &[
                (2, 3, 0),
                (2, 3, 1),
                (2, 3, 2),
                (3, 3, 0),
                (3, 3, 1),
                (3, 3, 2),
                (3, 3, 3),
            ],
            2,
            0x12d,
        )
        .map_err(|_| Error::Unsupported)?;
        let hdp = psp::bank(
            gpu,
            ip::HW_ID_HDP,
            &[(5, 0, 0), (5, 0, 1), (5, 0, 2), (5, 0, 3), (5, 0, 4)],
            0,
            0xd1,
        )
        .map_err(|_| Error::Unsupported)?;
        Ok(Self {
            engine: Engine {
                io: Mmio {
                    regs: gpu.regs,
                    vram: gpu.fb_bar,
                    size: gpu.vram.size,
                    mp0,
                    nbio,
                    invalidate_reg: Some(hdp + 0xd1 * 4),
                },
                authority,
                exchange,
                backup: buffer(ENCROACHED)?,
                cache: buffer(4096)?,
                state: State::Prepared,
            },
        })
    }
    /// Allocate Navi48's PSP14 cold-training owner before any memory access.
    ///
    /// # Safety
    /// Same exclusive GPU/PSP/HDP/index/reset ownership, client quiescence and
    /// permanent exchange reservations as `new`, for physical Navi48 instead.
    /// The bottom 32 MiB preimage remains owned on cancellation or failure.
    pub unsafe fn new_navi48(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        exchange: Training,
    ) -> Result<Self, Error> {
        let layout = crate::amdgpu_psp_ring::navi48_layout(gpu).map_err(|_| Error::Unsupported)?;
        validate_exchange(
            gpu.vram.size,
            gpu.fb_bar.len.min(gpu.vram.visible_size),
            exchange,
        )?;
        authority.invoke(Op(|| ())).map_err(|_| Error::Revoked)?;
        Ok(Self {
            engine: Engine {
                io: Mmio {
                    regs: gpu.regs,
                    vram: gpu.fb_bar,
                    size: gpu.vram.size,
                    mp0: layout.mp0,
                    nbio: layout.nbio,
                    invalidate_reg: layout.invalidate_reg,
                },
                authority,
                exchange,
                backup: buffer(ENCROACHED)?,
                cache: buffer(4096)?,
                state: State::Prepared,
            },
        })
    }
    pub fn state(&self) -> State {
        self.engine.state
    }
    pub async fn run(&mut self) -> Result<(), Error> {
        self.engine.run().await
    }
    /// Replay training after the ASIC lost its trained state (Linux
    /// `psp_resume` -> `PSP_MEM_TRAIN_RESUME`): short training from the
    /// retained cache, escalating to save/long training as Linux does. A
    /// resident SOS or a runtime-DB disable skips training, as at cold boot.
    ///
    /// # Safety
    /// As `new`/`new_navi48` (exclusive PSP/HDP/index/reset ownership and
    /// quiesced VRAM clients), after a completed ASIC reset or power loss and
    /// before SOS loads. Long escalation encroaches the bottom 32 MiB as
    /// `run` does. On failure/cancellation keep this owner and stop.
    pub async unsafe fn resume(&mut self) -> Result<(), Error> {
        self.engine.resume().await
    }
    /// A validated copy of firmware's P2C result, available only after success.
    pub fn training_data(&self) -> Option<&[u8]> {
        (self.state() == State::Ready && self.engine.cache_valid())
            .then_some(self.engine.cache.as_slice())
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_gddr6_tests.rs"]
mod tests;
