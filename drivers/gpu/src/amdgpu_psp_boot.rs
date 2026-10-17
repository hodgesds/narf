//! Navi22/PSP11 and Navi48/PSP14 secure-OS bootstrap. Protocol follows Linux
//! `psp_v11_0.c` and `psp_v14_0.c`: C2PMSG35 command/status, C2PMSG36 GPU address in MiB,
//! C2PMSG81 SOS heartbeat, all at MP0 base index **0** (not PSP13's index 1).
//! This requires initialized VRAM; it does not perform memory training,
//! create a GPCOM ring, allocate a TMR, or load graphics/SMC firmware.
use crate::{
    amdgpu::{AmdGpu, AMD_VENDOR, NAVI22, NAVI48},
    amdgpu_discovery as discovery,
    amdgpu_psp_firmware::{self as firmware, Component, Image, STAGING_SIZE},
    amdgpu_vram::{Pool, Reservation},
};
use alloc::vec::Vec;
use core::sync::atomic::{fence, Ordering};
use narf_bus::{BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, CapError, CapOp, Read, Write};

const STATUS: u32 = 0x63;
const ADDRESS: u32 = 0x64;
const SOS: u32 = 0x91;
const DONE: u32 = 1 << 31;

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
    Image(firmware::Error),
    Registry(narf_firmware::FirmwareError),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Prepared,
    Loading,
    Ready,
    Failed,
}

/// Immutable container copied inside live registry/blob capability invocations.
#[derive(Debug)]
pub struct Firmware {
    bytes: Vec<u8>,
    target: Target,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Target {
    Navi22,
    Psp14_0_2,
    Psp14_0_3,
}
impl Target {
    fn name(self) -> &'static str {
        match self {
            Self::Navi22 => firmware::NAVI22_SOS,
            Self::Psp14_0_2 => firmware::PSP14_0_2_SOS,
            Self::Psp14_0_3 => firmware::PSP14_0_3_SOS,
        }
    }
    fn parse(self, bytes: &[u8]) -> Result<Image<'_>, Error> {
        match self {
            Self::Navi22 => Image::parse(bytes),
            Self::Psp14_0_2 | Self::Psp14_0_3 => Image::parse_psp14(bytes),
        }
        .map_err(Error::Image)
    }
}
struct OpenFirmware(Target);
impl CapOp<narf_firmware::FirmwareRegistry, Read> for OpenFirmware {
    type Output = Result<Vec<u8>, Error>;
    fn execute(
        self,
        cap: &Cap<narf_firmware::FirmwareRegistry, Read>,
    ) -> Result<Self::Output, CapError> {
        let blob = match narf_firmware::open(self.0.name(), cap) {
            Ok(blob) => blob,
            Err(error) => return Ok(Err(Error::Registry(error))),
        };
        blob.invoke(CopyFirmware(self.0))
    }
}
struct CopyFirmware(Target);
impl CapOp<narf_firmware::FirmwareBlob, Read> for CopyFirmware {
    type Output = Result<Vec<u8>, Error>;
    fn execute(
        self,
        cap: &Cap<narf_firmware::FirmwareBlob, Read>,
    ) -> Result<Self::Output, CapError> {
        Ok((|| {
            let view = narf_firmware::view_of(cap).map_err(Error::Registry)?;
            self.0.parse(view.bytes)?;
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(view.bytes.len())
                .map_err(|_| Error::Allocation)?;
            bytes.extend_from_slice(view.bytes);
            Ok(bytes)
        })())
    }
}
fn profile(gpu: &AmdGpu) -> Result<(Target, u64), Error> {
    if gpu.chip.vid != AMD_VENDOR {
        return Err(Error::Unsupported);
    }
    let mut gc = gpu
        .ip_blocks
        .iter()
        .filter(|ip| ip.hw_id == discovery::HW_ID_GC && ip.instance == 0);
    let ip = gc.next().ok_or(Error::Unsupported)?;
    if gc.next().is_some() {
        return Err(Error::Unsupported);
    }
    let versions: &[(u8, u8, u8)] = match (gpu.chip.did, ip.major, ip.minor, ip.revision) {
        (NAVI22, 10, 3, 2) => &[(11, 0, 11)],
        (NAVI48, 12, 0, 1) => &[(14, 0, 2), (14, 0, 3)],
        _ => return Err(Error::Unsupported),
    };
    // bank rejects duplicate MP0 instances and checks the entire mailbox span.
    let base = crate::amdgpu_psp_ring::bank(gpu, discovery::HW_ID_MP0, versions, 0, SOS).map_err(
        |error| match error {
            crate::amdgpu_psp_ring::Error::Invalid => Error::Invalid,
            _ => Error::Unsupported,
        },
    )?;
    let mp0 =
        discovery::find_ip(&gpu.ip_blocks, discovery::HW_ID_MP0, 0).ok_or(Error::Unsupported)?;
    let target = match (mp0.major, mp0.minor, mp0.revision) {
        (11, 0, 11) => Target::Navi22,
        (14, 0, 2) => Target::Psp14_0_2,
        (14, 0, 3) => Target::Psp14_0_3,
        _ => return Err(Error::Unsupported),
    };
    Ok((target, base))
}
#[cfg(feature = "kernel-test")]
fn mp0_bank(gpu: &AmdGpu) -> Result<u64, Error> {
    profile(gpu).map(|(_, base)| base)
}
impl Firmware {
    pub(crate) fn is_psp14(&self, revision: u8) -> bool {
        matches!(
            (self.target, revision),
            (Target::Psp14_0_2, 2) | (Target::Psp14_0_3, 3)
        )
    }
    pub(crate) fn is_navi22(&self) -> bool {
        self.target == Target::Navi22
    }
    pub fn open(
        gpu: &AmdGpu,
        authority: &Cap<narf_firmware::FirmwareRegistry, Read>,
    ) -> Result<Self, Error> {
        let (target, _) = profile(gpu)?;
        Ok(Self {
            target,
            bytes: authority
                .invoke(OpenFirmware(target))
                .map_err(|_| Error::Revoked)??,
        })
    }
    pub fn image(&self) -> Result<Image<'_>, Error> {
        self.target.parse(&self.bytes)
    }
}

struct Op<F>(F);
impl<F: FnOnce() -> T, T> CapOp<BusDeviceCap, Write> for Op<F> {
    type Output = T;
    fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<T, CapError> {
        Ok((self.0)())
    }
}
trait Io {
    fn read(&mut self, reg: u32) -> u32;
    fn write(&mut self, reg: u32, value: u32);
    fn write_mem(&mut self, offset: usize, value: u32);
    fn finish_upload(&mut self);
}
#[derive(Debug)]
struct Mmio {
    regs: MmioRegion,
    base: u64,
    memory: MmioRegion,
}
impl Io for Mmio {
    fn read(&mut self, reg: u32) -> u32 {
        // SAFETY: constructor bounds the exact PSP11/PSP14 MP0 window.
        unsafe { self.regs.read32(self.base + u64::from(reg) * 4) }
    }
    fn write(&mut self, reg: u32, value: u32) {
        // SAFETY: same bounded window; owner excludes all other PSP clients.
        unsafe { self.regs.write32(self.base + u64::from(reg) * 4, value) };
    }
    fn write_mem(&mut self, offset: usize, value: u32) {
        // SAFETY: staging writes are aligned and strictly within the reservation.
        unsafe { self.memory.write32(offset as u64, value) };
    }
    fn finish_upload(&mut self) {
        fence(Ordering::SeqCst);
        // Drain posted BAR0 writes before ringing the BAR5 mailbox. Linux's
        // psp_copy_fw likewise copies to the VRAM staging BO before the command.
        // SAFETY: last dword of the permanently owned, fully written mapping.
        unsafe { self.memory.read32(STAGING_SIZE as u64 - 4) };
        fence(Ordering::SeqCst);
    }
}
#[derive(Debug)]
struct Engine<I: Io> {
    io: I,
    authority: Cap<BusDeviceCap, Write>,
    memory: Reservation,
    state: State,
    /// psp_v11_0_wait_for_bootloader waits for `(C2PMSG_35 & 0x8000FFFF) ==
    /// 0x80000000` (20 rounds of usec_timeout): nonzero low bits mean "keep
    /// waiting", not a rejection. PSP14 keeps the strict DONE-then-status rule.
    psp11: bool,
}
/// psp_v11_0_wait_for_bootloader: 20 × psp_wait_for, each usec_timeout
/// (100 000) iterations of RREG32 + udelay(1). The udelays alone are 2 s; the
/// uncached MMIO read per iteration (1-2 us over PCIe) makes Linux's real
/// bound 4-6 s, so wait the upper end.
pub(crate) const PSP11_BOOTLOADER_TIMEOUT_MS: u64 = 6000;
async fn delay(ms: u64) {
    narf_time::SleepUntil::new(narf_time::Deadline::after_ms(ms).as_instant()).await;
}
impl<I: Io> Engine<I> {
    fn access<T>(&mut self, f: impl FnOnce(&mut I) -> T) -> Result<T, Error> {
        let io = &mut self.io;
        self.authority
            .invoke(Op(|| f(io)))
            .map_err(|_| Error::Revoked)
    }
    fn heartbeat(&mut self) -> Result<u32, Error> {
        match self.access(|io| io.read(SOS))? {
            u32::MAX => Err(Error::DeviceGone),
            value => Ok(value),
        }
    }
    async fn response(&mut self) -> Result<(), Error> {
        let timeout = if self.psp11 {
            PSP11_BOOTLOADER_TIMEOUT_MS
        } else {
            1000
        };
        let deadline = narf_time::Deadline::after_ms(timeout);
        loop {
            let value = self.access(|io| io.read(STATUS))?;
            if value == u32::MAX {
                return Err(Error::DeviceGone);
            }
            if value & DONE != 0 {
                if value & 0xffff == 0 {
                    return Ok(());
                }
                // A persistent status at the deadline is still reported as
                // the bootloader's rejection code for diagnostics.
                if !self.psp11 || deadline.expired() {
                    return Err(Error::Rejected(value & 0xffff));
                }
            } else if deadline.expired() {
                return Err(Error::Timeout);
            }
            delay(1).await;
        }
    }
    async fn alive(&mut self) -> Result<(), Error> {
        // A nonzero but frozen register is insufficient proof that SOS boots.
        let initial = self.heartbeat()?;
        let deadline = narf_time::Deadline::after_ms(1000);
        loop {
            let value = self.heartbeat()?;
            if value != 0 && value != initial {
                return Ok(());
            }
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            delay(1).await;
        }
    }
    async fn upload(&mut self, bytes: &[u8]) -> Result<(), Error> {
        for start in (0..STAGING_SIZE).step_by(4096) {
            self.access(|io| {
                for offset in (start..start + 4096).step_by(4) {
                    let mut word = [0u8; 4];
                    if offset < bytes.len() {
                        let count = (bytes.len() - offset).min(4);
                        word[..count].copy_from_slice(&bytes[offset..offset + count]);
                    }
                    io.write_mem(offset, u32::from_le_bytes(word));
                }
            })?;
            narf_scheduler::yield_now().await;
        }
        self.access(|io| io.finish_upload())
    }
    async fn load_inner(&mut self, image: &Image<'_>) -> Result<(), Error> {
        if self.heartbeat()? != 0 {
            // BIOS/previous driver already started SOS. Verify liveness without
            // touching the bootloader or overwriting its firmware.
            return self.alive().await;
        }
        for (kind, bytes) in image.components() {
            self.response().await?;
            self.upload(bytes).await?;
            let address = (self.memory.address() >> 20) as u32;
            // Publication precedes both mailbox writes. Cancellation/revocation
            // can never return memory whose device ownership is uncertain.
            self.memory.publish();
            self.access(|io| {
                io.write(ADDRESS, address);
                io.write(STATUS, kind.command());
            })?;
            if kind == Component::SecureOs {
                delay(20).await;
                self.alive().await?;
            } else {
                self.response().await?;
            }
            // SAFETY: successful bootloader completion (or running SOS) proves
            // the copy has been consumed; PSP no longer reads this staging BO.
            unsafe { self.memory.stopped() };
        }
        Ok(())
    }
    async fn load(&mut self, image: &Image<'_>) -> Result<(), Error> {
        if self.state != State::Prepared {
            return Err(Error::Busy);
        }
        self.state = State::Loading;
        let result = self.load_inner(image).await;
        self.state = if result.is_ok() {
            State::Ready
        } else {
            State::Failed
        };
        result
    }
}

#[derive(Debug)]
pub struct Bootloader {
    engine: Engine<Mmio>,
    target: Target,
}
impl Bootloader {
    /// Reserve a 1 MiB staging BO at a 1 MiB-aligned **GPU** address. No hardware
    /// writes occur until `load`; the BAR's host physical address is never sent.
    ///
    /// # Safety
    /// Caller exclusively owns this physical GPU (not an SR-IOV VF), its PSP,
    /// reset/power controls and permanent mappings. VRAM must already be trained
    /// and accessible, with the pool's GPU address mapping valid for this GPU.
    /// The pool excludes firmware, scanout, discovery, training and TMR ranges.
    /// No memory training/reset or other PSP client may run during this object's
    /// lifetime. Retain quarantined memory after failure/cancellation until an
    /// independently verified device reset; dropping this object does not reset.
    pub unsafe fn new(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        pool: &Pool,
    ) -> Result<Self, Error> {
        let (target, base) = profile(gpu)?;
        let map = pool.mapping();
        let offset = map
            .phys
            .raw()
            .checked_sub(gpu.fb_bar.phys.raw())
            .ok_or(Error::Invalid)?;
        if gpu.fb_bar.virt.checked_add(offset) != Some(map.virt)
            || offset
                .checked_add(map.len)
                .is_none_or(|end| end > gpu.fb_bar.len.min(gpu.vram.visible_size))
        {
            return Err(Error::Invalid);
        }
        let memory = pool
            .reserve_aligned(STAGING_SIZE as u64, STAGING_SIZE as u64)
            .map_err(|_| Error::Allocation)?;
        Ok(Self {
            target,
            engine: Engine {
                io: Mmio {
                    regs: gpu.regs,
                    base,
                    memory: memory.mapping(),
                },
                authority,
                memory,
                state: State::Prepared,
                psp11: target == Target::Navi22,
            },
        })
    }
    pub fn state(&self) -> State {
        self.engine.state
    }
    /// Boot authenticated container components, or verify an already running SOS.
    /// A dropped future leaves Loading and cannot be retried through this object.
    /// Success proves SOS liveness only; it does not set `AmdGpu::fw_loaded`.
    pub async fn load(&mut self, firmware: &Firmware) -> Result<(), Error> {
        if firmware.target != self.target {
            return Err(Error::Unsupported);
        }
        self.engine.load(&firmware.image()?).await
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_psp_boot_tests.rs"]
pub(crate) mod tests;
