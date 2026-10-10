//! Navi22 SMC preparation and a cold-start SMU11 version handshake. Linux
//! `smu_v11_0.c`, `sienna_cichlid_ppt.c`, `smu_v11_0_7_ppsmc.h` and
//! `mp_11_0_offset.h`: MP1 index 0, message=66, argument=82, response=90.
//! No voltage, clock, fan or PowerPlay programming is exposed here.
use crate::{amdgpu::AmdGpu, amdgpu_discovery as discovery, amdgpu_smc_firmware as firmware};
use alloc::vec::Vec;
use narf_bus::{BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, CapError, CapOp, Read, Write};

const MESSAGE: u32 = 0x282;
const ARGUMENT: u32 = 0x292;
const RESPONSE: u32 = 0x29a;
const GET_VERSION: u32 = 2;
const GET_INTERFACE: u32 = 3;
pub const DRIVER_INTERFACE: u32 = 0x0e;

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
    InterfaceMismatch(u32),
    Image(firmware::Error),
    Registry(narf_firmware::FirmwareError),
}
pub(crate) fn mp1_bank(gpu: &AmdGpu) -> Result<u64, Error> {
    if gpu.chip.vid != crate::amdgpu::AMD_VENDOR || gpu.chip.did != crate::amdgpu::NAVI22 {
        return Err(Error::Unsupported);
    }
    let mut gc = gpu
        .ip_blocks
        .iter()
        .filter(|ip| ip.hw_id == discovery::HW_ID_GC && ip.instance == 0);
    let gc_ip = gc.next().ok_or(Error::Unsupported)?;
    if gc.next().is_some() || (gc_ip.major, gc_ip.minor, gc_ip.revision) != (10, 3, 2) {
        return Err(Error::Unsupported);
    }
    crate::amdgpu_psp_ring::bank(gpu, discovery::HW_ID_MP1, &[(11, 0, 11)], 0, RESPONSE).map_err(
        |error| match error {
            crate::amdgpu_psp_ring::Error::Invalid => Error::Invalid,
            _ => Error::Unsupported,
        },
    )
}
/// Immutable image read through registry/blob capabilities. No raw-byte
/// constructor is exposed to callers of the hardware loader.
#[derive(Debug)]
pub struct Firmware {
    bytes: Vec<u8>,
}
struct Open;
impl CapOp<narf_firmware::FirmwareRegistry, Read> for Open {
    type Output = Result<Vec<u8>, Error>;
    fn execute(
        self,
        cap: &Cap<narf_firmware::FirmwareRegistry, Read>,
    ) -> Result<Self::Output, CapError> {
        let blob = match narf_firmware::open(firmware::NAVI22_SMC, cap) {
            Ok(blob) => blob,
            Err(error) => return Ok(Err(Error::Registry(error))),
        };
        blob.invoke(CopyImage)
    }
}
struct CopyImage;
impl CapOp<narf_firmware::FirmwareBlob, Read> for CopyImage {
    type Output = Result<Vec<u8>, Error>;
    fn execute(
        self,
        cap: &Cap<narf_firmware::FirmwareBlob, Read>,
    ) -> Result<Self::Output, CapError> {
        Ok((|| {
            let view = narf_firmware::view_of(cap).map_err(Error::Registry)?;
            firmware::Image::parse(view.bytes).map_err(Error::Image)?;
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(view.bytes.len())
                .map_err(|_| Error::Allocation)?;
            bytes.extend_from_slice(view.bytes);
            Ok(bytes)
        })())
    }
}
impl Firmware {
    pub fn open(
        gpu: &AmdGpu,
        authority: &Cap<narf_firmware::FirmwareRegistry, Read>,
    ) -> Result<Self, Error> {
        mp1_bank(gpu)?;
        Ok(Self {
            bytes: authority.invoke(Open).map_err(|_| Error::Revoked)??,
        })
    }
    pub fn image(&self) -> Result<firmware::Image<'_>, Error> {
        firmware::Image::parse(&self.bytes).map_err(Error::Image)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Prepared,
    Querying,
    Ready,
    Failed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Versions {
    pub firmware: u32,
    pub interface: u32,
}
struct Op<F>(F);
impl<F: FnOnce() -> T, T> CapOp<BusDeviceCap, Write> for Op<F> {
    type Output = T;
    fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<T, CapError> {
        Ok((self.0)())
    }
}
trait Io {
    fn read(&mut self, register: u32) -> u32;
    fn write(&mut self, register: u32, value: u32);
}
#[derive(Debug)]
struct Mmio {
    regs: MmioRegion,
    base: u64,
}
impl Io for Mmio {
    fn read(&mut self, register: u32) -> u32 {
        // SAFETY: exact MP1 window bounded by mp1_bank, mapping is permanent.
        unsafe { self.regs.read32(self.base + u64::from(register) * 4) }
    }
    fn write(&mut self, register: u32, value: u32) {
        // SAFETY: same bounds, with exclusive ownership of this mailbox.
        unsafe {
            self.regs
                .write32(self.base + u64::from(register) * 4, value)
        };
    }
}
#[derive(Debug)]
struct Engine<I: Io> {
    io: I,
    authority: Cap<BusDeviceCap, Write>,
    state: State,
}
impl<I: Io> Engine<I> {
    fn access<T>(&mut self, f: impl FnOnce(&mut I) -> T) -> Result<T, Error> {
        let io = &mut self.io;
        self.authority
            .invoke(Op(|| f(io)))
            .map_err(|_| Error::Revoked)
    }
    async fn query(&mut self, message: u32) -> Result<u32, Error> {
        self.access(|io| {
            if io.read(RESPONSE) == u32::MAX {
                return Err(Error::DeviceGone);
            }
            // A freshly loaded SMU may leave response=0. Linux's first message
            // skips pre-poll; after that we own and complete every command.
            io.write(RESPONSE, 0);
            io.write(ARGUMENT, 0);
            io.write(MESSAGE, message);
            Ok(())
        })??;
        let deadline = narf_time::Deadline::after_ms(1000);
        loop {
            let response = self.access(|io| io.read(RESPONSE))?;
            match response {
                u32::MAX => return Err(Error::DeviceGone),
                1 => return self.access(|io| io.read(ARGUMENT)),
                0 => {}
                status => return Err(Error::Rejected(status)),
            }
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            narf_time::SleepUntil::new(narf_time::Deadline::after_ms(1).as_instant()).await;
        }
    }
    async fn verify_inner(&mut self) -> Result<Versions, Error> {
        let interface = self.query(GET_INTERFACE).await?;
        if interface == u32::MAX {
            return Err(Error::DeviceGone);
        }
        if interface != DRIVER_INTERFACE {
            return Err(Error::InterfaceMismatch(interface));
        }
        let firmware = self.query(GET_VERSION).await?;
        if firmware == u32::MAX {
            return Err(Error::DeviceGone);
        }
        if firmware == 0 {
            return Err(Error::Invalid);
        }
        Ok(Versions {
            firmware,
            interface,
        })
    }
    async fn verify(&mut self) -> Result<Versions, Error> {
        if self.state != State::Prepared {
            return Err(Error::Busy);
        }
        self.state = State::Querying;
        let result = self.verify_inner().await;
        self.state = if result.is_ok() {
            State::Ready
        } else {
            State::Failed
        };
        result
    }
}
#[derive(Debug)]
pub struct Smu {
    engine: Engine<Mmio>,
}
impl Smu {
    /// # Safety
    /// Caller owns this physical GPU's MP1 mailbox and reset/power controls
    /// exclusively, with permanent mappings. PSP must have successfully loaded
    /// SMC for this cold boot, with no mailbox command outstanding. This is not
    /// an attach/resume or firmware-reload path. Exclude legacy SMU helpers.
    pub unsafe fn after_upload(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
    ) -> Result<Self, Error> {
        Ok(Self {
            engine: Engine {
                io: Mmio {
                    regs: gpu.regs,
                    base: mp1_bank(gpu)?,
                },
                authority,
                state: State::Prepared,
            },
        })
    }
    pub fn state(&self) -> State {
        self.engine.state
    }
    /// Query the interface and running firmware version once. Cancellation
    /// retains Querying and prevents replay. Success does not enable DPM.
    pub async fn verify(&mut self) -> Result<Versions, Error> {
        self.engine.verify().await
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_smu_navi22_tests.rs"]
pub(crate) mod tests;
