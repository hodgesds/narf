//! Navi22 SMC preparation and a cold-start SMU11 version handshake. Linux
//! `smu_v11_0.c`, `sienna_cichlid_ppt.c`, `smu_v11_0_7_ppsmc.h` and
//! `mp_11_0_offset.h`: MP1 index 0, message=66, argument=82, response=90.
//! Board tables use a retained VRAM transfer buffer. Cold-boot power setup
//! enables a restricted GFX DPM and autonomous protection policy.
use crate::{amdgpu::AmdGpu, amdgpu_discovery as discovery, amdgpu_smc_firmware as firmware};
use alloc::vec::Vec;
use narf_bus::{BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, CapError, CapOp, Read, Write};

const MESSAGE: u32 = 0x282;
const ARGUMENT: u32 = 0x292;
const RESPONSE: u32 = 0x29a;
const GET_VERSION: u32 = 2;
const GET_INTERFACE: u32 = 3;
const SET_DRIVER_HIGH: u32 = 0xe;
const SET_DRIVER_LOW: u32 = 0xf;
const TRANSFER_TABLE: u32 = 0x13;
const RUN_DC_BTC: u32 = 0x36;
const ALLOWED_HIGH: u32 = 5;
const ALLOWED_LOW: u32 = 4;
const ENABLE_FEATURES: u32 = 6;
const RUNNING_LOW: u32 = 0xc;
const RUNNING_HIGH: u32 = 0xd;
const MIN_DPM_FREQ: u32 = 0x1d;
const MAX_DPM_FREQ: u32 = 0x1e;
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
    PowerPolicy(u32),
    Features { allowed: u64, enabled: u64 },
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
    UploadingPowerTable,
    PowerTableReady,
    ConfiguringPower,
    PowerReady,
    EnablingDisplayPower,
    DisplayPowerReady,
    Failed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Versions {
    pub firmware: u32,
    pub interface: u32,
}
/// Observed SMU policy and board frequency limits, not a clock override.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PowerStatus {
    pub allowed: u64,
    pub enabled: u64,
    pub gfx_min_mhz: u16,
    pub gfx_max_mhz: u16,
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
    fn stage_power(
        &mut self,
        memory: &crate::amdgpu_vram::Reservation,
        bytes: &[u8],
    ) -> Result<(), Error>;
}
#[derive(Debug)]
struct Mmio {
    regs: MmioRegion,
    base: u64,
    vram: MmioRegion,
    vram_size: u64,
    nbio: Option<u64>,
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
    fn stage_power(
        &mut self,
        memory: &crate::amdgpu_vram::Reservation,
        bytes: &[u8],
    ) -> Result<(), Error> {
        let nbio = self.nbio.ok_or(Error::Unsupported)?;
        let base = self.vram_size.checked_sub(1 << 20).ok_or(Error::Invalid)?;
        // SAFETY: exclusive GPU/index-latch ownership inherited from the SMU
        // constructor and uploader; this entire method runs in Cap::invoke.
        let mut reader =
            unsafe { crate::amdgpu_vram_access::MmioReader::new(&self.vram, &self.regs) };
        power_policy(|offset, out| {
            crate::amdgpu_vram_access::read(&mut reader, self.vram_size, base + offset as u64, out)
                .map_err(|_| crate::amdgpu_gddr6::Error::Invalid)
        })?;
        // PSP ring startup already installed this exact HDP flush remapping.
        // Refuse a changed mapping instead of racing another HDP owner.
        // SAFETY: nbio and remap hole were bounded at construction.
        if unsafe { self.regs.read32(nbio + 0x12d * 4) } != 0x7f000 {
            return Err(Error::Invalid);
        }
        let mapping = memory.mapping();
        for (index, word) in bytes.chunks_exact(4).enumerate() {
            // SAFETY: the owned reservation is larger than this validated
            // table; its permanent mapping belongs to this GPU's VRAM pool.
            unsafe {
                mapping.write32(
                    index as u64 * 4,
                    u32::from_le_bytes(word.try_into().unwrap()),
                )
            };
        }
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        // SAFETY: verified remap; MEMSIZE read drains the posted flush write.
        unsafe {
            self.regs.write32(0x7f000, 0);
            self.regs.read32(nbio + 0xc3 * 4);
        }
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
}
fn power_policy(
    read: impl FnMut(usize, &mut [u8]) -> Result<(), crate::amdgpu_gddr6::Error>,
) -> Result<(), Error> {
    let scpm = crate::amdgpu_gddr6::runtime_entry::<4>(read, 6)
        .map_err(|_| Error::Invalid)?
        .map_or(0, u32::from_le_bytes);
    if scpm != 0 {
        return Err(Error::PowerPolicy(scpm));
    }
    Ok(())
}
#[derive(Debug)]
struct Engine<I: Io> {
    io: I,
    authority: Cap<BusDeviceCap, Write>,
    state: State,
    // SMU retains DriverDramAddr even after acknowledgement. Keep this buffer
    // for the lifetime of the owner; Drop quarantines published allocations.
    power_memory: Option<crate::amdgpu_vram::Reservation>,
    power_policy: Option<crate::amdgpu_power_navi22::BootPolicy>,
}
impl<I: Io> Engine<I> {
    fn access<T>(&mut self, f: impl FnOnce(&mut I) -> T) -> Result<T, Error> {
        let io = &mut self.io;
        self.authority
            .invoke(Op(|| f(io)))
            .map_err(|_| Error::Revoked)
    }
    async fn query(&mut self, message: u32) -> Result<u32, Error> {
        self.command(message, 0).await
    }
    async fn command(&mut self, message: u32, parameter: u32) -> Result<u32, Error> {
        self.access(|io| {
            if io.read(RESPONSE) == u32::MAX {
                return Err(Error::DeviceGone);
            }
            // A freshly loaded SMU may leave response=0. Linux's first message
            // skips pre-poll; after that we own and complete every command.
            io.write(RESPONSE, 0);
            io.write(ARGUMENT, parameter);
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
    async fn upload(&mut self, bytes: &[u8], pool: &crate::amdgpu_vram::Pool) -> Result<(), Error> {
        if self.state != State::Ready {
            return Err(Error::Busy);
        }
        if bytes.len() != crate::amdgpu_power_navi22::SMC_BYTES {
            return Err(Error::Invalid);
        }
        let mut memory = pool
            .reserve(bytes.len() as u64)
            .map_err(|_| Error::Allocation)?;
        self.state = State::UploadingPowerTable;
        let result = async {
            self.access(|io| io.stage_power(&memory, bytes))??;
            let address = memory.address();
            memory.publish();
            self.power_memory = Some(memory);
            self.command(SET_DRIVER_HIGH, (address >> 32) as u32)
                .await?;
            self.command(SET_DRIVER_LOW, address as u32).await?;
            // TABLE_PPTABLE == 0; upper 16 bits (table argument) also zero.
            self.command(TRANSFER_TABLE, 0).await?;
            Ok(())
        }
        .await;
        self.state = if result.is_ok() {
            State::PowerTableReady
        } else {
            State::Failed
        };
        result
    }
    async fn configure_power(&mut self) -> Result<PowerStatus, Error> {
        if self.state != State::PowerTableReady {
            return Err(Error::Busy);
        }
        let policy = self.power_policy.ok_or(Error::Invalid)?;
        self.state = State::ConfiguringPower;
        let result = async {
            self.command(RUN_DC_BTC, 0).await?;
            self.command(ALLOWED_HIGH, (policy.allowed() >> 32) as u32)
                .await?;
            self.command(ALLOWED_LOW, policy.allowed() as u32).await?;
            self.command(ENABLE_FEATURES, 0).await?;
            let low = self.command(RUNNING_LOW, 0).await?;
            let high = self.command(RUNNING_HIGH, 0).await?;
            let enabled = u64::from(low) | (u64::from(high) << 32);
            if !policy.validate_enabled(enabled) {
                return Err(Error::Features {
                    allowed: policy.allowed(),
                    enabled,
                });
            }
            // PPCLK_GFXCLK == 0 in the upper 16 bits. Read only: leave the
            // board's frequency/voltage limits intact and use automatic DPM.
            let min = self.command(MIN_DPM_FREQ, 0).await?;
            let max = self.command(MAX_DPM_FREQ, 0).await?;
            if min == 0 || min > max || max > u32::from(u16::MAX) {
                return Err(Error::Invalid);
            }
            Ok(PowerStatus {
                allowed: policy.allowed(),
                enabled,
                gfx_min_mhz: min as u16,
                gfx_max_mhz: max as u16,
            })
        }
        .await;
        self.state = if result.is_ok() {
            State::PowerReady
        } else {
            State::Failed
        };
        result
    }
    async fn enable_display_power(&mut self) -> Result<(), Error> {
        if self.state == State::DisplayPowerReady {
            return self.access(|_| ());
        }
        if self.state != State::PowerReady {
            return Err(Error::Busy);
        }
        let policy = self.power_policy.ok_or(Error::Invalid)?;
        let allowed = policy.display_allowed().map_err(|_| Error::Unsupported)?;
        self.state = State::EnablingDisplayPower;
        let result = async {
            self.command(ALLOWED_HIGH, (allowed >> 32) as u32).await?;
            self.command(ALLOWED_LOW, allowed as u32).await?;
            self.command(ENABLE_FEATURES, 0).await?;
            let low = self.command(RUNNING_LOW, 0).await?;
            let high = self.command(RUNNING_HIGH, 0).await?;
            let enabled = u64::from(low) | u64::from(high) << 32;
            if !policy.validate_display(enabled) {
                return Err(Error::Features { allowed, enabled });
            }
            Ok(())
        }
        .await;
        self.state = if result.is_ok() {
            State::DisplayPowerReady
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
    /// Every display pipe and stream on this physical GPU must be retired.
    /// The exclusive DCN owner must install memory/fabric/display floors before
    /// enabling another stream. Cancellation retains EnablingDisplayPower.
    pub(crate) async unsafe fn enable_display_power(&mut self) -> Result<(), Error> {
        self.engine.enable_display_power().await
    }
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
                    vram: gpu.fb_bar,
                    vram_size: gpu.vram.size,
                    nbio: if gpu.regs.len >= 0x7f004 {
                        crate::amdgpu_psp_ring::bank(
                            gpu,
                            discovery::HW_ID_NBIF,
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
                        .ok()
                    } else {
                        None
                    },
                },
                authority,
                state: State::Prepared,
                power_memory: None,
                power_policy: None,
            },
        })
    }
    pub fn state(&self) -> State {
        self.engine.state
    }
    /// Send the prepared board table once after the version handshake. This
    /// does not enable DPM or run BTC. Nonzero/invalid PSP SCPM policy refuses
    /// the transfer before publishing an address or writing SMU commands.
    ///
    /// # Safety
    /// Caller owns this GPU's CPU-visible pool, HDP remap and VRAM index latch,
    /// with trained VRAM and completed PSP startup. The pool must use this
    /// GPU's GMC addresses and permanent mappings with all clients excluded.
    /// The table must come from this GPU's VBIOS, SMC image and PCI identity.
    /// Retain the SMU owner through failure/cancellation; do not reset or
    /// reuse its transfer buffer without independent hardware recovery.
    pub async unsafe fn upload_power_table(
        &mut self,
        table: &crate::amdgpu_power_navi22::Prepared,
        pool: &crate::amdgpu_vram::Pool,
    ) -> Result<(), Error> {
        let policy = table.boot_policy().map_err(|_| Error::Unsupported)?;
        self.engine.upload(table.bytes(), pool).await?;
        self.engine.power_policy = Some(policy);
        Ok(())
    }
    /// Run board calibration and enable the uploaded table's restricted boot
    /// policy once. Retains the owner/buffer on error or cancellation.
    ///
    /// # Safety
    /// All upload ownership contracts still apply. RLC autoload must have
    /// completed and queues must remain idle. This must precede any workload.
    /// Native DCN clock policy and OS thermal interrupt handling are separate.
    pub async unsafe fn configure_power(&mut self) -> Result<PowerStatus, Error> {
        self.engine.configure_power().await
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
