//! Raphael's SMU 13.0.5 graphics mailbox: the `smu_v13_0_5_ppt.c` messages a
//! GFX bring-up needs, sent with `smu_cmn.c`'s `smu_msg_v1_ops` protocol.
//!
//! PMFW is BIOS-resident on an APU: nothing is loaded, and `start` only proves
//! it runs and reads its versions. The mailbox is `MP1_C2PMSG_2` (message),
//! `_34` (argument) and `_33` (response). `smu_v13_0_5_ppt.c` defines their
//! offsets as `0xbee142 + 0xb00000 / 4` onwards — past the MMIO BAR — so
//! Linux's `RREG32`/`WREG32` reach them through NBIO's PCIE_INDEX2/DATA2:
//! with MP1 segment 0 at 0x16000 they are the SMN addresses below. This is not
//! the display's mailbox; the clock manager's VBIOSSMC messages use
//! `C2PMSG_3/37/38`. Nor is it `amdgpu_smu`'s `C2PMSG_66/82/90` MMIO mailbox,
//! which is Renoir's and Phoenix's.
use crate::{amdgpu::AmdGpu, amdgpu_discovery as discovery, amdgpu_psp_ring::bank};
use narf_bus::{BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, CapError, CapOp, Write};

/// MP1 segment 0, which every `SOC15_REG_OFFSET(MP1, 0, ..)` below adds.
const MP1_BASE: u64 = 0x0001_6000; // linux: n/a (Raphael discovery: MP1 segment 0)
/// SMN byte address of a `smu_v13_0_5_ppt.c` MP1 register.
const fn smn(reg: u64) -> u32 {
    ((MP1_BASE + reg) * 4) as u32
}
const MSG: u32 = smn(0xbee142 + 0xb00000 / 4); // linux: mmMP1_C2PMSG_2
const RESPONSE: u32 = smn(0xbee261 + 0xb00000 / 4); // linux: mmMP1_C2PMSG_33
const ARGUMENT: u32 = smn(0xbee262 + 0xb00000 / 4); // linux: mmMP1_C2PMSG_34
/// `MP1_Public | smnMP1_FIRMWARE_FLAGS` (`smu_v13_0.h`), read by
/// `smu_v13_0_check_fw_status` for every MP1 13.0.x but 13.0.4/13.0.11.
const FIRMWARE_FLAGS: u32 = 0x03b0_0000 | 0x0301_0024; // linux: MP1_Public | smnMP1_FIRMWARE_FLAGS
const INTERRUPTS_ENABLED: u32 = 1 << 0; // linux: MP1_FIRMWARE_FLAGS__INTERRUPTS_ENABLED_MASK

// smu_v13_0_5_ppsmc.h
const MSG_GET_SMU_VERSION: u32 = 2; // linux: PPSMC_MSG_GetSmuVersion
const MSG_POWER_DOWN_VCN: u32 = 5; // linux: PPSMC_MSG_PowerDownVcn
const MSG_POWER_UP_VCN: u32 = 6; // linux: PPSMC_MSG_PowerUpVcn
const MSG_POWER_DOWN_JPEG: u32 = 18; // linux: PPSMC_MSG_PowerDownJpeg
const MSG_POWER_UP_JPEG: u32 = 19; // linux: PPSMC_MSG_PowerUpJpeg
const MSG_ALLOW_GFXOFF: u32 = 22; // linux: PPSMC_MSG_AllowGfxOff
const MSG_DISALLOW_GFXOFF: u32 = 23; // linux: PPSMC_MSG_DisallowGfxOff
const MSG_GET_DRIVER_IF_VERSION: u32 = 25; // linux: PPSMC_MSG_GetDriverIfVersion

const RESP_NONE: u32 = 0; // linux: SMU_RESP_NONE
const RESP_OK: u32 = 1; // linux: PPSMC_Result_OK
const RESP_FAILED: u32 = 0xff; // linux: PPSMC_Result_Failed
const RESP_UNKNOWN: u32 = 0xfe; // linux: PPSMC_Result_UnknownCmd
const RESP_PREREQ: u32 = 0xfd; // linux: PPSMC_Result_CmdRejectedPrereq
const RESP_BUSY: u32 = 0xfc; // linux: PPSMC_Result_CmdRejectedBusy

/// `SMU13_0_5_DRIVER_IF_VERSION`. A firmware reporting another is recorded,
/// not refused: Linux only logs it, and no message here uses a driver table.
pub const DRIVER_IF_VERSION: u32 = 5; // linux: SMU13_0_5_DRIVER_IF_VERSION

/// `smu_cmn.c`'s default: `adev->usec_timeout * 20`, two seconds.
const TIMEOUT_MS: u64 = 2000; // linux: n/a (adev->usec_timeout * 20 us)

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Not Raphael, or its discovery does not match the audited layout.
    Unsupported,
    Revoked,
    /// A register read back all ones.
    DeviceGone,
    /// `MP1_FIRMWARE_FLAGS.INTERRUPTS_ENABLED` is clear: PMFW is not running.
    NotRunning,
    /// No response within the timeout (`-ETIME`).
    Timeout,
    /// The firmware refused the message, with its status.
    Rejected(u32),
    /// An unrecognised response (`-EREMOTEIO`): Linux marks the firmware hung
    /// (`SMU_FW_HANG`) and sends nothing further; so does this.
    Hung,
    /// `start` has not completed.
    NotStarted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Versions {
    /// `GetSmuVersion`: program, major, minor and debug bytes.
    pub smu: u32,
    /// `GetDriverIfVersion`.
    pub driver_if: u32,
}
impl Versions {
    pub fn driver_if_matches(&self) -> bool {
        self.driver_if == DRIVER_IF_VERSION
    }
}

trait Io: Send {
    /// `RREG32_PCIE` / `WREG32_PCIE`.
    fn read_smn(&mut self, address: u32) -> u32;
    fn write_smn(&mut self, address: u32, value: u32);
    /// Read-driven register models can use a bounded number of cooperative
    /// polls instead of a wall-clock deadline. Real MMIO always uses time.
    #[cfg(feature = "kernel-test")]
    fn wait_poll_limit(&self) -> Option<u32> {
        None
    }
}
#[derive(Debug)]
struct Mmio {
    regs: MmioRegion,
    nbio: u64,
}
impl Io for Mmio {
    fn read_smn(&mut self, address: u32) -> u32 {
        // SAFETY: the constructor bounds the NBIO bank through PCIE_DATA2.
        unsafe { crate::amdgpu_smn::read(&self.regs, self.nbio, address) }
    }
    fn write_smn(&mut self, address: u32, value: u32) {
        // SAFETY: as read_smn.
        unsafe { crate::amdgpu_smn::write(&self.regs, self.nbio, address, value) }
    }
}
struct Op<F>(F);
impl<F: FnOnce() -> T, T> CapOp<BusDeviceCap, Write> for Op<F> {
    type Output = T;
    fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<T, CapError> {
        Ok((self.0)())
    }
}

#[derive(Debug)]
struct Engine<I: Io> {
    io: I,
    authority: Cap<BusDeviceCap, Write>,
    /// `SMU_FW_INIT`: the first message skips the wait for a previous one,
    /// since no message has answered yet.
    first: bool,
    hung: bool,
    versions: Option<Versions>,
}
impl<I: Io> Engine<I> {
    fn access<T>(&mut self, f: impl FnOnce(&mut I) -> T) -> Result<T, Error> {
        let io = &mut self.io;
        self.authority
            .invoke(Op(|| f(io)))
            .map_err(|_| Error::Revoked)
    }
    /// `__smu_msg_v1_poll_stat`: wait for a nonzero response.
    async fn poll(&mut self) -> Result<u32, Error> {
        let deadline = narf_time::Deadline::after_ms(TIMEOUT_MS);
        #[cfg(feature = "kernel-test")]
        let mut polls = self.io.wait_poll_limit();
        loop {
            let value = self.access(|io| io.read_smn(RESPONSE))?;
            if value == u32::MAX {
                return Err(Error::DeviceGone);
            }
            if value != RESP_NONE {
                return Ok(value);
            }
            #[cfg(feature = "kernel-test")]
            if let Some(left) = &mut polls {
                if *left == 0 {
                    return Err(Error::Timeout);
                }
                *left -= 1;
                narf_scheduler::yield_now().await;
                continue;
            }
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            narf_time::SleepUntil::new(narf_time::Deadline::after_ms(1).as_instant()).await;
        }
    }
    /// `smu_msg_v1_decode_response` for a completed message.
    fn decode(&mut self, response: u32) -> Result<(), Error> {
        match response {
            RESP_OK => Ok(()),
            RESP_FAILED | RESP_UNKNOWN | RESP_PREREQ | RESP_BUSY => Err(Error::Rejected(response)),
            _ => {
                self.hung = true;
                Err(Error::Hung)
            }
        }
    }
    /// `smu_msg_v1_send_msg` with one argument and one output argument.
    async fn send(&mut self, message: u32, argument: u32) -> Result<u32, Error> {
        if self.hung {
            return Err(Error::Hung);
        }
        if !self.first {
            // The previous message must have completed; a fatal status left
            // by it stops here, as Linux's pre-poll does.
            let previous = self.poll().await?;
            if !matches!(
                previous,
                RESP_OK | RESP_FAILED | RESP_UNKNOWN | RESP_PREREQ | RESP_BUSY
            ) {
                self.hung = true;
                return Err(Error::Hung);
            }
        }
        self.first = false;
        self.access(|io| {
            io.write_smn(RESPONSE, 0);
            io.write_smn(ARGUMENT, argument);
            io.write_smn(MSG, message);
        })?;
        let response = self.poll().await?;
        self.decode(response)?;
        self.access(|io| io.read_smn(ARGUMENT))
    }
    async fn start(&mut self) -> Result<Versions, Error> {
        // smu_v13_0_check_fw_status.
        let flags = self.access(|io| io.read_smn(FIRMWARE_FLAGS))?;
        if flags == u32::MAX {
            return Err(Error::DeviceGone);
        }
        if flags & INTERRUPTS_ENABLED == 0 {
            return Err(Error::NotRunning);
        }
        // smu_cmn_get_smc_version: the interface version first.
        let driver_if = self.send(MSG_GET_DRIVER_IF_VERSION, 0).await?;
        let smu = self.send(MSG_GET_SMU_VERSION, 0).await?;
        let versions = Versions { smu, driver_if };
        self.versions = Some(versions);
        Ok(versions)
    }
    async fn started(&mut self, message: u32) -> Result<(), Error> {
        if self.versions.is_none() {
            return Err(Error::NotStarted);
        }
        self.send(message, 0).await.map(|_| ())
    }
}

/// Raphael's SMU graphics mailbox. Holding it grants the C2PMSG_2/33/34
/// messages only, not the display's VBIOSSMC messages, and no table.
#[derive(Debug)]
pub struct Smu(Engine<Mmio>);
impl Smu {
    /// # Safety
    /// Caller exclusively owns the SMU graphics mailbox (`MP1_C2PMSG_2/33/34`)
    /// for this object's lifetime and holds matching PCI authority and a
    /// permanent register mapping. NBIO's index pair is shared through
    /// `amdgpu_smn`.
    pub unsafe fn new(gpu: &AmdGpu, authority: Cap<BusDeviceCap, Write>) -> Result<Self, Error> {
        let nbio = resolve(gpu)?;
        Ok(Self(Engine {
            io: Mmio {
                regs: gpu.regs,
                nbio,
            },
            authority,
            first: true,
            hung: false,
            versions: None,
        }))
    }
    /// Prove PMFW runs and read its versions. Until this succeeds no other
    /// message is sent.
    pub async fn start(&mut self) -> Result<Versions, Error> {
        self.0.start().await
    }
    pub fn versions(&self) -> Option<Versions> {
        self.0.versions
    }
    /// `smu_v13_0_gfx_off_control` on MP1 13.0.5.
    pub async fn set_gfxoff(&mut self, allow: bool) -> Result<(), Error> {
        let message = if allow {
            MSG_ALLOW_GFXOFF
        } else {
            MSG_DISALLOW_GFXOFF
        };
        self.0.started(message).await
    }
    /// `smu_v13_0_5_dpm_set_vcn_enable`: VCN is power gated by default.
    pub async fn set_vcn_power(&mut self, up: bool) -> Result<(), Error> {
        let message = if up {
            MSG_POWER_UP_VCN
        } else {
            MSG_POWER_DOWN_VCN
        };
        self.0.started(message).await
    }
    /// `smu_v13_0_5_dpm_set_jpeg_enable`.
    pub async fn set_jpeg_power(&mut self, up: bool) -> Result<(), Error> {
        let message = if up {
            MSG_POWER_UP_JPEG
        } else {
            MSG_POWER_DOWN_JPEG
        };
        self.0.started(message).await
    }
}

/// The NBIO bank whose index pair reaches these SMN addresses, after proving
/// the GPU is Raphael with MP1 13.0.5 at the segment the addresses assume.
fn resolve(gpu: &AmdGpu) -> Result<u64, Error> {
    if crate::amdgpu_rdna2::apu_for_pci_id(gpu.chip.vid, gpu.chip.did)
        != Some(&crate::amdgpu_rdna2::RAPHAEL)
    {
        return Err(Error::Unsupported);
    }
    let mp1 =
        bank(gpu, discovery::HW_ID_MP1, &[(13, 0, 5)], 0, 0).map_err(|_| Error::Unsupported)?;
    if mp1 != MP1_BASE * 4 {
        return Err(Error::Unsupported);
    }
    bank(
        gpu,
        discovery::HW_ID_NBIF,
        crate::amdgpu_smn::NBIO_VERSIONS,
        0,
        crate::amdgpu_smn::PCIE_DATA2 as u32,
    )
    .map_err(|_| Error::Unsupported)
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_smu_raphael_tests.rs"]
mod tests;
