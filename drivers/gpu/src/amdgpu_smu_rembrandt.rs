//! Rembrandt's SMU 13.0.1/13.0.3 graphics mailbox: the `smu_v13_0_1_ppsmc.h`
//! messages a GFX bring-up needs, sent with `smu_cmn.c`'s `smu_msg_v1_ops` protocol.
//!
//! PMFW is BIOS-resident on an APU: nothing is loaded, and `start` only proves
//! it runs — a TestMessage echo, then its versions — in `amdgpu_smu::bring_up`'s
//! order. The mailbox is `MP1_C2PMSG_66` (argument), `_82` (message) and `_90`
//! (response) on MP1 window 0: the generic `psp_v13_0` family puts every C2PMSG
//! register on `_BASE_IDX` 0 (`mp_13_0_0/13_0_2/13_0_5_offset.h`), Phoenix's
//! 13.0.4 alone on 1. This is not the display's mailbox (C2PMSG_67/83/91, the
//! same window) nor Raphael's SMN route (C2PMSG_2/33/34 through
//! PCIE_INDEX2/DATA2).
use crate::{
    amdgpu::AmdGpu,
    amdgpu_discovery as discovery,
    amdgpu_psp_ring::bank,
    amdgpu_smu::{MP1_C2PMSG_ARG_REL, MP1_C2PMSG_MSG_REL, MP1_C2PMSG_RESP_REL},
};
use narf_bus::{BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, CapError, CapOp, Write};

/// `MP1_SMN_C2PMSG_66` — argument register (host → SMU), byte offset within
/// the MP1 window.
const ARGUMENT: u32 = MP1_C2PMSG_ARG_REL;
/// `MP1_SMN_C2PMSG_82` — message-id register (host → SMU).
const MSG: u32 = MP1_C2PMSG_MSG_REL;
/// `MP1_SMN_C2PMSG_90` — response register (SMU → host).
const RESPONSE: u32 = MP1_C2PMSG_RESP_REL;

// smu_v13_0_1_ppsmc.h (the same numbering as 13.0.4's)
const MSG_TEST_MESSAGE: u32 = crate::amdgpu_smu_v13::V13_MSG_TEST; // linux: PPSMC_MSG_TestMessage
const MSG_GET_SMU_VERSION: u32 = crate::amdgpu_smu_v13::V13_MSG_GET_PMFW_VERSION; // linux: PPSMC_MSG_GetSmuVersion
const MSG_GET_DRIVER_IF_VERSION: u32 = crate::amdgpu_smu_v13::V13_MSG_GET_DRIVER_IF; // linux: PPSMC_MSG_GetDriverIfVersion
const MSG_POWER_DOWN_VCN: u32 = crate::amdgpu_smu_v13::V13_MSG_POWER_DOWN_VCN; // linux: PPSMC_MSG_PowerDownVcn
const MSG_POWER_UP_VCN: u32 = crate::amdgpu_smu_v13::V13_MSG_POWER_UP_VCN; // linux: PPSMC_MSG_PowerUpVcn
const MSG_POWER_DOWN_JPEG: u32 = 0x21; // linux: PPSMC_MSG_PowerDownJpeg
const MSG_POWER_UP_JPEG: u32 = 0x22; // linux: PPSMC_MSG_PowerUpJpeg
const MSG_ALLOW_GFXOFF: u32 = crate::amdgpu_smu_v13::V13_MSG_ALLOW_GFX_OFF; // linux: PPSMC_MSG_AllowGfxOff
const MSG_DISALLOW_GFXOFF: u32 = crate::amdgpu_smu_v13::V13_MSG_DISALLOW_GFX_OFF; // linux: PPSMC_MSG_DisallowGfxOff
const MSG_GFX_DEVICE_DRIVER_RESET: u32 = 0x11; // linux: PPSMC_MSG_GfxDeviceDriverReset
const MODE2_RESET: u32 = 2; // linux: MODE2_RESET

/// `amdgpu_smu::bring_up`'s TestMessage sentinel: the argument PMFW echoes.
const SENTINEL: u32 = 0xDEAD_BEEF;

const RESP_NONE: u32 = 0; // linux: SMU_RESP_NONE
const RESP_OK: u32 = 1; // linux: PPSMC_Result_OK
const RESP_FAILED: u32 = 0xff; // linux: PPSMC_Result_Failed
const RESP_UNKNOWN: u32 = 0xfe; // linux: PPSMC_Result_UnknownCmd
const RESP_PREREQ: u32 = 0xfd; // linux: PPSMC_Result_CmdRejectedPrereq
const RESP_BUSY: u32 = 0xfc; // linux: PPSMC_Result_CmdRejectedBusy

/// `SMU13_YELLOW_CARP_DRIVER_IF_VERSION`. A firmware reporting another is
/// recorded, not refused: Linux only logs it, and no message here uses a
/// driver table.
pub const DRIVER_IF_VERSION: u32 = 4; // linux: SMU13_YELLOW_CARP_DRIVER_IF_VERSION

/// `smu_cmn.c`'s default: `adev->usec_timeout * 20`, two seconds.
const TIMEOUT_MS: u64 = 2000; // linux: n/a (adev->usec_timeout * 20 us)

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Not Rembrandt, or its discovery does not match the audited layout.
    Unsupported,
    Revoked,
    /// A register read back all ones.
    DeviceGone,
    /// No response within the timeout (`-ETIME`).
    Timeout,
    /// The TestMessage argument did not echo back (`-EREMOTEIO`):
    /// the mailbox answered but the argument did not round-trip.
    EchoMismatch,
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
    /// MMIO dword read at a byte offset within the MP1 window.
    fn read(&mut self, address: u32) -> u32;
    fn write(&mut self, address: u32, value: u32);
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
    /// MP1 window-0 base, byte address in `regs`.
    base: u64,
}
impl Io for Mmio {
    fn read(&mut self, address: u32) -> u32 {
        // SAFETY: the constructor bounds the MP1 window-0 bank past the
        // response register.
        unsafe { self.regs.read32(self.base + u64::from(address)) }
    }
    fn write(&mut self, address: u32, value: u32) {
        // SAFETY: as read.
        unsafe { self.regs.write32(self.base + u64::from(address), value) }
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
            let value = self.access(|io| io.read(RESPONSE))?;
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
            io.write(RESPONSE, 0);
            io.write(ARGUMENT, argument);
            io.write(MSG, message);
        })?;
        let response = self.poll().await?;
        self.decode(response)?;
        self.access(|io| io.read(ARGUMENT))
    }
    async fn start(&mut self) -> Result<Versions, Error> {
        // amdgpu_smu::bring_up step 1: the TestMessage echo proves PMFW runs.
        let echoed = self.send(MSG_TEST_MESSAGE, SENTINEL).await?;
        if echoed != SENTINEL {
            return Err(Error::EchoMismatch);
        }
        // Step 2: GetSmuVersion. Step 3: GetDriverIfVersion.
        let smu = self.send(MSG_GET_SMU_VERSION, 0).await?;
        let driver_if = self.send(MSG_GET_DRIVER_IF_VERSION, 0).await?;
        let versions = Versions { smu, driver_if };
        self.versions = Some(versions);
        Ok(versions)
    }
    async fn started(&mut self, message: u32) -> Result<(), Error> {
        self.started_with(message, 0).await
    }
    async fn started_with(&mut self, message: u32, argument: u32) -> Result<(), Error> {
        if self.versions.is_none() {
            return Err(Error::NotStarted);
        }
        self.send(message, argument).await.map(|_| ())
    }
}

/// Rembrandt's SMU graphics mailbox. Holding it grants the C2PMSG_66/82/90
/// messages only, not the display's VBIOSSMC messages, and no table.
#[derive(Debug)]
pub struct Smu(Engine<Mmio>);
impl Smu {
    /// # Safety
    /// Caller exclusively owns the SMU graphics mailbox (`MP1_C2PMSG_66/82/90`
    /// on window 0) for this object's lifetime and holds matching PCI authority
    /// and a permanent register mapping.
    pub unsafe fn new(gpu: &AmdGpu, authority: Cap<BusDeviceCap, Write>) -> Result<Self, Error> {
        let base = resolve(gpu)?;
        Ok(Self(Engine {
            io: Mmio {
                regs: gpu.regs,
                base,
            },
            authority,
            first: true,
            hung: false,
            versions: None,
        }))
    }
    /// Prove PMFW runs (TestMessage echo) and read its versions. Until this
    /// succeeds no other message is sent.
    pub async fn start(&mut self) -> Result<Versions, Error> {
        self.0.start().await
    }
    pub fn versions(&self) -> Option<Versions> {
        self.0.versions
    }
    /// `smu_v13_0_gfx_off_control` on MP1 13.0.1/13.0.3.
    pub async fn set_gfxoff(&mut self, allow: bool) -> Result<(), Error> {
        let message = if allow {
            MSG_ALLOW_GFXOFF
        } else {
            MSG_DISALLOW_GFXOFF
        };
        self.0.started(message).await
    }
    /// `yellow_carp_dpm_set_vcn_enable`: VCN is power gated by default.
    pub async fn set_vcn_power(&mut self, up: bool) -> Result<(), Error> {
        let message = if up {
            MSG_POWER_UP_VCN
        } else {
            MSG_POWER_DOWN_VCN
        };
        self.0.started(message).await
    }
    /// `yellow_carp_dpm_set_jpeg_enable`.
    pub async fn set_jpeg_power(&mut self, up: bool) -> Result<(), Error> {
        let message = if up {
            MSG_POWER_UP_JPEG
        } else {
            MSG_POWER_DOWN_JPEG
        };
        self.0.started(message).await
    }
    /// GfxDeviceDriverReset(MODE2_RESET). PMFW resets the graphics, SDMA and
    /// multimedia engines; nothing they ran survives.
    ///
    /// # Safety
    /// Every owner of those engines is quiesced and will be rebuilt, as
    /// `amdgpu_rembrandt_reset::mode2` requires.
    pub async unsafe fn mode2_reset(&mut self) -> Result<(), Error> {
        self.0
            .started_with(MSG_GFX_DEVICE_DRIVER_RESET, MODE2_RESET)
            .await
    }
}

/// The MP1 window-0 base, after proving the GPU is Rembrandt with MP1
/// 13.0.1/13.0.3 whose window extends past the response register.
fn resolve(gpu: &AmdGpu) -> Result<u64, Error> {
    if crate::amdgpu_rdna2::apu_for_pci_id(gpu.chip.vid, gpu.chip.did)
        != Some(&crate::amdgpu_rdna2::REMBRANDT)
    {
        return Err(Error::Unsupported);
    }
    bank(
        gpu,
        discovery::HW_ID_MP1,
        &[(13, 0, 1), (13, 0, 3)],
        0,
        RESPONSE / 4,
    )
    .map_err(|_| Error::Unsupported)
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_smu_rembrandt_tests.rs"]
mod tests;
