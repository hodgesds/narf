//! Phoenix SMU 13.0.4 graphics mailbox: the `smu_v13_0_4_ppsmc.h` messages a
//! GFX bring-up needs, sent over the `C2PMSG_66` (argument) / `82` (message)
//! / `90` (response) MMIO mailbox through the shared `amdgpu_smu`
//! `smu_msg_v1` protocol.
//!
//! PMFW is BIOS-resident on an APU: nothing is loaded, and `start` only proves
//! it runs and reads its versions. The mailbox lives in MP1 window **1**
//! (`regMP0_SMN_C2PMSG_66`, BASE_IDX 1): callers that pass window 0 land in
//! the wrong window (see the LINUX-GAP note in `amdgpu_smu`). This is not
//! Raphael's SMN/NBIO mailbox (`amdgpu_smu_raphael`, 13.0.5) and not the
//! 13.0.0 Navi31 message space (`amdgpu_smu_v13_0`, where e.g. AllowGfxOff
//! is 0x28/0x29). No `FIRMWARE_FLAGS` check: Linux skips it for 13.0.4 and
//! 13.0.11 (`smu_v13_0_check_fw_status`).
use crate::{
    amdgpu::AmdGpu,
    amdgpu_discovery as discovery,
    amdgpu_psp_ring::bank,
    amdgpu_smu::{
        send_message_get, send_message_void, SmuError, SmuMmio, MP1_C2PMSG_RESP_REL,
        SMU_13_0_4_DRIVER_IF_VERSION,
    },
    amdgpu_smu_v13 as v13,
};
use narf_bus::{BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, CapError, CapOp, Write};

/// `SMU_13_0_4_DRIVER_IF_VERSION` as Linux 7.4-rc2 reports it
/// (`smu13_driver_if_v13_0_4.h:30` puts 13.0.4 at 8). NARF still carries
/// 0x07 (see `SMU_13_0_4_DRIVER_IF_VERSION`); a firmware reporting 8 is
/// accepted and recorded, not refused — the bump needs its own lane + CI
/// verdict, and refusing here would brick Phoenix bring-up on newer PMFW.
pub const DRIVER_IF_VERSION_7_4_RC2: u32 = 8;
/// Driver-IF schema versions `start` accepts: NARF's carried 0x07 and the
/// 7.4-rc2 value 8. Anything else fails closed.
pub const ACCEPTED_DRIVER_IF_VERSIONS: [u32; 2] =
    [SMU_13_0_4_DRIVER_IF_VERSION, DRIVER_IF_VERSION_7_4_RC2];

const MODE2_RESET: u32 = 2; // linux: MODE2_RESET
/// `amdgpu_smu::bring_up`'s sentinel, echoed back by `TestMessage`.
const TEST_SENTINEL: u32 = 0xDEAD_BEEF;

// Kept: the test suite scripts this as the success response; production
// matches only failure codes in `Engine::decode`.
#[allow(dead_code)]
const RESP_OK: u32 = 1; // linux: PPSMC_Result_OK
const RESP_FAILED: u32 = 0xff; // linux: PPSMC_Result_Failed
const RESP_UNKNOWN: u32 = 0xfe; // linux: PPSMC_Result_UnknownCmd
const RESP_PREREQ: u32 = 0xfd; // linux: PPSMC_Result_CmdRejectedPrereq
const RESP_BUSY: u32 = 0xfc; // linux: PPSMC_Result_CmdRejectedBusy

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Not Phoenix, or its discovery does not match the audited layout.
    Unsupported,
    Revoked,
    /// A register read back all ones.
    DeviceGone,
    /// No response within the mailbox poll budget (`-ETIME`).
    Timeout,
    /// The firmware refused the message, with its status.
    Rejected(u32),
    /// An unrecognised response (`-EREMOTEIO`): Linux marks the firmware hung
    /// (`SMU_FW_HANG`) and sends nothing further; so does this.
    Hung,
    /// `start` has not completed.
    NotStarted,
    /// `TestMessage` did not echo the sentinel.
    EchoMismatch {
        sent: u32,
        got: u32,
    },
    /// `GetDriverIfVersion` returned a schema version outside
    /// `ACCEPTED_DRIVER_IF_VERSIONS`, with the reported value.
    DriverIfMismatch(u32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Versions {
    /// `GetPmfwVersion`: program, major, minor and debug bytes.
    pub smu: u32,
    /// `GetDriverIfVersion`.
    pub driver_if: u32,
}
impl Versions {
    /// True when the firmware reports the driver-IF schema NARF was
    /// compiled against (0x07). A firmware reporting 8 is accepted by
    /// `start` but does not match; callers that depend on the 0x07
    /// message layout must check this.
    pub fn driver_if_matches(&self) -> bool {
        self.driver_if == SMU_13_0_4_DRIVER_IF_VERSION
    }
}

#[derive(Debug)]
struct Mmio(MmioRegion);
impl SmuMmio for Mmio {
    fn read(&mut self, at: u32) -> u32 {
        // SAFETY: the constructor bounds the MP1 bank through BAR5 and the
        // caller invokes this under live PCI authority.
        unsafe { self.0.read32(u64::from(at)) }
    }
    fn write(&mut self, at: u32, value: u32) {
        // SAFETY: as read.
        unsafe { self.0.write32(u64::from(at), value) };
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
struct Engine<I: SmuMmio> {
    io: I,
    authority: Cap<BusDeviceCap, Write>,
    mp1_base: u32,
    hung: bool,
    versions: Option<Versions>,
}
impl<I: SmuMmio> Engine<I> {
    fn access<T>(&mut self, f: impl FnOnce(&mut I) -> T) -> Result<T, Error> {
        let io = &mut self.io;
        self.authority
            .invoke(Op(|| f(io)))
            .map_err(|_| Error::Revoked)
    }
    /// A vanished device reads back all ones; the shared mailbox poll would
    /// mistake that for a response, so liveness is checked before every
    /// send, mirroring Raphael's poll-site check.
    fn check_alive(&mut self) -> Result<(), Error> {
        let mp1_base = self.mp1_base;
        let resp = self.access(|io| io.read(mp1_base + MP1_C2PMSG_RESP_REL))?;
        if resp == u32::MAX {
            return Err(Error::DeviceGone);
        }
        Ok(())
    }
    /// `smu_msg_v1_decode_response` for a completed message.
    fn decode(&mut self, error: SmuError) -> Error {
        match error {
            SmuError::HandshakeTimeout | SmuError::ResponseTimeout => Error::Timeout,
            SmuError::NoMp1Base => Error::Unsupported,
            SmuError::Rejected(code) => match code {
                RESP_FAILED | RESP_UNKNOWN | RESP_PREREQ | RESP_BUSY => Error::Rejected(code),
                _ => {
                    self.hung = true;
                    Error::Hung
                }
            },
        }
    }
    /// One message through the shared mailbox, with the liveness check and
    /// response decoding on top. The mailbox I/O itself is a bounded sync
    /// spin (`SMU_POLL_BUDGET`); this stays `async` so call sites match
    /// Raphael's and the coordinator's.
    async fn send(&mut self, message: u32, argument: u32) -> Result<u32, Error> {
        if self.hung {
            return Err(Error::Hung);
        }
        self.check_alive()?;
        let base = self.mp1_base;
        let result = self.access(|io| send_message_get(io, base, message, argument))?;
        result.map_err(|e| self.decode(e))
    }
    async fn send_void(&mut self, message: u32, argument: u32) -> Result<(), Error> {
        if self.hung {
            return Err(Error::Hung);
        }
        self.check_alive()?;
        let base = self.mp1_base;
        let result = self.access(|io| send_message_void(io, base, message, argument))?;
        result.map_err(|e| self.decode(e))
    }
    async fn start(&mut self) -> Result<Versions, Error> {
        // `amdgpu_smu::bring_up`'s three steps, with the driver-IF check
        // widened to ACCEPTED_DRIVER_IF_VERSIONS instead of one value.
        // No FIRMWARE_FLAGS check: Linux skips it for 13.0.4/13.0.11.
        let echoed = self.send(v13::V13_MSG_TEST, TEST_SENTINEL).await?;
        if echoed != TEST_SENTINEL {
            return Err(Error::EchoMismatch {
                sent: TEST_SENTINEL,
                got: echoed,
            });
        }
        let smu = self.send(v13::V13_MSG_GET_PMFW_VERSION, 0).await?;
        let driver_if = self.send(v13::V13_MSG_GET_DRIVER_IF, 0).await?;
        if !ACCEPTED_DRIVER_IF_VERSIONS.contains(&driver_if) {
            return Err(Error::DriverIfMismatch(driver_if));
        }
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
        self.send_void(message, argument).await
    }
}

/// Phoenix's SMU graphics mailbox. Holding it grants the C2PMSG_66/82/90
/// messages only, not the display's VBIOSSMC messages, and no table.
#[derive(Debug)]
pub struct Smu(Engine<Mmio>);
impl Smu {
    /// # Safety
    /// Caller exclusively owns the SMU graphics mailbox (`MP1_C2PMSG_66/82/90`,
    /// window 1) for this object's lifetime and holds matching PCI authority
    /// and a permanent register mapping.
    pub unsafe fn new(gpu: &AmdGpu, authority: Cap<BusDeviceCap, Write>) -> Result<Self, Error> {
        let mp1_base = resolve(gpu)?;
        Ok(Self(Engine {
            io: Mmio(gpu.regs),
            authority,
            mp1_base,
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
    /// `smu_v13_0_4_gfx_off_control` on MP1 13.0.4.
    pub async fn set_gfxoff(&mut self, allow: bool) -> Result<(), Error> {
        let message = if allow {
            v13::V13_MSG_ALLOW_GFX_OFF
        } else {
            v13::V13_MSG_DISALLOW_GFX_OFF
        };
        self.0.started(message).await
    }
    /// `smu_v13_0_4_dpm_set_vcn_enable`: VCN is power gated by default.
    pub async fn set_vcn_power(&mut self, up: bool) -> Result<(), Error> {
        let message = if up {
            v13::V13_MSG_POWER_UP_VCN
        } else {
            v13::V13_MSG_POWER_DOWN_VCN
        };
        self.0.started(message).await
    }
    /// `smu_v13_0_4_dpm_set_jpeg_enable`.
    pub async fn set_jpeg_power(&mut self, up: bool) -> Result<(), Error> {
        let message = if up {
            v13::V13_MSG_POWER_UP_JPEG
        } else {
            v13::V13_MSG_POWER_DOWN_JPEG
        };
        self.0.started(message).await
    }
    /// `smu_v13_0_4_mode2_reset`: GfxDeviceDriverReset(MODE2_RESET). PMFW
    /// resets the graphics, SDMA and multimedia engines; nothing they ran
    /// survives.
    ///
    /// # Safety
    /// Every owner of those engines is quiesced and will be rebuilt, as
    /// `amdgpu_raphael_reset::mode2` requires.
    pub async unsafe fn mode2_reset(&mut self) -> Result<(), Error> {
        self.0
            .started_with(v13::V13_MSG_GFX_DEVICE_DRIVER_RESET, MODE2_RESET)
            .await
    }
}

/// The MP1 window-1 base, after proving the GPU is Phoenix (not Strix, which
/// shares `Family::Phoenix` but is RDNA3.5 with its own SMU) with MP1
/// 13.0.4 or 13.0.11 — the two MP1 versions Linux's `soc21.c` covers with
/// the 13.0.4 driver. `last` is `C2PMSG_90`, the highest mailbox dword.
fn resolve(gpu: &AmdGpu) -> Result<u32, Error> {
    if !matches!(
        (gpu.chip.vid, gpu.chip.did),
        (crate::amdgpu::AMD_VENDOR, crate::amdgpu::PHOENIX_HAWKPOINT1)
            | (crate::amdgpu::AMD_VENDOR, crate::amdgpu::PHOENIX1)
            | (crate::amdgpu::AMD_VENDOR, crate::amdgpu::PHOENIX2)
    ) {
        return Err(Error::Unsupported);
    }
    let base = bank(
        gpu,
        discovery::HW_ID_MP1,
        &[(13, 0, 4), (13, 0, 11)],
        1,
        0x29a,
    )
    .map_err(|_| Error::Unsupported)?;
    u32::try_from(base).map_err(|_| Error::Unsupported)
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_smu_phoenix_tests.rs"]
mod tests;
