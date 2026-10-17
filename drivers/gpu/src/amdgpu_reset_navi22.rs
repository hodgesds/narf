//! Navi22 reset on init. A GOP-posted discrete card already runs the
//! VBIOS-started SOS and PMFW; Linux never loads driver firmware over them.
//! `nv_need_reset_on_init` detects the SOS sign of life (MP0 C2PMSG_81) and
//! `amdgpu_device_mode1_reset` resets the ASIC before any IP block starts:
//! MP1 11.0.11 selects AMD_RESET_METHOD_MODE1, issued through PMFW
//! (`smu_v11_0_mode1_reset`) when `sienna_cichlid_is_mode1_reset_supported`,
//! else through the PSP (`psp_v11_0_mode1_reset`). The reset loses PCI config
//! state, including Resizable BAR sizes, so it is cached and restored here
//! before any MMIO, then the PSP bootloader and NBIO MEMSIZE are awaited.
//! The same reset core serves post-boot recovery (`Reset::new_recovery`):
//! `amdgpu_device_gpu_recover` resets unconditionally, without the SOS
//! sign-of-life decision.
use crate::{amdgpu::AmdGpu, amdgpu_discovery as discovery};
use narf_bus::{pci, BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, CapError, CapOp, Write};

// mp_11_0_offset.h, MP0/MP1 base index 0.
const BOOTLOADER: u32 = 0x63; // MP0_SMN_C2PMSG_35
const TOS: u32 = 0x80; // MP0_SMN_C2PMSG_64
const SOS: u32 = 0x91; // MP0_SMN_C2PMSG_81
const MESSAGE: u32 = 0x282; // MP1_SMN_C2PMSG_66
const ARGUMENT: u32 = 0x292; // MP1_SMN_C2PMSG_82
const RESPONSE: u32 = 0x29a; // MP1_SMN_C2PMSG_90
                             // nbio_2_3_offset.h.
const SCRATCH_3: u32 = 0x3b; // BIOS_SCRATCH_3, base index 1
const MEMSIZE: u32 = 0xc3; // RCC_DEV0_EPF0_RCC_CONFIG_MEMSIZE, base index 2
const NBIF: &[(u8, u8, u8)] = &[(2, 3, 0), (2, 3, 1), (2, 3, 2), (3, 3, 0), (3, 3, 1)];
// smu_v11_0_7_ppsmc.h.
const GET_SMU_VERSION: u32 = 0x2;
const MODE1_RESET: u32 = 0x30;
/// "PM FW support mode1 reset from 58.26".
const SMU_MODE1_MIN_VERSION: u32 = 0x003a_1a00;
const GFX_CTRL_CMD_ID_MODE1_RST: u32 = 0x0007_0000;
// MBOX_TOS_READY_FLAG / MBOX_TOS_READY_MASK and the bootloader ready bit.
const READY: u32 = 0x8000_0000;
const READY_MASK: u32 = 0x8000_ffff;
const ATOM_S3_ASIC_GUI_ENGINE_HUNG: u32 = 0x2000_0000;
/// SMU11_MODE1_RESET_WAIT_TIME_IN_MS, and the PSP path's msleep(500).
const SETTLE_MS: u64 = 500;
/// psp_v11_0_wait_for_bootloader: 20 retries of a 100 ms register wait.
const BOOTLOADER_MS: u64 = 2000;
/// adev->usec_timeout for the PSP mailbox and MEMSIZE waits.
const REGISTER_MS: u64 = 100;
/// smu_cmn message timeout (usec_timeout * 20).
const MESSAGE_MS: u64 = 2000;
const PCI_EXPRESS: u8 = 0x10;
const RESIZABLE_BAR: u16 = 0x15;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    Invalid,
    Revoked,
    Busy,
    DeviceGone,
    Timeout,
    Rejected(u32),
    /// PSP did not report TOS ready before the PSP mode1 command.
    PspNotReady(u32),
    /// Config-space save/restore failed or did not read back.
    Pci,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Smu,
    Psp,
}

/// Evidence of one completed reset, retained for boot diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Report {
    pub method: Method,
    /// Running PMFW version, when it answered GetSmuVersion.
    pub smu_version: Option<u32>,
    pub sos_before: u32,
    pub sos_after: u32,
    pub memsize: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Prepared,
    /// Also the state retained after cancellation: replay is refused.
    Resetting,
    /// SOS was not running, so the card is already cold.
    NotRequired,
    Complete(Report),
    Failed,
}

struct Op<F>(F);
impl<F: FnOnce() -> T, T> CapOp<BusDeviceCap, Write> for Op<F> {
    type Output = T;
    fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<T, CapError> {
        Ok((self.0)())
    }
}

trait Io {
    fn mp0(&mut self, register: u32) -> u32;
    fn set_mp0(&mut self, register: u32, value: u32);
    fn mp1(&mut self, register: u32) -> u32;
    fn set_mp1(&mut self, register: u32, value: u32);
    fn scratch(&mut self) -> u32;
    fn set_scratch(&mut self, value: u32);
    fn memsize(&mut self) -> u32;
    /// amdgpu_device_cache_pci_state followed by pci_clear_master.
    fn save_and_quiesce(&mut self, authority: &Cap<BusDeviceCap, Write>) -> Result<(), Error>;
    /// amdgpu_device_load_pci_state; verifies BARs and Resizable BAR sizes.
    fn restore(&mut self, authority: &Cap<BusDeviceCap, Write>) -> Result<(), Error>;
}

/// PCIe capability control words and Resizable BAR controls, which the
/// type-0 header snapshot does not include.
#[derive(Clone, Copy, Debug)]
struct PciState {
    header: pci::SavedPciConfig,
    // (capability offset, DevCtl, LnkCtl, DevCtl2, LnkCtl2)
    express: Option<(u16, [u16; 4])>,
    rebar: [(u16, u32); 6],
    rebar_count: usize,
}
const EXPRESS_CONTROLS: [u16; 4] = [0x08, 0x10, 0x28, 0x30];

fn config(cap: &Cap<BusDeviceCap, Write>, device: &BusDevice, offset: u16) -> Result<u32, Error> {
    pci::read_config32(cap, device, offset).map_err(|_| Error::Pci)
}

fn save(cap: &Cap<BusDeviceCap, Write>, device: &BusDevice) -> Result<PciState, Error> {
    let header = pci::save_config(cap, device).map_err(|_| Error::Pci)?;
    let mut express = None;
    let mut pointer = (config(cap, device, 0x34)? & 0xfc) as u16;
    for _ in 0..48 {
        if pointer < 0x40 {
            break;
        }
        let header = config(cap, device, pointer)?;
        if header as u8 == PCI_EXPRESS {
            let mut controls = [0; 4];
            for (control, offset) in controls.iter_mut().zip(EXPRESS_CONTROLS) {
                *control = config(cap, device, pointer + offset)? as u16;
            }
            express = Some((pointer, controls));
            break;
        }
        pointer = ((header >> 8) & 0xfc) as u16;
    }
    let mut rebar = [(0, 0); 6];
    let mut rebar_count = 0;
    let mut offset = 0x100u16;
    for _ in 0..64 {
        let header = config(cap, device, offset)?;
        if header == 0 || header == u32::MAX {
            break;
        }
        if header as u16 == RESIZABLE_BAR {
            let count = ((config(cap, device, offset + 8)? >> 5) & 7) as usize;
            if count == 0 || count > rebar.len() {
                return Err(Error::Pci);
            }
            for (index, entry) in rebar.iter_mut().take(count).enumerate() {
                let control = offset + 8 + 8 * index as u16;
                *entry = (control, config(cap, device, control)?);
            }
            rebar_count = count;
            break;
        }
        offset = ((header >> 20) & 0xffc) as u16;
        if offset < 0x100 {
            break;
        }
    }
    Ok(PciState {
        header,
        express,
        rebar,
        rebar_count,
    })
}

// pci_restore_state order: PCIe controls, Resizable BAR, then the header
// with the command register last so decoding resumes at the saved BARs.
fn restore(
    cap: &Cap<BusDeviceCap, Write>,
    device: &BusDevice,
    state: &PciState,
) -> Result<(), Error> {
    let write = |offset, value| pci::write_config32(cap, device, offset, value);
    if let Some((pointer, controls)) = state.express {
        for (control, offset) in controls.iter().zip(EXPRESS_CONTROLS) {
            // Zero upper halves: their status bits are RW1C.
            write(pointer + offset, u32::from(*control)).map_err(|_| Error::Pci)?;
        }
    }
    for &(offset, control) in &state.rebar[..state.rebar_count] {
        write(offset, control).map_err(|_| Error::Pci)?;
    }
    pci::restore_config(cap, device, &state.header).map_err(|_| Error::Pci)?;
    for &(offset, control) in &state.rebar[..state.rebar_count] {
        // Only the size and index fields are guaranteed to read back.
        if config(cap, device, offset)? & 0x3f07 != control & 0x3f07 {
            return Err(Error::Pci);
        }
    }
    let after = pci::save_config(cap, device).map_err(|_| Error::Pci)?;
    if after.bars != state.header.bars {
        return Err(Error::Pci);
    }
    Ok(())
}

#[derive(Debug)]
struct Mmio {
    regs: MmioRegion,
    mp0: u64,
    mp1: u64,
    scratch: u64,
    memsize: u64,
    device: BusDevice,
    saved: Option<PciState>,
}
impl Mmio {
    fn read(&self, base: u64, register: u32) -> u32 {
        // SAFETY: each base was bounded for its last register by bank(); the
        // BAR5 mapping is permanent and restored before any post-reset access.
        unsafe { self.regs.read32(base + u64::from(register) * 4) }
    }
    fn write(&self, base: u64, register: u32, value: u32) {
        // SAFETY: same bounds; the reset owner excludes every other client.
        unsafe { self.regs.write32(base + u64::from(register) * 4, value) }
    }
}
impl Io for Mmio {
    fn mp0(&mut self, register: u32) -> u32 {
        self.read(self.mp0, register)
    }
    fn set_mp0(&mut self, register: u32, value: u32) {
        self.write(self.mp0, register, value)
    }
    fn mp1(&mut self, register: u32) -> u32 {
        self.read(self.mp1, register)
    }
    fn set_mp1(&mut self, register: u32, value: u32) {
        self.write(self.mp1, register, value)
    }
    fn scratch(&mut self) -> u32 {
        self.read(self.scratch, SCRATCH_3)
    }
    fn set_scratch(&mut self, value: u32) {
        self.write(self.scratch, SCRATCH_3, value)
    }
    fn memsize(&mut self) -> u32 {
        self.read(self.memsize, MEMSIZE)
    }
    fn save_and_quiesce(&mut self, authority: &Cap<BusDeviceCap, Write>) -> Result<(), Error> {
        self.saved = Some(save(authority, &self.device)?);
        pci::clear_command(authority, &self.device, pci::cmd::BUS_MASTER)
            .map(|_| ())
            .map_err(|_| Error::Pci)
    }
    fn restore(&mut self, authority: &Cap<BusDeviceCap, Write>) -> Result<(), Error> {
        restore(
            authority,
            &self.device,
            self.saved.as_ref().ok_or(Error::Invalid)?,
        )
    }
}

/// Why the reset runs; only reset-on-init may skip a cold card.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// `nv_need_reset_on_init`: reset only when SOS is running.
    OnInit,
    /// `amdgpu_device_gpu_recover` with AMD_RESET_METHOD_MODE1: always.
    Recovery,
}
#[derive(Debug)]
struct Engine<I: Io> {
    io: I,
    authority: Cap<BusDeviceCap, Write>,
    state: State,
    mode: Mode,
}
async fn sleep_ms(ms: u64) {
    narf_time::SleepUntil::new(narf_time::Deadline::after_ms(ms).as_instant()).await;
}
impl<I: Io> Engine<I> {
    fn access<T>(&mut self, f: impl FnOnce(&mut I) -> T) -> Result<T, Error> {
        let io = &mut self.io;
        self.authority
            .invoke(Op(|| f(io)))
            .map_err(|_| Error::Revoked)
    }
    /// smu_cmn_send_smc_msg_with_param. The first message after load ignores
    /// the stale response register (SMU_FW_INIT), as every message here is.
    /// `read_argument` is false for Mode1Reset: Linux passes no read_arg, and
    /// the ASIC drops config space once the message is acknowledged.
    async fn command(
        &mut self,
        message: u32,
        argument: u32,
        read_argument: bool,
    ) -> Result<u32, Error> {
        self.access(|io| {
            io.set_mp1(RESPONSE, 0);
            io.set_mp1(ARGUMENT, argument);
            io.set_mp1(MESSAGE, message);
        })?;
        let deadline = narf_time::Deadline::after_ms(MESSAGE_MS);
        loop {
            match self.access(|io| io.mp1(RESPONSE))? {
                u32::MAX => return Err(Error::DeviceGone),
                1 if read_argument => return self.access(|io| io.mp1(ARGUMENT)),
                1 => return Ok(0),
                0 => {}
                status => return Err(Error::Rejected(status)),
            }
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            sleep_ms(1).await;
        }
    }
    /// Outer error: revocation. Inner error: the last value, never ready.
    async fn wait_mp0(&mut self, register: u32, ms: u64) -> Result<Result<u32, u32>, Error> {
        let deadline = narf_time::Deadline::after_ms(ms);
        loop {
            let value = self.access(|io| io.mp0(register))?;
            if value != u32::MAX && value & READY_MASK == READY {
                return Ok(Ok(value));
            }
            if deadline.expired() {
                return Ok(Err(value));
            }
            sleep_ms(1).await;
        }
    }
    async fn reset(&mut self, sos_before: u32) -> Result<Report, Error> {
        self.access(|io| {
            let scratch = io.scratch();
            io.set_scratch(scratch | ATOM_S3_ASIC_GUI_ENGINE_HUNG);
        })?;
        let authority = self.authority;
        self.io.save_and_quiesce(&authority)?;
        // A version the PMFW cannot report selects the PSP path, as Linux's
        // is_mode1_reset_supported returns false on a failed query.
        let smu_version = self.command(GET_SMU_VERSION, 0, true).await.ok();
        let method = match smu_version {
            Some(version) if version >= SMU_MODE1_MIN_VERSION => Method::Smu,
            _ => Method::Psp,
        };
        match method {
            Method::Smu => {
                self.command(MODE1_RESET, 0, false).await?;
            }
            Method::Psp => {
                self.wait_mp0(TOS, REGISTER_MS)
                    .await?
                    .map_err(Error::PspNotReady)?;
                self.access(|io| io.set_mp0(TOS, GFX_CTRL_CMD_ID_MODE1_RST))?;
            }
        }
        // Config space (BAR decode) is gone until restored: no MMIO here.
        sleep_ms(SETTLE_MS).await;
        self.authority.check_live().map_err(|_| Error::Revoked)?;
        self.io.restore(&authority)?;
        self.wait_mp0(BOOTLOADER, BOOTLOADER_MS)
            .await?
            .map_err(|value| {
                if value == u32::MAX {
                    Error::DeviceGone
                } else {
                    Error::Timeout
                }
            })?;
        let deadline = narf_time::Deadline::after_ms(REGISTER_MS);
        let memsize = loop {
            let memsize = self.access(|io| io.memsize())?;
            if memsize != u32::MAX {
                break memsize;
            }
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            sleep_ms(1).await;
        };
        let sos_after = self.access(|io| {
            let scratch = io.scratch();
            io.set_scratch(scratch & !ATOM_S3_ASIC_GUI_ENGINE_HUNG);
            io.mp0(SOS)
        })?;
        Ok(Report {
            method,
            smu_version,
            sos_before,
            sos_after,
            memsize,
        })
    }
    async fn run(&mut self) -> Result<Option<Report>, Error> {
        if self.state != State::Prepared {
            return Err(Error::Busy);
        }
        let sos = self.access(|io| io.mp0(SOS))?;
        if sos == u32::MAX {
            self.state = State::Failed;
            return Err(Error::DeviceGone);
        }
        if sos == 0 && self.mode == Mode::OnInit {
            self.state = State::NotRequired;
            return Ok(None);
        }
        self.state = State::Resetting;
        let result = self.reset(sos).await;
        self.state = match result {
            Ok(report) => State::Complete(report),
            Err(_) => State::Failed,
        };
        result.map(Some)
    }
}

/// One reset-on-init attempt for a discrete Navi22.
#[derive(Debug)]
pub struct Reset {
    engine: Engine<Mmio>,
}
impl Reset {
    /// Constructs register windows only; performs no I/O.
    ///
    /// # Safety
    /// Caller exclusively owns this physical Navi22 (not an SR-IOV VF), its
    /// MP0/MP1 mailboxes, NBIO scratch and PCI config space, with permanent
    /// BAR mappings. Nothing else may access the device, its VRAM or its
    /// config space while `run` is pending, and no NARF queue, interrupt or
    /// VRAM client may exist: the reset discards all device state. Every
    /// inherited scanout stops; a boot framebuffer on this card goes dark.
    pub unsafe fn new(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        device: BusDevice,
    ) -> Result<Self, Error> {
        let map = |error| match error {
            crate::amdgpu_psp_ring::Error::Invalid => Error::Invalid,
            _ => Error::Unsupported,
        };
        let bank = |id, versions: &[(u8, u8, u8)], index, last| {
            crate::amdgpu_psp_ring::bank(gpu, id, versions, index, last).map_err(map)
        };
        Ok(Self {
            engine: Engine {
                io: Mmio {
                    regs: gpu.regs,
                    mp0: bank(discovery::HW_ID_MP0, &[(11, 0, 11)], 0, SOS)?,
                    mp1: crate::amdgpu_smu_navi22::mp1_bank(gpu).map_err(|_| Error::Unsupported)?,
                    scratch: bank(discovery::HW_ID_NBIF, NBIF, 1, SCRATCH_3)?,
                    memsize: bank(discovery::HW_ID_NBIF, NBIF, 2, MEMSIZE)?,
                    device,
                    saved: None,
                },
                authority,
                state: State::Prepared,
                mode: Mode::OnInit,
            },
        })
    }
    /// The mode1 reset of `amdgpu_device_gpu_recover` for a booted card.
    /// Constructs register windows only; performs no I/O.
    ///
    /// # Safety
    /// `new`'s exclusive-ownership contract, after recovery has quiesced
    /// every NARF queue and interrupt source and no SMU mailbox command is
    /// outstanding: the reset discards all device state, including scanout.
    pub unsafe fn new_recovery(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        device: BusDevice,
    ) -> Result<Self, Error> {
        // SAFETY: forwarded contract; construction performs no I/O.
        let mut reset = unsafe { Self::new(gpu, authority, device) }?;
        reset.engine.mode = Mode::Recovery;
        Ok(reset)
    }
    pub fn mode(&self) -> Mode {
        self.engine.mode
    }
    pub fn state(&self) -> State {
        self.engine.state
    }
    /// Reset once if SOS is running (always in `Mode::Recovery`); `Ok(None)`
    /// when an init-time card is already cold. Cancellation retains
    /// Resetting and refuses replay.
    pub async fn run(&mut self) -> Result<Option<Report>, Error> {
        self.engine.run().await
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_reset_navi22_tests.rs"]
mod tests;
