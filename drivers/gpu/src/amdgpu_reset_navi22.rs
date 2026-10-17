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
//!
//! After the reset decision `amdgpu_device_init` posts the card when
//! `amdgpu_device_need_post` says so: `amdgpu_atombios_scratch_need_asic_init`
//! (BIOS_SCRATCH_7 `ATOM_S7_ASIC_INIT_COMPLETE` clear, which a mode1 reset
//! leaves) → `amdgpu_device_asic_init` → for GC 10.3 `amdgpu_atom_asic_init`:
//! ATOM `ASIC_Init` (command table 0) with PS[0]/PS[1] the FirmwareInfo
//! boot-up sclk/mclk dwords. That runs here through `amdgpu_atom_vm` against
//! the retained VBIOS, before any IP block. The decision applies to a cold
//! (never reset) card too; recovery (`amdgpu_device_reinit_after_reset`,
//! full reset) posts unconditionally. NV has no `pre_asic_init` hook, and
//! atomfirmware's scratch init (`amdgpu_atomfirmware_scratch_regs_init`)
//! only takes the scratch base from FirmwareInfo, which this owner does too.
use crate::{
    amdgpu::AmdGpu,
    amdgpu_atom_vm::{self as vm, Anomaly, AtomError, AtomState, Hooks, OpSite, ResolvedTable},
    amdgpu_atombios::{Atombios, ATOM_CT_WS_PTR},
    amdgpu_discovery as discovery,
};
use alloc::vec::Vec;
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
const SCRATCH_0: u32 = 0x38; // BIOS_SCRATCH_0, base index 1
const PCIE_INDEX2: u32 = 0xe; // base index 0
const PCIE_DATA2: u32 = 0xf; // base index 0
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
/// atombios.h `ATOM_S7_ASIC_INIT_COMPLETE_MASK`.
pub const ATOM_S7_ASIC_INIT_COMPLETE: u32 = 0x0000_0200;
/// `ATOM_CMD_INIT`: ASIC_Init, master command table entry 0.
const ASIC_INIT: u8 = 0;
// atom.h / atom_master_list_of_data_tables_v2_1.
const DATA_FIRMWAREINFO: usize = 4;
const DATA_VRAM_USAGE: usize = 11;
const FWI_DEFSCLK: usize = 8; // ATOM_FWI_DEFSCLK_PTR
const FWI_DEFMCLK: usize = 0xc; // ATOM_FWI_DEFMCLK_PTR
const FWI_SCRATCH_START: usize = 0x18; // bios_scratch_reg_startaddr
/// amdgpu_atomfirmware_allocate_fb_scratch's default FB scratch.
const FB_SCRATCH_DEFAULT: usize = 20 * 1024;
/// NARF bound on one ASIC_Init execution. Linux has only atom.c's 20 s
/// same-jump guard, which the VM applies as well.
const POST_MS: u64 = 60_000;
/// Opcodes between cooperative yields and liveness checks.
const YIELD_STEPS: u64 = 1024;
/// SMU11_MODE1_RESET_WAIT_TIME_IN_MS, and the PSP path's msleep(500).
const SETTLE_MS: u64 = 500;
/// psp_v11_0_wait_for_bootloader: 20 retries of a 100 ms register wait.
const BOOTLOADER_MS: u64 = 2000;
/// adev->usec_timeout for the PSP mailbox and MEMSIZE waits.
const REGISTER_MS: u64 = 100;
/// smu_cmn message timeout (usec_timeout * 20).
const MESSAGE_MS: u64 = 2000;
const PCI_EXPRESS: u8 = 0x10;
const PCI_MSI: u8 = 0x05;
const PCI_MSIX: u8 = 0x11;
const MSIX_ENABLE: u16 = 0x8000;
const MSIX_MASKALL: u16 = 0x4000;
/// BAR5, the register BAR Linux maps as rmmio.
const MMIO_BIR: u32 = 5;
const MSIX_SAVED: usize = 64;
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
    /// `amdgpu_device_asic_init` failed ("gpu post error!").
    Post(PostError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PostError {
    /// Post required but no VBIOS image was retained ("no vBIOS found").
    NoVbios,
    /// The image has no usable ATOM header, FirmwareInfo or directory.
    Image,
    /// FirmwareInfo's default sclk or mclk is zero (`amdgpu_atom_asic_init`
    /// returns 1).
    NoClocks,
    /// ASIC_Init's master command-table entry is zero.
    NoAsicInit,
    Allocation,
    /// The interpreter refused the bytecode at `site`.
    Atom {
        error: AtomError,
        site: Option<OpSite>,
    },
    /// ASIC_Init exceeded [`POST_MS`].
    Timeout,
    /// Retained for callers matching on it; ASIC_Init returning without
    /// `ATOM_S7_ASIC_INIT_COMPLETE` is only logged, as in Linux.
    Incomplete(u32),
}

/// Evidence of the post decision and, when it ran, of ASIC_Init.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Post {
    /// Dword index of BIOS_SCRATCH_0 (`adev->bios_scratch_reg_offset`).
    pub scratch_base: u32,
    /// BIOS_SCRATCH_7 when the decision was taken, and afterwards.
    pub scratch7_before: u32,
    pub scratch7_after: u32,
    /// ASIC_Init executed.
    pub ran: bool,
    /// PS[0] / PS[1]: FirmwareInfo boot-up sclk and mclk dwords.
    pub sclk: u32,
    pub mclk: u32,
    pub opcodes: u64,
    pub reads: u32,
    pub writes: u32,
    /// Sum of the DELAY opcodes' requests, in microseconds.
    pub delay_us: u64,
    /// atom.c "log and continue" conditions, and the first one.
    pub anomalies: u32,
    pub first_anomaly: Option<Anomaly>,
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
    /// The post that followed the reset.
    pub post: Post,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Prepared,
    /// Also the state retained after cancellation: replay is refused.
    Resetting,
    /// Deciding on or running ASIC_Init; retained after cancellation too.
    Posting,
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
    /// `RREG32`/`WREG32` by dword index (`amdgpu_device_rreg`): BAR5
    /// directly, beyond it through PCIE_INDEX2/PCIE_DATA2.
    fn reg(&mut self, dword: u32) -> u32;
    fn set_reg(&mut self, dword: u32, value: u32);
    fn memsize(&mut self) -> u32;
    /// Monotonic milliseconds.
    fn now_ms(&mut self) -> u64;
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
    /// (capability offset, Message Control, address lo, address hi, data,
    /// mask) of an MSI capability.
    msi: Option<(u16, u16, [u32; 4])>,
    /// (capability offset, Message Control) of the MSI-X capability.
    msix: Option<(u16, u16)>,
    /// The MSI-X table when it lives in the register BAR: (byte offset,
    /// entries, count). The reset wipes it with the rest of the device.
    msix_table: Option<(u64, [[u32; 4]; MSIX_SAVED], usize)>,
}
const EXPRESS_CONTROLS: [u16; 4] = [0x08, 0x10, 0x28, 0x30];

fn config(cap: &Cap<BusDeviceCap, Write>, device: &BusDevice, offset: u16) -> Result<u32, Error> {
    pci::read_config32(cap, device, offset).map_err(|_| Error::Pci)
}

fn save(cap: &Cap<BusDeviceCap, Write>, device: &BusDevice) -> Result<PciState, Error> {
    let header = pci::save_config(cap, device).map_err(|_| Error::Pci)?;
    let mut express = None;
    let mut msi = None;
    let mut msix = None;
    let mut pointer = (config(cap, device, 0x34)? & 0xfc) as u16;
    for _ in 0..48 {
        if pointer < 0x40 {
            break;
        }
        let header = config(cap, device, pointer)?;
        match header as u8 {
            PCI_EXPRESS => {
                let mut controls = [0; 4];
                for (control, offset) in controls.iter_mut().zip(EXPRESS_CONTROLS) {
                    *control = config(cap, device, pointer + offset)? as u16;
                }
                express = Some((pointer, controls));
            }
            // pci_save_state keeps the MSI/MSI-X state the driver set up
            // (pci_restore_msi_state rewrites it from the descriptors).
            PCI_MSI => {
                let control = (header >> 16) as u16;
                let wide = control & 0x80 != 0;
                let mut words = [0; 4];
                words[0] = config(cap, device, pointer + 4)?;
                let data = if wide {
                    words[1] = config(cap, device, pointer + 8)?;
                    pointer + 12
                } else {
                    pointer + 8
                };
                words[2] = config(cap, device, data)? & 0xffff;
                if control & 0x100 != 0 {
                    words[3] = config(cap, device, data + 4)?;
                }
                msi = Some((pointer, control, words));
            }
            PCI_MSIX => msix = Some((pointer, (header >> 16) as u16)),
            _ => {}
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
        msi,
        msix,
        msix_table: None,
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
    // pci_restore_msi_state: address/data first, then Message Control.
    if let Some((pointer, control, words)) = state.msi {
        write(pointer + 4, words[0]).map_err(|_| Error::Pci)?;
        let data = if control & 0x80 != 0 {
            write(pointer + 8, words[1]).map_err(|_| Error::Pci)?;
            pointer + 12
        } else {
            pointer + 8
        };
        write(data, words[2]).map_err(|_| Error::Pci)?;
        if control & 0x100 != 0 {
            write(data + 4, words[3]).map_err(|_| Error::Pci)?;
        }
        write(pointer, u32::from(control) << 16 | u32::from(PCI_MSI)).map_err(|_| Error::Pci)?;
    }
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
    /// PCIE_INDEX2 / PCIE_DATA2 dword indices (`nbio_v2_3_get_pcie_*`).
    pcie: (u32, u32),
    memsize: u64,
    device: BusDevice,
    saved: Option<PciState>,
}
impl Mmio {
    fn read(&self, base: u64, register: u32) -> u32 {
        // SAFETY: each base was bounded for its last register by bank(), and
        // base-0 indices by reg()'s BAR check; the BAR5 mapping is permanent
        // and restored before any post-reset access.
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
    fn reg(&mut self, dword: u32) -> u32 {
        if u64::from(dword) * 4 + 4 <= self.regs.len {
            return self.read(0, dword);
        }
        // amdgpu_device_indirect_rreg: index, posting read, data.
        let (index, data) = self.pcie;
        self.write(0, index, dword.wrapping_mul(4));
        self.read(0, index);
        self.read(0, data)
    }
    fn set_reg(&mut self, dword: u32, value: u32) {
        if u64::from(dword) * 4 + 4 <= self.regs.len {
            return self.write(0, dword, value);
        }
        // amdgpu_device_indirect_wreg.
        let (index, data) = self.pcie;
        self.write(0, index, dword.wrapping_mul(4));
        self.read(0, index);
        self.write(0, data, value);
        self.read(0, data);
    }
    fn memsize(&mut self) -> u32 {
        self.read(self.memsize, MEMSIZE)
    }
    fn now_ms(&mut self) -> u64 {
        narf_time::wall::monotonic_ns() / 1_000_000
    }
    fn save_and_quiesce(&mut self, authority: &Cap<BusDeviceCap, Write>) -> Result<(), Error> {
        let mut saved = save(authority, &self.device)?;
        if let Some((pointer, control)) = saved.msix {
            let table = config(authority, &self.device, pointer + 4)?;
            let offset = u64::from(table & !7);
            let count = (usize::from(control & 0x7ff) + 1).min(MSIX_SAVED);
            if table & 7 == MMIO_BIR && offset + count as u64 * 16 <= self.regs.len {
                let mut entries = [[0u32; 4]; MSIX_SAVED];
                for (index, entry) in entries.iter_mut().take(count).enumerate() {
                    for (word, value) in entry.iter_mut().enumerate() {
                        let at = offset + index as u64 * 16 + word as u64 * 4;
                        // SAFETY: bounded inside the permanent BAR5 mapping.
                        *value = unsafe { self.regs.read32(at) };
                    }
                }
                saved.msix_table = Some((offset, entries, count));
            }
        }
        self.saved = Some(saved);
        pci::clear_command(authority, &self.device, pci::cmd::BUS_MASTER)
            .map(|_| ())
            .map_err(|_| Error::Pci)
    }
    fn restore(&mut self, authority: &Cap<BusDeviceCap, Write>) -> Result<(), Error> {
        let saved = self.saved.as_ref().ok_or(Error::Invalid)?;
        restore(authority, &self.device, saved)?;
        // __pci_restore_msix_state: enable with every vector masked, rewrite
        // the table, then the saved Message Control.
        if let Some((pointer, control)) = saved.msix {
            let write = |value: u16| {
                pci::write_config32(
                    authority,
                    &self.device,
                    pointer,
                    u32::from(value) << 16 | u32::from(PCI_MSIX),
                )
                .map_err(|_| Error::Pci)
            };
            write(control | MSIX_ENABLE | MSIX_MASKALL)?;
            if let Some((offset, entries, count)) = saved.msix_table {
                for (index, entry) in entries.iter().take(count).enumerate() {
                    for (word, value) in entry.iter().enumerate() {
                        let at = offset + index as u64 * 16 + word as u64 * 4;
                        // SAFETY: bounded at save time inside BAR5, which the
                        // header restore above decodes again.
                        unsafe { self.regs.write32(at, *value) };
                    }
                }
            }
            write(control)?;
        }
        Ok(())
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
    /// The VBIOS image copied at construction, for ASIC_Init.
    vbios: Option<Vec<u8>>,
    /// `adev->bios_scratch_reg_offset`, a dword index.
    scratch: u32,
    /// The post decision of a run that did not reset.
    post: Option<Post>,
}
async fn sleep_ms(ms: u64) {
    narf_time::SleepUntil::new(narf_time::Deadline::after_ms(ms).as_instant()).await;
}

/// The ATOM directories ASIC_Init needs, located as `amdgpu_atom_parse` does.
struct Image<'a> {
    bios: &'a [u8],
    atom: Atombios<'a>,
    cmd_table: usize,
    data_table: usize,
}
impl<'a> Image<'a> {
    fn parse(bios: &'a [u8]) -> Option<Self> {
        let atom = Atombios::parse(bios).ok()?;
        let rom = crate::atombios::header::parse_rom_header(bios).ok()?;
        Some(Self {
            bios,
            atom,
            cmd_table: usize::from(rom.master_command_table_offset),
            data_table: usize::from(rom.master_data_table_offset),
        })
    }
    fn u16_at(&self, at: usize) -> Option<usize> {
        let b = self.bios.get(at..at + 2)?;
        Some(usize::from(u16::from_le_bytes([b[0], b[1]])))
    }
    fn u32_at(&self, at: usize) -> Option<u32> {
        let b = self.bios.get(at..at + 4)?;
        Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    /// `CU16(cmd_table + 4 + 2 * id)`; zero (absent) beyond the image.
    fn command(&self, id: u8) -> usize {
        self.u16_at(self.cmd_table + 4 + 2 * usize::from(id))
            .unwrap_or(0)
    }
    /// `CU16(data_table + 4 + 2 * index)`.
    fn data(&self, index: usize) -> Option<usize> {
        self.u16_at(self.data_table + 4 + 2 * index)
            .filter(|&at| at != 0)
    }
    fn table(&self, id: u8) -> Option<ResolvedTable<'a>> {
        let full = self.atom.cmd_table(u16::from(id)).ok()?;
        let (body, ps_dwords) = self.atom.cmd_table_body_and_ps(u16::from(id)).ok()?;
        Some(ResolvedTable {
            body,
            ps_dwords,
            start: self.command(id),
            ws_dwords: Some(usize::from(*full.get(ATOM_CT_WS_PTR)?)),
        })
    }
    /// `amdgpu_atomfirmware_scratch_regs_init`: FirmwareInfo's
    /// `bios_scratch_reg_startaddr`.
    fn scratch_base(&self) -> Option<u32> {
        self.u32_at(self.data(DATA_FIRMWAREINFO)? + FWI_SCRATCH_START)
            .filter(|&base| base != 0)
    }
    /// `amdgpu_atom_asic_init`'s PS[0] and PS[1].
    fn clocks(&self) -> Option<(u32, u32)> {
        let fwi = self.data(DATA_FIRMWAREINFO)?;
        Some((
            self.u32_at(fwi + FWI_DEFSCLK)?,
            self.u32_at(fwi + FWI_DEFMCLK)?,
        ))
    }
    /// `amdgpu_atomfirmware_allocate_fb_scratch`'s size in bytes.
    fn fb_scratch_bytes(&self) -> usize {
        let usage = self.data(DATA_VRAM_USAGE).and_then(|at| {
            let (frev, crev) = (*self.bios.get(at + 2)?, *self.bios.get(at + 3)?);
            if frev == 2 && crev == 1 {
                let start = self.u32_at(at + 4)?;
                // ATOM_VRAM_BLOCK_SRIOV_MSG_SHARE_RESERVATION keeps the default.
                if start & 0xc000_0000 == 2 << 30 {
                    return Some(0);
                }
                return Some(self.u16_at(at + 10)? << 10);
            }
            Some(0)
        });
        match usage {
            Some(bytes) if bytes != 0 => bytes,
            _ => FB_SCRATCH_DEFAULT,
        }
    }
}

/// The ATOM `card_info` for ASIC_Init: register callbacks through the
/// device authority, table resolution from the retained image.
struct Bus<'h, 'a, I: Io> {
    io: &'h mut I,
    authority: Cap<BusDeviceCap, Write>,
    image: &'h Image<'a>,
    revoked: bool,
    reads: u32,
    writes: u32,
}
impl<'a, I: Io> Hooks<'a> for Bus<'_, 'a, I> {
    fn reg_read(&mut self, index: u32) -> u32 {
        if self.revoked {
            return 0;
        }
        let io = &mut *self.io;
        match self.authority.invoke(Op(|| io.reg(index))) {
            Ok(value) => {
                self.reads = self.reads.saturating_add(1);
                value
            }
            Err(_) => {
                self.revoked = true;
                0
            }
        }
    }
    fn reg_write(&mut self, index: u32, value: u32) {
        if self.revoked {
            return;
        }
        let io = &mut *self.io;
        match self.authority.invoke(Op(|| io.set_reg(index, value))) {
            Ok(()) => self.writes = self.writes.saturating_add(1),
            Err(_) => self.revoked = true,
        }
    }
    fn resolve(&mut self, id: u8) -> Option<ResolvedTable<'a>> {
        self.image.table(id)
    }
    fn table_absent(&mut self, id: u8) -> bool {
        self.image.command(id) == 0
    }
    fn now_ms(&mut self) -> Option<u64> {
        Some(self.io.now_ms())
    }
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
    /// amdgpu_atombios_scratch_regs_engine_hung.
    fn engine_hung(&mut self, hung: bool) -> Result<(), Error> {
        let register = self.scratch + 3;
        self.access(|io| {
            let value = io.reg(register);
            io.set_reg(
                register,
                if hung {
                    value | ATOM_S3_ASIC_GUI_ENGINE_HUNG
                } else {
                    value & !ATOM_S3_ASIC_GUI_ENGINE_HUNG
                },
            );
        })
    }
    async fn reset(&mut self, sos_before: u32) -> Result<Report, Error> {
        self.engine_hung(true)?;
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
        self.engine_hung(false)?;
        let sos_after = self.access(|io| io.mp0(SOS))?;
        Ok(Report {
            method,
            smu_version,
            sos_before,
            sos_after,
            memsize,
            post: Post::default(),
        })
    }
    /// `amdgpu_device_need_post` + `amdgpu_device_asic_init`. `always` is
    /// recovery's unconditional post after a full reset.
    async fn post(&mut self, always: bool) -> Result<Post, Error> {
        let s7 = self.scratch + 7;
        let before = self.access(|io| io.reg(s7))?;
        if before == u32::MAX {
            return Err(Error::DeviceGone);
        }
        let mut post = Post {
            scratch_base: self.scratch,
            scratch7_before: before,
            scratch7_after: before,
            ..Post::default()
        };
        // amdgpu_atombios_scratch_need_asic_init.
        if !always && before & ATOM_S7_ASIC_INIT_COMPLETE != 0 {
            return Ok(post);
        }
        let failed = |error| Error::Post(error);
        let Self {
            io,
            authority,
            vbios,
            ..
        } = self;
        let authority = *authority;
        let bios = vbios.as_deref().ok_or(failed(PostError::NoVbios))?;
        let image = Image::parse(bios).ok_or(failed(PostError::Image))?;
        // amdgpu_atom_asic_init.
        let (sclk, mclk) = image.clocks().ok_or(failed(PostError::Image))?;
        if sclk == 0 || mclk == 0 {
            return Err(failed(PostError::NoClocks));
        }
        if image.command(ASIC_INIT) == 0 {
            return Err(failed(PostError::NoAsicInit));
        }
        let fb_words = image.fb_scratch_bytes() / 4;
        let mut fb = Vec::new();
        fb.try_reserve_exact(fb_words)
            .map_err(|_| failed(PostError::Allocation))?;
        fb.resize(fb_words, 0);
        let mut ps = [0u32; 16];
        ps[0] = sclk;
        ps[1] = mclk;
        post.sclk = sclk;
        post.mclk = mclk;
        post.ran = true;
        let began = io.now_ms();
        let mut state = AtomState::with_hooks(
            1,
            1,
            Bus {
                io,
                authority,
                image: &image,
                revoked: false,
                reads: 0,
                writes: 0,
            },
        );
        state.bios = bios;
        state.data_table = image.data_table;
        state.fb_scratch = fb;
        let atom = |error, site| failed(PostError::Atom { error, site });
        let mut machine =
            vm::Machine::start(&mut state, ASIC_INIT, &mut ps).map_err(|e| atom(e, None))?;
        loop {
            let step = machine.step(&mut state);
            if state.hooks.revoked {
                return Err(Error::Revoked);
            }
            match step.map_err(|e| atom(e, machine.last()))? {
                vm::Step::Done => break,
                vm::Step::Continue => {
                    if machine.steps() % YIELD_STEPS == 0 {
                        narf_scheduler::yield_now().await;
                        authority.check_live().map_err(|_| Error::Revoked)?;
                    }
                }
                // msleep/udelay, both as a cooperative sleep.
                vm::Step::Delay(us) => {
                    post.delay_us = post.delay_us.saturating_add(us);
                    narf_time::SleepUntil::new(narf_time::Deadline::after_us(us).as_instant())
                        .await;
                    authority.check_live().map_err(|_| Error::Revoked)?;
                }
            }
            if state.hooks.io.now_ms().saturating_sub(began) > POST_MS {
                return Err(failed(PostError::Timeout));
            }
        }
        post.opcodes = machine.steps();
        post.reads = state.hooks.reads;
        post.writes = state.hooks.writes;
        post.anomalies = state.anomalies;
        post.first_anomaly = state.first_anomaly;
        drop(state);
        let after = self.access(|io| io.reg(s7))?;
        post.scratch7_after = after;
        if after == u32::MAX {
            return Err(Error::DeviceGone);
        }
        // amdgpu_atomfirmware_asic_init returns amdgpu_atom_execute_table's
        // result and never re-reads BIOS_SCRATCH_7: a table that ran to its
        // end is a completed post. A still-clear bit is reported only.
        if after & ATOM_S7_ASIC_INIT_COMPLETE == 0 {
            use core::fmt::Write as _;
            let _ = writeln!(
                narf_console::Writer,
                "amdgpu: navi22 post: ASIC_Init ran but scratch7 {after:#x} lacks ASIC_INIT_COMPLETE"
            );
        }
        Ok(post)
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
            // No reset, but amdgpu_device_init still asks need_post.
            self.state = State::Posting;
            let post = self.post(false).await;
            self.state = match post {
                Ok(post) => {
                    self.post = Some(post);
                    State::NotRequired
                }
                Err(_) => State::Failed,
            };
            return post.map(|_| None);
        }
        self.state = State::Resetting;
        let result = match self.reset(sos).await {
            Ok(mut report) => {
                self.state = State::Posting;
                let always = self.mode == Mode::Recovery;
                self.post(always).await.map(|post| {
                    report.post = post;
                    report
                })
            }
            Err(error) => Err(error),
        };
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
    /// Constructs register windows and copies the VBIOS image; performs no
    /// I/O.
    ///
    /// # Safety
    /// Caller exclusively owns this physical Navi22 (not an SR-IOV VF), its
    /// MP0/MP1 mailboxes, NBIO scratch and PCI config space, with permanent
    /// BAR mappings. Nothing else may access the device, its VRAM or its
    /// config space while `run` is pending, and no NARF queue, interrupt or
    /// VRAM client may exist: the reset discards all device state, and
    /// ASIC_Init reprograms whatever the VBIOS bytecode touches. Every
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
        let dword = |base: u64| u32::try_from(base / 4).map_err(|_| Error::Invalid);
        let vbios = match gpu.vbios.as_ref() {
            Some(vbios) => {
                let mut bytes = Vec::new();
                bytes
                    .try_reserve_exact(vbios.bytes().len())
                    .map_err(|_| Error::Post(PostError::Allocation))?;
                bytes.extend_from_slice(vbios.bytes());
                Some(bytes)
            }
            None => None,
        };
        // amdgpu_atomfirmware_scratch_regs_init takes BIOS_SCRATCH_0 from
        // FirmwareInfo; without it, nbio_2_3's mmBIOS_SCRATCH_0.
        let nbio = dword(bank(discovery::HW_ID_NBIF, NBIF, 1, SCRATCH_0 + 7)?)? + SCRATCH_0;
        let scratch = vbios
            .as_deref()
            .and_then(Image::parse)
            .and_then(|image| image.scratch_base())
            .unwrap_or(nbio);
        if (u64::from(scratch) + 8) * 4 > gpu.regs.len {
            return Err(Error::Invalid);
        }
        let pcie = dword(bank(discovery::HW_ID_NBIF, NBIF, 0, PCIE_DATA2)?)?;
        Ok(Self {
            engine: Engine {
                io: Mmio {
                    regs: gpu.regs,
                    mp0: bank(discovery::HW_ID_MP0, &[(11, 0, 11)], 0, SOS)?,
                    mp1: crate::amdgpu_smu_navi22::mp1_bank(gpu).map_err(|_| Error::Unsupported)?,
                    pcie: (pcie + PCIE_INDEX2, pcie + PCIE_DATA2),
                    memsize: bank(discovery::HW_ID_NBIF, NBIF, 2, MEMSIZE)?,
                    device,
                    saved: None,
                },
                authority,
                state: State::Prepared,
                mode: Mode::OnInit,
                vbios,
                scratch,
                post: None,
            },
        })
    }
    /// The mode1 reset of `amdgpu_device_gpu_recover` for a booted card,
    /// followed by the unconditional post of a full reset.
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
    /// The post evidence of the last run: the report's for a reset, else
    /// the cold-card decision.
    pub fn post(&self) -> Option<Post> {
        match self.engine.state {
            State::Complete(report) => Some(report.post),
            _ => self.engine.post,
        }
    }
    /// Reset once if SOS is running (always in `Mode::Recovery`), then post
    /// if BIOS_SCRATCH_7 asks for it (always after a recovery reset);
    /// `Ok(None)` when an init-time card was cold (see `post`). Cancellation
    /// retains Resetting/Posting and refuses replay.
    pub async fn run(&mut self) -> Result<Option<Report>, Error> {
        let result = self.engine.run().await;
        if let Some(post) = self.post() {
            use core::fmt::Write as _;
            let _ = writeln!(
                narf_console::Writer,
                "amdgpu: navi22 post: scratch7 {:#x} -> {:#x}, asic_init {} ({} ops, {} writes, {} anomalies)",
                post.scratch7_before,
                post.scratch7_after,
                if post.ran { "ran" } else { "skipped" },
                post.opcodes,
                post.writes,
                post.anomalies,
            );
        }
        result
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_reset_navi22_tests.rs"]
mod tests;
