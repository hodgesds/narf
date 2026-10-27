//! Navi22 reset on init and shared Navi48 mode1 recovery. A GOP-posted discrete card already runs the
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
// linux-ctx: hdr=mp seg=0
// linux: mmMP0_SMN_C2PMSG_35
const BOOTLOADER: u32 = 0x63;
// linux: mmMP0_SMN_C2PMSG_64
const TOS: u32 = 0x80;
// linux: mmMP0_SMN_C2PMSG_81
const SOS: u32 = 0x91;
// linux: mmMP1_SMN_C2PMSG_66
const MESSAGE: u32 = 0x282;
// linux: mmMP1_SMN_C2PMSG_82
const ARGUMENT: u32 = 0x292;
// linux: mmMP1_SMN_C2PMSG_90
const RESPONSE: u32 = 0x29a;
// linux-ctx: reset

// nbio_2_3_offset.h.
// linux-ctx: hdr=nbio seg=1
// linux: mmBIOS_SCRATCH_0
const SCRATCH_0: u32 = 0x38;
// linux-ctx: hdr=nbio seg=0
// linux: mmPCIE_INDEX2
const PCIE_INDEX2: u32 = 0xe;
// linux: mmPCIE_DATA2
const PCIE_DATA2: u32 = 0xf;
// linux-ctx: hdr=nbio seg=2
// linux: mmRCC_DEV0_EPF0_RCC_CONFIG_MEMSIZE
const MEMSIZE: u32 = 0xc3;
// linux-ctx: reset
const NBIF: &[(u8, u8, u8)] = &[(2, 3, 0), (2, 3, 1), (2, 3, 2), (3, 3, 0), (3, 3, 1)];
// smu_v11_0_7_ppsmc.h.
const GET_SMU_VERSION: u32 = 0x2; // linux: PPSMC_MSG_GetSmuVersion
const MODE1_RESET: u32 = 0x30; // linux: PPSMC_MSG_Mode1Reset
/// "PM FW support mode1 reset from 58.26".
// linux: n/a (literal 0x003a1a00 in sienna_cichlid_ppt.c:sienna_cichlid_is_mode1_reset_supported)
const SMU_MODE1_MIN_VERSION: u32 = 0x003a_1a00;
// linux: GFX_CTRL_CMD_ID_MODE1_RST
const GFX_CTRL_CMD_ID_MODE1_RST: u32 = 0x0007_0000;
// MBOX_TOS_READY_FLAG / MBOX_TOS_READY_MASK and the bootloader ready bit.
const READY: u32 = 0x8000_0000; // linux: MBOX_TOS_READY_FLAG
const READY_MASK: u32 = 0x8000_ffff; // linux: MBOX_TOS_READY_MASK
const ATOM_S3_ASIC_GUI_ENGINE_HUNG: u32 = 0x2000_0000; // linux: ATOM_S3_ASIC_GUI_ENGINE_HUNG
/// atombios.h `ATOM_S7_ASIC_INIT_COMPLETE_MASK`.
pub const ATOM_S7_ASIC_INIT_COMPLETE: u32 = 0x0000_0200; // linux: ATOM_S7_ASIC_INIT_COMPLETE_MASK
/// `ATOM_CMD_INIT`: ASIC_Init, master command table entry 0.
// linux: n/a (ATOM_CMD_INIT = 0, amdgpu/atom.h; not in checker sets)
const ASIC_INIT: u8 = 0;
// atom.h / atom_master_list_of_data_tables_v2_1.
// linux: offsetof(struct atom_master_list_of_data_tables_v2_1, firmwareinfo) / 2
const DATA_FIRMWAREINFO: usize = 4;
// linux: offsetof(struct atom_master_list_of_data_tables_v2_1, vram_usagebyfirmware) / 2
const DATA_VRAM_USAGE: usize = 11;
// ATOM_FWI_DEFSCLK_PTR
// linux: offsetof(struct atom_firmware_info_v3_4, bootup_sclk_in10khz)
const FWI_DEFSCLK: usize = 8;
// ATOM_FWI_DEFMCLK_PTR
// linux: offsetof(struct atom_firmware_info_v3_4, bootup_mclk_in10khz)
const FWI_DEFMCLK: usize = 0xc;
// linux: offsetof(struct atom_firmware_info_v3_4, bios_scratch_reg_startaddr)
const FWI_SCRATCH_START: usize = 0x18; // bios_scratch_reg_startaddr
/// amdgpu_atomfirmware_allocate_fb_scratch's default FB scratch.
// linux: n/a (literal 20 * 1024 in amdgpu_atomfirmware.c:amdgpu_atomfirmware_allocate_fb_scratch)
const FB_SCRATCH_DEFAULT: usize = 20 * 1024;
/// NARF bound on one ASIC_Init execution. Linux has only atom.c's 20 s
/// same-jump guard, which the VM applies as well.
const POST_MS: u64 = 60_000; // linux: n/a (NARF bound)
/// Opcodes between cooperative yields and liveness checks.
const YIELD_STEPS: u64 = 1024; // linux: n/a (NARF policy)
/// SMU11_MODE1_RESET_WAIT_TIME_IN_MS, and the PSP path's msleep(500).
const SETTLE_MS: u64 = 500; // linux: SMU11_MODE1_RESET_WAIT_TIME_IN_MS
/// psp_v11_0_wait_for_bootloader after the reset: the same 20 x
/// usec_timeout register polls the cold PSP11 boot waits, whose real bound
/// is 4-6 s (the udelays alone are 2 s; see
/// [`crate::amdgpu_psp_boot::PSP11_BOOTLOADER_TIMEOUT_MS`]).
// linux: n/a (bound derived from psp_v11_0_wait_for_bootloader loops)
pub(crate) const BOOTLOADER_MS: u64 = crate::amdgpu_psp_boot::PSP11_BOOTLOADER_TIMEOUT_MS;
/// adev->usec_timeout for the PSP mailbox and MEMSIZE waits.
const REGISTER_MS: u64 = 100; // linux: n/a (NARF bound, usec_timeout)
/// smu_cmn message timeout (usec_timeout * 20).
const MESSAGE_MS: u64 = 2000; // linux: n/a (NARF bound, usec_timeout * 20)
const PCI_EXPRESS: u8 = 0x10; // linux: n/a (PCI_CAP_ID_EXP, uapi pci_regs.h)
const PCI_MSI: u8 = 0x05; // linux: n/a (PCI_CAP_ID_MSI, uapi pci_regs.h)
const PCI_MSIX: u8 = 0x11; // linux: n/a (PCI_CAP_ID_MSIX, uapi pci_regs.h)
const MSIX_ENABLE: u16 = 0x8000; // linux: n/a (PCI_MSIX_FLAGS_ENABLE, pci_regs.h)
const MSIX_MASKALL: u16 = 0x4000; // linux: n/a (PCI_MSIX_FLAGS_MASKALL, pci_regs.h)
/// BAR5, the register BAR Linux maps as rmmio.
const MMIO_BIR: u32 = 5; // linux: n/a (BAR index of rmmio on NV)
const MSIX_SAVED: usize = 64; // linux: n/a (NARF bound)
const RESIZABLE_BAR: u16 = 0x15; // linux: n/a (PCI_EXT_CAP_ID_REBAR, pci_regs.h)

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
    /// System resume found the card cold (power was removed): no reset ran,
    /// only the saved PCI state restore and the post.
    PowerCycle,
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
    /// Models whose clock is a poll counter can pace waits with
    /// cooperative yields instead of real sleeps, so a designed timeout
    /// takes its model poll count rather than that many real
    /// milliseconds. Real MMIO always sleeps.
    #[cfg(feature = "kernel-test")]
    fn yield_pace(&self) -> bool {
        false
    }
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
// linux: n/a (PCI_EXP_DEVCTL, PCI_EXP_LNKCTL, PCI_EXP_DEVCTL2, PCI_EXP_LNKCTL2; pci_regs.h)
const EXPRESS_CONTROLS: [u16; 4] = [0x08, 0x10, 0x28, 0x30];

fn config(cap: &Cap<BusDeviceCap, Write>, device: &BusDevice, offset: u16) -> Result<u32, Error> {
    pci::read_config32(cap, device, offset).map_err(|_| Error::Pci)
}

fn save(cap: &Cap<BusDeviceCap, Write>, device: &BusDevice) -> Result<PciState, Error> {
    let header = pci::save_config(cap, device).map_err(|_| Error::Pci)?;
    let mut express = None;
    let mut msi = None;
    let mut msix = None;
    // linux: n/a (PCI_CAPABILITY_LIST = 0x34, pci_regs.h)
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
                let wide = control & 0x80 != 0; // linux: n/a (PCI_MSI_FLAGS_64BIT)
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
            // linux: n/a (PCI_REBAR_CTRL = 8, PCI_REBAR_CTRL_NBAR_SHIFT = 5, NBAR_MASK 0xe0)
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
        offset = ((header >> 20) & 0xffc) as u16; // linux: n/a (PCI_EXT_CAP_NEXT)
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
        // linux-lit: 0x1f07=PCI_REBAR_CTRL_BAR_IDX | PCI_REBAR_CTRL_BAR_SIZE
        if config(cap, device, offset)? & 0x1f07 != control & 0x1f07 {
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
            // linux: n/a (PCI_MSIX_FLAGS_QSIZE = 0x7ff, PCI_MSIX_TABLE_BIR = 7)
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
    /// `amdgpu_device_resume` after S3: restore the PCI state saved before
    /// suspend, then post as `amdgpu_device_need_post` decides. A card whose
    /// SOS still runs (power was never removed) takes the mode1 path.
    Resume,
}
#[derive(Debug)]
struct Engine<I: Io> {
    io: I,
    authority: Cap<BusDeviceCap, Write>,
    state: State,
    mode: Mode,
    /// SMU14 debug-mailbox reset and ATOM firmware ASIC_Init v2.1.
    navi48: bool,
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
        // linux-lit: 4=sizeof(struct atom_common_table_header); 2=sizeof(uint16_t)
        self.u16_at(self.cmd_table + 4 + 2 * usize::from(id))
            .unwrap_or(0)
    }
    /// `CU16(data_table + 4 + 2 * index)`.
    fn data(&self, index: usize) -> Option<usize> {
        // linux-lit: 4=sizeof(struct atom_common_table_header); 2=sizeof(uint16_t)
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
            // linux-lit: 2=offsetof(struct atom_common_table_header, format_revision); 3=offsetof(struct atom_common_table_header, content_revision)
            let (frev, crev) = (*self.bios.get(at + 2)?, *self.bios.get(at + 3)?);
            if frev == 2 && crev == 1 {
                // linux-lit: 4=offsetof(struct vram_usagebyfirmware_v2_1, start_address_in_kb)
                let start = self.u32_at(at + 4)?;
                // ATOM_VRAM_BLOCK_SRIOV_MSG_SHARE_RESERVATION keeps the default.
                // linux-lit: 0xc000_0000=ATOM_VRAM_OPERATION_FLAGS_MASK; 2=ATOM_VRAM_BLOCK_SRIOV_MSG_SHARE_RESERVATION; 30=ATOM_VRAM_OPERATION_FLAGS_SHIFT
                if start & 0xc000_0000 == 2 << 30 {
                    return Some(0);
                }
                // linux-lit: 10=offsetof(struct vram_usagebyfirmware_v2_1, used_by_driver_in_kb)
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

/// `amdgpu_atomfirmware_allocate_fb_scratch`'s FB scratch size for `bios`
/// (VRAM_UsageByFirmware v2.1, else the 20 KiB default), shared with the
/// display-table interpreter (`amdgpu_navi22_bios`).
pub(crate) fn atom_fb_scratch_bytes(bios: &[u8]) -> usize {
    Image::parse(bios).map_or(FB_SCRATCH_DEFAULT, |image| image.fb_scratch_bytes())
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
    /// Whether `ms` have passed since `began` on [`Io::now_ms`], the clock
    /// every reset-path bound is measured on (as POST's is), so a model
    /// device's poll count, not host scheduling, decides its timeouts.
    fn expired(&mut self, began: u64, ms: u64) -> bool {
        self.io.now_ms().saturating_sub(began) >= ms
    }
    /// One pacing tick of a poll loop. Counter-clocked models pace by
    /// cooperative yield (see [`Io::yield_pace`]); hardware sleeps 1 ms.
    async fn pace(&mut self) {
        #[cfg(feature = "kernel-test")]
        if self.io.yield_pace() {
            narf_scheduler::yield_now().await;
            return;
        }
        sleep_ms(1).await;
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
        let began = self.io.now_ms();
        loop {
            match self.access(|io| io.mp1(RESPONSE))? {
                u32::MAX => return Err(Error::DeviceGone),
                // linux-lit: 1=PPSMC_Result_OK
                1 if read_argument => return self.access(|io| io.mp1(ARGUMENT)),
                1 => return Ok(0), // linux-lit: 1=PPSMC_Result_OK
                0 => {}
                status => return Err(Error::Rejected(status)),
            }
            if self.expired(began, MESSAGE_MS) {
                return Err(Error::Timeout);
            }
            self.pace().await;
        }
    }
    /// Outer error: revocation. Inner error: the last value, never ready.
    async fn wait_mp0(&mut self, register: u32, ms: u64) -> Result<Result<u32, u32>, Error> {
        let began = self.io.now_ms();
        loop {
            let value = self.access(|io| io.mp0(register))?;
            let mask = if self.navi48 && register == BOOTLOADER {
                READY
            } else {
                READY_MASK
            };
            if value != u32::MAX && value & mask == READY {
                return Ok(Ok(value));
            }
            if self.expired(began, ms) {
                return Ok(Err(value));
            }
            self.pace().await;
        }
    }
    /// amdgpu_atombios_scratch_regs_engine_hung.
    fn engine_hung(&mut self, hung: bool) -> Result<(), Error> {
        // linux: n/a (bios_scratch_reg_offset + 3, amdgpu_atombios.c)
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
        let (smu_version, method) = if self.navi48 {
            // smu_v14_0_2_mode1_reset / smu_msg_v1_send_debug_msg:
            // parameter, command, response clear. There is NO response poll.
            self.access(|io| {
                io.set_mp1(0x75, 0); // regMP1_SMN_C2PMSG_53, base 1
                io.set_mp1(0x8b, 2); // regMP1_SMN_C2PMSG_75, DEBUGSMC_MSG_Mode1Reset
                io.set_mp1(0x76, 0); // regMP1_SMN_C2PMSG_54
            })?;
            (None, Method::Smu)
        } else {
            let version = self.command(GET_SMU_VERSION, 0, true).await.ok();
            let method = if version.is_some_and(|v| v >= SMU_MODE1_MIN_VERSION) {
                self.command(MODE1_RESET, 0, false).await?;
                Method::Smu
            } else {
                self.wait_mp0(TOS, REGISTER_MS)
                    .await?
                    .map_err(Error::PspNotReady)?;
                self.access(|io| io.set_mp0(TOS, GFX_CTRL_CMD_ID_MODE1_RST))?;
                Method::Psp
            };
            (version, method)
        };
        // Config space is gone until restored: no MMIO, including liveness
        // reads, during the Linux-mandated one-second SMU14 settling interval.
        sleep_ms(if self.navi48 { 1000 } else { SETTLE_MS }).await;
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
        let began = self.io.now_ms();
        let memsize = loop {
            let memsize = self.access(|io| io.memsize())?;
            if memsize != u32::MAX {
                break memsize;
            }
            if self.expired(began, REGISTER_MS) {
                return Err(Error::Timeout);
            }
            self.pace().await;
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
        let s7 = self.scratch + 7; // linux: n/a (bios_scratch_reg_offset + 7, amdgpu_atombios.c)
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
        let navi48 = self.navi48;
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
        if navi48 {
            let header = image
                .atom
                .cmd_table(u16::from(ASIC_INIT))
                .map_err(|_| failed(PostError::Image))?;
            if header.get(2) != Some(&2) || header.get(3).is_none_or(|v| *v < 1) {
                return Err(failed(PostError::Image));
            }
        }
        let fb_words = image.fb_scratch_bytes() / 4;
        let mut fb = Vec::new();
        fb.try_reserve_exact(fb_words)
            .map_err(|_| failed(PostError::Allocation))?;
        fb.resize(fb_words, 0);
        // ASIC_Init v2.1 has two parameters and sixteen reserved dwords.
        let mut ps = [0u32; 18];
        ps[0] = if navi48 { sclk & 0x00ff_ffff } else { sclk };
        ps[1] = if navi48 { mclk & 0x00ff_ffff } else { mclk };
        post.sclk = sclk;
        post.mclk = mclk;
        post.ran = true;
        let began = io.now_ms();
        #[cfg(feature = "kernel-test")]
        let yield_pace = io.yield_pace();
        // Script delays pace through this closure: a counter-clocked
        // model's clock never advances inside a sleep, so its delays
        // yield instead of costing real time (#879).
        let pace = |us: u64| async move {
            #[cfg(feature = "kernel-test")]
            if yield_pace {
                narf_scheduler::yield_now().await;
                return;
            }
            narf_time::SleepUntil::new(narf_time::Deadline::after_us(us).as_instant()).await;
        };
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
        // Preserve Navi22's sixteen-dword parameter bound; only the
        // atomfirmware v2.1 path supplies the larger reserved workspace.
        let params = if navi48 { &mut ps[..] } else { &mut ps[..16] };
        let mut machine =
            vm::Machine::start(&mut state, ASIC_INIT, params).map_err(|e| atom(e, None))?;
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
                    pace(us).await;
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
                "amdgpu: post: ASIC_Init ran but scratch7 {after:#x} lacks ASIC_INIT_COMPLETE"
            );
        }
        Ok(post)
    }
    /// Resume: PCI state back before any MMIO, the bootloader and MEMSIZE
    /// awaited as after a reset, then post or (SOS alive) mode1 + post.
    async fn resume(&mut self) -> Result<Report, Error> {
        let authority = self.authority;
        self.state = State::Resetting;
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
        let sos = self.access(|io| io.mp0(SOS))?;
        if sos == u32::MAX {
            return Err(Error::DeviceGone);
        }
        if sos != 0 {
            let mut report = self.reset(sos).await?;
            self.state = State::Posting;
            report.post = self.post(true).await?;
            return Ok(report);
        }
        let memsize = self.access(|io| io.memsize())?;
        if memsize == u32::MAX {
            return Err(Error::DeviceGone);
        }
        self.state = State::Posting;
        let post = self.post(false).await?;
        Ok(Report {
            method: Method::PowerCycle,
            smu_version: None,
            sos_before: 0,
            sos_after: self.access(|io| io.mp0(SOS))?,
            memsize,
            post,
        })
    }
    /// Navi48 BACO exit (smu_v14_0_baco_set_state): BIOS_SCRATCH_6/7 = 0.
    fn clear_post_scratch(&mut self) -> Result<(), Error> {
        if !self.navi48 || self.mode != Mode::Resume || self.state != State::Prepared {
            return Err(Error::Busy);
        }
        let scratch = self.scratch;
        self.access(|io| {
            // linux: n/a (WREG32(adev->bios_scratch_reg_offset + 6/7, 0), smu_v14_0.c)
            io.set_reg(scratch + 6, 0);
            io.set_reg(scratch + 7, 0);
        })
    }
    async fn run(&mut self) -> Result<Option<Report>, Error> {
        if self.state != State::Prepared {
            return Err(Error::Busy);
        }
        if self.mode == Mode::Resume {
            let result = self.resume().await;
            self.state = match result {
                Ok(report) => State::Complete(report),
                Err(_) => State::Failed,
            };
            return result.map(Some);
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
        let profile = crate::amdgpu_rdna2::for_pci_id(gpu.chip.vid, gpu.chip.did)
            .ok_or(Error::Unsupported)?;
        crate::amdgpu_psp_ring::validate_rdna2_layout(gpu).map_err(|_| Error::Unsupported)?;
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
        // linux-lit: 1=mmBIOS_SCRATCH_0_BASE_IDX; 7=mmBIOS_SCRATCH_7 - mmBIOS_SCRATCH_0
        let nbio = dword(bank(discovery::HW_ID_NBIF, NBIF, 1, SCRATCH_0 + 7)?)? + SCRATCH_0;
        let scratch = vbios
            .as_deref()
            .and_then(Image::parse)
            .and_then(|image| image.scratch_base())
            .unwrap_or(nbio);
        if (u64::from(scratch) + 8) * 4 > gpu.regs.len {
            return Err(Error::Invalid);
        }
        // linux-lit: 0=mmPCIE_DATA2_BASE_IDX
        let pcie = dword(bank(discovery::HW_ID_NBIF, NBIF, 0, PCIE_DATA2)?)?;
        Ok(Self {
            engine: Engine {
                io: Mmio {
                    regs: gpu.regs,
                    // linux-lit: 0=mmMP0_SMN_C2PMSG_81_BASE_IDX
                    mp0: bank(discovery::HW_ID_MP0, &[profile.psp_version], 0, SOS)?,
                    mp1: bank(discovery::HW_ID_MP1, &[profile.psp_version], 0, RESPONSE)?,
                    pcie: (pcie + PCIE_INDEX2, pcie + PCIE_DATA2),
                    // linux-lit: 2=mmRCC_DEV0_EPF0_RCC_CONFIG_MEMSIZE_BASE_IDX
                    memsize: bank(discovery::HW_ID_NBIF, NBIF, 2, MEMSIZE)?,
                    device,
                    saved: None,
                },
                authority,
                state: State::Prepared,
                mode: Mode::OnInit,
                navi48: false,
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
    /// Navi48's unconditional mode1 reset, PCI restore and ASIC_Init v2.1.
    /// Shares the bounded ATOM interpreter and PCI/MSI/ReBAR preservation
    /// with Navi22; SMU14 uses a different mailbox and settling interval.
    /// # Safety
    /// Exclusively own this physical GPU, PCI configuration and VRAM. Stop
    /// all software MMIO/VRAM readers and writers, including IH and timestamps.
    /// Keep every old allocation quarantined. Cancellation is terminal.
    pub unsafe fn new_navi48_recovery(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        device: BusDevice,
    ) -> Result<Self, Error> {
        crate::amdgpu_navi48_firmware::Target::resolve(gpu).map_err(|_| Error::Unsupported)?;
        if device.id.vendor != gpu.chip.vid || device.id.device != gpu.chip.did {
            return Err(Error::Invalid);
        }
        let bank = |id, versions: &[(u8, u8, u8)], index, last| {
            crate::amdgpu_psp_ring::bank(gpu, id, versions, index, last)
                .map_err(|_| Error::Unsupported)
        };
        let bytes = gpu
            .vbios
            .as_ref()
            .ok_or(Error::Post(PostError::NoVbios))?
            .bytes();
        let mut vbios = Vec::new();
        vbios
            .try_reserve_exact(bytes.len())
            .map_err(|_| Error::Post(PostError::Allocation))?;
        vbios.extend_from_slice(bytes);
        let scratch = Image::parse(bytes)
            .and_then(|i| i.scratch_base())
            .ok_or(Error::Post(PostError::Image))?;
        if (u64::from(scratch) + 8) * 4 > gpu.regs.len {
            return Err(Error::Invalid);
        }
        let nbif = &[(7, 7, 0), (7, 7, 1), (6, 3, 1)];
        let pcie = u32::try_from(bank(discovery::HW_ID_NBIF, nbif, 0, PCIE_DATA2)? / 4)
            .map_err(|_| Error::Invalid)?;
        Ok(Self {
            engine: Engine {
                io: Mmio {
                    regs: gpu.regs,
                    mp0: bank(
                        discovery::HW_ID_MP0,
                        crate::amdgpu_rdna4::MP_VERSIONS,
                        0,
                        SOS,
                    )?,
                    mp1: bank(
                        discovery::HW_ID_MP1,
                        crate::amdgpu_rdna4::MP_VERSIONS,
                        1,
                        0x9a,
                    )?,
                    pcie: (pcie + PCIE_INDEX2, pcie + PCIE_DATA2),
                    memsize: bank(discovery::HW_ID_NBIF, nbif, 2, MEMSIZE)?,
                    device,
                    saved: None,
                },
                authority,
                state: State::Prepared,
                mode: Mode::Recovery,
                navi48: true,
                vbios: Some(vbios),
                scratch,
                post: None,
            },
        })
    }
    /// Navi48 system resume (`Mode::Resume`). Constructs register windows
    /// only; [`Self::save_for_resume`] captures PCI state before suspend and
    /// `run` after resume restores it and posts the card.
    /// # Safety
    /// `new_navi48_recovery`'s contract.
    pub unsafe fn new_navi48_resume(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        device: BusDevice,
    ) -> Result<Self, Error> {
        // SAFETY: forwarded contract.
        let mut reset = unsafe { Self::new_navi48_recovery(gpu, authority, device) }?;
        reset.engine.mode = Mode::Resume;
        Ok(reset)
    }
    /// amdgpu_device_cache_pci_state + pci_clear_master before suspend:
    /// BARs, ReBAR, PCIe controls, MSI/MSI-X with its table.
    /// # Safety
    /// Every engine is quiesced: no DMA may be in flight when bus mastering
    /// is cleared, and nothing touches the device until `run`.
    pub unsafe fn save_for_resume(&mut self) -> Result<(), Error> {
        if self.engine.mode != Mode::Resume || self.engine.state != State::Prepared {
            return Err(Error::Busy);
        }
        let authority = self.engine.authority;
        self.engine.io.save_and_quiesce(&authority)
    }
    /// smu_v14_0_baco_set_state(EXIT): after ExitBaco, clear BIOS_SCRATCH_6
    /// and BIOS_SCRATCH_7 "for coming asic reinit", so the resume's post
    /// (`amdgpu_device_need_post`) runs ASIC_Init. Navi48 runtime resume
    /// only, before `run`.
    /// # Safety
    /// As [`Self::save_for_resume`]; PMFW acknowledged ExitBaco.
    pub unsafe fn clear_post_scratch(&mut self) -> Result<(), Error> {
        self.engine.clear_post_scratch()
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
