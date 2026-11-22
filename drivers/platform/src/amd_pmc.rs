//! AMD PMC: the SoC power-management controller's S0i3 hints around
//! suspend-to-idle, after Linux's `drivers/platform/x86/amd/pmc/pmc.c`.
//!
//! The PMC is an SMU mailbox: three registers (message, argument,
//! response) in a 4 KiB MMIO window. The window's base comes from two SMN
//! registers, read through the root complex (00:00.0) config space.
//! `amd_pmc_s2idle_prepare` sends the OS hint with argument 1 after the
//! LPS0 entry, and `amd_pmc_s2idle_restore` sends it with 0 before the LPS0
//! exit. Without that hint the SoC never reaches S0i3. The driver binds
//! when an ACPI device with one of `amd_pmc_acpi_ids` exists, and the root
//! complex is one `pmc_pci_ids` lists. It registers with
//! [`narf_power::lps0`].
//!
//! Not done, all diagnostics or narrow quirks in Linux:
//! - SMU logging and the s0i3 statistics;
//! - the STB trace buffer;
//! - the idle-mask read in `check`;
//! - the 2.5 s EC delay quirk;
//! - the DMI quirk table;
//! - Cezanne's RTC wake programming (`amd_pmc_verify_czn_rtc`, SMU 64.53+
//!   with an armed RTC alarm).
use core::sync::atomic::{AtomicBool, Ordering};
use narf_lib::sync::IrqSafeSpinLock;

/// `amd_pmc_acpi_ids`.
pub const ACPI_IDS: [&str; 10] = [
    "AMDI0005", "AMDI0006", "AMDI0007", "AMDI0008", "AMDI0009", "AMDI000A", "AMDI000B", "AMDI000C",
    "AMD0004", "AMD0005",
];

const REGISTER_RESPONSE: u32 = 0x980; // linux: AMD_PMC_REGISTER_RESPONSE
const REGISTER_ARGUMENT: u32 = 0x9bc; // linux: AMD_PMC_REGISTER_ARGUMENT
const REGISTER_MESSAGE: u32 = 0x538; // linux: AMD_PMC_REGISTER_MESSAGE
const REGISTER_MSG_1AH_20H: u32 = 0x938; // linux: AMD_PMC_REGISTER_MSG_1AH_20H
const REGISTER_MSG_1AH_80H: u32 = 0xa10; // linux: AMD_PMC_REGISTER_MSG_1AH_80H
const REGISTER_ARG_1AH_80H: u32 = 0xa18; // linux: AMD_PMC_REGISTER_ARG_1AH_80H
const REGISTER_RSP_1AH_80H: u32 = 0xa14; // linux: AMD_PMC_REGISTER_RSP_1AH_80H
/// The window size and its offset from the SMN-reported base.
pub const MAPPING_SIZE: u64 = 0x1000; // linux: AMD_PMC_MAPPING_SIZE
pub const BASE_ADDR_OFFSET: u64 = 0x1_0000; // linux: AMD_PMC_BASE_ADDR_OFFSET
pub const BASE_ADDR_LO: u32 = 0x13b1_02e8; // linux: AMD_PMC_BASE_ADDR_LO
pub const BASE_ADDR_HI: u32 = 0x13b1_02ec; // linux: AMD_PMC_BASE_ADDR_HI
const BASE_ADDR_LO_MASK: u32 = 0xffff; // linux: AMD_PMC_BASE_ADDR_LO_MASK
const BASE_ADDR_HI_MASK: u32 = 0xfff0_0000; // linux: AMD_PMC_BASE_ADDR_HI_MASK

const RESULT_OK: u32 = 0x01; // linux: AMD_PMC_RESULT_OK
const RESULT_CMD_REJECT_BUSY: u32 = 0xfc; // linux: AMD_PMC_RESULT_CMD_REJECT_BUSY
const RESULT_CMD_UNKNOWN: u32 = 0xfe; // linux: AMD_PMC_RESULT_CMD_UNKNOWN

/// `enum amd_pmc_def`.
const MSG_OS_HINT_PCO: u32 = 0x02; // linux: MSG_OS_HINT_PCO
const MSG_OS_HINT_RN: u32 = 0x03; // linux: MSG_OS_HINT_RN
const SMU_MSG_LOG_DUMP_DATA: u32 = 0x08; // linux: SMU_MSG_LOG_DUMP_DATA

/// `readx_poll_timeout(..., PMC_MSG_DELAY_MIN_US, PMC_MSG_DELAY_MIN_US *
/// RESPONSE_REGISTER_LOOP_MAX)`: 1 s.
// linux: n/a (PMC_MSG_DELAY_MIN_US 50 * RESPONSE_REGISTER_LOOP_MAX 20000)
const RESPONSE_TIMEOUT_NS: u64 = 50 * 20_000 * 1_000;

/// `PCI_DEVICE_ID_AMD_CPU_ID_*` and the 1Ah root complexes.
pub mod cpu_id {
    pub const PCO: u16 = 0x15d0; // linux: PCI_DEVICE_ID_AMD_CPU_ID_PCO
    pub const CZN: u16 = 0x1630; // linux: PCI_DEVICE_ID_AMD_CPU_ID_CZN
    pub const VG: u16 = 0x1645; // linux: PCI_DEVICE_ID_AMD_CPU_ID_VG
    pub const YC: u16 = 0x14b5; // linux: PCI_DEVICE_ID_AMD_CPU_ID_YC
    pub const CB: u16 = 0x14d8; // linux: PCI_DEVICE_ID_AMD_CPU_ID_CB
    pub const PS: u16 = 0x14e8; // linux: PCI_DEVICE_ID_AMD_CPU_ID_PS
    pub const SP: u16 = 0x14a4; // linux: PCI_DEVICE_ID_AMD_CPU_ID_SP
    pub const SHP: u16 = 0x153a; // linux: PCI_DEVICE_ID_AMD_CPU_ID_SHP
    pub const M20H_ROOT: u16 = 0x1507; // linux: PCI_DEVICE_ID_AMD_1AH_M20H_ROOT
    pub const M60H_ROOT: u16 = 0x1122; // linux: PCI_DEVICE_ID_AMD_1AH_M60H_ROOT
    pub const M80H_ROOT: u16 = 0x115b; // linux: PCI_DEVICE_ID_AMD_1AH_M80H_ROOT
}

/// `struct amd_pmc_cpu_info`: the mailbox registers and the OS hint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CpuInfo {
    pub message: u32,
    pub argument: u32,
    pub response: u32,
    pub os_hint: u32,
}
const PCO_INFO: CpuInfo = CpuInfo {
    message: REGISTER_MESSAGE,
    argument: REGISTER_ARGUMENT,
    response: REGISTER_RESPONSE,
    os_hint: MSG_OS_HINT_PCO,
};
/// `amd_czn_cpu_info`, `amd_vg_cpu_info`, `amd_yc_cpu_info` and
/// `amd_ps_cpu_info`: one mailbox and `MSG_OS_HINT_RN`.
const RN_INFO: CpuInfo = CpuInfo {
    os_hint: MSG_OS_HINT_RN,
    ..PCO_INFO
};
/// `amd_1ah_cpu_info` and `amd_1ah_m70_cpu_info`.
const M20H_INFO: CpuInfo = CpuInfo {
    message: REGISTER_MSG_1AH_20H,
    ..RN_INFO
};
/// `amd_1ah_m80_cpu_info`.
const M80H_INFO: CpuInfo = CpuInfo {
    message: REGISTER_MSG_1AH_80H,
    argument: REGISTER_ARG_1AH_80H,
    response: REGISTER_RSP_1AH_80H,
    os_hint: MSG_OS_HINT_RN,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PmcError {
    /// The root complex is not in `pmc_pci_ids`.
    UnknownCpu(u16),
    /// The SoC has no S0i3 ("S0i3 is not supported on this hardware").
    NoS0i3,
    /// No ACPI PMC device, or its window could not be read or mapped.
    Absent,
    /// "failed to talk to SMU" / "SMU response timed out".
    Timeout,
    /// `AMD_PMC_RESULT_CMD_REJECT_BUSY`.
    Busy,
    /// `AMD_PMC_RESULT_CMD_UNKNOWN`.
    Unknown,
    /// Any other failure response.
    Failed(u32),
}

/// `amd_pmc_set_cpu_info`. Every 1Ah M20H/M60H part takes the same
/// mailbox; the M70h variant differs from the others only in its idle-mask
/// table.
pub fn cpu_info(root_device: u16) -> Result<CpuInfo, PmcError> {
    use cpu_id::*;
    match root_device {
        PCO => Ok(PCO_INFO),
        CZN | VG | YC | CB | PS => Ok(RN_INFO),
        M20H_ROOT | M60H_ROOT => Ok(M20H_INFO),
        M80H_ROOT => Ok(M80H_INFO),
        SP | SHP => Err(PmcError::NoS0i3),
        other => Err(PmcError::UnknownCpu(other)),
    }
}

/// `amd_pmc_probe`'s base: the SMN words, masked as Linux masks them (the
/// low word keeps bits 31:20, the high word bits 15:0), plus the offset.
pub fn window(lo: u32, hi: u32) -> u64 {
    let base = (u64::from(hi & BASE_ADDR_LO_MASK) << 32) | u64::from(lo & BASE_ADDR_HI_MASK);
    base + BASE_ADDR_OFFSET
}

/// The mailbox registers, by offset into the window.
pub trait Mailbox {
    fn read32(&mut self, offset: u32) -> u32;
    fn write32(&mut self, offset: u32, value: u32);
    /// Monotonic nanoseconds, for the response timeout.
    fn now_ns(&mut self) -> u64;
}

fn wait_response(mb: &mut impl Mailbox, info: &CpuInfo) -> Result<u32, PmcError> {
    let deadline = mb.now_ns().saturating_add(RESPONSE_TIMEOUT_NS);
    loop {
        let value = mb.read32(info.response);
        if value != 0 {
            return Ok(value);
        }
        if mb.now_ns() >= deadline {
            return Err(PmcError::Timeout);
        }
        core::hint::spin_loop();
    }
}

/// `amd_pmc_send_cmd` without a data reply: wait for the previous
/// response, clear it, write the argument and the message, then wait for
/// and decode the new response.
pub fn send(mb: &mut impl Mailbox, info: &CpuInfo, arg: u32, msg: u32) -> Result<(), PmcError> {
    wait_response(mb, info)?;
    mb.write32(info.response, 0);
    mb.write32(info.argument, arg);
    mb.write32(info.message, msg);
    match wait_response(mb, info)? {
        RESULT_OK => Ok(()),
        RESULT_CMD_REJECT_BUSY => Err(PmcError::Busy),
        RESULT_CMD_UNKNOWN => Err(PmcError::Unknown),
        other => Err(PmcError::Failed(other)),
    }
}

/// The s2idle hooks' messages: the OS hint with 1 at prepare. At restore,
/// the hint with 0, then (except on Picasso) the log dump
/// (`amd_pmc_dump_data`).
pub fn prepare(mb: &mut impl Mailbox, info: &CpuInfo) -> Result<(), PmcError> {
    send(mb, info, 1, info.os_hint)
}
pub fn restore(mb: &mut impl Mailbox, info: &CpuInfo) -> Result<(), PmcError> {
    let hint = send(mb, info, 0, info.os_hint);
    if info.os_hint != MSG_OS_HINT_PCO {
        let _ = send(mb, info, 0, SMU_MSG_LOG_DUMP_DATA);
    }
    hint
}

/// The bound PMC: its mapped window and mailbox.
struct Bound {
    regs: u64,
    info: CpuInfo,
}
struct Mmio(u64);
impl Mailbox for Mmio {
    fn read32(&mut self, offset: u32) -> u32 {
        // SAFETY: the window is this driver's `ioremap` of the PMC's 4 KiB
        // (Device attributes), and every mailbox offset is inside it.
        unsafe { core::ptr::read_volatile((self.0 + u64::from(offset)) as *const u32) }
    }
    fn write32(&mut self, offset: u32, value: u32) {
        // SAFETY: as for `read32`.
        unsafe { core::ptr::write_volatile((self.0 + u64::from(offset)) as *mut u32, value) }
    }
    fn now_ns(&mut self) -> u64 {
        narf_time::monotonic_ns()
    }
}
/// `pmc.lock`: one mailbox transaction at a time.
static PMC: IrqSafeSpinLock<Option<Bound>> = IrqSafeSpinLock::new(None);
static BOUND: AtomicBool = AtomicBool::new(false);

/// Whether the driver bound (Linux's `CONFIG_AMD_PMC` with the driver probed).
pub fn bound() -> bool {
    BOUND.load(Ordering::Acquire)
}

struct Lps0Hooks;
impl narf_power::lps0::Handler for Lps0Hooks {
    fn name(&self) -> &'static str {
        "amd_pmc"
    }
    fn prepare(&self) {
        let mut pmc = PMC.lock();
        if let Some(Bound { regs, info }) = pmc.as_mut() {
            if let Err(error) = prepare(&mut Mmio(*regs), info) {
                log(format_args!("suspend failed: {error:?}"));
            }
        }
    }
    fn restore(&self) {
        let mut pmc = PMC.lock();
        if let Some(Bound { regs, info }) = pmc.as_mut() {
            if let Err(error) = restore(&mut Mmio(*regs), info) {
                log(format_args!("resume failed: {error:?}"));
            }
        }
    }
}
static HOOKS: Lps0Hooks = Lps0Hooks;

fn log(args: core::fmt::Arguments<'_>) {
    use core::fmt::Write as _;
    let _ = writeln!(narf_console::Writer, "amd_pmc: {args}");
}

/// An SMN read through the root complex's config window (`amd_smn_read`:
/// index 0x60, data 0x64), serialized by the caller.
fn smn_read(cfg: narf_memory::PhysAddr, address: u32) -> Option<u32> {
    let index = narf_bus::ecam::ptr_for(cfg, 0x60)? as *mut u32;
    let data = narf_bus::ecam::ptr_for(cfg, 0x64)? as *const u32;
    narf_bus::ecam::ptr_for(cfg, 0x67)?;
    // SAFETY: both aligned words lie within the root complex's live ECAM
    // mapping; the probe runs once, before any other SMN user here.
    let value = unsafe {
        core::ptr::write_volatile(index, address);
        core::ptr::read_volatile(data)
    };
    (value != u32::MAX).then_some(value)
}

/// `amd_pmc_probe`: bind once, register the LPS0 hooks.
pub fn init() -> Result<(), PmcError> {
    let present = narf_aml::list_all_device_paths().into_iter().any(|path| {
        narf_aml::device_hid(&path).is_some_and(|hid| ACPI_IDS.contains(&hid.as_str()))
    });
    if !present {
        return Err(PmcError::Absent);
    }
    let root = narf_bus::devices()
        .into_iter()
        .find(|d| {
            d.id.vendor == 0x1022
                && matches!(d.kind, narf_bus::BusKind::Pcie { addr, .. }
                    if addr.segment == 0 && addr.bus == 0 && addr.device == 0 && addr.function == 0)
        })
        .ok_or(PmcError::Absent)?;
    let info = cpu_info(root.id.device)?;
    let narf_bus::BusKind::Pcie { cfg_phys, .. } = root.kind else {
        return Err(PmcError::Absent);
    };
    let lo = smn_read(cfg_phys, BASE_ADDR_LO).ok_or(PmcError::Absent)?;
    let hi = smn_read(cfg_phys, BASE_ADDR_HI).ok_or(PmcError::Absent)?;
    let phys = window(lo, hi);
    // SAFETY: the PMC's mailbox window is device MMIO that no other owner
    // maps; Device attributes keep the accesses uncached and ordered.
    let mapping = unsafe {
        narf_memory::ioremap::ioremap(phys, MAPPING_SIZE, narf_memory::ioremap::MmioAttrs::Device)
    }
    .map_err(|_| PmcError::Absent)?;
    *PMC.lock() = Some(Bound {
        regs: mapping.va(),
        info,
    });
    BOUND.store(true, Ordering::Release);
    narf_power::lps0::register(&HOOKS);
    log(format_args!(
        "root {:#06x}, mailbox at {phys:#x}, OS hint {:#x}",
        root.id.device, info.os_hint
    ));
    Ok(())
}

#[cfg(feature = "kernel-test")]
#[path = "amd_pmc_tests.rs"]
mod tests;
