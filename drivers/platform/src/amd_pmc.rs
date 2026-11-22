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
//! Around each park, as Linux's `amd_pmc_s2idle_*` do:
//! - **prepare:** reset and start SMU logging (the metrics table), then the
//!   OS hint;
//! - **check:** the 2.5 s delay before re-entering S0i3 after a wakeup
//!   that did reach it (over-voltage protection), or that the
//!   `need_suspend_delay` quirk or `amd_pmc.delay_suspend=1` asks for; then
//!   the idle mask;
//! - **restore:** the OS hint, the log dump, the deepest-state check, and
//!   the restore quirks ([`crate::amd_pmc_quirks`]).
//!
//! Every wait runs on the raw cycle counter, because the park has frozen
//! `CLOCK_MONOTONIC`.
//!
//! Not done:
//! - STB, off by default in Linux (`enable_stb`);
//! - the debugfs statistics;
//! - Cezanne's RTC wake programming beyond its version gate. NARF has no RTC
//!   alarm API, so no alarm is ever pending, which is
//!   `amd_pmc_verify_czn_rtc`'s "no alarm" path.
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
const SMU_MSG_GETSMUVERSION: u32 = 0x02; // linux: SMU_MSG_GETSMUVERSION
const SMU_MSG_LOG_GETDRAM_ADDR_HI: u32 = 0x04; // linux: SMU_MSG_LOG_GETDRAM_ADDR_HI
const SMU_MSG_LOG_GETDRAM_ADDR_LO: u32 = 0x05; // linux: SMU_MSG_LOG_GETDRAM_ADDR_LO
const SMU_MSG_LOG_START: u32 = 0x06; // linux: SMU_MSG_LOG_START
const SMU_MSG_LOG_RESET: u32 = 0x07; // linux: SMU_MSG_LOG_RESET
const SMU_MSG_LOG_DUMP_DATA: u32 = 0x08; // linux: SMU_MSG_LOG_DUMP_DATA
const SMU_MSG_GET_SUP_CONSTRAINTS: u32 = 0x09; // linux: SMU_MSG_GET_SUP_CONSTRAINTS
/// `usleep_range(DELAY_MIN_US, ...)` before a data reply is read.
const DELAY_MIN_US: u64 = 2000; // linux: DELAY_MIN_US
/// `msleep(2500)` in `amd_pmc_s2idle_check`.
// linux: n/a (literal 2500 ms in amd_pmc_s2idle_check)
const SUSPEND_DELAY_US: u64 = 2_500_000;
const SCRATCH_REG_CZN: u32 = 0x94; // linux: AMD_PMC_SCRATCH_REG_CZN
const SCRATCH_REG_YC: u32 = 0xd14; // linux: AMD_PMC_SCRATCH_REG_YC
const SCRATCH_REG_1AH: u32 = 0xf14; // linux: AMD_PMC_SCRATCH_REG_1AH
/// `sizeof(struct smu_metrics)`: four u32s, eight u64s, two u64[32].
// linux: n/a (sizeof(struct smu_metrics), pmc.h)
pub const METRICS_SIZE: u64 = 4 * 4 + 8 * 8 + 2 * 32 * 8;
// struct smu_metrics offsets.
const METRICS_S0I3_LAST_ENTRY_STATUS: u64 = 8; // linux: n/a (offsetof(struct smu_metrics, s0i3_last_entry_status))
const METRICS_TIMEIN_S0I3_LASTCAPTURE: u64 = 48; // linux: n/a (offsetof(struct smu_metrics, timein_s0i3_lastcapture))

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

/// `struct amd_pmc_cpu_info`: the mailbox registers, the OS hint and the
/// idle-mask scratch register.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CpuInfo {
    pub message: u32,
    pub argument: u32,
    pub response: u32,
    pub os_hint: u32,
    /// `scratch_reg`, for the idle mask; none on Picasso and Van Gogh.
    pub scratch: Option<u32>,
}
const PCO_INFO: CpuInfo = CpuInfo {
    message: REGISTER_MESSAGE,
    argument: REGISTER_ARGUMENT,
    response: REGISTER_RESPONSE,
    os_hint: MSG_OS_HINT_PCO,
    scratch: None,
};
/// `amd_vg_cpu_info`.
const VG_INFO: CpuInfo = CpuInfo {
    os_hint: MSG_OS_HINT_RN,
    ..PCO_INFO
};
/// `amd_czn_cpu_info`.
const CZN_INFO: CpuInfo = CpuInfo {
    scratch: Some(SCRATCH_REG_CZN),
    ..VG_INFO
};
/// `amd_yc_cpu_info` (Rembrandt and Raphael) and `amd_ps_cpu_info`.
const YC_INFO: CpuInfo = CpuInfo {
    scratch: Some(SCRATCH_REG_YC),
    ..VG_INFO
};
/// `amd_1ah_cpu_info` and `amd_1ah_m70_cpu_info`.
const M20H_INFO: CpuInfo = CpuInfo {
    message: REGISTER_MSG_1AH_20H,
    scratch: Some(SCRATCH_REG_1AH),
    ..VG_INFO
};
/// `amd_1ah_m80_cpu_info`.
const M80H_INFO: CpuInfo = CpuInfo {
    message: REGISTER_MSG_1AH_80H,
    argument: REGISTER_ARG_1AH_80H,
    response: REGISTER_RSP_1AH_80H,
    os_hint: MSG_OS_HINT_RN,
    scratch: Some(SCRATCH_REG_1AH),
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
    /// Not on this SoC (`-ENODEV`/`-EINVAL`: Picasso's SMU logging, an
    /// old Cezanne SMU's idle mask, a CPU without a scratch register).
    Unsupported,
}

/// `amd_pmc_set_cpu_info`. Every 1Ah M20H/M60H part takes the same
/// mailbox; the M70h variant differs from the others only in its idle-mask
/// table.
pub fn cpu_info(root_device: u16) -> Result<CpuInfo, PmcError> {
    use cpu_id::*;
    match root_device {
        PCO => Ok(PCO_INFO),
        CZN => Ok(CZN_INFO),
        VG => Ok(VG_INFO),
        YC | CB | PS => Ok(YC_INFO),
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

/// The hardware a PMC session reaches: the mailbox registers, the SMU's
/// metrics table, and the FCH PM scratch byte.
pub trait Mailbox {
    fn read32(&mut self, offset: u32) -> u32;
    fn write32(&mut self, offset: u32, value: u32);
    /// Nanoseconds on a clock that runs through the park.
    fn now_ns(&mut self) -> u64;
    /// `usleep_range`/`msleep`: spin `us` microseconds.
    fn delay_us(&mut self, us: u64) {
        let end = self.now_ns().saturating_add(us * 1000);
        while self.now_ns() < end {
            core::hint::spin_loop();
        }
    }
    /// `devm_ioremap` of the metrics table at `phys`; false if it failed.
    fn map_table(&mut self, phys: u64) -> bool;
    /// A u32 of the mapped table; 0 when nothing is mapped.
    fn table_read32(&mut self, offset: u64) -> u32;
    /// `memset_io` of the mapped table.
    fn table_zero(&mut self);
    /// `amd_pmc_skip_nvme_smi_handler`: bit 0 of the FCH PM scratch byte
    /// cleared.
    fn clear_fch_scratch_bit0(&mut self);
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
/// `amd_pmc_send_cmd` with a data reply: the argument register, read after
/// PMFW's `DELAY_MIN_US`.
pub fn send_read(
    mb: &mut impl Mailbox,
    info: &CpuInfo,
    arg: u32,
    msg: u32,
) -> Result<u32, PmcError> {
    send(mb, info, arg, msg)?;
    mb.delay_us(DELAY_MIN_US);
    Ok(mb.read32(info.argument))
}

/// `amd_pmc.delay_suspend` and `amd_pmc.disable_workarounds`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Options {
    /// -1 (the default) lets the quirk decide, 0 never delays, 1 always does.
    pub delay_suspend: i8,
    pub disable_workarounds: bool,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            delay_suspend: -1,
            disable_workarounds: false,
        }
    }
}
impl Options {
    pub fn parse(args: &narf_boot::KernelCmdline<'_>) -> Self {
        let delay_suspend = match args.value("amd_pmc.delay_suspend") {
            Some("0") => 0,
            Some("1") => 1,
            _ => -1,
        };
        let disable_workarounds = matches!(
            args.value("amd_pmc.disable_workarounds"),
            Some("1" | "y" | "Y" | "true")
        );
        Self {
            delay_suspend,
            disable_workarounds,
        }
    }
}

/// What `struct amd_pmc_dev` keeps across suspend-to-idle cycles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct State {
    pub info: CpuInfo,
    /// The root complex's device ID (`cpu_id`).
    pub cpu: u16,
    /// `amd_pmc_get_smu_version`: program, major, minor, revision.
    pub version: Option<[u8; 4]>,
    /// `active_ips` (`SMU_MSG_GET_SUP_CONSTRAINTS`).
    pub active_ips: Option<u32>,
    /// The metrics table's physical address, once mapped.
    pub table: Option<u64>,
    /// `is_first_check_after_suspend`.
    pub first_check: bool,
    pub quirk: crate::amd_pmc_quirks::Quirk,
    pub options: Options,
}
impl State {
    pub fn new(
        cpu: u16,
        info: CpuInfo,
        quirk: crate::amd_pmc_quirks::Quirk,
        options: Options,
    ) -> Self {
        Self {
            info,
            cpu,
            version: None,
            active_ips: None,
            table: None,
            first_check: false,
            quirk,
            options,
        }
    }
    fn picasso(&self) -> bool {
        self.cpu == cpu_id::PCO
    }
}

/// `amd_pmc_get_smu_version`, once.
pub fn smu_version(mb: &mut impl Mailbox, st: &mut State) -> Result<[u8; 4], PmcError> {
    if st.picasso() {
        return Err(PmcError::Unsupported);
    }
    if let Some(version) = st.version {
        return Ok(version);
    }
    let value = send_read(mb, &st.info, 0, SMU_MSG_GETSMUVERSION)?;
    let version = value.to_be_bytes();
    st.version = Some(version);
    Ok(version)
}

/// `amd_pmc_setup_smu_logging`: the active-IP list and the metrics table's
/// address once, then the table zeroed and logging reset and started.
/// Linux ignores the messages' results, and so does this.
pub fn setup_logging(mb: &mut impl Mailbox, st: &mut State) -> Result<(), PmcError> {
    if st.picasso() {
        return Err(PmcError::Unsupported);
    }
    if st.active_ips.is_none() {
        st.active_ips = send_read(mb, &st.info, 0, SMU_MSG_GET_SUP_CONSTRAINTS).ok();
    }
    if st.table.is_none() {
        let lo = send_read(mb, &st.info, 0, SMU_MSG_LOG_GETDRAM_ADDR_LO).unwrap_or(0);
        let hi = send_read(mb, &st.info, 0, SMU_MSG_LOG_GETDRAM_ADDR_HI).unwrap_or(0);
        let phys = (u64::from(hi) << 32) | u64::from(lo);
        if !mb.map_table(phys) {
            return Err(PmcError::Absent);
        }
        st.table = Some(phys);
    }
    mb.table_zero();
    let _ = send(mb, &st.info, 0, SMU_MSG_LOG_RESET);
    let _ = send(mb, &st.info, 0, SMU_MSG_LOG_START);
    Ok(())
}

/// The two `struct smu_metrics` fields the s2idle hooks read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Metrics {
    pub s0i3_last_entry_status: u32,
    pub timein_s0i3_lastcapture: u64,
}
/// `get_metrics_table`, setting logging up first if it never was.
pub fn metrics(mb: &mut impl Mailbox, st: &mut State) -> Result<Metrics, PmcError> {
    if st.table.is_none() {
        setup_logging(mb, st)?;
    }
    if st.picasso() {
        return Err(PmcError::Unsupported);
    }
    let lo = mb.table_read32(METRICS_TIMEIN_S0I3_LASTCAPTURE);
    let hi = mb.table_read32(METRICS_TIMEIN_S0I3_LASTCAPTURE + 4);
    Ok(Metrics {
        s0i3_last_entry_status: mb.table_read32(METRICS_S0I3_LAST_ENTRY_STATUS),
        timein_s0i3_lastcapture: (u64::from(hi) << 32) | u64::from(lo),
    })
}

/// `amd_pmc_verify_czn_rtc`'s gate: from SMU 64.53 Cezanne's PMFW takes an
/// RTC wake time in the hint's upper 16 bits. NARF has no RTC alarm API,
/// so no alarm is pending: `arg` goes out unchanged, as Linux sends it with
/// none armed.
pub fn czn_rtc_hint(mb: &mut impl Mailbox, st: &mut State, arg: u32) -> Result<u32, PmcError> {
    let [_, major, minor, _] = smu_version(mb, st)?;
    if major < 64 || (major == 64 && minor < 53) {
        return Ok(arg);
    }
    Ok(arg)
}

/// `amd_pmc_s2idle_prepare`: SMU logging reset and started, then the OS hint
/// with 1 (plus, on Cezanne, the RTC programming).
pub fn prepare(mb: &mut impl Mailbox, st: &mut State) -> Result<(), PmcError> {
    st.first_check = true;
    let _ = setup_logging(mb, st);
    let mut arg = 1;
    if st.cpu == cpu_id::CZN && !st.options.disable_workarounds {
        arg = czn_rtc_hint(mb, st, arg)?;
    }
    send(mb, &st.info, arg, st.info.os_hint)
}

/// `amd_pmc_intermediate_wakeup_need_delay`: the last wakeup came out of
/// S0i3, and entering it again at once can trip over-voltage protection.
fn intermediate_wakeup_need_delay(mb: &mut impl Mailbox, st: &mut State) -> bool {
    metrics(mb, st).is_ok_and(|m| m.s0i3_last_entry_status != 0)
}
/// `amd_pmc_want_suspend_delay`: the `need_suspend_delay` quirk unless
/// disabled, or `delay_suspend=1`.
fn want_suspend_delay(st: &State) -> bool {
    let o = st.options;
    if st.quirk.need_suspend_delay {
        o.delay_suspend == 1 || (o.delay_suspend == -1 && !o.disable_workarounds)
    } else {
        o.delay_suspend == 1
    }
}
/// `amd_pmc_idlemask_read`. Cezanne needs SMU 55.37 or newer.
pub fn idle_mask(mb: &mut impl Mailbox, st: &mut State) -> Result<u32, PmcError> {
    if st.cpu == cpu_id::CZN {
        let [_, major, minor, _] = smu_version(mb, st)?;
        if !(major > 56 || (major >= 55 && minor >= 37)) {
            return Err(PmcError::Unsupported);
        }
    }
    let scratch = st.info.scratch.ok_or(PmcError::Unsupported)?;
    Ok(mb.read32(scratch))
}
/// What `check` did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Check {
    pub delayed: bool,
    pub idle_mask: Option<u32>,
}
/// `amd_pmc_s2idle_check`: the delay if needed, then the idle mask.
pub fn check(mb: &mut impl Mailbox, st: &mut State) -> Check {
    let delayed = intermediate_wakeup_need_delay(mb, st) || want_suspend_delay(st);
    if delayed {
        mb.delay_us(SUSPEND_DELAY_US);
    }
    let idle_mask = idle_mask(mb, st).ok();
    st.first_check = false;
    Check { delayed, idle_mask }
}
/// `amd_pmc_s2idle_restore`. The OS hint with 0, then (except on Picasso)
/// the log dump. Then `amd_pmc_validate_deepest`'s metrics, then the restore
/// quirk. Returns the hint's result and the metrics read.
pub fn restore(mb: &mut impl Mailbox, st: &mut State) -> (Result<(), PmcError>, Option<Metrics>) {
    let hint = send(mb, &st.info, 0, st.info.os_hint);
    if !st.picasso() {
        let _ = send(mb, &st.info, 0, SMU_MSG_LOG_DUMP_DATA);
    }
    let deepest = metrics(mb, st).ok();
    if st.quirk.s2idle_bug_mmio {
        mb.clear_fch_scratch_bit0();
    }
    (hint, deepest)
}

/// The bound PMC: its mapped window, the metrics table mapping, and its
/// state.
struct Bound {
    mmio: Mmio,
    state: State,
}
struct Mmio {
    regs: u64,
    table: Option<u64>,
}
fn raw_ns() -> u64 {
    narf_time::cycles_to_ns(narf_time::raw_cycles())
}
impl Mailbox for Mmio {
    fn read32(&mut self, offset: u32) -> u32 {
        // SAFETY: the window is this driver's `ioremap` of the PMC's 4 KiB
        // (Device attributes), and every mailbox offset is inside it.
        unsafe { core::ptr::read_volatile((self.regs + u64::from(offset)) as *const u32) }
    }
    fn write32(&mut self, offset: u32, value: u32) {
        // SAFETY: as for `read32`.
        unsafe { core::ptr::write_volatile((self.regs + u64::from(offset)) as *mut u32, value) }
    }
    fn now_ns(&mut self) -> u64 {
        raw_ns()
    }
    fn map_table(&mut self, phys: u64) -> bool {
        // SAFETY: PMFW owns the table at `phys` and hands its address out
        // for exactly this read-only use; Device attributes keep it
        // uncached.
        match unsafe {
            narf_memory::ioremap::ioremap(
                phys,
                METRICS_SIZE,
                narf_memory::ioremap::MmioAttrs::Device,
            )
        } {
            Ok(mapping) => {
                self.table = Some(mapping.va());
                true
            }
            Err(_) => false,
        }
    }
    fn table_read32(&mut self, offset: u64) -> u32 {
        match self.table {
            // SAFETY: `offset` lies within the mapped METRICS_SIZE bytes.
            Some(va) if offset + 4 <= METRICS_SIZE => unsafe {
                core::ptr::read_volatile((va + offset) as *const u32)
            },
            _ => 0,
        }
    }
    fn table_zero(&mut self) {
        if let Some(va) = self.table {
            for offset in (0..METRICS_SIZE).step_by(4) {
                // SAFETY: as for `table_read32`.
                unsafe { core::ptr::write_volatile((va + offset) as *mut u32, 0) };
            }
        }
    }
    fn clear_fch_scratch_bit0(&mut self) {
        use crate::amd_pmc_quirks::FCH_PM_SCRATCH;
        // SAFETY: the FCH PM scratch byte is chipset MMIO no other NARF owner
        // maps; one byte is read and written back, as Linux does.
        if let Ok(mapping) = unsafe {
            narf_memory::ioremap::ioremap(
                FCH_PM_SCRATCH,
                1,
                narf_memory::ioremap::MmioAttrs::Device,
            )
        } {
            let at = mapping.va() as *mut u8;
            // SAFETY: the byte just mapped.
            unsafe { core::ptr::write_volatile(at, core::ptr::read_volatile(at) & !1) };
        }
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
        if let Some(Bound { mmio, state }) = pmc.as_mut() {
            if let Err(error) = prepare(mmio, state) {
                log(format_args!("suspend failed: {error:?}"));
            }
        }
    }
    fn check(&self) {
        let mut pmc = PMC.lock();
        if let Some(Bound { mmio, state }) = pmc.as_mut() {
            let first = state.first_check;
            let done = check(mmio, state);
            if done.delayed && first {
                log(format_args!(
                    "delaying suspend by 2.5s to avoid a platform bug"
                ));
            }
            if let Some(mask) = done.idle_mask {
                use core::fmt::Write as _;
                let _ = writeln!(
                    narf_console::PriorityWriter::<7>,
                    "amd_pmc: SMU idlemask s0i3: {mask:#x}"
                );
            }
        }
    }
    fn restore(&self) {
        let mut pmc = PMC.lock();
        if let Some(Bound { mmio, state }) = pmc.as_mut() {
            let (hint, deepest) = restore(mmio, state);
            if let Err(error) = hint {
                log(format_args!("resume failed: {error:?}"));
            }
            match deepest {
                Some(m) if m.s0i3_last_entry_status == 0 => {
                    log(format_args!("Last suspend didn't reach deepest state"));
                }
                Some(m) => {
                    use core::fmt::Write as _;
                    let _ = writeln!(
                        narf_console::PriorityWriter::<7>,
                        "amd_pmc: last suspend in deepest state for {}us",
                        m.timein_s0i3_lastcapture
                    );
                }
                None => {}
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

/// `amd_pmc_probe` with `amd_pmc_quirks_init`: bind once, register the
/// LPS0 hooks.
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
    let options = Options::parse(&narf_boot::args());
    let quirk = if options.disable_workarounds {
        crate::amd_pmc_quirks::Quirk::default()
    } else {
        match crate::amd_pmc_quirks::lookup(&crate::amd_pmc_quirks::read_dmi()) {
            Some((ident, quirk)) => {
                if quirk.s2idle_bug_mmio {
                    log(format_args!(
                        "Using s2idle quirk to avoid {ident} platform firmware bug"
                    ));
                }
                quirk
            }
            None => crate::amd_pmc_quirks::Quirk::default(),
        }
    };
    *PMC.lock() = Some(Bound {
        mmio: Mmio {
            regs: mapping.va(),
            table: None,
        },
        state: State::new(root.id.device, info, quirk, options),
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
