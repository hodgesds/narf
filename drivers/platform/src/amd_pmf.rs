//! AMD Platform Management Framework (PMF): the static power slider.
//!
//! Port of the SPS ("static power slider") half of Linux
//! `drivers/platform/x86/amd/pmf/` (`core.c`, `acpi.c`, `sps.c`,
//! `pmf.h`). PMF is firmware (the `AMDI0102`-class ACPI device and its
//! `APMF` method) plus the SMU's power-limit mailbox. The BIOS publishes
//! a power-limit table per power source (AC/DC) and slider position;
//! the OS picks the position through `platform_profile` and pushes the
//! matching limits to the SMU, and re-pushes them when the power source
//! changes:
//!
//! | Profile                         | Slider (`POWER_MODE_*`) |
//! |---------------------------------|-------------------------|
//! | `performance`                   | `PERFORMANCE`           |
//! | `balanced`                      | `BALANCED_POWER`        |
//! | `low-power`                     | `POWER_SAVER`           |
//!
//! Interface v1 tables carry the limits themselves (SPL, SPPT,
//! SPPT-APU-only, FPPT, STT minimum and the APU/HS2 skin-temperature
//! limits). Interface v2 tables carry an index per (source, mode) into
//! the `APTS` table of PMF PPT, PMF PPT-APU-only and STT limits.
//!
//! Also ported: `OS_POWER_SLIDER_UPDATE` (telling the BIOS the slider
//! position), the v1 SBIOS heartbeat and the v2 load heartbeat.
//!
//! Not ported (see the drivers spec §3.9): Auto Mode, CnQF and Smart PC
//! (the TEE policy engine), SBIOS request notifications, suspend/resume
//! heartbeats, and the metrics table. Their APMF bits are logged at
//! probe so a machine's needs are visible.

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt::Write as _;
use core::sync::atomic::{AtomicBool, Ordering};

use narf_aml::Value;
use narf_lib::sync::IrqSafeSpinLock;

use crate::amd_smu::{self, MailboxRegs, SmuMailbox};
use crate::platform_profile::{self, PlatformProfile, ProfileBackend};

// ── APMF functions (pmf.h) ───────────────────────────────────────────

pub const APMF_FUNC_VERIFY_INTERFACE: u32 = 0;
pub const APMF_FUNC_GET_SYS_PARAMS: u32 = 1;
pub const APMF_FUNC_SBIOS_REQUESTS: u32 = 2;
pub const APMF_FUNC_SBIOS_HEARTBEAT: u32 = 4;
pub const APMF_FUNC_AUTO_MODE: u32 = 5;
pub const APMF_FUNC_SET_FAN_IDX: u32 = 7;
pub const APMF_FUNC_OS_POWER_SLIDER_UPDATE: u32 = 8;
pub const APMF_FUNC_STATIC_SLIDER_GRANULAR: u32 = 9;
pub const APMF_FUNC_DYN_SLIDER_AC: u32 = 11;
pub const APMF_FUNC_DYN_SLIDER_DC: u32 = 12;
pub const APMF_FUNC_NOTIFY_SMART_PC_UPDATES: u32 = 14;
pub const APMF_FUNC_SBIOS_HEARTBEAT_V2: u32 = 16;

pub const PMF_IF_V1: u16 = 1;
pub const PMF_IF_V2: u16 = 2;

// ── SMU messages (pmf.h) ─────────────────────────────────────────────

pub const SET_SPL: u32 = 0x03;
pub const SET_SPPT: u32 = 0x05;
pub const SET_FPPT: u32 = 0x07;
pub const SET_STT_MIN_LIMIT: u32 = 0x18;
pub const SET_STT_LIMIT_APU: u32 = 0x19;
pub const SET_STT_LIMIT_HS2: u32 = 0x1A;
pub const SET_SPPT_APU_ONLY: u32 = 0x1D;
pub const SET_PMF_PPT: u32 = 0x25;
pub const SET_PMF_PPT_APU_ONLY: u32 = 0x26;

/// The PMF mailbox in the SMU window (`AMD_PMF_REGISTER_*`).
pub const PMF_REGS: MailboxRegs = MailboxRegs {
    message: 0xA18,
    argument: 0xA58,
    response: 0xA78,
};

/// `amd_pmf_acpi_ids`: (HID, needs `force_load`).
pub const ACPI_IDS: [(&str, bool); 6] = [
    ("AMDI0100", true),
    ("AMDI0102", false),
    ("AMDI0103", false),
    ("AMDI0105", false),
    ("AMDI0107", false),
    ("AMDI0108", false),
];

/// `pmf_pci_ids`: root complexes PMF supports.
pub const ROOT_IDS: [u16; 4] = [
    crate::amd_pmc::cpu_id::YC, // AMD_CPU_ID_RMB
    crate::amd_pmc::cpu_id::PS,
    crate::amd_pmc::cpu_id::M20H_ROOT,
    crate::amd_pmc::cpu_id::M60H_ROOT,
];

/// Power source index into the tables (`POWER_SOURCE_*`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PowerSource {
    Ac = 0,
    Dc = 1,
}

/// Slider position (`POWER_MODE_*`, the v1 table's second index).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PowerMode {
    Performance = 0,
    BalancedPower = 1,
    PowerSaver = 2,
}

/// `amd_pmf_get_pprof_modes`.
pub fn mode_for(profile: PlatformProfile) -> Option<PowerMode> {
    match profile {
        PlatformProfile::Performance | PlatformProfile::BalancedPerformance => {
            Some(PowerMode::Performance)
        }
        PlatformProfile::Balanced => Some(PowerMode::BalancedPower),
        PlatformProfile::LowPower | PlatformProfile::Quiet => Some(PowerMode::PowerSaver),
        PlatformProfile::Cool => None,
    }
}

// ── Firmware buffers ─────────────────────────────────────────────────

/// Why an `APMF` / `APTS` call produced no usable buffer.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FwError {
    /// The method call failed (Linux `-EIO`).
    CallFailed,
    /// The result is not a buffer, or is shorter than its header or than
    /// the structure read from it (Linux `-EINVAL`).
    BadBuffer,
    /// The function is not in the supported bitmap (Linux `-EINVAL`).
    Unsupported,
}

/// `apmf_if_call_store_buffer`'s checks: a buffer of at least 2 bytes
/// whose leading u16 size fits in it and covers `out_sz`.
pub fn store_buffer(result: &Value, out_sz: usize) -> Result<&[u8], FwError> {
    let Value::Buffer(b) = result else {
        return Err(FwError::BadBuffer);
    };
    if b.len() < 2 {
        return Err(FwError::BadBuffer);
    }
    let size = usize::from(u16::from_le_bytes([b[0], b[1]]));
    if b.len() < size || size < out_sz {
        return Err(FwError::BadBuffer);
    }
    Ok(&b[..out_sz])
}

fn le16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

/// `struct apmf_verify_interface`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct VerifyInterface {
    pub version: u16,
    pub notification_mask: u32,
    pub supported_functions: u32,
}

impl VerifyInterface {
    pub const SIZE: usize = 12;
    pub fn parse(b: &[u8]) -> Self {
        Self {
            version: le16(b, 2),
            notification_mask: le32(b, 4),
            supported_functions: le32(b, 8),
        }
    }
}

/// `struct apmf_system_params` (only what the driver uses).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SystemParams {
    pub valid_mask: u32,
    pub flags: u32,
    pub command_code: u8,
    pub heartbeat_int: u32,
}

impl SystemParams {
    pub const SIZE: usize = 15;
    pub fn parse(b: &[u8]) -> Self {
        Self {
            valid_mask: le32(b, 2),
            flags: le32(b, 6),
            command_code: b[10],
            heartbeat_int: le32(b, 11),
        }
    }
}

/// `struct apmf_sps_prop_granular`: one v1 table entry.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct SpsProp {
    pub fppt: u32,
    pub sppt: u32,
    pub sppt_apu_only: u32,
    pub spl: u32,
    pub stt_min: u32,
    pub stt_skin_temp_apu: u8,
    pub stt_skin_temp_hs2: u8,
    pub fan_id: u32,
}

impl SpsProp {
    pub const SIZE: usize = 26;
    fn parse(b: &[u8]) -> Self {
        Self {
            fppt: le32(b, 0),
            sppt: le32(b, 4),
            sppt_apu_only: le32(b, 8),
            spl: le32(b, 12),
            stt_min: le32(b, 16),
            stt_skin_temp_apu: b[20],
            stt_skin_temp_hs2: b[21],
            fan_id: le32(b, 22),
        }
    }
}

/// `struct apmf_static_slider_granular_output` (v1): six entries,
/// source-major (`prop[src * 3 + mode]`).
pub const SPS_V1_SIZE: usize = 2 + 6 * SpsProp::SIZE;
/// `struct apmf_static_slider_granular_output_v2`: `power_states[2][4]`.
pub const SPS_V2_SIZE: usize = 2 + 8;
/// `APTS_MAX_STATES`.
pub const APTS_MAX_STATES: usize = 16;

/// `struct amd_pmf_apts_output`: one v2 APTS entry.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct AptsProp {
    pub table_version: u16,
    pub fan_table_idx: u32,
    pub pmf_ppt: u32,
    pub ppt_pmf_apu_only: u32,
    pub stt_min_limit: u32,
    pub stt_skin_temp_limit_apu: u8,
    pub stt_skin_temp_limit_hs2: u8,
}

impl AptsProp {
    /// `struct amd_pmf_apts_granular_output`: u16 size, then the entry.
    pub const SIZE: usize = 2 + 20;
    fn parse(b: &[u8]) -> Self {
        Self {
            table_version: le16(b, 2),
            fan_table_idx: le32(b, 4),
            pmf_ppt: le32(b, 8),
            ppt_pmf_apu_only: le32(b, 12),
            stt_min_limit: le32(b, 16),
            stt_skin_temp_limit_apu: b[20],
            stt_skin_temp_limit_hs2: b[21],
        }
    }
}

/// The loaded static-slider tables.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SpsTables {
    /// `config_store.prop[src][mode]`.
    V1([[SpsProp; 3]; 2]),
    /// `config_store_v2.sps_idx.power_states[src][mode_v2]` and the APTS
    /// table it indexes (`apts_config_store`).
    V2 {
        states: [[u8; 4]; 2],
        apts: [AptsProp; APTS_MAX_STATES],
    },
}

/// `fixp_q88_fromint`: an integer as Q8.8.
pub const fn q88(v: u32) -> u32 {
    v << 8
}

// ── Seams ────────────────────────────────────────────────────────────

/// Exclusive use of the SMU mailbox for one batch of messages — Linux's
/// `dev->lock`, held across each whole `amd_pmf_send_cmd`. A plain
/// [`SmuMailbox`] (a test fake) is its own exclusive access.
pub trait MailboxAccess {
    fn transact(&mut self, f: &mut dyn FnMut(&mut dyn SmuMailbox));
}

impl<M: SmuMailbox> MailboxAccess for M {
    fn transact(&mut self, f: &mut dyn FnMut(&mut dyn SmuMailbox)) {
        f(self)
    }
}

/// What PMF needs from firmware: the `APMF` and `APTS` methods and the
/// system power source.
pub trait Firmware {
    /// `APMF(func, param)`: `param` is a buffer, or the integer 0 when
    /// `None` (`apmf_if_call`).
    fn apmf(&mut self, func: u32, param: Option<&[u8]>) -> Result<Value, FwError>;
    /// `APTS(1, index, 0)` (`apts_if_call`).
    fn apts(&mut self, index: u32) -> Result<Value, FwError>;
    /// `power_supply_is_system_supplied() > 0`.
    fn on_ac(&mut self) -> bool;
}

/// The bound device's view of firmware through the AML namespace.
#[derive(Debug)]
pub struct AmlFirmware {
    pub device: String,
}

impl Firmware for AmlFirmware {
    fn apmf(&mut self, func: u32, param: Option<&[u8]>) -> Result<Value, FwError> {
        let arg = match param {
            Some(b) => Value::Buffer(b.to_vec()),
            None => Value::Integer(0),
        };
        let path = format!("{}.APMF", self.device);
        narf_aml::eval::evaluate_method(&path, &[Value::Integer(u64::from(func)), arg]).map_err(
            |_| {
                log(format_args!("APMF method:{func} call failed"));
                FwError::CallFailed
            },
        )
    }

    fn apts(&mut self, index: u32) -> Result<Value, FwError> {
        let path = format!("{}.APTS", self.device);
        narf_aml::eval::evaluate_method(
            &path,
            &[
                Value::Integer(1),
                Value::Integer(u64::from(index)),
                Value::Integer(0),
            ],
        )
        .map_err(|_| {
            log(format_args!("APTS state_idx:{index} call failed"));
            FwError::CallFailed
        })
    }

    /// `power_supply_is_system_supplied`: online if any mains supply is;
    /// with no mains supply registered at all, assume a desktop on AC.
    fn on_ac(&mut self) -> bool {
        let adapters = narf_power::ac::enumerate();
        adapters.is_empty() || adapters.iter().any(|a| matches!(a.present(), Ok(true)))
    }
}

// ── Driver state ─────────────────────────────────────────────────────

/// Everything PMF learned at probe, plus the selected profile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct State {
    pub version: u16,
    pub supported: u32,
    pub notifications: u32,
    /// SBIOS heartbeat interval in seconds (v1); 0 means none.
    pub hb_interval: u32,
    pub profile: PlatformProfile,
    /// `None` when the BIOS has no static-slider table, or loading it
    /// failed.
    pub sps: Option<SpsTables>,
}

impl State {
    /// `is_apmf_func_supported`: bit `n - 1` set means function `n`.
    pub fn supported(&self, func: u32) -> bool {
        func != 0 && self.supported & (1 << (func - 1)) != 0
    }
}

/// `apmf_if_verify_interface` + `apmf_get_system_params` + the table
/// loads of `amd_pmf_init_sps`. `None` when `verify_interface` fails:
/// the device then offers nothing (Linux binds with no functions).
pub fn probe_state(fw: &mut impl Firmware) -> Option<State> {
    let verify = match fw
        .apmf(APMF_FUNC_VERIFY_INTERFACE, None)
        .and_then(|v| store_buffer(&v, VerifyInterface::SIZE).map(VerifyInterface::parse))
    {
        Ok(v) => v,
        Err(e) => {
            log(format_args!("APMF verify interface failed :{e:?}"));
            return None;
        }
    };
    let mut st = State {
        version: verify.version,
        supported: verify.supported_functions,
        notifications: verify.notification_mask,
        hb_interval: 0,
        profile: PlatformProfile::Balanced,
        sps: None,
    };
    if st.supported(APMF_FUNC_GET_SYS_PARAMS) {
        if let Ok(p) = fw
            .apmf(APMF_FUNC_GET_SYS_PARAMS, None)
            .and_then(|v| store_buffer(&v, SystemParams::SIZE).map(SystemParams::parse))
        {
            st.hb_interval = p.heartbeat_int;
        }
    }
    if st.supported(APMF_FUNC_STATIC_SLIDER_GRANULAR) {
        st.sps = load_sps(fw, st.version);
        if st.sps.is_none() {
            log(format_args!(
                "static slider table unreadable; leaving power limits to firmware"
            ));
        }
    }
    Some(st)
}

/// `amd_pmf_load_defaults_sps` / `_v2` + `amd_pmf_load_apts_defaults_sps_v2`.
fn load_sps(fw: &mut impl Firmware, version: u16) -> Option<SpsTables> {
    let v = fw.apmf(APMF_FUNC_STATIC_SLIDER_GRANULAR, None).ok()?;
    if version == PMF_IF_V2 {
        let b = store_buffer(&v, SPS_V2_SIZE).ok()?;
        let mut states = [[0u8; 4]; 2];
        for (src, row) in states.iter_mut().enumerate() {
            row.copy_from_slice(&b[2 + src * 4..2 + src * 4 + 4]);
        }
        let mut apts = [AptsProp::default(); APTS_MAX_STATES];
        for (i, entry) in apts.iter_mut().enumerate() {
            let v = fw.apts(i as u32).ok()?;
            *entry = AptsProp::parse(store_buffer(&v, AptsProp::SIZE).ok()?);
        }
        return Some(SpsTables::V2 { states, apts });
    }
    let b = store_buffer(&v, SPS_V1_SIZE).ok()?;
    let mut prop = [[SpsProp::default(); 3]; 2];
    let mut idx = 0;
    for row in prop.iter_mut() {
        for entry in row.iter_mut() {
            let at = 2 + idx * SpsProp::SIZE;
            *entry = SpsProp::parse(&b[at..at + SpsProp::SIZE]);
            idx += 1;
        }
    }
    Some(SpsTables::V1(prop))
}

fn source(fw: &mut impl Firmware) -> PowerSource {
    if fw.on_ac() {
        PowerSource::Ac
    } else {
        PowerSource::Dc
    }
}

/// The `(message, argument)` sequence `amd_pmf_set_sps_power_limits`
/// sends for `mode` on `src`.
pub fn limit_messages(tables: &SpsTables, src: PowerSource, mode: PowerMode) -> Vec<(u32, u32)> {
    match tables {
        SpsTables::V1(prop) => {
            let p = &prop[src as usize][mode as usize];
            vec![
                (SET_SPL, p.spl),
                (SET_FPPT, p.fppt),
                (SET_SPPT, p.sppt),
                (SET_SPPT_APU_ONLY, p.sppt_apu_only),
                (SET_STT_MIN_LIMIT, p.stt_min),
                (SET_STT_LIMIT_APU, q88(u32::from(p.stt_skin_temp_apu))),
                (SET_STT_LIMIT_HS2, q88(u32::from(p.stt_skin_temp_hs2))),
            ]
        }
        SpsTables::V2 { states, apts } => {
            // `POWER_MODE_BEST_PERFORMANCE` / `_BALANCED` /
            // `_BEST_POWER_EFFICIENCY` are v2 columns 0 / 1 / 2.
            let column = mode as usize;
            let index = usize::from(states[src as usize][column]);
            let Some(a) = apts.get(index) else {
                return Vec::new();
            };
            vec![
                (SET_PMF_PPT, a.pmf_ppt),
                (SET_PMF_PPT_APU_ONLY, a.ppt_pmf_apu_only),
                (SET_STT_MIN_LIMIT, a.stt_min_limit),
                (SET_STT_LIMIT_APU, q88(u32::from(a.stt_skin_temp_limit_apu))),
                (SET_STT_LIMIT_HS2, q88(u32::from(a.stt_skin_temp_limit_hs2))),
            ]
        }
    }
}

/// `amd_pmf_set_sps_power_limits`. SMU errors are logged, not returned:
/// Linux ignores each `amd_pmf_send_cmd` result here.
pub fn apply_limits(st: &State, src: PowerSource, mb: &mut impl MailboxAccess) {
    let (Some(tables), Some(mode)) = (st.sps.as_ref(), mode_for(st.profile)) else {
        return;
    };
    let messages = limit_messages(tables, src, mode);
    mb.transact(&mut |m| {
        for &(msg, arg) in &messages {
            if let Err(e) = amd_smu::send(m, &PMF_REGS, arg, msg) {
                log(format_args!("SMU cmd {msg:#x} failed: {e:?}"));
            }
        }
    });
}

/// `amd_pmf_power_slider_update_event`'s flag: which slider bit the BIOS
/// is told about (`DC_BEST_PERF` …).
pub fn slider_flag(src: PowerSource, mode: PowerMode) -> u8 {
    let bit = match (src, mode) {
        (PowerSource::Dc, PowerMode::Performance) => 0, // DC_BEST_PERF
        (PowerSource::Dc, PowerMode::BalancedPower) => 1, // DC_BETTER_PERF
        (PowerSource::Dc, PowerMode::PowerSaver) => 3,  // DC_BATTERY_SAVER
        (PowerSource::Ac, PowerMode::Performance) => 4, // AC_BEST_PERF
        (PowerSource::Ac, PowerMode::BalancedPower) => 5, // AC_BETTER_PERF
        (PowerSource::Ac, PowerMode::PowerSaver) => 6,  // AC_BETTER_BATTERY
    };
    1 << bit
}

/// `amd_pmf_power_slider_update_event` → `apmf_os_power_slider_update`.
pub fn slider_update(st: &State, src: PowerSource, fw: &mut impl Firmware) -> Result<(), FwError> {
    let mode = mode_for(st.profile).ok_or(FwError::Unsupported)?;
    // `struct os_power_slider { u16 size; u8 slider_event; }`
    let args = [3u8, 0, slider_flag(src, mode)];
    fw.apmf(APMF_FUNC_OS_POWER_SLIDER_UPDATE, Some(&args))
        .map(|_| ())
}

/// `amd_pmf_profile_set`: record the profile, tell the BIOS, then push
/// the limits.
pub fn set_profile(
    st: &mut State,
    profile: PlatformProfile,
    fw: &mut impl Firmware,
    mb: &mut impl MailboxAccess,
) -> Result<(), FwError> {
    st.profile = profile;
    let src = source(fw);
    if st.supported(APMF_FUNC_OS_POWER_SLIDER_UPDATE) {
        slider_update(st, src, fw)?;
    }
    if st.supported(APMF_FUNC_STATIC_SLIDER_GRANULAR) {
        apply_limits(st, src, mb);
    }
    Ok(())
}

/// `amd_pmf_pwr_src_notify_call` without Auto Mode / CnQF (never
/// enabled here): re-push the limits and re-tell the BIOS.
pub fn power_source_changed(st: &State, fw: &mut impl Firmware, mb: &mut impl MailboxAccess) {
    let src = source(fw);
    if st.supported(APMF_FUNC_STATIC_SLIDER_GRANULAR) {
        apply_limits(st, src, mb);
    }
    if st.supported(APMF_FUNC_OS_POWER_SLIDER_UPDATE) {
        let _ = slider_update(st, src, fw);
    }
}

/// Whether `amd_pmf_init_features` enables the static slider.
pub fn sps_enabled(st: &State) -> bool {
    st.supported(APMF_FUNC_STATIC_SLIDER_GRANULAR) || st.supported(APMF_FUNC_OS_POWER_SLIDER_UPDATE)
}

/// `amd_pmf_notify_sbios_heartbeat_event_v2(dev, ON_LOAD)`.
pub fn heartbeat_v2_load(fw: &mut impl Firmware) -> Result<(), FwError> {
    // `struct sbios_hb_event_v2 { u16 size; u8 load, unload, suspend, resume; }`
    let args = [6u8, 0, 1, 0, 0, 0];
    fw.apmf(APMF_FUNC_SBIOS_HEARTBEAT_V2, Some(&args))
        .map(|_| ())
}

/// The APMF features this driver leaves alone, for the probe log.
fn unported(st: &State) -> String {
    let mut s = String::new();
    for (func, name) in [
        (APMF_FUNC_AUTO_MODE, "auto-mode"),
        (APMF_FUNC_DYN_SLIDER_AC, "cnqf-ac"),
        (APMF_FUNC_DYN_SLIDER_DC, "cnqf-dc"),
        (APMF_FUNC_SBIOS_REQUESTS, "sbios-requests"),
        (APMF_FUNC_SET_FAN_IDX, "fan-index"),
        (APMF_FUNC_NOTIFY_SMART_PC_UPDATES, "smart-pc"),
    ] {
        if st.supported(func) {
            if !s.is_empty() {
                s.push(' ');
            }
            s.push_str(name);
        }
    }
    s
}

fn log(args: core::fmt::Arguments<'_>) {
    let _ = writeln!(narf_console::Writer, "amd-pmf: {args}");
}

// ── Binding ──────────────────────────────────────────────────────────

struct Bound {
    fw: AmlFirmware,
    st: State,
}

/// Probe state and firmware handle; never held across a mailbox wait.
static PMF: IrqSafeSpinLock<Option<Bound>> = IrqSafeSpinLock::new(None);
/// `dev->lock`: one SMU mailbox transaction at a time.
static MAILBOX: IrqSafeSpinLock<Option<amd_smu::MmioMailbox>> = IrqSafeSpinLock::new(None);
static BOUND: AtomicBool = AtomicBool::new(false);

/// Whether the driver bound.
pub fn bound() -> bool {
    BOUND.load(Ordering::Acquire)
}

/// Why [`init`] did not bind.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PmfError {
    /// No PMF ACPI device (or only `AMDI0100` without `force_load`).
    Absent,
    /// The root complex is not one PMF supports.
    UnknownCpu(u16),
    /// The SMU window could not be read or mapped.
    NoWindow,
}

/// Snapshot the state and firmware handle out of the lock, run `f`
/// with them, and store the state back. AML runs with no lock held.
fn with_bound<R>(f: impl FnOnce(&mut State, &mut AmlFirmware) -> R) -> Option<R> {
    let (mut st, mut fw) = {
        let g = PMF.lock();
        let b = g.as_ref()?;
        (
            b.st.clone(),
            AmlFirmware {
                device: b.fw.device.clone(),
            },
        )
    };
    let r = f(&mut st, &mut fw);
    if let Some(b) = PMF.lock().as_mut() {
        b.st.profile = st.profile;
    }
    Some(r)
}

/// The bound mailbox, `MAILBOX` held for each whole batch. No AML runs
/// inside a batch, so the IRQ-masked lock never spans a method call.
struct SharedMailbox;

impl MailboxAccess for SharedMailbox {
    fn transact(&mut self, f: &mut dyn FnMut(&mut dyn SmuMailbox)) {
        if let Some(m) = MAILBOX.lock().as_mut() {
            f(m);
        }
    }
}

fn profile_get() -> Option<PlatformProfile> {
    PMF.lock().as_ref().map(|b| b.st.profile)
}

fn profile_set(profile: PlatformProfile) -> bool {
    with_bound(|st, fw| set_profile(st, profile, fw, &mut SharedMailbox).is_ok()).unwrap_or(false)
}

/// The `amd-pmf` platform-profile handler (`amd_pmf_profile_probe`'s
/// choices; Linux also accepts the hidden quiet / balanced-performance,
/// which this tree's single-backend list has no slot for).
pub const CHOICES: [PlatformProfile; 3] = [
    PlatformProfile::LowPower,
    PlatformProfile::Balanced,
    PlatformProfile::Performance,
];

fn on_ac_event(_event: &narf_power::ac::AcEvent) {
    with_bound(|st, fw| power_source_changed(st, fw, &mut SharedMailbox));
}

/// `amd_pmf_probe` + `amd_pmf_init_features` (static slider only).
pub fn init() -> Result<(), PmfError> {
    let force_load = force_load_param(narf_boot::args().tokens());
    let device = ACPI_IDS
        .iter()
        .filter(|(_, needs_force)| force_load || !needs_force)
        .find_map(|(hid, _)| {
            narf_aml::find_all_devices_by_hid(hid)
                .into_iter()
                .find(|n| device_present(&n.path))
        })
        .ok_or(PmfError::Absent)?;

    let root = narf_bus::devices()
        .into_iter()
        .find(|d| {
            d.id.vendor == 0x1022
                && matches!(d.kind, narf_bus::BusKind::Pcie { addr, .. }
                    if addr.segment == 0 && addr.bus == 0 && addr.device == 0 && addr.function == 0)
        })
        .ok_or(PmfError::Absent)?;
    if !ROOT_IDS.contains(&root.id.device) {
        return Err(PmfError::UnknownCpu(root.id.device));
    }
    let narf_bus::BusKind::Pcie { cfg_phys, .. } = root.kind else {
        return Err(PmfError::Absent);
    };
    let lo = narf_bus::amd_smn::read(cfg_phys, amd_smu::BASE_ADDR_LO).ok_or(PmfError::NoWindow)?;
    let hi = narf_bus::amd_smn::read(cfg_phys, amd_smu::BASE_ADDR_HI).ok_or(PmfError::NoWindow)?;
    let mailbox = amd_smu::MmioMailbox::map(amd_smu::window(lo, hi)).ok_or(PmfError::NoWindow)?;
    *MAILBOX.lock() = Some(mailbox);

    let mut fw = AmlFirmware {
        device: device.path.clone(),
    };
    let st = probe_state(&mut fw);
    if let Some(st) = &st {
        log(format_args!(
            "APMF v{} functions {:#x} notifications {:#x}; not handled: [{}]",
            st.version,
            st.supported,
            st.notifications,
            unported(st)
        ));
    }

    let mut sps = false;
    if let Some(st) = &st {
        if sps_enabled(st) {
            // `amd_pmf_init_sps`: start balanced and push its limits.
            if st.supported(APMF_FUNC_STATIC_SLIDER_GRANULAR) {
                apply_limits(st, source(&mut fw), &mut SharedMailbox);
            }
            sps = true;
        }
        if st.hb_interval != 0 && st.version == PMF_IF_V1 {
            narf_scheduler::spawn(heartbeat_v1(device.path.clone(), st.hb_interval));
        }
        if st.supported(APMF_FUNC_SBIOS_HEARTBEAT_V2) {
            let _ = heartbeat_v2_load(&mut fw);
        }
    }
    *PMF.lock() = Some(Bound {
        fw,
        st: st.unwrap_or(State {
            version: 0,
            supported: 0,
            notifications: 0,
            hb_interval: 0,
            profile: PlatformProfile::Balanced,
            sps: None,
        }),
    });
    if sps {
        if !platform_profile::register_backend(ProfileBackend {
            name: "amd-pmf",
            choices: &CHOICES,
            get: profile_get,
            set: profile_set,
        }) {
            log(format_args!(
                "Failed to register SPS support: another platform-profile handler is active"
            ));
        }
        narf_power::ac::subscribe(on_ac_event);
    }
    BOUND.store(true, Ordering::Release);
    log(format_args!(
        "registered PMF device successfully ({})",
        device.path
    ));
    Ok(())
}

/// `kstrtobool`: `y`/`Y`/`t`/`T`/`1` and `on` are true, `n`/`N`/`f`/`F`/
/// `0` and `off` false, by their leading characters; anything else is
/// `None` (`-EINVAL`).
pub fn kstrtobool(v: &str) -> Option<bool> {
    match v.as_bytes() {
        [b'y' | b'Y' | b't' | b'T' | b'1', ..] => Some(true),
        [b'n' | b'N' | b'f' | b'F' | b'0', ..] => Some(false),
        [b'o' | b'O', b'n' | b'N', ..] => Some(true),
        [b'o' | b'O', b'f' | b'F', ..] => Some(false),
        _ => None,
    }
}

/// The `amd_pmf.force_load` boot parameter (`param_set_bool`): a bare
/// name sets it, `=value` goes through [`kstrtobool`] (an invalid value
/// is rejected and leaves the default), the last occurrence wins, and
/// `-`/`_` are interchangeable in the name (`parameq`).
pub fn force_load_param<'a>(tokens: impl IntoIterator<Item = &'a str>) -> bool {
    let mut value = false;
    for arg in tokens {
        let (name, v) = match arg.split_once('=') {
            Some((n, v)) => (n, Some(v)),
            None => (arg, None),
        };
        let same = name.len() == "amd_pmf.force_load".len()
            && name
                .bytes()
                .zip("amd_pmf.force_load".bytes())
                .all(|(a, b)| a == b || (a == b'-' && b == b'_'));
        if !same {
            continue;
        }
        match v {
            None => value = true,
            Some(v) => {
                if let Some(b) = kstrtobool(v) {
                    value = b;
                }
            }
        }
    }
    value
}

/// `acpi_bus_get_status`: `_STA` bit 0, with a missing `_STA` meaning
/// present (`ACPI_STA_DEFAULT`) and a failed evaluation meaning absent.
fn device_present(path: &str) -> bool {
    match narf_aml::prt_crs::evaluate_sta_for(path) {
        Ok(sta) => sta & narf_aml::prt_crs::STA_DEVICE_PRESENT != 0,
        Err(narf_aml::prt_crs::BridgeError::MethodNotFound) => true,
        Err(_) => false,
    }
}

/// `apmf_sbios_heartbeat_notify`: call APMF function 4 every
/// `interval` seconds, stopping at the first failure.
async fn heartbeat_v1(device: String, interval: u32) {
    let mut fw = AmlFirmware { device };
    loop {
        if fw.apmf(APMF_FUNC_SBIOS_HEARTBEAT, None).is_err() {
            return;
        }
        narf_time::sleep_ms(u64::from(interval) * 1000).await;
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amd_pmf_tests.rs"]
mod tests;
