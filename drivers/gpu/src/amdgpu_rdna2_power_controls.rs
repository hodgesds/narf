//! Runtime RX 6000 power controls behind the DRM card's sysfs attributes:
//! Linux `power_dpm_force_performance_level` and `pp_features`.
//!
//! sysfs stores are synchronous, while every SMU change runs under the
//! platform owner's async lock. A store therefore validates its input, then
//! queues the change to a task; all changes are serialized by [`CONTROL`],
//! and a newer write of the same attribute supersedes an older one that has
//! not started (latest wins, as consecutive Linux writes would end). Reads
//! report the last applied state.
//!
//! Deliberate divergences from Linux, both keeping display admission intact:
//! * performance levels move GFXCLK only (`auto`, `low`, `high`); memory and
//!   SoC clocks stay at the display owner's admitted floors. `manual` and the
//!   `profile_*` levels are refused (`EOPNOTSUPP`).
//! * `pp_features` may change only bits a power-policy feature owns (GFXOFF,
//!   hub power gating, memory/fabric DPM, deep sleep), each all-or-none;
//!   enabling still passes that feature's display-admission and driver gates.
use crate::amdgpu_navi22_power_policy::{policy_smu_bits, OptIn};
use crate::amdgpu_smu_navi22::GfxLevel;
use alloc::string::String;
use core::fmt::Write;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use narf_filesystem::FsError;
use narf_lib::mutex::Mutex;

/// Serializes every queued control change.
static CONTROL: Mutex<()> = Mutex::new(());
/// Set once a completed boot publishes its controls; cleared on loss.
static READY: AtomicBool = AtomicBool::new(false);
static LEVEL: AtomicU8 = AtomicU8::new(0);
static LEVEL_GENERATION: AtomicU64 = AtomicU64::new(0);
static FEATURES_GENERATION: AtomicU64 = AtomicU64::new(0);
static RUNNING: AtomicU64 = AtomicU64::new(0);

/// sienna_cichlid's PMFW feature map in bit order (`FEA_MAP` entries of
/// `sienna_cichlid_feature_mask_map`; bits 23 and 43 are unmapped).
const FEATURE_NAMES: [(&str, u8); 43] = [
    ("DPM_PREFETCHER", 0),       // linux-lit: 0=FEATURE_DPM_PREFETCHER_BIT
    ("DPM_GFXCLK", 1),           // linux-lit: 1=FEATURE_DPM_GFXCLK_BIT
    ("DPM_GFX_GPO", 2),          // linux-lit: 2=FEATURE_DPM_GFX_GPO_BIT
    ("DPM_UCLK", 3),             // linux-lit: 3=FEATURE_DPM_UCLK_BIT
    ("DPM_FCLK", 4),             // linux-lit: 4=FEATURE_DPM_FCLK_BIT
    ("DPM_SOCCLK", 5),           // linux-lit: 5=FEATURE_DPM_SOCCLK_BIT
    ("DPM_MP0CLK", 6),           // linux-lit: 6=FEATURE_DPM_MP0CLK_BIT
    ("DPM_LINK", 7),             // linux-lit: 7=FEATURE_DPM_LINK_BIT
    ("DPM_DCEFCLK", 8),          // linux-lit: 8=FEATURE_DPM_DCEFCLK_BIT
    ("DPM_XGMI", 9),             // linux-lit: 9=FEATURE_DPM_XGMI_BIT
    ("MEM_VDDCI_SCALING", 10),   // linux-lit: 10=FEATURE_MEM_VDDCI_SCALING_BIT
    ("MEM_MVDD_SCALING", 11),    // linux-lit: 11=FEATURE_MEM_MVDD_SCALING_BIT
    ("DS_GFXCLK", 12),           // linux-lit: 12=FEATURE_DS_GFXCLK_BIT
    ("DS_SOCCLK", 13),           // linux-lit: 13=FEATURE_DS_SOCCLK_BIT
    ("DS_FCLK", 14),             // linux-lit: 14=FEATURE_DS_FCLK_BIT
    ("DS_LCLK", 15),             // linux-lit: 15=FEATURE_DS_LCLK_BIT
    ("DS_DCEFCLK", 16),          // linux-lit: 16=FEATURE_DS_DCEFCLK_BIT
    ("DS_UCLK", 17),             // linux-lit: 17=FEATURE_DS_UCLK_BIT
    ("GFX_ULV", 18),             // linux-lit: 18=FEATURE_GFX_ULV_BIT
    ("FW_DSTATE", 19),           // linux-lit: 19=FEATURE_FW_DSTATE_BIT
    ("GFXOFF", 20),              // linux-lit: 20=FEATURE_GFXOFF_BIT
    ("BACO", 21),                // linux-lit: 21=FEATURE_BACO_BIT
    ("MM_DPM_PG", 22),           // linux-lit: 22=FEATURE_MM_DPM_PG_BIT
    ("PPT", 24),                 // linux-lit: 24=FEATURE_PPT_BIT
    ("TDC", 25),                 // linux-lit: 25=FEATURE_TDC_BIT
    ("APCC_PLUS", 26),           // linux-lit: 26=FEATURE_APCC_PLUS_BIT
    ("GTHR", 27),                // linux-lit: 27=FEATURE_GTHR_BIT
    ("ACDC", 28),                // linux-lit: 28=FEATURE_ACDC_BIT
    ("VR0HOT", 29),              // linux-lit: 29=FEATURE_VR0HOT_BIT
    ("VR1HOT", 30),              // linux-lit: 30=FEATURE_VR1HOT_BIT
    ("FW_CTF", 31),              // linux-lit: 31=FEATURE_FW_CTF_BIT
    ("FAN_CONTROL", 32),         // linux-lit: 32=FEATURE_FAN_CONTROL_BIT
    ("THERMAL", 33),             // linux-lit: 33=FEATURE_THERMAL_BIT
    ("GFX_DCS", 34),             // linux-lit: 34=FEATURE_GFX_DCS_BIT
    ("RM", 35),                  // linux-lit: 35=FEATURE_RM_BIT
    ("LED_DISPLAY", 36),         // linux-lit: 36=FEATURE_LED_DISPLAY_BIT
    ("GFX_SS", 37),              // linux-lit: 37=FEATURE_GFX_SS_BIT
    ("OUT_OF_BAND_MONITOR", 38), // linux-lit: 38=FEATURE_OUT_OF_BAND_MONITOR_BIT
    ("TEMP_DEPENDENT_VMIN", 39), // linux-lit: 39=FEATURE_TEMP_DEPENDENT_VMIN_BIT
    ("MMHUB_PG", 40),            // linux-lit: 40=FEATURE_MMHUB_PG_BIT
    ("ATHUB_PG", 41),            // linux-lit: 41=FEATURE_ATHUB_PG_BIT
    ("APCC_DFLL", 42),           // linux-lit: 42=FEATURE_APCC_DFLL_BIT
    ("RSMU_SMN_CG", 44),         // linux-lit: 44=FEATURE_RSMU_SMN_CG_BIT
];

fn level_code(level: GfxLevel) -> u8 {
    match level {
        GfxLevel::Auto => 0,
        GfxLevel::Low => 1,
        GfxLevel::High => 2,
    }
}

/// Parse a `power_dpm_force_performance_level` write.
pub fn parse_level(text: &str) -> Result<GfxLevel, FsError> {
    match text.trim() {
        "auto" => Ok(GfxLevel::Auto),
        "low" => Ok(GfxLevel::Low),
        "high" => Ok(GfxLevel::High),
        "manual" | "profile_standard" | "profile_min_sclk" | "profile_min_mclk"
        | "profile_peak" | "profile_exit" | "perf_determinism" => Err(FsError::Unsupported),
        _ => Err(FsError::InvalidData),
    }
}

/// The applied level as Linux spells it.
pub fn level() -> &'static str {
    match LEVEL.load(Ordering::Acquire) {
        1 => "low",
        2 => "high",
        _ => "auto",
    }
}

/// Parse a `pp_features` write: a hex mask, with or without `0x`.
pub fn parse_mask(text: &str) -> Result<u64, FsError> {
    let text = text.trim();
    let digits = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))
        .unwrap_or(text);
    u64::from_str_radix(digits, 16).map_err(|_| FsError::InvalidData)
}

/// The opt-in a `pp_features` write of `mask` requests, given the running
/// mask and the opt-in currently requested. Bits no policy feature owns must
/// be left as they run; a feature's bits must be all set or all clear.
pub fn requested_optin(mask: u64, running: u64, current: OptIn) -> Result<OptIn, FsError> {
    let owned = policy_smu_bits();
    if (mask ^ running) & !owned != 0 {
        return Err(FsError::OperationNotPermitted);
    }
    current.with_smu_mask(mask).ok_or(FsError::InvalidData)
}

/// Linux `smu_cmn_get_pp_feature_mask` output for `running`.
pub fn format_features(running: u64) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "features high: 0x{:08x} low: 0x{:08x}",
        (running >> 32) as u32,
        running as u32
    );
    // Linux: "%-2s. %-20s  %-3s : %-s" over "No", "Feature", "Bit", "State".
    out.push_str(
        "No. Feature               Bit : State
",
    );
    for (index, (name, bit)) in FEATURE_NAMES.iter().enumerate() {
        let state = if running >> bit & 1 != 0 {
            "enabled"
        } else {
            "disabled"
        };
        let _ = writeln!(out, "{index:02}. {name:<20} ({bit:2}) : {state}");
    }
    out
}

/// `pp_features` show: empty until a completed boot publishes its controls.
pub fn features() -> String {
    if READY.load(Ordering::Acquire) {
        format_features(RUNNING.load(Ordering::Acquire))
    } else {
        String::new()
    }
}

/// Publish the controls after a completed boot (and its power saving):
/// sample the running mask once so reads need no SMU round trip.
pub async fn publish() {
    let _serial = CONTROL.lock().await;
    if let Ok(running) = crate::amdgpu_navi22_platform::running_features().await {
        RUNNING.store(running, Ordering::Release);
        LEVEL.store(level_code(GfxLevel::Auto), Ordering::Release);
        READY.store(true, Ordering::Release);
    }
}

/// Withdraw the controls (device loss or a reset in progress).
pub fn withdraw() {
    READY.store(false, Ordering::Release);
}

/// Controls are published.
pub fn ready() -> bool {
    READY.load(Ordering::Acquire)
}

/// Queue a performance level change.
pub fn request_level(text: &str) -> Result<(), FsError> {
    let level = parse_level(text)?;
    if !ready() {
        return Err(FsError::NoDevice);
    }
    let generation = LEVEL_GENERATION.fetch_add(1, Ordering::AcqRel) + 1;
    narf_scheduler::spawn(async move {
        let _serial = CONTROL.lock().await;
        if LEVEL_GENERATION.load(Ordering::Acquire) != generation || !ready() {
            return;
        }
        match crate::amdgpu_navi22_platform::set_gfx_level(level).await {
            Ok(()) => LEVEL.store(level_code(level), Ordering::Release),
            Err(error) => {
                let _ = writeln!(
                    narf_console::Writer,
                    "amdgpu: rdna2 performance level {level:?} failed: {error:?}"
                );
            }
        }
    });
    Ok(())
}

/// Queue a `pp_features` change. Validation against the running mask runs
/// now, so malformed or forbidden masks fail the write itself.
pub fn request_features(text: &str) -> Result<(), FsError> {
    let mask = parse_mask(text)?;
    if !ready() {
        return Err(FsError::NoDevice);
    }
    let current = crate::amdgpu_navi22_platform::requested_power_saving();
    let optin = requested_optin(mask, RUNNING.load(Ordering::Acquire), current)?;
    if optin == current {
        return Ok(());
    }
    let generation = FEATURES_GENERATION.fetch_add(1, Ordering::AcqRel) + 1;
    narf_scheduler::spawn(async move {
        let _serial = CONTROL.lock().await;
        if FEATURES_GENERATION.load(Ordering::Acquire) != generation || !ready() {
            return;
        }
        // SAFETY: a completed boot published these controls; every GC MMIO
        // client takes a GFXOFF reference and this task holds no lock the
        // platform takes.
        let result = unsafe { crate::amdgpu_navi22_platform::replace_power_saving(optin) }.await;
        if let Err(error) = result {
            let _ = writeln!(
                narf_console::Writer,
                "amdgpu: rdna2 pp_features {mask:#x} failed: {error:?}"
            );
        }
        if let Ok(running) = crate::amdgpu_navi22_platform::running_features().await {
            RUNNING.store(running, Ordering::Release);
        }
    });
    Ok(())
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_rdna2_power_controls_tests.rs"]
mod tests;
