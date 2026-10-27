//! `_CRS` bus-speed composition + DesignWare SCL timing derivation,
//! shared by the two DW-core drivers in this crate (AMD FCH
//! `amd_fch` and Intel LPSS `lpss`) — issue #772.
//!
//! Until this module landed, both wrappers programmed fixed
//! 400 kHz timing constants at `enable()` and the `ConnectionSpeed`
//! that ACPI `_CRS` declares for every I2C-attached child (ACPI 6.5
//! §6.4.3.8.2.1 `I2cSerialBus` descriptor) was decoded — by
//! `narf_aml::resource` and by the I2C-HID bind — and then dropped
//! on the floor. A device whose `_CRS` declares 100 kHz (or 1 MHz
//! Fast-mode Plus) was driven at whatever the constants happened
//! to produce.
//!
//! Two pieces, mirroring Linux's split:
//!
//! - **Composition** ([`bus_speed_hz`]): walk the AML namespace,
//!   collect the `ConnectionSpeed` of every `I2cSerialBus`
//!   descriptor whose `ResourceSource` names this controller, and
//!   take the *slowest* — the semantics of Linux
//!   `i2c_acpi_find_bus_speed()` (`drivers/i2c/i2c-core-acpi.c`:
//!   "Find the I2C bus speed by walking the ACPI namespace for
//!   all I2C slaves devices connected to this bus and use the
//!   speed of slowest device"). The DW core programs one SCL rate
//!   per bus (the count registers are write-locked while the core
//!   is enabled), so per-device rates compose to a single bus
//!   rate; slowest-wins is the only composition under which no
//!   device is ever overdriven. A descriptor speed of 0 is
//!   "not declared" and does not drag the composition to 0
//!   (Linux returns 0 = unknown for the whole lookup in that
//!   spirit). When nothing on the bus declares a speed this
//!   returns `None` and the wrappers keep their pre-#772 default
//!   programming byte-for-byte.
//!
//! - **Timing derivation** ([`timings_for`]): the DW databook
//!   count formulas as implemented by Linux
//!   `i2c_dw_scl_hcnt()` / `i2c_dw_scl_lcnt()`
//!   (`drivers/i2c/busses/i2c-designware-common.c`) with the
//!   per-mode `tHIGH` / `tLOW` from `i2c_dw_set_timings_master()`
//!   (`i2c-designware-master.c`), which are the I2C-bus
//!   specification's (UM10204) mode minima:
//!     Standard 100 kHz: tHIGH 4000 ns, tLOW 4700 ns
//!     Fast     400 kHz: tHIGH  600 ns, tLOW 1300 ns
//!     Fast+      1 MHz: tHIGH  260 ns, tLOW  500 ns
//!   Fall time `tf` is Linux's default 300 ns for both edges
//!   (its `sda_fall_ns ?: 300` / `scl_fall_ns ?: 300` when the
//!   firmware supplies no measured values). The mode is the
//!   declared speed rounded *up* to the enclosing standard mode
//!   (Linux `i2c_dw_acpi_round_bus_speed()`), so a 340 kHz
//!   declaration programs Fast-mode counts, and the counts are
//!   always the mode's nominal counts, never an interpolation.
//!   Speeds above Fast-mode Plus round into Fast-mode Plus:
//!   these wrappers do not program the DW high-speed (3.4 MHz)
//!   count registers, and driving a device slower than its
//!   declared maximum is always wire-legal, while overdriving
//!   one is not. Fast-mode Plus runs in the FS count registers
//!   with the FAST `IC_CON` speed field, exactly as Linux does
//!   ("Only difference is the timing parameter values since the
//!   registers are the same").
//!
//! The input clock is a parameter, never a guess: each wrapper
//! supplies its own grounded rate (FCH 133 MHz per AMD PPR; LPSS
//! per-HID per Linux `intel-lpss-acpi.c`). A wrapper that cannot
//! name its input clock passes no speed-derived programming at
//! all and keeps its defaults — computing counts from an
//! invented clock would be worse than ignoring the speed.

use alloc::vec::Vec;

use narf_aml::resource::ResourceItem;

/// Standard-mode ceiling (Hz) — I2C_MAX_STANDARD_MODE_FREQ.
pub const STANDARD_MODE_HZ: u32 = 100_000;
/// Fast-mode ceiling (Hz) — I2C_MAX_FAST_MODE_FREQ.
pub const FAST_MODE_HZ: u32 = 400_000;
/// Fast-mode-Plus ceiling (Hz) — I2C_MAX_FAST_MODE_PLUS_FREQ.
/// Also the fastest rate these wrappers program (see module docs).
pub const FAST_MODE_PLUS_HZ: u32 = 1_000_000;

/// Default SCL/SDA fall time in ns (Linux's fallback when the
/// firmware provides no measured fall times).
const FALL_NS: u32 = 300;

// Per-mode tHIGH / tLOW in ns — I2C specification minima as used
// by Linux `i2c_dw_set_timings_master()`.
const SS_T_HIGH_NS: u32 = 4000;
const SS_T_LOW_NS: u32 = 4700;
const FS_T_HIGH_NS: u32 = 600;
const FS_T_LOW_NS: u32 = 1300;
const FP_T_HIGH_NS: u32 = 260;
const FP_T_LOW_NS: u32 = 500;

/// Which DW speed mode a declared bus frequency programs.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DwSpeedMode {
    /// 100 kHz — SS count registers, `IC_CON.SPEED = 0b01`.
    Standard,
    /// 400 kHz — FS count registers, `IC_CON.SPEED = 0b10`.
    Fast,
    /// 1 MHz — FS count registers with Fast+ counts,
    /// `IC_CON.SPEED = 0b10` (same field as Fast; see module docs).
    FastPlus,
}

impl DwSpeedMode {
    /// Round a declared bus frequency up to its enclosing
    /// standard mode (Linux `i2c_dw_acpi_round_bus_speed()`
    /// semantics, capped at Fast-mode Plus — see module docs).
    pub fn from_declared_hz(hz: u32) -> Self {
        if hz <= STANDARD_MODE_HZ {
            DwSpeedMode::Standard
        } else if hz <= FAST_MODE_HZ {
            DwSpeedMode::Fast
        } else {
            DwSpeedMode::FastPlus
        }
    }

    /// The `IC_CON` SPEED field value (bits [2:1]) for this mode.
    pub fn ic_con_speed_bits(self) -> u32 {
        match self {
            DwSpeedMode::Standard => 0b01 << 1,
            DwSpeedMode::Fast | DwSpeedMode::FastPlus => 0b10 << 1,
        }
    }
}

/// The four SCL count registers for one bus configuration: the SS
/// pair (always derived, as Linux always derives them — they are
/// also the counts Standard mode runs on) and the FS pair (Fast
/// counts, or Fast+ counts when `mode` is
/// [`DwSpeedMode::FastPlus`]).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DwSclTimings {
    pub mode: DwSpeedMode,
    pub ss_hcnt: u32,
    pub ss_lcnt: u32,
    pub fs_hcnt: u32,
    pub fs_lcnt: u32,
}

/// `DIV_ROUND_CLOSEST(n, 1_000_000)` on u64, as in Linux's
/// `DIV_ROUND_CLOSEST_ULL` for the unsigned case.
fn div_round_closest_micro(n: u64) -> u64 {
    (n + 500_000) / 1_000_000
}

/// Linux `i2c_dw_scl_hcnt()` with `offset = 0`:
/// `round(ic_clk_khz * (tHIGH + tf)) - 3`, where the databook
/// conditional is `IC_SCL_HCNT + 3 >= IC_CLK * (tHD;STA + tf)`.
/// `ic_clk` is in kHz (Linux `get_clk_rate_khz()`), times in ns.
///
/// The `.max(1)` floor is defensive only: at every input clock
/// these wrappers run (≥ 100 MHz) the smallest derived count is
/// 53 (Fast+ HCNT), so the floor is unreachable in practice; it
/// exists so a future caller passing a nonsensical clock gets a
/// slow bus, not a wrapped 4-billion count.
pub fn scl_hcnt(ic_clk_khz: u32, t_high_ns: u32) -> u32 {
    let cycles = div_round_closest_micro(ic_clk_khz as u64 * (t_high_ns as u64 + FALL_NS as u64));
    (cycles as i64 - 3).max(1) as u32
}

/// Linux `i2c_dw_scl_lcnt()` with `offset = 0`:
/// `round(ic_clk_khz * (tLOW + tf)) - 1`. The core starts
/// counting the LOW period as soon as it pulls SCL down, so the
/// fall time must be inside the count to meet `tLOW`.
pub fn scl_lcnt(ic_clk_khz: u32, t_low_ns: u32) -> u32 {
    let cycles = div_round_closest_micro(ic_clk_khz as u64 * (t_low_ns as u64 + FALL_NS as u64));
    (cycles as i64 - 1).max(1) as u32
}

/// Derive the full count set for input clock `ic_clk_khz` (kHz)
/// and declared bus frequency `bus_freq_hz` (Hz).
pub fn timings_for(ic_clk_khz: u32, bus_freq_hz: u32) -> DwSclTimings {
    let mode = DwSpeedMode::from_declared_hz(bus_freq_hz);
    let (fs_t_high, fs_t_low) = match mode {
        DwSpeedMode::FastPlus => (FP_T_HIGH_NS, FP_T_LOW_NS),
        _ => (FS_T_HIGH_NS, FS_T_LOW_NS),
    };
    DwSclTimings {
        mode,
        ss_hcnt: scl_hcnt(ic_clk_khz, SS_T_HIGH_NS),
        ss_lcnt: scl_lcnt(ic_clk_khz, SS_T_LOW_NS),
        fs_hcnt: scl_hcnt(ic_clk_khz, fs_t_high),
        fs_lcnt: scl_lcnt(ic_clk_khz, fs_t_low),
    }
}

/// Compose one bus speed from the speeds its devices declare:
/// the slowest non-zero declaration wins (Linux
/// `i2c_acpi_find_bus_speed()`); zero means "not declared" and
/// is skipped; no declarations at all yields `None`.
pub fn compose_bus_speed(declared: &[u32]) -> Option<u32> {
    declared.iter().copied().filter(|&hz| hz != 0).min()
}

/// Every `ConnectionSpeed` declared by an `I2cSerialBus`
/// descriptor whose `ResourceSource` is `controller_path`,
/// gathered by walking the whole AML namespace (the same walk
/// `narf_aml::dump_i2c_slaves` performs for diagnostics). The
/// string match is verbatim, the convention the crate's existing
/// consumers (`gsb`, the I2C-HID bind) already use when they hand
/// a `ResourceSource` to `registry::find`.
pub fn declared_speeds_hz(controller_path: &str) -> Vec<u32> {
    let mut out = Vec::new();
    for path in narf_aml::list_all_device_paths() {
        let items = match narf_aml::prt_crs::evaluate_crs_for(&path) {
            Ok(v) => v,
            Err(_) => continue,
        };
        for item in items {
            if let ResourceItem::I2cSerialBus {
                connection_speed,
                resource_source,
                ..
            } = item
            {
                if resource_source == controller_path {
                    out.push(connection_speed);
                }
            }
        }
    }
    out
}

/// The composed bus speed for the controller at
/// `controller_path`: `Some(hz)` when at least one attached
/// device declares a non-zero `ConnectionSpeed`, `None` when the
/// bus declares nothing (callers keep their default programming).
/// Boot-time only — the walk evaluates every device's `_CRS`.
pub fn bus_speed_hz(controller_path: &str) -> Option<u32> {
    compose_bus_speed(&declared_speeds_hz(controller_path))
}
