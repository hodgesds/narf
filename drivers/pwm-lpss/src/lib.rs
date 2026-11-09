#![no_std]

//! Intel Low Power Subsystem (LPSS) PWM controller driver.
//!
//! First production `PwmDevice` implementor in-tree (issue #1699):
//! the LPSS PWM block found on Bay Trail, Braswell, Broxton and
//! Tangier SoCs, enumerated over PCI (Linux `drivers/pwm/pwm-lpss.c`
//! + `pwm-lpss-pci.c`, `pwm-lpss.h`).
//!
//! Register model (one 32-bit control register per channel):
//!
//! ```text
//! offset = channel * 0x400 + 0x00        // PWM_SIZE, PWM
//!   bit 31  PWM_ENABLE
//!   bit 30  PWM_SW_UPDATE — set on a timing write, cleared by the
//!           block at the start of the next output cycle
//!   bits [8 .. 8+base_unit_bits)  base_unit — period in clock ticks
//!   bits [7:0]  on_time_div — 255 - duty fraction (normal polarity)
//! ```
//!
//! Programming follows Linux `pwm_lpss_prepare()` exactly:
//! `base_unit = round(freq * base_unit_range / clk_rate)`, clamped to
//! `[1, base_unit_range - 1]` (a 0 base_unit never increments, per the
//! datasheet note Linux cites); `on_time_div = 255 - floor(255 *
//! duty_ns / period_ns)` for normal polarity. The LPSS block has no
//! polarity bit — Linux `get_state()` hard-codes
//! `PWM_POLARITY_NORMAL` — so `Polarity::Inversed` is emulated in
//! software by complementing the duty (`on_time_div = floor(255 *
//! duty_ns / period_ns)`), the same technique Linux `pwm-meson.c`
//! uses for hardware without a polarity control.
//!
//! Enable sequencing follows Linux `pwm_lpss_prepare_enable()`:
//! non-bypass parts (Bay Trail / Braswell / Tangier) set ENABLE
//! before waiting for `SW_UPDATE` to clear; bypass parts (Broxton)
//! wait first, then set ENABLE.
//!
//! REBASE NOTE (#1700): the `narf_pwm` controller registry
//! (`register_controller` / `lookup_controller`) does not exist on
//! main yet — it arrives with open draft PR #1700. Until then,
//! `probe()` stashes each bound controller in [`probed_controllers`]
//! and no DT consumer can resolve it by phandle. Once #1700 lands,
//! `probe()` gains one line per controller,
//! `narf_pwm::register_controller(phandle, dev.clone())`, and this
//! note (plus the remainder tracked on #1699) goes away. Which
//! phandle a PCI-enumerated LPSS function registers under is itself
//! a #1700-followup question: the registry is DT-phandle-keyed and
//! LPSS on x86 is PCI/ACPI-enumerated, so there is no DT node to
//! take a phandle from.

extern crate alloc;

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use async_trait::async_trait;

use narf_bus::{BusDevice, BusDeviceCap, MatchKind, MmioRegion, PciMatch, ProbeError};
use narf_capabilities::{Cap, Write};
use narf_lib::mutex::Mutex as AsyncMutex;
use narf_lib::sync::IrqSafeSpinLock;
use narf_pwm::{Polarity, PwmConfig, PwmDevice, PwmError};

// ── Linux-grounded register model ───────────────────────────────────
// Source: torvalds/linux `drivers/pwm/pwm-lpss.c` (+ `pwm-lpss.h`,
// `pwm-lpss-pci.c`). All constants below are transcribed from that
// file; see the doc comment at the top of this module.

/// Offset of a channel's control register within its 0x400 window.
const PWM_CTRL: u64 = 0x00;
/// Stride between channel register windows (`PWM_SIZE`).
const PWM_STRIDE: u64 = 0x400;
/// Output-enable bit (`PWM_ENABLE`).
const PWM_ENABLE: u32 = 1 << 31;
/// Software-update bit (`PWM_SW_UPDATE`).
const PWM_SW_UPDATE: u32 = 1 << 30;
/// Shift of the base_unit field (`PWM_BASE_UNIT_SHIFT`).
const PWM_BASE_UNIT_SHIFT: u32 = 8;
/// Mask of the on_time_div field (`PWM_ON_TIME_DIV_MASK`, bits 7:0).
const PWM_ON_TIME_DIV_MASK: u32 = 0xFF;
/// Maximum channels on any LPSS part (`LPSS_MAX_PWMS`).
const LPSS_MAX_PWMS: usize = 4;

/// PCI vendor ID for every LPSS part (`PCI_VENDOR_ID_INTEL`).
const LPSS_VENDOR: u16 = 0x8086;
/// BAR holding the PWM register block (Linux `pcim_iomap_region(pdev, 0, ...)`).
const LPSS_BAR: u8 = 0;

/// Poll budget for `SW_UPDATE` to clear, in register reads.
/// Linux polls every 40 µs for up to 500 ms (`readl_poll_timeout`
/// in `pwm_lpss_wait_for_update`); this loop does the same number of
/// reads in bursts of 32 with a cooperative yield between bursts, so
/// a stuck bit costs ~100k reads and then `HardwareError`, and a
/// healthy block exits on the first burst.
const UPDATE_POLL_BURST: u32 = 32;
const UPDATE_POLL_BURSTS: u32 = 3_200;

// ── Board data ──────────────────────────────────────────────────────
// Source: `pwm_lpss_byt_info` / `pwm_lpss_bsw_info` /
// `pwm_lpss_bxt_info` / `pwm_lpss_tng_info` in `pwm-lpss.c`, and the
// `pwm_lpss_pci_ids[]` table in `pwm-lpss-pci.c`.

/// Per-SoC parameters for an LPSS PWM block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LpssBoardInfo {
    /// Input clock rate in Hz (`clk_rate`).
    pub clk_rate: u32,
    /// Number of PWM channels (`npwm`).
    pub npwm: u32,
    /// Width of the base_unit field in bits (`base_unit_bits`).
    pub base_unit_bits: u32,
    /// Whether ENABLE is set after (rather than before) waiting for
    /// `SW_UPDATE` to clear (`bypass`).
    pub bypass: bool,
}

/// Bay Trail — 25 MHz clock, 1 channel, 16-bit base_unit.
pub const LPSS_BYT_INFO: LpssBoardInfo = LpssBoardInfo {
    clk_rate: 25_000_000,
    npwm: 1,
    base_unit_bits: 16,
    bypass: false,
};

/// Braswell — 19.2 MHz clock, 1 channel, 16-bit base_unit.
pub const LPSS_BSW_INFO: LpssBoardInfo = LpssBoardInfo {
    clk_rate: 19_200_000,
    npwm: 1,
    base_unit_bits: 16,
    bypass: false,
};

/// Broxton — 19.2 MHz clock, 4 channels, 22-bit base_unit, bypass.
pub const LPSS_BXT_INFO: LpssBoardInfo = LpssBoardInfo {
    clk_rate: 19_200_000,
    npwm: 4,
    base_unit_bits: 22,
    bypass: true,
};

/// Tangier — 19.2 MHz clock, 4 channels, 22-bit base_unit.
pub const LPSS_TNG_INFO: LpssBoardInfo = LpssBoardInfo {
    clk_rate: 19_200_000,
    npwm: 4,
    base_unit_bits: 22,
    bypass: false,
};

/// Bay Trail PWM (`pwm_lpss_byt_info`).
pub const LPSS_DID_BYT_0: u16 = 0x0f08;
/// Bay Trail PWM, second function (`pwm_lpss_byt_info`).
pub const LPSS_DID_BYT_1: u16 = 0x0f09;
/// Braswell PWM (`pwm_lpss_bsw_info`).
pub const LPSS_DID_BSW_0: u16 = 0x2288;
/// Braswell PWM, second function (`pwm_lpss_bsw_info`).
pub const LPSS_DID_BSW_1: u16 = 0x2289;
/// Broxton PWM (`pwm_lpss_bxt_info`).
pub const LPSS_DID_BXT_0: u16 = 0x0ac8;
/// Broxton PWM, Apollo Lake (`pwm_lpss_bxt_info`).
pub const LPSS_DID_BXT_1: u16 = 0x5ac8;
/// Broxton PWM, Gemini Lake (`pwm_lpss_bxt_info`).
pub const LPSS_DID_BXT_2: u16 = 0x31c8;
/// Broxton PWM, second Apollo Lake function (`pwm_lpss_bxt_info`).
pub const LPSS_DID_BXT_3: u16 = 0x1ac8;
/// Tangier PWM (`pwm_lpss_tng_info`).
pub const LPSS_DID_TNG: u16 = 0x11a5;

/// Every PCI device ID this driver claims. Kept as one `const` so
/// `register_pci_driver` and the table smoke read the same list —
/// no drift between code and test.
pub const SUPPORTED_DEVICE_IDS: &[u16] = &[
    LPSS_DID_BYT_0,
    LPSS_DID_BYT_1,
    LPSS_DID_BSW_0,
    LPSS_DID_BSW_1,
    LPSS_DID_BXT_0,
    LPSS_DID_BXT_1,
    LPSS_DID_BXT_2,
    LPSS_DID_BXT_3,
    LPSS_DID_TNG,
];

/// Board data for a PCI device ID, or `None` if this driver does not
/// claim the ID. Mirrors the `.driver_data` column of Linux
/// `pwm_lpss_pci_ids[]`.
pub fn board_info_for(device_id: u16) -> Option<&'static LpssBoardInfo> {
    match device_id {
        LPSS_DID_BYT_0 | LPSS_DID_BYT_1 => Some(&LPSS_BYT_INFO),
        LPSS_DID_BSW_0 | LPSS_DID_BSW_1 => Some(&LPSS_BSW_INFO),
        LPSS_DID_BXT_0 | LPSS_DID_BXT_1 | LPSS_DID_BXT_2 | LPSS_DID_BXT_3 => Some(&LPSS_BXT_INFO),
        LPSS_DID_TNG => Some(&LPSS_TNG_INFO),
        _ => None,
    }
}

// ── Timing arithmetic (pure; Linux `pwm_lpss_prepare`) ──────────────

/// `DIV_ROUND_CLOSEST_ULL(n, d)`: round-half-up integer division.
fn div_round_closest(numer: u64, denom: u64) -> u64 {
    (numer + denom / 2) / denom
}

/// Timing bits (`base_unit << 8 | on_time_div`) for a config, without
/// the ENABLE / SW_UPDATE bits.
///
/// Mirrors Linux `pwm_lpss_prepare()`:
/// `base_unit = round(freq * base_unit_range / clk_rate)`, clamped to
/// `[1, base_unit_range - 1]`; `on_time_div = 255 - floor(255 *
/// duty_ns / period_ns)` for normal polarity. For inversed polarity
/// the duty is complemented (`on_time_div = floor(255 * duty_ns /
/// period_ns)`) — the LPSS block has no polarity bit, so inversion
/// is done by swapping the high/low lengths, as Linux `pwm-meson.c`
/// does for hardware without polarity control.
///
/// Errors: `InvalidConfig` for a zero frequency, a period that
/// underflows to 0 ns (frequency above 1 GHz), or a duty cycle longer
/// than the period.
fn timing_bits(info: &LpssBoardInfo, config: &PwmConfig) -> Result<u32, PwmError> {
    if config.frequency_hz == 0 {
        return Err(PwmError::InvalidConfig);
    }
    let period_ns = 1_000_000_000u64 / u64::from(config.frequency_hz);
    if period_ns == 0 {
        return Err(PwmError::InvalidConfig);
    }
    if config.duty_cycle_ns > period_ns {
        return Err(PwmError::InvalidConfig);
    }
    // Linux: `freq = NSEC_PER_SEC; do_div(freq, period_ns)`.
    let freq_hz = 1_000_000_000u64 / period_ns;
    let base_unit_range = 1u64 << info.base_unit_bits;
    let mut base_unit = div_round_closest(freq_hz * base_unit_range, u64::from(info.clk_rate));
    // A 0 base_unit never increments (datasheet note Linux cites);
    // clamp to [1, base_unit_range - 1] to avoid overflowing the field.
    base_unit = base_unit.clamp(1, base_unit_range - 1);
    let duty_frac = 255u64 * config.duty_cycle_ns / period_ns;
    let on_time_div = match config.polarity {
        Polarity::Normal => 255 - duty_frac,
        Polarity::Inversed => duty_frac,
    };
    Ok(((base_unit as u32) << PWM_BASE_UNIT_SHIFT) | (on_time_div as u32))
}

/// Bit mask covering the base_unit field for this part.
fn base_unit_mask(info: &LpssBoardInfo) -> u32 {
    (((1u64 << info.base_unit_bits) - 1) as u32) << PWM_BASE_UNIT_SHIFT
}

// ── Driver ──────────────────────────────────────────────────────────

/// Cached per-channel software state. The hardware register holds the
/// programmed timing + enable bit; this mirrors it so `enable()` can
/// re-apply the last `set_config()` (the `PwmDevice` trait splits
/// config from enable, while Linux `apply()` always carries both).
#[derive(Debug, Clone, Copy)]
struct ChannelState {
    config: Option<PwmConfig>,
    enabled: bool,
}

impl ChannelState {
    const fn new() -> Self {
        Self {
            config: None,
            enabled: false,
        }
    }
}

/// One bound LPSS PWM controller.
#[derive(Debug)]
pub struct LpssPwm {
    name: String,
    mmio: MmioRegion,
    info: &'static LpssBoardInfo,
    state: AsyncMutex<[ChannelState; LPSS_MAX_PWMS]>,
}

impl LpssPwm {
    /// Build a controller over an already-mapped BAR0 window.
    ///
    /// `mmio` must cover `info.npwm * 0x400` bytes; the caller (PCI
    /// `probe()`, or a fixture) owns the mapping.
    pub fn new(name: String, mmio: MmioRegion, info: &'static LpssBoardInfo) -> Self {
        Self {
            name,
            mmio,
            info,
            state: AsyncMutex::new([ChannelState::new(); LPSS_MAX_PWMS]),
        }
    }

    /// Controller name (PCI address form, e.g. `pwm-lpss-00:1a.0`).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Board data this controller was bound with.
    pub fn info(&self) -> &'static LpssBoardInfo {
        self.info
    }

    /// Byte offset of a channel's control register.
    fn ctrl_offset(channel: u32) -> u64 {
        u64::from(channel) * PWM_STRIDE + PWM_CTRL
    }

    /// Read a channel's control register.
    ///
    /// # Safety
    /// `channel < info.npwm`; the BAR window is mapped and owned by
    /// this controller.
    unsafe fn read_ctrl(&self, channel: u32) -> u32 {
        // SAFETY: caller-checked channel; offset is in the mapped BAR.
        unsafe { self.mmio.read32(Self::ctrl_offset(channel)) }
    }

    /// Write a channel's control register.
    ///
    /// # Safety
    /// `channel < info.npwm`; the BAR window is mapped and owned by
    /// this controller.
    unsafe fn write_ctrl(&self, channel: u32, value: u32) {
        // SAFETY: caller-checked channel; offset is in the mapped BAR.
        unsafe { self.mmio.write32(Self::ctrl_offset(channel), value) }
    }

    /// Program a channel's timing bits, preserving the ENABLE bit
    /// (Linux `pwm_lpss_prepare()` read-modify-writes the control
    /// register), then raise `SW_UPDATE` so the block latches the new
    /// timing at the next cycle. Returns the programmed control value
    /// (without `SW_UPDATE`).
    ///
    /// # Safety
    /// `channel < info.npwm`.
    unsafe fn prepare(&self, channel: u32, config: &PwmConfig) -> Result<u32, PwmError> {
        let timing = timing_bits(self.info, config)?;
        // SAFETY: caller-checked channel.
        let mut ctrl = unsafe { self.read_ctrl(channel) };
        ctrl &= !(base_unit_mask(self.info) | PWM_ON_TIME_DIV_MASK);
        ctrl |= timing;
        // SAFETY: caller-checked channel.
        unsafe { self.write_ctrl(channel, ctrl) };
        // SAFETY: caller-checked channel.
        unsafe { self.write_ctrl(channel, ctrl | PWM_SW_UPDATE) };
        Ok(ctrl)
    }

    /// Wait for the block to clear `SW_UPDATE` (Linux
    /// `pwm_lpss_wait_for_update()`). A bit that never clears means
    /// the block froze on the update — Linux logs
    /// "PWM_SW_UPDATE was not cleared" and returns an error.
    async fn wait_for_update(&self, channel: u32) -> Result<(), PwmError> {
        for _ in 0..UPDATE_POLL_BURSTS {
            for _ in 0..UPDATE_POLL_BURST {
                // SAFETY: channel was checked by the caller.
                if (unsafe { self.read_ctrl(channel) } & PWM_SW_UPDATE) == 0 {
                    return Ok(());
                }
                core::hint::spin_loop();
            }
            narf_scheduler::yield_now().await;
        }
        Err(PwmError::HardwareError)
    }
}

#[async_trait]
impl PwmDevice for LpssPwm {
    async fn set_config(&self, channel: u32, config: &PwmConfig) -> Result<(), PwmError> {
        if channel >= self.info.npwm {
            return Err(PwmError::InvalidChannel);
        }
        // Validate (and compute) before touching hardware.
        timing_bits(self.info, config)?;
        let mut state = self.state.lock().await;
        // Linux `pwm_lpss_is_updating()`: a new update while the
        // previous one is still latched freezes the block, so refuse
        // (NARF has no Busy variant; this is a hardware error).
        // SAFETY: channel checked above.
        if (unsafe { self.read_ctrl(channel) } & PWM_SW_UPDATE) != 0 {
            return Err(PwmError::HardwareError);
        }
        // SAFETY: channel checked above.
        unsafe { self.prepare(channel, config) }?;
        self.wait_for_update(channel).await?;
        state[channel as usize].config = Some(*config);
        // The ENABLE bit is preserved by `prepare()`; an enabled
        // channel keeps running with the new timing.
        Ok(())
    }

    async fn enable(&self, channel: u32) -> Result<(), PwmError> {
        if channel >= self.info.npwm {
            return Err(PwmError::InvalidChannel);
        }
        let mut state = self.state.lock().await;
        if state[channel as usize].enabled {
            return Ok(());
        }
        let Some(config) = state[channel as usize].config else {
            // Nothing was ever programmed: there is no waveform to
            // enable. Linux `apply()` always carries full state, so
            // this case cannot arise there; here it is a caller error.
            return Err(PwmError::InvalidConfig);
        };
        // SAFETY: channel checked above.
        if (unsafe { self.read_ctrl(channel) } & PWM_SW_UPDATE) != 0 {
            return Err(PwmError::HardwareError);
        }
        // SAFETY: channel checked above.
        let ctrl = unsafe { self.prepare(channel, &config) }?;
        if !self.info.bypass {
            // Bay Trail / Braswell / Tangier: set ENABLE before
            // waiting (Linux `pwm_lpss_prepare_enable()`).
            // SAFETY: channel checked above.
            unsafe { self.write_ctrl(channel, ctrl | PWM_SW_UPDATE | PWM_ENABLE) };
            self.wait_for_update(channel).await?;
        } else {
            // Broxton (bypass): wait first, then set ENABLE.
            self.wait_for_update(channel).await?;
            // SAFETY: channel checked above.
            unsafe { self.write_ctrl(channel, ctrl | PWM_ENABLE) };
        }
        state[channel as usize].enabled = true;
        Ok(())
    }

    async fn disable(&self, channel: u32) -> Result<(), PwmError> {
        if channel >= self.info.npwm {
            return Err(PwmError::InvalidChannel);
        }
        let mut state = self.state.lock().await;
        if !state[channel as usize].enabled {
            return Ok(());
        }
        // Linux `pwm_lpss_apply()` disable: clear ENABLE, no update
        // wait — the output stops at the next cycle boundary.
        // SAFETY: channel checked above.
        let ctrl = unsafe { self.read_ctrl(channel) };
        // SAFETY: channel checked above.
        unsafe { self.write_ctrl(channel, ctrl & !PWM_ENABLE) };
        state[channel as usize].enabled = false;
        Ok(())
    }

    fn channel_count(&self) -> u32 {
        self.info.npwm
    }
}

// ── Probe / registry ────────────────────────────────────────────────

/// Controllers bound by `probe()` this boot. Kept alive here (and
/// visible via [`probed_controllers`]) until the `narf_pwm`
/// controller registry lands with #1700 — see the REBASE NOTE at the
/// top of this module.
static PROBED: IrqSafeSpinLock<Vec<Arc<LpssPwm>>> = IrqSafeSpinLock::new(Vec::new());

/// Controllers bound by `probe()` this boot, as `PwmDevice`s.
pub fn probed_controllers() -> Vec<Arc<dyn PwmDevice>> {
    PROBED
        .lock()
        .iter()
        .map(|c| Arc::clone(c) as Arc<dyn PwmDevice>)
        .collect()
}

/// PCI probe: claim an LPSS PWM function, map BAR0, and stash the
/// bound controller.
///
/// REBASE NOTE (#1700): once the `narf_pwm` controller registry
/// lands, add `narf_pwm::register_controller(phandle, dev.clone())`
/// here (with whatever phandle the DT/ACPI layer assigns this
/// PCI-enumerated function) so DT consumers such as `pwm-fan` can
/// resolve it.
pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), ProbeError> {
    let Some(info) = board_info_for(device.id.device) else {
        return Err(ProbeError::NotForThisDriver);
    };
    narf_bus::pci::set_command(&cap, &device, narf_bus::pci::cmd::MEM_SPACE)
        .map_err(|_| ProbeError::BadDevice)?;

    // SAFETY: MMIO access is valid once the BAR is mapped.
    let mmio =
        unsafe { narf_bus::map_bar(&device, LPSS_BAR) }.map_err(|_| ProbeError::BadDevice)?;

    let name = match device.kind {
        narf_bus::BusKind::Pcie { addr, .. } => {
            format!(
                "pwm-lpss-{:02x}:{:02x}.{}",
                addr.bus, addr.device, addr.function
            )
        }
        _ => String::from("pwm-lpss-unknown"),
    };
    let dev = Arc::new(LpssPwm::new(name.clone(), mmio, info));
    PROBED.lock().push(Arc::clone(&dev));

    let _ = core::fmt::write(
        &mut narf_console::Writer,
        format_args!("  pwm-lpss: detected {} ({} channel(s))\n", name, info.npwm),
    );
    Ok(())
}

/// Register the PCI match entries for every LPSS device ID.
pub fn register_pci_driver() {
    for did in SUPPORTED_DEVICE_IDS.iter().copied() {
        narf_bus::register_pci_driver(PciMatch {
            name: "pwm_lpss",
            kind: MatchKind::VendorDevice {
                vendor: LPSS_VENDOR,
                device: did,
            },
            probe,
        });
    }
}

/// Force-link hook: register the LPSS PCI driver at Stage::Subsys,
/// alongside the other PCI match registrations (cf. i801 SMBus).
/// The bus `probe_all` walk that binds matched devices runs after
/// this stage.
pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    narf_init::register(Stage::Subsys, "pwm-lpss", || {
        register_pci_driver();
        InitResult::Ok
    });
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use alloc::boxed::Box;
    use alloc::sync::Arc as AllocArc;
    use core::future::Future;
    use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// Fake BAR0 backing: heap-allocated so the window can cover all
    /// four 0x400 channel windows (backlight's Intel-PWM fixture
    /// pattern: leaked `Box<[u8]>` + `MmioRegion` over its address).
    fn fake_mmio() -> (MmioRegion, *mut u32) {
        let buf: Box<[u8]> =
            alloc::vec![0u8; LPSS_MAX_PWMS * PWM_STRIDE as usize].into_boxed_slice();
        let raw = Box::leak(buf);
        let phys = narf_memory::PhysAddr::new(raw.as_ptr() as u64);
        let mmio = MmioRegion {
            phys,
            virt: phys.raw(),
            len: raw.len() as u64,
            kind: narf_bus::BarKind::Mmio32 {
                prefetchable: false,
            },
        };
        (mmio, raw.as_mut_ptr() as *mut u32)
    }

    /// Volatile read of a fake 32-bit register.
    ///
    /// # Safety
    /// `ptr` is a live fake-MMIO backing pointer; `off` is a byte
    /// offset inside it.
    unsafe fn fake_read(ptr: *const u32, off: u64) -> u32 {
        // SAFETY: caller-checked fake backing + offset.
        unsafe { core::ptr::read_volatile(ptr.byte_add(off as usize)) }
    }

    /// Hardware model: the block clears `SW_UPDATE` at the start of
    /// the next output cycle. The simulator task watches every
    /// channel register and clears the bit when it sees it set,
    /// recording whether ENABLE was ever observed while the bit was
    /// still set — that distinguishes the bypass / non-bypass enable
    /// orderings. It exits when `done` is set (or after a safety cap
    /// so a wedged test cannot hang the harness).
    struct Sim {
        mmio: MmioRegion,
        npwm: u32,
        done: AllocArc<AtomicBool>,
        saw_enable_with_update: AllocArc<AtomicBool>,
    }

    impl Sim {
        async fn run(self) {
            let mut polls: u32 = 0;
            while !self.done.load(Ordering::Acquire) && polls < 200_000 {
                for ch in 0..self.npwm {
                    // SAFETY: fake MMIO window, channel in range.
                    let v = unsafe { self.mmio.read32(LpssPwm::ctrl_offset(ch)) };
                    if (v & PWM_SW_UPDATE) != 0 {
                        if (v & PWM_ENABLE) != 0 {
                            self.saw_enable_with_update.store(true, Ordering::Release);
                        }
                        // SAFETY: fake MMIO window, channel in range.
                        unsafe {
                            self.mmio
                                .write32(LpssPwm::ctrl_offset(ch), v & !PWM_SW_UPDATE);
                        }
                    }
                }
                polls += 1;
                narf_scheduler::yield_now().await;
            }
        }
    }

    /// Drive one async driver call to completion with the simulator
    /// running, returning the call's `Result` discriminant as a code:
    /// 0 = Ok, 1 = InvalidChannel, 2 = InvalidConfig, 3 =
    /// HardwareError. Register contents are asserted from the fake
    /// backing afterwards.
    fn run_with_sim<F, Fut>(pwm: AllocArc<LpssPwm>, sim: Sim, op: F) -> u32
    where
        F: FnOnce(AllocArc<LpssPwm>) -> Fut + Send + 'static,
        Fut: Future<Output = Result<(), PwmError>> + Send + 'static,
    {
        narf_scheduler::__reset_queues_for_test();
        let outcome = AllocArc::new(AtomicU32::new(0xFF));
        let done = sim.done.clone();
        let fut = op(pwm);
        let o = outcome.clone();
        narf_scheduler::spawn(async move {
            let r = fut.await;
            o.store(
                match r {
                    Ok(()) => 0,
                    Err(PwmError::InvalidChannel) => 1,
                    Err(PwmError::InvalidConfig) => 2,
                    Err(PwmError::HardwareError) => 3,
                },
                Ordering::SeqCst,
            );
            done.store(true, Ordering::Release);
        });
        narf_scheduler::spawn(sim.run());
        narf_scheduler::run_until_empty();
        outcome.load(Ordering::SeqCst)
    }

    fn cfg(freq: u32, duty_ns: u64, pol: Polarity) -> PwmConfig {
        PwmConfig {
            frequency_hz: freq,
            duty_cycle_ns: duty_ns,
            polarity: pol,
        }
    }

    fn smoke_lpss_byt_1khz_50pct() -> TestResult {
        let (mmio, ptr) = fake_mmio();
        let pwm = AllocArc::new(LpssPwm::new(String::from("test-byt"), mmio, &LPSS_BYT_INFO));
        let sim = Sim {
            mmio,
            npwm: 1,
            done: AllocArc::new(AtomicBool::new(false)),
            saw_enable_with_update: AllocArc::new(AtomicBool::new(false)),
        };
        // 1000 Hz, 50% duty: base_unit = round(1000 * 65536 /
        // 25e6) = 3; on_time_div = 255 - floor(255 * 500000 /
        // 1000000) = 128. ctrl = (3 << 8) | 128 = 0x380.
        let code = run_with_sim(pwm.clone(), sim, |p| async move {
            p.set_config(0, &cfg(1000, 500_000, Polarity::Normal)).await
        });
        if code != 0 {
            return TestResult::Fail("BYT 1kHz/50% set_config failed");
        }
        // SAFETY: fake backing, channel 0 in range.
        let ctrl = unsafe { fake_read(ptr, 0x00) };
        if ctrl != 0x380 {
            return TestResult::Fail("BYT ctrl != 0x380 (base_unit 3, on_time_div 128)");
        }
        if (ctrl & PWM_ENABLE) != 0 {
            return TestResult::Fail("set_config must not enable the channel");
        }
        if pwm.channel_count() != 1 {
            return TestResult::Fail("BYT channel_count != 1");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers-pwm-lpss", smoke_lpss_byt_1khz_50pct);

    fn smoke_lpss_bxt_25khz_25pct() -> TestResult {
        let (mmio, ptr) = fake_mmio();
        let pwm = AllocArc::new(LpssPwm::new(String::from("test-bxt"), mmio, &LPSS_BXT_INFO));
        let sim = Sim {
            mmio,
            npwm: 4,
            done: AllocArc::new(AtomicBool::new(false)),
            saw_enable_with_update: AllocArc::new(AtomicBool::new(false)),
        };
        // 25000 Hz, 25% duty: base_unit = round(25000 * 4194304 /
        // 19.2e6) = 5461 (0x1555); on_time_div = 255 - floor(255 *
        // 10000 / 40000) = 192 (0xC0). ctrl = 0x1555C0.
        let code = run_with_sim(pwm.clone(), sim, |p| async move {
            p.set_config(3, &cfg(25_000, 10_000, Polarity::Normal))
                .await
        });
        if code != 0 {
            return TestResult::Fail("BXT 25kHz/25% set_config failed");
        }
        // Channel 3 lives at 3 * 0x400 = 0xC00; channels 0-2 untouched.
        // SAFETY: fake backing, offsets in range.
        let ctrl3 = unsafe { fake_read(ptr, 0xC00) };
        if ctrl3 != 0x0015_55C0 {
            return TestResult::Fail("BXT ch3 ctrl != 0x1555C0 (base_unit 5461, on_time_div 192)");
        }
        for ch in 0..3u64 {
            // SAFETY: fake backing, offsets in range.
            if unsafe { fake_read(ptr, ch * 0x400) } != 0 {
                return TestResult::Fail("untouched BXT channel register moved");
            }
        }
        if pwm.channel_count() != 4 {
            return TestResult::Fail("BXT channel_count != 4");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers-pwm-lpss", smoke_lpss_bxt_25khz_25pct);

    fn smoke_lpss_inversed_polarity_complements_duty() -> TestResult {
        let (mmio, ptr) = fake_mmio();
        let pwm = AllocArc::new(LpssPwm::new(String::from("test-bxt"), mmio, &LPSS_BXT_INFO));
        let sim = Sim {
            mmio,
            npwm: 4,
            done: AllocArc::new(AtomicBool::new(false)),
            saw_enable_with_update: AllocArc::new(AtomicBool::new(false)),
        };
        // Same 25 kHz / 25% as above, inversed: on_time_div =
        // floor(255 * 10000 / 40000) = 63 (0x3F). ctrl = 0x15553F.
        let code = run_with_sim(pwm.clone(), sim, |p| async move {
            p.set_config(0, &cfg(25_000, 10_000, Polarity::Inversed))
                .await
        });
        if code != 0 {
            return TestResult::Fail("BXT inversed set_config failed");
        }
        // SAFETY: fake backing, channel 0 in range.
        let ctrl = unsafe { fake_read(ptr, 0x00) };
        if ctrl != 0x0015_553F {
            return TestResult::Fail("BXT inversed ctrl != 0x15553F (on_time_div 63)");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers-pwm-lpss",
        smoke_lpss_inversed_polarity_complements_duty
    );

    fn smoke_lpss_enable_disable() -> TestResult {
        let (mmio, ptr) = fake_mmio();
        let pwm = AllocArc::new(LpssPwm::new(String::from("test-byt"), mmio, &LPSS_BYT_INFO));
        let sim = Sim {
            mmio,
            npwm: 1,
            done: AllocArc::new(AtomicBool::new(false)),
            saw_enable_with_update: AllocArc::new(AtomicBool::new(false)),
        };
        // Enable with no config yet must fail: there is no waveform.
        let code = run_with_sim(pwm.clone(), sim, |p| async move {
            p.enable(0).await?;
            p.set_config(0, &cfg(1000, 500_000, Polarity::Normal))
                .await?;
            p.enable(0).await?;
            p.enable(0).await?; // idempotent
            p.disable(0).await?;
            p.disable(0).await?; // idempotent
            Ok(())
        });
        if code != 2 {
            return TestResult::Fail("enable-without-config must be InvalidConfig");
        }
        // The op chain stopped at the first error, so nothing was
        // programmed; run the happy path in a second pass.
        let sim2 = Sim {
            mmio,
            npwm: 1,
            done: AllocArc::new(AtomicBool::new(false)),
            saw_enable_with_update: AllocArc::new(AtomicBool::new(false)),
        };
        let code = run_with_sim(pwm.clone(), sim2, |p| async move {
            p.set_config(0, &cfg(1000, 500_000, Polarity::Normal))
                .await?;
            p.enable(0).await?;
            p.enable(0).await?;
            p.disable(0).await?;
            p.disable(0).await?;
            Ok(())
        });
        if code != 0 {
            return TestResult::Fail("BYT config/enable/disable chain failed");
        }
        // SAFETY: fake backing, channel 0 in range.
        let ctrl = unsafe { fake_read(ptr, 0x00) };
        if ctrl != 0x380 {
            return TestResult::Fail("final BYT ctrl != 0x380 (timing kept, ENABLE cleared)");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers-pwm-lpss", smoke_lpss_enable_disable);

    fn smoke_lpss_bypass_ordering() -> TestResult {
        // Non-bypass (Bay Trail): ENABLE is set before the update
        // wait, so the hardware model observes ENABLE while
        // SW_UPDATE is still set. Bypass (Broxton): the wait comes
        // first, so it never does.
        for (info, name, expect_saw) in [
            (&LPSS_BYT_INFO, "byt", true),
            (&LPSS_BXT_INFO, "bxt", false),
        ] {
            let (mmio, ptr) = fake_mmio();
            let pwm = AllocArc::new(LpssPwm::new(String::from(name), mmio, info));
            let saw = AllocArc::new(AtomicBool::new(false));
            let sim = Sim {
                mmio,
                npwm: info.npwm,
                done: AllocArc::new(AtomicBool::new(false)),
                saw_enable_with_update: saw.clone(),
            };
            let code = run_with_sim(pwm.clone(), sim, |p| async move {
                p.set_config(0, &cfg(1000, 500_000, Polarity::Normal))
                    .await?;
                p.enable(0).await
            });
            if code != 0 {
                return TestResult::Fail("ordering test op chain failed");
            }
            if saw.load(Ordering::Acquire) != expect_saw {
                return TestResult::Fail("enable/update ordering wrong for part");
            }
            // SAFETY: fake backing, channel 0 in range.
            let ctrl = unsafe { fake_read(ptr, 0x00) };
            if (ctrl & PWM_ENABLE) == 0 {
                return TestResult::Fail("channel must end enabled");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers-pwm-lpss", smoke_lpss_bypass_ordering);

    fn smoke_lpss_rejects_bad_channel_and_config() -> TestResult {
        let (mmio, _ptr) = fake_mmio();
        let pwm = AllocArc::new(LpssPwm::new(String::from("test-byt"), mmio, &LPSS_BYT_INFO));
        let sim = Sim {
            mmio,
            npwm: 1,
            done: AllocArc::new(AtomicBool::new(false)),
            saw_enable_with_update: AllocArc::new(AtomicBool::new(false)),
        };
        // Channel 1 on a 1-channel part; zero frequency; duty longer
        // than the period. Each must fail with its own error code.
        let code = run_with_sim(pwm.clone(), sim, |p| async move {
            let mut got = 0u32;
            if let Err(PwmError::InvalidChannel) =
                p.set_config(1, &cfg(1000, 500_000, Polarity::Normal)).await
            {
                got += 1;
            }
            if let Err(PwmError::InvalidConfig) =
                p.set_config(0, &cfg(0, 0, Polarity::Normal)).await
            {
                got += 1;
            }
            if let Err(PwmError::InvalidConfig) = p
                .set_config(0, &cfg(1000, 2_000_000, Polarity::Normal))
                .await
            {
                got += 1;
            }
            if let Err(PwmError::InvalidChannel) = p.enable(9).await {
                got += 1;
            }
            if let Err(PwmError::InvalidChannel) = p.disable(9).await {
                got += 1;
            }
            if got == 5 {
                Ok(())
            } else {
                Err(PwmError::HardwareError)
            }
        });
        if code != 0 {
            return TestResult::Fail("not all 5 bad-input rejections fired");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers-pwm-lpss",
        smoke_lpss_rejects_bad_channel_and_config
    );

    fn smoke_lpss_stuck_sw_update_is_hardware_error() -> TestResult {
        // No simulator task: the block never clears SW_UPDATE.
        // First call: `prepare()` latches the update and the wait
        // must give up with HardwareError after the poll budget
        // instead of spinning forever. Second call: the bit is still
        // set from the first call, so the entry check
        // (`pwm_lpss_is_updating`) must refuse immediately, also
        // with HardwareError.
        let (mmio, ptr) = fake_mmio();
        let pwm = AllocArc::new(LpssPwm::new(String::from("test-byt"), mmio, &LPSS_BYT_INFO));
        narf_scheduler::__reset_queues_for_test();
        let outcome = AllocArc::new(AtomicU32::new(0xFF));
        let p = pwm.clone();
        let o = outcome.clone();
        narf_scheduler::spawn(async move {
            let mut code = 0u32;
            let r1 = p.set_config(0, &cfg(1000, 500_000, Polarity::Normal)).await;
            if r1 != Err(PwmError::HardwareError) {
                code = 1;
            }
            let r2 = p.set_config(0, &cfg(1000, 500_000, Polarity::Normal)).await;
            if r2 != Err(PwmError::HardwareError) {
                code = 2;
            }
            o.store(code, Ordering::SeqCst);
        });
        narf_scheduler::run_until_empty();
        if outcome.load(Ordering::SeqCst) != 0 {
            return TestResult::Fail("stuck SW_UPDATE must be HardwareError on both paths");
        }
        // SAFETY: fake backing, channel 0 in range.
        let ctrl = unsafe { fake_read(ptr, 0x00) };
        if (ctrl & PWM_SW_UPDATE) == 0 {
            return TestResult::Fail("stuck bit must still be set after the failed updates");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers-pwm-lpss",
        smoke_lpss_stuck_sw_update_is_hardware_error
    );

    fn smoke_lpss_pci_id_table_matches_linux() -> TestResult {
        // All nine IDs from Linux `pwm_lpss_pci_ids[]`, each mapped
        // to the right board data; an unclaimed ID maps to nothing.
        // (Claimant check: no other in-tree driver claims these IDs —
        // the only hits are unrelated table constants in GPU filter
        // coefficients and rtw88 DM tables.)
        let cases: &[(u16, &LpssBoardInfo)] = &[
            (0x0f08, &LPSS_BYT_INFO),
            (0x0f09, &LPSS_BYT_INFO),
            (0x2288, &LPSS_BSW_INFO),
            (0x2289, &LPSS_BSW_INFO),
            (0x0ac8, &LPSS_BXT_INFO),
            (0x5ac8, &LPSS_BXT_INFO),
            (0x31c8, &LPSS_BXT_INFO),
            (0x1ac8, &LPSS_BXT_INFO),
            (0x11a5, &LPSS_TNG_INFO),
        ];
        if SUPPORTED_DEVICE_IDS.len() != cases.len() {
            return TestResult::Fail("SUPPORTED_DEVICE_IDS length != 9 Linux IDs");
        }
        for (id, want) in cases {
            if !SUPPORTED_DEVICE_IDS.contains(id) {
                return TestResult::Fail("Linux PCI ID missing from table");
            }
            match board_info_for(*id) {
                Some(got) if got == *want => {}
                _ => return TestResult::Fail("PCI ID mapped to wrong board data"),
            }
        }
        if board_info_for(0x8086).is_some() || board_info_for(0xFFFF).is_some() {
            return TestResult::Fail("unclaimed ID must map to None");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers-pwm-lpss", smoke_lpss_pci_id_table_matches_linux);

    fn smoke_lpss_timing_bits_pure() -> TestResult {
        // Direct arithmetic checks against Linux `pwm_lpss_prepare`:
        // 0% and 100% duty at both polarities, plus the base_unit
        // clamp (a 1 Hz request rounds to 0 and must clamp to 1).
        let normal_0 = timing_bits(&LPSS_BYT_INFO, &cfg(1000, 0, Polarity::Normal));
        let normal_100 = timing_bits(&LPSS_BYT_INFO, &cfg(1000, 1_000_000, Polarity::Normal));
        let inv_0 = timing_bits(&LPSS_BYT_INFO, &cfg(1000, 0, Polarity::Inversed));
        let inv_100 = timing_bits(&LPSS_BYT_INFO, &cfg(1000, 1_000_000, Polarity::Inversed));
        // BYT 1 kHz: base_unit 3 → 0x300. 0% normal → on_time_div 255
        // (output low); 100% normal → 0 (always high); inversed swaps.
        if normal_0 != Ok(0x300 | 255) {
            return TestResult::Fail("0% normal must be 0x3FF");
        }
        if normal_100 != Ok(0x300) {
            return TestResult::Fail("100% normal must be 0x300");
        }
        if inv_0 != Ok(0x300) {
            return TestResult::Fail("0% inversed must be 0x300");
        }
        if inv_100 != Ok(0x300 | 255) {
            return TestResult::Fail("100% inversed must be 0x3FF");
        }
        // 1 Hz on BYT: round(1 * 65536 / 25e6) = 0 → clamped to 1.
        if timing_bits(&LPSS_BYT_INFO, &cfg(1, 500_000_000, Polarity::Normal)) != Ok(0x100 | 128) {
            return TestResult::Fail("1 Hz base_unit must clamp to 1");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers-pwm-lpss", smoke_lpss_timing_bits_pure);
}
