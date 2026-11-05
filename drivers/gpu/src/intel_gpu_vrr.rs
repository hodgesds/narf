//! Variable Refresh Rate (VRR / Adaptive Sync) engine for Intel graphics.
//!
//! Controls transcoder VRR timing registers (`TRANS_VRR_CTL`, `TRANS_VRR_VMIN`,
//! `TRANS_VRR_VMAX`, `TRANS_VRR_FLIPLINE`, `TRANS_VRR_VSYNC`, `TRANS_PUSH`)
//! across Intel display generations:
//! - Gen12 (TigerLake, RocketLake, DG1): display 12; direct `vtotal` values,
//!   `TRANS_VRR_CTL` enable/flip-line flags.
//! - Display 13 (AlderLake, RaptorLake, DG2): `vtotal - 1` offsets,
//!   `VRR_CTL_IGN_MAX_STRETCH`.
//! - Display 14 (MeteorLake / Xe_LPG): `TRANS_VRR_VSYNC`, `guardband` packed in
//!   `TRANS_VRR_CTL`.
//! - Display 20 (LunarLake / Xe2_LPD): `EMP_AS_SDP_TL` Adaptive Sync SDP timing.
//! - Display 30 (PantherLake / Xe3_LPD): VRR timing generator architecture.
//!
//! Corresponds to Linux `drivers/gpu/drm/i915/display/intel_vrr.c` and
//! `intel_vrr_regs.h`.

use core::sync::atomic::{AtomicBool, Ordering};
use narf_filesystem::FsError;
use narf_lib::sync::IrqSafeSpinLock;

use crate::{intel_gpu::Generation, intel_gpu_aux::MmioWindow, intel_gpu_modeset::Mode};

// ── Transcoder Register Offsets (relative to Transcoder base) ────────────────

pub const TRANS_VRR_CTL_OFFSET: u64 = 0x420;
pub const TRANS_VRR_VMAX_OFFSET: u64 = 0x424;
pub const TRANS_VRR_STATUS_OFFSET: u64 = 0x42c;
pub const TRANS_VRR_VMIN_OFFSET: u64 = 0x434;
pub const TRANS_VRR_FLIPLINE_OFFSET: u64 = 0x438;
pub const TRANS_VRR_VSYNC_OFFSET: u64 = 0x078;
pub const EMP_AS_SDP_TL_OFFSET: u64 = 0x204;
pub const TRANS_PUSH_OFFSET: u64 = 0xa70;

// ── Transcoder Base Addresses ────────────────────────────────────────────────

pub const TRANSCODER_A_BASE: u64 = 0x60000;
pub const TRANSCODER_B_BASE: u64 = 0x61000;
pub const TRANSCODER_C_BASE: u64 = 0x62000;
pub const TRANSCODER_D_BASE: u64 = 0x63000;
pub const TRANSCODER_EDP_BASE: u64 = 0x6f000;

// ── Register Bit Definitions ─────────────────────────────────────────────────

pub const VRR_CTL_VRR_ENABLE: u32 = 1 << 31;
pub const VRR_CTL_IGN_MAX_STRETCH: u32 = 1 << 30;
pub const VRR_CTL_FLIP_LINE_EN: u32 = 1 << 29;
pub const VRR_CTL_CMRR_ENABLE: u32 = 1 << 27;
pub const VRR_CTL_GUARDBAND_MASK: u32 = 0xffff;

pub const VRR_STATUS_VRR_EN_LIVE: u32 = 1 << 27;
pub const VRR_STATUS_FLIP_BEING_PUSHED: u32 = 1 << 26;

pub const TRANS_PUSH_EN: u32 = 1 << 31;
pub const TRANS_PUSH_SEND: u32 = 1 << 30;

/// Max hardware vertical total supported by the VRR registers (13 bits).
pub const VRR_MAX_VTOTAL_HW: u32 = 0x1fff;

// ── Transcoders ──────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum VrrTranscoder {
    A,
    B,
    C,
    D,
    Edp,
}

impl VrrTranscoder {
    pub const fn base(self) -> u64 {
        match self {
            Self::A => TRANSCODER_A_BASE,
            Self::B => TRANSCODER_B_BASE,
            Self::C => TRANSCODER_C_BASE,
            Self::D => TRANSCODER_D_BASE,
            Self::Edp => TRANSCODER_EDP_BASE,
        }
    }

    pub const fn for_crtc(crtc_id: u32) -> Self {
        match crtc_id {
            1 => Self::A,
            2 => Self::B,
            3 => Self::C,
            4 => Self::D,
            _ => Self::A,
        }
    }
}

// ── Display Hardware Generation for VRR ──────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum DisplayVrrIp {
    Gen12,
    Display13,
    Display14,
    Display20,
    Display30,
}

impl DisplayVrrIp {
    pub const fn from_generation(gen: Generation) -> Self {
        match gen {
            Generation::TigerLake => Self::Gen12,
            Generation::AlderLake => Self::Display13,
            Generation::MeteorLake => Self::Display14,
            Generation::LunarLake => Self::Display20,
            Generation::PantherLake => Self::Display30,
        }
    }

    /// Whether VMIN, VMAX, and FLIPLINE write `val - 1` (display 13+) or `val` (Gen12).
    pub const fn uses_vtotal_minus_one(self) -> bool {
        matches!(
            self,
            Self::Display13 | Self::Display14 | Self::Display20 | Self::Display30
        )
    }

    /// Whether `TRANS_VRR_VSYNC` (`base + 0x078`) is supported (display 14+).
    pub const fn has_vrr_vsync(self) -> bool {
        matches!(self, Self::Display14 | Self::Display20 | Self::Display30)
    }

    /// Whether `EMP_AS_SDP_TL` (`base + 0x204`) is supported (display 20+).
    pub const fn has_emp_as_sdp(self) -> bool {
        matches!(self, Self::Display20 | Self::Display30)
    }

    /// Whether the guardband field is packed into `TRANS_VRR_CTL[15:0]` (display 14+).
    pub const fn uses_guardband_in_ctl(self) -> bool {
        matches!(self, Self::Display14 | Self::Display20 | Self::Display30)
    }

    /// Whether `VRR_CTL_IGN_MAX_STRETCH` is supported (display 13).
    pub const fn uses_ign_max_stretch(self) -> bool {
        matches!(self, Self::Display13)
    }
}

// ── VRR Refresh Range ────────────────────────────────────────────────────────

/// A sink's supported variable refresh rate range in Hz.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VrrRange {
    pub min_hz: u16,
    pub max_hz: u16,
}

impl VrrRange {
    pub const fn new(min_hz: u16, max_hz: u16) -> Option<Self> {
        if min_hz != 0 && max_hz > min_hz && (max_hz - min_hz) >= 10 {
            Some(Self { min_hz, max_hz })
        } else {
            None
        }
    }

    pub const fn supports_refresh(&self, hz: u32) -> bool {
        hz >= self.min_hz as u32 && hz <= self.max_hz as u32
    }

    /// Parse VRR range from an EDID byte slice (monitor range descriptor or DisplayID).
    pub fn from_edid(edid: &[u8]) -> Option<Self> {
        let r = crate::amdgpu_freesync::monitor_range(edid)
            .filter(|r| r.min_vfreq != 0 && r.max_vfreq != 0)
            .or_else(|| crate::amdgpu_freesync::displayid_range(edid))?;
        Self::new(r.min_vfreq, r.max_vfreq)
    }

    /// Parse VRR range from an EDID and optional DPCD block.
    pub fn from_edid_and_dpcd(edid: &[u8], dpcd: Option<&[u8; 16]>) -> Option<Self> {
        if let Some(dpcd) = dpcd {
            if dpcd[7] & crate::amdgpu_freesync::DPCD_MSA_TIMING_PAR_IGNORED == 0 {
                return None;
            }
        }
        Self::from_edid(edid)
    }
}

// ── Modeline Refresh Helper ──────────────────────────────────────────────────

/// Calculate the rounded vertical refresh rate in Hz for a display mode.
pub fn mode_vrefresh(mode: &Mode) -> u32 {
    let total = u64::from(mode.h_total) * u64::from(mode.v_total);
    if total == 0 {
        return 0;
    }
    let num = u64::from(mode.pixel_clock_khz) * 1000;
    u32::try_from((num + total / 2) / total).unwrap_or(0)
}

// ── VRR Timings ──────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VrrTimings {
    pub vmin: u32,
    pub vmax: u32,
    pub flipline: u32,
    pub guardband: u16,
    pub vsync_start: u32,
    pub vsync_end: u32,
}

impl VrrTimings {
    /// Compute transcoder VRR timing registers for a given mode, sink VRR range, and display IP.
    pub fn compute(mode: &Mode, range: VrrRange, ip: DisplayVrrIp) -> Option<Self> {
        if mode.h_total == 0 || mode.v_total == 0 || mode.pixel_clock_khz == 0 {
            return None;
        }
        if mode.v_total <= mode.v_active || mode.v_sync_start > mode.v_total {
            return None;
        }
        let hz = mode_vrefresh(mode);
        if !range.supports_refresh(hz) {
            return None;
        }

        let vmin = u32::from(mode.v_total);
        // Minimum refresh rate corresponds to maximum frame duration / vtotal:
        // lines = (pixel_clock_khz * 1000) / (h_total * min_hz)
        let num = u64::from(mode.pixel_clock_khz) * 1000;
        let denom = u64::from(mode.h_total) * u64::from(range.min_hz);
        if denom == 0 {
            return None;
        }
        let raw_vmax = u32::try_from(num / denom).ok()?;
        let vmax = raw_vmax.min(VRR_MAX_VTOTAL_HW).max(vmin);
        let flipline = vmin;

        let vsync_start = u32::from(mode.v_total.saturating_sub(mode.v_sync_start));
        let vsync_end = u32::from(mode.v_total.saturating_sub(mode.v_sync_end));

        let guardband = if ip.uses_guardband_in_ctl() {
            let guard = u64::from(vsync_start + 1).max(8);
            let max_guard = u64::from(mode.v_total.saturating_sub(mode.v_active)).min(0xffff);
            u16::try_from(guard.min(max_guard)).unwrap_or(8)
        } else {
            0
        };

        Some(Self {
            vmin,
            vmax,
            flipline,
            guardband,
            vsync_start,
            vsync_end,
        })
    }
}

// ── Hardware Register Programming ────────────────────────────────────────────

/// Program the transcoder VRR timing limit registers (`TRANS_VRR_VMIN`, `TRANS_VRR_VMAX`,
/// `TRANS_VRR_FLIPLINE`, and `TRANS_VRR_VSYNC` / `EMP_AS_SDP_TL` where supported).
pub fn program_vrr_timings(
    io: &(impl MmioWindow + ?Sized),
    trans: VrrTranscoder,
    ip: DisplayVrrIp,
    timings: &VrrTimings,
) -> Result<(), FsError> {
    let base = trans.base();
    if ip.uses_vtotal_minus_one() {
        io.write32(base + TRANS_VRR_VMIN_OFFSET, timings.vmin.saturating_sub(1));
        io.write32(base + TRANS_VRR_VMAX_OFFSET, timings.vmax.saturating_sub(1));
        io.write32(
            base + TRANS_VRR_FLIPLINE_OFFSET,
            timings.flipline.saturating_sub(1),
        );
    } else {
        io.write32(base + TRANS_VRR_VMIN_OFFSET, timings.vmin);
        io.write32(base + TRANS_VRR_VMAX_OFFSET, timings.vmax);
        io.write32(base + TRANS_VRR_FLIPLINE_OFFSET, timings.flipline);
    }

    if ip.has_vrr_vsync() {
        let vsync_val = ((timings.vsync_end & 0x1fff) << 16) | (timings.vsync_start & 0x1fff);
        io.write32(base + TRANS_VRR_VSYNC_OFFSET, vsync_val);
    }

    if ip.has_emp_as_sdp() {
        io.write32(base + EMP_AS_SDP_TL_OFFSET, timings.vsync_start & 0x1fff);
    }

    if io.display_access_ok() {
        Ok(())
    } else {
        Err(FsError::NoDevice)
    }
}

/// Enable VRR on the specified transcoder: arms `TRANS_PUSH` and writes `TRANS_VRR_CTL`.
pub fn vrr_enable(
    io: &(impl MmioWindow + ?Sized),
    trans: VrrTranscoder,
    ip: DisplayVrrIp,
    guardband: u16,
) -> Result<(), FsError> {
    let base = trans.base();
    io.write32(base + TRANS_PUSH_OFFSET, TRANS_PUSH_EN);

    let mut ctl = VRR_CTL_VRR_ENABLE | VRR_CTL_FLIP_LINE_EN;
    if ip.uses_ign_max_stretch() {
        ctl |= VRR_CTL_IGN_MAX_STRETCH;
    }
    if ip.uses_guardband_in_ctl() {
        ctl |= u32::from(guardband) & VRR_CTL_GUARDBAND_MASK;
    }

    io.write32(base + TRANS_VRR_CTL_OFFSET, ctl);
    if io.display_access_ok() {
        Ok(())
    } else {
        Err(FsError::NoDevice)
    }
}

/// Disable VRR on the specified transcoder: clears `VRR_CTL_VRR_ENABLE`, waits for
/// `VRR_STATUS_VRR_EN_LIVE` to clear, then resets `TRANS_PUSH`.
pub fn vrr_disable(
    io: &(impl MmioWindow + ?Sized),
    trans: VrrTranscoder,
    _ip: DisplayVrrIp,
) -> Result<(), FsError> {
    let base = trans.base();
    let ctl = io.read32(base + TRANS_VRR_CTL_OFFSET);
    if ctl == u32::MAX || !io.display_access_ok() {
        return Err(FsError::NoDevice);
    }
    if ctl & VRR_CTL_VRR_ENABLE == 0 {
        return Ok(());
    }

    // Keep flip line enable and guardband, clear VRR enable
    let new_ctl = (ctl & !VRR_CTL_VRR_ENABLE) | VRR_CTL_FLIP_LINE_EN;
    io.write32(base + TRANS_VRR_CTL_OFFSET, new_ctl);

    // Wait for hardware to exit VRR live state (bounded to 10,000 polls)
    for _ in 0..10_000 {
        let status = io.read32(base + TRANS_VRR_STATUS_OFFSET);
        if status == u32::MAX || !io.display_access_ok() {
            return Err(FsError::NoDevice);
        }
        if status & VRR_STATUS_VRR_EN_LIVE == 0 {
            break;
        }
    }

    io.write32(base + TRANS_PUSH_OFFSET, 0);
    if io.display_access_ok() {
        Ok(())
    } else {
        Err(FsError::NoDevice)
    }
}

/// Send a push event on `TRANS_PUSH` to terminate vblank early on an armed page flip.
pub fn vrr_send_push(io: &(impl MmioWindow + ?Sized), trans: VrrTranscoder) -> Result<(), FsError> {
    io.write32(trans.base() + TRANS_PUSH_OFFSET, TRANS_PUSH_EN);
    if io.display_access_ok() {
        Ok(())
    } else {
        Err(FsError::NoDevice)
    }
}

/// Query whether VRR is currently active in hardware on the transcoder.
pub fn is_vrr_active(io: &(impl MmioWindow + ?Sized), trans: VrrTranscoder) -> bool {
    let ctl = io.read32(trans.base() + TRANS_VRR_CTL_OFFSET);
    ctl != u32::MAX && (ctl & VRR_CTL_VRR_ENABLE != 0)
}

// ── Global Driver VRR State ──────────────────────────────────────────────────

#[derive(Debug)]
pub struct VrrState {
    enabled: [AtomicBool; 4],
    timings: [IrqSafeSpinLock<Option<VrrTimings>>; 4],
    range: [IrqSafeSpinLock<Option<VrrRange>>; 4],
}

impl Default for VrrState {
    fn default() -> Self {
        Self::new()
    }
}

impl VrrState {
    pub const fn new() -> Self {
        Self {
            enabled: [
                AtomicBool::new(false),
                AtomicBool::new(false),
                AtomicBool::new(false),
                AtomicBool::new(false),
            ],
            timings: [
                IrqSafeSpinLock::new(None),
                IrqSafeSpinLock::new(None),
                IrqSafeSpinLock::new(None),
                IrqSafeSpinLock::new(None),
            ],
            range: [
                IrqSafeSpinLock::new(None),
                IrqSafeSpinLock::new(None),
                IrqSafeSpinLock::new(None),
                IrqSafeSpinLock::new(None),
            ],
        }
    }

    fn crtc_index(crtc_id: u32) -> Option<usize> {
        match crtc_id {
            1..=4 => Some((crtc_id - 1) as usize),
            _ => None,
        }
    }

    pub fn set_enabled(&self, crtc_id: u32, enabled: bool) {
        if let Some(idx) = Self::crtc_index(crtc_id) {
            self.enabled[idx].store(enabled, Ordering::SeqCst);
        }
    }

    pub fn is_enabled(&self, crtc_id: u32) -> bool {
        Self::crtc_index(crtc_id)
            .map(|idx| self.enabled[idx].load(Ordering::SeqCst))
            .unwrap_or(false)
    }

    pub fn set_timings(&self, crtc_id: u32, timings: Option<VrrTimings>) {
        if let Some(idx) = Self::crtc_index(crtc_id) {
            *self.timings[idx].lock() = timings;
        }
    }

    pub fn timings(&self, crtc_id: u32) -> Option<VrrTimings> {
        Self::crtc_index(crtc_id).and_then(|idx| *self.timings[idx].lock())
    }

    pub fn set_range(&self, crtc_id: u32, range: Option<VrrRange>) {
        if let Some(idx) = Self::crtc_index(crtc_id) {
            *self.range[idx].lock() = range;
        }
    }

    pub fn range(&self, crtc_id: u32) -> Option<VrrRange> {
        Self::crtc_index(crtc_id).and_then(|idx| *self.range[idx].lock())
    }
}

pub static VRR_STATE: VrrState = VrrState::new();

/// Retain and apply a CRTC's VRR request (from DRM `VRR_ENABLED`).
pub fn request_vrr_enabled(crtc_id: u32, enabled: bool) {
    VRR_STATE.set_enabled(crtc_id, enabled);

    // Apply to hardware if controller is initialized
    let trans = VrrTranscoder::for_crtc(crtc_id);
    crate::intel_gpu::with_controller(|dev| {
        let ip = DisplayVrrIp::from_generation(dev.chip.generation);
        let io = dev.mode_window();
        if enabled {
            if let Some(timings) = VRR_STATE.timings(crtc_id) {
                let _ = program_vrr_timings(&io, trans, ip, &timings);
                let _ = vrr_enable(&io, trans, ip, timings.guardband);
            }
        } else {
            let _ = vrr_disable(&io, trans, ip);
        }
    });
}

/// Invoked on a completed/armed primary plane flip to trigger dynamic VRR push.
pub fn on_plane_flip(crtc_id: u32, io: &(impl MmioWindow + ?Sized)) {
    if VRR_STATE.is_enabled(crtc_id) {
        let trans = VrrTranscoder::for_crtc(crtc_id);
        let _ = vrr_send_push(io, trans);
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "intel_gpu_vrr_tests.rs"]
mod tests;
