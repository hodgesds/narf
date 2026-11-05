//! AMD ATIF backlight codec — the `_DSM` surface, decoded.
//!
//! ATIF (AMD ACPI Total Interface) is a WMI-exposed `_DSM` surface
//! that AMD-laptop firmware uses to mediate things the host can't
//! drive directly: thermal events, hotkeys, expansion-dock
//! detection, and panel backlight. Function 0 returns the
//! supported-function bitmap; function 3 sets brightness as a
//! 0–100 percentage; function 4 returns the current percentage.
//! This module is the pure codec for that surface — the GUID, the
//! function indices, the bitmap decode, and the invocation trait —
//! with no dispatcher state of its own.
//!
//! ## Why this file is a codec and not a dispatcher
//!
//! This module previously carried a unified dispatcher (a global
//! `set` / `get` / `backend()` surface with Intel-PWM, ATIF, and
//! ACPI-`_BCL` backends behind `activate_*` functions). It was a
//! second, parallel brightness universe: the `activate_*`
//! functions had no production callers, its `_BCL` decode was the
//! third independent implementation of the protocol in the tree,
//! and its Intel backend duplicated the PWM device in
//! `narf_drivers_backlight::intel_bl`. The consolidation (#949,
//! #1021) retired the dispatcher and its duplicate backends:
//!
//! - Panel brightness has exactly one owner registry — the
//!   arbitrated registry in `narf-drivers-backlight`
//!   (`register_backlight` / `panel_owner`), which publishes the
//!   elected owner to `/sys/class/backlight`.
//! - The Intel PWM path is `narf_drivers_backlight::intel_bl`,
//!   installed from the Intel GPU probe.
//! - The ACPI `_BCL`/`_BCM`/`_BQC` path is
//!   `narf_drivers_backlight::acpi_video`.
//! - The AMD native path is `AmdgpuPanelBacklight` (this crate),
//!   over `Amdgpu::set_backlight`.
//!
//! An ATIF brightness owner, when one is wired, will be a
//! `BacklightDevice` in `narf-drivers-backlight` (Firmware kind)
//! built on this codec and the live `_DSM` runner; it registers
//! through the same arbitration as every other candidate. Until
//! then the codec stands alone, exercised by its decode smoke.
//!
//! ## References
//!
//! Linux is GPL-2.0-or-later and NARF was relicensed to the
//! same on 2026-05-20, so the upstream sources may be cited
//! and adapted directly:
//!
//! - `drivers/platform/x86/amd/pmf/sps.c` /
//!   `drivers/gpu/drm/radeon/radeon_atif.c` — the ATIF GUID
//!   and the `_DSM` function-supported-bitmap convention.
//! - `drivers/gpu/drm/amd/amdgpu/amdgpu_acpi.c` —
//!   `amdgpu_atif_set_backlight` shows the func-3 set call shape.
//! - ACPI 6.5 §9.1.1 — the `_DSM` function-0 bitmap convention.

extern crate alloc;

use alloc::vec::Vec;

// ── ATIF (AMD _DSM) ────────────────────────────────────────────────
//
// The function-supported bitmap follows the standard _DSM
// convention (ACPI 6.5 §9.1.1):
//   - Function 0: returns a Buffer whose bits indicate which
//     other function indices are valid for this revision.
//   - Bit 0 of function 0's return is *always* set (the spec
//     promises function 0 itself is supported).
//
// AMD's documented ATIF function map (per radeon_atif.c and
// amdgpu_acpi.c):
//   - Func 1 — QUERY_BRIGHTNESS_TRANSFER_CHARACTERISTICS
//   - Func 2 — SET_PREFERRED_BRIGHTNESS_NOTIFICATION
//   - Func 3 — SET_BRIGHTNESS_PERCENTAGE
//   - Func 4 — GET_BRIGHTNESS_PERCENTAGE
//   - Func 5 — SELECT_ACTIVE_DISPLAYS
//   - Func 6 — GET_LID_STATE
//   - Func 7 — GET_TV_STANDARD
//   - Func 8..N — thermal / hotkey / expansion notifications

/// ATIF WMI GUID, little-endian mixed-endian (Microsoft GUID byte
/// order): `ea3168f8-ce3c-4c12-aedd-69dd0e6bb59b`.
/// First three groups are little-endian; the trailing two groups
/// are big-endian per the MS GUID convention. This is the byte
/// layout AML sees when the `_DSM` Buffer argument is decoded.
pub const ATIF_GUID: [u8; 16] = [
    0xf8, 0x68, 0x31, 0xea, // ea3168f8 (LE)
    0x3c, 0xce, // ce3c     (LE)
    0x12, 0x4c, // 4c12     (LE)
    0xae, 0xdd, // aedd     (BE)
    0x69, 0xdd, 0x0e, 0x6b, 0xb5, 0x9b, // 69dd0e6bb59b (BE)
];

/// ATIF function indices.
pub const ATIF_FN_QUERY_FUNCTIONS: u8 = 0;
pub const ATIF_FN_QUERY_BRIGHTNESS_TC: u8 = 1;
pub const ATIF_FN_SET_BRIGHTNESS_PCT: u8 = 3;
pub const ATIF_FN_GET_BRIGHTNESS_PCT: u8 = 4;

/// Result of decoding the `_DSM` function-0 supported-bitmap. Each
/// `Some` entry says "function index `i` is supported". The bitmap
/// is little-endian; bit 0 of byte 0 is always set per spec.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DsmSupported {
    /// All supported function indices, ascending.
    pub functions: Vec<u8>,
}

impl DsmSupported {
    /// True iff function `f` appears in the supported set.
    pub fn supports(&self, f: u8) -> bool {
        self.functions.contains(&f)
    }
}

/// Decode the buffer returned by `_DSM(GUID, rev, 0, Package())`
/// into the supported-function set. Per ACPI 6.5 §9.1.1 the buffer
/// is a bitmask: bit `i` of byte `i / 8` ↔ function `i` is
/// supported. Function 0 (bit 0) MUST be set; if it isn't, this
/// function returns an empty set so the caller falls through to the
/// next backend without spamming.
pub fn decode_dsm_supported(buf: &[u8]) -> DsmSupported {
    if buf.is_empty() || buf[0] & 0x01 == 0 {
        return DsmSupported::default();
    }
    let mut funcs = Vec::new();
    for (byte_idx, byte) in buf.iter().enumerate() {
        for bit in 0..8 {
            if (byte >> bit) & 1 != 0 {
                let f = (byte_idx as u16) * 8 + bit;
                if f <= u8::MAX as u16 {
                    funcs.push(f as u8);
                }
            }
        }
    }
    DsmSupported { functions: funcs }
}

/// Trait an ATIF consumer uses to invoke `_DSM` against the WMI
/// device. Pure trait → testable without an AML interpreter. The
/// production wiring implements this by calling
/// `narf_aml::eval::evaluate_dsm`.
pub trait AtifInvoke: Sync + Send {
    /// Invoke `_DSM(GUID=ATIF, rev=1, function, package_arg)`. The
    /// `package_arg` is encoded by the caller; for func 0 it's an
    /// empty package, for func 3 (set) it's `Package(Integer(pct))`.
    /// Returns the raw buffer the AML method returned, or `None`
    /// on AML evaluation error.
    fn dsm(&self, function: u8, package_arg: &[u8]) -> Option<Vec<u8>>;
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    //! Smoke for the ATIF codec. The dispatcher's priority and
    //! round-trip smokes were retired with the dispatcher itself
    //! (#949); backend selection now lives in the backlight crate's
    //! arbitration fixtures, and the Intel/ACPI codecs are covered
    //! by that crate's smokes.

    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_atif_dsm_supported_bitmap_decode() -> TestResult {
        // Buffer says func 0, 1, 3, 4 supported.
        // Bit positions: 0, 1, 3, 4 → byte 0 = 0b0001_1011 = 0x1B.
        let supported = decode_dsm_supported(&[0x1B]);
        if !supported.supports(0)
            || !supported.supports(1)
            || !supported.supports(3)
            || !supported.supports(4)
        {
            return TestResult::Fail("expected 0/1/3/4 supported");
        }
        if supported.supports(2) || supported.supports(5) {
            return TestResult::Fail("false-positive supports");
        }
        // Function 0 unset → spec violation, empty set.
        let empty = decode_dsm_supported(&[0x02]);
        if !empty.functions.is_empty() {
            return TestResult::Fail("missing func 0 should yield empty");
        }
        let empty2 = decode_dsm_supported(&[]);
        if !empty2.functions.is_empty() {
            return TestResult::Fail("empty buf should yield empty");
        }
        // Multi-byte bitmap: func 0, 8, 16.
        let supported = decode_dsm_supported(&[0x01, 0x01, 0x01]);
        if !supported.supports(0) || !supported.supports(8) || !supported.supports(16) {
            return TestResult::Fail("multi-byte bitmap miss");
        }
        // GUID sanity.
        if ATIF_GUID[0] != 0xf8 || ATIF_GUID[15] != 0x9b {
            return TestResult::Fail("ATIF GUID bytes wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/backlight",
        smoke_atif_dsm_supported_bitmap_decode
    );
}
