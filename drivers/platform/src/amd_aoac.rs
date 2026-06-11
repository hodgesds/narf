//! AMD AOAC (Always-On Always-Connected) — Modern Standby / S0ix.
//!
//! Modern Standby replaces S3 sleep on current AMD laptops.  Instead
//! of a hard power-off the SOC cycles each IP block through D-states
//! (PCIe power management semantics) independently.  The FCH (Fusion
//! Controller Hub) MMIO window at `0xFED8_0000` contains a pair of
//! per-IP control/status registers that firmware and the OS negotiate
//! to gate clocks and power planes.
//!
//! ## Register map
//!
//! FCH MMIO base: `0xFED8_0000`.
//!
//! | offset | name             | width | description               |
//! |--------|------------------|-------|---------------------------|
//! | 0x9C   | AOAC_DEV_D3_CTL  | u32   | per-IP D-state control    |
//! | 0xA0   | AOAC_DEV_D3_STATE| u32   | per-IP current D-state    |
//!
//! Each IP occupies 2 bits in `AOAC_DEV_D3_CTL`.  IP indices 0–15
//! map to bits `[2*n+1 : 2*n]`; indices 16–31 are in the upper
//! half-word (bits 31:16).  The second register word at +0x04 covers
//! IPs 32–47.
//!
//! Control bit-pair semantics (per AMD FCH PPR §3.x AOAC):
//!   `00` = D0 (active)
//!   `01` = D3hot request (clock-gate, keep power)
//!   `11` = D3cold request (full power-off)
//!
//! State bit-pair (AOAC_DEV_D3_STATE) is read-only and reflects the
//! actual hardware state.
//!
//! ## Platform detection
//!
//! The FCH MMIO base is architecturally fixed at `0xFED8_0000` for
//! all AMD FCH generations (Kabini, Renoir, Phoenix …).  The base is
//! identity-mapped at boot.  CPUID-gated helpers select the correct
//! IP-index table:
//!
//! - Renoir / Lucienne (Family 0x17, models 0x60–0xAF): 48-IP layout.
//! - Phoenix HawkPoint1 (Family 0x19, model 0x74): 48-IP layout,
//!   same offsets, additional NVMe2 / PCIe endpoint indices.
//!
//! Ref: AMD GPIO/FCH driver `gpio-amd-fch.c`
//!      (`AMD_FCH_MMIO_BASE 0xFED80000`); AMD FCH PPR for
//!      Renoir/Phoenix, §AOAC.

#![allow(dead_code)]

extern crate alloc;

use core::sync::atomic::{AtomicBool, Ordering};

use narf_arch::x86_64::cpuid::cpuid;

// ── FCH MMIO base ────────────────────────────────────────────────────

/// AMD FCH MMIO base, identity-mapped. Architecturally fixed.
/// Same address used by `gpio-amd-fch.c` (`AMD_FCH_MMIO_BASE`).
pub const FCH_MMIO_BASE: u64 = 0xFED8_0000;

// AOAC register offsets from FCH_MMIO_BASE.
// Each register covers 16 IPs (2 bits/IP × 16 = 32 bits).
// Register word 0 → IPs 0–15; word 1 → IPs 16–31; word 2 → IPs 32–47.

/// D-state control: write to request D0 / D3hot / D3cold.
const AOAC_DEV_D3_CTL_0: u64 = 0x9C; // IPs 0–15
const AOAC_DEV_D3_CTL_1: u64 = 0xA0; // IPs 16–31

/// D-state status: read to query current hardware state.
const AOAC_DEV_D3_STATE_0: u64 = 0xA4; // IPs 0–15
const AOAC_DEV_D3_STATE_1: u64 = 0xA8; // IPs 16–31

// ── D-state encoding ─────────────────────────────────────────────────

/// 2-bit D-state encoding in the AOAC control/status registers.
const D_STATE_D0: u8 = 0b00; // active
const D_STATE_D3HOT: u8 = 0b01; // clock-gated, powered
const D_STATE_D3COLD: u8 = 0b11; // fully power-gated

// ── IP enumeration ───────────────────────────────────────────────────

/// AOAC-controllable IP blocks.  Each variant maps to a hardware
/// index in the FCH D3 control register pair.
///
/// Indices follow AMD FCH PPR §AOAC IP Table (Renoir / Phoenix share
/// the same layout for indices 0–15; Phoenix adds additional NVMe/
/// PCIe entries above index 16).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AoacIp {
    /// USB XHCI controller 0 — index 0.
    UsbXhci0 = 0,
    /// USB XHCI controller 1 — index 1.
    UsbXhci1 = 1,
    /// USB OHCI controller (USB 1.1 companion) — index 2.
    UsbOhci = 2,
    /// SATA controller — index 3.
    Sata = 3,
    /// NVMe / PCIe storage controller — index 4.
    Nvme = 4,
    /// Integrated GPU (VGA / display engine) — index 5.
    GpuVga = 5,
    /// Audio Co-Processor (ACP) — index 6.
    Acp = 6,
    /// SDIO controller 0 — index 7.
    Sdio0 = 7,
    /// SDIO controller 1 — index 8.
    Sdio1 = 8,
    /// I2C bus 0 — index 9.
    I2c0 = 9,
    /// I2C bus 1 — index 10.
    I2c1 = 10,
    /// I2C bus 2 — index 11.
    I2c2 = 11,
    /// I2C bus 3 — index 12.
    I2c3 = 12,
    /// UART 0 — index 13.
    Uart0 = 13,
    /// UART 1 — index 14.
    Uart1 = 14,
    /// SPI controller — index 15.
    Spi = 15,
}

impl AoacIp {
    /// Hardware IP index (0–15 for the first control word, ≥16 for
    /// the second).  Used to compute the register address and the
    /// bit position within that register.
    #[inline]
    pub const fn index(self) -> u8 {
        self as u8
    }

    /// Offset of the D3-control register covering this IP.
    #[inline]
    pub const fn ctl_reg(self) -> u64 {
        if self.index() < 16 {
            AOAC_DEV_D3_CTL_0
        } else {
            AOAC_DEV_D3_CTL_1
        }
    }

    /// Offset of the D3-state register covering this IP.
    #[inline]
    pub const fn state_reg(self) -> u64 {
        if self.index() < 16 {
            AOAC_DEV_D3_STATE_0
        } else {
            AOAC_DEV_D3_STATE_1
        }
    }

    /// Bit position of the low bit of this IP's 2-bit field within
    /// its register word.  IPs 0–15 → bits 0,2,4,…30.  IPs 16–31
    /// wrap back to 0,2,4,…30 (within the second word).
    #[inline]
    pub const fn bit_pos(self) -> u8 {
        (self.index() % 16) * 2
    }
}

// ── Platform detection ───────────────────────────────────────────────

/// Detected SOC class, used to gate any per-generation quirks.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AmdSoc {
    /// Renoir / Lucienne: Family 0x17, models 0x60–0xAF.
    Renoir,
    /// Phoenix HawkPoint1: Family 0x19, model 0x74.
    Phoenix,
    /// Unrecognised — AOAC registers may still work (same layout);
    /// treated conservatively.
    Unknown,
}

/// Detect the running AMD SOC generation from CPUID.
///
/// AMD CPUID(1).EAX encodes family/model in the standard x86 manner
/// (`base_family=0xF` + `ext_family` for all modern AMD).
///
/// # Safety
/// Must be called at CPL 0 on x86-64.
pub fn detect_soc() -> AmdSoc {
    // Vendor check: CPUID(0) EBX:EDX:ECX = "AuthenticAMD".
    // SAFETY: leaf 0 always defined.
    let (_, ebx, ecx, edx) = unsafe { cpuid(0, 0) };
    let is_amd = ebx == 0x6874_7541 && edx == 0x6974_6E65 && ecx == 0x444D_4163;
    if !is_amd {
        return AmdSoc::Unknown;
    }

    // Decode family/model from CPUID(1).EAX.
    // SAFETY: leaf 1 always defined.
    let (sig, _, _, _) = unsafe { cpuid(1, 0) };
    let base_family = ((sig >> 8) & 0xF) as u16;
    let ext_family = ((sig >> 20) & 0xFF) as u16;
    let family = base_family + if base_family == 0xF { ext_family } else { 0 };
    let base_model = ((sig >> 4) & 0xF) as u16;
    let ext_model = ((sig >> 16) & 0xF) as u16;
    let model = base_model | (ext_model << 4);

    // Renoir: Family 0x17 (Zen2), models 0x60–0xAF.
    // Lucienne sits in the same range (0x68).
    if family == 0x17 && (0x60..=0xAF).contains(&model) {
        return AmdSoc::Renoir;
    }
    // Phoenix / HawkPoint1: Family 0x19 (Zen4), model 0x74.
    if family == 0x19 && model == 0x74 {
        return AmdSoc::Phoenix;
    }

    AmdSoc::Unknown
}

// ── D-state representation ───────────────────────────────────────────

/// Observable D-state of an AOAC IP block.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AoacState {
    /// IP is fully active (D0).
    D0,
    /// Clock-gated, power retained (D3hot).
    D3hot,
    /// Power-gated (D3cold).
    D3cold,
    /// Raw 2-bit encoding not matching a named state.
    Unknown(u8),
}

impl AoacState {
    fn from_bits(bits: u8) -> Self {
        match bits & 0b11 {
            0b00 => AoacState::D0,
            0b01 => AoacState::D3hot,
            0b11 => AoacState::D3cold,
            other => AoacState::Unknown(other),
        }
    }
}

// ── Error ────────────────────────────────────────────────────────────

/// Errors returned by AOAC operations.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AoacError {
    /// Platform is not an AMD SOC with a known FCH.
    UnsupportedPlatform,
}

// ── Core register access ─────────────────────────────────────────────

/// MMIO base actually used at runtime (allows unit tests to
/// redirect to a fake register block without a real FCH).
static MMIO_BASE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(FCH_MMIO_BASE);

/// Whether AOAC has been probed and is usable.
static AOAC_READY: AtomicBool = AtomicBool::new(false);

/// Read a 32-bit FCH MMIO register at `base + offset`.
///
/// # Safety
/// `base + offset` must be identity-mapped FCH MMIO.
#[inline]
unsafe fn mmio_read32(base: u64, offset: u64) -> u32 {
    // SAFETY: caller-asserted.
    unsafe { core::ptr::read_volatile((base + offset) as *const u32) }
}

/// Write a 32-bit FCH MMIO register.
///
/// # Safety
/// Same as `mmio_read32`.
#[inline]
unsafe fn mmio_write32(base: u64, offset: u64, val: u32) {
    // SAFETY: caller-asserted.
    unsafe { core::ptr::write_volatile((base + offset) as *mut u32, val) }
}

// ── Public API ───────────────────────────────────────────────────────

/// Probe the FCH AOAC registers and mark the subsystem ready.
///
/// Must be called once during platform initialisation, after the FCH
/// MMIO window is identity-mapped.  Safe to call on non-AMD silicon —
/// returns `Err(UnsupportedPlatform)` without touching any hardware.
pub fn init() -> Result<(), AoacError> {
    if detect_soc() == AmdSoc::Unknown {
        return Err(AoacError::UnsupportedPlatform);
    }
    AOAC_READY.store(true, Ordering::Release);
    Ok(())
}

/// Request a D-state transition for `ip`.
///
/// - `on = true`  → D0  (wake / activate the IP).
/// - `on = false` → D3hot (clock-gate).
///
/// D3cold is not exposed here; it requires additional sequencing
/// (power-plane isolation) deferred to a future PM layer.
pub fn aoac_set_d3(ip: AoacIp, on: bool) -> Result<(), AoacError> {
    if !AOAC_READY.load(Ordering::Acquire) {
        return Err(AoacError::UnsupportedPlatform);
    }
    let base = MMIO_BASE.load(Ordering::Acquire);
    let reg_off = ip.ctl_reg();
    let bit = ip.bit_pos();
    let mask: u32 = 0b11 << bit;
    let val: u32 = if on {
        (D_STATE_D0 as u32) << bit
    } else {
        (D_STATE_D3HOT as u32) << bit
    };

    // SAFETY: FCH MMIO, identity-mapped; read-modify-write.
    let current = unsafe { mmio_read32(base, reg_off) };
    let updated = (current & !mask) | val;
    // SAFETY: same.
    unsafe { mmio_write32(base, reg_off, updated) };
    Ok(())
}

/// Read the current hardware D-state for `ip`.
pub fn aoac_get_state(ip: AoacIp) -> AoacState {
    if !AOAC_READY.load(Ordering::Acquire) {
        return AoacState::Unknown(0xFF);
    }
    let base = MMIO_BASE.load(Ordering::Acquire);
    let reg_off = ip.state_reg();
    let bit = ip.bit_pos();
    // SAFETY: FCH MMIO, identity-mapped.
    let raw = unsafe { mmio_read32(base, reg_off) };
    let bits = ((raw >> bit) & 0b11) as u8;
    AoacState::from_bits(bits)
}

// ── Test helpers ─────────────────────────────────────────────────────

/// Redirect MMIO access to a fake register block for unit tests.
///
/// `fake_base` must be the address of an 8-byte buffer (covering the
/// two 4-byte register words).
#[doc(hidden)]
pub fn __test_redirect(fake_base: u64) {
    MMIO_BASE.store(fake_base, Ordering::Release);
    AOAC_READY.store(true, Ordering::Release);
}

/// Reset subsystem state for test isolation.
#[doc(hidden)]
pub fn __test_reset() {
    MMIO_BASE.store(FCH_MMIO_BASE, Ordering::Release);
    AOAC_READY.store(false, Ordering::Release);
}
