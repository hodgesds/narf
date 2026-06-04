//! USB Type-C mux abstraction — orientation + SuperSpeed routing +
//! DP routing.
//!
//! The "Type-C mux" is a switch on the motherboard / SoC that routes
//! the USB-C connector's differential pairs to the correct on-die IP
//! block depending on what is plugged in:
//!
//! | Mode         | SS lanes  | DP lanes |
//! |--------------|-----------|----------|
//! | USB only     | USB3 ×2   | 0        |
//! | DP Pin C/E   | 0         | DP ×4    |
//! | DP Pin D/F   | USB3 ×2   | DP ×2    |
//! | Thunderbolt  | TBT       | TBT      |
//!
//! Orientation (Normal / Reversed) determines which physical pair is
//! TX and which is RX; the mux must invert the lane assignment for a
//! Reversed plug.
//!
//! Linux ref:
//! - `drivers/usb/typec/mux.c` + `include/linux/usb/typec_mux.h`
//! - `drivers/usb/typec/mux/` (Intel PMC mux, GPIO mux, …)
//!
//! NARF boards implement the `TypecMux` trait.  The abstract
//! `MuxSetting` encodes everything the hardware mux needs to know;
//! vendor drivers translate it to register writes.

use super::altmode::DpPinAssign;
use super::Orientation;

// ── MuxSetting ─────────────────────────────────────────────────────

/// SuperSpeed lane routing.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SsRouting {
    /// USB 3.x SuperSpeed (both pairs to USB host/device).
    Usb3,
    /// 4 DP lanes — all SS lanes re-purposed for DisplayPort.
    Dp4Lane,
    /// 2 DP + 2 USB SS lanes.
    Dp2Lane,
    /// Thunderbolt 3/4 — both pairs to TBT controller.
    Thunderbolt,
    /// Disconnected / undefined.
    None,
}

/// The complete mux configuration to program.
///
/// Linux analogue: `struct typec_mux_state` (`typec_mux.h`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MuxSetting {
    /// Cable plug orientation.
    pub orientation: Orientation,
    /// How the SuperSpeed pairs are routed.
    pub ss: SsRouting,
}

impl MuxSetting {
    /// USB-only setting for the given orientation (both SS pairs to
    /// USB3).
    pub fn from_orientation(orient: Orientation) -> Self {
        Self {
            orientation: orient,
            ss: SsRouting::Usb3,
        }
    }

    /// DP Alt Mode setting.  Derives `SsRouting` from the pin
    /// assignment (even pins keep SS; odd pins give all 4 lanes to
    /// DP).
    pub fn dp(orient: Orientation, pin: DpPinAssign) -> Self {
        use super::altmode::dp_lane_count;
        let ss = if dp_lane_count(pin) == 4 {
            SsRouting::Dp4Lane
        } else {
            SsRouting::Dp2Lane
        };
        Self {
            orientation: orient,
            ss,
        }
    }

    /// Thunderbolt Alt Mode setting.
    pub fn thunderbolt(orient: Orientation) -> Self {
        Self {
            orientation: orient,
            ss: SsRouting::Thunderbolt,
        }
    }

    /// Disconnected state.
    pub fn none() -> Self {
        Self {
            orientation: Orientation::Unknown,
            ss: SsRouting::None,
        }
    }
}

// ── TypecMux trait ─────────────────────────────────────────────────

/// Platform-specific Type-C mux.
///
/// Board code registers an implementation during init.  The Type-C
/// connector class calls `configure()` when orientation or Alt Mode
/// changes.
///
/// Linux analogue: `struct typec_mux_dev` / `typec_mux_ops.set()`
/// (`drivers/usb/typec/mux.c`).
pub trait TypecMux: Send + Sync + core::fmt::Debug {
    /// Apply `setting` to the hardware mux.
    fn configure(&self, setting: MuxSetting);
}

// ── NullMux (stub for tests / systems without a mux) ──────────────

/// A no-op mux for systems that don't have a software-configurable
/// mux (e.g., fixed-function single-port laptops, QEMU, or bare-
/// metal bring-up before the real driver lands).
#[derive(Debug)]
pub struct NullMux;

impl TypecMux for NullMux {
    fn configure(&self, _setting: MuxSetting) {
        // intentionally empty
    }
}
