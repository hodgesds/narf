//! Hot-plug detect (HPD) — IRQ → connector status transitions.
//!
//! ## Reference
//!
//! - **`/home/daniel/git/linux/drivers/gpu/drm/nouveau/nvkm/subdev/gpio/base.c`**
//!   — generic GPIO + HPD line tracking. Each HPD line on the
//!   GPU's GPIO mux fires an interrupt when its state changes.
//! - **`drivers/gpu/drm/nouveau/dispnv50/disp.c::nv50_disp_intr_*`**
//!   — Maxwell+ display IRQ top-half + hotplug dispatch.
//! - **`drivers/gpu/drm/nouveau/nouveau_connector.c::nouveau_connector_detect`**
//!   — the bottom-half that re-probes EDID after an HPD signal.
//!
//! ## State machine
//!
//! HPD on DP / HDMI is a noisy line — physical insertion bounces
//! several times before settling. We debounce in software: a
//! `Disconnect → Connect` transition arms a 100 ms timer; a
//! second event inside the window resets the timer; only after
//! the timer expires with the line still asserted do we tell KMS
//! the connector is alive.

#![allow(dead_code)]

/// HPD source index (which GPIO pin is firing). DCB connectors
/// reference HPD lines by index 0..7. Cite
/// `dcb_gpio_parse` / `nvkm/subdev/gpio/base.c`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HpdSource(pub u8);

/// Event reported by the GPU's HPD IRQ handler.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HpdEvent {
    /// Falling edge: cable removed (or DP short-pulse with cable
    /// gone — distinguished elsewhere).
    Disconnect,
    /// Rising edge: cable inserted.
    Connect,
    /// "Short pulse" — DP / HDMI signal-level event that doesn't
    /// indicate plug/unplug but does indicate something changed
    /// (loss of sync, MST topology refresh, sink CRC mismatch).
    /// The bottom-half re-reads DPCD link status to figure out
    /// what to do.
    ShortPulse,
}

/// HPD bottom-half outcome — what the KMS layer should do.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HpdOutcome {
    /// No change; ignore.
    Stable,
    /// Connector became live; KMS should probe EDID + run DP link
    /// training + flag connector_status_connected.
    BecameConnected,
    /// Connector went away; KMS should tear down framebuffers
    /// bound to it and flag connector_status_disconnected.
    BecameDisconnected,
    /// Short pulse needs handling but the connector status is
    /// unchanged. Caller re-reads DPCD link status.
    ShortPulse,
}

/// Per-connector debouncer.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HpdDebouncer {
    pub source: HpdSource,
    pub state: HpdState,
    /// TSC / monotonic-tick at which the debounce window started.
    pub timer_start: u64,
    /// Debounce window in ticks. 100 ms × tick rate; the caller
    /// supplies the value so this stays a pure module.
    pub debounce_ticks: u64,
}

/// Internal state of a debouncing connector.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HpdState {
    /// No cable known.
    Idle,
    /// Saw `Connect` at `timer_start`; waiting for the line to
    /// settle.
    Debouncing,
    /// Cable settled and KMS knows.
    Connected,
}

impl HpdDebouncer {
    pub const fn new(source: HpdSource, debounce_ticks: u64) -> Self {
        Self {
            source,
            state: HpdState::Idle,
            timer_start: 0,
            debounce_ticks,
        }
    }

    /// Process a fresh HPD event reported by the IRQ handler.
    /// `now_ticks` is the current monotonic tick reading.
    pub fn handle(&mut self, ev: HpdEvent, now_ticks: u64) -> HpdOutcome {
        match (self.state, ev) {
            (HpdState::Idle, HpdEvent::Connect) => {
                self.state = HpdState::Debouncing;
                self.timer_start = now_ticks;
                HpdOutcome::Stable
            }
            (HpdState::Debouncing, HpdEvent::Disconnect) => {
                // Bounce off; go back to idle.
                self.state = HpdState::Idle;
                HpdOutcome::Stable
            }
            (HpdState::Debouncing, HpdEvent::Connect) => {
                // Restart the debounce window — line settled,
                // then bounced again.
                self.timer_start = now_ticks;
                HpdOutcome::Stable
            }
            (HpdState::Connected, HpdEvent::Disconnect) => {
                self.state = HpdState::Idle;
                self.timer_start = 0;
                HpdOutcome::BecameDisconnected
            }
            (HpdState::Connected, HpdEvent::ShortPulse) => HpdOutcome::ShortPulse,
            _ => HpdOutcome::Stable,
        }
    }

    /// Periodic tick — call this from the connector poll task.
    /// Returns `BecameConnected` once the debounce window
    /// expires with the line still asserted.
    pub fn poll(&mut self, now_ticks: u64) -> HpdOutcome {
        if let HpdState::Debouncing = self.state {
            let elapsed = now_ticks.wrapping_sub(self.timer_start);
            if elapsed >= self.debounce_ticks {
                self.state = HpdState::Connected;
                return HpdOutcome::BecameConnected;
            }
        }
        HpdOutcome::Stable
    }
}
