// SPDX-License-Identifier: GPL-2.0-or-later
//! Device-wide firmware `event_msgs` mask composed from per-owner needs.
//!
//! The firmware keeps one event mask for the whole device. Linux registers
//! handlers per event code in `fweh` (`brcmf_fweh_register`) and
//! `brcmf_fweh_activate_events` (`fweh.c`) writes the union of every
//! registered handler plus `BRCMF_E_IF`; no role writes a private mask.
//! NARF's role owners each declare the events they consume (the primary
//! role, the secondary-interface registry, each live secondary bsscfg),
//! and every `event_msgs` writer sends the union, so no writer clears
//! another owner's bits.
use super::vif_wire::MAX_IFS;

/// `BRCMF_EVENTING_MASK_LEN` as the native owners write it (16 bytes).
pub const LEN: usize = 16;
pub type Mask = [u8; LEN];

/// The owner whose event needs a writer updates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Need {
    /// The interface-0 role (station, AP or monitor). Through a
    /// `vif_bsscfg::Bsscfg` view this names that bsscfg's own owner.
    Primary,
    /// The secondary-interface registry (`BRCMF_E_IF` while listening).
    Interfaces,
    /// The role owner of secondary firmware interface `ifidx`.
    Secondary(u8),
}

/// Mask with each listed event code set.
pub fn mask(events: &[usize]) -> Mask {
    let mut out = [0; LEN];
    for &event in events {
        if event < LEN * 8 {
            out[event / 8] |= 1 << (event % 8);
        }
    }
    out
}

/// Per-owner needs and the mask last written to the firmware.
#[derive(Clone, Debug)]
pub struct Composition {
    primary: Mask,
    interfaces: Mask,
    secondary: [Mask; MAX_IFS as usize],
    written: Option<Mask>,
}

impl Default for Composition {
    fn default() -> Self {
        Self::new()
    }
}

impl Composition {
    pub const fn new() -> Self {
        Self {
            primary: [0; LEN],
            interfaces: [0; LEN],
            secondary: [[0; LEN]; MAX_IFS as usize],
            written: None,
        }
    }

    /// Record `need`'s events and return the union to write. A secondary
    /// ifidx out of range (0 or >= `MAX_IFS`) records nothing.
    pub fn compose(&mut self, need: Need, events: Mask) -> Mask {
        match need {
            Need::Primary => self.primary = events,
            Need::Interfaces => self.interfaces = events,
            Need::Secondary(ifidx) if ifidx != 0 && ifidx < MAX_IFS => {
                self.secondary[ifidx as usize] = events
            }
            Need::Secondary(_) => {}
        }
        self.union()
    }

    pub fn union(&self) -> Mask {
        let mut out = self.primary;
        for other in core::iter::once(&self.interfaces).chain(self.secondary.iter()) {
            for (byte, bits) in out.iter_mut().zip(other) {
                *byte |= bits;
            }
        }
        out
    }

    /// A successful `event_msgs` SET carried `mask`.
    pub fn written(&mut self, mask: Mask) {
        self.written = Some(mask);
    }

    /// The mask last known written, if any.
    pub fn current(&self) -> Option<Mask> {
        self.written
    }
}
