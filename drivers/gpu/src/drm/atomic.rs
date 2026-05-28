//! Atomic mode-setting state machine.
//!
//! Stub — implemented in a follow-up commit.

use alloc::vec::Vec;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AtomicError {
    OverBandwidth,
    UnknownCrtc,
    UnknownConnector,
    UnknownPlane,
    InvalidMode,
    PlaneNotInRange,
    ZeroBandwidthBudget,
    NoCheck,
}

#[derive(Clone, Debug, Default)]
pub struct ConnectorState { pub id: u32, pub crtc_id: Option<u32> }
#[derive(Clone, Debug, Default)]
pub struct CrtcState { pub id: u32, pub enable: bool, pub mode: Option<crate::Mode>, pub active: bool }
#[derive(Clone, Debug, Default)]
pub struct PlaneState { pub id: u32, pub crtc_id: Option<u32>, pub fb_id: Option<u32>, pub crtc_x: i32, pub crtc_y: i32, pub crtc_w: u32, pub crtc_h: u32 }
#[derive(Clone, Debug, Default)]
pub struct AtomicState { pub connectors: Vec<ConnectorState>, pub crtcs: Vec<CrtcState>, pub planes: Vec<PlaneState>, pub allow_modeset: bool, pub checked: bool }
