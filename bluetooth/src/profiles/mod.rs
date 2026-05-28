//! Bluetooth audio profiles: A2DP (source + sink) and HFP.
//!
//! ## Module layout
//!
//! - [`avdtp`] — AVDTP signalling-session state machine (sits above
//!   the packet-level codec in [`crate::avdtp`]).
//! - [`a2dp`]  — A2DP source/sink roles: SEP table, SBC capability
//!   negotiation, stream-start state machine.
//! - [`hfp`]   — HFP service-level connection (SLC) machine, SCO
//!   parameter selection, AT command classifier.
//!
//! ## Spec references
//!
//! - Audio/Video Distribution Transport Protocol Specification 1.3 —
//!   Bluetooth SIG. Signalling procedures and message formats.
//! - Advanced Audio Distribution Profile 1.4 — Bluetooth SIG.
//!   SBC codec capability table, source/sink roles.
//! - Hands-Free Profile 1.8 — Bluetooth SIG. SLC procedure, SCO
//!   setup, AT commands, CVSD/mSBC codec selection.

pub mod a2dp;
pub mod avdtp;
pub mod hfp;
