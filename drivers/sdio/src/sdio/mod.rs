// SPDX-License-Identifier: GPL-2.0-or-later
//! SDIO protocol layer.
//!
//! - [`cccr`]    — CCCR / FBR register layout and CIS tuple decode.
//! - [`function`] — `SdioFunction` trait and CMD52/CMD53 argument encoders.

pub mod cccr;
pub mod function;
