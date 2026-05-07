//! narf-pinctrl — pin-mux / GPIO / PMIC codecs (clean-room).
//!
//! ## Sources (public only)
//!
//! - **MIPI Alliance Specification for System Power Management
//!   Interface (SPMI)**, Version 2.0. Public summary + opcode
//!   tables at <https://www.mipi.org/specifications/spmi>.
//! - **Synopsys DesignWare APB GPIO** databook excerpts (public —
//!   datasheet-grade documentation common to many ARM SoCs that
//!   license the IP). Register names + bit layout used by
//!   [`dwapb`].
//! - **Qualcomm PMIC peripheral register reference** — common
//!   peripheral-type IDs (GPIO 0x10, MPP 0x11, LDO/SMPS regulators
//!   0x06/0x05, RTC 0x6000, ...). Public via Qualcomm linux-msm
//!   kernel-driver headers; these constants are the device-side
//!   reality, not Linux's interpretation of them.
//!
//! No GPL / Linux source consulted.
//!
//! ## What this crate is
//!
//! Three transport-neutral codec modules:
//!
//! - [`pinmux`] — pin-function / drive-strength / pull-up-down
//!   encoding shared by every ARM SoC's pin-mux register block.
//!   Produces / consumes the 32-bit "config" word that controllers
//!   like Qualcomm TLMM, MediaTek pinmux, Rockchip GRF expose.
//! - [`spmi`] — MIPI SPMI 2.0 master-to-slave command codec used
//!   by Qualcomm PMICs and similar power-management ICs. Builds
//!   the 8-bit-or-larger command word, decodes responses.
//! - [`dwapb`] — DesignWare APB GPIO register layout. Read /
//!   write helpers for the per-bank Data, Direction, Interrupt
//!   Enable / Mask / Type / Polarity registers.
//! - [`qcom_pmic`] — Qualcomm PMIC peripheral GPIO type registers
//!   (mode select, drive control, output value).

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

pub mod dwapb;
pub mod pinmux;
pub mod qcom_pmic;
pub mod spmi;

mod tests;
