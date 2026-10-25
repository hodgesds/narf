// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Source B terminal emission closure. These finite MMIO operations can run
//! from Drop, even after calibration permission is revoked. Device authority
//! is still required. They neither finish XTAL shutdown nor prove RF/DMA idle.
use super::power::{Error, Io};
#[path = "radio_stop/regs.rs"]
mod regs;
use regs::*;
fn read(io: &mut impl Io, a: u32) -> Result<u32, Error> {
    let v = io.read32(a)?;
    if matches!(v, u32::MAX | 0xeaeaeaea | 0xdeadbeef) {
        Err(Error::Gone)
    } else {
        Ok(v)
    }
}
fn masked(io: &mut impl Io, a: u32, m: u32, v: u32) -> Result<(), Error> {
    let old = read(io, a)?;
    io.write32(a, (old & !m) | (v & m))
}
fn first(result: Result<(), Error>, error: &mut Option<Error>) {
    if let Err(e) = result {
        if error.is_none() {
            *error = Some(e);
        }
    }
}
/// Stop both source PMAC modes and return manual PMAC routing to TMAC,
/// then close RFCTM/NCTL controls from the source one-shot/restore callbacks.
/// Continue independent closing writes after a failure, but report no receipt.
pub(super) fn engines(io: &mut impl Io) -> Result<(), Error> {
    let fields = [
        (R_PMAC_TX_PRD, B_PMAC_CTX_EN, 0),
        (R_PMAC_TX_PRD, B_PMAC_PTX_EN, 0),
        (R_PMAC_GNT, B_PMAC_GNT_TXEN, 0),
        (R_PMAC_GNT, B_PMAC_GNT_RXEN, 0),
        (R_PMAC_RX_CFG1, B_PMAC_OPT1_MSK, 0),
        (R_PMAC_RXMOD, B_PMAC_RXMOD_MSK, 0),
        (R_MAC_SEL, B_MAC_SEL_DPD_EN, 0),
        (R_MAC_SEL, B_MAC_SEL_MOD, 0),
        (R_MAC_SEL, B_MAC_SEL_PWR_EN, 0),
        (R_P0_RFCTM, B_P0_RFCTM_EN, 0),
        (R_NCTL_N1, B_NCTL_N1_CIP, 0),
        (R_NCTL_RPT, u32::MAX, 0),
        (R_KIP_SYSCFG, u32::MAX, 0x80000000),
    ];
    let mut error = None;
    for (a, m, v) in fields {
        first(masked(io, 0x10000 + a, m, v), &mut error);
    }
    for (a, m, v) in fields {
        let check = read(io, 0x10000 + a).and_then(|actual| {
            if actual & m == v {
                Ok(())
            } else {
                Err(Error::Access)
            }
        });
        first(check, &mut error);
    }
    error.map_or(Ok(()), Err)
}
/// Exact first two operations of B mac_disable_bb_rf, with real readback.
/// Analog RF00S/RF10S XTAL shutdown remains a distinct asynchronous step.
pub(super) fn clocks(io: &mut impl Io) -> Result<(), Error> {
    let mut error = None;
    first(masked(io, R_AX_WLRF_CTRL, B_AX_AFC_AFEDIG, 0), &mut error);
    let reset = io.read8(R_AX_SYS_FUNC_EN).and_then(|v| {
        io.write8(
            R_AX_SYS_FUNC_EN,
            v & !((B_AX_FEN_BBRSTB | B_AX_FEN_BB_GLB_RSTN) as u8),
        )
    });
    first(reset, &mut error);
    let clock = read(io, R_AX_WLRF_CTRL).and_then(|v| {
        if v & B_AX_AFC_AFEDIG == 0 {
            Ok(())
        } else {
            Err(Error::Access)
        }
    });
    first(clock, &mut error);
    let reset = io.read8(R_AX_SYS_FUNC_EN).and_then(|v| {
        if u32::from(v) & (B_AX_FEN_BBRSTB | B_AX_FEN_BB_GLB_RSTN) == 0 {
            Ok(())
        } else {
            Err(Error::Access)
        }
    });
    first(reset, &mut error);
    error.map_or(Ok(()), Err)
}
#[cfg(any(test, feature = "kernel-test"))]
#[path = "radio_stop/tests.rs"]
mod tests;
