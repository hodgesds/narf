// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Restrictive A terminal closure from rtw8852a.c PMAC stop/TMAC helpers,
//! then mac.c `rtw89_mac_disable_bb_rf`. No reset, reclaim or RF-idle receipt.
use crate::rtw89::power::{Error, Io};
pub(in crate::rtw89) const RECIPE: &[u8] = b"A exact restrictive cancellation v1: source PMAC CTX/PTX=0, PMAC TX/RX grants/OPT/RXMOD=0, MAC_SEL DPD/MOD/PWR=0 when radio_started; mac.c rtw89_mac_disable_bb_rf SYS_FUNC_EN byte clear3 then WLRF_CTRL dword clear0x8282 then PHYREG_SET byte clear8; original current Bus only, reserved bits preserved, best effort/no stop-reset-reclaim receipt";

fn read(io: &mut impl Io, a: u32) -> Result<u32, Error> {
    let v = io.read32(a)?;
    if matches!(v, u32::MAX | 0xeaea_eaea | 0xdead_beef) {
        Err(Error::Gone)
    } else {
        Ok(v)
    }
}
fn clear(io: &mut impl Io, a: u32, mask: u32) -> Result<(), Error> {
    let old = read(io, a)?;
    io.write32(a, old & !mask)?;
    if read(io, a)? & mask != 0 {
        return Err(Error::Access);
    }
    Ok(())
}
fn clear8(io: &mut impl Io, a: u32, mask: u8) -> Result<(), Error> {
    let old = io.read8(a)?;
    if old == u8::MAX {
        // A valid byte can have every bit set while its containing register
        // is live. Confirm the full-word device sentinel before refusing the
        // restrictive clear; both observations use current original Bus I/O.
        read(io, a & !3)?;
    }
    io.write8(a, old & !mask)?;
    if io.read8(a)? & mask != 0 {
        return Err(Error::Access);
    }
    Ok(())
}
/// Each actual access remains within the original NativeIo Bus invoke.
/// Continue independent restrictive operations after failure; never report
/// successful stop/DMA retirement from this best-effort terminal helper.
pub(in crate::rtw89) fn close(io: &mut impl Io, engines_started: bool) -> Result<(), Error> {
    let mut first = None;
    let mut retain = |r: Result<(), Error>| {
        if let Err(e) = r {
            if first.is_none() {
                first = Some(e);
            }
        }
    };
    if engines_started {
        for (a, mask) in [
            (0x109c4, 1),
            (0x109c4, 0x10),
            (0x10980, 1),
            (0x10980, 0x10000),
            (0x10988, 0xfff),
            (0x10994, 0xf0),
            (0x109a4, 0x400),
            (0x109a4, 0x1c),
            (0x109a4, 0x10000),
        ] {
            retain(clear(io, a, mask));
        }
    }
    // Exact A callback order; B's AFC_AFEDIG-first clock recipe differs.
    retain(clear8(io, 0x2, 3));
    retain(clear(io, 0x2f0, 0x8282));
    retain(clear8(io, 0x8040, 8));
    first.map_or(Ok(()), Err)
}
