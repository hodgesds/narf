// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Nonemitting AX monitor-vif configuration. Source Linux7.3-rc4
//! mac_vif_init/configure_filter/physts_parsing_init; no RF/channel writes.
use super::*;
use crate::rtw89::monitor_wire as wire;
fn quiet(io: &mut impl Interface) -> Result<(), Error> {
    awake(io)?;
    if read(io, 0xc000)? & wire::CMAC_TX != 0 {
        return Err(Error::Access);
    }
    Ok(())
}
pub(in crate::rtw89) async fn initialize(
    io: &mut impl Interface,
    own: [u8; 6],
    secure: bool,
    admission: &Admission,
) -> Result<(), Error> {
    checked(io, Some(admission), |io| {
        io.preflight(!secure)?;
        quiet(io)?; // precedes EVERY role/filter/PHYSTS change
        let port = wire::port(read(io, 0xc400)?).ok_or(Error::Access)?;
        modify(io, 0xc400, u32::MAX, port)?;
        crypto_off(io)?;
        if !secure {
            tables(io)?;
        }
        Ok(())
    })?;
    // Monitor is an actual distinct firmware role, never a station peer.
    command(io, 9, 8, &codec::pause(false), false, Some(admission)).await?;
    pause_applied(io, false, Some(admission)).await?;
    command(io, 8, 4, &wire::role(false), true, Some(admission)).await?;
    command(io, 8, 0, &wire::join(), true, Some(admission)).await?;
    command(
        io,
        6,
        0,
        &codec::cam(own, [0; 6], 0, false, true),
        true,
        Some(admission),
    )
    .await?;
    command(io, 5, 2, &codec::default_cctl(), true, Some(admission)).await?;
    checked(io, Some(admission), |io| {
        quiet(io)?;
        let filter = wire::receive_filter(read(io, wire::RX_FILTER)?).ok_or(Error::Access)?;
        modify(io, wire::RX_FILTER, u32::MAX, filter)?;
        for address in wire::FORWARD {
            modify(io, address, u32::MAX, wire::TO_HOST)?;
        }
        // Same source disabled failed/broken PHYSTS reports, then actual AX
        // bitmap page addresses (reserved9 occupies no register).
        modify(io, 0x10738, 0xc, 0xc)?;
        for page in 0u8..16 {
            if page == 9 {
                continue;
            }
            let address = 0x1073c + u32::from(if page > 9 { page - 1 } else { page }) * 4;
            let value = wire::physts(page, read(io, address)?).ok_or(Error::Access)?;
            modify(io, address, u32::MAX, value)?;
        }
        quiet(io)
    })
}
