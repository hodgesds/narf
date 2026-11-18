// SPDX-License-Identifier: GPL-2.0-only
// Copyright(c) 2009-2014 Realtek Corporation.
//! RTL8723BE/RTL8192DE internal link preparation. Endpoint/parent policy is
//! still owned by aspm_native; these commands never write the shared bridge.
//! Source: Linux 7.3-rc4 rtl8723be/hw.c SHA256 d607646ade82b909f3fb7f34a436a302b8e0f72a06e11c4d4710f3a6078fbf65;
//! rtl8192de/hw.c b216670f2624867215430a0088b485d868cd3d2597f8decd6c77a331af148e71.
//! wifi.h defines ASPM_L1_LATENCY=7. These hashes identify consulted source,
//! not hardware equivalence or acceptance.
use super::*;

async fn mdio_idle(io: &impl Port, bit: u8) -> Result<(), Error> {
    for attempt in 0..=20 {
        if io.read8(0x358)? & bit == 0 {
            return Ok(());
        }
        if attempt == 20 {
            break;
        }
        io.delay_us(10).await;
    }
    Err(Error::Deadline)
}
async fn mdio_read(io: &impl Port, address: u8) -> Result<u16, Error> {
    mdio_idle(io, 0x60).await?;
    io.write8(0x358, address | 0x40)?;
    mdio_idle(io, 0x40).await?;
    io.read16(0x356)
}
async fn mdio_write(io: &impl Port, address: u8, value: u16) -> Result<(), Error> {
    mdio_idle(io, 0x60).await?;
    io.write16(0x354, value)?;
    io.write8(0x358, address | 0x20)?;
    mdio_idle(io, 0x20).await
}
async fn dbi_read_byte(io: &impl Port, address: u16) -> Result<u8, Error> {
    idle(io).await?;
    io.write16(0x350, address & 0xfffc)?;
    io.write8(0x352, 2)?;
    idle(io).await?;
    io.read8(0x34c + address % 4)
}
async fn dbi_write_byte(io: &impl Port, address: u16, value: u8) -> Result<(), Error> {
    idle(io).await?;
    let lane = address % 4;
    io.write8(0x348 + lane, value)?;
    io.write16(0x350, (address & 0xfffc) | (1 << (lane + 12)))?;
    io.write8(0x352, 1)?;
    idle(io).await?;
    if dbi_read_byte(io, address).await? != value {
        return Err(Error::Gate);
    }
    Ok(())
}

/// rtl8723be/hw.c::_rtl8723be_enable_aspm_back_door. Exact MDIO words,
/// byte-enable DBI writes and ASPM_L1_LATENCY=7; no EE dword substitution.
pub(super) async fn prepare_be(io: &impl Port) -> Result<(), Error> {
    for (address, value) in [
        (1, 0x0663),
        (4, 0x7544),
        (6, 0xb880),
        (7, 0x4000),
        (8, 0x9003),
        (9, 0x0d03),
        (0xa, 0x4037),
        (0xb, 0x0070),
    ] {
        if mdio_read(io, address).await? != value {
            mdio_write(io, address, value).await?;
        }
        if mdio_read(io, address).await? != value {
            return Err(Error::Gate);
        }
    }
    let before = dbi_read_byte(io, 0x70f).await?;
    dbi_write_byte(io, 0x70f, before | 0x80 | (7 << 3)).await?;
    let before = dbi_read_byte(io, 0x719).await?;
    dbi_write_byte(io, 0x719, before | 0x18).await
}

/// rtl8192de/hw.c::_rtl92de_enable_aspm_back_door with actual support=1.
/// The old cold setup uses support=0. These exact lane writes replace that
/// closed setting only after current enabled parent/endpoint policy permits it.
pub(super) async fn prepare_de(io: &impl Port) -> Result<(), Error> {
    dbi_write_byte(io, 0x70f, 0x93).await?;
    dbi_write_byte(io, 0x719, 0x1b).await
}
