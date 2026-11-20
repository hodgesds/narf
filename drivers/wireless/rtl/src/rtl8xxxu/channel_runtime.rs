// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8188EU first-channel setup with MAC TX/RX closed.
//! Linux rtl8xxxu/8188e.c::rtl8188eu_config_channel (20MHz branch) and
//! 8188f.c::rtl8188f_set_crystal_cap. This is not regulatory TX authority.
use super::{
    calibration,
    device_init::Factory,
    firmware_transport::{ControlIo, Error, Owner},
};

/// Initial setup before a packet owner opens RX. Hot retune requires separate
/// MAC/FIFO/USB quiescence and must not reuse this routine on active traffic.
pub(super) async fn initial20<I: ControlIo>(
    o: &Owner<I>,
    f: Factory,
    channel: u8,
) -> Result<(), Error> {
    if !(1..=13).contains(&channel) {
        return Err(Error::BadEfuse);
    }
    if o.read16(0x100).await? & 0xc0 != 0 {
        return Err(Error::Calibration);
    }
    let bandwidth = o.read8(0x603).await?;
    o.write8(0x603, bandwidth | 4).await?;
    for register in [0x800, 0x900] {
        let value = o.read32(register).await?;
        o.write32(register, value & !1).await?;
    }
    let mode = calibration::read_rf(o, 0x18).await?;
    calibration::write_rf(o, 0x18, (mode & !0x3ff) | u32::from(channel)).await?;
    let mode = calibration::read_rf(o, 0x18).await?;
    calibration::write_rf(o, 0x18, (mode & !0xc00) | 0xc00).await?;
    // RTL8188E shares this crystal-cap setter with 8188F. Keep both XTAL
    // fields equal to the retained six-bit factory value, preserving others.
    let value = o.read32(0x24).await?;
    let cap = u32::from(f.crystal_cap & 0x3f);
    o.write32(0x24, (value & !0x7ff800) | cap << 17 | cap << 11)
        .await?;
    Ok(())
}
