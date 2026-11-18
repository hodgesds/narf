// SPDX-License-Identifier: GPL-2.0-or-later
//! AE hw.c::_rtl8723e_enable_aspm_back_door, default aspm_support1.
//! The caller retains the original current NASR3 source and PCI function.
use super::{idle, read, Port};
use crate::rtlwifi::firmware_transport::Error;

pub(super) async fn prepare(io: &impl Port) -> Result<(), Error> {
    idle(io).await?;
    io.write8(0x34b, 0x93)?;
    io.write16(0x350, 0x870c)?;
    io.write8(0x352, 1)?;
    idle(io).await?;
    // Default const_support_pciaspm=1 sets support_backdoor=true in pci.c.
    // A disabled policy never enters this preparation or enables the link.
    io.write8(0x349, 0x1b)?;
    io.write16(0x350, 0x2718)?;
    io.write8(0x352, 1)?;
    idle(io).await?;
    // Byte enables8/2 target byte3 of0x70c and byte1 of0x718. These
    // observations prove internal programming, not link exit or DMA idle.
    if read(io, 0x70c).await? >> 24 != 0x93 || read(io, 0x718).await? & 0xff00 != 0x1b00 {
        return Err(Error::Gate);
    }
    Ok(())
}
