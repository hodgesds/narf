//! RTL8188EU factory/FIFO/MAC/BB/RF initialization through the retained EP0
//! owner. Linux rtl8xxxu/{core.c,8188e.c,8188f.c}; no bulk or station claim.
//!
//! Any transport error terminates the enclosing one-shot owner. These
//! functions never attempt cleanup I/O after an ambiguous transfer failure.
use super::firmware_transport::{ControlIo, Error, Owner};
use super::phy_tables::{AGC_REGS_8188E, BB_REGS_8188E, MAC_REGS_8188E, RF_A_REGS_8188E};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Factory {
    pub cut: u8,
    pub mac: [u8; 6],
    pub cck_power: [u8; 6],
    pub ht40_power: [u8; 5],
    pub crystal_cap: u8,
    pub channel_plan: u8,
    pub thermal: u8,
    pub board_option: u8,
}

/// Endpoint geometry comes from descriptors, never from the chip's name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Endpoints {
    pub input: u8,
    pub output: [u8; 3],
    pub output_count: u8,
    pub input_packet: u16,
    pub output_packets: [u16; 3],
}

pub fn endpoints(config: &[u8]) -> Result<Endpoints, Error> {
    if config.len() < 9 || config[0] != 9 || config[1] != 2 {
        return Err(Error::BadEndpoints);
    }
    let total = u16::from_le_bytes([config[2], config[3]]) as usize;
    if total != config.len() {
        return Err(Error::BadEndpoints);
    }
    let mut plan = Endpoints {
        input: 0,
        output: [0; 3],
        output_count: 0,
        input_packet: 0,
        output_packets: [0; 3],
    };
    let mut offset = 9;
    let mut claimed = false;
    let mut selected = false;
    let mut advertised = 0;
    let mut count = 0;
    while offset < total {
        let length = *config.get(offset).ok_or(Error::BadEndpoints)? as usize;
        if length < 2 || offset + length > total {
            return Err(Error::BadEndpoints);
        }
        let d = &config[offset..offset + length];
        match d[1] {
            4 => {
                if d.len() < 9 {
                    return Err(Error::BadEndpoints);
                }
                if selected && count != advertised {
                    return Err(Error::BadEndpoints);
                }
                // The first vendor interface's active default alternate.
                selected = !claimed && d[3] == 0 && d[5] == 0xff;
                if selected {
                    claimed = true;
                    advertised = d[4];
                    count = 0;
                }
            }
            5 if selected => {
                if d.len() < 7 {
                    return Err(Error::BadEndpoints);
                }
                count += 1;
                let addr = d[2];
                if addr & 0x70 != 0 || addr & 15 == 0 {
                    return Err(Error::BadEndpoints);
                }
                if d[3] & 3 == 2 {
                    let packet = u16::from_le_bytes([d[4], d[5]]);
                    if packet == 0 || packet > 512 {
                        return Err(Error::BadEndpoints);
                    }
                    if addr & 0x80 != 0 {
                        if plan.input != 0 {
                            return Err(Error::BadEndpoints);
                        }
                        plan.input = addr;
                        plan.input_packet = packet;
                    } else {
                        let slot = plan.output_count as usize;
                        if slot == 3 || plan.output[..slot].contains(&addr) {
                            return Err(Error::BadEndpoints);
                        }
                        plan.output[slot] = addr;
                        plan.output_packets[slot] = packet;
                        plan.output_count += 1;
                    }
                }
            }
            _ => (),
        }
        offset += length;
    }
    if (selected && count != advertised) || plan.input == 0 || plan.output_count == 0 {
        return Err(Error::BadEndpoints);
    }
    Ok(plan)
}

pub fn parse_factory(cut: u8, map: &[u8; 512]) -> Result<Factory, Error> {
    if map[..2] != [0x29, 0x81] {
        return Err(Error::BadEfuse);
    }
    let mac: [u8; 6] = map[0xd7..0xdd].try_into().unwrap();
    if mac == [0; 6] || mac[0] & 1 != 0 {
        return Err(Error::BadEfuse);
    }
    Ok(Factory {
        cut,
        mac,
        cck_power: map[0x10..0x16].try_into().unwrap(),
        ht40_power: map[0x16..0x1b].try_into().unwrap(),
        crystal_cap: map[0xb9] & 0x3f,
        channel_plan: map[0xb8],
        thermal: map[0xba],
        board_option: map[0xc1],
    })
}

pub(super) async fn factory<I: ControlIo>(owner: &Owner<I>) -> Result<Factory, Error> {
    let cfg = owner.read32(0xf0).await?;
    let cut = ((cfg >> 12) & 15) as u8;
    // Linux rejects test silicon and I cut before profile-specific writes.
    if cfg == u32::MAX || cfg & (1 << 23) != 0 || cut == 8 {
        return Err(Error::UnsupportedSilicon);
    }
    owner.write8(0xcf, 0x69).await?;
    let value = owner.read16(0).await?;
    owner.write16(0, value | 1 << 15).await?;
    let value = owner.read16(2).await?;
    owner.write16(2, value | 1 << 12).await?;
    let value = owner.read16(8).await?;
    owner.write16(8, value | (1 << 5) | (1 << 1)).await?;
    let mut physical = [0xff; 512];
    for (address, byte) in physical.iter_mut().enumerate() {
        owner.write8(0x31, address as u8).await?;
        let value = owner.read8(0x32).await?;
        owner
            .write8(0x32, (value & 0xfc) | ((address >> 8) as u8 & 3))
            .await?;
        let value = owner.read8(0x33).await?;
        owner.write8(0x33, value & 0x7f).await?;
        let mut ready = false;
        for _ in 0..500 {
            if owner.read32(0x30).await? & (1 << 31) != 0 {
                ready = true;
                break;
            }
        }
        if !ready {
            return Err(Error::EfuseTimeout);
        }
        owner.delay_us(50).await;
        *byte = owner.read32(0x30).await? as u8;
    }
    // Every prior transfer completed; closing the read gate is safe here.
    owner.write8(0xcf, 0).await?;
    let mut map = [0xff; 512];
    crate::rtw88::efuse::decode_map(&physical, &mut map).map_err(|_| Error::BadEfuse)?;
    parse_factory(cut, &map)
}

/// Configure queues and RX FIFO boundary before firmware/MAC activation.
/// The initial profile stays cold after reset, as a future runtime reset
/// owner will handle inherited MAC/FIFO state explicitly.
pub(super) async fn pre_firmware<I: ControlIo>(
    owner: &Owner<I>,
    eps: Endpoints,
) -> Result<(), Error> {
    let count = eps.output_count;
    if !(1..=3).contains(&count) {
        return Err(Error::BadEndpoints);
    }
    let hi = 0x29u32;
    let normal = if count >= 2 { 0x1c } else { 0 };
    let low = if count >= 3 { 0x1c } else { 0 };
    let public = 0xa9 - hi - normal - low - 1;
    owner.write32(0x214, normal).await?;
    owner
        .write32(0x200, 1 << 31 | public << 16 | low << 8 | hi)
        .await?;
    let low_queue = if count == 3 {
        1
    } else if count == 2 {
        2
    } else {
        3
    };
    let vi = if count == 3 { 2 } else { 3 };
    let value = owner.read16(0x10c).await?;
    owner
        .write16(
            0x10c,
            value & 7 | 3 << 4 | vi << 6 | low_queue << 8 | low_queue << 10 | 3 << 12 | 3 << 14,
        )
        .await?;
    owner.write16(0x116, 0x25ff).await
}

async fn llt<I: ControlIo>(owner: &Owner<I>, address: u8, next: u8) -> Result<(), Error> {
    owner
        .write32(0x1e0, 1 << 30 | (address as u32) << 8 | next as u32)
        .await?;
    for _ in 0..21 {
        if owner.read32(0x1e0).await? & (3 << 30) == 0 {
            return Ok(());
        }
    }
    Err(Error::LltTimeout)
}

pub(super) async fn mac_bb_rf<I: ControlIo>(
    owner: &Owner<I>,
    factory: Factory,
) -> Result<(), Error> {
    for row in MAC_REGS_8188E {
        if row.is_sentinel() {
            break;
        }
        owner.write8(row.reg, row.val).await?;
    }
    owner.write16(0x4ca, 0x0707).await?;
    let value = owner.read16(2).await?;
    owner.write16(2, value | 3 | (1 << 13)).await?;
    owner.write8(0x1f, 7).await?;
    owner.write8(2, 0x17).await?; // BB resets plus USBA/USBD.
    for table in [BB_REGS_8188E, AGC_REGS_8188E] {
        for row in table {
            if row.reg == 0xffff && row.val == u32::MAX {
                break;
            }
            owner.write32(row.reg, row.val).await?;
            owner.delay_us(1).await;
        }
    }
    let value = owner.read32(0x24).await?;
    let cap = factory.crystal_cap as u32;
    owner
        .write32(0x24, (value & !0x007ff800) | ((cap | cap << 6) << 11))
        .await?;
    let env = owner.read16(0x870).await? & (1 << 4);
    let value = owner.read32(0x860).await?;
    owner.write32(0x860, value | 1 << 20).await?;
    owner.delay_us(1).await;
    let value = owner.read32(0x860).await?;
    owner.write32(0x860, value | 1 << 4).await?;
    owner.delay_us(1).await;
    let value = owner.read32(0x824).await?;
    owner.write32(0x824, value & !0x400).await?;
    owner.delay_us(1).await;
    let value = owner.read32(0x824).await?;
    owner.write32(0x824, value & !0x800).await?;
    owner.delay_us(1).await;
    for row in RF_A_REGS_8188E {
        if row.is_sentinel() {
            break;
        }
        let delay = match row.reg {
            0xfe => 50_000,
            0xfd => 5_000,
            0xfc => 1_000,
            0xfb => 50,
            0xfa => 5,
            0xf9 => 1,
            _ => 0,
        };
        if delay != 0 {
            owner.delay_us(delay).await;
            continue;
        }
        // The RF address is eight bits: real 8188EU tables include 0x57,
        // 0x58, 0xef, etc. Truncating to five bits aliases different RF regs.
        owner
            .write32(0x840, (row.reg as u32) << 20 | row.val & 0xfffff)
            .await?;
        owner.delay_us(1).await;
    }
    let value = owner.read16(0x870).await?;
    owner.write16(0x870, value & !(1 << 4) | env).await?;
    // TX boundary/LLT are installed before any MAC TX/RX enable.
    for address in [0x424, 0x425, 0x45d, 0x114, 0x209] {
        owner.write8(address, 0xaa).await?;
    }
    owner.write8(0x104, 0x11).await?; // RX/TX 128-byte pages.
    for address in 0..0xa9 {
        llt(owner, address, address + 1).await?;
    }
    llt(owner, 0xa9, 0xff).await?;
    for address in 0xaa..175 {
        llt(owner, address, address + 1).await?;
    }
    llt(owner, 175, 0xaa).await?;
    // Keep the MAC's TX/RX gates closed until complete calibration, channel
    // and packet ownership are installed by the following runtime stage.
    let cr = owner.read16(0x100).await?;
    owner.write16(0x100, cr & !0xc0).await
}
