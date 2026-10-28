// SPDX-License-Identifier: GPL-2.0-or-later
//! Exact EE awake/mailbox and legacy station registers. The caller retains
//! the sole Prepared/PacketIo owner through every wait and publication.
use super::{
    firmware_transport::{Error as AccessError, Io},
    prepare::Error,
};
#[path = "radio/reserved_template.rs"]
mod reserved;

#[derive(Debug, Default)]
pub(super) struct Mailbox {
    next: u8,
    pub(super) failed: bool,
}
fn read(io: &impl Io, reg: u16) -> Result<u32, Error> {
    let value = io.read32(reg)?;
    if value == u32::MAX {
        Err(Error::Access(AccessError::Gone))
    } else {
        Ok(value)
    }
}
fn byte(io: &impl Io, reg: u16, value: u8) -> Result<(), Error> {
    io.write8(reg, value)?;
    if io.read8(reg)? != value {
        return Err(Error::Readback);
    }
    Ok(())
}
fn word(io: &impl Io, reg: u16, value: u16) -> Result<(), Error> {
    io.write_bytes(reg, &value.to_le_bytes())?;
    if u16::from_le_bytes([io.read8(reg)?, io.read8(reg + 1)?]) != value {
        return Err(Error::Readback);
    }
    Ok(())
}
fn dword(io: &impl Io, reg: u16, value: u32) -> Result<(), Error> {
    io.write32(reg, value)?;
    if read(io, reg)? != value {
        return Err(Error::Readback);
    }
    Ok(())
}
pub(super) fn radio_on(io: &impl Io) -> Result<(), Error> {
    if read(io, 0x6c)? & (1 << 31) == 0 {
        return Err(Error::RadioOff);
    }
    Ok(())
}
impl Mailbox {
    /// Busy is hardware-set when this exact box is published and cleared by
    /// the firmware CPU on consumption. This is not an on-air receipt.
    pub(super) async fn send(&mut self, io: &impl Io, id: u8, payload: &[u8]) -> Result<(), Error> {
        self.send_admitted(io, id, payload, None).await
    }
    pub(super) async fn send_admitted(
        &mut self,
        io: &impl Io,
        id: u8,
        payload: &[u8],
        admission: Option<&super::prepare::station::Admission>,
    ) -> Result<(), Error> {
        if self.failed || !matches!((id, payload.len()), (0, 5) | (1, 1) | (3, 2) | (0x20, 5)) {
            return Err(Error::State);
        }
        self.failed = true;
        let mask = 1 << self.next;
        async fn free(
            io: &impl Io,
            mask: u8,
            admission: Option<&super::prepare::station::Admission>,
        ) -> Result<(), Error> {
            for _ in 0..100 {
                if admission.is_some_and(|control| {
                    control.closed.load(core::sync::atomic::Ordering::Acquire)
                }) {
                    return Err(Error::State);
                }
                let status = io.read8(0x1cc)?;
                if status == 255 {
                    return Err(Error::Access(AccessError::Gone));
                }
                if status & mask == 0 {
                    return Ok(());
                }
                io.delay_us(10).await;
            }
            Err(Error::CommandTimeout)
        }
        free(io, mask, admission).await?;
        let base = 0x1d0 + u16::from(self.next) * 4;
        let mut inline = [0; 4];
        inline[0] = id;
        let length = payload.len().min(3);
        inline[1..1 + length].copy_from_slice(&payload[..length]);
        {
            let _publication = admission.map(|control| control.publication.lock());
            if admission
                .is_some_and(|control| control.closed.load(core::sync::atomic::Ordering::Acquire))
            {
                return Err(Error::State);
            }
            if payload.len() > 3 {
                // The actual EE fw.c writer supports the needed5-byte form with
                // TWO extension bytes. Do not advertise the generic7-byte form.
                io.write_bytes(0x1f0 + u16::from(self.next) * 4, &payload[3..])?;
            }
            io.write_bytes(base, &inline)?;
        }
        free(io, mask, admission).await?;
        self.next = (self.next + 1) & 3;
        self.failed = false;
        Ok(())
    }
    pub(super) async fn awake(&mut self, io: &impl Io) -> Result<(), Error> {
        radio_on(io)?;
        // hw.c::HW_VAR_SET_RPWM/_fwlps_leave, low-power clocks disabled.
        let previous = io.read8(0x361)?;
        io.delay_us(1).await;
        byte(io, 0x361, if previous & 0x80 == 0 { 0x80 } else { 0 })?;
        // fw.c::rtl88e_set_fw_pwrmode_cmd(ACTIVE), sw.c interval5.
        self.send(io, 0x20, &[0, 0x10, 5, 0, 0x0c]).await
    }
    /// hw.c::_rtl88ee_fwlps_enter with sw.c low_power_enable=false: send
    /// fw.c::rtl88e_set_fw_pwrmode_cmd(fwctrl_psmode = FW_PS_DTIM_MODE)
    /// (mode 1, RLBM 0, smart_ps 1, awake interval 5, no U-APSD,
    /// FW_PWR_STATE_RF_OFF), then HW_VAR_SET_RPWM(FW_PS_STATE_RF_OFF_88E)
    /// with the toggle bit flipped. The firmware owns the reserved-page
    /// Null/PS-Poll templates already published by the join; no CPWM ack
    /// is awaited on this path (only low_power_enable clock-on polls it).
    pub(super) async fn doze(&mut self, io: &impl Io) -> Result<(), Error> {
        radio_on(io)?;
        self.send(io, 0x20, &[1, 0x10, 5, 0, 0]).await?;
        let previous = io.read8(0x361)?;
        io.delay_us(1).await;
        byte(io, 0x361, if previous & 0x80 == 0 { 0x80 } else { 0 })
    }
}
pub(super) fn reserved_pages(own: [u8; 6], peer: [u8; 6], aid: u16) -> Result<[u8; 768], Error> {
    if !(1..=2007).contains(&aid) {
        return Err(Error::Packet);
    }
    let mut bytes = reserved::TEMPLATE;
    // Exact Linux page locations: beacon0, PS-Poll2, Null3, ProbeRsp4.
    bytes[10..16].copy_from_slice(&own);
    bytes[16..22].copy_from_slice(&peer);
    let at = 2 * 128;
    bytes[at + 2..at + 4].copy_from_slice(&(aid | 0xc000).to_le_bytes());
    bytes[at + 4..at + 10].copy_from_slice(&peer);
    bytes[at + 10..at + 16].copy_from_slice(&own);
    for at in [3 * 128, 4 * 128] {
        bytes[at + 4..at + 10].copy_from_slice(&peer);
        bytes[at + 10..at + 16].copy_from_slice(&own);
        bytes[at + 16..at + 22].copy_from_slice(&peer);
    }
    Ok(bytes)
}
pub(super) async fn prepare_peer(
    io: &impl Io,
    peer: [u8; 6],
    rates: u16,
    basic: u16,
    capability: u16,
) -> Result<(), Error> {
    radio_on(io)?;
    if peer == [0; 6] || peer[0] & 1 != 0 || rates & 1 == 0 || basic & 1 == 0 || basic & !0x15f != 0
    {
        return Err(Error::Packet);
    }
    // Linux resets CAM before association even for its software crypto path.
    io.write32(0x670, 0xc0000000)?;
    let mut cleared = false;
    for _ in 0..1000 {
        if read(io, 0x670)? & (1 << 31) == 0 {
            cleared = true;
            break;
        }
        io.delay_us(10).await;
    }
    if !cleared {
        return Err(Error::CommandTimeout);
    }
    byte(io, 0x680, 0)?;
    for (index, value) in peer.into_iter().enumerate() {
        byte(io, 0x618 + index as u16, value)?;
    }
    configure_rates(io, rates, basic, capability)?;
    // No autonomous beacon transmission in station or no-link state.
    byte(io, 0x422, io.read8(0x422)? & !(1 << 6))?;
    byte(io, 0x541, 0x64)?;
    byte(io, 0x542, io.read8(0x542)? & !1)?;
    byte(io, 0x550, (io.read8(0x550)? & !2) | 16)?;
    byte(io, 0x511, 0x66)?;
    dword(io, 0x608, super::packet_mac::RCR & !0xc0)?;
    Ok(())
}
pub(super) fn configure_rates(
    io: &impl Io,
    rates: u16,
    basic: u16,
    capability: u16,
) -> Result<(), Error> {
    if rates & 1 == 0 || basic & 1 == 0 || basic & !0x15f != 0 {
        return Err(Error::Packet);
    }
    word(io, 0x440, (basic & 0x15f) | 1)?;
    byte(io, 0x480, (15 - basic.leading_zeros()) as u8)?;
    let short = capability & 0x400 != 0;
    let slot = if short { 9 } else { 20 };
    byte(io, 0x51b, slot)?;
    for reg in [0x515, 0x517, 0x429, 0x63b] {
        byte(io, reg, 10)?;
    }
    word(io, 0x63e, 0x0e0e)?;
    // mac80211/util.c::ieee80211_set_wmm_default(enable_qos=false)
    // and base.c::rtl_get_hal_edca_param: legacy DCF, no TXOP burst.
    let cw_min = if rates & 0xff0 == 0 { 5 } else { 4 };
    let edca = (10 << 12) | (cw_min << 8) | (u32::from(slot) * 2 + 10);
    dword(io, 0x508, edca)?;
    let preamble = io.read8(0x66a)?;
    byte(
        io,
        0x66a,
        (preamble & !2) | if capability & 0x20 != 0 { 2 } else { 0 },
    )?;
    Ok(())
}
pub(super) fn associated(io: &impl Io, aid: u16) -> Result<(), Error> {
    radio_on(io)?;
    if !(1..=2007).contains(&aid) {
        return Err(Error::Packet);
    }
    let previous = u16::from_le_bytes([io.read8(0x6a8)?, io.read8(0x6a9)?]);
    word(io, 0x6a8, (previous & 0xc000) | aid)?;
    byte(io, 0x102, (io.read8(0x102)? & !3) | 2)?;
    dword(io, 0x608, super::packet_mac::RCR | 0xc0)?;
    byte(io, 0x550, io.read8(0x550)? & !16)?;
    Ok(())
}
/// rtl88ee_update_channel_access_setting + HW_VAR_SIFS, HT14us.
pub(super) fn ht_timing(io: &impl Io) -> Result<(), Error> {
    for reg in [0x515, 0x517, 0x429, 0x63b] {
        byte(io, reg, 14)?;
    }
    word(io, 0x63e, 0x0e0e)
}
pub(super) fn disconnected(io: &impl Io) -> Result<(), Error> {
    byte(io, 0x102, io.read8(0x102)? & !3)?;
    for reg in 0x618..0x61e {
        byte(io, reg, 0)?;
    }
    let old = u16::from_le_bytes([io.read8(0x6a8)?, io.read8(0x6a9)?]);
    word(io, 0x6a8, old & 0xc000)?;
    dword(io, 0x608, super::packet_mac::RCR & !0xc0)?;
    byte(io, 0x550, io.read8(0x550)? | 16)
}
