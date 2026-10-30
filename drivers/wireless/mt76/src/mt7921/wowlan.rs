//! CONNAC2 WoWLAN wire requests consumed by the retained native owner.
//!
//! Linux mt76_connac_mcu.c CONFIG_PM and mt76_connac_mcu.h packed TLVs.
//! The associated firmware generation survives HIF suspend under a real
//! platform wake route. Encoders alone never authorize a suspend or grant.

use narf_wireless::{WowlanConfig, WowlanPattern};
use zeroize::Zeroizing;

use super::firmware_transport::Error;

pub(super) const UNI_SUSPEND: u16 = 0x05;
pub(super) const UNI_OFFLOAD: u16 = 0x06;

pub(crate) fn validate(config: &WowlanConfig) -> Result<(), Error> {
    // CONNAC2's native bitmap table holds one pattern and no offset field.
    if config.gtk_rekey_failure || config.patterns.len() > 1 {
        return Err(Error::Bounds);
    }
    if !config.disconnect
        && !config.magic_packet
        && config.patterns.is_empty()
        && config.net_detect.is_none()
    {
        return Err(Error::Bounds);
    }
    for pattern in &config.patterns {
        if pattern.offset != 0
            || pattern.pattern.is_empty()
            || pattern.pattern.len() > 128
            || pattern.mask.len() != pattern.pattern.len().div_ceil(8)
        {
            return Err(Error::Bounds);
        }
    }
    if let Some(config) = &config.net_detect {
        super::wowlan_nlo::validate(config)?;
    }
    Ok(())
}

/// `{bss_idx,pad[3]}` + UNI_SUSPEND_MODE_SETTING TLV.
pub(super) fn suspend_mode(enable: bool) -> [u8; 16] {
    let mut body = [0; 16];
    body[6..8].copy_from_slice(&12u16.to_le_bytes());
    body[8] = u8::from(enable);
    body[9] = 1; // mdtim, mt76_connac_mcu_set_suspend_iter
    body[10] = 1; // wow_suspend
    body
}

pub(super) fn arp_mode(enable: bool) -> [u8; 12] {
    let mut body = [0; 12];
    body[6..8].copy_from_slice(&8u16.to_le_bytes());
    body[8] = u8::from(enable);
    // No IP addresses are inferred from Ethernet traffic. The native
    // address list stays empty until a real address owner supplies it.
    body
}

pub(super) fn nd_mode(enable: bool) -> [u8; 12] {
    let mut body = arp_mode(enable);
    body[4..6].copy_from_slice(&1u16.to_le_bytes());
    body
}

pub(super) fn gtk_mode(enable: bool) -> Zeroizing<[u8; 76]> {
    let mut body = Zeroizing::new([0; 76]);
    body[4..6].copy_from_slice(&2u16.to_le_bytes());
    body[6..8].copy_from_slice(&72u16.to_le_bytes());
    body[48] = u8::from(!enable); // mode0 enable, mode1 disable
    body
}

/// Only current authenticated CCMP-128 RSNA material may reach this encoder.
/// No debug representation or unzeroized retained copy is constructed.
pub(super) fn gtk_update(
    kek: &[u8],
    kck: &[u8],
    replay: u64,
) -> Result<Zeroizing<[u8; 76]>, Error> {
    if kek.len() != 16 || kck.len() != 16 {
        return Err(Error::Bounds);
    }
    let mut body = gtk_mode(false);
    body[8..24].copy_from_slice(kek);
    body[24..40].copy_from_slice(kck);
    body[40..48].copy_from_slice(&replay.to_be_bytes());
    body[48] = 2; // rekey update
    body[50] = 1; // update data without enabling the offload
    body[52..56].copy_from_slice(&2u32.to_le_bytes()); // NL80211_WPA_VERSION_2
    body[56..60].copy_from_slice(&(1u32 << 4).to_le_bytes()); // CCMP pairwise
    body[60..64].copy_from_slice(&(1u32 << 4).to_le_bytes()); // CCMP group
                                                              // Linux key_iter leaves keyid0 and key_mgmt/mgmt_group_cipher zero;
                                                              // firmware already owns the native installed PTK/GTK/IGTK records.
    Ok(body)
}

pub(super) fn pattern(pattern: &WowlanPattern, enable: bool) -> Result<[u8; 160], Error> {
    if pattern.offset != 0
        || pattern.pattern.is_empty()
        || pattern.pattern.len() > 128
        || pattern.mask.len() != pattern.pattern.len().div_ceil(8)
    {
        return Err(Error::Bounds);
    }
    let mut body = [0; 160];
    body[4..6].copy_from_slice(&4u16.to_le_bytes());
    body[6..8].copy_from_slice(&156u16.to_le_bytes());
    body[9] = u8::from(enable);
    body[10] = pattern.pattern.len() as u8;
    body[12..12 + pattern.mask.len()].copy_from_slice(&pattern.mask);
    body[28..28 + pattern.pattern.len()].copy_from_slice(&pattern.pattern);
    Ok(body)
}

pub(super) fn control(config: &WowlanConfig, enable: bool) -> Result<[u8; 32], Error> {
    validate(config)?;
    let mut body = [0; 32];
    body[4..6].copy_from_slice(&1u16.to_le_bytes());
    body[6..8].copy_from_slice(&12u16.to_le_bytes());
    body[8] = if enable { 1 } else { 2 }; // START/STOP
    if config.magic_packet {
        body[9] |= 1;
    }
    if config.disconnect {
        body[9] |= (1 << 2) | (1 << 4);
    }
    if !config.patterns.is_empty() {
        body[9] |= 1 << 6;
    }
    if config.net_detect.is_some() {
        body[9] |= 1 << 5;
    }
    body[10] = 2; // WOW_PCIE
    body[16..18].copy_from_slice(&2u16.to_le_bytes());
    body[18..20].copy_from_slice(&16u16.to_le_bytes());
    body[20] = 0xff; // follow actual firmware's GPIO default
    Ok(body)
}
