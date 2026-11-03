// SPDX-License-Identifier: GPL-2.0-or-later
//! C21/C22 negotiated non-HT WMM with one BE/TID0 producer. Linux rtw88
//! mac80211.c::__rtw_conf_tx and fw.c::rtw_fw_send_ra_info; no RF permission.
use super::{
    firmware_transport::{Error, Io},
    packet_format::DataProfile,
    station_control::Admission,
};
use narf_wireless::wmm::Parameters;
pub(super) fn readback(
    mut read: impl FnMut(u16) -> Result<u32, Error>,
    gains: [u8; 2],
) -> Result<(), Error> {
    for (reg, gain) in [0x18a0, 0x41a0].into_iter().zip(gains) {
        if (read(reg)? >> 16) & 127 != u32::from(gain) {
            return Err(Error::Prerequisite);
        }
    }
    for reg in [0x18e8, 0x41e8] {
        if read(reg)? & 0x1fc00 != 0 {
            return Err(Error::Prerequisite);
        }
    }
    for reg in [0x3a00, 0x3a04, 0x3a08] {
        if read(reg)? != 0 {
            return Err(Error::Prerequisite);
        }
    }
    if read(0x100)? & 0x200 != 0 || read(0x680)? & 0xcf != 0 {
        return Err(Error::Prerequisite);
    }
    Ok(())
}
/// Readback of a C22 5GHz primary's retained OFDM program (`radio::ofdm5`):
/// CCK references zero, the N2xO per-path OFDM references and the
/// 0x3a04/0x3a08 differences. REG_RRSR is the profile's, checked by
/// [`commit`] itself.
pub(super) fn readback5(
    mut read: impl FnMut(u16) -> Result<u32, Error>,
    ofdm: [u8; 2],
    diffs: [u32; 2],
) -> Result<(), Error> {
    for ((cck, reg), reference) in [(0x18a0, 0x18e8), (0x41a0, 0x41e8)].into_iter().zip(ofdm) {
        if read(cck)? & 0x7f_0000 != 0 || read(reg)? & 0x1fc00 != u32::from(reference) << 10 {
            return Err(Error::Prerequisite);
        }
    }
    if read(0x3a00)? != 0 || read(0x3a04)? != diffs[0] || read(0x3a08)? != diffs[1] {
        return Err(Error::Prerequisite);
    }
    if read(0x100)? & 0x200 != 0 || read(0x680)? & 0xcf != 0 {
        return Err(Error::Prerequisite);
    }
    Ok(())
}
/// EDCA words. rtw88 mac80211.c::rtw_aifsn_to_aifs: AIFS = AIFSN * slot +
/// SIFS, SIFS 16 on `RTW_BAND_5G` and 10 otherwise; mac80211 mlme.c
/// `ieee80211_handle_bss_capability` forces the short slot on 5GHz.
pub(super) fn words(p: Parameters, short: bool, band5: bool) -> Result<[u32; 4], Error> {
    let short = short || band5;
    let sifs = if band5 { 16 } else { 10 };
    if p.ac[0].admission_control {
        return Err(Error::Unsupported);
    }
    let mut words = [0; 4];
    for (i, mut ac) in p.ac.into_iter().enumerate() {
        if i == 0 {
            ac.aifsn = ac.aifsn.max(3);
            ac.ecw_min = ac.ecw_min.max(5);
            ac.ecw_max = ac.ecw_max.max(10);
            ac.txop = 0;
        }
        let aifs = u16::from(ac.aifsn) * if short { 9 } else { 20 } + sifs;
        if ac.aifsn < 2
            || ac.ecw_min > ac.ecw_max
            || ac.ecw_max > 15
            || ac.txop > 0x7ff
            || aifs > 255
        {
            return Err(Error::Unsupported);
        }
        words[i] = u32::from(aifs)
            | (u32::from(ac.ecw_min) << 8)
            | (u32::from(ac.ecw_max) << 12)
            | (u32::from(ac.txop) << 16);
    }
    Ok(words)
}
pub(super) async fn commit(
    io: &mut impl Io,
    profile: DataProfile,
    p: Option<Parameters>,
    short: bool,
    admission: &Admission,
) -> Result<(), Error> {
    // The chip-specific N21L/N22L grant already encloses these publications.
    // The native gains are unchanged; read them through the same retained
    // backend before opening a descriptor/rate mode that depends on them.
    io.station_profile_readback()?;
    if let Some(p) = p {
        let words = words(p, short, profile.band5)?;
        // Canonical ACI BE/BK/VI/VO maps to source BE/BK/VI/VO registers.
        for (reg, value) in [0x508, 0x50c, 0x504, 0x500].into_iter().zip(words) {
            admission.run(|| {
                io.station_allowed()?;
                super::radio::mask(io, reg, 0x07ff_ffff, value)?;
                if io.read32(reg)? & 0x07ff_ffff != value {
                    return Err(Error::Prerequisite);
                }
                Ok(())
            })?;
            narf_scheduler::yield_now().await;
        }
    }
    ra_info(io, profile, admission).await?;
    admission.run(|| {
        io.station_allowed()?;
        let mask = profile.response_mask();
        io.write32(0x440, mask)?;
        if io.read32(0x440)? != mask {
            return Err(Error::Prerequisite);
        }
        io.station_profile_readback()?;
        io.packet_profile(profile)
    })
}
/// Source `fw.c::rtw_fw_send_ra_info`: RATE_ID 20:16, INIT_RA_LVL1, SGI_EN
/// bit23, BW_MODE 25:24 (N2xB 40MHz, N2xV 80MHz), LDPC bit26, VHT_EN 29:28
/// (N2xV `si->vht_enable`, mask `RA_MASK_VHT_RATES | RA_MASK_OFDM_IN_VHT`) (`si->ldpc_en`, separately qualified N2xC), DIS_PT bit30.
pub(super) async fn ra_info(
    io: &mut impl Io,
    profile: DataProfile,
    admission: &Admission,
) -> Result<(), Error> {
    let rates = profile.ra_mask().to_le_bytes();
    super::station_control::send(
        io,
        [
            0x40,
            0,
            profile.rate_id() | (1 << 5) | (u8::from(profile.sgi) << 7),
            0x40 | (u8::from(profile.vht.is_some()) << 4)
                | (u8::from(profile.ldpc) << 2)
                | profile.bw_mode(),
            rates[0],
            rates[1],
            rates[2],
            rates[3],
        ],
        Some(admission),
    )
    .await
}
