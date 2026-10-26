// SPDX-License-Identifier: GPL-2.0-or-later
//! C22 negotiated non-HT WMM with one BE/TID0 producer. Linux rtw88
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
pub(super) fn words(p: Parameters, short: bool) -> Result<[u32; 4], Error> {
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
        let aifs = u16::from(ac.aifsn) * if short { 9 } else { 20 } + 10;
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
    // The sealed N22L grant must already enclose these actual publications.
    // The native gains are unchanged; read them through the same retained
    // backend before opening a descriptor/rate mode that depends on them.
    io.station_profile_readback()?;
    if let Some(p) = p {
        let words = words(p, short)?;
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
    let rates = profile.rates.to_le_bytes();
    super::station_control::send(
        io,
        [
            0x40,
            0,
            profile.rate_id() | (1 << 5),
            0x40,
            rates[0],
            rates[1],
            0,
            0,
        ],
        Some(admission),
    )
    .await?;
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
