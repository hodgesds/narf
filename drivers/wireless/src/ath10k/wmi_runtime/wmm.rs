// SPDX-License-Identifier: GPL-2.0-or-later
//! One-vdev STA WMM. Linux ath10k wmi.{c,h}, wmi-tlv.{c,h} and
//! mac.c::ath10k_conf_tx define the native PDEV records and TXOP units.
use super::{wire, Dialect, Error};
use alloc::vec::Vec;
use narf_wireless::wmm::{Parameters, INFORMATION};

fn admit(parameters: Parameters) -> Result<Parameters, Error> {
    // No TSPEC admission or U-APSD is negotiated. VO/VI/BK ACM is served by
    // `tx_qos` downgrade (`ieee80211_downgrade_queue`); an ACM-only BE queue
    // would push all ordinary traffic onto BK, so that BSS stays refused.
    if parameters.ac[0].admission_control {
        return Err(Error::Unsupported);
    }
    Ok(parameters)
}

pub(super) fn offer(ies: &[u8], mut sme: &[u8]) -> Result<Option<Parameters>, Error> {
    // The driver owns WMM negotiation. Caller elements cannot duplicate or
    // replace the Information IE or request U-APSD without its queue owner.
    while !sme.is_empty() {
        let header = sme.get(..2).ok_or(Error::Malformed)?;
        let end = 2 + usize::from(header[1]);
        let body = sme.get(2..end).ok_or(Error::Malformed)?;
        if header[0] == 221 && body.starts_with(&[0, 0x50, 0xf2, 2]) {
            return Err(Error::Unsupported);
        }
        sme = &sme[end..];
    }
    Parameters::parse(ies)
        .map_err(|_| Error::Malformed)?
        .map(admit)
        .transpose()
}

pub(super) fn response(
    offered: Option<Parameters>,
    response: &[u8],
) -> Result<Option<Parameters>, Error> {
    let received = Parameters::parse(response).map_err(|_| Error::Malformed)?;
    match (offered, received) {
        (None, None) => Ok(None),
        (Some(_), Some(parameters)) => admit(parameters).map(Some),
        _ => Err(Error::Unsupported),
    }
}

pub(super) fn information() -> &'static [u8] {
    &INFORMATION
}

pub(super) fn command(dialect: Dialect, parameters: Parameters) -> Result<Vec<u8>, Error> {
    let parameters = admit(parameters)?;
    let tlv = dialect == Dialect::Tlv;
    let id = match dialect {
        Dialect::Main | Dialect::Tlv => 0x4006,
        Dialect::TenOne | Dialect::TenTwo | Dialect::TenTwoFour => 0x9009,
        Dialect::TenFour => 0x900b,
    };
    // TLV has two zero pdev/dg_type words, then four independently tagged
    // native AC records. Legacy dialects carry just the four24-byte records.
    let mut out = wire::packet(id, if tlv { 124 } else { 96 })?;
    let mut at = if tlv {
        wire::put(&mut out, 4, (83 << 16) | 8);
        16
    } else {
        4
    };
    for ac in parameters.ac {
        if tlv {
            wire::put(&mut out, at, (84 << 16) | 24);
            at += 4;
        }
        for value in [
            u32::from(ac.cw_min()),
            u32::from(ac.cw_max()),
            u32::from(ac.aifsn),
            u32::from(ac.txop) * 32,
            u32::from(ac.admission_control),
            0, // Normal ACK; no driver-owned no-ACK negotiation.
        ] {
            wire::put(&mut out, at, value);
            at += 4;
        }
    }
    Ok(out)
}
