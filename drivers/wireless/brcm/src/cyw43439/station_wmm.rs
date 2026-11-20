// SPDX-License-Identifier: GPL-2.0-or-later
//! Negotiated firmware WMM state and 802.1D priority mapping.
//!
//! Linux `brcmf_get_assoc_ies` reads the station's current EDCA parameters
//! from the firmware `wme_ac_sta` iovar after association and ranks them
//! with `brcmf_wifi_prioritize_acparams`; `brcmf_map_prio_to_prec` then maps
//! each 802.1D priority onto SDIO host precedence, and `brcmf_flowring`
//! maps it onto a msgbuf FIFO. References: Linux brcmfmac `cfg80211.c`
//! (L6206..L6340), `cfg80211.h` (EDCF masks), `fwsignal.h` (FIFO numbers)
//! and `flowring.c::brcmf_flowring_prio2fifo`.

use super::Error;

/// `BRCMF_FWS_FIFO_AC_{BK,BE,VI,VO}`.
const FIFO_BK: u8 = 0;
const FIFO_BE: u8 = 1;
const FIFO_VI: u8 = 2;
const FIFO_VO: u8 = 3;
/// `brcmf_init_wmm_prio`: 802.1D 0,3→BE; 1,2→BK; 4,5→VI; 6,7→VO.
pub const DEFAULT_AC_PRIORITY: [u8; 8] = [
    FIFO_BE, FIFO_BK, FIFO_BK, FIFO_BE, FIFO_VI, FIFO_VI, FIFO_VO, FIFO_VO,
];
/// Four `brcmf_cfg80211_edcf_acparam {ACI, ECW, TXOP:u16}` rows.
pub const ACPARAM_LEN: usize = 16;
/// `AC_BE`, `AC_BK`, `AC_VI`, `AC_VO` row order.
const AC_BE: usize = 0;
const AC_BK: usize = 1;
const AC_VI: usize = 2;
const AC_VO: usize = 3;

/// `brcmf_wifi_prioritize_acparams`: per-802.1D AC rank from the current
/// firmware EDCA rows. Returns the default map when every rank is equal.
pub fn prioritize(acparams: &[u8]) -> Result<[u8; 8], Error> {
    if acparams.len() != ACPARAM_LEN {
        return Err(Error::Malformed);
    }
    let mut ranking = [0u8; 4];
    for (aci, row) in acparams.chunks_exact(4).enumerate() {
        let aifsn = row[0] & 0x0f; // EDCF_AIFSN_MASK
        let acm = row[0] & 0x10 != 0; // EDCF_ACM_MASK
        let ecwmin = row[1] & 0x0f; // EDCF_ECWMIN_MASK
        let ecwmax = (row[1] & 0xf0) >> 4; // EDCF_ECWMAX_MASK/SHIFT
        ranking[aci] = aifsn + ecwmin + ecwmax;
        // A station may not use an admission-controlled AC: rank it as BE.
        if aci != AC_BE && aci != AC_BK && acm {
            ranking[aci] = ranking[AC_BE];
        }
    }
    let mut rank = [0u8; 4];
    for aci in 0..4 {
        rank[aci] = (0..4)
            .filter(|&other| other != aci && ranking[aci] < ranking[other])
            .count() as u8;
    }
    if rank.iter().all(|&r| r == rank[AC_BE]) {
        return Ok(DEFAULT_AC_PRIORITY);
    }
    Ok([
        rank[AC_BE],
        rank[AC_BK],
        rank[AC_BK],
        rank[AC_BE],
        rank[AC_VI],
        rank[AC_VI],
        rank[AC_VO],
        rank[AC_VO],
    ])
}

/// `brcmf_map_prio_to_prec`: SDIO host precedence (0..7) whose bit in the
/// SDPCM `fc_mask` stops this 802.1D priority.
pub fn precedence(ac_priority: &[u8; 8], priority: u8) -> u8 {
    let priority = usize::from(priority & 7);
    let ac = ac_priority[priority] & 3;
    // PRIO_8021D_EE=3; ACM-demoted priorities use BE's 4-level precedence.
    if priority > 3 && ac == ac_priority[0] & 3 {
        return ac * 2;
    }
    // PRIO_8021D_{BE,BK,CL,VO} take the even precedence.
    if matches!(priority, 0 | 1 | 4 | 6) {
        ac * 2
    } else {
        ac * 2 + 1
    }
}

/// `brcmf_flowring_prio2fifo`: one msgbuf station flow per FIFO.
pub fn fifo(priority: u8) -> u8 {
    [0, 1, 1, 0, 2, 2, 3, 3][usize::from(priority & 7)]
}
