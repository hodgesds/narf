// SPDX-License-Identifier: GPL-2.0-or-later
//! Linux7.3-rc4 rtw88 power commands and station reserved-page layout.
//! These bytes carry no PCI, association, RF or DMA publication authority.
use super::firmware_transport::Info;
use alloc::{vec, vec::Vec};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Profile {
    pub c2h_wake: bool,
    pub clock: bool,
    pub tx_wake: bool,
    pub old_pages: bool,
}
impl Profile {
    pub(super) fn from_firmware(did: u16, info: Info) -> Option<Self> {
        if !matches!(did, 0xc821 | 0xc822) {
            return None;
        }
        Some(Self {
            c2h_wake: info.features & 3 == 3,
            clock: info.features & 5 == 5,
            tx_wake: info.features & 0x11 == 0x11,
            old_pages: did == 0xc822 && (info.version, info.subversion, info.subindex) < (9, 9, 13),
        })
    }
}

/// ps.c::rtw_enter_lps_core / rtw_leave_lps_core, single associated port0.
/// RLBM1 + SMARTPS2 applies to LPS; ACTIVE uses RLBM0 + SMARTPS0.
pub(super) fn parameters(enter: bool) -> [u8; 8] {
    [
        0x20,
        u8::from(enter),
        if enter { 0x21 } else { 0 },
        1,
        0,
        if enter { 0 } else { 0x0c },
        0,
        0,
    ]
}

/// ps.c::rtw_power_mode_change: clear every old request bit except the
/// inverted bit7, set ACK and optionally LCLK / TX_WAKE. No PG support here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ClockRequest {
    pub wire: u8,
    previous_confirmation: u8,
}
impl ClockRequest {
    pub(super) fn prepare(profile: Profile, previous: u8, cpwm: u8, enter: bool) -> Option<Self> {
        if !profile.clock || previous == 0xff || cpwm == 0xff {
            return None;
        }
        Some(Self {
            wire: (!previous & 0x80) | 0x40 | u8::from(enter) | if profile.tx_wake { 2 } else { 0 },
            previous_confirmation: cpwm,
        })
    }
    /// Only an actual current native CPWM read after this exact publication
    /// may be passed here. Matching low state bits do not acknowledge RPWM.
    pub(super) fn acknowledged(self, cpwm: u8) -> bool {
        cpwm != 0xff && (cpwm ^ self.previous_confirmation) & 0x80 != 0
    }
}

pub(super) const TCR: u16 = 0x604;
pub(super) fn register_awake(tcr: u32) -> bool {
    tcr != u32::MAX && tcr & 0x80 == 0
}
/// C2H_WLAN_RFON is an id+sequence header; Linux imposes no payload length.
/// A caller must discard pre-command RX and own the original outstanding
/// wake transition. A stale C2H id alone cannot establish readiness.
pub(super) fn wake_event(body: &[u8]) -> bool {
    body.len() >= 2 && body[0] == 0x32
}

/// Nondeep LPS uses PS-Poll, QoS-Null and Null templates. Power-gating save
/// pages are intentionally absent: this layout cannot activate PG mode.
pub(super) struct Pages {
    pub bytes: Vec<u8>,
    pub locations: [u8; 8],
}
fn put(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
impl Pages {
    pub(super) fn station(own: [u8; 6], peer: [u8; 6], aid: u16, wmm: bool) -> Option<Self> {
        let unicast = |a: [u8; 6]| a[0] & 1 == 0 && a != [0; 6];
        if !unicast(own) || !unicast(peer) || own == peer || !(1..=2007).contains(&aid) {
            return None;
        }
        // mac80211::{ieee80211_pspoll_get,ieee80211_nullfunc_get}.
        let mut poll = vec![0xa4, 0];
        poll.extend_from_slice(&(aid | 0xc000).to_le_bytes());
        poll.extend_from_slice(&peer);
        poll.extend_from_slice(&own);
        let mut null = vec![0x48, 1, 0, 0];
        null.extend_from_slice(&peer);
        null.extend_from_slice(&own);
        null.extend_from_slice(&peer);
        null.extend_from_slice(&[0, 0]);
        let mut qos = null.clone();
        if wmm {
            qos[0] = 0xc8;
            qos.extend_from_slice(&[7, 0]);
        }
        // fw.c::rtw_build_rsvd_page: page128, descriptor48, dummy page0.
        // The outer download descriptor consumes the first48 bytes of page0,
        // so subsequent inner descriptors start at buffer80,208,336.
        let mut bytes = vec![0; 464];
        for (i, frame) in [poll, qos, null].into_iter().enumerate() {
            let at = 80 + i * 128;
            let descriptor = &mut bytes[at..at + 48];
            let ps_poll = i == 0;
            // tx.c::rtw_tx_rsvd_page_pkt_info_update; fixed CCK1, port0,
            // MACID0, no hardware encryption/aggregation/rate fallback.
            put(
                descriptor,
                0,
                frame.len() as u32 | 48 << 16 | 1 << 26 | if ps_poll { 0 } else { 1 << 31 },
            );
            put(descriptor, 4, 18 << 8 | 8 << 16);
            put(descriptor, 8, if i == 1 { 1 << 23 } else { 0 });
            put(
                descriptor,
                12,
                1 << 8 | 1 << 10 | if ps_poll { 1 << 15 } else { 0 },
            );
            put(descriptor, 32, if ps_poll { 0 } else { 1 << 15 });
            bytes[at + 48..at + 48 + frame.len()].copy_from_slice(&frame);
        }
        Some(Self {
            bytes,
            locations: [0, 0, 1, 3, 2, 0, 0, 0],
        })
    }
}

#[cfg(feature = "kernel-test")]
#[path = "runtime_ps_wire_tests.rs"]
mod tests;
