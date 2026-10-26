//! Bounded station-side A-MSDU decoding after native receive admission.
//! Linux net/wireless/util.c::ieee80211_amsdu_to_8023s supplies the
//! subframe/RFC1042 rules and first-subframe aggregation-injection check.
//! This parser grants no association, key, controlled-port or radio authority.
use alloc::vec::Vec;

/// Default IEEE HT maximum when MAX_AMSDU is not advertised.
pub const MAX_BYTES: usize = 3839;
/// Every admitted subframe contains a14-byte header and eight-byte LLC/SNAP.
pub const MAX_SUBFRAMES: usize = MAX_BYTES / 22;
const RFC1042: [u8; 6] = [0xaa, 0xaa, 3, 0, 0, 0];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Length,
    Address,
    Protocol,
    Injection,
    Allocation,
}

fn unicast(mac: &[u8]) -> bool {
    mac != [0; 6] && mac[0] & 1 == 0
}

fn protocol_allowed(body: &[u8]) -> bool {
    let mut protocol = u16::from_be_bytes([body[6], body[7]]);
    let mut at = 8;
    // An aggregated VLAN frame must not smuggle the private control port.
    // At most the ordinary customer/provider pair is admitted here.
    for _ in 0..2 {
        if !matches!(protocol, 0x8100 | 0x88a8) {
            break;
        }
        let Some(tag) = body.get(at..at + 4) else {
            return false;
        };
        protocol = u16::from_be_bytes([tag[2], tag[3]]);
        at += 4;
    }
    protocol >= 0x600
        && !matches!(
            protocol,
            0x888e | 0x88c7 | 0x80f3 | 0x8137 | 0x8100 | 0x88a8
        )
}

/// Decode the complete plaintext aggregate into Ethernet-II frames atomically.
/// `local` and the outer802.11 `receiver` come from the retained native station
/// header, not a subframe. A unicast outer receiver must be the local station;
/// its subframes may name that local destination or multicast, as in Linux's
/// station check_da rule. A multicast outer receiver admits only that exact DA.
/// Each SA must be a nonlocal unicast. Payloads use RFC1042 Ethernet-II only;
/// EAPOL, preauthentication, legacy tunnel exceptions and nested control ports
/// are rejected. Native header/PHY/peer/protection admission is the caller's.
///
/// Padding is counted between subframes only; its bytes are unspecified by
/// IEEE802.11 and are never interpreted. The last subframe has no padding.
/// Any bad later subframe drops the whole result before it can be published.
pub fn decode(body: &[u8], local: [u8; 6], receiver: [u8; 6]) -> Result<Vec<Vec<u8>>, Error> {
    if !unicast(&local) || receiver == [0; 6] || receiver[0] & 1 == 0 && receiver != local {
        return Err(Error::Address);
    }
    if !(22..=MAX_BYTES).contains(&body.len()) {
        return Err(Error::Length);
    }
    let mut frames = Vec::new();
    let mut rest = body;
    while !rest.is_empty() {
        if frames.len() == MAX_SUBFRAMES {
            return Err(Error::Length);
        }
        let subheader = rest.get(..14).ok_or(Error::Length)?;
        let len = usize::from(u16::from_be_bytes([subheader[12], subheader[13]]));
        if !(8..=1508).contains(&len) {
            return Err(Error::Length);
        }
        let extent = 14 + len;
        let payload = rest.get(14..extent).ok_or(Error::Length)?;
        let da = &subheader[..6];
        let sa = &subheader[6..12];
        // CCMP's ordinary QoS AAD masks A-MSDU-present. An adversary must
        // not reinterpret an authenticated standalone RFC1042 MSDU as an
        // aggregate by flipping that unauthenticated bit (FragAttacks).
        if frames.is_empty() && da == RFC1042 {
            return Err(Error::Injection);
        }
        if da == [0; 6]
            || receiver[0] & 1 != 0 && da != receiver
            || receiver[0] & 1 == 0 && da[0] & 1 == 0 && da != local
            || !unicast(sa)
            || sa == local
        {
            return Err(Error::Address);
        }
        if payload[..6] != RFC1042 || !protocol_allowed(payload) {
            return Err(Error::Protocol);
        }
        let mut frame = Vec::new();
        frame
            .try_reserve_exact(12 + len - 6)
            .map_err(|_| Error::Allocation)?;
        frame.extend_from_slice(&subheader[..12]);
        frame.extend_from_slice(&payload[6..]);
        frames.try_reserve(1).map_err(|_| Error::Allocation)?;
        frames.push(frame);
        if rest.len() == extent {
            break;
        }
        let padded = extent + (4 - extent % 4) % 4;
        // Any following bytes must contain another whole subframe. A
        // dangling/trailing pad cannot silently turn into a final subframe.
        rest = rest.get(padded..).ok_or(Error::Length)?;
        if rest.len() < 22 {
            return Err(Error::Length);
        }
    }
    Ok(frames)
}

#[cfg(feature = "kernel-test")]
#[path = "amsdu_tests.rs"]
mod tests;
