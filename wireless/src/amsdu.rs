//! Bounded station-side A-MSDU decoding after native receive admission.
//! Linux net/wireless/util.c::ieee80211_amsdu_to_8023s supplies the
//! subframe/RFC1042 rules and first-subframe aggregation-injection check.
//! This parser grants no association, key, controlled-port or radio authority.
use alloc::vec::Vec;

/// Default IEEE HT maximum when MAX_AMSDU is not advertised.
pub const MAX_BYTES: usize = 3839;
/// Every admitted subframe contains a14-byte header and eight-byte LLC/SNAP.
pub const MAX_SUBFRAMES: usize = MAX_BYTES / 22;
/// Largest aggregate body any `Limit` admits (VHT11454-byte MPDU).
pub const MAX_LARGE_BYTES: usize = Limit::Vht11454.bytes();
/// Subframe work bound for `MAX_LARGE_BYTES`.
pub const MAX_LARGE_SUBFRAMES: usize = MAX_LARGE_BYTES / 22;
/// Protected QoS MPDU overhead outside the aggregate body: the26-byte
/// admitted QoS header (no HT Control/Address4), the8-byte CCMP header,
/// the8-byte MIC and the4-byte FCS.
const PROTECTED_MPDU_OVERHEAD: usize = 26 + 8 + 8 + 4;

/// A locally advertised (receive) or peer-advertised (transmit) A-MSDU size.
/// HT values are the A-MSDU limits of IEEE802.11-2020 9.4.2.55.2 (HT
/// Capability Information bit11). VHT values are the Maximum MPDU Length of
/// 9.4.2.157.2; an A-MSDU in a VHT PPDU is bounded only by that MPDU length
/// (10.12, A-MSDU operation), so the body bound subtracts the admitted
/// protected-header/CCMP/FCS overhead. The value is a size fact; it grants no
/// PHY, BA, association or channel authority. The default for every existing
/// entry point remains `Ht3839`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Limit {
    #[default]
    Ht3839,
    Ht7935,
    Vht3895,
    Vht7991,
    Vht11454,
}
impl Limit {
    /// Maximum aggregate body bytes admitted under this limit.
    pub const fn bytes(self) -> usize {
        match self {
            Self::Ht3839 => 3839,
            Self::Ht7935 => 7935,
            Self::Vht3895 => 3895 - PROTECTED_MPDU_OVERHEAD,
            Self::Vht7991 => 7991 - PROTECTED_MPDU_OVERHEAD,
            Self::Vht11454 => 11454 - PROTECTED_MPDU_OVERHEAD,
        }
    }
    /// Minimum-size (22-byte) subframes that fit in `bytes()`.
    pub const fn max_subframes(self) -> usize {
        self.bytes() / 22
    }
    /// HT Capability Information bit11 (Maximum A-MSDU Length).
    pub const fn from_ht_capability(info: u16) -> Self {
        if info & (1 << 11) != 0 {
            Self::Ht7935
        } else {
            Self::Ht3839
        }
    }
    /// VHT Capabilities Information bits0..1 (Maximum MPDU Length); the
    /// reserved value3 is rejected.
    pub const fn from_vht_capability(info: u32) -> Option<Self> {
        match info & 3 {
            0 => Some(Self::Vht3895),
            1 => Some(Self::Vht7991),
            2 => Some(Self::Vht11454),
            _ => None,
        }
    }
}
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
    ethertype_allowed(u16::from_be_bytes([body[6], body[7]]), &body[8..])
}

/// `tags` begins immediately after the outer EtherType.
fn ethertype_allowed(mut protocol: u16, tags: &[u8]) -> bool {
    let mut at = 0;
    // An aggregated VLAN frame must not smuggle the private control port.
    // At most the ordinary customer/provider pair is admitted here.
    for _ in 0..2 {
        if !matches!(protocol, 0x8100 | 0x88a8) {
            break;
        }
        let Some(tag) = tags.get(at..at + 4) else {
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
    decode_with_limit(body, local, receiver, Limit::Ht3839)
}

/// `decode` under an explicitly advertised local receive `limit`. Only a
/// driver whose native receive path, buffers and published capability actually
/// support the larger HT7935 or VHT MPDU size may pass it; every other rule of
/// `decode` is unchanged.
pub fn decode_with_limit(
    body: &[u8],
    local: [u8; 6],
    receiver: [u8; 6],
    limit: Limit,
) -> Result<Vec<Vec<u8>>, Error> {
    if !unicast(&local) || receiver == [0; 6] || receiver[0] & 1 == 0 && receiver != local {
        return Err(Error::Address);
    }
    if !(22..=limit.bytes()).contains(&body.len()) {
        return Err(Error::Length);
    }
    let mut frames = Vec::new();
    let mut rest = body;
    while !rest.is_empty() {
        if frames.len() == limit.max_subframes() {
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

/// Encode station-originated Ethernet-II frames as one A-MSDU body
/// (IEEE802.11-2020 9.3.2.2.2): each subframe carries DA, SA, a big-endian
/// length, the RFC1042 LLC/SNAP header and the payload, and every subframe
/// except the last is padded to a four-byte boundary with zero bytes, as
/// Linux mac80211's ieee80211_amsdu_aggregate builds it. `limit` is the
/// peer's advertised maximum. The encoder applies the receive-side admission
/// rules so it never produces an aggregate a conformant receiver discards: a
/// unicast/multicast nonzero DA, the local unicast SA, an Ethernet-II protocol
/// outside the control-port/tunnel set and no RFC1042-looking first DA. The
/// result is atomic; any failing frame returns no partial aggregate.
pub fn encode(frames: &[&[u8]], local: [u8; 6], limit: Limit) -> Result<Vec<u8>, Error> {
    if !unicast(&local) {
        return Err(Error::Address);
    }
    if frames.is_empty() || frames.len() > limit.max_subframes() {
        return Err(Error::Length);
    }
    let mut total = 0usize;
    for (i, frame) in frames.iter().enumerate() {
        if !(14..=1514).contains(&frame.len()) {
            return Err(Error::Length);
        }
        if frame[..6] == [0; 6] || frame[6..12] != local {
            return Err(Error::Address);
        }
        if i == 0 && frame[..6] == RFC1042 {
            return Err(Error::Injection);
        }
        if !ethertype_allowed(u16::from_be_bytes([frame[12], frame[13]]), &frame[14..]) {
            return Err(Error::Protocol);
        }
        total = total.next_multiple_of(4) + 14 + 8 + frame.len() - 14;
    }
    if total > limit.bytes() {
        return Err(Error::Length);
    }
    let mut body = Vec::new();
    body.try_reserve_exact(total)
        .map_err(|_| Error::Allocation)?;
    for frame in frames {
        body.resize(body.len().next_multiple_of(4), 0);
        body.extend_from_slice(&frame[..12]);
        body.extend_from_slice(&((frame.len() - 14 + 8) as u16).to_be_bytes());
        body.extend_from_slice(&RFC1042);
        body.extend_from_slice(&frame[12..]);
    }
    Ok(body)
}

#[cfg(feature = "kernel-test")]
#[path = "amsdu_tests.rs"]
mod tests;
