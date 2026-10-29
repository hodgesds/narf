// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! TX/RX L3/L4 checksum offload between the NARF frame-ring contract
//! (`narf_net::TxMeta::csum_l4`, `narf_net::RxMeta`) and the Intel
//! TX_CMD `offload_assist` word / RX MPDU descriptor.
//!
//! | NARF | Linux |
//! |---|---|
//! | [`OFFLOADS`] | `IWL_TX_CSUM_NETIF_FLAGS \| NETIF_F_RXCSUM` in every 22000/AX210/Bz/Sc `mac_cfg` (`iwl-config.h`) |
//! | [`prepare_tx`] | `mvm/tx.c::iwl_mvm_tx_csum`, `mld/tx.c::iwl_mld_get_offload_assist` (non-A-MSDU branch) |
//! | [`rx_meta_l3l4`] | `mvm/rxmq.c::iwl_mvm_rx_csum`, pre-AX210 `l3l4_flags` branch |
//! | [`rx_meta_complete`] | `mvm/rxmq.c::iwl_mvm_rx_csum` / `mld/rx.c::iwl_mld_rx_csum` (`FH_RSCSR_RPA_EN`, `v3.raw_xsum`, `CHECKSUM_COMPLETE`) and the SNAP adjustment in `iwl_mvm_create_skb` |
//!
//! Linux hands any `CHECKSUM_PARTIAL` IPv4/IPv6 TCP/UDP skb to the firmware;
//! NARF's frame-ring contract instead requires the driver to validate the
//! request: only an unfragmented IPv4, or IPv6 without extension headers,
//! TCP/UDP packet of the requested kind is accepted. Anything else is refused
//! and never transmitted partially checksummed. RX verdicts are reported only
//! when the hardware's result proves the checksum; an unverifiable result
//! leaves software verification in place.
use narf_net::{L4CsumKind, OffloadCapabilities, RxMeta};

/// Advertised frame-ring offloads: L4 checksum generation and RX checksum
/// verdicts. TSO is a driver-side A-MSDU segmentation in Linux
/// (`iwl_mld_tx_tso_segment`), not a firmware offload; VLAN insertion is
/// not supported.
pub const OFFLOADS: OffloadCapabilities = OffloadCapabilities {
    tx_checksum: true,
    rx_checksum: true,
    max_tso_bytes: 0,
    vlan_insert: false,
};

/// `fw/api/tx.h` `enum iwl_tx_offload_assist_flags_pos`.
pub const OFFLD_IP_HDR: u32 = 0;
pub const OFFLD_L4_EN: u32 = 6;
pub const OFFLD_L3_EN: u32 = 7;
pub const OFFLD_MH_SIZE: u32 = 8;
pub const OFFLD_PAD: u32 = 13;
pub const OFFLD_AMSDU: u32 = 14;

/// `fw/api/rx.h` `enum iwl_rx_l3l4_flags` and `enum iwl_rx_l3_proto_values`.
pub const L3L4_IP_HDR_CSUM_OK: u16 = 1 << 0;
pub const L3L4_TCP_UDP_CSUM_OK: u16 = 1 << 1;
const L3_PROTO_POS: u16 = 4;
const L3_TYPE_IPV4: u16 = 1;
const L3_TYPE_IPV6_FRAG: u16 = 3;
const L3_TYPE_IPV6: u16 = 4;
/// `iwl-fh.h` `FH_RSCSR_RPA_EN`: the descriptor carries a raw checksum.
pub const RSCSR_RPA_EN: u32 = 1 << 25;

const ETH_HLEN: usize = 14;
const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86dd;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
/// RFC 1042 SNAP prefix the station inserts before the EtherType.
const SNAP_WORDS: u32 = 4;

fn be16(b: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([b[off], b[off + 1]])
}

fn sum16(b: &[u8]) -> u32 {
    let mut chunks = b.chunks_exact(2);
    let mut sum: u32 = chunks
        .by_ref()
        .map(|w| u32::from(u16::from_be_bytes([w[0], w[1]])))
        .sum();
    if let [last] = chunks.remainder() {
        sum += u32::from(*last) << 8;
    }
    sum
}

fn fold(mut s: u32) -> u16 {
    while s >> 16 != 0 {
        s = (s & 0xffff) + (s >> 16);
    }
    s as u16
}

struct Layout {
    ipv4: bool,
    ihl: usize,
    l4: usize,
    l4_len: usize,
    proto: u8,
    pseudo: u32,
}

/// L3/L4 geometry of an Ethernet II frame whose L4 checksum the hardware
/// can generate or verify: an unfragmented IPv4 packet, or an IPv6 packet
/// without extension headers, whose IP length exactly fills the frame.
fn layout(eth: &[u8]) -> Option<Layout> {
    if eth.len() < ETH_HLEN {
        return None;
    }
    let ip = ETH_HLEN;
    match be16(eth, 12) {
        ETH_P_IP => {
            if eth.len() < ip + 20 || eth[ip] >> 4 != 4 {
                return None;
            }
            let ihl = usize::from(eth[ip] & 0x0f) * 4;
            let total = usize::from(be16(eth, ip + 2));
            if ihl < 20 || total < ihl || ip + total != eth.len() || be16(eth, ip + 6) & 0x3fff != 0
            {
                return None;
            }
            Some(Layout {
                ipv4: true,
                ihl,
                l4: ip + ihl,
                l4_len: total - ihl,
                proto: eth[ip + 9],
                pseudo: sum16(&eth[ip + 12..ip + 20]),
            })
        }
        ETH_P_IPV6 => {
            if eth.len() < ip + 40 || eth[ip] >> 4 != 6 {
                return None;
            }
            let len = usize::from(be16(eth, ip + 4));
            if len == 0 || ip + 40 + len != eth.len() {
                return None;
            }
            Some(Layout {
                ipv4: false,
                ihl: 40,
                l4: ip + 40,
                l4_len: len,
                proto: eth[ip + 6],
                pseudo: sum16(&eth[ip + 8..ip + 40]),
            })
        }
        _ => None,
    }
}

/// Offset of the L4 checksum field after validating the L4 header against
/// the requested kind.
fn l4_field(eth: &[u8], l: &Layout, kind: L4CsumKind) -> Option<usize> {
    match (l.proto, kind) {
        (IPPROTO_TCP, L4CsumKind::Tcp) => {
            if l.l4_len < 20 {
                return None;
            }
            let doff = usize::from(eth[l.l4 + 12] >> 4) * 4;
            (20..=l.l4_len).contains(&doff).then_some(l.l4 + 16)
        }
        (IPPROTO_UDP, L4CsumKind::Udp) => {
            (l.l4_len >= 8 && usize::from(be16(eth, l.l4 + 4)) == l.l4_len).then_some(l.l4 + 6)
        }
        _ => None,
    }
}

/// Prepare a `CHECKSUM_PARTIAL` Ethernet frame for firmware L4 checksum
/// generation and return the `offload_assist` checksum bits (without the
/// MAC-header size / pad bits, which the queue owner adds for every frame).
///
/// Like `iwl_mvm_tx_csum`, the L4 checksum field is reset to zero, the IP
/// header offset is the 8-byte SNAP header (4 words) and the L3 checksum is
/// only requested for A-MSDU, which this station profile never builds.
/// `None` means no offload was requested. A refused request is an error and
/// the frame must not be transmitted.
pub fn prepare_tx(eth: &mut [u8], kind: Option<L4CsumKind>) -> Result<u32, &'static str> {
    let Some(kind) = kind else {
        return Ok(0);
    };
    let l = layout(eth).ok_or("Intel TX checksum request has unsupported L3 layout")?;
    let field = l4_field(eth, &l, kind).ok_or("Intel TX checksum request has mismatched L4")?;
    eth[field..field + 2].copy_from_slice(&[0, 0]);
    Ok(1 << OFFLD_L4_EN | SNAP_WORDS << OFFLD_IP_HDR)
}

/// Validate a TX metadata request for this offload contract without
/// changing the frame. Used before an Ethernet frame is queued.
pub fn tx_admissible(eth: &[u8], meta: narf_net::TxMeta) -> bool {
    meta.tso_mss.is_none()
        && meta.vlan_tag.is_none()
        && meta
            .csum_l4
            .is_none_or(|kind| layout(eth).is_some_and(|l| l4_field(eth, &l, kind).is_some()))
}

/// Pre-AX210 verdict from the MQ descriptor `l3l4_flags`
/// (`iwl_mvm_rx_csum`): TCP/UDP checksum OK and either the IPv4 header
/// checksum OK or an IPv6 packet. The firmware's L3 classification must
/// match the delivered EtherType; the ring contract reports `csum_l4` only
/// for a whole TCP/UDP packet and `csum_l3` only for IPv4.
pub fn rx_meta_l3l4(flags: u16, eth: &[u8]) -> RxMeta {
    let mut meta = RxMeta::default();
    let l3 = (flags >> L3_PROTO_POS) & 0xf;
    if flags & L3L4_TCP_UDP_CSUM_OK == 0 {
        return meta;
    }
    let Some(l) = layout(eth) else {
        return meta;
    };
    if l.proto != IPPROTO_TCP && l.proto != IPPROTO_UDP {
        return meta;
    }
    let ok = if l.ipv4 {
        l3 == L3_TYPE_IPV4 && flags & L3L4_IP_HDR_CSUM_OK != 0
    } else {
        matches!(l3, L3_TYPE_IPV6 | L3_TYPE_IPV6_FRAG)
    };
    if ok {
        meta.csum_l3 = l.ipv4;
        meta.csum_l4 = true;
    }
    meta
}

/// AX210+ verdict from a `CHECKSUM_COMPLETE` raw one's-complement sum.
///
/// `raw` is the descriptor's big-endian `raw_xsum`; Linux uses
/// `csum_unfold(~raw)` as the sum of the bytes following the MAC header.
/// Pre-Bz hardware starts after the SNAP header, while Bz and later include
/// it (`iwl_mvm_create_skb`: "mac80211 assumes full CSUM including SNAP").
/// The verdict is derived like `__skb_checksum_validate_complete`: remove
/// the SNAP and IP header contributions, add the pseudo header and require
/// the folded total to be `0xffff`. A raw sum covering different bytes
/// therefore fails closed instead of claiming verification.
pub fn rx_meta_complete(raw: u16, includes_snap: bool, eth: &[u8]) -> RxMeta {
    let mut meta = RxMeta::default();
    let Some(l) = layout(eth) else {
        return meta;
    };
    if l.proto != IPPROTO_TCP && l.proto != IPPROTO_UDP {
        return meta;
    }
    let ip = &eth[ETH_HLEN..ETH_HLEN + l.ihl];
    let header = fold(sum16(ip));
    if l.ipv4 && header != 0xffff {
        return meta;
    }
    // Total covered sum, then remove the SNAP/EtherType words when present.
    let mut total = u32::from(!raw);
    if includes_snap {
        let snap = fold(0xaaaa + 0x0300 + u32::from(be16(eth, 12)));
        total += u32::from(!snap);
    }
    // Remove the IP header (its IPv4 sum is 0xffff == -0 and IPv6 has no
    // header checksum, so subtract its actual word sum).
    total += u32::from(!header);
    let pseudo = l.pseudo + u32::from(l.proto) + l.l4_len as u32;
    if fold(fold(total) as u32 + u32::from(fold(pseudo))) == 0xffff {
        meta.csum_l3 = l.ipv4;
        meta.csum_l4 = true;
    }
    meta
}

#[cfg(any(test, feature = "kernel-test"))]
pub(super) mod tests {
    use super::*;
    use alloc::{vec, vec::Vec};
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// IPv4/UDP or TCP test packet with a correct software checksum.
    pub(in crate::iwlwifi) fn ipv4(proto: u8, payload: &[u8]) -> Vec<u8> {
        let l4_header = if proto == IPPROTO_TCP { 20 } else { 8 };
        let l4_len = l4_header + payload.len();
        let total = 20 + l4_len;
        let mut b = vec![0u8; ETH_HLEN + total];
        b[..6].copy_from_slice(&[2, 4, 6, 8, 10, 12]);
        b[6..12].copy_from_slice(&[2; 6]);
        b[12..14].copy_from_slice(&ETH_P_IP.to_be_bytes());
        let ip = ETH_HLEN;
        b[ip] = 0x45;
        b[ip + 2..ip + 4].copy_from_slice(&(total as u16).to_be_bytes());
        b[ip + 8] = 64;
        b[ip + 9] = proto;
        b[ip + 12..ip + 16].copy_from_slice(&[10, 1, 1, 2]);
        b[ip + 16..ip + 20].copy_from_slice(&[10, 1, 1, 1]);
        let h = !fold(sum16(&b[ip..ip + 20]));
        b[ip + 10..ip + 12].copy_from_slice(&h.to_be_bytes());
        let l4 = ip + 20;
        b[l4..l4 + 2].copy_from_slice(&1234u16.to_be_bytes());
        b[l4 + 2..l4 + 4].copy_from_slice(&80u16.to_be_bytes());
        if proto == IPPROTO_TCP {
            b[l4 + 12] = 5 << 4;
        } else {
            b[l4 + 4..l4 + 6].copy_from_slice(&(l4_len as u16).to_be_bytes());
        }
        b[l4 + l4_header..].copy_from_slice(payload);
        let field = if proto == IPPROTO_TCP {
            l4 + 16
        } else {
            l4 + 6
        };
        let pseudo = sum16(&b[ip + 12..ip + 20]) + u32::from(proto) + l4_len as u32;
        let c = !fold(pseudo + sum16(&b[l4..]));
        b[field..field + 2].copy_from_slice(&c.to_be_bytes());
        b
    }

    fn ipv6_udp(payload: &[u8]) -> Vec<u8> {
        let l4_len = 8 + payload.len();
        let mut b = vec![0u8; ETH_HLEN + 40 + l4_len];
        b[12..14].copy_from_slice(&ETH_P_IPV6.to_be_bytes());
        let ip = ETH_HLEN;
        b[ip] = 0x60;
        b[ip + 4..ip + 6].copy_from_slice(&(l4_len as u16).to_be_bytes());
        b[ip + 6] = IPPROTO_UDP;
        b[ip + 7] = 64;
        b[ip + 8] = 0xfe;
        b[ip + 9] = 0x80;
        b[ip + 23] = 2;
        b[ip + 24] = 0xfe;
        b[ip + 25] = 0x80;
        b[ip + 39] = 1;
        let l4 = ip + 40;
        b[l4 + 4..l4 + 6].copy_from_slice(&(l4_len as u16).to_be_bytes());
        b[l4 + 8..].copy_from_slice(payload);
        let pseudo = sum16(&b[ip + 8..ip + 40]) + u32::from(IPPROTO_UDP) + l4_len as u32;
        let c = !fold(pseudo + sum16(&b[l4..]));
        b[l4 + 6..l4 + 8].copy_from_slice(&c.to_be_bytes());
        b
    }

    /// The raw sum the hardware reports for bytes after the MAC header.
    pub(in crate::iwlwifi) fn raw_after_header(eth: &[u8], includes_snap: bool) -> u16 {
        let mut s = sum16(&eth[ETH_HLEN..]);
        if includes_snap {
            s += 0xaaaa + 0x0300 + u32::from(be16(eth, 12));
        }
        !fold(s)
    }

    fn smoke_iwl_tx_checksum_offload_assist_matches_linux() -> TestResult {
        let mut udp = ipv4(IPPROTO_UDP, b"hello");
        match prepare_tx(&mut udp, Some(L4CsumKind::Udp)) {
            // L4_EN (bit 6) + IP header at 4 words after the MAC header.
            Ok(0x44) if udp[ETH_HLEN + 26..ETH_HLEN + 28] == [0, 0] => {}
            _ => return TestResult::Fail("UDP offload_assist or field reset differs"),
        }
        let mut tcp = ipv4(IPPROTO_TCP, b"x");
        if prepare_tx(&mut tcp, Some(L4CsumKind::Tcp)) != Ok(0x44)
            || tcp[ETH_HLEN + 36..ETH_HLEN + 38] != [0, 0]
        {
            return TestResult::Fail("TCP offload_assist or field reset differs");
        }
        let mut v6 = ipv6_udp(b"abc");
        if prepare_tx(&mut v6, Some(L4CsumKind::Udp)) != Ok(0x44) {
            return TestResult::Fail("IPv6 UDP offload refused");
        }
        let mut plain = ipv4(IPPROTO_UDP, b"z");
        let before = plain.clone();
        if prepare_tx(&mut plain, None) != Ok(0) || plain != before {
            return TestResult::Fail("frame without request changed");
        }
        // Mismatched kind, fragment and truncated length are refused and
        // leave the frame unchanged.
        let mut wrong = ipv4(IPPROTO_UDP, b"q");
        let original = wrong.clone();
        if prepare_tx(&mut wrong, Some(L4CsumKind::Tcp)).is_ok() || wrong != original {
            return TestResult::Fail("mismatched L4 kind accepted");
        }
        let mut frag = ipv4(IPPROTO_UDP, b"q");
        frag[ETH_HLEN + 6] = 0x20;
        if prepare_tx(&mut frag, Some(L4CsumKind::Udp)).is_ok()
            || tx_admissible(&frag, narf_net::TxMeta::with_csum(L4CsumKind::Udp))
        {
            return TestResult::Fail("IPv4 fragment accepted for L4 offload");
        }
        let mut short = ipv4(IPPROTO_UDP, b"q");
        short.pop();
        if prepare_tx(&mut short, Some(L4CsumKind::Udp)).is_ok() {
            return TestResult::Fail("truncated packet accepted");
        }
        if tx_admissible(&udp, narf_net::TxMeta::with_tso(1400))
            || !tx_admissible(&ipv4(6, b""), narf_net::TxMeta::with_csum(L4CsumKind::Tcp))
        {
            return TestResult::Fail("TSO accepted or valid TCP request refused");
        }
        TestResult::Pass
    }

    fn smoke_iwl_rx_l3l4_checksum_verdict_matches_linux() -> TestResult {
        let udp = ipv4(IPPROTO_UDP, b"data");
        let v4 = L3L4_TCP_UDP_CSUM_OK | L3L4_IP_HDR_CSUM_OK | L3_TYPE_IPV4 << 4;
        let m = rx_meta_l3l4(v4, &udp);
        if !m.csum_l3 || !m.csum_l4 {
            return TestResult::Fail("IPv4 CSUM_OK verdict not reported");
        }
        if rx_meta_l3l4(L3L4_TCP_UDP_CSUM_OK | L3_TYPE_IPV4 << 4, &udp) != RxMeta::default() {
            return TestResult::Fail("IPv4 without IP_HDR_CSUM_OK reported verified");
        }
        if rx_meta_l3l4(L3L4_IP_HDR_CSUM_OK | L3_TYPE_IPV4 << 4, &udp) != RxMeta::default() {
            return TestResult::Fail("missing TCP_UDP_CSUM_OK reported verified");
        }
        let v6 = ipv6_udp(b"data");
        let m = rx_meta_l3l4(L3L4_TCP_UDP_CSUM_OK | L3_TYPE_IPV6 << 4, &v6);
        if m.csum_l3 || !m.csum_l4 {
            return TestResult::Fail("IPv6 verdict differs from Linux");
        }
        // Firmware classification must agree with the delivered EtherType.
        if rx_meta_l3l4(L3L4_TCP_UDP_CSUM_OK | L3_TYPE_IPV6 << 4, &udp) != RxMeta::default() {
            return TestResult::Fail("mismatched L3 classification accepted");
        }
        let mut arp = udp.clone();
        arp[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
        if rx_meta_l3l4(v4, &arp) != RxMeta::default() {
            return TestResult::Fail("non-IP frame reported verified");
        }
        TestResult::Pass
    }

    fn smoke_iwl_rx_complete_checksum_verdict_fails_closed() -> TestResult {
        for proto in [IPPROTO_UDP, IPPROTO_TCP] {
            let p = ipv4(proto, b"complete-checksum");
            for snap in [false, true] {
                let m = rx_meta_complete(raw_after_header(&p, snap), snap, &p);
                if !m.csum_l3 || !m.csum_l4 {
                    return TestResult::Fail("valid CHECKSUM_COMPLETE not verified");
                }
                // Coverage mismatch (SNAP included or not) must fail closed.
                if rx_meta_complete(raw_after_header(&p, snap), !snap, &p) != RxMeta::default() {
                    return TestResult::Fail("raw sum with different coverage verified");
                }
            }
            let mut bad = p.clone();
            let last = bad.len() - 1;
            bad[last] ^= 0x40;
            if rx_meta_complete(raw_after_header(&bad, false), false, &bad) != RxMeta::default() {
                return TestResult::Fail("corrupted L4 payload verified");
            }
        }
        let v6 = ipv6_udp(b"six");
        let m = rx_meta_complete(raw_after_header(&v6, true), true, &v6);
        if m.csum_l3 || !m.csum_l4 {
            return TestResult::Fail("IPv6 CHECKSUM_COMPLETE verdict differs");
        }
        let mut badip = ipv4(IPPROTO_UDP, b"h");
        badip[ETH_HLEN + 8] ^= 1;
        if rx_meta_complete(raw_after_header(&badip, false), false, &badip) != RxMeta::default() {
            return TestResult::Fail("invalid IPv4 header verified");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/iwlwifi/csum",
        smoke_iwl_tx_checksum_offload_assist_matches_linux
    );
    kernel_test_in!(
        "drivers/wireless/iwlwifi/csum",
        smoke_iwl_rx_l3l4_checksum_verdict_matches_linux
    );
    kernel_test_in!(
        "drivers/wireless/iwlwifi/csum",
        smoke_iwl_rx_complete_checksum_verdict_fails_closed
    );
}
