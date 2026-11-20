//! Checksum offload between the stack's frame-ring contract
//! (`narf_net::TxMeta::csum_l4`, `narf_net::RxMeta`) and the TCL / RX
//! descriptor bits.
//!
//! | NARF | Linux |
//! |---|---|
//! | [`OFFLOADS`] | `ath11k_mac_register`: `hw->netdev_features = NETIF_F_HW_CSUM` (not raw mode) |
//! | [`csum_partial_prepare`] | an skb with `ip_summed == CHECKSUM_PARTIAL` (`tcp_v4_send_check` / `udp4_hwcsum`: the L4 checksum field holds the folded pseudo-header sum); `ath11k_dp_tx` then sets `HAL_TCL_DATA_CMD_INFO1_{IP4,UDP4,UDP6,TCP4,TCP6}_CKSUM_EN` |
//! | [`rx_meta`] | `ath11k_dp_rx_h_csum_offload`: `CHECKSUM_UNNECESSARY` unless the RX attention IP / L4 checksum-fail bit is set |
//!
//! NETIF_F_HW_CSUM lets Linux hand any `CHECKSUM_PARTIAL` skb to the
//! driver; NARF's contract (`net/specification/spec.md` §3.2) has the
//! driver validate the request instead: only an unfragmented IPv4 or
//! IPv6 (no extension header) TCP / UDP packet of the requested kind,
//! without an in-band VLAN tag, is accepted, and its seed is (re)written
//! here. Anything else is refused — never sent partially checksummed.

use narf_net::{L4CsumKind, OffloadCapabilities, RxMeta};

use super::dp_ring::ETH_HLEN;
use super::tx_hdr::{ETH_P_IP, ETH_P_IPV6};

/// What the netdev advertises (`NETIF_F_HW_CSUM`; no TSO — ath11k has
/// no `NETIF_F_TSO` — and no VLAN insertion). RX checksum results are
/// reported on the RX frame ring.
pub const OFFLOADS: OffloadCapabilities = OffloadCapabilities {
    tx_checksum: true,
    rx_checksum: true,
    max_tso_bytes: 0,
    vlan_insert: false,
};

const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
pub const EINVAL: i32 = 22;

fn be16(b: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([b[off], b[off + 1]])
}

fn sum16(b: &[u8]) -> u32 {
    b.chunks_exact(2)
        .map(|w| u16::from_be_bytes([w[0], w[1]]) as u32)
        .sum()
}

fn fold(mut s: u32) -> u16 {
    while s >> 16 != 0 {
        s = (s & 0xffff) + (s >> 16);
    }
    s as u16
}

/// The L3 / L4 layout of an Ethernet frame the hardware can checksum:
/// `(ipv4, l4 offset, l4 length, protocol, pseudo-header sum without
/// the length)`.
fn layout(eth: &[u8]) -> Option<(bool, usize, usize, u8, u32)> {
    if eth.len() < ETH_HLEN {
        return None;
    }
    let ip = ETH_HLEN;
    match be16(eth, 12) {
        ETH_P_IP => {
            if eth.len() < ip + 20 || eth[ip] >> 4 != 4 {
                return None;
            }
            let ihl = (eth[ip] & 0x0f) as usize * 4;
            let total = be16(eth, ip + 2) as usize;
            // MF set or a fragment offset: the L4 header is not whole.
            if ihl < 20 || total < ihl || ip + total != eth.len() || be16(eth, ip + 6) & 0x3fff != 0
            {
                return None;
            }
            Some((
                true,
                ip + ihl,
                total - ihl,
                eth[ip + 9],
                sum16(&eth[ip + 12..ip + 20]),
            ))
        }
        ETH_P_IPV6 => {
            if eth.len() < ip + 40 || eth[ip] >> 4 != 6 {
                return None;
            }
            let len = be16(eth, ip + 4) as usize;
            // Jumbograms and extension headers are left to software.
            if len == 0 || ip + 40 + len != eth.len() {
                return None;
            }
            Some((
                false,
                ip + 40,
                len,
                eth[ip + 6],
                sum16(&eth[ip + 8..ip + 40]),
            ))
        }
        _ => None,
    }
}

/// `CHECKSUM_PARTIAL` for an Ethernet frame: validate it against the
/// requested L4 kind and write the folded (uncomplemented)
/// pseudo-header sum — what `tcp_v4_send_check` / `__tcp_v6_send_check`
/// / `udp4_hwcsum` leave in the checksum field — so the TCL engine
/// completes it. `Err(EINVAL)` = refused (the stack must checksum it).
pub fn csum_partial_prepare(eth: &mut [u8], kind: L4CsumKind) -> Result<(), i32> {
    let (_, l4, l4_len, proto, sum) = layout(eth).ok_or(EINVAL)?;
    let field = match (proto, kind) {
        (IPPROTO_TCP, L4CsumKind::Tcp) => {
            if l4_len < 20 {
                return Err(EINVAL);
            }
            let doff = (eth[l4 + 12] >> 4) as usize * 4;
            if doff < 20 || doff > l4_len {
                return Err(EINVAL);
            }
            l4 + 16
        }
        (IPPROTO_UDP, L4CsumKind::Udp) => {
            if l4_len < 8 || be16(eth, l4 + 4) as usize != l4_len {
                return Err(EINVAL);
            }
            l4 + 6
        }
        _ => return Err(EINVAL),
    };
    let seed = fold(sum + proto as u32 + l4_len as u32);
    eth[field..field + 2].copy_from_slice(&seed.to_be_bytes());
    Ok(())
}

/// The RX frame ring's checksum verdict for a delivered Ethernet II
/// frame. `csum_ok` is `ath11k_dp_rx_h_csum_offload`'s
/// `CHECKSUM_UNNECESSARY` (neither attention fail bit set). The ring
/// contract is narrower than an skb's `ip_summed`: `csum_l3` only for
/// an IPv4 header, `csum_l4` only for a TCP / UDP packet the hardware
/// parsed whole (unfragmented, no IPv6 extension header).
pub fn rx_meta(eth: &[u8], csum_ok: bool) -> RxMeta {
    let mut m = RxMeta::default();
    if !csum_ok {
        return m;
    }
    if eth.len() >= ETH_HLEN + 20 && be16(eth, 12) == ETH_P_IP && eth[ETH_HLEN] >> 4 == 4 {
        m.csum_l3 = true;
    }
    if let Some((_, _, _, proto, _)) = layout(eth) {
        m.csum_l4 = proto == IPPROTO_TCP || proto == IPPROTO_UDP;
    }
    m
}
