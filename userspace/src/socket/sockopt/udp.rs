//! `SOL_UDP` socket options for AF_INET / AF_INET6 UDP sockets:
//! `udp_lib_setsockopt` / `udp_lib_getsockopt` (`net/ipv4/udp.c`), reached
//! from `udp_setsockopt` and `udpv6_setsockopt` alike.
//!
//! Modelled: `UDP_SEGMENT` (the socket's default GSO size), `UDP_GRO`
//! (accept coalesced GSO datagrams and report `UDP_GRO` cmsgs) and
//! `UDP_NO_CHECK6_TX` (zero IPv6 UDP checksums; refused by GSO sends).
//! `UDP_CORK`, `UDP_ENCAP` and `UDP_NO_CHECK6_RX` are not modelled — NARF has
//! no UDP corking, no encapsulation receive hooks and no per-socket IPv6
//! zero-checksum acceptance — so setting them stays -ENOPROTOOPT; reading
//! them reports their (never changed) default 0, as Linux does.

use super::*;

/// `include/uapi/linux/udp.h`.
pub const UDP_CORK: u32 = 1;
pub const UDP_ENCAP: u32 = 100;
pub const UDP_NO_CHECK6_TX: u32 = 101;
pub const UDP_NO_CHECK6_RX: u32 = 102;
pub const UDP_SEGMENT: u32 = narf_net::udp_gso::UDP_SEGMENT;
pub const UDP_GRO: u32 = narf_net::udp_gso::UDP_GRO;
/// `include/net/udplite.h`.
pub const UDPLITE_SEND_CSCOV: u32 = 10;
pub const UDPLITE_RECV_CSCOV: u32 = 11;

impl SocketFile {
    /// A UDP socket (`udp_prot` / `udpv6_prot`): the SOL_UDP level belongs
    /// to it. An AF_INET ICMP datagram socket (`ping_prot`) is SOCK_DGRAM
    /// too but hands SOL_UDP to `ip_setsockopt`.
    pub(crate) fn is_udp(&self) -> bool {
        matches!(self.domain, AF_INET | AF_INET6)
            && self.kind == SOCK_DGRAM
            && self.protocol == IPPROTO_UDP
    }

    /// `udp_lib_setsockopt` for `level == SOL_UDP`.
    pub(super) fn udp_set(&self, name: u32, value: &[u8]) -> SocketOpResult {
        // `if (optlen < sizeof(int)) return -EINVAL;` precedes the switch,
        // so it applies to unknown options too.
        if value.len() < 4 {
            return EINVAL_R;
        }
        let val = i32::from_ne_bytes([value[0], value[1], value[2], value[3]]);
        let on = val != 0;
        match name {
            UDP_SEGMENT => {
                // `if (val < 0 || val > USHRT_MAX) return -EINVAL;`
                if !(0..=i32::from(u16::MAX)).contains(&val) {
                    return EINVAL_R;
                }
                self.options.lock().ext.udp_gso_size = val as u16;
                OK
            }
            UDP_GRO => {
                // GRO_ENABLED and ACCEPT_L4 follow the same bit.
                self.options.lock().ext.udp_gro = on;
                OK
            }
            UDP_NO_CHECK6_TX => {
                self.options.lock().ext.udp_no_check6_tx = on;
                OK
            }
            // `UDPLITE_*_CSCOV`: `if (!is_udplite) return -ENOPROTOOPT;`.
            // UDP_CORK / UDP_ENCAP / UDP_NO_CHECK6_RX: not modelled (see the
            // module docs); everything else is the switch's default.
            _ => ENOPROTOOPT_R,
        }
    }

    /// `udp_lib_getsockopt`: `len = min(len, sizeof(int))` bytes of the
    /// value (the caller already rejected a negative length).
    pub(super) fn udp_get(&self, name: u32, buf: &mut [u8]) -> SocketOpResult {
        let o = self.options.lock();
        let val: i32 = match name {
            UDP_SEGMENT => i32::from(o.ext.udp_gso_size),
            UDP_GRO => i32::from(o.ext.udp_gro),
            UDP_NO_CHECK6_TX => i32::from(o.ext.udp_no_check6_tx),
            // Never settable here, so their defaults: `udp_test_bit(CORK)`,
            // `up->encap_type`, `udp_get_no_check6_rx`, `up->pcslen` and
            // `up->pcrlen` are all 0 on a UDP socket.
            UDP_CORK | UDP_ENCAP | UDP_NO_CHECK6_RX | UDPLITE_SEND_CSCOV | UDPLITE_RECV_CSCOV => 0,
            _ => return ENOPROTOOPT_R,
        };
        drop(o);
        put_int(buf, val)
    }
}
