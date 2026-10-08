//! `SOL_IPV6` socket options — split out of the parent `sockopt` module with no
//! behaviour change. Dispatch, shared helpers, and option-name constants stay
//! in `sockopt.rs`; this file holds just the IPV6_* set/get methods.

use super::*;

impl SocketFile {
    pub(super) fn ipv6_set(&self, name: u32, value: &[u8]) -> Option<SocketOpResult> {
        let val = ip6_val(value);
        let on = val != 0;
        let short = value.len() < 4;
        let ns = self.net_ns_id();
        let mut o = self.options.lock();
        let r = match name {
            super::IPV6_UNICAST_HOPS => {
                if short || !(-1..=255).contains(&val) {
                    return Some(EINVAL_R);
                }
                o.ipv6_unicast_hops = val;
                OK
            }
            IPV6_MULTICAST_LOOP => {
                if short || (val != 0 && val != 1) {
                    return Some(EINVAL_R);
                }
                o.ext.ipv6_mc_loop = on;
                OK
            }
            IPV6_MULTICAST_HOPS => {
                if self.kind == SOCK_STREAM {
                    return Some(ENOPROTOOPT_R);
                }
                if short || !(-1..=255).contains(&val) {
                    return Some(EINVAL_R);
                }
                o.ext.ipv6_mcast_hops = if val == -1 {
                    IPV6_DEFAULT_MCASTHOPS
                } else {
                    val
                };
                OK
            }
            super::IPV6_MTU => {
                if short || (val != 0 && val < IPV6_MIN_MTU) {
                    return Some(EINVAL_R);
                }
                o.ipv6_mtu_set = val != 0;
                if val != 0 {
                    o.ipv6_mtu = val as u32;
                }
                OK
            }
            IPV6_MINHOPCOUNT => {
                if short || !(0..=255).contains(&val) {
                    return Some(EINVAL_R);
                }
                // LINUX-GAP: IPV6_MINHOPCOUNT — stored and reported; received
                // packets are not filtered by hop limit.
                o.ext.ipv6_minhopcount = val;
                OK
            }
            IPV6_RECVERR_RFC4884 => {
                if short || !(0..=1).contains(&val) {
                    return Some(EINVAL_R);
                }
                o.ext.ipv6_recverr_rfc4884 = on;
                OK
            }
            IPV6_MULTICAST_ALL => {
                if short {
                    return Some(EINVAL_R);
                }
                o.ext.ipv6_mc_all = on;
                OK
            }
            IPV6_AUTOFLOWLABEL => {
                // LINUX-GAP: IPV6_AUTOFLOWLABEL — stored and reported; NARF
                // sends flow label 0.
                o.ext.ipv6_autoflowlabel = Some(on);
                OK
            }
            super::IPV6_DONTFRAG => {
                o.ipv6_dontfrag = on;
                OK
            }
            super::IPV6_RECVERR => {
                if short {
                    return Some(EINVAL_R);
                }
                o.ipv6_recverr = on;
                OK
            }
            IPV6_ROUTER_ALERT_ISOLATE => {
                if short {
                    return Some(EINVAL_R);
                }
                o.ext.ipv6_router_alert_isolate = on;
                OK
            }
            super::IPV6_MTU_DISCOVER => {
                if short || !(0..=IPV6_PMTUDISC_OMIT).contains(&val) {
                    return Some(EINVAL_R);
                }
                o.ipv6_mtu_discover = val as u32;
                OK
            }
            IPV6_FLOWINFO_SEND => {
                if short {
                    return Some(EINVAL_R);
                }
                o.ext.ipv6_flowinfo_send = on;
                OK
            }
            IPV6_ADDR_PREFERENCES => {
                if short {
                    return Some(EINVAL_R);
                }
                match addr_preferences(o.ext.ipv6_srcprefs, val as u32) {
                    Some(p) => {
                        // LINUX-GAP: ip6_sock_set_addr_preferences — stored and
                        // reported; source selection does not consult it.
                        o.ext.ipv6_srcprefs = p;
                        OK
                    }
                    None => EINVAL_R,
                }
            }
            IPV6_MULTICAST_IF => {
                if self.kind == SOCK_STREAM {
                    return Some(ENOPROTOOPT_R);
                }
                if short {
                    return Some(EINVAL_R);
                }
                if val != 0 {
                    if !ifindex_exists(ns, val as u32) {
                        return Some(SocketOpResult::Err(SockError::NoDevice));
                    }
                    let bound = o.bindtodevice_index;
                    if bound != 0 && bound != val as u32 {
                        return Some(EINVAL_R);
                    }
                }
                o.ext.ipv6_mcast_oif = val as u32;
                OK
            }
            IPV6_UNICAST_IF => {
                if value.len() != 4 {
                    return Some(EINVAL_R);
                }
                let ifindex = u32::from_be(val as u32);
                if ifindex == 0 {
                    o.ext.ipv6_ucast_oif = 0;
                    return Some(OK);
                }
                if !ifindex_exists(ns, ifindex) {
                    return Some(SocketOpResult::Err(SockError::AddrNotAvail));
                }
                if o.bindtodevice_index != 0 {
                    return Some(EINVAL_R);
                }
                o.ext.ipv6_ucast_oif = ifindex;
                OK
            }
            // The socket-locked switch: every option but the sticky
            // headers requires a full int.
            super::IPV6_RECVPKTINFO
            | IPV6_2292PKTINFO
            | super::IPV6_RECVHOPLIMIT
            | IPV6_2292HOPLIMIT
            | IPV6_RECVRTHDR
            | IPV6_2292RTHDR
            | IPV6_RECVHOPOPTS
            | IPV6_2292HOPOPTS
            | IPV6_RECVDSTOPTS
            | IPV6_2292DSTOPTS
            | IPV6_RECVTCLASS
            | IPV6_FLOWINFO
            | IPV6_RECVPATHMTU
            | IPV6_RECVORIGDSTADDR => {
                if short {
                    return Some(EINVAL_R);
                }
                // LINUX-GAP: do_ipv6_setsockopt rxopt bits — stored and
                // reported; only IPV6_PKTINFO / IPV6_HOPLIMIT / IPV6_TCLASS
                // cmsgs are generated on receive.
                match name {
                    super::IPV6_RECVPKTINFO => o.ipv6_recvpktinfo = on,
                    super::IPV6_RECVHOPLIMIT => o.ipv6_recvhoplimit = on,
                    IPV6_2292PKTINFO => o.ext.ipv6_2292pktinfo = on,
                    IPV6_2292HOPLIMIT => o.ext.ipv6_2292hoplimit = on,
                    IPV6_RECVRTHDR => o.ext.ipv6_recvrthdr = on,
                    IPV6_2292RTHDR => o.ext.ipv6_2292rthdr = on,
                    IPV6_RECVHOPOPTS => o.ext.ipv6_recvhopopts = on,
                    IPV6_2292HOPOPTS => o.ext.ipv6_2292hopopts = on,
                    IPV6_RECVDSTOPTS => o.ext.ipv6_recvdstopts = on,
                    IPV6_2292DSTOPTS => o.ext.ipv6_2292dstopts = on,
                    IPV6_RECVTCLASS => o.ext.ipv6_recvtclass = on,
                    IPV6_FLOWINFO => o.ext.ipv6_flowinfo = on,
                    IPV6_RECVPATHMTU => o.ext.ipv6_recvpathmtu = on,
                    _ => o.ext.ipv6_recvorigdstaddr = on,
                }
                OK
            }
            IPV6_TCLASS => {
                if short || !(-1..=0xff).contains(&val) {
                    return Some(EINVAL_R);
                }
                let mut v = if val == -1 { 0 } else { val };
                if self.kind == SOCK_STREAM {
                    v = (v & !3) | (o.ext.ipv6_tclass & 3);
                }
                // LINUX-GAP: IPV6_TCLASS — stored and reported; the IPv6
                // output path sends traffic class 0.
                o.ext.ipv6_tclass = v;
                OK
            }
            IPV6_TRANSPARENT => {
                if on && !net_raw_or_admin() {
                    return Some(EPERM_R);
                }
                if short {
                    return Some(EINVAL_R);
                }
                // Shares the IPv4 socket's TRANSPARENT bit.
                o.ext.ip_transparent = on;
                OK
            }
            IPV6_FREEBIND => {
                if short {
                    return Some(EINVAL_R);
                }
                // Shares the IPv4 socket's FREEBIND bit.
                o.ip_freebind = on;
                OK
            }
            super::IPV6_PKTINFO => {
                if value.len() < 20 {
                    return Some(EINVAL_R);
                }
                let ifindex = read_u32_at(value, 16);
                // `sk_dev_equal_l3scope`: no L3 masters, so a bound socket
                // only accepts its own device.
                let bound = o.bindtodevice_index;
                if bound != 0 && bound != ifindex {
                    return Some(EINVAL_R);
                }
                // LINUX-GAP: sticky IPV6_PKTINFO — stored; the IPv6 output
                // path does not use it for source/interface selection.
                o.ext.ipv6_sticky_pktinfo = (read_in6_at(value, 0), ifindex);
                OK
            }
            IPV6_ADD_MEMBERSHIP | IPV6_DROP_MEMBERSHIP => {
                if value.len() < 20 {
                    return Some(EINVAL_R);
                }
                if self.is_tcp() {
                    return Some(errno_err(errno::EPROTO));
                }
                drop(o);
                return Some(self.ipv6_mc_join_leave(
                    name == IPV6_ADD_MEMBERSHIP,
                    read_in6_at(value, 0),
                    read_u32_at(value, 16),
                ));
            }
            MCAST_JOIN_GROUP | MCAST_LEAVE_GROUP => {
                if value.len() < GROUP_REQ_LEN {
                    return Some(EINVAL_R);
                }
                let ifindex = read_u32_at(value, 0);
                let family = u16::from_ne_bytes([value[8], value[9]]);
                if family != AF_INET6 {
                    return Some(SocketOpResult::Err(SockError::AddrNotAvail));
                }
                let group = read_in6_at(value, 16);
                drop(o);
                return Some(self.ipv6_mc_join_leave(name == MCAST_JOIN_GROUP, group, ifindex));
            }
            IPV6_ROUTER_ALERT => {
                if short {
                    return Some(EINVAL_R);
                }
                // `ip6_ra_control`.
                if self.kind != SOCK_RAW || self.protocol != IPPROTO_RAW {
                    return Some(ENOPROTOOPT_R);
                }
                // LINUX-GAP: ip6_ra_control — recorded; router-alert packets
                // are not queued to the socket.
                o.ext.ipv6_router_alert = on;
                OK
            }
            IPV6_IPSEC_POLICY | IPV6_XFRM_POLICY => {
                if !capable(crate::handlers::CAP_NET_ADMIN) {
                    return Some(EPERM_R);
                }
                // LINUX-GAP: xfrm_user_policy — no IPsec (CONFIG_XFRM=n).
                ENOPROTOOPT_R
            }
            IPV6_RECVFRAGSIZE => {
                // No optlen check on this one (do_ipv6_setsockopt).
                o.ext.ipv6_recvfragsize = on;
                OK
            }
            _ => return None,
        };
        Some(r)
    }

    /// `__ipv6_sock_mc_join` / `ipv6_sock_mc_drop`.
    fn ipv6_mc_join_leave(&self, join: bool, group: [u8; 16], ifindex: u32) -> SocketOpResult {
        if !is_multicast_v6(&group) {
            return EINVAL_R;
        }
        let ns = self.net_ns_id();
        let matches =
            |m: &Ip6McMembership| (ifindex == 0 || m.ifindex == ifindex) && m.group == group;
        if join {
            if self.options.lock().ext.ipv6_mc_list.iter().any(matches) {
                return SocketOpResult::Err(SockError::AddrInUse);
            }
            // `ip6_mc_find_dev`.
            let dev = if ifindex == 0 {
                route_dev_v6(ns)
            } else if ifindex_exists(ns, ifindex) {
                Some(ifindex)
            } else {
                None
            };
            let Some(dev) = dev else {
                return SocketOpResult::Err(SockError::NoDevice);
            };
            self.options.lock().ext.ipv6_mc_list.insert(
                0,
                Ip6McMembership {
                    group,
                    ifindex: dev,
                },
            );
            mc_inc_v6(ns, dev, group);
            return OK;
        }
        let mut o = self.options.lock();
        let list = &mut o.ext.ipv6_mc_list;
        match list.iter().position(matches) {
            Some(i) => {
                let m = list.remove(i);
                drop(o);
                mc_dec_v6(ns, m.ifindex, m.group);
                OK
            }
            None => SocketOpResult::Err(SockError::AddrNotAvail),
        }
    }

    pub(super) fn ipv6_get(&self, name: u32, buf: &mut [u8]) -> Option<SocketOpResult> {
        let o = self.options.lock();
        let v = match name {
            IPV6_ADDRFORM => {
                if !matches!(self.protocol, IPPROTO_UDP | IPPROTO_TCP | 0)
                    || !matches!(self.kind, SOCK_STREAM | SOCK_DGRAM)
                {
                    return Some(ENOPROTOOPT_R);
                }
                drop(o);
                if !self.is_established() {
                    return Some(SocketOpResult::Err(SockError::NotConnected));
                }
                i32::from(AF_INET6)
            }
            IPV6_PATHMTU => {
                // `struct ip6_mtuinfo { sockaddr_in6; u32 mtu }`.
                if buf.len() < 32 {
                    return Some(EINVAL_R);
                }
                let mtu = if o.ipv6_mtu_set { o.ipv6_mtu } else { 1500 };
                drop(o);
                if !self.is_established() {
                    return Some(SocketOpResult::Err(SockError::NotConnected));
                }
                // LINUX-GAP: IPV6_PATHMTU — NARF keeps no per-destination
                // PMTU cache; the address is left zero and the MTU is the
                // socket's IPV6_MTU or the link default.
                let mut info = [0u8; 32];
                info[0..2].copy_from_slice(&AF_INET6.to_ne_bytes());
                info[28..32].copy_from_slice(&mtu.to_ne_bytes());
                return Some(put_bytes(buf, &info));
            }
            IPV6_2292PKTOPTIONS => {
                if self.kind != SOCK_STREAM {
                    return Some(ENOPROTOOPT_R);
                }
                // LINUX-GAP: IPV6_2292PKTOPTIONS — no cmsgs are synthesised.
                return Some(SocketOpResult::OptValue { n: 0 });
            }
            super::IPV6_UNICAST_HOPS => {
                if o.ipv6_unicast_hops < 0 {
                    IPV6_DEFAULT_HOPLIMIT
                } else {
                    o.ipv6_unicast_hops
                }
            }
            IPV6_MULTICAST_HOPS => o.ext.ipv6_mcast_hops,
            IPV6_MULTICAST_LOOP => o.ext.ipv6_mc_loop as i32,
            IPV6_MULTICAST_IF => o.ext.ipv6_mcast_oif as i32,
            IPV6_MULTICAST_ALL => o.ext.ipv6_mc_all as i32,
            IPV6_UNICAST_IF => o.ext.ipv6_ucast_oif.to_be() as i32,
            super::IPV6_MTU_DISCOVER => o.ipv6_mtu_discover as i32,
            super::IPV6_RECVERR => o.ipv6_recverr as i32,
            IPV6_FLOWINFO_SEND => o.ext.ipv6_flowinfo_send as i32,
            super::IPV6_RECVPKTINFO => o.ipv6_recvpktinfo as i32,
            IPV6_2292PKTINFO => o.ext.ipv6_2292pktinfo as i32,
            super::IPV6_RECVHOPLIMIT => o.ipv6_recvhoplimit as i32,
            IPV6_2292HOPLIMIT => o.ext.ipv6_2292hoplimit as i32,
            IPV6_RECVRTHDR => o.ext.ipv6_recvrthdr as i32,
            IPV6_2292RTHDR => o.ext.ipv6_2292rthdr as i32,
            IPV6_RECVHOPOPTS => o.ext.ipv6_recvhopopts as i32,
            IPV6_2292HOPOPTS => o.ext.ipv6_2292hopopts as i32,
            IPV6_RECVDSTOPTS => o.ext.ipv6_recvdstopts as i32,
            IPV6_2292DSTOPTS => o.ext.ipv6_2292dstopts as i32,
            IPV6_TCLASS => o.ext.ipv6_tclass,
            IPV6_RECVTCLASS => o.ext.ipv6_recvtclass as i32,
            IPV6_FLOWINFO => o.ext.ipv6_flowinfo as i32,
            IPV6_RECVPATHMTU => o.ext.ipv6_recvpathmtu as i32,
            IPV6_TRANSPARENT => o.ext.ip_transparent as i32,
            IPV6_FREEBIND => o.ip_freebind as i32,
            IPV6_RECVORIGDSTADDR => o.ext.ipv6_recvorigdstaddr as i32,
            IPV6_ADDR_PREFERENCES => {
                let p = o.ext.ipv6_srcprefs;
                let mut v = if p & PREFER_SRC_TMP != 0 {
                    PREFER_SRC_TMP
                } else if p & PREFER_SRC_PUBLIC != 0 {
                    PREFER_SRC_PUBLIC
                } else {
                    PREFER_SRC_PUBTMP_DEFAULT
                };
                v |= if p & PREFER_SRC_COA != 0 {
                    PREFER_SRC_COA
                } else {
                    PREFER_SRC_HOME
                };
                v as i32
            }
            IPV6_MINHOPCOUNT => o.ext.ipv6_minhopcount,
            super::IPV6_DONTFRAG => o.ipv6_dontfrag as i32,
            // `ip6_autoflowlabel`: net.ipv6.auto_flowlabels defaults to
            // IP6_AUTO_FLOW_LABEL_OPTOUT, i.e. on.
            IPV6_AUTOFLOWLABEL => o.ext.ipv6_autoflowlabel.unwrap_or(true) as i32,
            IPV6_RECVFRAGSIZE => o.ext.ipv6_recvfragsize as i32,
            IPV6_ROUTER_ALERT => o.ext.ipv6_router_alert as i32,
            IPV6_ROUTER_ALERT_ISOLATE => o.ext.ipv6_router_alert_isolate as i32,
            IPV6_RECVERR_RFC4884 => o.ext.ipv6_recverr_rfc4884 as i32,
            _ => return None,
        };
        // `len = min_t(unsigned int, sizeof(int), len)`: no one-byte form.
        Some(put_int(buf, v))
    }
}
