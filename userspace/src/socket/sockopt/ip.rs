//! `SOL_IP` socket options — split out of the parent `sockopt` module with no
//! behaviour change. Dispatch, shared helpers, and option-name constants stay
//! in `sockopt.rs`; this file holds just the IP_* set/get methods.

use super::*;

impl SocketFile {
    pub(super) fn ip_set(&self, name: u32, value: &[u8]) -> Option<SocketOpResult> {
        let val = ip_val(value);
        let on = val != 0;
        let short = value.is_empty();
        if name == IP_ROUTER_ALERT {
            // `ip_ra_control`.
            if self.kind != SOCK_RAW || self.protocol == IPPROTO_RAW {
                return Some(EINVAL_R);
            }
            // LINUX-GAP: ip_ra_control — recorded; router-alert packets are
            // not queued to the socket.
            self.options.lock().ext.ip_router_alert = on;
            return Some(OK);
        }
        if (MRT_BASE..=MRT_MAX).contains(&name) {
            // `ip_mroute_setsockopt`.
            if self.kind != SOCK_RAW || self.protocol != IPPROTO_IGMP {
                return Some(EOPNOTSUPP_R);
            }
            // LINUX-GAP: ip_mroute_setsockopt — NARF has no multicast
            // routing table.
            return Some(ENOPROTOOPT_R);
        }
        let mut o = self.options.lock();
        let r = match name {
            IP_PKTINFO => {
                drop(o);
                self.options.lock().ip_pktinfo = on;
                return Some(OK);
            }
            IP_RECVTTL => {
                drop(o);
                self.options.lock().ip_recvttl = on;
                return Some(OK);
            }
            IP_RECVTOS => {
                // recvmsg returns an IP_TOS cmsg (`ip_cmsg_recv_tos`).
                o.ext.ip_recvtos = on;
                OK
            }
            IP_RECVOPTS | IP_RETOPTS | IP_PASSSEC | IP_RECVORIGDSTADDR => {
                // recvmsg returns IP_ORIGDSTADDR for every datagram. Linux
                // writes IP_RECVOPTS / IP_RETOPTS only for a packet carrying
                // IP options and IP_PASSSEC only with an LSM peer label —
                // neither of which NARF's IPv4 receive path produces — so
                // like Linux for such packets they yield no cmsg.
                match name {
                    IP_RECVOPTS => o.ext.ip_recvopts = on,
                    IP_RETOPTS => o.ext.ip_retopts = on,
                    IP_PASSSEC => o.ext.ip_passsec = on,
                    _ => o.ext.ip_origdstaddr = on,
                }
                OK
            }
            IP_RECVFRAGSIZE => {
                if !matches!(self.kind, SOCK_RAW | SOCK_DGRAM) {
                    return Some(EINVAL_R);
                }
                // LINUX-GAP: do_ip_setsockopt IP_RECVFRAGSIZE — stored; no
                // IP_RECVFRAGSIZE cmsg (NARF does not reassemble fragments
                // for userspace sockets).
                o.ext.ip_recvfragsize = on;
                OK
            }
            IP_RECVERR => {
                // LINUX-GAP: do_ip_setsockopt IP_RECVERR — stored and
                // reported; NARF keeps no ICMP error queue, so MSG_ERRQUEUE
                // stays empty.
                o.ext.ip_recverr = on;
                OK
            }
            IP_RECVERR_RFC4884 => {
                if !(0..=1).contains(&val) {
                    return Some(EINVAL_R);
                }
                o.ext.ip_recverr_rfc4884 = on;
                OK
            }
            IP_FREEBIND => {
                if short {
                    return Some(EINVAL_R);
                }
                o.ip_freebind = on;
                OK
            }
            IP_HDRINCL => {
                if self.kind != SOCK_RAW {
                    return Some(ENOPROTOOPT_R);
                }
                o.ext.ip_hdrincl = on;
                OK
            }
            IP_MULTICAST_LOOP => {
                if short {
                    return Some(EINVAL_R);
                }
                o.ext.ip_mc_loop = on;
                OK
            }
            IP_MULTICAST_ALL => {
                if short {
                    return Some(EINVAL_R);
                }
                if val != 0 && val != 1 {
                    return Some(EINVAL_R);
                }
                o.ext.ip_mc_all = on;
                OK
            }
            IP_TRANSPARENT => {
                if on && !net_raw_or_admin() {
                    return Some(EPERM_R);
                }
                if short {
                    return Some(EINVAL_R);
                }
                o.ext.ip_transparent = on;
                OK
            }
            IP_NODEFRAG => {
                if self.kind != SOCK_RAW {
                    return Some(ENOPROTOOPT_R);
                }
                o.ext.ip_nodefrag = on;
                OK
            }
            IP_BIND_ADDRESS_NO_PORT => {
                // LINUX-GAP: IP_BIND_ADDRESS_NO_PORT — stored and reported;
                // bind() still reserves an ephemeral port immediately.
                o.ext.ip_bind_address_no_port = on;
                OK
            }
            IP_MINTTL => {
                if short || !(0..=255).contains(&val) {
                    return Some(EINVAL_R);
                }
                // LINUX-GAP: IP_MINTTL — stored and reported; received
                // packets are not filtered by TTL.
                o.ext.ip_minttl = val;
                OK
            }
            IP_MTU_DISCOVER => {
                // `ip_sock_set_mtu_discover`.
                if !(0..=IP_PMTUDISC_OMIT).contains(&val) {
                    return Some(EINVAL_R);
                }
                // LINUX-GAP: IP_MTU_DISCOVER — stored and reported; the IPv4
                // output path does not set or clear DF from it.
                o.ext.ip_pmtudisc = val;
                OK
            }
            IP_LOCAL_PORT_RANGE => {
                let lo = val as u32 as u16;
                let hi = ((val as u32) >> 16) as u16;
                if value.len() != 4 || (lo != 0 && hi != 0 && lo > hi) {
                    return Some(EINVAL_R);
                }
                // LINUX-GAP: IP_LOCAL_PORT_RANGE — stored and reported;
                // ephemeral allocation ignores the per-socket range.
                o.ext.ip_local_port_range = val as u32;
                OK
            }
            IP_CHECKSUM => {
                o.ext.ip_checksum = on;
                OK
            }
            IP_OPTIONS => {
                if value.len() > 40 {
                    return Some(EINVAL_R);
                }
                // LINUX-GAP: ip_options_get — the options are stored and read
                // back, not compiled/validated or emitted on the wire.
                o.ext.ip_options = value.to_vec();
                OK
            }
            IP_UNICAST_IF => {
                if value.len() != 4 {
                    return Some(EINVAL_R);
                }
                let ifindex = u32::from_be(val as u32);
                if ifindex == 0 {
                    o.ext.ip_uc_index = 0;
                    return Some(OK);
                }
                if !ifindex_exists(self.net_ns_id(), ifindex) {
                    return Some(SocketOpResult::Err(SockError::AddrNotAvail));
                }
                // No L3 master devices: `midx` is 0, so any bound device
                // conflicts.
                if o.bindtodevice_index != 0 {
                    return Some(EINVAL_R);
                }
                o.ext.ip_uc_index = ifindex;
                OK
            }
            IP_MULTICAST_IF => {
                if self.kind == SOCK_STREAM || value.len() < 4 {
                    return Some(EINVAL_R);
                }
                let (mut ifindex, addr) = if value.len() >= 12 {
                    (read_u32_at(value, 8), read_be_u32_at(value, 4))
                } else if value.len() >= 8 {
                    (0, read_be_u32_at(value, 4))
                } else {
                    (0, read_be_u32_at(value, 0))
                };
                let ns = self.net_ns_id();
                if ifindex == 0 {
                    if addr == 0 {
                        o.ext.ip_mc_index = 0;
                        o.ext.ip_mc_addr = 0;
                        return Some(OK);
                    }
                    match ip_dev_find(ns, addr, true) {
                        Some(d) => ifindex = d,
                        None => return Some(SocketOpResult::Err(SockError::AddrNotAvail)),
                    }
                } else if !ifindex_exists(ns, ifindex) {
                    return Some(SocketOpResult::Err(SockError::AddrNotAvail));
                }
                if o.bindtodevice_index != 0 && ifindex != o.bindtodevice_index {
                    return Some(EINVAL_R);
                }
                o.ext.ip_mc_index = ifindex;
                o.ext.ip_mc_addr = addr;
                OK
            }
            IP_ADD_MEMBERSHIP | IP_DROP_MEMBERSHIP => {
                if self.is_tcp() {
                    return Some(errno_err(errno::EPROTO));
                }
                if value.len() < 8 {
                    return Some(EINVAL_R);
                }
                let group = read_be_u32_at(value, 0);
                let addr = read_be_u32_at(value, 4);
                let ifindex = if value.len() >= 12 {
                    read_u32_at(value, 8)
                } else {
                    0
                };
                drop(o);
                self.ip_mc_join_leave(name == IP_ADD_MEMBERSHIP, group, addr, ifindex)
            }
            MCAST_JOIN_GROUP | MCAST_LEAVE_GROUP => {
                // `ip_mcast_join_leave` (no IS_ICSK check on this path).
                if value.len() < GROUP_REQ_LEN {
                    return Some(EINVAL_R);
                }
                let ifindex = read_u32_at(value, 0);
                let family = u16::from_ne_bytes([value[8], value[9]]);
                if family != AF_INET {
                    return Some(EINVAL_R);
                }
                let group = read_be_u32_at(value, 12);
                drop(o);
                self.ip_mc_join_leave(name == MCAST_JOIN_GROUP, group, 0, ifindex)
            }
            IP_IPSEC_POLICY | IP_XFRM_POLICY => {
                if !capable(crate::handlers::CAP_NET_ADMIN) {
                    return Some(EPERM_R);
                }
                // LINUX-GAP: xfrm_user_policy — NARF has no IPsec, which is
                // what a kernel without CONFIG_XFRM answers.
                ENOPROTOOPT_R
            }
            _ => return None,
        };
        Some(r)
    }

    /// `__ip_mc_join_group` / `ip_mc_leave_group`.
    fn ip_mc_join_leave(
        &self,
        join: bool,
        group: u32,
        addr: u32,
        mut ifindex: u32,
    ) -> SocketOpResult {
        let ns = self.net_ns_id();
        let given_ifindex = ifindex;
        if join {
            if !is_multicast_v4(group) {
                return EINVAL_R;
            }
            if !ip_mc_find_dev(ns, group, addr, &mut ifindex) {
                return SocketOpResult::Err(SockError::NoDevice);
            }
            let mut o = self.options.lock();
            let list = &mut o.ext.ip_mc_list;
            if list
                .iter()
                .any(|m| m.group == group && m.ifindex == ifindex)
            {
                return SocketOpResult::Err(SockError::AddrInUse);
            }
            if list.len() >= IGMP_MAX_MEMBERSHIPS {
                return SocketOpResult::Err(SockError::NoBufs);
            }
            list.insert(
                0,
                IpMcMembership {
                    group,
                    ifindex,
                    addr,
                },
            );
            drop(o);
            mc_inc_v4(ns, ifindex, group);
            return OK;
        }
        let found_dev = ip_mc_find_dev(ns, group, addr, &mut ifindex);
        if given_ifindex == 0 && addr == 0 && !found_dev {
            return SocketOpResult::Err(SockError::NoDevice);
        }
        let mut o = self.options.lock();
        let list = &mut o.ext.ip_mc_list;
        let pos = list.iter().position(|m| {
            m.group == group
                && if ifindex != 0 {
                    m.ifindex == ifindex
                } else {
                    addr == 0 || m.addr == addr
                }
        });
        match pos {
            Some(i) => {
                let m = list.remove(i);
                drop(o);
                mc_dec_v4(ns, m.ifindex, m.group);
                OK
            }
            None => SocketOpResult::Err(SockError::AddrNotAvail),
        }
    }

    pub(super) fn ip_get(&self, name: u32, buf: &mut [u8]) -> Option<SocketOpResult> {
        if (MRT_BASE..=MRT_MAX).contains(&name) {
            // `ip_mroute_getsockopt`.
            if self.kind != SOCK_RAW || self.protocol != IPPROTO_IGMP {
                return Some(EOPNOTSUPP_R);
            }
            return Some(ENOPROTOOPT_R);
        }
        let o = self.options.lock();
        let v = match name {
            IP_PKTINFO => o.ip_pktinfo as i32,
            IP_RECVTTL => o.ip_recvttl as i32,
            IP_RECVTOS => o.ext.ip_recvtos as i32,
            IP_RECVOPTS => o.ext.ip_recvopts as i32,
            IP_RETOPTS => o.ext.ip_retopts as i32,
            IP_PASSSEC => o.ext.ip_passsec as i32,
            IP_RECVORIGDSTADDR => o.ext.ip_origdstaddr as i32,
            IP_CHECKSUM => o.ext.ip_checksum as i32,
            IP_RECVFRAGSIZE => o.ext.ip_recvfragsize as i32,
            IP_RECVERR => o.ext.ip_recverr as i32,
            IP_RECVERR_RFC4884 => o.ext.ip_recverr_rfc4884 as i32,
            IP_FREEBIND => o.ip_freebind as i32,
            IP_HDRINCL => {
                (o.ext.ip_hdrincl || (self.kind == SOCK_RAW && self.protocol == IPPROTO_RAW)) as i32
            }
            IP_MULTICAST_LOOP => o.ext.ip_mc_loop as i32,
            IP_MULTICAST_ALL => o.ext.ip_mc_all as i32,
            IP_TRANSPARENT => o.ext.ip_transparent as i32,
            IP_NODEFRAG => o.ext.ip_nodefrag as i32,
            IP_BIND_ADDRESS_NO_PORT => o.ext.ip_bind_address_no_port as i32,
            IP_ROUTER_ALERT => o.ext.ip_router_alert as i32,
            IP_MINTTL => o.ext.ip_minttl,
            IP_MTU_DISCOVER => o.ext.ip_pmtudisc,
            IP_UNICAST_IF => o.ext.ip_uc_index.to_be() as i32,
            IP_LOCAL_PORT_RANGE => o.ext.ip_local_port_range as i32,
            IP_MULTICAST_IF => {
                return Some(put_bytes(buf, &o.ext.ip_mc_addr.to_be_bytes()));
            }
            IP_OPTIONS => {
                return Some(put_bytes(buf, &o.ext.ip_options));
            }
            IP_PKTOPTIONS => {
                if self.kind != SOCK_STREAM {
                    return Some(ENOPROTOOPT_R);
                }
                // LINUX-GAP: do_ip_getsockopt IP_PKTOPTIONS — no cmsgs are
                // synthesised; the control buffer comes back empty.
                return Some(SocketOpResult::OptValue { n: 0 });
            }
            IP_PROTOCOL => {
                drop(o);
                self.inet_num() as i32
            }
            _ => return None,
        };
        Some(ip_copyval(buf, v))
    }
}
