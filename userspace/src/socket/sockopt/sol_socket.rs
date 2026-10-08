//! `SOL_SOCKET` socket options — split out of the parent `sockopt` module with no
//! behaviour change. Dispatch, shared helpers, and option-name constants stay
//! in `sockopt.rs`; this file holds just the SO_* set/get methods.

use super::*;

impl SocketFile {
    pub(super) fn sol_socket_set(&self, name: u32, value: &[u8]) -> Option<SocketOpResult> {
        let val = ip6_val(value);
        let on = val != 0;
        // sk_setsockopt's lockless switch.
        let r = match name {
            SO_PRIORITY => {
                if (0..=6).contains(&val) || net_raw_or_admin() {
                    self.options.lock().ext.priority = val as u32;
                    OK
                } else {
                    EPERM_R
                }
            }
            SO_BUSY_POLL => {
                if val < 0 {
                    return Some(EINVAL_R);
                }
                self.options.lock().ext.busy_poll = val as u32;
                OK
            }
            SO_PREFER_BUSY_POLL => {
                if on && !capable(crate::handlers::CAP_NET_ADMIN) {
                    return Some(EPERM_R);
                }
                self.options.lock().ext.prefer_busy_poll = on;
                OK
            }
            SO_BUSY_POLL_BUDGET => {
                let mut o = self.options.lock();
                if val as i64 > i64::from(o.ext.busy_poll_budget)
                    && !capable(crate::handlers::CAP_NET_ADMIN)
                {
                    return Some(EPERM_R);
                }
                if !(0..=i32::from(u16::MAX)).contains(&val) {
                    return Some(EINVAL_R);
                }
                o.ext.busy_poll_budget = val as u32;
                OK
            }
            SO_MAX_PACING_RATE => {
                // `ulval = (val == ~0U) ? ~0UL : (unsigned int)val`, then the
                // full unsigned long when optlen covers one.
                let mut rate = if val == -1 {
                    u64::MAX
                } else {
                    u64::from(val as u32)
                };
                if value.len() >= 8 {
                    rate = u64::from_ne_bytes(value[..8].try_into().unwrap_or([0; 8]));
                }
                // LINUX-GAP: sk_setsockopt SO_MAX_PACING_RATE — stored and
                // reported; NARF has no fq pacing to apply it to.
                self.options.lock().ext.max_pacing_rate = rate;
                OK
            }
            SO_TXREHASH => {
                if !self.is_tcp() {
                    return Some(EOPNOTSUPP_R);
                }
                if !(-1..=1).contains(&val) {
                    return Some(EINVAL_R);
                }
                let mut v = val as u8;
                if v == SOCK_TXREHASH_DEFAULT {
                    v = SYSCTL_TXREHASH;
                }
                self.options.lock().ext.txrehash = v;
                OK
            }
            SO_PEEK_OFF => return None,
            SO_RCVTIMEO_OLD | SO_RCVTIMEO_NEW => match sock_set_timeout(value) {
                Ok(t) => {
                    self.options.lock().ext.rcvtimeo = t;
                    OK
                }
                Err(e) => SocketOpResult::Err(e),
            },
            SO_SNDTIMEO_OLD | SO_SNDTIMEO_NEW => match sock_set_timeout(value) {
                Ok(t) => {
                    self.options.lock().ext.sndtimeo = t;
                    OK
                }
                Err(e) => SocketOpResult::Err(e),
            },
            // The locked switch.
            SO_DEBUG => {
                if on && !capable(crate::handlers::CAP_NET_ADMIN) {
                    return Some(SocketOpResult::Err(SockError::Access));
                }
                self.options.lock().ext.debug = on;
                OK
            }
            SO_REUSEPORT => {
                if on && !matches!(self.domain, AF_INET | AF_INET6) {
                    return Some(EOPNOTSUPP_R);
                }
                self.options.lock().reuseport = on;
                OK
            }
            SO_DONTROUTE => {
                // LINUX-GAP: sk_setsockopt SO_DONTROUTE (SOCK_LOCALROUTE) —
                // stored and reported; NARF's route lookup does not restrict
                // the socket to directly connected destinations.
                self.options.lock().ext.dontroute = on;
                OK
            }
            SO_SNDBUF | SO_SNDBUFFORCE => {
                let requested = if name == SO_SNDBUFFORCE {
                    if !capable(crate::handlers::CAP_NET_ADMIN) {
                        return Some(EPERM_R);
                    }
                    val.max(0) as u32
                } else {
                    (val as u32).min(WMEM_MAX)
                };
                let v = requested.min((i32::MAX / 2) as u32);
                self.options.lock().sndbuf = (v * 2).max(SOCK_MIN_SNDBUF);
                OK
            }
            SO_RCVBUF | SO_RCVBUFFORCE => {
                let requested = if name == SO_RCVBUFFORCE {
                    if !capable(crate::handlers::CAP_NET_ADMIN) {
                        return Some(EPERM_R);
                    }
                    val.max(0)
                } else {
                    (val as u32).min(RMEM_MAX) as i32
                };
                // `__sock_set_rcvbuf`.
                let v = requested.min(i32::MAX / 2) as u32;
                self.options.lock().rcvbuf = (v * 2).max(SOCK_MIN_RCVBUF);
                OK
            }
            SO_OOBINLINE => {
                // LINUX-GAP: sk_setsockopt SO_OOBINLINE (SOCK_URGINLINE) —
                // stored and reported; NARF's TCP has no urgent-data path.
                self.options.lock().ext.oobinline = on;
                OK
            }
            SO_NO_CHECK => {
                // LINUX-GAP: sk_setsockopt SO_NO_CHECK — stored; the UDP
                // transmit path always checksums.
                self.options.lock().ext.no_check = on;
                OK
            }
            SO_BSDCOMPAT | SO_CNX_ADVICE => OK,
            SO_RCVLOWAT => {
                let mut v = if val < 0 { i32::MAX } else { val };
                if self.is_tcp() {
                    // `tcp_set_rcvlowat`: capped at half of tcp_rmem[2].
                    v = v.min(6_291_456 >> 1);
                }
                // LINUX-GAP: sk_setsockopt SO_RCVLOWAT — stored and reported;
                // readiness and blocking reads do not wait for the low-water
                // mark.
                self.options.lock().ext.rcvlowat = if v == 0 { 1 } else { v };
                OK
            }
            SO_DETACH_FILTER => {
                let mut o = self.options.lock();
                if o.ext.filter_locked {
                    return Some(EPERM_R);
                }
                if o.classic_filter.take().is_none() {
                    return Some(SocketOpResult::Err(SockError::NoEntry));
                }
                OK
            }
            SO_LOCK_FILTER => {
                let mut o = self.options.lock();
                if o.ext.filter_locked && !on {
                    return Some(EPERM_R);
                }
                o.ext.filter_locked = on;
                OK
            }
            SO_MARK => {
                if !net_raw_or_admin() {
                    return Some(EPERM_R);
                }
                // LINUX-GAP: sk_setsockopt SO_MARK — stored and reported;
                // NARF has no fwmark policy routing or netfilter mark match.
                self.options.lock().ext.mark = val as u32;
                OK
            }
            SO_RCVMARK | SO_RCVPRIORITY | SO_RXQ_OVFL | SO_WIFI_STATUS | SO_NOFCS
            | SO_SELECT_ERR_QUEUE => {
                // LINUX-GAP: sk_setsockopt socket flags — stored and
                // reported; the matching ancillary data / behaviour is not
                // generated.
                let mut o = self.options.lock();
                match name {
                    SO_RCVMARK => o.ext.rcvmark = on,
                    SO_RCVPRIORITY => o.ext.rcvpriority = on,
                    SO_RXQ_OVFL => o.ext.rxq_ovfl = on,
                    SO_WIFI_STATUS => o.ext.wifi_status = on,
                    SO_NOFCS => o.ext.nofcs = on,
                    _ => o.ext.select_err_queue = on,
                }
                OK
            }
            SO_PASSCRED => {
                if !self.may_scm_recv() {
                    return Some(EOPNOTSUPP_R);
                }
                self.set_passcred(on);
                OK
            }
            SO_PASSSEC => {
                if !self.may_scm_recv() {
                    return Some(EOPNOTSUPP_R);
                }
                self.options.lock().ext.passsec = on;
                OK
            }
            SO_PASSPIDFD | SO_PASSRIGHTS => {
                if self.domain != AF_UNIX {
                    return Some(EOPNOTSUPP_R);
                }
                let mut o = self.options.lock();
                if name == SO_PASSPIDFD {
                    // LINUX-GAP: sk_setsockopt SO_PASSPIDFD — stored and
                    // reported; no SCM_PIDFD is attached on receive.
                    o.ext.passpidfd = on;
                } else {
                    // LINUX-GAP: sk_setsockopt SO_PASSRIGHTS — stored and
                    // reported; SCM_RIGHTS delivery is not refused when off.
                    o.ext.passrights = on;
                }
                OK
            }
            SO_INCOMING_CPU => {
                self.options.lock().ext.incoming_cpu = val;
                OK
            }
            SO_BINDTOIFINDEX => {
                // `sock_bindtoindex_locked`: re-binding a bound socket needs
                // CAP_NET_RAW; a negative index is EINVAL; the index itself
                // is never looked up.
                let mut o = self.options.lock();
                if o.bindtodevice_index != 0 && !capable(crate::handlers::CAP_NET_RAW) {
                    return Some(EPERM_R);
                }
                if val < 0 {
                    return Some(EINVAL_R);
                }
                o.bindtodevice_index = val as u32;
                o.bindtodevice = if val == 0 {
                    None
                } else {
                    ifindex_name(self.net_ns_id(), val as u32)
                };
                OK
            }
            SO_BUF_LOCK => {
                if val & !SOCK_BUF_LOCK_MASK != 0 {
                    return Some(EINVAL_R);
                }
                self.options.lock().ext.buf_lock = val;
                OK
            }
            SO_RESERVE_MEM => {
                if val < 0 {
                    return Some(EINVAL_R);
                }
                // LINUX-GAP: sock_reserve_memory — the reservation is
                // recorded (rounded to pages) but NARF has no socket memory
                // accounting to pre-charge.
                let pages = (val as u32).div_ceil(4096);
                self.options.lock().ext.reserve_mem = (pages * 4096) as i32;
                OK
            }
            SO_INQ if self.domain == AF_UNIX => {
                // `unix_setsockopt`: exactly an int, stream only, 0 or 1.
                if value.len() != 4 || self.kind != SOCK_STREAM || !(0..=1).contains(&val) {
                    return Some(EINVAL_R);
                }
                // LINUX-GAP: unix_setsockopt SO_INQ — stored; recvmsg does
                // not attach SCM_INQ.
                self.options.lock().ext.unix_inq = on;
                OK
            }
            _ => return None,
        };
        Some(r)
    }

    pub(super) fn sol_socket_get(&self, name: u32, buf: &mut [u8]) -> Option<SocketOpResult> {
        let o = self.options.lock();
        let r = match name {
            SO_DEBUG => put_int(buf, o.ext.debug as i32),
            SO_DONTROUTE => put_int(buf, o.ext.dontroute as i32),
            SO_OOBINLINE => put_int(buf, o.ext.oobinline as i32),
            SO_NO_CHECK => put_int(buf, o.ext.no_check as i32),
            SO_PRIORITY => put_int(buf, o.ext.priority as i32),
            SO_BSDCOMPAT => put_int(buf, 0),
            SO_RCVTIMEO_OLD | SO_RCVTIMEO_NEW => put_bytes(buf, &sock_get_timeout(o.ext.rcvtimeo)),
            SO_SNDTIMEO_OLD | SO_SNDTIMEO_NEW => put_bytes(buf, &sock_get_timeout(o.ext.sndtimeo)),
            SO_RCVLOWAT => put_int(buf, o.ext.rcvlowat),
            SO_SNDLOWAT => put_int(buf, 1),
            SO_PASSCRED => {
                if !self.may_scm_recv() {
                    return Some(EOPNOTSUPP_R);
                }
                put_int(buf, self.passcred.load(Ordering::Acquire) as i32)
            }
            SO_PASSPIDFD | SO_PASSRIGHTS => {
                if self.domain != AF_UNIX {
                    return Some(EOPNOTSUPP_R);
                }
                let v = if name == SO_PASSPIDFD {
                    o.ext.passpidfd
                } else {
                    o.ext.passrights
                };
                put_int(buf, v as i32)
            }
            SO_PASSSEC => {
                if !self.may_scm_recv() {
                    return Some(EOPNOTSUPP_R);
                }
                put_int(buf, o.ext.passsec as i32)
            }
            SO_MARK => put_int(buf, o.ext.mark as i32),
            SO_RCVMARK => put_int(buf, o.ext.rcvmark as i32),
            SO_RCVPRIORITY => put_int(buf, o.ext.rcvpriority as i32),
            SO_RXQ_OVFL => put_int(buf, o.ext.rxq_ovfl as i32),
            SO_WIFI_STATUS => put_int(buf, o.ext.wifi_status as i32),
            SO_NOFCS => put_int(buf, o.ext.nofcs as i32),
            SO_PEEK_OFF => {
                if !self.has_peek_off() {
                    return Some(EOPNOTSUPP_R);
                }
                // SO_PEEK_OFF is never set (see sol_socket_set), so it is
                // still the `sk_peek_off = -1` of `sock_init_data_uid`.
                put_int(buf, -1)
            }
            SO_LOCK_FILTER => put_int(buf, o.ext.filter_locked as i32),
            SO_BPF_EXTENSIONS => put_int(buf, SKF_AD_MAX),
            SO_SELECT_ERR_QUEUE => put_int(buf, o.ext.select_err_queue as i32),
            SO_BUSY_POLL => put_int(buf, o.ext.busy_poll as i32),
            SO_PREFER_BUSY_POLL => put_int(buf, o.ext.prefer_busy_poll as i32),
            SO_MAX_PACING_RATE => {
                if buf.len() >= 8 {
                    put_bytes(buf, &o.ext.max_pacing_rate.to_ne_bytes())
                } else {
                    put_int(
                        buf,
                        o.ext.max_pacing_rate.min(u64::from(u32::MAX)) as u32 as i32,
                    )
                }
            }
            SO_INCOMING_CPU => put_int(buf, o.ext.incoming_cpu),
            SO_INCOMING_NAPI_ID => put_int(buf, 0),
            SO_MEMINFO => {
                // LINUX-GAP: sk_get_meminfo — only the buffer sizes are
                // modelled; the allocation counters read 0.
                let mut m = [0u8; SK_MEMINFO_VARS * 4];
                m[4..8].copy_from_slice(&o.rcvbuf.to_ne_bytes());
                m[12..16].copy_from_slice(&o.sndbuf.to_ne_bytes());
                put_bytes(buf, &m)
            }
            SO_COOKIE => {
                if buf.len() < 8 {
                    return Some(EINVAL_R);
                }
                drop(o);
                put_bytes(buf, &self.sock_cookie().to_ne_bytes())
            }
            SO_NETNS_COOKIE => {
                if buf.len() != 8 {
                    return Some(EINVAL_R);
                }
                put_bytes(buf, &(self.net_ns_id() + 1).to_ne_bytes())
            }
            SO_ZEROCOPY => put_int(buf, 0),
            SO_TXTIME => put_bytes(buf, &[0u8; 8]),
            SO_TIMESTAMPING_OLD | SO_TIMESTAMPING_NEW => put_bytes(buf, &[0u8; 8]),
            SO_BINDTOIFINDEX => put_int(buf, o.bindtodevice_index as i32),
            SO_BUF_LOCK => put_int(buf, o.ext.buf_lock),
            SO_RESERVE_MEM => put_int(buf, o.ext.reserve_mem),
            SO_TXREHASH => {
                if !self.is_tcp() {
                    return Some(EOPNOTSUPP_R);
                }
                put_int(buf, i32::from(o.ext.txrehash))
            }
            SO_PEERNAME => {
                drop(o);
                let Some(peer) = self.peer_addr() else {
                    return Some(SocketOpResult::Err(SockError::NotConnected));
                };
                let mut raw = Vec::with_capacity(2 + peer.body.len());
                raw.extend_from_slice(&peer.family.to_ne_bytes());
                raw.extend_from_slice(&peer.body);
                // `if (lv < len) return -EINVAL;`
                if raw.len() < buf.len() {
                    return Some(EINVAL_R);
                }
                put_bytes(buf, &raw)
            }
            _ => return None,
        };
        Some(r)
    }

    /// `sock_gen_cookie`: a stable, unique, non-zero id per socket.
    fn sock_cookie(&self) -> u64 {
        let mut o = self.options.lock();
        if o.ext.cookie == 0 {
            o.ext.cookie = NEXT_SOCK_COOKIE.fetch_add(1, Ordering::Relaxed);
        }
        o.ext.cookie
    }
}
