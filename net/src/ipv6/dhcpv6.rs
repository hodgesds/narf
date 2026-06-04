//! DHCPv6 client state machine — RFC 8415.
//!
//! References (public-only):
//! - RFC 8415 — Dynamic Host Configuration Protocol for IPv6 (T.
//!   Mrugalski et al, Nov 2018). §18 (Client states, M1..M5),
//!   §18.2.1 (Solicit-Advertise), §18.2.4 (Renew), §18.2.5 (Rebind),
//!   §21.4 (IA_NA), §21.21 (IA_PD), §21.4 IA Address sub-option.
//!   <https://datatracker.ietf.org/doc/html/rfc8415>
//! - RFC 3315 — DHCPv6 (kept for the original IA_NA / IA_TA layouts
//!   that 8415 inherits unchanged).
//!   <https://datatracker.ietf.org/doc/html/rfc3315>
//!
//! The wire-format codec lives in `crate::pkt_dhcpv6`; this module
//! owns the state machine + the small inbound decoder for the few
//! options the client actually consumes (IA_NA / IAADDR / Status /
//! DNS Servers / SOL_MAX_RT).
//!
//! State transitions follow the conventional labels:
//!
//! ```text
//!   INIT ─ tx Solicit ──▶ SOLICIT
//!                         │ rx Advertise
//!                         ▼
//!                       REQUEST ─ tx Request ──▶ wait Reply ──▶ BOUND
//!                         │
//!                         │ T1 expires → tx Renew
//!                         ▼
//!                       RENEWING ─ T2 expires → REBINDING
//!                         │
//!                         │ lease expires → INIT
//!                         ▼
//!                       INIT
//! ```

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use crate::pkt_dhcpv6::{
    append_clientid_duid_ll, append_elapsed_time, append_option, append_oro, iter_options,
    DhcpV6Header, DhcpV6Option, MT_REPLY, MT_REQUEST, MT_SOLICIT, OPT_CLIENTID, OPT_DNS_SERVERS,
    OPT_DOMAIN_LIST, OPT_IAADDR, OPT_IA_NA, OPT_IA_PD, OPT_SERVERID, OPT_STATUS_CODE,
};

/// Client state (RFC 8415 §18).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DhcpV6State {
    Init,
    Solicit,
    Request,
    Bound,
    Renewing,
    Rebinding,
    Released,
}

/// One lease.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IaAddr {
    pub addr: [u8; 16],
    pub preferred_lifetime_s: u32,
    pub valid_lifetime_s: u32,
}

#[derive(Clone, Debug)]
pub struct DhcpV6Client {
    pub iface: String,
    pub mac: [u8; 6],
    pub state: DhcpV6State,
    pub transaction_id: u32,
    pub iaid: u32,
    pub server_duid: Vec<u8>,
    pub leases: Vec<IaAddr>,
    pub dns: Vec<[u8; 16]>,
    /// Renew (T1) deadline (monotonic-ns).
    pub t1_deadline_ns: u64,
    /// Rebind (T2) deadline.
    pub t2_deadline_ns: u64,
    /// Last lease expiry.
    pub lease_deadline_ns: u64,
}

impl DhcpV6Client {
    pub fn new(iface: &str, mac: [u8; 6], iaid: u32) -> Self {
        Self {
            iface: String::from(iface),
            mac,
            state: DhcpV6State::Init,
            transaction_id: 0,
            iaid,
            server_duid: Vec::new(),
            leases: Vec::new(),
            dns: Vec::new(),
            t1_deadline_ns: 0,
            t2_deadline_ns: 0,
            lease_deadline_ns: 0,
        }
    }

    /// Build a Solicit message. Includes a Client ID (DUID-LL),
    /// Elapsed Time, an Option Request Option (DNS, Domain List), and
    /// an IA_NA option with the client's IAID.
    pub fn build_solicit(&mut self, transaction_id: u32) -> Vec<u8> {
        self.transaction_id = transaction_id & 0x00FF_FFFF;
        self.state = DhcpV6State::Solicit;
        let mut out = Vec::with_capacity(96);
        let hdr = DhcpV6Header {
            msg_type: MT_SOLICIT,
            transaction_id: self.transaction_id,
        };
        out.extend_from_slice(&hdr.encode());
        append_clientid_duid_ll(&mut out, 1, &self.mac);
        append_elapsed_time(&mut out, 0);
        append_oro(&mut out, &[OPT_DNS_SERVERS, OPT_DOMAIN_LIST]);
        // IA_NA option: 4-byte IAID + 4-byte T1 + 4-byte T2 + sub-opts
        // (none — server fills these in on Reply).
        let mut ia_na = Vec::with_capacity(12);
        ia_na.extend_from_slice(&self.iaid.to_be_bytes());
        ia_na.extend_from_slice(&0u32.to_be_bytes()); // T1: let server pick
        ia_na.extend_from_slice(&0u32.to_be_bytes()); // T2: let server pick
        append_option(&mut out, OPT_IA_NA, &ia_na);
        out
    }

    /// Build a Request message including the Server DUID echoed from
    /// the Advertise.
    pub fn build_request(&mut self) -> Vec<u8> {
        self.state = DhcpV6State::Request;
        let mut out = Vec::with_capacity(128);
        let hdr = DhcpV6Header {
            msg_type: MT_REQUEST,
            transaction_id: self.transaction_id,
        };
        out.extend_from_slice(&hdr.encode());
        append_clientid_duid_ll(&mut out, 1, &self.mac);
        append_option(&mut out, OPT_SERVERID, &self.server_duid);
        append_elapsed_time(&mut out, 0);
        append_oro(&mut out, &[OPT_DNS_SERVERS, OPT_DOMAIN_LIST]);
        let mut ia_na = Vec::with_capacity(12);
        ia_na.extend_from_slice(&self.iaid.to_be_bytes());
        ia_na.extend_from_slice(&0u32.to_be_bytes());
        ia_na.extend_from_slice(&0u32.to_be_bytes());
        append_option(&mut out, OPT_IA_NA, &ia_na);
        out
    }

    /// Consume an Advertise message: record the server DUID + any
    /// offered IAADDR, transition to Request.
    pub fn on_advertise(&mut self, payload: &[u8]) -> bool {
        if payload.len() < 4 {
            return false;
        }
        let hdr = match DhcpV6Header::decode(payload) {
            Ok(h) => h,
            Err(_) => return false,
        };
        if hdr.msg_type != crate::pkt_dhcpv6::MT_ADVERTISE {
            return false;
        }
        if (hdr.transaction_id & 0x00FF_FFFF) != self.transaction_id {
            return false;
        }
        for opt in iter_options(&payload[4..]) {
            match opt {
                Ok(o) => self.consume_option(o),
                Err(_) => return false,
            }
        }
        if self.server_duid.is_empty() {
            return false;
        }
        self.state = DhcpV6State::Request;
        true
    }

    /// Consume a Reply message: finalise leases, T1/T2 deadlines,
    /// transition to Bound.
    pub fn on_reply(&mut self, payload: &[u8], now_ns: u64) -> bool {
        if payload.len() < 4 {
            return false;
        }
        let hdr = match DhcpV6Header::decode(payload) {
            Ok(h) => h,
            Err(_) => return false,
        };
        if hdr.msg_type != MT_REPLY {
            return false;
        }
        if (hdr.transaction_id & 0x00FF_FFFF) != self.transaction_id {
            return false;
        }
        let mut t1_s = 0u32;
        let mut t2_s = 0u32;
        for opt in iter_options(&payload[4..]) {
            let opt = match opt {
                Ok(o) => o,
                Err(_) => return false,
            };
            if opt.code == OPT_IA_NA && opt.data.len() >= 12 {
                t1_s = u32::from_be_bytes([opt.data[4], opt.data[5], opt.data[6], opt.data[7]]);
                t2_s = u32::from_be_bytes([opt.data[8], opt.data[9], opt.data[10], opt.data[11]]);
            }
            self.consume_option(opt);
        }
        if self.leases.is_empty() {
            // No address allocated — back to Init.
            self.state = DhcpV6State::Init;
            return false;
        }
        self.t1_deadline_ns = now_ns.saturating_add((t1_s as u64) * 1_000_000_000);
        self.t2_deadline_ns = now_ns.saturating_add((t2_s as u64) * 1_000_000_000);
        // Lease deadline = max(valid_lifetime).
        self.lease_deadline_ns = self
            .leases
            .iter()
            .map(|l| now_ns.saturating_add((l.valid_lifetime_s as u64) * 1_000_000_000))
            .max()
            .unwrap_or(0);
        self.state = DhcpV6State::Bound;
        true
    }

    fn consume_option(&mut self, opt: DhcpV6Option<'_>) {
        match opt.code {
            OPT_SERVERID => {
                self.server_duid.clear();
                self.server_duid.extend_from_slice(opt.data);
            }
            OPT_CLIENTID => { /* server echoed our DUID; nothing to do */ }
            OPT_IA_NA => {
                // IA_NA body: IAID(4) + T1(4) + T2(4) + sub-opts
                if opt.data.len() < 12 {
                    return;
                }
                let sub = &opt.data[12..];
                for s in iter_options(sub) {
                    let Ok(s) = s else { return };
                    if s.code == OPT_IAADDR && s.data.len() >= 24 {
                        let mut a = [0u8; 16];
                        a.copy_from_slice(&s.data[0..16]);
                        let preferred =
                            u32::from_be_bytes([s.data[16], s.data[17], s.data[18], s.data[19]]);
                        let valid =
                            u32::from_be_bytes([s.data[20], s.data[21], s.data[22], s.data[23]]);
                        if valid > 0 {
                            self.leases.push(IaAddr {
                                addr: a,
                                preferred_lifetime_s: preferred,
                                valid_lifetime_s: valid,
                            });
                        }
                    }
                }
            }
            OPT_IA_PD => {
                // Prefix delegation: not consumed in Stage-1 client
                // (we surface the option so future routing-prefix
                // logic can attach).
            }
            OPT_DNS_SERVERS => {
                let mut p = 0;
                while p + 16 <= opt.data.len() {
                    let mut a = [0u8; 16];
                    a.copy_from_slice(&opt.data[p..p + 16]);
                    self.dns.push(a);
                    p += 16;
                }
            }
            OPT_STATUS_CODE => {
                // RFC 8415 §21.13: 2 bytes status + UTF-8 message.
                // Non-success codes → drop the lease list so we don't
                // claim addresses the server rejected.
                if opt.data.len() >= 2 {
                    let status = u16::from_be_bytes([opt.data[0], opt.data[1]]);
                    if status != 0 {
                        self.leases.clear();
                    }
                }
            }
            _ => {}
        }
    }

    /// Run the once-per-tick timer advance. Caller supplies
    /// `now_ns`; we transition based on T1 / T2 / lease deadlines.
    pub fn tick(&mut self, now_ns: u64) {
        match self.state {
            DhcpV6State::Bound => {
                if now_ns >= self.t1_deadline_ns {
                    self.state = DhcpV6State::Renewing;
                }
            }
            DhcpV6State::Renewing => {
                if now_ns >= self.t2_deadline_ns {
                    self.state = DhcpV6State::Rebinding;
                }
            }
            DhcpV6State::Rebinding => {
                if now_ns >= self.lease_deadline_ns {
                    self.state = DhcpV6State::Init;
                    self.leases.clear();
                }
            }
            _ => {}
        }
    }
}
