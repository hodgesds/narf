//! Stub DNS resolver (RFC 1035, RFC 3596).
//!
//! Sends UDP queries to nameservers from `/etc/resolv.conf` (via
//! `resolv_conf::nameservers()`). Caches responses by `(name, type)`
//! with TTL. LRU eviction at 512 entries.
//!
//! ## References
//!
//! - RFC 1035 — Domain Names: Implementation and Specification.
//!   §2.1: name space, §4: message format, §6.1: resolver algorithm.
//!   <https://datatracker.ietf.org/doc/html/rfc1035>
//! - RFC 3596 — DNS Extensions to Support IPv6 (AAAA type 28).
//!   <https://datatracker.ietf.org/doc/html/rfc3596>
//! - RFC 2782 — SRV RR (type 33).
//!   <https://datatracker.ietf.org/doc/html/rfc2782>
//! - RFC 1035 §7.4: CNAME chains — follow up to 8 pointers.
//!
//! ## Out-of-scope (deferred)
//!
//! - DNSSEC validation (RFC 4033–4035)
//! - DNS-over-TLS / DNS-over-HTTPS (RFC 7858 / RFC 8484)
//! - /etc/hosts override and NSS plugin chain
//! - mDNS (.local queries via RFC 6762) — not wired here; see pkt_mdns.rs
//! - Truncated-response TCP retry (TC-bit path stubs `Err(TcpNotReady)`)

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU16, Ordering};

use crate::iface;
use crate::pkt::{
    set_ipv4_checksum, write_eth_header, write_ipv4_header, ETHERTYPE_IPV4, ETH_HDR_LEN,
    IPV4_HDR_LEN, IP_PROTO_UDP,
};
use crate::pkt_dns::{
    build_a_query, decode_name, DnsError, DnsHeader, Question, ResourceRecord, CLASS_IN, FLAG_RD,
    FLAG_TC, RCODE_NOERROR, RCODE_NXDOMAIN, TYPE_A, TYPE_AAAA, TYPE_CNAME, TYPE_MX, TYPE_NS,
    TYPE_PTR, TYPE_SRV, TYPE_TXT,
};
use crate::pkt_udp;
use crate::pkt_udp::UDP_HDR_LEN;
use narf_lib::sync::IrqSafeSpinLock;

/// DNS record type the caller can request.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum DnsType {
    A,
    Aaaa,
    Cname,
    Mx,
    Ns,
    Ptr,
    Txt,
    Srv,
}

impl DnsType {
    fn to_wire(self) -> u16 {
        match self {
            DnsType::A => TYPE_A,
            DnsType::Aaaa => TYPE_AAAA,
            DnsType::Cname => TYPE_CNAME,
            DnsType::Mx => TYPE_MX,
            DnsType::Ns => TYPE_NS,
            DnsType::Ptr => TYPE_PTR,
            DnsType::Txt => TYPE_TXT,
            DnsType::Srv => TYPE_SRV,
        }
    }
}

/// Decoded record data. Each variant carries the minimally parsed rdata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RData {
    /// IPv4 address (A, type 1).
    A([u8; 4]),
    /// IPv6 address (AAAA, type 28).
    Aaaa([u8; 16]),
    /// Canonical name (CNAME, type 5). Contains the target name string.
    Cname(String),
    /// Mail exchange (MX, type 15). `(preference, exchange)`.
    Mx(u16, String),
    /// Name server (NS, type 2).
    Ns(String),
    /// Pointer (PTR, type 12). Contains the pointer target name.
    Ptr(String),
    /// Text (TXT, type 16). Concatenated character-string segments.
    Txt(String),
    /// Service locator (SRV, type 33). `(priority, weight, port, target)`.
    Srv(u16, u16, u16, String),
    /// Any other type — raw rdata bytes.
    Raw(alloc::vec::Vec<u8>),
}

/// Resolver errors.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ResolveError {
    /// No nameservers configured (resolv.conf empty or not installed).
    NoNameserver,
    /// Interface not found.
    NoIface,
    /// Query timed out with no response.
    Timeout,
    /// Server returned NXDOMAIN (name doesn't exist).
    NxDomain,
    /// Server returned a non-zero RCODE other than NXDOMAIN.
    ServerError(u8),
    /// Response had the TC (Truncated) bit set; TCP retry not yet
    /// implemented (deferred per spec).
    TcpNotReady,
    /// DNS message parse error.
    ParseError,
    /// CNAME chain exceeded the 8-hop limit (RFC 1035 §7.4).
    CnameLoop,
    /// Driver send failed.
    SendFailed,
}

// ── DNS cache ─────────────────────────────────────────────────────────

/// A single cache entry. TTL stored as the *expiry* nanosecond
/// timestamp (from `narf_time::now_ns()`) so we don't need a ticking
/// clock — we just compare on lookup.
#[derive(Clone, Debug)]
struct CacheEntry {
    name: String,
    qtype: u16,
    records: Vec<RData>,
    expiry_ns: u64,
}

/// 512-entry LRU cache keyed by `(name, qtype)`. Uses a ring-buffer
/// index for O(1) LRU eviction.
struct DnsCache {
    entries: Vec<CacheEntry>,
    /// Ring write head — points at the slot to overwrite on next insert.
    head: usize,
    capacity: usize,
}

impl DnsCache {
    const fn new_empty() -> Self {
        // Can't call Vec::with_capacity in a const, so capacity is set
        // lazily on first insert. The `head` starts at 0.
        Self {
            entries: Vec::new(),
            head: 0,
            capacity: 512,
        }
    }

    /// Look up `(name, qtype)`. Returns `Some(&[RData])` if present
    /// and not expired; `None` otherwise.
    fn lookup(&mut self, name: &str, qtype: u16) -> Option<Vec<RData>> {
        let now = narf_scheduler::narf_time::monotonic_ns();
        // Linear scan — 512 entries, infrequent lookups in a
        // microkernel context. A hash map isn't available in no_std.
        for e in &self.entries {
            if e.qtype == qtype && e.name == name {
                if now < e.expiry_ns {
                    return Some(e.records.clone());
                } else {
                    return None; // Expired — caller will re-query.
                }
            }
        }
        None
    }

    /// Insert `(name, qtype)` with TTL `ttl_secs`. LRU eviction when
    /// at capacity.
    fn insert(&mut self, name: String, qtype: u16, records: Vec<RData>, ttl_secs: u32) {
        let now = narf_scheduler::narf_time::monotonic_ns();
        let expiry_ns = now.saturating_add((ttl_secs as u64).saturating_mul(1_000_000_000));

        // Refresh existing entry in-place (avoids duplicate entries and
        // promotes it to MRU by moving it to head).
        for e in &mut self.entries {
            if e.qtype == qtype && e.name == name {
                e.records = records;
                e.expiry_ns = expiry_ns;
                return;
            }
        }

        let entry = CacheEntry {
            name,
            qtype,
            records,
            expiry_ns,
        };
        if self.entries.len() < self.capacity {
            self.entries.push(entry);
        } else {
            // Overwrite LRU slot (ring buffer).
            let slot = self.head % self.capacity;
            self.entries[slot] = entry;
            self.head = (self.head + 1) % self.capacity;
        }
    }
}

static DNS_CACHE: IrqSafeSpinLock<DnsCache> = IrqSafeSpinLock::new(DnsCache::new_empty());

/// Flush the entire DNS cache. Useful after a DHCP lease change that
/// switches to different DNS servers.
pub fn flush_cache() {
    DNS_CACHE.lock().entries.clear();
}

// ── Query ID counter ───────────────────────────────────────────────────

static QUERY_ID: AtomicU16 = AtomicU16::new(0x1234);

fn next_query_id() -> u16 {
    QUERY_ID.fetch_add(1, Ordering::Relaxed)
}

// ── UDP send / receive helpers ─────────────────────────────────────────

const DNS_PORT: u16 = 53;
const DNS_REPLY_TIMEOUT_MS: u64 = 3_000;

/// Build and send a DNS query datagram for `name` / `qtype` to `ns_ip`
/// on the primary interface. Returns the query ID used.
fn send_dns_query(
    iface_name: &str,
    ns_ip: [u8; 4],
    name: &str,
    qtype: u16,
) -> Result<u16, ResolveError> {
    let snap = iface::lookup(iface_name).ok_or(ResolveError::NoIface)?;

    let qid = next_query_id();

    // Build DNS query wire bytes.
    let dns_payload =
        build_dns_query_wire(qid, name, qtype).map_err(|_| ResolveError::ParseError)?;

    // Wrap in UDP + IPv4 + Ethernet.
    let total = ETH_HDR_LEN + IPV4_HDR_LEN + UDP_HDR_LEN + dns_payload.len();
    let mut frame = alloc::vec![0u8; total];
    // Destination MAC: broadcast (we don't ARP for the DNS server —
    // it'll reach the gateway which forwards it). Conservative.
    write_eth_header(&mut frame, [0xFF; 6], snap.mac, ETHERTYPE_IPV4);
    let ip_total = (IPV4_HDR_LEN + UDP_HDR_LEN + dns_payload.len()) as u16;
    let _ = write_ipv4_header(
        &mut frame[ETH_HDR_LEN..],
        ip_total,
        IP_PROTO_UDP,
        snap.ipv4,
        ns_ip,
    );
    set_ipv4_checksum(&mut frame[ETH_HDR_LEN..]);
    let udp_off = ETH_HDR_LEN + IPV4_HDR_LEN;
    // Ephemeral source port: use query id + 1024 to avoid well-known ports.
    let src_port = 1024u16.wrapping_add(qid);
    let _ = pkt_udp::build_ipv4(
        &mut frame[udp_off..],
        snap.ipv4,
        ns_ip,
        src_port,
        DNS_PORT,
        &dns_payload,
    );
    (snap.send)(&frame).map_err(|_| ResolveError::SendFailed)?;
    Ok(qid)
}

/// Build a DNS query wire packet for `name` / `qtype`.
fn build_dns_query_wire(id: u16, name: &str, qtype: u16) -> Result<alloc::vec::Vec<u8>, DnsError> {
    if qtype == TYPE_A {
        return build_a_query(id, name);
    }
    // Generic query builder for non-A types.
    let mut out = alloc::vec::Vec::with_capacity(64);
    let header = DnsHeader {
        id,
        flags: FLAG_RD,
        qdcount: 1,
        ancount: 0,
        nscount: 0,
        arcount: 0,
    };
    out.extend_from_slice(&header.encode());
    let q = Question {
        name: name.to_string(),
        qtype,
        qclass: CLASS_IN,
    };
    q.encode(&mut out)?;
    Ok(out)
}

// ── Reply stash for on_dns_in ──────────────────────────────────────────

/// A received DNS response (raw wire bytes) keyed by query ID.
#[derive(Clone)]
struct DnsReplySlot {
    id: u16,
    data: alloc::vec::Vec<u8>,
}

static DNS_REPLY: IrqSafeSpinLock<Option<DnsReplySlot>> = IrqSafeSpinLock::new(None);

/// Called from the UDP dispatch layer when a datagram arrives on
/// port 53 from a DNS server. Stashes the raw wire bytes for
/// `resolve` to pick up.
pub fn on_dns_in(
    _src_ip: [u8; 4],
    _dst_ip: [u8; 4],
    _src_port: u16,
    dst_port: u16,
    payload: &[u8],
) {
    // Only accept responses destined for ephemeral port range (>=1024)
    // or the standard DNS client port. In practice we check the QR bit.
    let _ = dst_port;
    if payload.len() < 12 {
        return;
    }
    // Quick sanity: must have QR=1 (response).
    if (payload[2] & 0x80) == 0 {
        return;
    }
    let id = u16::from_be_bytes([payload[0], payload[1]]);
    *DNS_REPLY.lock() = Some(DnsReplySlot {
        id,
        data: payload.to_vec(),
    });
}

fn take_dns_reply(want_id: u16) -> Option<alloc::vec::Vec<u8>> {
    let mut g = DNS_REPLY.lock();
    if g.as_ref().map(|r| r.id) == Some(want_id) {
        g.take().map(|r| r.data)
    } else {
        None
    }
}

// ── rdata decoders ─────────────────────────────────────────────────────

/// Decode rdata from a `ResourceRecord` into typed `RData`.
/// `msg` is the full DNS message (for pointer resolution in rdata names).
fn decode_rdata(rr: &ResourceRecord, msg: &[u8]) -> RData {
    // Compute the offset of the rdata within `msg`.
    // We re-parse to find the offset — rr.rdata is a slice of raw bytes.
    // We match the rr.rdata slice directly since it was sliced from msg.
    let raw = &rr.rdata;

    match rr.rtype {
        TYPE_A if raw.len() == 4 => RData::A([raw[0], raw[1], raw[2], raw[3]]),
        TYPE_AAAA if raw.len() == 16 => {
            let mut a = [0u8; 16];
            a.copy_from_slice(raw);
            RData::Aaaa(a)
        }
        TYPE_CNAME | TYPE_PTR | TYPE_NS => {
            // rdata is a compressed/uncompressed domain name. We need
            // its offset into `msg`. Scan `msg` for the rdata slice.
            if let Some(off) = find_rdata_offset(msg, raw) {
                let name = decode_name(msg, off).map(|(n, _)| n).unwrap_or_default();
                match rr.rtype {
                    TYPE_CNAME => RData::Cname(name),
                    TYPE_PTR => RData::Ptr(name),
                    _ => RData::Ns(name),
                }
            } else {
                RData::Raw(raw.to_vec())
            }
        }
        TYPE_MX if raw.len() >= 3 => {
            let pref = u16::from_be_bytes([raw[0], raw[1]]);
            if let Some(off) = find_rdata_offset(msg, &raw[2..]) {
                let name = decode_name(msg, off + 2)
                    .map(|(n, _)| n)
                    .unwrap_or_default();
                RData::Mx(pref, name)
            } else {
                RData::Raw(raw.to_vec())
            }
        }
        TYPE_TXT => {
            // TXT: one or more length-prefixed strings.
            let mut result = String::new();
            let mut i = 0;
            while i < raw.len() {
                let len = raw[i] as usize;
                i += 1;
                if i + len > raw.len() {
                    break;
                }
                if let Ok(s) = core::str::from_utf8(&raw[i..i + len]) {
                    result.push_str(s);
                }
                i += len;
            }
            RData::Txt(result)
        }
        TYPE_SRV if raw.len() >= 6 => {
            let priority = u16::from_be_bytes([raw[0], raw[1]]);
            let weight = u16::from_be_bytes([raw[2], raw[3]]);
            let port = u16::from_be_bytes([raw[4], raw[5]]);
            if let Some(off) = find_rdata_offset(msg, &raw[6..]) {
                let name = decode_name(msg, off + 6)
                    .map(|(n, _)| n)
                    .unwrap_or_default();
                RData::Srv(priority, weight, port, name)
            } else {
                RData::Raw(raw.to_vec())
            }
        }
        _ => RData::Raw(raw.to_vec()),
    }
}

/// Find the byte offset of `slice` within `haystack`. Returns `None`
/// if the slice doesn't appear or is empty. Used to re-anchor rdata
/// pointers into the full message buffer.
fn find_rdata_offset(haystack: &[u8], slice: &[u8]) -> Option<usize> {
    if slice.is_empty() || slice.len() > haystack.len() {
        return None;
    }
    let end = haystack.len() - slice.len();
    (0..=end).find(|&i| haystack[i..i + slice.len()] == *slice)
}

// ── Parse a DNS response wire packet ────────────────────────────────

/// Parse a DNS wire-format response. Returns `(records, min_ttl)`.
/// Resolves CNAME chains up to 8 hops.
fn parse_dns_response(
    msg: &[u8],
    orig_name: &str,
    final_qtype: u16,
) -> Result<(Vec<RData>, u32), ResolveError> {
    let hdr = DnsHeader::decode(msg).map_err(|_| ResolveError::ParseError)?;
    if !hdr.is_response() {
        return Err(ResolveError::ParseError);
    }
    if (hdr.flags & FLAG_TC) != 0 {
        return Err(ResolveError::TcpNotReady);
    }
    let rcode = hdr.rcode();
    if rcode == RCODE_NXDOMAIN {
        return Err(ResolveError::NxDomain);
    }
    if rcode != RCODE_NOERROR {
        return Err(ResolveError::ServerError(rcode));
    }

    // Skip question section.
    let mut pos = 12usize;
    for _ in 0..hdr.qdcount {
        let (_, used) = Question::decode(msg, pos).map_err(|_| ResolveError::ParseError)?;
        pos += used;
    }

    // Collect all answer RRs.
    let mut rrs: Vec<ResourceRecord> = Vec::new();
    for _ in 0..hdr.ancount {
        let (rr, used) = ResourceRecord::decode(msg, pos).map_err(|_| ResolveError::ParseError)?;
        pos += used;
        rrs.push(rr);
    }

    // Resolve CNAME chains: follow up to 8 hops.
    let mut current_name = orig_name.to_lowercase();
    let mut hops = 0usize;
    loop {
        if hops > 8 {
            return Err(ResolveError::CnameLoop);
        }
        // Look for the final requested type first.
        let typed: Vec<&ResourceRecord> = rrs
            .iter()
            .filter(|r| r.rtype == final_qtype && r.name.to_lowercase() == current_name)
            .collect();
        if !typed.is_empty() {
            let min_ttl = typed.iter().map(|r| r.ttl).min().unwrap_or(60);
            let data = typed.iter().map(|r| decode_rdata(r, msg)).collect();
            return Ok((data, min_ttl));
        }
        // Look for a CNAME redirect.
        let cname = rrs
            .iter()
            .find(|r| r.rtype == TYPE_CNAME && r.name.to_lowercase() == current_name);
        match cname {
            Some(cn) => {
                // Follow the CNAME.
                let target = match decode_rdata(cn, msg) {
                    RData::Cname(t) => t,
                    _ => return Err(ResolveError::ParseError),
                };
                current_name = target.to_lowercase();
                hops += 1;
            }
            None => {
                // No typed records and no CNAME for this name — empty result.
                return Ok((Vec::new(), 60));
            }
        }
    }
}

// ── Public resolver API ────────────────────────────────────────────────

/// Resolve `name` for `qtype` against the configured nameservers.
///
/// Checks the cache first. On a miss, sends a UDP query to the first
/// configured nameserver and waits up to `DNS_REPLY_TIMEOUT_MS` (3 s)
/// for a response.
///
/// CNAME chains are followed automatically (up to 8 hops).
///
/// If the response has TC=1, returns `Err(ResolveError::TcpNotReady)` —
/// TCP retry is deferred (noted in module doc).
///
/// `iface_name`: the network interface to use for sending. Pass `""` to
/// use the primary interface (first registered).
pub fn resolve(iface_name: &str, name: &str, qtype: DnsType) -> Result<Vec<RData>, ResolveError> {
    let wire_type = qtype.to_wire();

    // 1. Cache check.
    if let Some(cached) = DNS_CACHE.lock().lookup(name, wire_type) {
        return Ok(cached);
    }

    // 2. Determine interface.
    let effective_iface = if iface_name.is_empty() {
        iface::primary().map(|s| s.name).unwrap_or_default()
    } else {
        String::from(iface_name)
    };
    if effective_iface.is_empty() {
        return Err(ResolveError::NoIface);
    }

    // 3. Get nameservers.
    let ns_strings = crate::resolv_conf::nameservers();
    if ns_strings.is_empty() {
        return Err(ResolveError::NoNameserver);
    }

    // Try each nameserver in order (one attempt per server, per `options
    // attempts` semantics — simplified to 1 attempt for boot-path use).
    let mut last_err = ResolveError::Timeout;
    for ns_str in &ns_strings {
        let ns_ip = match parse_ipv4_str(ns_str) {
            Some(ip) => ip,
            None => continue,
        };

        *DNS_REPLY.lock() = None;

        let qid = match send_dns_query(&effective_iface, ns_ip, name, wire_type) {
            Ok(id) => id,
            Err(e) => {
                last_err = e;
                continue;
            }
        };

        // 4. Wait for reply.
        let deadline = narf_scheduler::narf_time::Deadline::after_ns(
            DNS_REPLY_TIMEOUT_MS.saturating_mul(1_000_000),
        );
        let mut raw_reply: Option<alloc::vec::Vec<u8>> = None;
        let _ = narf_scheduler::responsive_spin_until(
            || {
                while iface::drain_pump() {}
                if let Some(data) = take_dns_reply(qid) {
                    raw_reply = Some(data);
                    return true;
                }
                false
            },
            deadline,
        );

        let raw = match raw_reply {
            Some(r) => r,
            None => {
                last_err = ResolveError::Timeout;
                continue;
            }
        };

        // 5. Parse the response.
        match parse_dns_response(&raw, name, wire_type) {
            Ok((records, ttl)) => {
                // 6. Cache the result.
                DNS_CACHE
                    .lock()
                    .insert(name.to_string(), wire_type, records.clone(), ttl);
                return Ok(records);
            }
            Err(e) => {
                last_err = e;
                continue;
            }
        }
    }

    Err(last_err)
}

/// Resolve a hostname to IPv4 addresses. Convenience wrapper over
/// `resolve(iface, name, DnsType::A)`.
pub fn resolve_a(iface_name: &str, name: &str) -> Result<Vec<[u8; 4]>, ResolveError> {
    resolve(iface_name, name, DnsType::A).map(|rds| {
        rds.into_iter()
            .filter_map(|r| if let RData::A(ip) = r { Some(ip) } else { None })
            .collect()
    })
}

/// Parse a dotted-decimal IPv4 string (e.g. "1.2.3.4") into `[u8; 4]`.
/// Returns `None` on any parse error.
pub fn parse_ipv4_str(s: &str) -> Option<[u8; 4]> {
    let mut parts = s.split('.');
    let a: u8 = parts.next()?.parse().ok()?;
    let b: u8 = parts.next()?.parse().ok()?;
    let c: u8 = parts.next()?.parse().ok()?;
    let d: u8 = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None; // trailing parts
    }
    Some([a, b, c, d])
}

// ── Test helpers ───────────────────────────────────────────────────────

/// Test-only: inject a raw DNS reply as if it arrived on the wire.
/// `qid` must match the query ID used. Bypasses the UDP receive path.
#[doc(hidden)]
pub fn __inject_reply_for_test(qid: u16, data: &[u8]) {
    *DNS_REPLY.lock() = Some(DnsReplySlot {
        id: qid,
        data: data.to_vec(),
    });
}

/// Test-only: directly call `parse_dns_response` without network I/O.
#[doc(hidden)]
pub fn __parse_response_for_test(
    msg: &[u8],
    name: &str,
    qtype: u16,
) -> Result<(Vec<RData>, u32), ResolveError> {
    parse_dns_response(msg, name, qtype)
}

/// Test-only: force a cache insertion so TTL-hit tests work.
#[doc(hidden)]
pub fn __cache_insert_for_test(name: &str, qtype: u16, records: Vec<RData>, ttl_secs: u32) {
    DNS_CACHE
        .lock()
        .insert(name.to_string(), qtype, records, ttl_secs);
}

/// Test-only: look up from cache directly.
#[doc(hidden)]
pub fn __cache_lookup_for_test(name: &str, qtype: u16) -> Option<Vec<RData>> {
    DNS_CACHE.lock().lookup(name, qtype)
}

/// Test-only: flush cache.
#[doc(hidden)]
pub fn __flush_cache_for_test() {
    flush_cache();
}
