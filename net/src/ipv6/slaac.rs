//! Stateless Address Autoconfiguration — RFC 4862 + RFC 8981.
//!
//! References (public-only):
//! - RFC 4862 — IPv6 Stateless Address Autoconfiguration (S. Thomson,
//!   T. Narten, T. Jinmei, Sep 2007). §4 (overview), §5.3 (creation of
//!   link-local addresses), §5.4 (DAD), §5.5.3 (autonomous address-
//!   configuration), §5.5.4 (state transitions for preferred / valid
//!   lifetimes).
//!   <https://datatracker.ietf.org/doc/html/rfc4862>
//! - RFC 8981 — Temporary Addresses for IPv6 (F. Gont, S. Krishnan,
//!   T. Narten, R. Draves, Feb 2021). §3 (constants), §3.3 (privacy
//!   address generation).
//!   <https://datatracker.ietf.org/doc/html/rfc8981>
//! - RFC 7217 — Stable Privacy-Enhanced IIDs (F. Gont, Apr 2014).
//!   <https://datatracker.ietf.org/doc/html/rfc7217>
//!
//! Two address kinds per autonomous PIO:
//! - Stable: prefix || EUI-64-from-MAC (or RFC-7217 opaque IID).
//! - Temporary: prefix || random IID rotated every ~24h.
//!
//! Both run DAD on creation. The stable one feeds source-address
//! selection's "use the same scope first" rule; the temporary one is
//! preferred for new outbound flows but is left in place until its
//! valid lifetime expires.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use super::addrs::{
    self, eui64_from_mac, link_local_from_mac, random_iid, slaac_compose, AddrScope, AddrState,
    Ipv6IfAddr,
};
use super::ndp::RaPrefix;

/// Configuration knob for SLAAC's privacy addresses.
#[derive(Copy, Clone, Debug)]
pub struct SlaacConfig {
    /// Generate RFC 8981 temporary addresses alongside the stable one.
    pub privacy_extensions: bool,
    /// Maximum desired lifetime for temporary addresses, in seconds.
    /// RFC 8981 §3.3 recommends 86400 (24h).
    pub temp_valid_lifetime_s: u32,
    /// Maximum desired preferred lifetime for temporary addresses.
    /// RFC 8981 §3.3 recommends 21600 (6h).
    pub temp_preferred_lifetime_s: u32,
}

impl Default for SlaacConfig {
    fn default() -> Self {
        Self {
            privacy_extensions: true,
            temp_valid_lifetime_s: 86_400,
            temp_preferred_lifetime_s: 21_600,
        }
    }
}

/// Generated address tuple (the caller will install it into the addr
/// registry and run DAD).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlaacAddress {
    pub addr: [u8; 16],
    pub prefix_len: u8,
    pub preferred_lifetime_s: u32,
    pub valid_lifetime_s: u32,
    pub temporary: bool,
}

/// Drop a tentative link-local at iface-up time.
///
/// Returns the constructed `Ipv6IfAddr` for the caller to install in
/// the registry and trigger DAD on. Idempotent: if a link-local is
/// already bound it is replaced.
pub fn link_local(iface: &str, mac: [u8; 6], now_ns: u64) -> Ipv6IfAddr {
    let addr = link_local_from_mac(mac);
    let entry = Ipv6IfAddr {
        iface: String::from(iface),
        addr,
        prefix_len: 64,
        state: AddrState::Tentative,
        scope: AddrScope::LinkLocal,
        // Link-local lifetimes are infinite (RFC 4291 §2.5.6).
        preferred_deadline_ns: u64::MAX,
        valid_deadline_ns: u64::MAX,
        temporary: false,
    };
    addrs::add(entry.clone());
    let _ = now_ns; // reserved for future DAD timer expansion
    entry
}

/// Process one PIO (Prefix Information Option) from an RA. Returns
/// every address the SLAAC engine wants to bring up. RFC 4862 §5.5.3.
///
/// Skipped silently when:
/// - `pio.autonomous == false` (A=0)
/// - `pio.prefix_len != 64` (RFC 7421: SLAAC requires /64)
/// - `pio.preferred_lifetime_s > pio.valid_lifetime_s` (malformed)
/// - The prefix is link-local (must not be auto-configured this way)
pub fn process_pio(
    iface: &str,
    mac: [u8; 6],
    pio: &RaPrefix,
    cfg: SlaacConfig,
    now_ns: u64,
) -> Vec<SlaacAddress> {
    let mut out = Vec::new();
    if !pio.autonomous {
        return out;
    }
    if pio.prefix_len != 64 {
        return out;
    }
    if pio.preferred_lifetime_s > pio.valid_lifetime_s {
        return out;
    }
    if pio.prefix[0] == 0xFE && (pio.prefix[1] & 0xC0) == 0x80 {
        return out;
    }
    // Stable: EUI-64 IID.
    let stable = slaac_compose(&pio.prefix, pio.prefix_len, &eui64_from_mac(mac));
    out.push(SlaacAddress {
        addr: stable,
        prefix_len: pio.prefix_len,
        preferred_lifetime_s: pio.preferred_lifetime_s,
        valid_lifetime_s: pio.valid_lifetime_s,
        temporary: false,
    });
    // Temporary: random IID, possibly with shorter lifetimes
    // (RFC 8981 §3.3 — caps the lifetimes at TEMP_*_LIFETIME).
    if cfg.privacy_extensions {
        let seed = now_ns
            .rotate_left(13)
            ^ u64::from_be_bytes([mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], 0, 0]);
        let iid = random_iid(seed);
        let temp = slaac_compose(&pio.prefix, pio.prefix_len, &iid);
        let temp_valid = pio.valid_lifetime_s.min(cfg.temp_valid_lifetime_s);
        let temp_preferred = pio.preferred_lifetime_s.min(cfg.temp_preferred_lifetime_s);
        out.push(SlaacAddress {
            addr: temp,
            prefix_len: pio.prefix_len,
            preferred_lifetime_s: temp_preferred,
            valid_lifetime_s: temp_valid,
            temporary: true,
        });
    }
    // Install each as Tentative in the addr registry. Real-HW DAD is
    // wired by the dispatch layer (ipv6_stack); the registry holds
    // them as Tentative until DAD passes.
    for a in &out {
        addrs::add(Ipv6IfAddr {
            iface: String::from(iface),
            addr: a.addr,
            prefix_len: a.prefix_len,
            state: AddrState::Tentative,
            scope: addrs::scope_of(&a.addr),
            preferred_deadline_ns: now_ns
                .saturating_add((a.preferred_lifetime_s as u64) * 1_000_000_000),
            valid_deadline_ns: now_ns
                .saturating_add((a.valid_lifetime_s as u64) * 1_000_000_000),
            temporary: a.temporary,
        });
    }
    out
}

/// Mark an address as DAD-passed → Preferred.
pub fn dad_passed(iface: &str, addr: &[u8; 16]) {
    addrs::set_state(iface, addr, AddrState::Preferred);
}

/// Mark an address as DAD-failed → drop.
pub fn dad_failed(iface: &str, addr: &[u8; 16]) {
    addrs::remove(iface, addr);
}
