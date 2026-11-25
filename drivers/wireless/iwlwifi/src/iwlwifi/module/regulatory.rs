//! The kernel's regulatory domain, for the module build.
//!
//! Built in, the station's RF policy (`mld_policy`) reads
//! `narf_wireless::reg::db`: the signed deployment policy, a Linux-database
//! country, or a domain `iw reg set` installed. A module cannot link that
//! database, so it asks the `WIFI` family host for the kernel's current
//! domain (`GET_REGULATORY`, an additive v2 opcode) and caches it:
//!
//! - [`ensure_snapshot`] — the built-in `reg::db::ensure_snapshot`: query
//!   (bootstrapping the staged signed policy when none is installed) and
//!   refresh the cache; used where the built-in driver makes its initial
//!   request (association, active scan).
//! - [`snapshot`] — the built-in `reg::db::snapshot`: the cached domain, as
//!   one `Arc` until the kernel's revision changes, because the policy fences
//!   compare snapshots by identity on every publication.
//! - [`refresh`] — re-read the kernel's domain; a changed revision replaces
//!   the `Arc` (every fence bound to the old one then fails, exactly as a
//!   built-in reinstall does), an absent domain clears it. The radio's
//!   service loop calls this once a second.
//!
//! An older host without the opcode answers `-EOPNOTSUPP`: the cache stays
//! empty and every RF-emitting path fails closed, as built in without a
//! policy.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use narf_wireless::reg::{RegFlags, RegRule, RegulatoryDomain};

use super::kernel::narf_lib::sync::IrqSafeSpinLock;

mod ffi {
    unsafe extern "C" {
        pub fn narf_wireless_submit(
            dev: u64,
            session: u64,
            opcode: u32,
            request: *const u8,
            len: usize,
            out_op: *mut u64,
        ) -> i32;
        pub fn narf_wireless_poll(
            dev: u64,
            session: u64,
            op: u64,
            reply: *mut u8,
            len: usize,
            out_len: *mut usize,
        ) -> i32;
    }
}

/// `module_host::OP_GET_REGULATORY`.
const OP_GET_REGULATORY: u32 = 0x06;
/// `module_host::MAX_REGULATORY_RULES` / `REGULATORY_RULE_LEN`.
const MAX_RULES: usize = 128;
const RULE_LEN: usize = 20;

/// The device's `WIFI` session; 0 until the radio opens it.
static SESSION: AtomicU64 = AtomicU64::new(0);
/// The cached domain and the kernel revision it was read at.
static CACHE: IrqSafeSpinLock<Option<(u64, Arc<RegulatoryDomain>)>> = IrqSafeSpinLock::new(None);

/// Bind the queries to the device's `WIFI` session.
pub(crate) fn set_session(session: u64) {
    SESSION.store(session, Ordering::Release);
}

/// Decode a `GET_REGULATORY` reply (`module_host::encode_regulatory`).
fn decode(bytes: &[u8]) -> Option<(u64, RegulatoryDomain)> {
    let revision = u64::from_le_bytes(bytes.get(..8)?.try_into().ok()?);
    let country_code: [u8; 2] = bytes.get(8..10)?.try_into().ok()?;
    let count = usize::from(u16::from_le_bytes(bytes.get(10..12)?.try_into().ok()?));
    if bytes.get(12..16)? != [0; 4] || count > MAX_RULES || bytes.len() != 16 + count * RULE_LEN {
        return None;
    }
    let mut rules = Vec::with_capacity(count);
    for raw in bytes[16..].chunks_exact(RULE_LEN) {
        let word = |at: usize| u32::from_le_bytes([raw[at], raw[at + 1], raw[at + 2], raw[at + 3]]);
        if raw[13..16] != [0; 3] {
            return None;
        }
        rules.push(RegRule {
            freq_start_mhz: word(0),
            freq_end_mhz: word(4),
            max_bandwidth_mhz: word(8),
            max_power_dbm: raw[12] as i8,
            // An unknown bit is a restriction this build cannot honour.
            flags: RegFlags::from_bits(word(16))?,
        });
    }
    Some((
        revision,
        RegulatoryDomain {
            country_code,
            rules,
        },
    ))
}

/// One `GET_REGULATORY` round trip. `Ok(None)`: no domain is installed.
fn query(ensure: bool) -> Result<Option<(u64, RegulatoryDomain)>, i32> {
    let session = SESSION.load(Ordering::Acquire);
    if session == 0 {
        return Err(-19);
    }
    let request = [u8::from(ensure), 0, 0, 0];
    let mut op = 0u64;
    // SAFETY: `request` names four readable bytes; `op` is a live local.
    let rc = unsafe {
        ffi::narf_wireless_submit(
            super::device(),
            session,
            OP_GET_REGULATORY,
            request.as_ptr(),
            request.len(),
            &mut op,
        )
    };
    if rc != 0 {
        return Err(rc);
    }
    let mut reply = alloc::vec![0u8; 16 + MAX_RULES * RULE_LEN];
    let mut len = 0usize;
    // SAFETY: `reply` names its length in writable bytes; `len` is a live local.
    let rc = unsafe {
        ffi::narf_wireless_poll(
            super::device(),
            session,
            op,
            reply.as_mut_ptr(),
            reply.len(),
            &mut len,
        )
    };
    match rc {
        0 => decode(reply.get(..len).ok_or(-5)?).map(Some).ok_or(-5),
        -2 => Ok(None),
        error => Err(error),
    }
}

/// Install a freshly read domain, keeping the cached `Arc` when the kernel's
/// revision (and so the domain) is unchanged.
fn install(read: Option<(u64, RegulatoryDomain)>) -> Option<Arc<RegulatoryDomain>> {
    let mut cache = CACHE.lock();
    match read {
        None => {
            *cache = None;
            None
        }
        Some((revision, domain)) => {
            if let Some((cached, current)) = cache.as_ref() {
                if *cached == revision && **current == domain {
                    return Some(current.clone());
                }
            }
            let domain = Arc::new(domain);
            *cache = Some((revision, domain.clone()));
            Some(domain)
        }
    }
}

/// `reg::db::snapshot`: the cached domain.
pub(crate) fn snapshot() -> Option<Arc<RegulatoryDomain>> {
    CACHE.lock().as_ref().map(|(_, domain)| domain.clone())
}

/// `reg::db::ensure_snapshot`: the kernel's domain, bootstrapping the staged
/// signed policy when none is installed.
pub(crate) fn ensure_snapshot() -> Result<Arc<RegulatoryDomain>, ()> {
    match query(true) {
        Ok(read) => install(read).ok_or(()),
        Err(_) => Err(()),
    }
}

/// `reg::db::ensure_domain`.
pub(crate) fn ensure_domain() -> Result<RegulatoryDomain, ()> {
    ensure_snapshot().map(|domain| domain.as_ref().clone())
}

/// Re-read the kernel's current domain (see the module docs). A failed query
/// clears the cache: without a current answer from the authority, emitting
/// paths fail closed. (All queries run on the module's one executor, so the
/// session's single operation slot is never contended.)
pub(crate) fn refresh() {
    let read = query(false).unwrap_or(None);
    let _ = install(read);
}
