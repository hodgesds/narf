//! The kernel's regulatory domain, for the module build.
//!
//! Built in, the station's RF policy (`mld_policy`, `reg_source`) reads
//! `narf_wireless::reg::db`: the signed deployment policy, a Linux-database
//! country, or a domain `iw reg set` installed. A module cannot link that
//! database. It copies the kernel's active domain through the shared KABI
//! export `narf_wireless_regdomain` (one NRGD v1 record, decoded by the
//! kernel-free `narf_wireless::reg::parse_domain_record`: the policy loader's
//! layout and rule checks, accepting the world domain "00" the kernel holds
//! until a policy is installed, as the built-in database read does) and
//! caches it:
//!
//! - [`ensure_snapshot`] — where the built-in makes its initial request
//!   (`reg::db::ensure_snapshot`): read and refresh the cache.
//! - [`snapshot`] — `reg::db::snapshot`: the cached domain, one `Arc` until
//!   the kernel's domain changes, because the policy fences compare
//!   snapshots by identity on every publication.
//! - [`refresh`] — re-read; a changed domain replaces the `Arc` (every fence
//!   bound to the old one then fails, as a built-in reinstall does), an
//!   absent one clears it. The radio's service loop calls this once a second.
//!
//! Without a domain (`-ENODATA`), or when the read fails, the cache is empty
//! and every RF-emitting path fails closed, as built in without a policy.
//! [`read`] is the one function that touches the KABI.

use alloc::sync::Arc;

use narf_wireless::reg::RegulatoryDomain;

use super::kernel::narf_lib::sync::IrqSafeSpinLock;

mod ffi {
    unsafe extern "C" {
        pub fn narf_wireless_regdomain(buf: *mut u8, len: usize, out_len: *mut usize) -> i32;
    }
}

const ENOBUFS: i32 = -105;
const ENODATA: i32 = -61;

/// The cached domain.
static CACHE: IrqSafeSpinLock<Option<Arc<RegulatoryDomain>>> = IrqSafeSpinLock::new(None);

/// The kernel's active domain: `Ok(None)` when none is installed. The only
/// KABI call here (one NRGD v1 record, sized with a zero-length call).
fn read() -> Result<Option<RegulatoryDomain>, i32> {
    let mut needed = 0usize;
    // SAFETY: sizing call — null buffer, zero length, live `needed`.
    match unsafe { ffi::narf_wireless_regdomain(core::ptr::null_mut(), 0, &mut needed) } {
        ENODATA => return Ok(None),
        0 | ENOBUFS => {}
        error => return Err(error),
    }
    let mut record = alloc::vec![0u8; needed];
    let mut len = 0usize;
    // SAFETY: `record` names `needed` writable bytes; `len` is a live local.
    match unsafe { ffi::narf_wireless_regdomain(record.as_mut_ptr(), record.len(), &mut len) } {
        0 => {}
        ENODATA => return Ok(None),
        error => return Err(error),
    }
    let record = record.get(..len).ok_or(-5)?;
    narf_wireless::reg::parse_domain_record(record)
        .map(Some)
        .map_err(|_| -5)
}

/// Install a freshly read domain, keeping the cached `Arc` when the domain is
/// unchanged.
fn install(read: Option<RegulatoryDomain>) -> Option<Arc<RegulatoryDomain>> {
    let mut cache = CACHE.lock();
    match read {
        None => {
            *cache = None;
            None
        }
        Some(domain) => {
            if let Some(current) = cache.as_ref() {
                if **current == domain {
                    return Some(current.clone());
                }
            }
            let domain = Arc::new(domain);
            *cache = Some(domain.clone());
            Some(domain)
        }
    }
}

/// `reg::db::snapshot`: the cached domain.
pub(crate) fn snapshot() -> Option<Arc<RegulatoryDomain>> {
    CACHE.lock().clone()
}

/// `reg::db::ensure_snapshot`: the kernel's domain, read now.
pub(crate) fn ensure_snapshot() -> Result<Arc<RegulatoryDomain>, ()> {
    install(read().unwrap_or(None)).ok_or(())
}

/// `reg::db::ensure_domain`.
pub(crate) fn ensure_domain() -> Result<RegulatoryDomain, ()> {
    ensure_snapshot().map(|domain| domain.as_ref().clone())
}

/// Re-read the kernel's domain (see the module docs). A failed read clears
/// the cache, so emitting paths fail closed.
pub(crate) fn refresh() {
    let _ = install(read().unwrap_or(None));
}
