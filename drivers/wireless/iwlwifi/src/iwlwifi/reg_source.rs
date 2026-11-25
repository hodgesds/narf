//! The installed regulatory domain, for the Gen2 MVM owner's policy reads.
//!
//! Built in, `narf_wireless::reg::db::get_domain()`. In the module build the
//! kernel's database is read through the `WIFI` host and cached per revision
//! (`module/regulatory.rs`); this answers that cache, which is the same
//! snapshot the module's MLD station fences use.

/// The installed domain, or `None` when no policy is installed.
pub(super) fn get_domain() -> Option<narf_wireless::reg::RegulatoryDomain> {
    #[cfg(feature = "builtin")]
    return narf_wireless::reg::db::get_domain();
    #[cfg(feature = "module")]
    return super::module::regulatory::snapshot().map(|domain| domain.as_ref().clone());
}
