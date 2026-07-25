//! Per-network-namespace netfilter state.
//!
//! Namespace id zero is the initial network namespace.  Non-zero ids are
//! minted by the userspace namespace layer and select independent rule,
//! conntrack, and NAT stores here.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;

use narf_capabilities::{Cap, CapKind, CapType, Invoke};
use narf_lib::sync::IrqSafeSpinLock;

use super::conntrack::{Conntrack, MAX_ENTRIES};
use super::filter::Filter;
use super::nat::Nat;

/// All mutable netfilter state owned by one network namespace.
#[derive(Debug)]
pub struct NetfilterNamespace {
    id: u64,
    pub(crate) filter: Filter,
    pub(crate) conntrack: Conntrack,
    pub(crate) nat: Nat,
}

#[derive(Copy, Clone, Debug)]
pub struct NetfilterAdminCap;

impl CapType for NetfilterAdminCap {
    const KIND: CapKind = CapKind::NetfilterAdmin;
}

/// Operations independently delegable for a namespace firewall.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct NetfilterRights(u32);

impl NetfilterRights {
    pub const READ: Self = Self(1 << 0);
    pub const RULESET: Self = Self(1 << 1);
    pub const CONNTRACK: Self = Self(1 << 2);
    pub const NAT: Self = Self(1 << 3);
    pub const ALL: Self = Self(Self::READ.0 | Self::RULESET.0 | Self::CONNTRACK.0 | Self::NAT.0);

    pub const fn contains(self, required: Self) -> bool {
        self.0 & required.0 == required.0
    }
}

/// Revocable authority inseparably bound to one network namespace.
#[derive(Clone, Debug)]
pub struct NetfilterAdminHandle {
    cap: Cap<NetfilterAdminCap, Invoke>,
    net_ns_id: u64,
    rights: NetfilterRights,
}

impl NetfilterAdminHandle {
    pub fn mint(net_ns_id: u64, rights: NetfilterRights) -> Self {
        Self {
            cap: Cap::bootstrap(),
            net_ns_id,
            rights,
        }
    }

    pub fn net_ns_id(&self) -> u64 {
        self.net_ns_id
    }

    pub fn check(&self, required: NetfilterRights) -> Result<(), NetfilterAuthorityError> {
        self.cap
            .check_live()
            .map_err(|_| NetfilterAuthorityError::Revoked)?;
        self.rights
            .contains(required)
            .then_some(())
            .ok_or(NetfilterAuthorityError::RightsTooWeak)
    }

    pub fn revoke(self) {
        self.cap.revoke();
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum NetfilterAuthorityError {
    Revoked,
    RightsTooWeak,
}

impl NetfilterNamespace {
    fn new(id: u64) -> Self {
        Self {
            id,
            filter: Filter::new(),
            conntrack: Conntrack::new(MAX_ENTRIES),
            nat: Nat::new(),
        }
    }

    pub fn id(&self) -> u64 {
        self.id
    }
}

static NAMESPACES: IrqSafeSpinLock<BTreeMap<u64, Arc<NetfilterNamespace>>> =
    IrqSafeSpinLock::new(BTreeMap::new());

/// Resolve (and, on first use, create) the state for `id`.
pub fn get(id: u64) -> Arc<NetfilterNamespace> {
    let mut namespaces = NAMESPACES.lock();
    namespaces
        .entry(id)
        .or_insert_with(|| Arc::new(NetfilterNamespace::new(id)))
        .clone()
}

#[cfg(test)]
pub(crate) fn reset_all() {
    NAMESPACES.lock().clear();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netfilter::rules::Match;
    use crate::netfilter::Verdict;

    #[test]
    fn namespace_rulesets_are_isolated() {
        reset_all();
        crate::netfilter::filter::nf_table_add_in(
            41,
            "filter",
            "input",
            Match::any(),
            Verdict::Drop,
        );
        assert_eq!(get(41).filter.snapshot().len(), 1);
        assert!(get(42).filter.snapshot().is_empty());
    }

    #[test]
    fn authority_is_scoped_limited_and_revocable() {
        let admin = NetfilterAdminHandle::mint(77, NetfilterRights::READ);
        assert_eq!(admin.net_ns_id(), 77);
        assert_eq!(admin.check(NetfilterRights::READ), Ok(()));
        assert_eq!(
            admin.check(NetfilterRights::RULESET),
            Err(NetfilterAuthorityError::RightsTooWeak)
        );
        let copy = admin.clone();
        admin.revoke();
        assert_eq!(
            copy.check(NetfilterRights::READ),
            Err(NetfilterAuthorityError::Revoked)
        );
    }
}
