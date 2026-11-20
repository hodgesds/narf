// SPDX-License-Identifier: GPL-2.0-or-later
//! Firmware-SME peer observations and software copy/port generations. These
//! epochs are not reconstructed firmware SCB generations or RX key indices.
use super::{
    ap_key::Installed,
    ap_native::{self, Guard},
    ap_plan::Plan,
    ap_scope::Epoch,
    ap_wire,
};
use crate::cyw43439::{fullmac::Fullmac, runtime::Error};
use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicUsize, Ordering};
use narf_wireless::ap_control::ApEmissionAuthority;

pub(super) const MAX_PEERS: usize = 8;
pub(super) struct Peer {
    pub(super) mac: [u8; 6],
    pub(super) ies: Vec<u8>,
    pub(super) observed: Option<ap_wire::Peer>,
    pub(super) epoch: Epoch,
    pub(super) data: Epoch,
    pub(super) key_epoch: Epoch,
    pub(super) key: Option<Installed>,
    pub(super) authorized: bool,
    pub(super) authorization: Option<ApEmissionAuthority>,
    pub(super) associated: bool,
    /// Real observed deletion/absence is required before same-MAC re-add.
    pub(super) removed: bool,
    pub(super) verify: bool,
    pub(super) remove_requested: bool,
    pub(super) removal_observed: bool,
    pub(super) absent: bool,
    pub(super) notified: bool,
    pub(super) delete_sent: bool,
    pub(super) removal_deadline: Option<narf_time::Deadline>,
    pub(super) removal_reason: u16,
    copies: Arc<AtomicUsize>,
}
impl Peer {
    pub(super) fn indication(mac: [u8; 6], ies: Vec<u8>, plan: &Plan) -> Result<Self, Error> {
        if !ap_wire::unicast(mac) || mac == plan.own || ies.is_empty() || ies.len() > 2304 {
            return Err(Error::Malformed);
        }
        validate_ies(&ies, plan)?;
        Ok(Self {
            mac,
            ies,
            observed: None,
            epoch: Epoch::new(),
            data: Epoch::new(),
            key_epoch: Epoch::new(),
            key: None,
            authorized: false,
            authorization: None,
            associated: false,
            removed: false,
            verify: true,
            remove_requested: false,
            removal_observed: false,
            absent: false,
            notified: false,
            delete_sent: false,
            removal_deadline: None,
            removal_reason: 3,
            copies: Arc::new(AtomicUsize::new(0)),
        })
    }
    /// Apply denial at the actual event boundary before any async native
    /// query or prepared callback. The post-loss peer epoch may carry DEL;
    /// old DATA/key/copy captures cannot become current after a later add.
    pub(super) fn deny(&mut self, removal: bool) -> Result<(), Error> {
        self.data.advance().map_err(|_| Error::Failed)?;
        self.key_epoch.advance().map_err(|_| Error::Failed)?;
        self.epoch.advance().map_err(|_| Error::Failed)?;
        self.key = None;
        self.authorization = None;
        self.authorized = false;
        self.associated = false;
        self.verify = false;
        self.removed = removal;
        Ok(())
    }
    pub(super) fn data_current(&self, privacy: bool) -> bool {
        self.associated
            && !self.removed
            && self.authorized
            && self.epoch.current()
            && self.data.current()
            && self
                .authorization
                .as_ref()
                .is_some_and(ApEmissionAuthority::current)
            && (!privacy || self.key.as_ref().is_some_and(Installed::current))
    }
    pub(super) fn copy(&self) -> Result<CopyLease, Error> {
        self.copies
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |old| {
                old.checked_add(1)
            })
            .map_err(|_| Error::EventOverflow)?;
        Ok(CopyLease(self.copies.clone()))
    }
    pub(super) fn unused(&self) -> bool {
        self.copies.load(Ordering::Acquire) == 0
    }
}
pub(crate) struct CopyLease(Arc<AtomicUsize>);
pub(super) struct Rejected {
    pub(super) mac: [u8; 6],
    pub(super) sent: bool,
    pub(super) deadline: Option<narf_time::Deadline>,
    pub(super) epoch: Epoch,
}
impl Drop for CopyLease {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}
impl Drop for Peer {
    fn drop(&mut self) {
        self.epoch.close();
        self.data.close();
        self.key_epoch.close();
    }
}
fn validate_ies(mut ies: &[u8], plan: &Plan) -> Result<(), Error> {
    let mut ssid = false;
    let mut rates = Vec::new();
    let mut rsne = None;
    while !ies.is_empty() {
        let n = usize::from(*ies.get(1).ok_or(Error::Malformed)?);
        let element = ies.get(..2 + n).ok_or(Error::Malformed)?;
        match element[0] {
            0 => {
                if ssid || element[2..] != plan.config.ssid {
                    return Err(Error::Malformed);
                }
                ssid = true;
            }
            1 | 50 => {
                if n == 0 || element[0] == 1 && n > 8 {
                    return Err(Error::Malformed);
                }
                rates.extend_from_slice(&element[2..]);
            }
            48 => {
                if rsne.replace(element).is_some() {
                    return Err(Error::Malformed);
                }
            }
            // This owner actually programs a legacy, non-WMM BSS. Optional
            // PHY/WMM/UAPSD/PMF/client roles are not silently accepted.
            45 | 61 | 191 | 192 | 244 | 255 => return Err(Error::Unsupported),
            221 if element[2..].starts_with(&[0, 0x50, 0xf2, 1])
                || element[2..].starts_with(&[0, 0x50, 0xf2, 2])
                || element[2..].starts_with(&[0x50, 0x6f, 0x9a, 9]) =>
            {
                return Err(Error::Unsupported)
            }
            _ => {}
        }
        ies = &ies[element.len()..];
    }
    if !ssid || rates.is_empty() || rates.len() > 16 {
        return Err(Error::Malformed);
    }
    for basic in plan.rates.iter().filter(|rate| **rate & 128 != 0) {
        if !rates.iter().any(|rate| rate & 127 == basic & 127) {
            return Err(Error::Unsupported);
        }
    }
    match (rsne, &plan.rsne) {
        (None, None) => {}
        (Some(request), Some(expected)) => {
            use narf_wireless::rsn::RsnIe;
            let request = RsnIe::decode_body(&request[2..]).ok_or(Error::Malformed)?;
            let expected = RsnIe::decode_body(&expected[2..]).ok_or(Error::Malformed)?;
            if request.group_cipher != expected.group_cipher
                || request.pairwise_ciphers != expected.pairwise_ciphers
                || request.akms != expected.akms
                || request.rsn_capabilities & 0xc0 != 0
                || request.group_management_cipher.is_some()
            {
                return Err(Error::Unsupported);
            }
        }
        _ => return Err(Error::Unsupported),
    }
    Ok(())
}
pub(super) async fn query<R: Fullmac>(
    runtime: &mut R,
    guard: &Guard<'_>,
    mac: [u8; 6],
) -> Result<ap_wire::Peer, Error> {
    let reply = ap_native::get_var(runtime, guard, "sta_info", &mac, 512).await?;
    let peer = ap_wire::peer(&reply)?;
    // Native firmware authentication+association, not UI metadata, creates
    // this peer. WME is unsupported by the actual disabled profile.
    if peer.mac != mac || peer.flags & 0x18 != 0x18 || peer.flags & 2 != 0 {
        return Err(Error::Malformed);
    }
    Ok(peer)
}
