//! AP-only GET_KEY snapshots through the original deferred request authority.
//! Linux nl80211_get_key/get_key_callback: NEW_KEY reply with top-level and
//! nested cipher/sequence/index, and no temporal key bytes.
use super::*;
use alloc::{boxed::Box, vec};
use core::future::Future;
use narf_net::netlink_generic::DeferredRequest;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Selector {
    index: u8,
    pairwise: bool,
    peer: Option<[u8; 6]>,
}
fn selector(attrs: &[(u16, &[u8])]) -> Result<Selector, i32> {
    reject_unknown(attrs, &[3, 6, 8, 55, 313])?;
    if attr(attrs, 313).is_some() {
        return Err(EINVAL);
    }
    let index = u8_attr(attrs, 8)?.unwrap_or(0);
    if index > 5 {
        return Err(EINVAL);
    } // no BIGTK/beacon protection opt-in
    let peer = match attr(attrs, 6) {
        Some(raw) if raw.len() < 6 => return Err(ERANGE),
        Some(raw) => Some(raw[..6].try_into().map_err(|_| EINVAL)?),
        None => None,
    };
    let pairwise = match u32_attr(attrs, 55)? {
        Some(kind) => match kind {
            0 => false,
            1 => true,
            _ => return Err(EINVAL),
        },
        None => peer.is_some(),
    };
    if pairwise {
        if index != 0 || peer.is_none_or(|mac: [u8; 6]| mac == [0; 6] || mac[0] & 1 != 0) {
            return Err(ENOENT);
        }
    } else if peer.is_some() {
        return Err(ENOENT); // no IBSS_RSN group/peer namespace
    }
    Ok(Selector {
        index,
        pairwise,
        peer,
    })
}
fn errno(error: crate::WirelessError) -> i32 {
    match error {
        crate::WirelessError::NotSupported => EOPNOTSUPP,
        crate::WirelessError::Busy => EBUSY,
        crate::WirelessError::Timeout => 110,
        crate::WirelessError::InvalidArgs => EINVAL,
        crate::WirelessError::HardwareError => 5,
        crate::WirelessError::Denied => EPERM,
    }
}
fn reply(ifindex: u32, wdev: u64, selected: Selector, sequence: crate::KeySequence) -> GenlReply {
    let mut attrs = Vec::new();
    push_attr(&mut attrs, 3, &ifindex.to_ne_bytes());
    push_attr(&mut attrs, 8, &[selected.index]);
    push_attr(&mut attrs, 153, &wdev.to_ne_bytes());
    if let Some(peer) = selected.peer {
        push_attr(&mut attrs, 6, &peer);
    }
    push_attr(&mut attrs, 9, &sequence.cipher.to_ne_bytes());
    push_attr(&mut attrs, 10, &sequence.seq);
    let mut key = Vec::new();
    push_attr(&mut key, 2, &[selected.index]);
    push_attr(&mut key, 3, &sequence.cipher.to_ne_bytes());
    push_attr(&mut key, 4, &sequence.seq);
    // Linux nla_nest_start_noflag: do not invent a different response shape.
    push_attr(&mut attrs, 80, &key);
    GenlReply { command: 11, attrs }
}
pub(super) fn handle(
    bytes: &[u8],
    context: RequestContext<'_>,
    slot: Option<&DeferredRequest>,
) -> Result<Vec<GenlReply>, i32> {
    let attrs = attributes(bytes)?;
    let (ifindex, iface) = netdev_from_attrs(&attrs, context.net_ns_id)?;
    station::netdev_up(iface.as_ref())?;
    let admin = authority(&context, iface.as_ref())?;
    if !matches!(iface.current_iftype(), 3 | 9)
        || iface.ap_control_generation().is_none()
        || !iface.supports_ap_authenticator()
        || !iface.supports_ap_key_sequence()
    {
        return Err(EOPNOTSUPP);
    }
    let selected = selector(&attrs)?;
    // Preserve the exact admitted identity through deferred callbacks; do not
    // re-resolve a receiver or a changed registry enumeration at reply time.
    let wiphy = crate::registry::wiphy_index(iface.wiphy_id()).ok_or(ENODEV)?;
    let wdev = station::wdev_id(wiphy, ifindex);
    let slot = slot.ok_or(EOPNOTSUPP)?;
    let authority = Arc::new(
        crate::ap_control::ApControlAuthority::bind(
            admin,
            &iface,
            context.net_ns_id,
            ifindex,
            slot.reply_sink(),
        )
        .and_then(crate::ap_control::ApControlAuthority::reserve)
        .map_err(errno)?,
    );
    let owned = authority.clone();
    slot.defer_replies_checked(
        Box::pin(async move {
            owned.require_up().map_err(errno)?;
            let mut native = Box::pin(iface.key_sequence_ap_async(
                &owned,
                selected.index,
                selected.pairwise,
                selected.peer,
            ));
            let result = core::future::poll_fn(|cx| {
                if let Err(error) = owned.current() {
                    return core::task::Poll::Ready(Err(errno(error)));
                }
                native.as_mut().poll(cx)
            })
            .await;
            drop(native);
            let sequence = result.map_err(i32::abs)?;
            owned.check_for(iface.as_ref()).map_err(errno)?;
            owned.require_up().map_err(errno)?;
            if sequence.cipher == 0 {
                return Err(EINVAL);
            }
            Ok(vec![reply(ifindex, wdev, selected, sequence)])
        }),
        authority,
    )?;
    Ok(Vec::new())
}

#[cfg(feature = "kernel-test")]
#[path = "ap_key_parse_tests.rs"]
mod tests;
