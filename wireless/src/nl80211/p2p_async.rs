//! Native P2P-device/ROC requests keep their exact source and real WDEV.
//! No netdev, administrative UP bit or native started receipt is invented.
use super::*;
use alloc::boxed::Box;
use core::future::Future;
use narf_net::netlink_generic::DeferredRequest;

pub(super) enum Operation {
    Start,
    Stop,
    Roc {
        cookie: u64,
        frequency_mhz: u32,
        duration_ms: u32,
    },
    Cancel(u64),
}
/// Only these explicitly opted-in control-only operations may consult a
/// fresh child grant retained on the actual creating socket. Legacy callers
/// retain the existing RequestContext authority path.
pub(super) fn source_authority(
    context: &RequestContext<'_>,
    iface: &dyn crate::WirelessNetIface,
    slot: Option<&DeferredRequest>,
) -> Result<narf_net::AdminHandle, i32> {
    authority(context, iface).or_else(|error| {
        if iface.control_namespace() != Some(context.net_ns_id) {
            return Err(error);
        }
        slot.and_then(|slot| {
            slot.reply_sink()
                .control_admin(iface.name(), context.net_ns_id)
        })
        .filter(|admin| {
            admin
                .authorize_interface(iface.name(), context.net_ns_id)
                .is_ok()
        })
        .ok_or(error)
    })
}
fn errno(error: crate::WirelessError) -> i32 {
    match error {
        crate::WirelessError::Timeout => 110,
        crate::WirelessError::HardwareError => 5,
        other => mlme_errno(other),
    }
}

/// Resolve the original request once. Both selectors, if supplied, must
/// identify the same actual netdev. A control WDEV has no IFINDEX alias.
pub(super) fn interface(
    attrs: &[(u16, &[u8])],
    namespace: u64,
) -> Result<(Arc<dyn crate::WirelessNetIface>, Option<u32>), i32> {
    let index = u32_attr(attrs, 3)?;
    let id = u64_attr(attrs, 153)?;
    if let Some(id) = id {
        if let Some(iface) = crate::registry::control_by_id(id, namespace) {
            if index.is_some() {
                return Err(EINVAL);
            }
            return Ok((iface, None));
        }
        let iface = crate::registry::list()
            .into_iter()
            .find(|iface| {
                iface.control_namespace().is_none()
                    && super::super::in_namespace(iface.as_ref(), namespace)
                    && narf_net::netlink_route::ifindex_for_name(iface.name()).is_some_and(
                        |actual| {
                            index.is_none_or(|index| actual == index)
                                && crate::registry::wiphy_index(iface.wiphy_id())
                                    .is_some_and(|wiphy| station::wdev_id(wiphy, actual) == id)
                        },
                    )
            })
            .ok_or(ENODEV)?;
        let index = narf_net::netlink_route::ifindex_for_name(iface.name()).ok_or(ENODEV)?;
        return Ok((iface, Some(index)));
    }
    let (index, iface) = netdev_from_attrs(attrs, namespace)?;
    Ok((iface, Some(index)))
}

pub(super) fn device(
    command: u8,
    bytes: &[u8],
    context: RequestContext<'_>,
    slot: Option<&DeferredRequest>,
) -> Result<Vec<GenlReply>, i32> {
    let attrs = attributes(bytes)?;
    reject_unknown(&attrs, &[3, 153])?;
    let (iface, index) = interface(&attrs, context.net_ns_id)?;
    let admin = source_authority(&context, iface.as_ref(), slot)?;
    if index.is_some() || iface.current_iftype() != 10 || !iface.async_p2p_device_control() {
        return Err(EOPNOTSUPP);
    }
    defer(
        iface,
        admin,
        context.net_ns_id,
        None,
        slot,
        if command == START_P2P_DEVICE {
            Operation::Start
        } else {
            Operation::Stop
        },
    )
}

pub(super) fn defer(
    iface: Arc<dyn crate::WirelessNetIface>,
    admin: narf_net::AdminHandle,
    namespace: u64,
    index: Option<u32>,
    slot: Option<&DeferredRequest>,
    operation: Operation,
) -> Result<Vec<GenlReply>, i32> {
    let slot = slot.ok_or(EOPNOTSUPP)?;
    let authority = match index {
        Some(index) => crate::ap_control::RadioControlAuthority::bind(
            admin,
            &iface,
            namespace,
            index,
            slot.reply_sink(),
        ),
        None => {
            let wdev = crate::registry::control_for(iface.as_ref()).ok_or(ENODEV)?;
            crate::ap_control::RadioControlAuthority::bind_wdev(
                admin,
                &iface,
                namespace,
                wdev.id(),
                slot.reply_sink(),
            )
        }
    }
    .and_then(crate::ap_control::RadioControlAuthority::reserve)
    .map_err(errno)?;
    authority.require_link().map_err(errno)?;
    let authority = Arc::new(authority);
    let retained = authority.clone();
    slot.defer_replies_checked(
        Box::pin(async move {
            let call = retained.clone();
            let mut native = Box::pin(async move {
                let mut replies = Vec::new();
                match operation {
                    Operation::Start => iface.start_p2p_device_async(&call).await,
                    Operation::Stop => iface.stop_p2p_device_async(&call).await,
                    Operation::Cancel(cookie) => {
                        iface.cancel_remain_on_channel_async(&call, cookie).await
                    }
                    Operation::Roc {
                        cookie,
                        frequency_mhz,
                        duration_ms,
                    } => {
                        let result = iface
                            .remain_on_channel_async(&call, cookie, frequency_mhz, duration_ms)
                            .await;
                        if result.is_ok() {
                            let mut attrs = Vec::new();
                            push_attr(&mut attrs, 88, &cookie.to_ne_bytes());
                            replies.push(GenlReply {
                                command: REMAIN_ON_CHANNEL,
                                attrs,
                            });
                        }
                        result
                    }
                }
                .map_err(errno)?;
                call.check_for(iface.as_ref()).map_err(errno)?;
                Ok(replies)
            });
            let result = core::future::poll_fn(|cx| {
                if let Err(error) = retained.require_link() {
                    return core::task::Poll::Ready(Err(errno(error)));
                }
                native.as_mut().poll(cx)
            })
            .await;
            drop(native);
            retained.require_link().map_err(errno)?;
            result
        }),
        authority,
    )?;
    Ok(Vec::new())
}
