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
    RegisterFrame(u16, Vec<u8>),
    Frame {
        cookie: u64,
        request: crate::MgmtTxRequest,
    },
    /// `nl80211_trigger_scan` on the control WDEV (`p2p_scan_async`).
    Scan {
        request: crate::ScanRequest,
        guard: super::p2p_scan_async::ScanGuard,
    },
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
/// Netdev roles keep their real IFINDEX, UP requirement and captured mode
/// generation. A driver must explicitly opt each native management direction
/// in; DEVICE10 keeps its separate control-WDEV path.
pub(super) fn netdev_management_supported(
    iface: &dyn crate::WirelessNetIface,
    transmit: bool,
) -> bool {
    match iface.current_iftype() {
        2 => {
            if transmit {
                iface.async_radio_management_tx_control()
            } else {
                iface.async_radio_management_rx_control()
            }
        }
        mode @ (8 | 9) => {
            iface
                .get_wireless_info()
                .modes
                .contains(crate::iface::WirelessModes::P2P)
                && iface.p2p_interface_types().contains(&mode)
                && if transmit {
                    iface.async_p2p_netdev_management_tx_control()
                } else {
                    iface.async_p2p_netdev_management_rx_control()
                }
        }
        _ => false,
    }
}

pub(super) fn register_frame(
    bytes: &[u8],
    context: RequestContext<'_>,
    slot: Option<&DeferredRequest>,
) -> Result<Vec<GenlReply>, i32> {
    let attrs = attributes(bytes)?;
    reject_unknown(&attrs, &[3, 153, 91, 101])?;
    let (iface, index) = interface(&attrs, context.net_ns_id)?;
    let supported = match index {
        Some(_) => netdev_management_supported(iface.as_ref(), false),
        None => iface.current_iftype() == 10 && iface.async_p2p_management_rx_control(),
    };
    if !supported {
        return Err(EOPNOTSUPP);
    }
    let admin = source_authority(&context, iface.as_ref(), slot)?;
    let frame_type = u16_attr(&attrs, 101)?.ok_or(EINVAL)?;
    if frame_type & !0xf0 != 0 {
        return Err(EINVAL);
    }
    let prefix = attr(&attrs, 91).ok_or(EINVAL)?.to_vec();
    defer(
        iface,
        admin,
        context.net_ns_id,
        index,
        slot,
        Operation::RegisterFrame(frame_type, prefix),
    )
}

pub(super) fn frame(
    bytes: &[u8],
    context: RequestContext<'_>,
    slot: Option<&DeferredRequest>,
) -> Result<Vec<GenlReply>, i32> {
    let attrs = attributes(bytes)?;
    reject_unknown(&attrs, &[3, 153, 38, 51, 87, 108, 135])?;
    let (iface, index) = interface(&attrs, context.net_ns_id)?;
    let supported = match index {
        Some(_) => netdev_management_supported(iface.as_ref(), true),
        None => iface.current_iftype() == 10 && iface.async_p2p_management_tx_control(),
    };
    if !supported {
        return Err(EOPNOTSUPP);
    }
    let admin = source_authority(&context, iface.as_ref(), slot)?;
    let sent = attr(&attrs, 51).ok_or(EINVAL)?;
    if !(24..=4096).contains(&sent.len()) || sent[0] & 15 != 0 {
        return Err(EINVAL);
    }
    let frequency = u32_attr(&attrs, 38)?;
    if let Some(frequency) = frequency {
        channel(frequency)?;
    }
    let offchannel_ok = attr(&attrs, 108).is_some();
    if offchannel_ok && !iface.supports_offchannel_mgmt_tx() {
        return Err(EOPNOTSUPP);
    }
    let no_cck = attr(&attrs, 135);
    if no_cck.is_some_and(|flag| !flag.is_empty()) {
        return Err(EINVAL);
    }
    let duration = u32_attr(&attrs, 87)?;
    if duration.is_some_and(|duration| {
        !iface.supports_offchannel_mgmt_tx()
            || !(10..=iface.max_remain_on_channel_duration_ms()).contains(&duration)
    }) {
        return Err(EINVAL);
    }
    let request = crate::MgmtTxRequest {
        frequency_mhz: frequency.unwrap_or(0),
        frame: sent.to_vec(),
        offchannel_ok,
        duration: duration.unwrap_or(0),
        no_cck: no_cck.is_some(),
    };
    let cookie = FRAME_COOKIE
        .fetch_update(
            core::sync::atomic::Ordering::Relaxed,
            core::sync::atomic::Ordering::Relaxed,
            |value| (value != 0).then(|| value.checked_add(1)).flatten(),
        )
        .map_err(|_| EBUSY)?;
    defer(
        iface,
        admin,
        context.net_ns_id,
        index,
        slot,
        Operation::Frame { cookie, request },
    )
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
                    Operation::Start => iface.start_p2p_device_async(&call).await.map_err(errno),
                    Operation::Stop => iface.stop_p2p_device_async(&call).await.map_err(errno),
                    Operation::Cancel(cookie) => iface
                        .cancel_remain_on_channel_async(&call, cookie)
                        .await
                        .map_err(errno),
                    Operation::RegisterFrame(frame_type, prefix) => {
                        iface
                            .register_mgmt_frame_radio_async(&call, frame_type, &prefix)
                            .await
                    }
                    Operation::Frame { cookie, request } => {
                        let sent = request.frame.clone();
                        let acked = iface
                            .mgmt_tx_radio_async(&call, cookie, request)
                            .await
                            .map_err(errno)?;
                        call.check_for(iface.as_ref()).map_err(errno)?;
                        let wiphy = crate::registry::wiphy_index(iface.wiphy_id()).ok_or(ENODEV)?;
                        let mut attrs = Vec::new();
                        push_attr(&mut attrs, 1, &wiphy.to_ne_bytes());
                        if let Some(index) = index {
                            // Original bound IFINDEX; check_for above also
                            // rejects replacement, transfer and generation ABA.
                            push_attr(&mut attrs, 3, &index.to_ne_bytes());
                        } else {
                            let wdev =
                                crate::registry::control_for(iface.as_ref()).ok_or(ENODEV)?;
                            push_attr(&mut attrs, 153, &wdev.id().to_ne_bytes());
                        }
                        push_attr(&mut attrs, 51, &sent);
                        push_attr(&mut attrs, 88, &cookie.to_ne_bytes());
                        if acked {
                            push_attr(&mut attrs, 92, &[]);
                        }
                        // Native ACK and packet retirement are already complete.
                        // Status is MLME multicast using the original netdev
                        // IFINDEX or actual control-only WDEV selected above.
                        // All virtual/source callbacks above have finished.
                        // A driver-recorded original native receipt is the
                        // last denial fence, including late wiphy queries.
                        call.require_link().map_err(errno)?;
                        call.frame_completion_current(Some(cookie)).map_err(errno)?;
                        publish_event(
                            NL80211_FAMILY_ID,
                            19,
                            namespace,
                            GenlReply {
                                command: FRAME_TX_STATUS,
                                attrs,
                            },
                        );
                        call.require_link().map_err(errno)?;
                        call.frame_completion_current(Some(cookie)).map_err(errno)?;
                        let mut attrs = Vec::new();
                        push_attr(&mut attrs, 88, &cookie.to_ne_bytes());
                        replies.push(GenlReply {
                            command: FRAME,
                            attrs,
                        });
                        Ok(())
                    }
                    Operation::Scan { request, guard } => {
                        let mut results = iface
                            .p2p_device_scan_async(&call, request)
                            .await
                            .map_err(errno)?;
                        call.check_for(iface.as_ref()).map_err(errno)?;
                        results.truncate(256);
                        let results = results
                            .into_iter()
                            .map(|bss| {
                                let ies = iface
                                    .scan_information_elements(bss.bssid)
                                    .unwrap_or_default();
                                (bss, ies)
                            })
                            .collect();
                        let wiphy = crate::registry::wiphy_index(iface.wiphy_id()).ok_or(ENODEV)?;
                        call.require_link().map_err(errno)?;
                        guard.store(results);
                        // Scan done precedes the deferred ACK; the guard
                        // (`rdev->scan_req`) ends with this request.
                        guard.publish_done(wiphy);
                        Ok(())
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
                        result.map_err(errno)
                    }
                }?;
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
