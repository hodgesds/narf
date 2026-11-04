//! Opt-in native AP controls with exact-socket terminal acknowledgements.
use super::*;
use alloc::{boxed::Box, vec};
use core::future::Future;
use narf_net::netlink_generic::DeferredRequest;

pub(super) enum Operation {
    Start(Box<(crate::ApConfig, crate::ApStartSettings)>),
    Stop,
    PowerSave(crate::P2pGoPowerSave),
    Beacon(Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<u8>>),
    AddStation(crate::StationConfig),
    SetStation(crate::StationConfig),
    DelStation(Option<[u8; 6]>, u16),
    RegisterFrame(u16, Vec<u8>),
    AddKey(crate::OwnedKey, Option<(bool, bool)>),
    DelKey(u8, bool, Option<[u8; 6]>),
    DefaultKey {
        index: u8,
        unicast: bool,
        multicast: bool,
        management: bool,
        beacon: bool,
    },
    ControlPort {
        request: crate::ControlPortTxRequest,
        cookie: Option<u64>,
    },
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

pub(super) fn defer(
    iface: Arc<dyn crate::WirelessNetIface>,
    admin: narf_net::AdminHandle,
    slot: Option<&DeferredRequest>,
    namespace: u64,
    ifindex: u32,
    operation: Operation,
) -> Result<Vec<GenlReply>, i32> {
    let slot = slot.ok_or(EOPNOTSUPP)?;
    let authority = Arc::new(
        crate::ap_control::ApControlAuthority::bind(
            admin,
            &iface,
            namespace,
            ifindex,
            slot.reply_sink(),
        )
        .and_then(crate::ap_control::ApControlAuthority::reserve)
        .map_err(errno)?,
    );
    let owned = authority.clone();
    slot.defer_checked(
        Box::pin(async move {
            // Every poll, including a nested native receipt wait, must still
            // belong to this current administrative/interface/mode generation.
            let call_authority = owned.clone();
            let mut native = Box::pin(async move {
                match operation {
                    Operation::Start(settings) => {
                        let (config, settings) = *settings;
                        iface
                            .start_ap_with_settings_async(&call_authority, config, settings)
                            .await
                            .map_err(errno)
                    }
                    Operation::Stop => iface.stop_ap_async(&call_authority).await.map_err(errno),
                    Operation::PowerSave(settings) => {
                        call_authority.require_up().map_err(errno)?;
                        iface
                            .set_p2p_go_power_save_ap_async(&call_authority, settings)
                            .await
                            .map_err(errno)
                    }
                    Operation::Beacon(head, tail, probe) => iface
                        .set_beacon_async(&call_authority, head, tail, probe)
                        .await
                        .map_err(errno),
                    Operation::AddStation(station) => iface
                        .add_station_async(&call_authority, station)
                        .await
                        .map_err(errno),
                    Operation::SetStation(station) => iface
                        .set_station_async(&call_authority, station)
                        .await
                        .map_err(errno),
                    Operation::DelStation(peer, reason) => iface
                        .del_station_async(&call_authority, peer, reason)
                        .await
                        .map_err(errno),
                    Operation::RegisterFrame(kind, prefix) => iface
                        .register_mgmt_frame_ap_async(&call_authority, kind, prefix)
                        .await
                        .map_err(errno),
                    Operation::AddKey(key, default) => {
                        let index = key.params().idx;
                        iface
                            .add_key_ap_async(&call_authority, key)
                            .await
                            .map_err(i32::abs)?;
                        if let Some((unicast, multicast)) = default {
                            iface
                                .default_key_ap_async(
                                    &call_authority,
                                    index,
                                    unicast,
                                    multicast,
                                    false,
                                    false,
                                )
                                .await
                                .map_err(i32::abs)?;
                        }
                        Ok(())
                    }
                    Operation::DelKey(index, pairwise, peer) => iface
                        .del_key_ap_async(&call_authority, index, pairwise, peer)
                        .await
                        .map_err(i32::abs),
                    Operation::DefaultKey {
                        index,
                        unicast,
                        multicast,
                        management,
                        beacon,
                    } => iface
                        .default_key_ap_async(
                            &call_authority,
                            index,
                            unicast,
                            multicast,
                            management,
                            beacon,
                        )
                        .await
                        .map_err(i32::abs),
                    Operation::ControlPort { request, cookie } => {
                        let mut sent = zeroize::Zeroizing::new(request.dest.to_vec());
                        sent.extend_from_slice(&iface.mac());
                        sent.extend_from_slice(&request.ethertype.to_be_bytes());
                        sent.extend_from_slice(request.pdu());
                        let acked = iface
                            .tx_control_port_ap_async(&call_authority, request)
                            .await
                            .map_err(i32::abs)?;
                        call_authority.check_for(iface.as_ref()).map_err(errno)?;
                        if let Some(cookie) = cookie {
                            let mut attrs = Vec::new();
                            push_attr(&mut attrs, 3, &ifindex.to_ne_bytes());
                            push_attr(&mut attrs, 51, &sent);
                            push_attr(&mut attrs, 88, &cookie.to_ne_bytes());
                            if acked {
                                push_attr(&mut attrs, 92, &[]);
                            }
                            call_authority.current().map_err(errno)?;
                            publish_event(
                                NL80211_FAMILY_ID,
                                19,
                                namespace,
                                GenlReply {
                                    command: station::CONTROL_PORT_FRAME_TX_STATUS,
                                    attrs,
                                },
                            );
                        }
                        Ok(())
                    }
                }
            });
            let result = core::future::poll_fn(|cx| {
                if let Err(error) = owned.current() {
                    return core::task::Poll::Ready(Err(errno(error)));
                }
                native.as_mut().poll(cx)
            })
            .await;
            drop(native);
            owned.current().map_err(errno)?;
            result
        }),
        authority,
    )?;
    Ok(Vec::new())
}

pub(super) fn defer_frame(
    iface: Arc<dyn crate::WirelessNetIface>,
    admin: narf_net::AdminHandle,
    slot: Option<&DeferredRequest>,
    namespace: u64,
    ifindex: u32,
    cookie: u64,
    request: crate::MgmtTxRequest,
) -> Result<Vec<GenlReply>, i32> {
    let slot = slot.ok_or(EOPNOTSUPP)?;
    let authority = Arc::new(
        crate::ap_control::ApControlAuthority::bind(
            admin,
            &iface,
            namespace,
            ifindex,
            slot.reply_sink(),
        )
        .and_then(crate::ap_control::ApControlAuthority::reserve)
        .map_err(errno)?,
    );
    let owned = authority.clone();
    slot.defer_replies_checked(
        Box::pin(async move {
            let sent = request.frame.clone();
            let acked = iface
                .mgmt_tx_ap_async(&owned, cookie, request)
                .await
                .map_err(errno)?;
            owned.check_for(iface.as_ref()).map_err(errno)?;
            let mut event = Vec::new();
            push_attr(&mut event, 3, &ifindex.to_ne_bytes());
            push_attr(&mut event, 51, &sent);
            push_attr(&mut event, 88, &cookie.to_ne_bytes());
            if acked {
                push_attr(&mut event, 92, &[]);
            }
            // Same native terminal result as Linux's cfg80211_mgmt_tx_status;
            // this event grants no peer/port authority. The original request
            // source and AP generation must still be current at this edge.
            publish_event(
                NL80211_FAMILY_ID,
                19,
                namespace,
                GenlReply {
                    command: FRAME_TX_STATUS,
                    attrs: event,
                },
            );
            owned.current().map_err(errno)?;
            let mut attrs = Vec::new();
            push_attr(&mut attrs, 88, &cookie.to_ne_bytes());
            Ok(vec![GenlReply {
                command: FRAME,
                attrs,
            }])
        }),
        authority,
    )?;
    Ok(Vec::new())
}
