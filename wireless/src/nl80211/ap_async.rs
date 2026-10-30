//! Opt-in native AP controls with exact-socket terminal acknowledgements.
use super::*;
use alloc::boxed::Box;
use core::future::Future;
use narf_net::netlink_generic::DeferredRequest;

pub(super) enum Operation {
    Start(crate::ApConfig),
    Stop,
    Beacon(Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<u8>>),
    AddStation(crate::StationConfig),
    SetStation(crate::StationConfig),
    DelStation(Option<[u8; 6]>, u16),
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
                    Operation::Start(config) => iface.start_ap_async(&call_authority, config).await,
                    Operation::Stop => iface.stop_ap_async(&call_authority).await,
                    Operation::Beacon(head, tail, probe) => {
                        iface
                            .set_beacon_async(&call_authority, head, tail, probe)
                            .await
                    }
                    Operation::AddStation(station) => {
                        iface.add_station_async(&call_authority, station).await
                    }
                    Operation::SetStation(station) => {
                        iface.set_station_async(&call_authority, station).await
                    }
                    Operation::DelStation(peer, reason) => {
                        iface.del_station_async(&call_authority, peer, reason).await
                    }
                }
            });
            let result = core::future::poll_fn(|cx| {
                if let Err(error) = owned.current() {
                    return core::task::Poll::Ready(Err(error));
                }
                native.as_mut().poll(cx)
            })
            .await;
            drop(native);
            owned.current().map_err(errno)?;
            result.map_err(errno)
        }),
        authority,
    )?;
    Ok(Vec::new())
}
