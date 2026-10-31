//! Opt-in native scheduled-scan controls with terminal exact-source ACKs.
use super::*;
use alloc::boxed::Box;
use core::future::Future;
use narf_net::netlink_generic::DeferredRequest;

pub(super) enum Operation {
    Start(crate::SchedScanRequest),
    Stop,
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
        crate::ap_control::RadioControlAuthority::bind(
            admin,
            &iface,
            namespace,
            ifindex,
            slot.reply_sink(),
        )
        .and_then(crate::ap_control::RadioControlAuthority::reserve)
        .map_err(errno)?,
    );
    authority.require_link().map_err(errno)?;
    let retained = authority.clone();
    slot.defer_checked(
        Box::pin(async move {
            let call = retained.clone();
            let receiver = iface.clone();
            let mut native = Box::pin(async move {
                let event = call.event_authority().map_err(errno)?;
                match operation {
                    Operation::Start(request) => {
                        receiver
                            .start_sched_scan_async(&call, request)
                            .await
                            .map_err(i32::abs)?;
                        call.check_for(receiver.as_ref()).map_err(errno)?;
                        event.scheduled_scan_started().map_err(errno)
                    }
                    Operation::Stop => {
                        receiver
                            .stop_sched_scan_async(&call)
                            .await
                            .map_err(i32::abs)?;
                        call.check_for(receiver.as_ref()).map_err(errno)?;
                        event.scheduled_scan_stopped().map_err(errno)
                    }
                }
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
