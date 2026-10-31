//! Metadata/filter work shares retained native transport ownership. No
//! subscription creates a native START or RF owner by itself.
use super::*;
use alloc::vec::Vec;
pub(crate) async fn register(
    iface: Weak<crate::iface::p2p::P2pDeviceIface>,
    authority: Arc<RadioControlAuthority>,
    frame_type: u16,
    prefix: Vec<u8>,
) -> Result<(), i32> {
    let concrete = iface.upgrade().ok_or(1)?;
    concrete.request_current(&authority).map_err(|_| 1)?;
    let expected_mac = concrete.physical_mac().map_err(|_| 1)?;
    drop(concrete);
    let alive = Arc::new(AtomicBool::new(true));
    let mut caller = Caller {
        alive: alive.clone(),
        terminal: false,
    };
    let result = Arc::new(narf_lib::sync::IrqSafeSpinLock::new(None));
    let target = result.clone();
    let status = retained_owner_work(false, move |mut transport| {
        Box::pin(async move {
            let completed = if alive.load(Ordering::Acquire) {
                transport.register_p2p_management(
                    iface,
                    authority,
                    frame_type,
                    &prefix,
                    expected_mac,
                )
            } else {
                Err(125)
            };
            let status = completed.as_ref().map(|_| ()).map_err(|_| Error::Authority);
            *target.lock() = Some(completed);
            (transport, status)
        })
    })
    .await;
    caller.terminal = true;
    let completed = result.lock().take();
    completed.unwrap_or_else(|| status.map_err(|_| 1))
}
pub(in crate::mt7921::firmware_transport) fn register_session<B: Backend>(
    session: &mut Session<B>,
    iface: Weak<crate::iface::p2p::P2pDeviceIface>,
    authority: Arc<RadioControlAuthority>,
    frame_type: u16,
    prefix: &[u8],
    expected_mac: [u8; 6],
) -> Result<(), i32> {
    let concrete = iface.upgrade().ok_or(1)?;
    concrete.request_current(&authority).map_err(|_| 1)?;
    if concrete.physical_mac().map_err(|_| 1)? != expected_mac {
        return Err(1);
    }
    let info = match session.state {
        State::RadioReady(info)
        | State::ScanReady(info)
        | State::P2pDevice(info)
        | State::Associated { info, .. }
        | State::AccessPoint { info, .. } => info,
        _ => return Err(16),
    };
    if info.capabilities.mac != expected_mac {
        return Err(1);
    }
    let filters = concrete.management_subscriptions();
    let install = filters.prepare(&authority, frame_type, prefix)?;
    session.register_p2p_management(&authority, filters, install)?;
    concrete.request_current(&authority).map_err(|_| 1)
}
