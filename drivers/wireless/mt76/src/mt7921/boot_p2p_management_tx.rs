//! Published management work survives dropping the external request future.
use super::*;

pub(crate) async fn transmit(
    iface: Weak<crate::iface::p2p::P2pDeviceIface>,
    authority: Arc<RadioControlAuthority>,
    cookie: u64,
    request: narf_wireless::MgmtTxRequest,
) -> Result<bool, Error> {
    let concrete = iface.upgrade().ok_or(Error::Authority)?;
    concrete
        .request_current(&authority)
        .map_err(|_| Error::Authority)?;
    let expected_mac = concrete.physical_mac().map_err(|_| Error::Authority)?;
    let generation = crate::mt7921::pci::generation();
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
            if transport.generation() != generation {
                return (transport, Err(Error::DeviceGone));
            }
            let completed = transport
                .transmit_p2p_management(iface, authority, cookie, request, alive, expected_mac)
                .await;
            let status = completed.as_ref().map(|_| ()).map_err(|error| *error);
            *target.lock() = Some(completed);
            (transport, status)
        })
    })
    .await;
    caller.terminal = true;
    status?;
    if generation != crate::mt7921::pci::generation() {
        return Err(Error::DeviceGone);
    }
    let completed = result.lock().take();
    completed.unwrap_or(Err(Error::DeviceGone))
}

/// Hardware and native fixtures execute this same concrete owner body.
pub(in crate::mt7921::firmware_transport) async fn run_session<B: Backend>(
    session: &mut Session<B>,
    iface: Weak<crate::iface::p2p::P2pDeviceIface>,
    authority: Arc<RadioControlAuthority>,
    cookie: u64,
    request: narf_wireless::MgmtTxRequest,
    alive: Arc<AtomicBool>,
    expected_mac: [u8; 6],
) -> Result<bool, Error> {
    let concrete = iface.upgrade().ok_or(Error::Authority)?;
    concrete
        .request_current(&authority)
        .map_err(|_| Error::Authority)?;
    if concrete.physical_mac().map_err(|_| Error::Authority)? != expected_mac
        || session
            .p2p_owner
            .as_ref()
            .is_none_or(|owner| owner.info.capabilities.mac != expected_mac)
    {
        return Err(Error::Authority);
    }
    if !concrete.started_current() || !alive.load(Ordering::Acquire) {
        return Err(Error::Busy);
    }
    drop(concrete);
    let cleanup = Arc::new(AtomicBool::new(false));
    let result = {
        let mut native = Box::pin(session.send_p2p_management(
            authority.clone(),
            cookie,
            &request,
            cleanup.clone(),
        ));
        core::future::poll_fn(|cx| {
            // Only a native terminal/failure edge enables retained cleanup.
            // No caller/source check can turn this into new RF permission.
            if !cleanup.load(Ordering::Acquire) {
                if !alive.load(Ordering::Acquire) {
                    return Poll::Ready(Err(Error::Cancelled));
                }
                if iface
                    .upgrade()
                    .is_none_or(|iface| iface.request_current(&authority).is_err())
                {
                    return Poll::Ready(Err(Error::Authority));
                }
            }
            native.as_mut().poll(cx)
        })
        .await
    };
    if result.is_err()
        && (matches!(session.state, State::Running(_) | State::Failed { .. })
            || session
                .p2p_owner
                .as_ref()
                .is_some_and(|owner| owner.pending.is_some()))
    {
        session.recover(expected_mac).await?;
    }
    if session.p2p_owner.is_none() {
        if let Some(iface) = iface.upgrade() {
            iface.commit_stopped();
        }
    }
    let ack = result?;
    let concrete = iface.upgrade().ok_or(Error::Authority)?;
    concrete
        .request_current(&authority)
        .map_err(|_| Error::Authority)?;
    if !alive.load(Ordering::Acquire) || !concrete.started_current() {
        return Err(Error::Authority);
    }
    Ok(ack)
}
