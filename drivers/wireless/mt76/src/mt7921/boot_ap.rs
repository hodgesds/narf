//! Retained AP work and exact concrete-interface publication.
use super::*;
use alloc::{
    boxed::Box,
    sync::{Arc, Weak},
};
use core::future::Future;
use core::sync::atomic::{AtomicBool, Ordering};
use narf_net::Interface;
use narf_wireless::ap_control::ApControlAuthority;

pub(crate) enum Request {
    Start(Box<(narf_wireless::ApConfig, narf_wireless::ApStartSettings)>),
    Stop,
    Beacon(Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<u8>>),
    AddStation(narf_wireless::StationConfig),
    SetStation(narf_wireless::StationConfig),
    DelStation(Option<[u8; 6]>),
    AddKey(narf_wireless::OwnedKey),
    DelKey(u8, bool, Option<[u8; 6]>),
    DefaultKey(u8),
    Management(narf_wireless::MgmtTxRequest),
    Control(narf_wireless::ControlPortTxRequest),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Reply {
    Done,
    Ack(bool),
}
/// Advance existing retained work without creating a station rekey task.
/// AP cancellation cleanup must progress even with carrier/admin DOWN.
pub(crate) fn progress() -> Result<bool, Error> {
    let mut cx = core::task::Context::from_waker(core::task::Waker::noop());
    match poll_boot_keys(&mut cx) {
        Poll::Ready(result) => result.map(|_| true),
        Poll::Pending => Ok(false),
    }
}
pub(crate) async fn cleanup(iface: Weak<crate::iface::Mt76Iface>) -> Result<(), Error> {
    let concrete = iface.upgrade().ok_or(Error::Authority)?;
    concrete
        .ap_cleanup_current()
        .map_err(|_| Error::Authority)?;
    let expected_mac = concrete.mac();
    let generation = super::super::pci::generation();
    drop(concrete);
    retained_owner_work(false, move |mut transport| {
        Box::pin(async move {
            // An earlier retained transition may finish while cleanup is
            // waiting. Never apply this old interface's cleanup to a newly
            // probed native transport or a replacement ACTIVE object.
            if transport.generation() != generation
                || iface
                    .upgrade()
                    .is_none_or(|iface| iface.ap_cleanup_current().is_err())
            {
                return (transport, Err(Error::DeviceGone));
            }
            let result = transport.cleanup_ap(expected_mac).await;
            if transport.ap_retired() {
                if let Some(concrete) = iface.upgrade() {
                    concrete.commit_ap_stopped();
                }
            }
            (transport, result)
        })
    })
    .await
}
pub(crate) fn step(tx: Option<&[u8]>) -> Result<(PacketStep, Vec<ApRxEvent>), Error> {
    // The caller may own its short pending-TX lock. Do not poll a retained
    // future here: terminal host commit also retires that queue.
    if KEY_WORK.try_lock().is_none_or(|work| work.is_some()) {
        return Err(Error::Busy);
    }
    let Some(mut owner) = BOOT_OWNER.try_lock() else {
        return Err(Error::Busy);
    };
    let owner = owner.as_mut().ok_or(Error::DeviceGone)?;
    let step = owner.step_ap_network(tx)?;
    let mut events = Vec::new();
    for _ in 0..64 {
        let Some(event) = owner.pop_ap_event()? else {
            break;
        };
        events.push(event);
    }
    Ok((step, events))
}
pub(crate) fn current(epoch: u64) -> Result<bool, Error> {
    let Some(owner) = BOOT_OWNER.try_lock() else {
        return Ok(false);
    };
    owner
        .as_ref()
        .map_or(Ok(false), |owner| owner.ap_receive_current(epoch))
}
pub(crate) fn stations() -> Vec<[u8; 6]> {
    BOOT_OWNER
        .try_lock()
        .and_then(|owner| {
            owner
                .as_ref()
                .and_then(|owner| owner.ap_station_macs().ok())
        })
        .unwrap_or_default()
}
/// A final non-reentrant IPC/event publication is serialized with native
/// key/peer/epoch replacement. Callbacks must run before entering here.
pub(crate) fn publish(epoch: u64, publish: impl FnOnce()) -> Result<bool, Error> {
    let Some(owner) = BOOT_OWNER.try_lock() else {
        return Ok(false);
    };
    let Some(owner) = owner.as_ref() else {
        return Ok(false);
    };
    if !owner.ap_receive_current(epoch)? {
        return Ok(false);
    }
    publish();
    Ok(true)
}
#[derive(Clone, Copy)]
enum Commit {
    Start(narf_wireless::ControlPort),
    Stop,
    Epoch,
    Transmit,
}

struct Caller {
    alive: Arc<AtomicBool>,
    terminal: bool,
}
impl Drop for Caller {
    fn drop(&mut self) {
        if !self.terminal {
            self.alive.store(false, Ordering::Release);
        }
    }
}

/// The actual registered iface supplies this weak identity after check_for.
/// No new authority is created by retaining a result cell or cancellation flag.
pub(crate) async fn request(
    iface: Weak<crate::iface::Mt76Iface>,
    authority: Arc<ApControlAuthority>,
    operation: Request,
) -> Result<Reply, Error> {
    let concrete = iface.upgrade().ok_or(Error::Authority)?;
    concrete
        .ap_request_current(&authority)
        .map_err(|_| Error::Authority)?;
    let expected_mac = concrete.mac();
    drop(concrete);
    let alive = Arc::new(AtomicBool::new(true));
    let mut caller = Caller {
        alive: alive.clone(),
        terminal: false,
    };
    let result = Arc::new(narf_lib::sync::IrqSafeSpinLock::new(None));
    // Settle the existing native owner before claiming it. Its previous
    // terminal error does not turn a failed owner into a fresh radio.
    let _ = finish_boot_keys().await;
    iface
        .upgrade()
        .ok_or(Error::Authority)?
        .ap_request_current(&authority)
        .map_err(|_| Error::Authority)?;
    let generation;
    {
        let Some(mut work) = KEY_WORK.try_lock() else {
            return Err(Error::Busy);
        };
        if work.is_some() {
            return Err(Error::Busy);
        }
        let Some(mut slot) = BOOT_OWNER.try_lock() else {
            return Err(Error::Busy);
        };
        let concrete = iface.upgrade().ok_or(Error::Authority)?;
        let transport = slot.take().ok_or(Error::DeviceGone)?;
        concrete.ap_work_started();
        generation = transport.generation();
        let target = result.clone();
        *work = Some(KeyWork {
            future: Some(Box::pin(async move {
                let mut transport = transport;
                let completed = transport
                    .run_ap_request(iface, authority, operation, alive, expected_mac)
                    .await;
                {
                    let mut cell = target.lock();
                    *cell = Some(completed);
                }
                (transport, completed.map(|_| ()))
            })),
            completed: None,
        });
    }
    // Either the waiting callback, the service task, synchronous drain or
    // the existing removal reaper may advance this same retained work.
    let status = finish_boot_keys().await;
    let completed = { result.lock().take() };
    caller.terminal = true;
    if generation != super::super::pci::generation() {
        return Err(Error::DeviceGone);
    }
    completed.unwrap_or_else(|| Err(status.err().unwrap_or(Error::Ring)))
}

/// Shared by the actual Transport backend and native model composition.
/// The host commit is inside this retained operation, before its terminal
/// result. A dropped borrowed callback cannot strand an uncommitted beacon.
pub(super) async fn run_session<B: Backend>(
    session: &mut Session<B>,
    iface: Weak<crate::iface::Mt76Iface>,
    authority: Arc<ApControlAuthority>,
    operation: Request,
    alive: Arc<AtomicBool>,
    expected_mac: [u8; 6],
) -> Result<Reply, Error> {
    let commit = match &operation {
        Request::Start(settings) => Commit::Start(settings.1.control_port),
        Request::Stop => Commit::Stop,
        Request::Management(_) | Request::Control(_) => Commit::Transmit,
        _ => Commit::Epoch,
    };
    let result = {
        let mut native = Box::pin(apply(session, authority.clone(), operation));
        core::future::poll_fn(|cx| {
            if !alive.load(Ordering::Acquire) {
                return Poll::Ready(Err(Error::Cancelled));
            }
            let Some(concrete) = iface.upgrade() else {
                return Poll::Ready(Err(Error::Authority));
            };
            if concrete.ap_request_current(&authority).is_err() {
                return Poll::Ready(Err(Error::Authority));
            }
            native.as_mut().poll(cx)
        })
        .await
    };
    let reply = match result {
        Ok(reply) => reply,
        Err(error) => {
            // Pure preflight refusal preserves an already-valid AP. Running
            // or failed native work and a pending beacon require actual reset.
            if matches!(session.state, State::Running(_) | State::Failed { .. })
                || session
                    .ap_owner
                    .as_ref()
                    .is_some_and(|owner| owner.pending.is_some())
            {
                session.recover(expected_mac).await?;
                if let Some(concrete) = iface.upgrade() {
                    concrete.commit_ap_stopped();
                }
            } else if session.ap_owner.is_none() {
                if let Some(concrete) = iface.upgrade() {
                    concrete.commit_ap_stopped();
                }
            }
            return Err(error);
        }
    };
    let publication = (|| {
        if !alive.load(Ordering::Acquire) {
            return Err(Error::Cancelled);
        }
        let concrete = iface.upgrade().ok_or(Error::Authority)?;
        concrete
            .ap_request_current(&authority)
            .map_err(|_| Error::Authority)?;
        match commit {
            Commit::Start(control) => {
                let epoch = session.commit_ap_start(&authority)?;
                let identity = session
                    .ap_owner
                    .as_ref()
                    .ok_or(Error::Busy)?
                    .identity
                    .clone();
                concrete
                    .commit_ap_started(&authority, identity, epoch, control)
                    .map_err(|_| Error::Authority)?;
            }
            Commit::Stop => concrete.commit_ap_stopped(),
            Commit::Epoch => concrete
                .commit_ap_epoch(&authority, session.receive_epoch)
                .map_err(|_| Error::Authority)?,
            Commit::Transmit => (),
        }
        concrete
            .ap_request_current(&authority)
            .map_err(|_| Error::Authority)?;
        Ok(())
    })();
    if let Err(error) = publication {
        // Native completion without current host publication is not START
        // success. Retire actual hardware, retaining everything on failure.
        session.recover(expected_mac).await?;
        if let Some(concrete) = iface.upgrade() {
            concrete.commit_ap_stopped();
        }
        return Err(error);
    }
    Ok(reply)
}

/// A GO control request: START/STOP have their own no-reset owners
/// (`go_link::start_go`/`stop_go`); everything else is the AP owner's.
pub(super) async fn apply_go<B: Backend>(
    session: &mut Session<B>,
    authority: Arc<ApControlAuthority>,
    operation: Request,
) -> Result<Reply, Error> {
    match operation {
        Request::Start(_) | Request::Stop => Err(Error::Bounds),
        operation => apply(session, authority, operation).await,
    }
}

async fn apply<B: Backend>(
    session: &mut Session<B>,
    authority: Arc<ApControlAuthority>,
    operation: Request,
) -> Result<Reply, Error> {
    match operation {
        Request::Start(settings) => {
            let (config, settings) = *settings;
            session
                .start_ap_with_settings(authority, config, settings)
                .await?;
        }
        Request::Stop => session.stop_ap(&authority).await?,
        Request::Beacon(head, tail, probe) => {
            session
                .ap_update_beacon(authority, head, tail, probe)
                .await?
        }
        Request::AddStation(config) => session.ap_add_station(authority, config).await?,
        Request::SetStation(config) => session.ap_update_station(authority, config).await?,
        Request::DelStation(peer) => session.ap_delete_station(authority, peer).await?,
        Request::AddKey(key) => {
            let install =
                ap_crypto::Install::from_params(key.params()).map_err(|_| Error::Bounds)?;
            drop(key);
            session.ap_install_key(authority, install).await?;
        }
        Request::DelKey(index, pairwise, peer) => {
            session
                .ap_delete_key(authority, index, pairwise, peer)
                .await?
        }
        Request::DefaultKey(index) => session.ap_default_key(authority, index).await?,
        Request::Management(request) => {
            let frequency = session
                .ap_owner
                .as_ref()
                .ok_or(Error::Busy)?
                .plan
                .config
                .frequency_mhz;
            if request.offchannel_ok
                || request.duration != 0
                || request.frequency_mhz != 0 && request.frequency_mhz != frequency
            {
                return Err(Error::Bounds);
            }
            return session
                .ap_send_management(authority, &request.frame)
                .await
                .map(Reply::Ack);
        }
        Request::Control(request) => {
            return session
                .ap_send_control(authority, request)
                .await
                .map(Reply::Ack)
        }
    }
    Ok(Reply::Done)
}
