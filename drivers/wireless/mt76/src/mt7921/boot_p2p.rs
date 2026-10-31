//! Retained native P2P-device work; dropping the borrowed CLI waiter never
//! drops a published command, actual BSS owner or serialization lease.
use super::*;
use alloc::{
    boxed::Box,
    sync::{Arc, Weak},
};
use core::{
    future::Future,
    sync::atomic::{AtomicBool, Ordering},
};
use narf_wireless::ap_control::RadioControlAuthority;
#[path = "boot_p2p_management.rs"]
pub(crate) mod management;

pub(crate) enum Request {
    Start,
    Stop,
    Roc {
        cookie: u64,
        frequency_mhz: u32,
        duration_ms: u32,
    },
    Cancel(u64),
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
pub(crate) async fn request(
    iface: Weak<crate::iface::p2p::P2pDeviceIface>,
    authority: Arc<RadioControlAuthority>,
    operation: Request,
) -> Result<(), Error> {
    let concrete = iface.upgrade().ok_or(Error::Authority)?;
    concrete
        .request_current(&authority)
        .map_err(|_| Error::Authority)?;
    let expected_mac = concrete.physical_mac().map_err(|_| Error::Authority)?;
    drop(concrete);
    let alive = Arc::new(AtomicBool::new(true));
    let mut caller = Caller {
        alive: alive.clone(),
        terminal: false,
    };
    let _ = finish_boot_keys().await;
    iface
        .upgrade()
        .ok_or(Error::Authority)?
        .request_current(&authority)
        .map_err(|_| Error::Authority)?;
    let result = Arc::new(narf_lib::sync::IrqSafeSpinLock::new(None));
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
        concrete
            .request_current(&authority)
            .map_err(|_| Error::Authority)?;
        let mut transport = slot.take().ok_or(Error::DeviceGone)?;
        generation = transport.generation();
        concrete.work_started();
        let target = result.clone();
        *work = Some(KeyWork {
            future: Some(Box::pin(async move {
                let completed = transport
                    .run_p2p_request(iface, authority, operation, alive, expected_mac)
                    .await;
                *target.lock() = Some(completed);
                (transport, completed)
            })),
            completed: None,
        });
    }
    let status = finish_boot_keys().await;
    let completed = result.lock().take();
    caller.terminal = true;
    if generation != super::super::pci::generation() {
        return Err(Error::DeviceGone);
    }
    completed.unwrap_or(status)
}

/// DEL owns both native stop and exact metadata withdrawal in KEY_WORK.
/// Cancellation drops only the borrowed waiter; it cannot strand a stopped
/// or uncertain native owner between the two phases.
pub(crate) async fn delete(
    iface: Weak<crate::iface::p2p::P2pDeviceIface>,
    authority: Arc<RadioControlAuthority>,
) -> Result<narf_wireless::ap_control::RadioControlRetirement, Error> {
    let concrete = iface.upgrade().ok_or(Error::Authority)?;
    concrete
        .request_current(&authority)
        .map_err(|_| Error::Authority)?;
    let expected_mac = concrete.physical_mac().map_err(|_| Error::Authority)?;
    drop(concrete);
    let alive = Arc::new(AtomicBool::new(true));
    let mut caller = Caller {
        alive: alive.clone(),
        terminal: false,
    };
    let _ = finish_boot_keys().await;
    let result = Arc::new(narf_lib::sync::IrqSafeSpinLock::new(None));
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
        concrete
            .request_current(&authority)
            .map_err(|_| Error::Authority)?;
        let mut transport = slot.take().ok_or(Error::DeviceGone)?;
        generation = transport.generation();
        concrete.work_started();
        let target = result.clone();
        *work = Some(KeyWork {
            future: Some(Box::pin(async move {
                let completed = transport
                    .run_p2p_delete(iface, authority, alive, expected_mac)
                    .await;
                let status = completed.as_ref().map(|_| ()).map_err(|error| *error);
                *target.lock() = Some(completed);
                (transport, status)
            })),
            completed: None,
        });
    }
    let status = finish_boot_keys().await;
    let completed = result.lock().take();
    caller.terminal = true;
    if generation != super::super::pci::generation() {
        return Err(Error::DeviceGone);
    }
    completed.unwrap_or_else(|| Err(status.err().unwrap_or(Error::DeviceGone)))
}
/// This exact body is shared by Hardware and native command/DMA fixtures.
pub(super) async fn delete_session<B: Backend>(
    session: &mut Session<B>,
    iface: Weak<crate::iface::p2p::P2pDeviceIface>,
    authority: Arc<RadioControlAuthority>,
    alive: Arc<AtomicBool>,
    expected_mac: [u8; 6],
) -> Result<narf_wireless::ap_control::RadioControlRetirement, Error> {
    let completed = run_session(
        session,
        iface.clone(),
        authority.clone(),
        Request::Stop,
        alive,
        expected_mac,
    )
    .await;
    let concrete = iface.upgrade().ok_or(Error::Authority)?;
    if let Err(error) = completed {
        if session.p2p_owner.is_none() {
            concrete.commit_stopped();
            concrete.release_retired_metadata();
        }
        return Err(error);
    }
    let result = concrete
        .retire_metadata(&authority)
        .map_err(|_| Error::Authority);
    if result.is_err() {
        concrete.release_retired_metadata();
    }
    result
}

pub(crate) async fn maintenance(
    iface: Weak<crate::iface::p2p::P2pDeviceIface>,
) -> Result<(), Error> {
    let concrete = iface.upgrade().ok_or(Error::Authority)?;
    concrete.cleanup_current().map_err(|_| Error::Authority)?;
    let expected_mac = concrete.physical_mac().map_err(|_| Error::Authority)?;
    let generation = super::super::pci::generation();
    drop(concrete);
    retained_owner_work(false, move |mut transport| {
        Box::pin(async move {
            if transport.generation() != generation
                || iface
                    .upgrade()
                    .is_none_or(|iface| iface.cleanup_current().is_err())
            {
                return (transport, Err(Error::DeviceGone));
            }
            let result = transport.maintain_p2p_device(iface, expected_mac).await;
            (transport, result)
        })
    })
    .await
}

/// Used unchanged by Hardware and native hardware-model composition.
pub(super) async fn run_session<B: Backend>(
    session: &mut Session<B>,
    iface: Weak<crate::iface::p2p::P2pDeviceIface>,
    authority: Arc<RadioControlAuthority>,
    operation: Request,
    alive: Arc<AtomicBool>,
    expected_mac: [u8; 6],
) -> Result<(), Error> {
    let native_mac = match session.state {
        State::RadioReady(info)
        | State::ScanReady(info)
        | State::P2pDevice(info)
        | State::Associated { info, .. }
        | State::AccessPoint { info, .. } => Some(info.capabilities.mac),
        _ => None,
    };
    if native_mac.is_some_and(|mac| mac != expected_mac) {
        return Err(Error::Authority);
    }
    let concrete = iface.upgrade().ok_or(Error::Authority)?;
    concrete
        .request_current(&authority)
        .map_err(|_| Error::Authority)?;
    concrete.work_started();
    let vif = concrete.native_vif().map_err(|_| Error::Authority)?;
    drop(concrete);
    let start = matches!(operation, Request::Start);
    let stop = matches!(operation, Request::Stop);
    let roc = matches!(operation, Request::Roc { .. });
    let stop_notification = stop.then(|| session.p2p_stop_roc_notification()).flatten();
    let result = {
        let mut native = Box::pin(async {
            match operation {
                Request::Start => {
                    if session
                        .p2p_owner
                        .as_ref()
                        .is_some_and(|owner| owner.activated)
                        && session.p2p_ready()
                    {
                        session.check_p2p_request(&authority)
                    } else {
                        session.start_p2p_device_on(authority.clone(), vif).await
                    }
                }
                Request::Stop => {
                    if session.p2p_owner.is_none() {
                        session.backend.check()
                    } else {
                        session.stop_p2p_device(&authority).await
                    }
                }
                Request::Roc {
                    cookie,
                    frequency_mhz,
                    duration_ms,
                } => session
                    .acquire_p2p_roc(authority.clone(), cookie, frequency_mhz, duration_ms)
                    .await
                    .map(|_| ()),
                Request::Cancel(cookie) => session.cancel_p2p_roc(authority.clone(), cookie).await,
            }
        });
        core::future::poll_fn(|cx| {
            if !alive.load(Ordering::Acquire) {
                return Poll::Ready(Err(Error::Cancelled));
            }
            if iface
                .upgrade()
                .is_none_or(|iface| iface.request_current(&authority).is_err())
            {
                return Poll::Ready(Err(Error::Authority));
            }
            native.as_mut().poll(cx)
        })
        .await
    };
    if let Err(error) = result {
        if matches!(session.state, State::Running(_) | State::Failed { .. })
            || session
                .p2p_owner
                .as_ref()
                .is_some_and(|owner| owner.pending.is_some())
        {
            session.recover(expected_mac).await?;
        }
        if session.p2p_owner.is_none() {
            if let Some(iface) = iface.upgrade() {
                iface.commit_stopped();
            }
        }
        return Err(error);
    }
    let publication = (|| {
        if !alive.load(Ordering::Acquire) {
            return Err(Error::Cancelled);
        }
        let concrete = iface.upgrade().ok_or(Error::Authority)?;
        concrete
            .request_current(&authority)
            .map_err(|_| Error::Authority)?;
        if start {
            let identity = session.commit_p2p_device(&authority)?;
            session.bind_p2p_management(&authority, concrete.management_subscriptions())?;
            concrete
                .commit_started(&authority, identity)
                .map_err(|_| Error::Authority)?;
        } else if stop {
            concrete.commit_stopped();
            if let Some((source, receipt)) = stop_notification {
                if source.current().is_ok() {
                    source
                        .roc_expired(receipt.cookie, receipt.frequency_mhz, receipt.duration_ms)
                        .map_err(|_| Error::Authority)?;
                    source.current().map_err(|_| Error::Authority)?;
                }
            }
        } else if roc {
            session.commit_p2p_roc(&authority)?;
        }
        concrete
            .request_current(&authority)
            .map_err(|_| Error::Authority)?;
        Ok(())
    })();
    if let Err(error) = publication {
        // Native receipt ownership is already known at this point. A lost
        // publication source must retire its own independent device/finite
        // ROC, rather than resetting an unrelated live home association.
        let independent = session.p2p_owner.as_ref().is_some_and(|owner| {
            owner.vif.index() != 0 && owner.ready && session.check_p2p_home().is_ok()
        });
        if independent {
            session.stop_p2p_device_owned().await?;
        } else if session.p2p_owner.is_some() || session.check_p2p_home().is_err() {
            session.recover(expected_mac).await?;
        }
        if let Some(iface) = iface.upgrade() {
            iface.commit_stopped();
        }
        return Err(error);
    }
    Ok(())
}
pub(super) async fn maintain_session<B: Backend>(
    session: &mut Session<B>,
    iface: Weak<crate::iface::p2p::P2pDeviceIface>,
    expected_mac: [u8; 6],
) -> Result<(), Error> {
    let concrete = iface.upgrade().ok_or(Error::Authority)?;
    concrete.cleanup_current().map_err(|_| Error::Authority)?;
    if session.p2p_owner.is_some() {
        if concrete.started_current() {
            session.expire_p2p_roc().await?;
        } else {
            session.stop_p2p_device_owned().await?;
        }
    } else if matches!(session.state, State::Running(_) | State::Failed { .. }) {
        // This generation owns uncertain started work, never a fresh role.
        session.recover(expected_mac).await?;
    }
    if session.p2p_owner.is_none() {
        concrete.commit_stopped();
    } else {
        session.service_p2p_management_receive()?;
    }
    Ok(())
}
