//! Concrete shared Intel AP host metadata; full callbacks stay outside native State.
use super::runtime::Hardware;
use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::{
    future::Future,
    pin::Pin,
    sync::atomic::{AtomicBool, Ordering},
    task::{Context, Poll, Waker},
};
use narf_lib::sync::IrqSafeSpinLock;
use narf_wireless::{
    ap_control::{ApControlAuthority, ApEventAuthority},
    WirelessError,
};
pub(super) fn error(errno: i32) -> WirelessError {
    match errno {
        1 => WirelessError::Denied,
        16 => WirelessError::Busy,
        22 | 2 => WirelessError::InvalidArgs,
        95 => WirelessError::NotSupported,
        _ => WirelessError::HardwareError,
    }
}

pub(super) struct Host {
    pub(super) client_rx: Arc<super::p2p_client_rx::Host>,
    pub(super) role: IrqSafeSpinLock<narf_net::native_emission::ProviderLifetime>,
    pub(super) active: IrqSafeSpinLock<Option<Arc<super::ap_owner::Owner>>>,
    pub(super) registrations: IrqSafeSpinLock<Vec<Arc<Registration>>>,
    pub(super) history: Arc<IrqSafeSpinLock<super::sc_security::KeyHistory>>,
    pub(super) early: IrqSafeSpinLock<early::Staging>,
    pub(super) waker: IrqSafeSpinLock<Option<Waker>>,
}
impl Host {
    pub(super) fn new() -> Self {
        Self {
            client_rx: super::p2p_client_rx::Host::new(),
            role: IrqSafeSpinLock::new(narf_net::native_emission::ProviderLifetime::new()),
            active: IrqSafeSpinLock::new(None),
            registrations: IrqSafeSpinLock::new(Vec::new()),
            history: Arc::new(IrqSafeSpinLock::new(Default::default())),
            early: IrqSafeSpinLock::new(early::Staging::default()),
            waker: IrqSafeSpinLock::new(None),
        }
    }
}
pub(super) struct Registration {
    pub(super) event: ApEventAuthority,
    pub(super) frame_type: u16,
    pub(super) prefix: Vec<u8>,
}
pub(super) enum Operation {
    Start(
        Box<narf_wireless::ApConfig>,
        Box<narf_wireless::ApStartSettings>,
    ),
    Stop,
    Beacon(Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<u8>>),
    Add(narf_wireless::StationConfig),
    Set(narf_wireless::StationConfig),
    Delete(Option<[u8; 6]>),
    Key(narf_wireless::OwnedKey),
    DeleteKey(u8, bool, Option<[u8; 6]>),
    DefaultKey(u8, bool, bool, bool, bool),
    Control(narf_wireless::ControlPortTxRequest),
    Management(narf_wireless::MgmtTxRequest),
}
pub(super) struct Reply {
    pub(super) result: Option<Result<bool, i32>>,
    pub(super) waker: Option<Waker>,
}
pub(super) struct Waiter {
    pub(super) reply: Arc<IrqSafeSpinLock<Reply>>,
    pub(super) cancel: Arc<AtomicBool>,
    pub(super) consumed: bool,
}
impl Future for Waiter {
    type Output = Result<bool, i32>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let result = {
            let mut reply = self.reply.lock();
            if let Some(result) = reply.result.take() {
                Some(result)
            } else {
                reply.waker = Some(cx.waker().clone());
                None
            }
        };
        if let Some(result) = result {
            self.consumed = true;
            Poll::Ready(result)
        } else {
            Poll::Pending
        }
    }
}
impl Drop for Waiter {
    fn drop(&mut self) {
        if !self.consumed {
            self.cancel.store(true, Ordering::Release);
        }
    }
}

pub(super) struct Publication {
    pub(super) event: ApEventAuthority,
    pub(super) source: super::runtime::source::Fence,
    pub(super) receive: super::runtime::rx_epoch::Publication,
    pub(super) data: Option<super::ap_owner::DataPublication>,
    pub(super) frequency: u32,
    pub(super) packet: Arc<super::ap_session::packet::Event>,
}
impl Publication {
    fn current_copy(&self) -> Result<(), &'static str> {
        if !self.receive.current() || self.data.as_ref().is_some_and(|data| !data.current()) {
            return Err("AP copied event epoch retired");
        }
        Ok(())
    }
    pub(super) fn publish(self) {
        // No native State/control/admission lock surrounds event callbacks.
        if self.source.invoke(|| self.current_copy()).is_err() {
            return;
        }
        let prepared = match self.packet.as_ref() {
            super::ap_session::packet::Event::Management { frame, rssi } => self
                .event
                .prepare_management_received(self.frequency, Some(*rssi), frame),
            super::ap_session::packet::Event::Control {
                peer,
                ethertype,
                pdu,
                unencrypted,
            } => self
                .event
                .prepare_control_received(*peer, *ethertype, pdu, *unencrypted),
        };
        let Ok(prepared) = prepared else {
            return;
        };
        // Preparation may reenter the native owner through arbitrary provider
        // callbacks. Recheck every original physical/source/key/DATA proof now;
        // only fixed original receiver/source checks remain before delivery.
        let _ = self.source.invoke(|| {
            self.current_copy()?;
            prepared
                .deliver()
                .map_err(|_| "AP original event source retired")
        });
    }
}

#[path = "ap_early.rs"]
pub(super) mod early;
