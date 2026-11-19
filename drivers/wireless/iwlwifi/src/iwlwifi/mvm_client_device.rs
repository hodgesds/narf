//! API77 retained CLIENT Radio FRAME, original source and terminal cleanup.
use super::super::{ap_host as host, p2p_client_request as source};
use super::*;
impl Device {
    pub(in crate::iwlwifi) fn client_receive_epoch(&self) -> Option<u64> {
        (self.mode.load(Ordering::Acquire) == 8
            && self.up.load(Ordering::Acquire)
            && self.port.load(Ordering::Acquire)
            && !self.stopping.load(Ordering::Acquire)
            && !self.terminal.load(Ordering::Acquire))
        .then(|| self.generation.load(Ordering::Acquire))
    }

    pub(super) fn client_register(
        &self,
        authority: &narf_wireless::ap_control::RadioControlAuthority,
        kind: u16,
        prefix: &[u8],
    ) -> Result<(), i32> {
        let generation =
            core::num::NonZeroU64::new(self.mode_generation.load(Ordering::Acquire)).ok_or(1)?;
        let role = { self.ap_host.role.lock().observe() };
        let registration = super::super::p2p_client_rx::registration(
            authority, self, generation, role, kind, prefix,
        )
        .map_err(|error| match error {
            WirelessError::InvalidArgs => 22,
            WirelessError::Busy => 16,
            _ => 1,
        })?;
        self.ap_host.client_rx.prune().map_err(|_| 1)?;
        {
            let mut state = self.state.try_lock().ok_or(16)?;
            state
                .owner
                .as_mut()
                .ok_or(16)?
                .ap_hardware()
                .client_receive_host(
                    self.ap_host.client_rx.clone(),
                    super::super::p2p_client_rx::Receiver::Mvm(self.me.clone()),
                )
                .map_err(|_| 5)?;
            self.ap_host.client_rx.add(registration).map_err(|_| 16)?;
            state
                .owner
                .as_mut()
                .unwrap()
                .ap_hardware()
                .client_refresh_filter();
        }
        authority.check_for(self).map_err(|_| 1)?;
        self.p2p.waker().wake_by_ref();
        Ok(())
    }
    pub(super) fn client_publications(&self) -> Vec<super::super::p2p_client_rx::Publication> {
        let Some(mut state) = self.state.try_lock() else {
            return Vec::new();
        };
        state
            .owner
            .as_mut()
            .map_or_else(Vec::new, |owner| owner.ap_hardware().take_client_events())
    }

    pub(super) async fn client_frame(
        &self,
        authority: &narf_wireless::ap_control::RadioControlAuthority,
        cookie: u64,
        request: narf_wireless::MgmtTxRequest,
    ) -> Result<bool, WirelessError> {
        authority.check_for(self)?;
        authority.require_mode(8)?;
        authority.require_link()?;
        let (native, sources, port_generation) = {
            let mut state = self.state.try_lock().ok_or(WirelessError::Busy)?;
            if !self.up.load(Ordering::Acquire) || !self.port.load(Ordering::Acquire) {
                return Err(WirelessError::Busy);
            }
            let hw = state
                .owner
                .as_mut()
                .ok_or(WirelessError::Busy)?
                .ap_hardware();
            (
                hw.p2p_client_native().ok_or(WirelessError::Denied)?,
                hw.client_frame_source()
                    .map_err(|_| WirelessError::Denied)?,
                (
                    self.generation.clone(),
                    self.generation.load(Ordering::Acquire),
                ),
            )
        };
        native
            .plan
            .management(&request)
            .map_err(|_| WirelessError::InvalidArgs)?;
        let generation = core::num::NonZeroU64::new(self.mode_generation.load(Ordering::Acquire))
            .ok_or(WirelessError::Denied)?;
        let role = { self.ap_host.role.lock().observe() };
        let permit = source::Request::capture(
            authority,
            self,
            generation,
            role,
            self.p2p.waker(),
            native,
            source::Origin {
                sources,
                mvm: Some(self.source.clone()),
                generation: port_generation,
                receive: None,
            },
        )
        .map_err(|_| WirelessError::Denied)?;
        if !permit.watch() {
            return Err(WirelessError::Denied);
        }
        let device = self.me.upgrade().ok_or(WirelessError::Denied)?;
        let mut slot = self.control.try_lock().ok_or(WirelessError::Busy)?;
        if slot.is_some() {
            return Err(WirelessError::Busy);
        }
        let reply = Arc::new(IrqSafeSpinLock::new(host::Reply {
            result: None,
            waker: None,
        }));
        let completed = reply.clone();
        let retained = authority.clone();
        let actual = permit.clone();
        *slot = Some(Work::new(async move {
            let mut state = device.state.lock().await;
            let result = async {
                actual.check()?;
                let owner = state
                    .owner
                    .as_mut()
                    .ok_or("API77 client FRAME native owner absent")?;
                if !owner
                    .ap_hardware()
                    .p2p_client_native()
                    .is_some_and(|current| Arc::ptr_eq(&current, &actual.native))
                {
                    return Err("API77 client FRAME original native owner changed");
                }
                owner.ap_hardware().client_request(Some(actual.clone()))?;
                owner
                    .client_management(&request, &actual, &device.environment.ap_policy, || {
                        (device.environment.policy)()
                    })
                    .await
                    .and_then(|value| {
                        actual.check()?;
                        Ok(value)
                    })
            }
            .await;
            if let Some(owner) = state.owner.as_mut() {
                let _ = owner.ap_hardware().client_request(None);
            }
            if result.is_err() {
                device.down(true);
                if let Some(owner) = state.owner.as_mut() {
                    owner.ap_hardware().clear_rf_policy();
                    owner.station_fail();
                    let _ = owner.suspend_transport().await;
                }
            }
            drop(state);
            let wake = {
                let mut reply = completed.lock();
                reply.result = Some(result.map_err(|_| 5));
                reply.waker.take()
            };
            if let Some(wake) = wake {
                wake.wake();
            }
            drop(retained);
        }));
        drop(slot);
        let mut waiter = Box::pin(source::Waiter {
            inner: host::Waiter {
                reply,
                cancel: permit.cancel.clone(),
                consumed: false,
            },
            request: permit.clone(),
        });
        let result = poll_fn(|cx| {
            if !permit.watch() {
                permit.cancel();
            }
            let _ = progress::poll_work(&self.control, cx);
            waiter.as_mut().poll(cx)
        })
        .await;
        authority.check_for(self)?;
        authority.require_link()?;
        let acked = result.map_err(host::error)?;
        let completion = Arc::new(source::Completion { request: permit });
        authority.complete_frame_for(self, cookie, completion)?;
        Ok(acked)
    }
}
