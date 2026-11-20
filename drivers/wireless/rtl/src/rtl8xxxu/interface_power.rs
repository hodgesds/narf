// SPDX-License-Identifier: GPL-2.0-or-later
//! Original-receiver ndo_open/ndo_stop with scheduler-owned native USB work.
use super::*;
use alloc::sync::Weak;
use narf_net::iface::{NetIfaceSnapshot, OpenStopEvent, OpenStopTarget};

pub(super) struct Admin {
    binding: Option<NetIfaceSnapshot>,
    event: Option<OpenStopEvent>,
    generation: u64,
    running: bool,
}
impl Admin {
    pub(super) const fn new() -> Self {
        Self {
            binding: None,
            event: None,
            generation: 0,
            running: false,
        }
    }
}
struct Target<C: ControlIo, B: PacketIo, E: Environment>(Weak<Device<C, B, E>>);
impl<C: ControlIo, B: PacketIo, E: Environment> core::fmt::Debug for Target<C, B, E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rtl8188euAdminTarget")
            .finish_non_exhaustive()
    }
}
impl<C: ControlIo + 'static, B: PacketIo + 'static, E: Environment + 'static> OpenStopTarget
    for Target<C, B, E>
{
    fn transition(&self, event: OpenStopEvent) {
        let Some(device) = self.0.upgrade() else {
            return;
        };
        if event.name() != device.name || event.up() && !event.current() {
            return;
        }
        device.request_admin(event);
    }
}
impl<C: ControlIo, B: PacketIo, E: Environment> Device<C, B, E> {
    pub(in crate::rtl8xxxu) fn admin_pending(&self) -> bool {
        self.admin.lock().running
    }
    pub(super) fn publish_carrier(&self, up: bool) -> bool {
        let binding = self.admin.lock().binding.clone();
        match binding {
            Some(binding) if up => {
                narf_net::iface::set_link_metadata_for(&binding, true, None, None)
            }
            Some(binding) => narf_net::iface::withdraw_link_metadata_for(&binding),
            None => narf_net::iface::set_link_metadata(&self.name, up, None, None),
        }
    }
    pub(super) fn administratively_open(&self) -> bool {
        let admin = self.admin.lock();
        admin.binding.is_none()
            || !admin.running && admin.event.as_ref().is_some_and(|e| e.up() && e.current())
    }
    /// Synchronous block_on callers cannot wait for a separate PM task.
    /// A bound control operation either owns free state now or rejects Busy.
    pub(super) async fn control_state(
        &self,
        allow_closed: bool,
    ) -> Result<narf_lib::mutex::MutexGuard<'_, State<C, B, E>>, WirelessError> {
        let (bound, running) = {
            let admin = self.admin.lock();
            (admin.binding.is_some(), admin.running)
        };
        if running {
            return Err(WirelessError::Busy);
        }
        let state = if bound {
            self.state.try_lock().ok_or(WirelessError::Busy)?
        } else {
            self.state.lock().await
        };
        if !allow_closed
            && (self.closed.load(Ordering::Acquire) || self.failed.load(Ordering::Acquire))
        {
            return Err(WirelessError::HardwareError);
        }
        Ok(state)
    }
}
impl<C: ControlIo + 'static, B: PacketIo + 'static, E: Environment + 'static> Device<C, B, E> {
    pub(in crate::rtl8xxxu) fn bind_admin(
        self: &Arc<Self>,
        registration: NetIfaceSnapshot,
    ) -> Result<(), service_runtime::Error> {
        if registration.name != self.name || registration.mac != self.mac || registration.link_up {
            return Err(service_runtime::Error::State);
        }
        let state = self.state.try_lock().ok_or(service_runtime::Error::State)?;
        if state.service.phase() != service_runtime::Phase::Parked {
            return Err(service_runtime::Error::State);
        }
        state.service.current()?;
        drop(state);
        let mut admin = self.admin.lock();
        if admin.binding.is_some() {
            return Err(service_runtime::Error::State);
        }
        admin.binding = Some(registration.clone());
        drop(admin);
        if !narf_net::iface::set_open_stop_target(
            &registration,
            Arc::new(Target(Arc::downgrade(self))),
        ) {
            self.close();
            return Err(service_runtime::Error::State);
        }
        self.publish_carrier(false);
        Ok(())
    }
    fn request_admin(self: &Arc<Self>, event: OpenStopEvent) {
        let binding = if event.up() {
            // This observation is only for publication. The captured Device,
            // its original USB claim and current native grants select hardware.
            let Some(binding) = narf_net::iface::lookup(event.name()) else {
                return;
            };
            if !event.current() {
                return;
            }
            Some(binding)
        } else {
            None
        };
        let spawn = {
            let mut admin = self.admin.lock();
            let current = event.current();
            if !current && (event.up() || admin.event.as_ref().is_some_and(OpenStopEvent::current))
            {
                return;
            }
            let Some(next) = admin.generation.checked_add(1) else {
                drop(admin);
                self.close();
                return;
            };
            admin.generation = next;
            if let Some(binding) = binding {
                admin.binding = Some(binding);
            }
            // Serialize immediate admission closure with the worker's final
            // reopen. Registry callbacks run outside its locks, and these
            // short metadata operations perform no await or USB access.
            self.closed.store(true, Ordering::Release);
            self.bssid.store(0, Ordering::Release);
            self.up.store(false, Ordering::Release);
            *self.rx.lock() = None;
            if let Some(binding) = &admin.binding {
                narf_net::iface::withdraw_link_metadata_for(binding);
            }
            admin.event = Some(event);
            let spawn = !admin.running;
            admin.running = true;
            spawn
        };
        if spawn {
            let device = self.clone();
            narf_scheduler::spawn(async move {
                device.run_admin().await;
            });
        }
    }
    async fn run_admin(self: Arc<Self>) {
        loop {
            let (generation, event) = {
                let admin = self.admin.lock();
                (admin.generation, admin.event.clone())
            };
            let Some(event) = event else {
                self.close();
                return;
            };
            let mut state = self.state.lock().await;
            state.clear_transmit();
            let result = if event.up() && event.current() {
                // Every real UP follows initial DOWN or another real DOWN.
                // Even a coalesced reversal must retire the old association;
                // an unfinished earlier wake may have left RX-only state.
                match state.service.park().await {
                    Ok(()) => state.service.resume_parked().await,
                    Err(error) => Err(error),
                }
            } else {
                state.service.park().await
            };
            if result.is_err() {
                state.clear_transmit();
                drop(state);
                self.close();
                self.admin.lock().running = false;
                return;
            }
            let (current, same) = {
                let admin = self.admin.lock();
                let current = event.current();
                let same = admin.generation == generation;
                if event.up() && same && current && !self.failed.load(Ordering::Acquire) {
                    state.epoch = 0;
                    self.closed.store(false, Ordering::Release);
                }
                (current, same)
            };
            if event.up() && !current && same {
                // Registration loss during an actual wake cannot publish to a
                // successor. Finish this old device's park under its own grant.
                let _ = state.service.park().await;
                drop(state);
                self.close();
                self.admin.lock().running = false;
                return;
            }
            drop(state);
            let mut admin = self.admin.lock();
            if admin.generation == generation {
                admin.running = false;
                return;
            }
            // A reversal never drops the completed/pending native operation.
            // Apply the latest original-receiver request in the next iteration.
        }
    }
}
