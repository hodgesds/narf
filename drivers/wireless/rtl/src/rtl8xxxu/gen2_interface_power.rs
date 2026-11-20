// SPDX-License-Identifier: GPL-2.0-or-later
//! Gen2 administrative IFF_UP/IFF_DOWN (mac80211 `ieee80211_open` /
//! `ieee80211_stop` → `drv_start`/`drv_stop` → `rtl8xxxu_start`/
//! `rtl8xxxu_stop`) with scheduler-owned native USB work, as the RTL8188EU
//! `interface_power`. DOWN retires any station (`disconnect`), stops and
//! powers off the chip (`Radio::park_idle`); UP is a fresh
//! `rtl8xxxu_init_device` lifecycle (`restart_parked`) back to the idle
//! `RadioReady` radio, which scans and joins start as before. Carrier is
//! physical metadata (`set_link_metadata_for`/`withdraw_link_metadata_for`)
//! and never changes the operator's IFF_UP.
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
struct Target<C: ControlIo, B: PacketIo>(Weak<Device<C, B>>);
impl<C: ControlIo, B: PacketIo> core::fmt::Debug for Target<C, B> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rtl8xxxuGen2AdminTarget")
            .finish_non_exhaustive()
    }
}
impl<C: ControlIo + 'static, B: PacketIo + 'static> OpenStopTarget for Target<C, B> {
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

impl<C: ControlIo, B: PacketIo> State<C, B> {
    /// IFF_DOWN: station teardown (`ra_disconnect`, `rtl8xxxu_stop`), the
    /// chip power-off; candidates die with the receive stream. Failure is
    /// terminal (`Slot::Failed`).
    pub(super) async fn park(&mut self) -> Result<(), gen2_radio::Error> {
        self.clear_transmit();
        self.cache.clear();
        let mut radio = match core::mem::replace(&mut self.slot, Slot::Failed) {
            Slot::Station(mut station) => {
                station
                    .disconnect()
                    .await
                    .map_err(|_| gen2_radio::Error::State)?;
                station.into_radio()
            }
            Slot::Idle(radio) => *radio,
            Slot::Failed => return Err(gen2_radio::Error::State),
        };
        radio.park_idle().await?;
        self.slot = Slot::Idle(Box::new(radio));
        Ok(())
    }
    /// IFF_UP: a fresh owner lifecycle to `RadioReady`.
    pub(super) async fn wake(&mut self) -> Result<(), gen2_radio::Error> {
        let Slot::Idle(radio) = &mut self.slot else {
            return Err(gen2_radio::Error::State);
        };
        radio.restart_parked().await?;
        if radio.phase() != gen2_radio::Phase::Prepared {
            self.slot = Slot::Failed;
            return Err(gen2_radio::Error::State);
        }
        Ok(())
    }
}

impl<C: ControlIo, B: PacketIo> Device<C, B> {
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
    /// The owner for a control operation: `Busy` while an admin transition
    /// runs (or, once bound, while another holder has the state), and
    /// `HardwareError` while closed (DOWN) or failed unless `allow_closed`.
    pub(super) async fn control_state(
        &self,
        allow_closed: bool,
    ) -> Result<narf_lib::mutex::MutexGuard<'_, State<C, B>>, WirelessError> {
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
impl<C: ControlIo + 'static, B: PacketIo + 'static> Device<C, B> {
    /// Bind the registered netdev's open/stop hook. The radio must already
    /// be physically parked (register_netdevice starts IFF_DOWN).
    pub(super) fn bind_admin(
        self: &Arc<Self>,
        registration: NetIfaceSnapshot,
    ) -> Result<(), gen2_radio::Error> {
        if registration.name != self.name || registration.mac != self.mac || registration.link_up {
            return Err(gen2_radio::Error::State);
        }
        let state = self.state.try_lock().ok_or(gen2_radio::Error::State)?;
        if !matches!(&state.slot, Slot::Idle(radio) if radio.phase() == gen2_radio::Phase::Parked) {
            return Err(gen2_radio::Error::State);
        }
        drop(state);
        let mut admin = self.admin.lock();
        if admin.binding.is_some() {
            return Err(gen2_radio::Error::State);
        }
        admin.binding = Some(registration.clone());
        drop(admin);
        if !narf_net::iface::set_open_stop_target(
            &registration,
            Arc::new(Target(Arc::downgrade(self))),
        ) {
            self.close();
            return Err(gen2_radio::Error::State);
        }
        self.publish_carrier(false);
        Ok(())
    }
    fn request_admin(self: &Arc<Self>, event: OpenStopEvent) {
        let binding = if event.up() {
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
            // Admission closes immediately; the worker's final reopen is
            // serialized with it. No await or USB access under this lock.
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
                // Every real UP follows initial DOWN or a real DOWN; a
                // coalesced reversal still retires the old association.
                match state.park().await {
                    Ok(()) => state.wake().await,
                    Err(error) => Err(error),
                }
            } else {
                state.park().await
            };
            if result.is_err() {
                state.slot = Slot::Failed;
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
                    // A fresh RX Narf-Ring generation for the reopened netdev.
                    let (producer, consumer) = narf_ipc::channel();
                    state.rx = producer;
                    *self.rx.lock() = Some(consumer);
                    self.closed.store(false, Ordering::Release);
                }
                (current, same)
            };
            if event.up() && !current && same {
                // Registration loss during a wake cannot publish to a
                // successor; finish this device's park and close it.
                let _ = state.park().await;
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
        }
    }
}
