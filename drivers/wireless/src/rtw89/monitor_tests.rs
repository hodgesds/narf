// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Actual controller/public Device/raw packet lifecycle with explicit inert
//! full-RFK/channel/firmware-source boundaries. No real radio is fabricated.
use super::*;
use crate::rtw89::{
    interface, packet_core as packet, station, station_control, station_lifecycle::Lifecycle,
};
use alloc::{boxed::Box, collections::VecDeque, sync::Arc, vec, vec::Vec};
use core::{
    future::Future,
    task::{Context, Waker},
};
use narf_capabilities::{Cap, Read};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_net::Interface as _;
use narf_wireless::WirelessNetIface as _;
const OWN: [u8; 6] = [2, 4, 6, 8, 10, 12];
struct Backend {
    control: station_control::tests::Model,
    device: narf_capabilities::Cap<narf_bus::BusDeviceCap, narf_capabilities::Write>,
    qualification: Arc<crate::rtw89::radio_policy::Qualification>,
    cap: Cap<narf_firmware::FirmwareBlob, Read>,
    observed: [u32; 4],
    quiet: bool,
    raw: VecDeque<Vec<u8>>,
    assembler: crate::rtw89::rx_packet::Assembler,
    stopped: bool,
    close_program: bool,
}
impl Backend {
    fn new() -> Self {
        let (qualification, cap) = crate::rtw89::radio_policy::tests::revocable_model();
        Self {
            control: station_control::tests::Model::new(),
            device: Cap::bootstrap(),
            qualification: Arc::new(qualification),
            cap,
            observed: [0x1c01; 4],
            quiet: true,
            raw: VecDeque::new(),
            assembler: Default::default(),
            stopped: false,
            close_program: false,
        }
    }
    fn inject(&mut self, frame: &[u8], errors: u32) -> Result<(), &'static str> {
        let length = frame.len() + 4;
        let mut bytes = vec![0; 20 + length];
        let extent = bytes.len() as u32;
        bytes[..4].copy_from_slice(&(extent | 1 << 15 | 1 << 14).to_le_bytes());
        bytes[4..8].copy_from_slice(&(length as u32).to_le_bytes());
        bytes[16..20].copy_from_slice(&errors.to_le_bytes());
        bytes[20..20 + frame.len()].copy_from_slice(frame);
        match self
            .assembler
            .segment(&bytes, false)
            .map_err(|_| "actual monitor RXBD assembly")?
        {
            Some(crate::rtw89::rx_packet::Event::Wifi(_, raw)) => self.raw.push_back(raw),
            Some(crate::rtw89::rx_packet::Event::Dropped) => {}
            _ => return Err("unexpected monitor RXBD event"),
        }
        Ok(())
    }
}
// SAFETY: private RAM/controller/source model, no actual hardware. All modeled
// original device/base sources and actual production control codecs remain
// checked; the RFK/channel-read boundary is explicitly inert above.
unsafe impl Io for Backend {
    fn current(&mut self, admission: &Admission, _: Selection) -> Result<(), power::Error> {
        admission.check()?;
        crate::rtw88::pci_park::invoke(&self.device, || {
            self.qualification.with_current(|| {
                if self.stopped || self.control.word(0xc000) & monitor_wire::CMAC_TX != 0 {
                    return Err(power::Error::Access);
                }
                Ok(())
            })
        })
        .map_err(|_| power::Error::Access)?
    }
    async fn program(
        &mut self,
        admission: &Admission,
        selection: Selection,
    ) -> Result<(), power::Error> {
        self.current(admission, selection)?;
        station_control::initialize_monitor(&mut self.control, OWN, false, admission).await?;
        if self.close_program {
            admission.close();
        }
        self.current(admission, selection)
    }
    async fn observed_channel(
        &mut self,
        admission: &Admission,
        selection: Selection,
    ) -> Result<[u32; 4], power::Error> {
        self.current(admission, selection)?;
        Ok(self.observed)
    }
    fn retire_prefix(
        &mut self,
        admission: &Admission,
        selection: Selection,
    ) -> Result<bool, power::Error> {
        self.current(admission, selection)?;
        self.raw.clear();
        Ok(self.quiet)
    }
    fn receive(
        &mut self,
        admission: &Admission,
        selection: Selection,
        budget: usize,
    ) -> Result<Vec<Vec<u8>>, power::Error> {
        self.current(admission, selection)?;
        Ok((0..budget).filter_map(|_| self.raw.pop_front()).collect())
    }
    fn stop(&mut self) -> Result<(), power::Error> {
        self.stopped = true;
        Ok(())
    }
}
struct Driver {
    backend: Backend,
    controller: Option<Controller>,
}
impl Driver {
    fn new() -> Self {
        Self {
            backend: Backend::new(),
            controller: None,
        }
    }
}
#[async_trait::async_trait]
// SAFETY: no real hardware; retained private same-model control/native source.
// Ordinary station/TX paths refuse rather than minting peer or RF authority.
unsafe impl station::Io for Driver {
    fn monitor_capable(&mut self) -> Result<bool, power::Error> {
        self.backend
            .qualification
            .current()
            .map_err(|_| power::Error::Access)?;
        Ok(true)
    }
    fn monitor_active(&self) -> bool {
        self.controller.is_some()
    }
    async fn monitor_start(
        &mut self,
        desired: Arc<Desired>,
        admission: Admission,
    ) -> Result<Source, power::Error> {
        if self.controller.is_some() {
            return Err(power::Error::Terminal);
        }
        self.controller = Some(Controller::prepare(desired.clone(), admission.clone())?);
        let controller = self.controller.as_mut().unwrap();
        controller.start(&mut self.backend).await?;
        // SAFETY: explicit inert RFK/channel boundary, real same-source control
        // receipts/controller epoch above. Never used by a production attach.
        Ok(unsafe {
            Source::new(
                self.backend.device,
                self.backend.qualification.clone(),
                desired.clone(),
                desired.snapshot(),
                admission,
                controller.epoch(),
            )
        })
    }
    fn monitor_poll(&mut self) -> Result<Vec<Vec<u8>>, power::Error> {
        self.controller
            .as_mut()
            .ok_or(power::Error::Terminal)?
            .poll(&mut self.backend)
    }
    fn monitor_stop(&mut self) -> Result<(), power::Error> {
        self.controller
            .as_mut()
            .ok_or(power::Error::Terminal)?
            .stop(&mut self.backend)
    }
    fn station_allowed(&mut self) -> Result<(), power::Error> {
        Err(power::Error::Unsupported)
    }
    fn station_own(&mut self) -> Result<[u8; 6], power::Error> {
        Ok(OWN)
    }
    async fn station_prepare_initial(
        &mut self,
        _: [u8; 6],
        _: &Admission,
    ) -> Result<(), power::Error> {
        Err(power::Error::Unsupported)
    }
    async fn station_prepare_peer(
        &mut self,
        _: [u8; 6],
        _: &Admission,
    ) -> Result<(), power::Error> {
        Err(power::Error::Unsupported)
    }
    async fn station_commit_peer(
        &mut self,
        _: [u8; 6],
        _: u16,
        _: bool,
        _: &Admission,
    ) -> Result<(), power::Error> {
        Err(power::Error::Unsupported)
    }
    async fn station_disconnect(&mut self, _: [u8; 6], _: &Admission) -> Result<(), power::Error> {
        Err(power::Error::Unsupported)
    }
    fn packet_prepare(&mut self, _: [u8; 6], _: u8) -> Result<(), packet::Error> {
        Err(packet::Error::State)
    }
    fn packet_start(&mut self) -> Result<(), packet::Error> {
        Err(packet::Error::State)
    }
    fn packet_ready(&self) -> bool {
        false
    }
    fn packet_submit(&mut self, _: &[u8], _: bool) -> Result<u64, packet::Error> {
        Err(packet::Error::State)
    }
    fn packet_poll(&mut self) -> Result<packet::Step, packet::Error> {
        Err(packet::Error::State)
    }
    fn packet_stop(&mut self) -> Result<(), packet::Error> {
        self.backend.stopped = true;
        Ok(())
    }
}
fn selected() -> Arc<Desired> {
    let desired = Desired::new();
    desired.select(desired.snapshot(), 6).unwrap();
    desired
}
#[inline(never)]
fn start(controller: &mut Controller, backend: &mut Backend) -> Result<(), power::Error> {
    narf_scheduler::block_on(controller.start(backend))
}
fn controller_sources() -> Result<(), &'static str> {
    for failure in 0..7 {
        let desired = selected();
        let admission = Admission::new();
        let mut controller = Controller::prepare(desired.clone(), admission.clone())
            .map_err(|_| "prepare monitor")?;
        let epoch = controller.epoch();
        let mut backend = Backend::new();
        backend.inject(&[0xd4, 0, 0, 0, 1, 2, 3, 4, 5, 6], 0)?;
        match failure {
            1 => backend.observed[3] ^= 1,
            2 => backend.quiet = false,
            3 => backend.close_program = true,
            4 => {
                backend.cap.revoke();
            }
            5 => {
                desired.select(desired.snapshot(), 2).unwrap();
            }
            6 => {
                backend.device.revoke();
            }
            _ => {}
        }
        let result = start(&mut controller, &mut backend);
        if failure != 0 {
            if result.is_ok() || epoch.current() {
                return Err(
                    "monitor opened without original current source/native channel/quiet prefix",
                );
            }
            continue;
        }
        if result.is_err()
            || !epoch.current()
            || !controller
                .poll(&mut backend)
                .map_err(|_| "monitor poll")?
                .is_empty()
        {
            return Err("pre-active input became capture");
        }
        let ack = [0xd4, 0, 0, 0, 1, 2, 3, 4, 5, 6];
        backend.inject(&ack, 0)?;
        backend.inject(&ack, 1 << 9)?;
        backend.inject(&ack, 4)?;
        backend.inject(&ack, 1 << 6)?;
        if controller.poll(&mut backend).map_err(|_| "raw RX poll")? != vec![ack.to_vec()] {
            return Err("raw FCS/error/crypto/cut admission changed original ACK");
        }
        controller.stop(&mut backend).map_err(|_| "monitor stop")?;
        if epoch.current() || controller.poll(&mut backend).is_ok() {
            return Err("stopped monitor epoch revived");
        }
    }
    Ok(())
}
fn smoke_rtw8852b_monitor_original_native_channel_prefix_source_and_raw_rx() -> TestResult {
    controller_sources().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/rtw89/monitor",
    smoke_rtw8852b_monitor_original_native_channel_prefix_source_and_raw_rx
);
struct Public {
    device: Arc<interface::Device<Driver>>,
    lifecycle: Arc<Lifecycle<Driver>>,
    sockets: Vec<Arc<narf_net::raw_sock::PacketSock>>,
}
impl Public {
    fn new(desired: Arc<Desired>, name: Option<&str>) -> Result<Self, &'static str> {
        let lifecycle = Arc::new(Lifecycle::new(Driver::new()));
        let name = name
            .map(alloc::string::String::from)
            .unwrap_or_else(|| narf_net::iface::reserve_name("r89mon%d").into());
        let device = Arc::new(interface::Device::new_selected(
            &name,
            OWN,
            lifecycle.clone(),
            Arc::new(station::NativeEnvironment),
            desired,
        ));
        narf_net::iface::register(&name, OWN, |_, _| Err(()));
        narf_net::iface::set_link_layer(&name, narf_net::iface::LinkLayer::Ieee80211Radiotap)
            .map_err(|_| "monitor representation")?;
        if !interface::Device::bind_sleep_target(&device) {
            return Err("original monitor admin receiver");
        }
        device.admit_for_test(); // explicit inert registration/attach boundary
        narf_scheduler::block_on(device.activate())
            .map_err(|_| "actual public monitor activate")?;
        Ok(Self {
            device,
            lifecycle,
            sockets: Vec::new(),
        })
    }
    fn backend<T>(&self, op: impl FnOnce(&mut Backend) -> T) -> T {
        let mut held = self.lifecycle.retained.try_lock().unwrap();
        op(&mut held.as_mut().unwrap().io.backend)
    }
    fn bind(&mut self) -> Result<Arc<narf_net::raw_sock::PacketSock>, &'static str> {
        let socket =
            narf_net::raw_sock::PacketSock::create(0, narf_net::raw_sock::SOCK_RAW, 0, 212992);
        socket
            .bind(
                None,
                narf_net::iface::ifindex_of(self.device.name()).ok_or("monitor index")? as i32,
                narf_net::raw_sock::ETH_P_ALL.to_be(),
            )
            .map_err(|_| "monitor raw bind")?;
        // Every fixture binds while the interface is still admin DOWN:
        // `packet_do_bind` (net/packet/af_packet.c:3303) then reports
        // `sk->sk_err = ENETDOWN`, which the first recv returns and clears.
        // NETDEV_UP re-registers the hook (`packet_notifier`).
        if socket.recv(false).err() != Some(100) {
            return Err("bind on a DOWN monitor did not report ENETDOWN");
        }
        self.sockets.push(socket.clone());
        Ok(socket)
    }
    fn up(&self) {
        narf_net::iface::set_link_state(self.device.name(), true);
    }
}
impl Drop for Public {
    fn drop(&mut self) {
        for socket in &self.sockets {
            socket.release();
        }
        narf_net::iface::set_link_state(self.device.name(), false);
        let mut owner = self.lifecycle.retained.try_lock().unwrap();
        let _ = owner.as_mut().unwrap().station_stop();
        drop(owner);
        interface::withdraw(&self.device);
        narf_net::iface::unregister(self.device.name());
    }
}
#[inline(never)]
fn service(device: &interface::Device<Driver>) {
    // Constructor/poll are isolated from the calling fixture stack. Polling
    // only to the real worker timer avoids block_on inside another poll.
    let mut work = Box::pin(device.service_once());
    let _ = work.as_mut().poll(&mut Context::from_waker(Waker::noop()));
}
fn public_capture() -> Result<(), &'static str> {
    // Actual public metadata flow on the retiring original station shell:
    // explicit inert passive-station/full-RFK attach boundary, then the real
    // down-only SET_INTERFACE backend immediately followed by SET_WIPHY.
    let desired = Desired::new();
    let lifecycle = Arc::new(Lifecycle::new(Driver::new()));
    let name = narf_net::iface::reserve_name("r89mon-pending%d");
    let old = Arc::new(interface::Device::new_selected(
        name,
        OWN,
        lifecycle.clone(),
        Arc::new(station::NativeEnvironment),
        desired.clone(),
    ));
    narf_net::iface::register(name, OWN, |_, _| Err(()));
    if !interface::Device::bind_sleep_target(&old) {
        return Err("original pending-role metadata receiver");
    }
    old.admit_for_test();
    old.model_monitor_metadata_ready()
        .map_err(|_| "inert original station full-RFK boundary")?;
    let old_snapshot = narf_net::iface::lookup(name).ok_or("old station registration")?;
    old.set_iftype(6)
        .map_err(|_| "actual original SET_INTERFACE monitor")?;
    let pending_channel = narf_wireless::monitor::Channel {
        frequency_mhz: 2412,
        width: 1,
        center1_mhz: 2412,
        center2_mhz: 0,
    };
    old.set_monitor_channel(pending_channel)
        .map_err(|_| "pending monitor fixed-channel metadata should not wait for reset")?;
    service(&old);
    if !old.closed()
        || old.current_iftype() != 6
        || lifecycle
            .retained
            .try_lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .io
            .controller
            .is_some()
    {
        return Err("metadata ACK granted old shell native capture");
    }
    interface::withdraw(&old);
    narf_net::iface::unregister(name);
    let mut f = Public::new(desired, Some(name))?;
    if narf_net::iface::OpenStopEvent::observe(&old_snapshot).is_some()
        || old.set_monitor_channel(pending_channel).is_ok()
    {
        return Err("retired old metadata source followed fresh registration");
    }

    if f.device.current_iftype() != 6
        || !f
            .device
            .get_wireless_info()
            .modes
            .contains(narf_wireless::iface::WirelessModes::MONITOR)
    {
        return Err("qualified monitor missing actual public role advertisement");
    }
    for flags in [2, 4, 1 << 5, 1 << 6, 1 << 7] {
        if f.device.validate_monitor_flags(flags).is_ok() {
            return Err("unsupported monitor active/error/injection flags accepted");
        }
    }
    f.device
        .validate_monitor_flags((1 << 3) | (1 << 4))
        .map_err(|_| "supported raw control/otherBSS profile")?;
    let channel = narf_wireless::monitor::Channel {
        frequency_mhz: 2412,
        width: 1,
        center1_mhz: 2412,
        center2_mhz: 0,
    };
    f.device
        .set_monitor_channel(channel)
        .map_err(|_| "actual fixed monitor channel")?;
    for bad in [
        narf_wireless::monitor::Channel {
            frequency_mhz: 2437,
            center1_mhz: 2437,
            ..channel
        },
        narf_wireless::monitor::Channel {
            width: 2,
            ..channel
        },
        narf_wireless::monitor::Channel {
            center2_mhz: 2412,
            ..channel
        },
    ] {
        if f.device.set_monitor_channel(bad).is_ok() {
            return Err("monitor silently narrowed/retuned unsupported channel");
        }
    }
    let raw = f.bind()?;
    // DOWN never opens native capture or a station port.
    service(&f.device);
    if f.backend(|io| !io.control.packets().is_empty()) || f.device.link_up() {
        return Err("admin DOWN installed monitor role/capture");
    }
    f.up();
    service(&f.device);
    if f.device.closed()
        || !f.backend(|io| {
            io.control
                .packets()
                .iter()
                .any(|p| p[8..] == monitor_wire::role(false))
        })
    {
        return Err("public UP skipped actual monitor role receipts");
    }
    let ack = [0xd4, 0, 0, 0, 1, 2, 3, 4, 5, 6];
    let mut protected = vec![0u8; 32];
    protected[..2].copy_from_slice(&[8, 0x40]);
    protected[4..10].copy_from_slice(&[2, 1, 1, 1, 1, 1]);
    f.backend(|io| {
        io.inject(&ack, 0)?;
        io.inject(&protected, 0)?;
        io.inject(&ack, 1 << 9)?;
        Ok::<_, &'static str>(())
    })?;
    service(&f.device);
    for expected in [ack.as_slice(), protected.as_slice()] {
        let message = raw
            .recv(false)
            .map_err(|_| "raw packet monitor frame absent")?;
        if message.data.get(14..) != Some(expected)
            || message.hatype != 803
            || message.data[10..12] != 2412u16.to_le_bytes()
            || message.data[4..8] != 10u32.to_le_bytes()
            || message.data.len() != 14 + expected.len()
        {
            return Err("raw monitor bytes/FCS/observed channel/absent PHY metadata changed");
        }
    }
    if raw.recv(false).is_ok()
        || f.device.link_up()
        || f.device
            .enqueue(&[0; 60], narf_net::TxMeta::default())
            .is_ok()
        || narf_net::iface::send_on(f.device.name(), &[0; 60]).is_ok()
        || f.device.set_iftype(2) != Err(narf_wireless::WirelessError::Busy)
        || f.device.set_monitor_channel(channel) != Err(narf_wireless::WirelessError::Busy)
    {
        return Err("monitor admitted error frame/injection/station port/active mode change");
    }
    f.backend(|io| {
        io.cap.revoke();
    });
    f.backend(|io| io.inject(&ack, 0))?;
    service(&f.device);
    if raw.recv(false).is_ok() || !f.device.closed() {
        return Err("retired original RF source published capture");
    }
    Ok(())
}
fn smoke_rtw8852b_monitor_public_up_raw_capture_flags_channel_and_no_injection() -> TestResult {
    public_capture().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/rtw89/monitor",
    smoke_rtw8852b_monitor_public_up_raw_capture_flags_channel_and_no_injection
);
struct HeldSocket(Arc<narf_net::raw_sock::PacketSock>);
impl Drop for HeldSocket {
    fn drop(&mut self) {
        self.0.release();
    }
}
fn generations() -> Result<(), &'static str> {
    let desired = selected();
    let mut f = Public::new(desired.clone(), None)?;
    let raw = f.bind()?;
    f.sockets.clear();
    let _old_socket = HeldSocket(raw.clone());
    f.up();
    service(&f.device);
    let old_source = {
        let owner = f.lifecycle.retained.try_lock().unwrap();
        owner
            .as_ref()
            .unwrap()
            .io
            .controller
            .as_ref()
            .unwrap()
            .epoch()
    };
    let name = alloc::string::String::from(f.device.name());
    let old_snapshot = narf_net::iface::lookup(&name).ok_or("original monitor snapshot")?;
    narf_net::iface::set_link_state(&name, false);
    if !f.device.closed() || old_source.current() || raw.recv(false).is_ok() {
        return Err("DOWN did not synchronously retire original capture");
    }
    // A new UP on the same old owner cannot revive it. Actual fresh controller
    // receipts belong to a different registration/physical generation.
    f.up();
    service(&f.device);
    if !f.device.closed() || old_source.current() {
        return Err("old monitor owner revived after DOWN/UP");
    }
    narf_net::iface::set_link_state(&name, false);
    drop(f);
    let mut fresh = Public::new(desired.clone(), Some(&name))?;
    let next = narf_net::iface::lookup(&name).ok_or("fresh monitor snapshot")?;
    if next.ownership_epoch == old_snapshot.ownership_epoch
        || narf_net::iface::OpenStopEvent::observe(&old_snapshot).is_some()
    {
        return Err("monitor rebind reused registration");
    }
    let fresh_raw = fresh.bind()?;
    fresh.up();
    service(&fresh.device);
    fresh.backend(|io| io.inject(&[0xd4, 0, 0, 0, 9, 8, 7, 6, 5, 4], 0))?;
    service(&fresh.device);
    if fresh_raw.recv(false).is_err() || raw.recv(false).is_ok() || old_source.current() {
        return Err("monitor copy/socket followed fresh registration");
    }
    narf_net::iface::set_link_state(&name, false);
    // Mode selection is metadata only and the old source stays dead. Exercise
    // the same atomic selector used by the supervisor, including stale-write
    // denial, without inventing a second NIC or a physical reset receipt.
    let selection = desired.snapshot();
    fresh
        .device
        .set_iftype(2)
        .map_err(|_| "public down-only station next role")?;
    let station = desired.snapshot();
    if fresh.device.current_iftype() != 2
        || narf_net::iface::lookup(&name)
            .is_none_or(|entry| entry.link_layer != narf_net::iface::LinkLayer::Ethernet)
        || desired.select(selection, 6).is_some()
        || station.generation <= selection.generation
        || desired.current(selection)
    {
        return Err("stale monitor role selection revived");
    }
    Ok(())
}
fn smoke_rtw8852b_monitor_down_rebind_original_copies_and_role_generations() -> TestResult {
    generations().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/rtw89/monitor",
    smoke_rtw8852b_monitor_down_rebind_original_copies_and_role_generations
);

/// WoWLAN is advertised only by a generation that composed the whole WoW
/// path; an inert/unactivated shell refuses it and never arms, while the
/// retained configuration still crosses generations. Unexecuted.
fn smoke_rtw8852b_wowlan_unadvertised_without_composed_wow() -> TestResult {
    let lifecycle = Arc::new(Lifecycle::new(Driver::new()));
    let device = interface::Device::new_selected(
        "r89wow-inert",
        OWN,
        lifecycle,
        Arc::new(station::NativeEnvironment),
        selected(),
    );
    let config = narf_wireless::WowlanConfig {
        disconnect: true,
        magic_packet: true,
        gtk_rekey_failure: false,
        patterns: Vec::new(),
        net_detect: None,
    };
    if device.wowlan_support().is_some()
        || device.set_wowlan(Some(config.clone())) != Err(narf_wireless::EOPNOTSUPP)
        || device.wowlan_config().is_some()
    {
        return TestResult::Fail("WoWLAN advertised before the WoW path was composed");
    }
    device.restore_wowlan(Some(config.clone()), None);
    if device.wowlan_config().is_none() || device.wowlan().0.is_none() {
        return TestResult::Fail("retained WoWLAN configuration lost across generations");
    }
    if narf_scheduler::block_on(device.wow_suspend()) != Ok(false)
        || narf_scheduler::block_on(device.wow_resume()).is_ok()
        || device.closed()
    {
        return TestResult::Fail("uncomposed shell armed WoW or closed itself");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw8852b_wowlan_unadvertised_without_composed_wow
);
