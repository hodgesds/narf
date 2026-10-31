//! Native periodic-scan commands and autonomous lifetime over actual TFH/
//! RFH allocations. Only firmware execution/radio remain fixture supplied.
use super::*;
use narf_capabilities::{Cap, Invoke};
use narf_net::netlink_generic::{
    build_replies_with_endpoint, DeferredReplySink, ReplyOptions, RequestContext,
};
use narf_wireless::ap_control::RadioControlAuthority;
use narf_wireless::{NetDetectMatch, NetDetectScanPlan, SchedScanRequest};

pub(super) struct Model {
    request: SchedScanRequest,
    profiles_seen: bool,
    pub(super) hold_start: bool,
    pub(super) hold_stop: bool,
    pub(super) abort_status: u32,
    malformed_abort: bool,
    pub(super) live: bool,
}
impl Model {
    fn new(request: SchedScanRequest) -> Self {
        Self {
            request,
            profiles_seen: false,
            hold_start: false,
            hold_stop: false,
            abort_status: 0,
            malformed_abort: false,
            live: false,
        }
    }
    pub(super) fn profiles(&mut self, body: &[u8]) -> R {
        require(
            body.len() == 584 && body[..512].iter().all(|&v| v == 0),
            "Sc PNO native blocklist/profile extent",
        )?;
        for i in 0..8 {
            require(
                body[512 + i * 8..520 + i * 8]
                    == if i < self.request.matches.len() {
                        vec![i as u8, 255, 63, 3, 12, 1, 0, 0]
                    } else {
                        vec![0; 8]
                    },
                "Sc PNO literal per-profile fields",
            )?;
        }
        require(
            body[576..]
                == [
                    0,
                    self.request.matches.len() as u8,
                    1,
                    1,
                    1,
                    u8::from(
                        self.request
                            .matches
                            .first()
                            .is_none_or(|m| m.ssid.is_empty()),
                    ),
                    0,
                    0,
                ],
            "Sc PNO profile clients/match notification",
        )?;
        self.profiles_seen = true;
        Ok(())
    }
    pub(super) fn start(&mut self, body: &[u8]) -> R {
        require(
            self.profiles_seen
                && !self.live
                && body.len() == 1948
                && word(body, 0) == 1
                && word(body, 4) == 2
                && body[45] == 1
                && body[52] == 6,
            "Sc PNO UID/native scan extent/channel/profile ordering",
        )?;
        let flags = half(body, 8);
        require(
            flags & 0x101 == 0x101 && flags & (1 << 8) != 0,
            "Sc PNO missing actual periodic/preemptive flags",
        )?;
        let pass_all = self
            .request
            .matches
            .first()
            .is_none_or(|m| m.ssid.is_empty());
        require(
            (flags & (1 << 5) != 0) != pass_all,
            "Sc PNO match/pass-all flags",
        )?;
        // Independent native schedule offsets: header48 +68 channel8.
        for (i, plan) in self.request.plans.iter().enumerate() {
            require(
                half(body, 592 + 4 * i) == plan.interval_secs as u16
                    && body[594 + 4 * i] == plan.iterations.map_or(255, |n| n as u8)
                    && body[595 + 4 * i] == 0,
                "Sc PNO literal periodic plan",
            )?;
        }
        require(
            half(body, 600) == self.request.delay_secs.min(65535) as u16
                && body[602..604] == [0, 0],
            "Sc PNO delay clamp/reserved",
        )?;
        let active = word(body, 48) & 0xfffff != 0;
        require(
            active == !self.request.probe_ssids.is_empty(),
            "Sc PNO match sets wrongly authorized probes",
        )?;
        if active {
            require(
                flags & (1 << 11) == 0 && half(body, 606) == 26,
                "Sc PNO active MAC segment",
            )?;
            let mac = &body[634..640]; // probe604 + data20 + SA10
            if let Some(random) = self.request.random_mac {
                require(
                    mac[0] & 3 == 2
                        && mac
                            .iter()
                            .enumerate()
                            .all(|(i, &v)| v & random.mask[i] == random.addr[i] & random.mask[i]),
                    "Sc PNO random source bits/entropy contract",
                )?;
            } else {
                require(mac == OWN, "Sc PNO actual probe source")?;
            }
            require(
                self.request.matches.iter().rev().enumerate().all(|(i, m)| {
                    body[1141 + i * 34] as usize == m.ssid.len()
                        && body[1142 + i * 34..1142 + i * 34 + m.ssid.len()] == m.ssid
                }),
                "Sc PNO reverse direct-SSID match table",
            )?;
            if !self.request.probe_ies.is_empty() {
                let at = half(body, 620) as usize;
                let len = half(body, 622) as usize;
                require(
                    len == self.request.probe_ies.len()
                        && at + len <= 512
                        && body[624 + at..624 + at + len] == self.request.probe_ies,
                    "Sc PNO common probe IE segment",
                )?;
            }
        } else {
            require(
                flags & (1 << 11) != 0,
                "Sc PNO passive profile emitted probes",
            )?;
        }
        self.live = true;
        Ok(())
    }
    pub(super) fn abort(&mut self, body: &[u8]) -> R<Vec<u8>> {
        require(
            self.live && body == [1, 0, 0, 0, 0, 0, 0, 0],
            "Sc PNO aborted wrong firmware slot",
        )?;
        if self.abort_status == 2 {
            self.live = false;
        }
        Ok(if self.malformed_abort {
            vec![]
        } else {
            self.abort_status.to_le_bytes().to_vec()
        })
    }
}

#[derive(Debug)]
struct Source(AtomicBool, IrqSafeSpinLock<Vec<Vec<u8>>>);
impl DeferredReplySink for Source {
    fn current(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
    fn deliver(&self, message: Vec<u8>) -> Result<(), i32> {
        if !self.current() {
            return Err(125);
        }
        self.1.lock().push(message);
        Ok(())
    }
}
struct Control {
    fixture: Option<Guard>,
    source: Arc<Source>,
    admin: narf_net::AdminHandle,
    daemon: Cap<narf_net::stack::StackDaemon, Invoke>,
    ifindex: u32,
}
impl Control {
    fn new(request: SchedScanRequest) -> R<Self> {
        Self::with_guard(request, Guard::new(false, Fault::None)?)
    }
    fn with_guard(request: SchedScanRequest, guard: Guard) -> R<Self> {
        let device = guard.device();
        let authority = narf_net::bootstrap_authority();
        let cap = narf_net::registry()
            .register(&authority, RegisteredDevice(device.clone()))
            .map_err(|_| "Sc PNO real driver registry")?;
        let daemon = Cap::<narf_net::stack::StackDaemon, Invoke>::bootstrap();
        let admin = narf_net::stack::control_registered(&narf_net::stack::StackAttach {
            iface: cap,
            daemon,
        })
        .map_err(|_| "Sc PNO actual delegated daemon authority")?
        .admin;
        narf_wireless::registry::register(device.clone());
        narf_wireless::nl80211::register();
        let ifindex = narf_net::iface::lookup(device.name())
            .ok_or("Sc PNO actual netdev")?
            .ifindex;
        HARNESS.lock().as_mut().unwrap().1.scheduled = Some(Model::new(request));
        Ok(Self {
            fixture: Some(guard),
            source: Arc::new(Source(
                AtomicBool::new(true),
                IrqSafeSpinLock::new(Vec::new()),
            )),
            admin,
            daemon,
            ifindex,
        })
    }
    fn device(&self) -> &Arc<Device> {
        self.fixture.as_ref().unwrap().device()
    }
    fn authority(&self) -> R<RadioControlAuthority> {
        let iface: Arc<dyn WirelessNetIface> = self.device().clone();
        RadioControlAuthority::bind(
            self.admin.clone(),
            &iface,
            0,
            self.ifindex,
            self.source.clone(),
        )
        .and_then(RadioControlAuthority::reserve)
        .map_err(|_| "Sc PNO actual radio lease")
    }
    fn request(&self) -> SchedScanRequest {
        HARNESS
            .lock()
            .as_ref()
            .unwrap()
            .1
            .scheduled
            .as_ref()
            .unwrap()
            .request
            .clone()
    }
    fn start(&self) -> R {
        let authority = self.authority()?;
        run(
            self.device()
                .start_sched_scan_async(&authority, self.request()),
            service,
        )?
        .map_err(|_| "Sc PNO native START")
    }
    fn stop(&self) -> R {
        let authority = self.authority()?;
        run(self.device().stop_sched_scan_async(&authority), service)?
            .map_err(|_| "Sc PNO native STOP")
    }
}
impl Drop for Control {
    fn drop(&mut self) {
        self.source.0.store(false, Ordering::Release);
        if self.fixture.is_some() {
            for _ in 0..64 {
                let _ = service();
                drain();
            }
            narf_wireless::registry::unregister(self.device().name());
            narf_net::registry().unregister(self.device().name());
        }
        self.fixture.take();
    }
}
fn configured(active: bool) -> SchedScanRequest {
    SchedScanRequest {
        probe_ssids: if active {
            vec![SSID.to_vec()]
        } else {
            Vec::new()
        },
        frequencies_mhz: vec![2437],
        probe_ies: if active {
            vec![221, 3, 0x76, 1, 2]
        } else {
            Vec::new()
        },
        matches: vec![NetDetectMatch {
            ssid: SSID.to_vec(),
            rssi_threshold_dbm: Some(-70),
        }],
        plans: vec![
            NetDetectScanPlan {
                interval_secs: 7,
                iterations: Some(2),
            },
            NetDetectScanPlan {
                interval_secs: 30,
                iterations: None,
            },
        ],
        delay_secs: 100_000,
        random_mac: None,
    }
}
fn until(mut condition: impl FnMut() -> bool) -> R {
    let deadline = narf_time::Deadline::after_ms(2500);
    loop {
        service()?;
        drain();
        narf_scheduler::poll_one_round();
        if condition() {
            return Ok(());
        }
        if deadline.expired() {
            return Err("Sc PNO native progress bound");
        }
        narf_scheduler::sleep_pumps::run();
    }
}
fn attr(out: &mut Vec<u8>, kind: u16, body: &[u8]) {
    out.extend_from_slice(&((body.len() + 4) as u16).to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(body);
    out.resize(out.len().next_multiple_of(4), 0);
}
fn message(control: &Control, command: u8, sequence: u32) -> Vec<u8> {
    let mut fields = Vec::new();
    attr(&mut fields, 3, &control.ifindex.to_ne_bytes());
    if command == 75 {
        let request = control.request();
        let mut ssids = Vec::new();
        for (i, ssid) in request.probe_ssids.iter().enumerate() {
            attr(&mut ssids, i as u16, ssid);
        }
        if !ssids.is_empty() {
            attr(&mut fields, 0x802d, &ssids);
        }
        let mut frequencies = Vec::new();
        for (i, freq) in request.frequencies_mhz.iter().enumerate() {
            attr(&mut frequencies, i as u16, &freq.to_ne_bytes());
        }
        attr(&mut fields, 0x802c, &frequencies);
        attr(&mut fields, 42, &request.probe_ies);
        let mut matches = Vec::new();
        for (i, m) in request.matches.iter().enumerate() {
            let mut one = Vec::new();
            attr(&mut one, 1, &m.ssid);
            if let Some(rssi) = m.rssi_threshold_dbm {
                attr(&mut one, 2, &rssi.to_ne_bytes());
            }
            attr(&mut matches, 0x8001 + i as u16, &one);
        }
        if !matches.is_empty() {
            attr(&mut fields, 0x8084, &matches);
        }
        let mut plans = Vec::new();
        for (i, p) in request.plans.iter().enumerate() {
            let mut one = Vec::new();
            attr(&mut one, 1, &p.interval_secs.to_ne_bytes());
            if let Some(n) = p.iterations {
                attr(&mut one, 2, &n.to_ne_bytes());
            }
            attr(&mut plans, 0x8001 + i as u16, &one);
        }
        attr(&mut fields, 0x80e1, &plans);
        attr(&mut fields, 220, &request.delay_secs.to_ne_bytes());
    }
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&((20 + fields.len()) as u32).to_ne_bytes());
    bytes.extend_from_slice(&narf_wireless::nl80211::NL80211_FAMILY_ID.to_ne_bytes());
    bytes.extend_from_slice(&(if command == 32 { 0x301u16 } else { 5u16 }).to_ne_bytes());
    bytes.extend_from_slice(&sequence.to_ne_bytes());
    bytes.extend_from_slice(&77u32.to_ne_bytes());
    bytes.extend_from_slice(&[command, 1, 0, 0]);
    bytes.extend_from_slice(&fields);
    bytes
}
fn dispatch(control: &Control, command: u8, sequence: u32) -> R<Vec<Vec<u8>>> {
    build_replies_with_endpoint(
        &message(control, command, sequence),
        ReplyOptions::default(),
        RequestContext {
            admin: Some(&control.admin),
            portid: 77,
            ..RequestContext::default()
        },
        control.source.clone(),
    )
    .map_err(|_| "Sc PNO actual generic-netlink dispatch")
}
fn inject_result() {
    let mut slot = HARNESS.lock();
    let wire = &mut slot.as_mut().unwrap().1;
    let beacon = wire.ap.beacon();
    wire.mpdu(&beacon, false);
    wire.firmware.inject(0xd9, 0, 0x8000, &[]);
}
fn smoke_sc_scheduled_native_profiles_periodic_probe_results_cache_and_terminal_stop() -> TestResult
{
    check(|| {
        let control = Control::new(configured(true))?;
        require(
            dispatch(&control, 75, 0x7101)?.is_empty(),
            "Sc PNO queued START acknowledged early",
        )?;
        until(|| !control.source.1.lock().is_empty())?;
        {
            let replies = control.source.1.lock();
            require(
                replies.len() == 1
                    && replies[0].get(16..20) == Some(&0i32.to_ne_bytes())
                    && replies[0].get(8..12) == Some(&0x7101u32.to_ne_bytes()),
                "Sc PNO START terminal actual sequence/ACK",
            )?;
        }
        require(
            control
                .device()
                .state
                .try_lock()
                .is_some_and(|s| s.scheduled.is_some() && !s.needs_reset),
            "Sc PNO did not retain autonomous native owner",
        )?;
        inject_result();
        until(|| control.device().scan_information_elements(AP).is_some())?;
        let replies = dispatch(&control, 32, 0x7102)?;
        require(
            replies
                .iter()
                .any(|reply| reply.windows(SSID.len()).any(|s| s == SSID)),
            "Sc PNO RESULTS did not update actual GET_SCAN cache",
        )?;
        control.source.1.lock().clear();
        require(
            dispatch(&control, 76, 0x7103)?.is_empty(),
            "Sc PNO queued STOP acknowledged early",
        )?;
        until(|| !control.source.1.lock().is_empty())?;
        let stopped =
            control.device().state.try_lock().is_some_and(|s| {
                s.scheduled.is_none() && !s.needs_reset && !s.hardware.is_failed()
            });
        require(
            stopped,
            "Sc PNO explicit native abort failed healthy retirement",
        )
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/sc/scheduled",
    smoke_sc_scheduled_native_profiles_periodic_probe_results_cache_and_terminal_stop
);

fn smoke_sc_scheduled_dropped_start_waiter_retains_native_dma_and_quiesces() -> TestResult {
    check(|| {
        let control = Control::new(configured(false))?;
        HARNESS
            .lock()
            .as_mut()
            .unwrap()
            .1
            .scheduled
            .as_mut()
            .unwrap()
            .hold_start = true;
        let authority = control.authority()?;
        let mut future = Box::pin(
            control
                .device()
                .start_sched_scan_async(&authority, control.request()),
        );
        let mut cx = Context::from_waker(Waker::noop());
        until(|| {
            let _ = future.as_mut().poll(&mut cx);
            HARNESS.lock().as_ref().unwrap().1.held.is_some()
        })?;
        drop(future);
        drop(authority);
        until(|| {
            control
                .device()
                .state
                .try_lock()
                .is_some_and(|s| s.stop_completed)
        })?;
        let state = control
            .device()
            .state
            .try_lock()
            .ok_or("Sc PNO canceled retained state")?;
        require(
            state.hardware.is_failed()
                && state.scheduled.is_none()
                && model::retained(&state.hardware).0 > 0,
            "Sc PNO dropped caller released uncertain command DMA or emitter",
        )?;
        drop(state);
        {
            let mut h = HARNESS.lock();
            let wire = &mut h.as_mut().unwrap().1;
            let (c, g, s) = wire.held.take().unwrap();
            wire.firmware.inject(c, if g == 1 { 0 } else { g }, s, &[]);
        }
        drain();
        require(
            !control.device().link_up()
                && control
                    .device()
                    .state
                    .try_lock()
                    .is_some_and(|s| s.scheduled.is_none()),
            "Sc PNO stale start receipt resurrected closed owner",
        )
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/sc/scheduled",
    smoke_sc_scheduled_dropped_start_waiter_retains_native_dma_and_quiesces
);

fn smoke_sc_scheduled_stop_waits_owned_uid_and_survives_dropped_stop_waiter() -> TestResult {
    check(|| {
        let control = Control::new(configured(false))?;
        control.start()?;
        HARNESS
            .lock()
            .as_mut()
            .unwrap()
            .1
            .scheduled
            .as_mut()
            .unwrap()
            .hold_stop = true;
        let authority = control.authority()?;
        let mut stop = Box::pin(control.device().stop_sched_scan_async(&authority));
        let mut cx = Context::from_waker(Waker::noop());
        until(|| {
            let _ = stop.as_mut().poll(&mut cx);
            HARNESS
                .lock()
                .as_ref()
                .unwrap()
                .1
                .commands
                .iter()
                .any(|(g, c, _)| (*g, *c) == (1, 0xe))
        })?;
        require(
            stop.as_mut().poll(&mut cx).is_pending(),
            "Sc PNO command ACK incorrectly proved autonomous stop",
        )?;
        drop(stop);
        drop(authority);
        {
            let mut h = HARNESS.lock();
            let wire = &mut h.as_mut().unwrap().1;
            let mut done = [0; 16];
            done[..4].copy_from_slice(&0u32.to_le_bytes());
            done[6] = 2;
            wire.firmware.inject(0xf, 0, 0x8000, &done);
        }
        drain();
        require(
            control.device().state.try_lock().is_none(),
            "Sc PNO foreign UID released retained stop state",
        )?;
        {
            let mut h = HARNESS.lock();
            let wire = &mut h.as_mut().unwrap().1;
            let mut done = [0; 16];
            done[..4].copy_from_slice(&1u32.to_le_bytes());
            done[6] = 2;
            wire.firmware.inject(0xf, 0, 0x8000, &done);
            wire.scheduled.as_mut().unwrap().live = false;
        }
        until(|| {
            control
                .device()
                .control
                .try_lock()
                .is_some_and(|c| c.is_none())
        })?;
        require(
            control.device().state.try_lock().is_some_and(|s| {
                !s.needs_reset && !s.hardware.is_failed() && s.scheduled.is_none()
            }),
            "Sc PNO dropped STOP lost its native terminal owner",
        )?;
        HARNESS
            .lock()
            .as_mut()
            .unwrap()
            .1
            .scheduled
            .as_mut()
            .unwrap()
            .hold_stop = false;
        control.start()?;
        control.stop()
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/sc/scheduled",
    smoke_sc_scheduled_stop_waits_owned_uid_and_survives_dropped_stop_waiter
);

fn smoke_sc_scheduled_live_policy_source_and_malformed_abort_cannot_leave_emitter() -> TestResult {
    check(|| {
        for boundary in 0..4 {
            let control = Control::new(configured(boundary == 0))?;
            control.start()?;
            match boundary {
                0 => control.fixture.as_ref().unwrap().policy_db.clear(),
                1 => control.daemon.revoke(),
                2 => control.source.0.store(false, Ordering::Release),
                _ => {
                    HARNESS
                        .lock()
                        .as_mut()
                        .unwrap()
                        .1
                        .scheduled
                        .as_mut()
                        .unwrap()
                        .malformed_abort = true;
                    require(
                        control.stop().is_err(),
                        "Sc PNO empty abort ACK accepted as stop proof",
                    )?;
                }
            }
            until(|| {
                control
                    .device()
                    .state
                    .try_lock()
                    .is_some_and(|s| s.scheduled.is_none())
            })?;
            if boundary == 0 || boundary == 3 {
                require(
                    control.device().state.try_lock().is_some_and(|s| {
                        s.needs_reset && s.stop_completed && s.hardware.is_failed()
                    }),
                    "Sc PNO lost authority/ambiguous stop skipped physical fallback",
                )?;
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/sc/scheduled",
    smoke_sc_scheduled_live_policy_source_and_malformed_abort_cannot_leave_emitter
);

fn smoke_sc_scheduled_pass_all_passive_filters_not_found_and_random_probe_source() -> TestResult {
    check(|| {
        let mut request = configured(false);
        request.matches.clear();
        let control = Control::new(request)?;
        require(
            dispatch(&control, 75, 0x7110)?.is_empty(),
            "Sc PNO pass-all parser refused native opt-in",
        )?;
        until(|| !control.source.1.lock().is_empty())?;
        {
            let mut h = HARNESS.lock();
            let wire = &mut h.as_mut().unwrap().1;
            let beacon = wire.ap.beacon();
            wire.mpdu(&beacon, false);
            let mut iteration = [0; 16];
            iteration[..4].copy_from_slice(&1u32.to_le_bytes());
            wire.firmware.inject(0xb5, 0, 0x8000, &iteration);
            wire.scheduled.as_mut().unwrap().abort_status = 2;
        }
        until(|| control.device().scan_information_elements(AP).is_some())?;
        control.stop()?;
        drop(control);
        let mut request = configured(true);
        request.random_mac = Some(narf_wireless::ScanRandomMac {
            addr: [2, 0x76, 0, 0, 0, 0],
            mask: [255, 255, 0, 0, 0, 0],
        });
        let control = Control::new(request)?;
        control.start()?;
        control.stop()
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/sc/scheduled",
    smoke_sc_scheduled_pass_all_passive_filters_not_found_and_random_probe_source
);
