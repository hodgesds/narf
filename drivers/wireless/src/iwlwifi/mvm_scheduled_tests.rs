//! Source-selected API77 periodic profiles over actual TFH/RFH and public
//! current-capability controls. Firmware/radio execution stays modeled.
use super::*;
use narf_capabilities::Invoke;
use narf_net::netlink_generic::DeferredReplySink;
use narf_wireless::ap_control::RadioControlAuthority;
use narf_wireless::{NetDetectMatch, NetDetectScanPlan, SchedScanRequest};
type R<T = ()> = Result<T, &'static str>;
#[derive(Clone, Copy)]
pub(super) struct Profile {
    pub command: Option<u8>,
    pub short: bool,
}
pub(super) struct Model {
    pub profile: Profile,
    pub request: SchedScanRequest,
    profiles: bool,
    live: bool,
    hold_start: bool,
    hold_profile: bool,
    hold_stop: bool,
    status: u32,
    malformed: bool,
}
impl Model {
    pub(super) fn new(profile: Profile, request: SchedScanRequest) -> Self {
        Self {
            profile,
            request,
            profiles: false,
            live: false,
            hold_start: false,
            hold_profile: false,
            hold_stop: false,
            status: 0,
            malformed: false,
        }
    }
    fn profile_bytes(&mut self, b: &[u8]) -> R {
        let maximum = if self.profile.command.is_some_and(|v| v != 99 && v >= 3) {
            8
        } else {
            11
        };
        let blocklist = if self.profile.short { 128 } else { 512 };
        ensure(
            b.len() == blocklist + maximum * 8 + 8 && b[..blocklist].iter().all(|&x| x == 0),
            "MVM PNO actual blocklist/profile size",
        )?;
        for i in 0..maximum {
            let expected = if i < self.request.matches.len() {
                [i as u8, 255, 63, 3, 12, 1, 0, 0]
            } else {
                [0; 8]
            };
            ensure(
                b[blocklist + i * 8..blocklist + i * 8 + 8] == expected,
                "MVM PNO independent profile record",
            )?;
        }
        ensure(
            b[blocklist + maximum * 8..]
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
            "MVM PNO native profile client controls",
        )?;
        self.profiles = true;
        Ok(())
    }
    fn scan(&mut self, b: &[u8]) -> R {
        ensure(
            self.profiles
                && !self.live
                && b.len() == 1940
                && word(b, 0) == 1
                && word(b, 4) == 2
                && b[45] == 1
                && b[52] == 1,
            "MVM PNO v15 extent/UID/channel/OOC/profile ordering",
        )?;
        let active = !self.request.probe_ssids.is_empty();
        ensure(
            (word(b, 48) & 0xfffff != 0) == active
                && (half(b, 8) & 0x800 == 0) == active
                && half(b, 8) & 0x101 == 0x101,
            "MVM PNO periodic/passive/probe mask",
        )?;
        for (i, p) in self.request.plans.iter().enumerate() {
            ensure(
                half(b, 584 + i * 4) == p.interval_secs as u16
                    && b[586 + i * 4] == p.iterations.map_or(255, |n| n as u8)
                    && b[587 + i * 4] == 0,
                "MVM PNO native two-plan bytes",
            )?;
        }
        ensure(
            half(b, 592) == self.request.delay_secs.min(65535) as u16 && b[594..596] == [0, 0],
            "MVM PNO delay clamp/reserved bytes",
        )?;
        if active {
            ensure(
                half(b, 598) == 26 && half(b, 600) == 26,
                "MVM PNO qualified raw26/band probe segments",
            )?;
            let source = &b[626..632];
            if let Some(random) = self.request.random_mac {
                ensure(
                    source[0] & 1 == 0
                        && source.iter().enumerate().all(|(i, &byte)| {
                            byte & random.mask[i] == random.addr[i] & random.mask[i]
                        }),
                    "MVM PNO random source mask changed hardware identity qualification",
                )?;
            } else {
                ensure(
                    source == OWN,
                    "MVM PNO probe source differs from actual MAC",
                )?;
            }
            let at = half(b, 612) as usize;
            let len = half(b, 614) as usize;
            ensure(
                at + len <= 512 && b[616 + at..616 + at + len] == self.request.probe_ies,
                "MVM PNO actual common IE segment",
            )?;
        }
        self.live = true;
        Ok(())
    }
}
fn word(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}
fn half(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(b[at..at + 2].try_into().unwrap())
}
fn ensure(value: bool, error: &'static str) -> R {
    if value {
        Ok(())
    } else {
        Err(error)
    }
}
impl Actor {
    pub(super) fn scheduled_command(&mut self, g: u8, c: u8, s: u16, b: &[u8]) -> R<bool> {
        if self.pno.is_none() {
            return Ok(false);
        }
        match (g, c) {
            (1, 0x6e) => {
                self.pno.as_mut().unwrap().profile_bytes(b)?;
                if self.pno.as_ref().unwrap().hold_profile {
                    self.held = Some((c, 0, s, vec![]));
                } else {
                    self.reply(c, 0, s, vec![]);
                }
            }
            (1, 0xd) if b.get(..4) == Some(&1u32.to_le_bytes()) => {
                self.pno.as_mut().unwrap().scan(b)?;
                if self.pno.as_ref().unwrap().hold_start {
                    self.held = Some((c, 0, s, vec![]));
                } else {
                    self.reply(c, 0, s, vec![]);
                }
            }
            (1, 0xe) => {
                ensure(
                    b == [1, 0, 0, 0, 0, 0, 0, 0] && self.pno.as_ref().unwrap().live,
                    "MVM PNO abort UID/control",
                )?;
                let model = self.pno.as_mut().unwrap();
                let status = model.status;
                let complete = !model.hold_stop && status <= 1;
                let malformed = model.malformed;
                if status == 2 || complete {
                    model.live = false;
                }
                self.reply(
                    c,
                    0,
                    s,
                    if malformed {
                        vec![]
                    } else {
                        status.to_le_bytes().to_vec()
                    },
                );
                if complete {
                    let mut done = [0; 16];
                    done[..4].copy_from_slice(&1u32.to_le_bytes());
                    done[6] = 2;
                    self.inject(0xf, 0, 0x8000, &done);
                }
            }
            _ => return Ok(false),
        }
        Ok(true)
    }
}
#[derive(Debug)]
struct Source(
    AtomicBool,
    IrqSafeSpinLock<Option<Arc<super::super::super::scheduled_epoch::Audit>>>,
);
impl DeferredReplySink for Source {
    fn current(&self) -> bool {
        let audit = self.1.lock().clone();
        if let Some(audit) = audit {
            audit.observe();
        }
        self.0.load(Ordering::Acquire)
    }
    fn deliver(&self, _: Vec<u8>) -> Result<(), i32> {
        if self.current() {
            Ok(())
        } else {
            Err(125)
        }
    }
}
struct Control {
    harness: Option<Box<Harness>>,
    source: Arc<Source>,
    admin: narf_net::AdminHandle,
    daemon: Cap<narf_net::stack::StackDaemon, Invoke>,
    ifindex: u32,
}
impl Control {
    fn new(profile: Profile, active: bool, protected: bool) -> R<Self> {
        let request = request(active);
        let h = Box::new(Harness::build_nvm_scheduled(
            protected,
            false,
            1,
            3,
            false,
            false,
            0,
            0,
            0,
            false,
            profile.command == Some(3),
            Some(Model::new(profile, request)),
        )?);
        let grant = narf_net::bootstrap_authority();
        let cap = narf_net::registry()
            .register(&grant, Registered(h.device.clone()))
            .map_err(|_| "MVM PNO actual net capability registration")?;
        let daemon = Cap::<narf_net::stack::StackDaemon, Invoke>::bootstrap();
        let admin = narf_net::stack::control_registered(&narf_net::stack::StackAttach {
            iface: cap,
            daemon,
        })
        .map_err(|_| "MVM PNO actual delegated admin")?
        .admin;
        narf_wireless::registry::register(h.device.clone());
        let ifindex = narf_net::iface::lookup(h.device.name())
            .ok_or("MVM PNO actual ifindex")?
            .ifindex;
        Ok(Self {
            harness: Some(h),
            source: Arc::new(Source(AtomicBool::new(true), IrqSafeSpinLock::new(None))),
            admin,
            daemon,
            ifindex,
        })
    }
    fn h(&self) -> &Harness {
        self.harness.as_ref().unwrap()
    }
    fn authority(&self) -> R<RadioControlAuthority> {
        let iface: Arc<dyn WirelessNetIface> = self.h().device.clone();
        RadioControlAuthority::bind(
            self.admin.clone(),
            &iface,
            0,
            self.ifindex,
            self.source.clone(),
        )
        .and_then(RadioControlAuthority::reserve)
        .map_err(|_| "MVM PNO actual native lease")
    }
    fn start(&self) -> R {
        let authority = self.authority()?;
        let request = self.h().actor.lock().pno.as_ref().unwrap().request.clone();
        run(self.h().device.start_sched_scan_async(&authority, request))?
            .map_err(|_| "MVM PNO native START")
    }
    fn stop(&self) -> R {
        let authority = self.authority()?;
        run(self.h().device.stop_sched_scan_async(&authority))?.map_err(|_| "MVM PNO native STOP")
    }
    fn discover(&self) -> R {
        {
            let mut a = self.h().actor.lock();
            let beacon = a.security.ap.beacon();
            a.inject(0xc1, 0, 0x8000, &envelope(&beacon));
            a.inject(0xd9, 0, 0x8000, &[]);
        }
        until(self, || {
            self.h().device.scan_information_elements(AP).is_some()
        })
    }
}
impl Drop for Control {
    fn drop(&mut self) {
        self.source.0.store(false, Ordering::Release);
        if self.harness.is_some() {
            for _ in 0..16 {
                let _ = self.h().actor.lock().serve();
                self.h().device.drain();
            }
            narf_wireless::registry::unregister(self.h().device.name());
            narf_net::registry().unregister(self.h().device.name());
        }
        self.harness.take();
    }
}
fn request(active: bool) -> SchedScanRequest {
    SchedScanRequest {
        probe_ssids: if active {
            vec![b"net".to_vec()]
        } else {
            vec![]
        },
        frequencies_mhz: vec![2412],
        probe_ies: vec![221, 3, 0x76, 1, 2],
        matches: vec![NetDetectMatch {
            ssid: b"net".to_vec(),
            rssi_threshold_dbm: Some(-70),
        }],
        plans: vec![
            NetDetectScanPlan {
                interval_secs: 5,
                iterations: Some(3),
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
fn until(control: &Control, mut done: impl FnMut() -> bool) -> R {
    let deadline = narf_time::Deadline::after_ms(3000);
    loop {
        control.h().actor.lock().serve()?;
        control.h().device.drain();
        if done() {
            return Ok(());
        }
        if deadline.expired() {
            return Err("MVM PNO progress bound");
        }
        narf_scheduler::sleep_pumps::run();
    }
}
fn smoke_mvm_scheduled_actual_profile_and_linux_defaults_keep_idle_native_owner() -> TestResult {
    check(|| {
        for profile in [
            Profile {
                command: Some(3),
                short: false,
            },
            Profile {
                command: None,
                short: false,
            },
            Profile {
                command: Some(2),
                short: true,
            },
            Profile {
                command: Some(99),
                short: true,
            },
        ] {
            let c = Control::new(profile, true, false)?;
            if profile.command == Some(3) {
                c.h().actor.lock().pno.as_mut().unwrap().request.random_mac =
                    Some(narf_wireless::ScanRandomMac {
                        addr: [2, 0x76, 0, 0, 0, 0],
                        mask: [255, 255, 0, 0, 0, 0],
                    });
            }
            let before = c.h().actor.lock().commands.len();
            c.start()?;
            ensure(
                c.h()
                    .device
                    .state
                    .try_lock()
                    .is_some_and(|s| s.scheduled.is_some())
                    && !c.h().device.link_up(),
                "MVM PNO running native owner/idle carrier",
            )?;
            let commands = c.h().actor.lock().commands[before..].to_vec();
            let powers: Vec<_> = commands
                .iter()
                .filter(|(g, c, _)| (*g, *c) == (1, 0x9f))
                .collect();
            ensure(
                powers.len() == 2
                    && powers[0].2[0] == 2
                    && powers[1].2[0] == 1
                    && !commands
                        .iter()
                        .any(|(g, c, _)| *g == 1 && matches!(*c, 8 | 0x18)),
                "MVM PNO lacks qualified device/SAR or installed station",
            )?;
            c.discover()?;
            if profile.command == Some(99) {
                c.h().actor.lock().pno.as_mut().unwrap().status = 2;
            }
            c.stop()?;
            ensure(
                !c.h().device.terminal.load(Ordering::Acquire)
                    && c.h()
                        .device
                        .state
                        .try_lock()
                        .is_some_and(|s| s.scheduled.is_none()),
                "MVM PNO healthy stop lost configured owner",
            )?;
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/scheduled",
    smoke_mvm_scheduled_actual_profile_and_linux_defaults_keep_idle_native_owner
);

fn smoke_mvm_scheduled_passive_without_probe_qualifier_and_results_join_real_wpa2_dhcp(
) -> TestResult {
    check(|| {
        let c = Control::new(
            Profile {
                command: Some(3),
                short: false,
            },
            false,
            true,
        )?;
        c.h().available.store(false, Ordering::Release);
        c.start()?;
        c.discover()?;
        c.h().available.store(true, Ordering::Release);
        run(c.h().device.associate(c.h().request()))?
            .map_err(|_| "MVM PNO result did not retire UID and join")?;
        ensure(
            c.h().device.link_up()
                && c.h()
                    .device
                    .state
                    .try_lock()
                    .is_some_and(|s| s.scheduled.is_none()),
            "MVM PNO-to-station port or retirement",
        )?;
        let lease = narf_net::dhcp::dhcp_acquire(c.h().device.name(), 0)
            .map_err(|_| "MVM PNO real DORA")?;
        ensure(NETWORK.matches_lease(&lease), "MVM PNO DORA lease")?;
        let before = c.h().actor.lock().commands.len();
        ensure(
            c.start().is_err(),
            "MVM PNO accepted non-idle Linux-refused station",
        )?;
        ensure(
            c.h().actor.lock().commands.len() == before,
            "MVM refused non-idle PNO mutated hardware",
        )?;
        run(c.h().device.disassociate())?.map_err(|_| "MVM PNO joined close")
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/scheduled",
    smoke_mvm_scheduled_passive_without_probe_qualifier_and_results_join_real_wpa2_dhcp
);

fn smoke_mvm_scheduled_dropped_start_pins_native_command_and_power_revocation_stops() -> TestResult
{
    check(|| {
        for boundary in 0..6 {
            let c = Control::new(
                Profile {
                    command: Some(3),
                    short: false,
                },
                true,
                false,
            )?;
            if boundary == 0 {
                c.h().actor.lock().pno.as_mut().unwrap().hold_start = true;
                let authority = c.authority()?;
                let request = c.h().actor.lock().pno.as_ref().unwrap().request.clone();
                let mut start = Box::pin(c.h().device.start_sched_scan_async(&authority, request));
                until(&c, || {
                    let _ = once(start.as_mut());
                    c.h().actor.lock().held.is_some()
                })?;
                drop(start);
                drop(authority);
            } else {
                c.start()?;
                match boundary {
                    1 => {
                        c.h().scan_power.revoke();
                    }
                    2 => {
                        c.h().firmware.revoke();
                    }
                    3 => {
                        c.h().db.clear();
                    }
                    4 => {
                        c.daemon.revoke();
                    }
                    _ => c.source.0.store(false, Ordering::Release),
                }
            }
            until(&c, || {
                c.h()
                    .device
                    .state
                    .try_lock()
                    .is_some_and(|s| s.scheduled.is_none())
                    && c.h().device.control.try_lock().is_some_and(|s| s.is_none())
            })?;
            ensure(
                !c.h().device.link_up(),
                "MVM PNO lost authority left live carrier",
            )?;
            if boundary <= 3 {
                ensure(
                    c.h().device.terminal.load(Ordering::Acquire),
                    "MVM PNO RF/source loss skipped retained physical stop",
                )?;
            }
            if boundary == 0 {
                ensure(
                    c.h().retained().0 > 0,
                    "MVM dropped PNO start freed uncertain DMA",
                )?;
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/scheduled",
    smoke_mvm_scheduled_dropped_start_pins_native_command_and_power_revocation_stops
);

fn smoke_mvm_scheduled_dropped_stop_waits_exact_uid_and_bad_status_quarantines() -> TestResult {
    check(|| {
        let c = Control::new(
            Profile {
                command: Some(3),
                short: false,
            },
            false,
            false,
        )?;
        c.start()?;
        c.h().actor.lock().pno.as_mut().unwrap().hold_stop = true;
        let authority = c.authority()?;
        let mut stop = Box::pin(c.h().device.stop_sched_scan_async(&authority));
        until(&c, || {
            let _ = once(stop.as_mut());
            c.h()
                .actor
                .lock()
                .commands
                .iter()
                .any(|(g, c, _)| (*g, *c) == (1, 0xe))
        })?;
        ensure(
            once(stop.as_mut()).is_pending(),
            "MVM PNO abort ACK released autonomous owner",
        )?;
        drop(stop);
        drop(authority);
        {
            let mut a = c.h().actor.lock();
            let mut done = [0; 16];
            done[6] = 2;
            a.inject(0xf, 0, 0x8000, &done);
        }
        c.h().device.drain();
        ensure(
            c.h().device.state.try_lock().is_none(),
            "MVM PNO foreign completion released UID",
        )?;
        {
            let mut a = c.h().actor.lock();
            let mut done = [0; 16];
            done[0] = 1;
            done[6] = 2;
            a.inject(0xf, 0, 0x8000, &done);
            a.pno.as_mut().unwrap().live = false;
        }
        until(&c, || {
            c.h().device.control.try_lock().is_some_and(|s| s.is_none())
        })?;
        ensure(
            !c.h().device.terminal.load(Ordering::Acquire),
            "MVM PNO dropped STOP destroyed healthy transport",
        )?;
        c.h().actor.lock().pno.as_mut().unwrap().hold_stop = false;
        c.start()?;
        c.h().actor.lock().pno.as_mut().unwrap().malformed = true;
        ensure(
            c.stop().is_err() && c.h().device.terminal.load(Ordering::Acquire),
            "MVM PNO malformed abort ACK proved stop",
        )
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/scheduled",
    smoke_mvm_scheduled_dropped_stop_waits_exact_uid_and_bad_status_quarantines
);

fn smoke_mvm_scheduled_terminal_notification_does_not_refresh_old_bss() -> TestResult {
    check(|| {
        let c = Control::new(
            Profile {
                command: Some(3),
                short: false,
            },
            false,
            false,
        )?;
        c.start()?;
        c.discover()?;
        c.h().clock.fetch_add(
            narf_time::wall::ns_to_cycles(11_000_000_000),
            Ordering::AcqRel,
        );
        {
            let mut a = c.h().actor.lock();
            let mut done = [0; 16];
            done[0] = 1;
            done[6] = 1;
            a.inject(0xf, 0, 0x8000, &done);
            a.pno.as_mut().unwrap().live = false;
        }
        until(&c, || {
            c.h()
                .device
                .state
                .try_lock()
                .is_some_and(|s| s.scheduled.is_none())
        })?;
        ensure(
            c.h().device.scan_information_elements(AP).is_none()
                && run(c.h().device.associate(c.h().request()))?.is_err(),
            "MVM PNO completion rejuvenated expired BSS",
        )
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/scheduled",
    smoke_mvm_scheduled_terminal_notification_does_not_refresh_old_bss
);

fn smoke_mvm_scheduled_mcc_during_profile_or_held_start_stops_retained_emitter() -> TestResult {
    check(|| {
        for published in [false, true] {
            let c = Control::new(
                Profile {
                    command: Some(3),
                    short: false,
                },
                true,
                false,
            )?;
            {
                let mut actor = c.h().actor.lock();
                let model = actor.pno.as_mut().unwrap();
                model.hold_profile = !published;
                model.hold_start = published;
            }
            let authority = c.authority()?;
            let request = c.h().actor.lock().pno.as_ref().unwrap().request.clone();
            let mut start = Box::pin(c.h().device.start_sched_scan_async(&authority, request));
            until(&c, || {
                let _ = once(start.as_mut());
                c.h().actor.lock().held.is_some()
            })?;
            {
                let mut actor = c.h().actor.lock();
                actor.inject(0xc9, 0, 0x8000, &[b'C', b'A', 0, 0]);
                if !published {
                    let (cmd, group, sequence, body) = actor.held.take().unwrap();
                    actor.inject(cmd, group, sequence, &body);
                }
            }
            // An observed native policy loss cannot wait for an unrelated
            // held command receipt or its two-second command timeout.
            let deadline = narf_time::Deadline::after_ms(500);
            loop {
                if let Poll::Ready(result) = once(start.as_mut()) {
                    ensure(result.is_err(), "MVM native MCC loss acknowledged START")?;
                    break;
                }
                c.h().actor.lock().serve()?;
                if deadline.expired() {
                    return Err("MVM native MCC did not interrupt held scan receipt");
                }
                narf_scheduler::sleep_pumps::run();
            }
            drop(start);
            drop(authority);
            ensure(
                c.h().device.terminal.load(Ordering::Acquire),
                "MVM native MCC loss skipped retained transport retirement",
            )?;
            let emitted = c.h().actor.lock().commands.iter().any(|(g, cmd, body)| {
                (*g, *cmd) == (1, 0xd) && body.get(..4) == Some(&1u32.to_le_bytes())
            });
            ensure(
                emitted == published,
                "MVM known stale MCC reached scanner publication",
            )?;
            if published {
                ensure(
                    c.h().retained().0 > 0,
                    "MVM MCC stop freed uncertain SCAN_REQ DMA",
                )?;
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/scheduled",
    smoke_mvm_scheduled_mcc_during_profile_or_held_start_stops_retained_emitter
);

fn copied_result(control: &Control, bssid: [u8; 6]) -> R<Vec<super::super::scheduled::Delivery>> {
    {
        let mut actor = control.h().actor.lock();
        let mut beacon = actor.security.ap.beacon();
        beacon[10..16].copy_from_slice(&bssid);
        beacon[16..22].copy_from_slice(&bssid);
        actor.inject(0xc1, 0, 0x8000, &envelope(&beacon));
        actor.inject(0xd9, 0, 0x8000, &[]);
    }
    let mut state = control
        .h()
        .device
        .state
        .try_lock()
        .ok_or("MVM copied result state")?;
    let (copies, retire) = control.h().device.scheduled_tick(&mut state);
    ensure(!retire, "MVM actual copied result failed")?;
    Ok(copies)
}
fn scan_cache(control: &Control) -> R<Vec<Vec<u8>>> {
    use narf_net::netlink_generic::{build_replies_with_endpoint, ReplyOptions, RequestContext};
    let mut message = Vec::new();
    message.extend_from_slice(&28u32.to_ne_bytes());
    message.extend_from_slice(&narf_wireless::nl80211::NL80211_FAMILY_ID.to_ne_bytes());
    message.extend_from_slice(&0x301u16.to_ne_bytes());
    message.extend_from_slice(&0x7208u32.to_ne_bytes());
    message.extend_from_slice(&77u32.to_ne_bytes());
    message.extend_from_slice(&[32, 1, 0, 0]);
    message.extend_from_slice(&8u16.to_ne_bytes());
    message.extend_from_slice(&3u16.to_ne_bytes());
    message.extend_from_slice(&control.ifindex.to_ne_bytes());
    narf_wireless::nl80211::register();
    build_replies_with_endpoint(
        &message,
        ReplyOptions::default(),
        RequestContext {
            admin: Some(&control.admin),
            portid: 77,
            ..RequestContext::default()
        },
        control.source.clone(),
    )
    .map_err(|_| "MVM actual GET_SCAN dispatch")
}
fn smoke_mvm_scheduled_cache_callback_is_linearized_with_native_uid_retirement() -> TestResult {
    check(|| {
        let control = Control::new(
            Profile {
                command: Some(3),
                short: false,
            },
            false,
            false,
        )?;
        control.start()?;
        let weak = Arc::downgrade(&control.h().device);
        let audit = Arc::new(super::super::super::scheduled_epoch::Audit::new(
            control.h().device.scan_generation.clone(),
            move || weak.upgrade().is_some_and(|d| d.state.try_lock().is_some()),
        ));
        let mut first = copied_result(&control, AP)?;
        ensure(first.len() == 1, "MVM actual copied result missing")?;
        *control.source.1.lock() = Some(audit.clone());
        first.remove(0).publish();
        *control.source.1.lock() = None;
        ensure(
            audit.valid() && audit.calls() >= 3,
            "MVM shared cache/source callback escaped publication gate or held native state",
        )?;
        let stale = copied_result(&control, AP)?;
        {
            let mut actor = control.h().actor.lock();
            let mut done = [0; 16];
            done[0] = 1;
            done[6] = 1;
            actor.inject(0xf, 0, 0x8000, &done);
            actor.pno.as_mut().unwrap().live = false;
        }
        let stopped = {
            let mut state = control
                .h()
                .device
                .state
                .try_lock()
                .ok_or("MVM terminal copy state")?;
            let (copies, retire) = control.h().device.scheduled_tick(&mut state);
            ensure(!retire, "MVM actual terminal copy failed")?;
            copies
        };
        ensure(stopped.len() == 1, "MVM actual terminal copy missing")?;
        control.start()?;
        let next = [2, 4, 6, 8, 10, 13];
        for publication in copied_result(&control, next)? {
            publication.publish();
        }
        *control.source.1.lock() = Some(audit.clone());
        let before = audit.calls();
        for publication in stale.into_iter().chain(stopped) {
            publication.publish();
        }
        *control.source.1.lock() = None;
        ensure(
            audit.calls() == before,
            "MVM retired callback reentered shared source/cache",
        )?;
        let replies = scan_cache(&control)?;
        ensure(
            replies.iter().any(|r| r.windows(6).any(|b| b == next))
                && !replies.iter().any(|r| r.windows(6).any(|b| b == AP)),
            "MVM late result replaced successor GET_SCAN data",
        )?;
        control.stop()
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/scheduled",
    smoke_mvm_scheduled_cache_callback_is_linearized_with_native_uid_retirement
);
