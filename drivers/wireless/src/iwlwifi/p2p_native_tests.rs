//! Literal inert firmware conversations over real posted command/TFH/RFH
//! queues and the actual control-WDEV frontend. No model opens a host gate.
use super::*;
use narf_capabilities::{Cap, Invoke};
use narf_net::netlink_generic::DeferredReplySink;
use narf_wireless::ap_control::RadioControlAuthority;
const NODE: [u8; 6] = [2, 0x75, 1, 2, 3, 4];
const PEER: [u8; 6] = [2, 0x75, 5, 6, 7, 8];
const INTERVAL: u32 = 5000;

pub(super) struct Model {
    own: Option<[u8; 6]>,
    link: bool,
    aux: bool,
    queue: bool,
    read: u16,
    write: u16,
    activity: Option<u32>,
    start: bool,
    pub(super) hold: Option<(u8, u8)>,
    pub(super) held: Option<Vec<u8>>,
    no_start: bool,
    ack: bool,
    hold_tx: bool,
    held_tx: Option<(u16, u16)>,
    tx: Vec<Vec<u8>>,
    retired: usize,
}
impl Model {
    pub(super) fn new() -> Self {
        Self {
            own: None,
            link: false,
            aux: false,
            queue: false,
            read: 0,
            write: 0,
            activity: None,
            start: false,
            hold: None,
            held: None,
            no_start: false,
            ack: true,
            hold_tx: false,
            held_tx: None,
            tx: Vec::new(),
            retired: 0,
        }
    }
    pub(super) fn command(
        &mut self,
        group: u8,
        cmd: u8,
        version: u8,
        b: &[u8],
        fw: &mut model::Firmware,
    ) -> R<Option<Vec<u8>>> {
        let mut reply = Vec::new();
        match (group, cmd) {
            (3, 8) if b.len() == 52 && word(b, 0) == 1 => {
                require(
                    version == 3
                        && matches!(word(b, 4), 1 | 3)
                        && word(b, 8) == 6
                        && b[12..18] == NODE
                        && word(b, 20) == 2
                        && b[26..].iter().all(|v| *v == 0),
                    "P2P literal MAC1/type6/filter2/physical address",
                )?;
                if word(b, 4) == 1 {
                    require(self.own.is_none(), "P2P duplicate live MAC")?;
                    self.own = Some(NODE)
                } else {
                    require(
                        !self.link && !self.aux && !self.queue,
                        "P2P MAC removal before terminal dependent owners",
                    )?;
                    self.own = None;
                }
            }
            (3, 9) if b.len() == 208 && word(b, 4) == 1 => {
                require(
                    version == 8 && word(b, 8) == 1 && b[16..22] == NODE && word(b, 36) == 0,
                    "P2P literal LINK1/MAC1/no-CCK identity",
                )?;
                match word(b, 0) {
                    1 => {
                        require(
                            self.own == Some(NODE) && word(b, 28) == 0,
                            "P2P LINK needs native inactive MAC",
                        )?;
                        self.link = true
                    }
                    3 => {
                        require(
                            !self.aux && !self.queue,
                            "P2P LINK removal before exact AUX retirement",
                        )?;
                        self.link = false
                    }
                    _ => return Err("P2P LINK unexpected action"),
                }
            }
            (3, 0xb) => {
                require(
                    self.link
                        && self.own == Some(NODE)
                        && !self.aux
                        && b.len() == 16
                        && word(b, 0) == 14
                        && b[4..].iter().all(|v| *v == 0),
                    "P2P AUX is actual dedicated16-byte last factual station14, not STA_CFG/AUX31",
                )?;
                self.aux = true;
            }
            (5, 0x17) if self.own.is_some() => {
                require(
                    version == 3
                        && b.len() == 36
                        && word(b, 4) == 1 << 14
                        && b[8] == 16
                        && b[9..16].iter().all(|v| *v == 0),
                    "P2P actual AUX/TID16 TVQM extent",
                )?;
                match word(b, 0) {
                    0 => {
                        require(
                            self.aux
                                && !self.queue
                                && word(b, 16) == 4
                                && b[20..28] != [0; 8]
                                && b[28..36] != [0; 8],
                            "P2P queue needs actual AUX and DMA",
                        )?;
                        self.queue = true;
                        self.read = 0;
                        self.write = 0;
                    }
                    1 => {
                        require(
                            self.queue
                                && self.activity.is_none()
                                && self.read == self.write
                                && b[16..].iter().all(|v| *v == 0),
                            "P2P queue remove before actual ROC/flush prefix",
                        )?;
                        self.queue = false;
                    }
                    _ => return Err("P2P queue unsupported action"),
                }
                reply = vec![0; 8];
                reply[0] = 1;
            }
            (3, 0x0e) => {
                require(
                    version == 6 && b.len() == 44 && matches!(word(b, 4), 1 | 3),
                    "P2P actual ROCv6 activity/extent",
                )?;
                if word(b, 0) == 1 {
                    require(
                        self.aux
                            && self.queue
                            && self.activity.is_none()
                            && word(b, 8) == 14
                            && word(b, 12) == 6
                            && b[16..20] == [1, 0, 0, 0]
                            && b[20..26] == NODE
                            && b[26..28] == [0; 2]
                            && word(b, 28) == 195
                            && word(b, 32) == 4882
                            && b[36..].iter().all(|v| *v == 0),
                        "P2P ROC exact node/channel/TU/native owner",
                    )?;
                    self.activity = Some(word(b, 4));
                    if !self.no_start {
                        // Both physical copies belong to the one RFH drain
                        // whose grant was still closed at capture time. The
                        // intervening START cannot retrofit either copy.
                        fw.inject(0xc1, 0, 0x8000, &management(1, 1));
                        self.notification(fw, true, true, word(b, 4));
                        fw.inject(0xc1, 0, 0x8000, &management(1, 1));
                    }
                } else {
                    require(
                        word(b, 0) == 3
                            && self.activity == Some(word(b, 4))
                            && b[8..].iter().all(|v| *v == 0),
                        "P2P synchronous REMOVE needs original activity and zero tail",
                    )?;
                    self.activity = None;
                    self.start = false;
                    self.retired += 1;
                }
            }
            (1, 0x9f) if self.own.is_some() => {
                require(
                    matches!(version, 10 | 11)
                        && b.len() == if version == 10 { 108 } else { 116 }
                        && word(b, 0) == 1
                        && word(b, 4) == 0
                        && half(b, 8) == 136
                        && b[10..].iter().all(|v| *v == 0),
                    "P2P actual global SET_DEVICE power ceiling, never station0 SET_LINK",
                )?;
            }
            (1, 0x1e) if self.own.is_some() => {
                require(
                    version == 2 && b == [14, 0, 0, 0, 255, 255, 0, 0] && self.activity.is_none(),
                    "P2P native flush before synchronous ROC remove",
                )?;
                reply = vec![0; 132];
                reply[0] = 14;
                reply[2] = u8::from(self.queue);
                if self.queue {
                    reply[4..6].copy_from_slice(&16u16.to_le_bytes());
                    reply[6] = 1;
                    reply[8..10].copy_from_slice(&self.read.to_le_bytes());
                    reply[10..12].copy_from_slice(&self.write.to_le_bytes());
                    self.read = self.write;
                }
            }
            (3, 0xc) if self.own.is_some() => {
                require(
                    b == [14, 0, 0, 0] && self.aux && !self.queue && self.activity.is_none(),
                    "P2P AUX retirement precedes actual queue receipt",
                )?;
                self.aux = false;
            }
            _ => return Ok(None),
        }
        Ok(Some(reply))
    }
    fn notification(
        &mut self,
        fw: &mut model::Firmware,
        started: bool,
        success: bool,
        activity: u32,
    ) {
        let mut b = [0; 12];
        b[..4].copy_from_slice(&u32::from(success).to_le_bytes());
        b[4..8].copy_from_slice(&u32::from(started).to_le_bytes());
        b[8..].copy_from_slice(&activity.to_le_bytes());
        if started && success && self.activity == Some(activity) {
            self.start = true
        }
        fw.inject(0xf8, 3, 0x8000, &b);
    }
    pub(super) fn transmit(&mut self, p: &Published, fw: &mut model::Firmware) -> R {
        let b = &p.bytes;
        require(
            self.own == Some(NODE)
                && self.link
                && self.aux
                && self.queue
                && self.activity.is_some()
                && self.start
                && p.queue == 1
                && b.len() >= 56
                && b[0] == 0x1c
                && half(b, 6) == 3
                && word(b, 8) == 12 << 8
                && word(b, 20) == 0x4100,
            "P2P native TX lacks real ROC/AUX/TID/OFDM6/no-crypto owner",
        )?;
        let frame = b[32..].to_vec();
        require(
            frame.len() == usize::from(half(b, 4))
                && matches!(frame[0], 0x40 | 0xd0)
                && frame[1] & 0xc7 == 0
                && frame[10..16] == NODE
                && frame[22] & 15 == 0,
            "P2P native management frame physical identity/header",
        )?;
        self.write = p.pointer;
        self.tx.push(frame);
        if self.hold_tx {
            self.held_tx = Some((p.queue, p.pointer));
            return Ok(());
        }
        self.read = p.pointer;
        if self.ack {
            fw.tx_complete(p.queue, p.pointer)
        } else {
            let mut b = [0; 48];
            b[0] = 1;
            b[40] = 0x82;
            b[36..38].copy_from_slice(&p.queue.to_le_bytes());
            b[44..].copy_from_slice(&u32::from(p.pointer).to_le_bytes());
            fw.inject(0x1c, 0, 0x8000, &b);
        }
        Ok(())
    }
}

#[derive(Debug)]
struct Source {
    owner: narf_net::native_emission::ProviderLifetime,
    messages: IrqSafeSpinLock<Vec<Vec<u8>>>,
    children: IrqSafeSpinLock<Vec<narf_net::AdminHandle>>,
    retire_on_check: AtomicBool,
}
impl Source {
    fn new() -> Self {
        Self {
            owner: narf_net::native_emission::ProviderLifetime::new(),
            messages: IrqSafeSpinLock::new(Vec::new()),
            children: IrqSafeSpinLock::new(Vec::new()),
            retire_on_check: AtomicBool::new(false),
        }
    }
    fn count(&self, command: u8) -> usize {
        self.messages
            .lock()
            .iter()
            .filter(|b| b.get(16) == Some(&command))
            .count()
    }
}
impl DeferredReplySink for Source {
    fn current(&self) -> bool {
        if self.retire_on_check.swap(false, Ordering::AcqRel) {
            self.owner.retire().notify()
        }
        self.owner.observe().current()
    }
    fn native_source(&self) -> Option<narf_net::native_emission::Lifetime> {
        Some(self.owner.observe())
    }
    fn retain_control_admin(&self, admin: narf_net::AdminHandle) -> Result<(), i32> {
        if !self.current() {
            return Err(1);
        }
        self.children.lock().push(admin);
        Ok(())
    }
    fn control_admin(&self, name: &str, namespace: u64) -> Option<narf_net::AdminHandle> {
        if !self.current() {
            return None;
        }
        let children = { self.children.lock().clone() };
        children
            .into_iter()
            .find(|admin| admin.authorize_interface(name, namespace).is_ok())
    }
    fn deliver(&self, message: Vec<u8>) -> Result<(), i32> {
        if !self.current() {
            return Err(1);
        }
        self.messages.lock().push(message);
        Ok(())
    }
}
struct Fixture {
    guard: Box<Guard>,
    parent: Cap<narf_net::NetIface, narf_capabilities::Write>,
    admin: narf_net::AdminHandle,
    source: Arc<Source>,
    child: Option<Arc<dyn WirelessNetIface>>,
}
impl Fixture {
    #[inline(never)]
    fn new(bz: Option<super::super::super::bz_fixture::Case>) -> R<Self> {
        let guard = Box::new(Guard::build_native_profile(
            false,
            Fault::None,
            None,
            None,
            None,
            NativeModel {
                receive_model: ReceiveModel::P2p,
                tx_model: None,
                api89: None,
                bz,
                six: None,
            },
        )?);
        let device = guard.device();
        narf_net::iface::set_link_state(device.name(), false);
        let grant = narf_net::bootstrap_authority();
        let parent = narf_net::registry()
            .register(&grant, RegisteredDevice(device.clone()))
            .map_err(|_| "P2P actual parent registry receipt")?;
        device.p2p.registered(grant, parent);
        let daemon = Cap::<narf_net::StackDaemon, Invoke>::bootstrap();
        let admin = narf_net::stack::control_registered(&narf_net::StackAttach {
            iface: parent,
            daemon,
        })
        .map_err(|_| "P2P original parent delegated Admin")?
        .admin;
        narf_wireless::registry::register(device.clone());
        Ok(Self {
            guard,
            parent,
            admin,
            source: Arc::new(Source::new()),
            child: None,
        })
    }
    fn device(&self) -> &Arc<Device> {
        self.guard.device()
    }
    fn parent_authority(&self) -> R<RadioControlAuthority> {
        let device = self.device();
        let iface: Arc<dyn WirelessNetIface> = device.clone();
        let index = narf_net::iface::lookup(device.name())
            .ok_or("P2P physical registration absent")?
            .ifindex;
        RadioControlAuthority::bind(self.admin.clone(), &iface, 0, index, self.source.clone())
            .and_then(RadioControlAuthority::reserve)
            .map_err(|_| "P2P original parent request")
    }
    fn create(&mut self) -> R {
        let authority = self.parent_authority()?;
        let child = run(
            Box::pin(self.device().new_control_interface_async(
                &authority,
                "p2p-iwl",
                10,
                Some(NODE),
            )),
            service,
        )?
        .map_err(|_| "P2P actual NEW control child")?;
        require(
            child.current_iftype() == 10
                && child.control_namespace() == Some(0)
                && !child.link_up()
                && child.rx_ring().lock().is_none()
                && child.tx_ring().lock().is_none()
                && narf_net::iface::lookup(child.name()).is_none()
                && narf_wireless::registry::control_for(child.as_ref()).is_some(),
            "P2P NEW invented netdev/UP or lost real WDEV",
        )?;
        self.child = Some(child);
        Ok(())
    }
    fn child(&self) -> &Arc<dyn WirelessNetIface> {
        self.child.as_ref().unwrap()
    }
    fn authority(&self) -> R<RadioControlAuthority> {
        self.authority_from(self.source.clone())
    }
    fn authority_from(&self, source: Arc<Source>) -> R<RadioControlAuthority> {
        let child = self.child();
        let wdev = narf_wireless::registry::control_for(child.as_ref())
            .ok_or("P2P current WDEV absent")?;
        let admin = self
            .source
            .control_admin(child.name(), 0)
            .ok_or("P2P socket did not retain actual child grant")?;
        RadioControlAuthority::bind_wdev(admin, child, 0, wdev.id(), source)
            .and_then(RadioControlAuthority::reserve)
            .map_err(|_| "P2P exact control source/role/reservation")
    }
    fn start(&self) -> R {
        let authority = self.authority()?;
        run(
            Box::pin(self.child().start_p2p_device_async(&authority)),
            service,
        )?
        .map_err(|_| "P2P actual native MAC/LINK START receipts")
    }
    fn roc(&self, cookie: u64) -> R {
        self.roc_from(self.source.clone(), cookie)
    }
    fn roc_from(&self, source: Arc<Source>, cookie: u64) -> R {
        let authority = self.authority_from(source)?;
        run(
            Box::pin(
                self.child()
                    .remain_on_channel_async(&authority, cookie, 2437, INTERVAL),
            ),
            service,
        )?
        .map_err(|_| "P2P actual native ROC START")
    }
    fn register(&self) -> R {
        let authority = self.authority()?;
        run(
            Box::pin(
                self.child()
                    .register_mgmt_frame_radio_async(&authority, 0xd0, &[4, 9]),
            ),
            service,
        )?
        .map_err(|_| "P2P original REGISTER_FRAME")
    }
    fn frame(&self, cookie: u64, protected: bool) -> R<bool> {
        self.transmit(cookie, protected, false)
    }
    fn transmit(&self, cookie: u64, protected: bool, implicit: bool) -> R<bool> {
        let authority = self.authority()?;
        let mut frame = vec![0; 26];
        frame[0] = 0xd0;
        frame[1] = u8::from(protected) * 0x40;
        frame[4..10].copy_from_slice(&PEER);
        frame[10..16].copy_from_slice(&NODE);
        frame[16..22].copy_from_slice(&PEER);
        frame[24..].copy_from_slice(&[4, 9]);
        run(
            Box::pin(self.child().mgmt_tx_radio_async(
                &authority,
                cookie,
                narf_wireless::MgmtTxRequest {
                    frequency_mhz: 2437,
                    frame,
                    offchannel_ok: implicit,
                    duration: if implicit { INTERVAL } else { 0 },
                    no_cck: true,
                },
            )),
            service,
        )?
        .map_err(|_| "P2P actual management TX result")
    }
    fn stop(&self) -> R {
        let authority = self.authority()?;
        run(
            Box::pin(self.child().stop_p2p_device_async(&authority)),
            service,
        )?
        .map_err(|_| "P2P native STOP terminal receipts")
    }
    fn delete(&mut self) -> R {
        let child = self.child().clone();
        let authority = self.authority()?;
        let retired = run(
            Box::pin(child.delete_control_interface_async(&authority)),
            service,
        )?
        .map_err(|_| "P2P native DEL terminal typed receipt")?;
        require(
            retired.current()
                && narf_wireless::registry::control_by_id(
                    narf_wireless::registry::control_for(child.as_ref())
                        .ok_or("P2P retired identity absent")?
                        .id(),
                    0,
                )
                .is_none(),
            "P2P native DEL leaked selector or stale terminal identity",
        )?;
        drop(retired);
        drop(authority);
        require(
            narf_wireless::registry::control_for(child.as_ref()).is_none(),
            "P2P terminal DEL did not release exact metadata",
        )?;
        self.child = None;
        Ok(())
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        // Native cleanup remains owned even after source/caller retirement.
        // Release any deliberately held inert receipt before bounded pump.
        {
            let mut slot = HARNESS.lock();
            if let Some((_, wire)) = slot.as_mut() {
                if let Some(p2p) = &mut wire.native_p2p {
                    p2p.hold = None;
                    p2p.no_start = false;
                    p2p.hold_tx = false;
                    if let Some((cmd, group, sequence)) = wire.held.take() {
                        wire.firmware.inject(
                            cmd,
                            group,
                            sequence,
                            &p2p.held.take().unwrap_or_default(),
                        );
                    }
                    if let Some((queue, pointer)) = p2p.held_tx.take() {
                        wire.firmware.tx_complete(queue, pointer)
                    }
                }
            }
        }
        for _ in 0..64 {
            let _ = service();
            let _ = self.device().step(None);
        }
        if self
            .device()
            .state
            .try_lock()
            .is_some_and(|state| state.hardware.p2p_started())
        {
            let _ = run(Box::pin(self.device().p2p_stop_request()), service);
            let _ = self.device().step(None);
        }
        if let Some(child) = self.child.take() {
            child.release_control_metadata()
        }
        narf_wireless::registry::unregister(self.device().name());
        narf_net::registry().unregister_for_handle(&self.parent);
    }
}
fn native_state(fixture: &Fixture) -> R {
    let state = fixture
        .device()
        .state
        .try_lock()
        .ok_or("P2P terminal State still busy")?;
    require(
        !state.hardware.p2p_started()
            && !state.hardware.is_failed()
            && model::retained(&state.hardware) == (0, 0, 0),
        "P2P terminal cleanup lacks actual DMA/queue/ROC receipts",
    )
}
fn management(band: u8, link: u8) -> Vec<u8> {
    let mut b = vec![0; 64 + 26];
    b[..2].copy_from_slice(&26u16.to_le_bytes());
    b[7] = (band << 6) | link;
    b[12..16].copy_from_slice(&3u32.to_le_bytes());
    b[40] = 45;
    b[42] = 6;
    b[64] = 0xd0;
    b[68..74].copy_from_slice(&NODE);
    b[74..80].copy_from_slice(&PEER);
    b[80..86].copy_from_slice(&PEER);
    b[88..].copy_from_slice(&[4, 9]);
    b
}
fn inject_management(band: u8, link: u8) {
    HARNESS
        .lock()
        .as_mut()
        .unwrap()
        .1
        .firmware
        .inject(0xc1, 0, 0x8000, &management(band, link));
}
fn pump(fixture: &Fixture) -> R {
    let deadline = narf_time::Deadline::after_ms(3000);
    for _ in 0..100_000 {
        service()?;
        let _ = fixture.device().step(None);
        let idle = fixture.device().state.try_lock().is_some_and(|state| {
            !state.hardware.has_pending_rx() && !state.hardware.p2p_needs_retirement()
        });
        if idle {
            return Ok(());
        }
        if deadline.expired() {
            return Err("P2P retained native worker did not reach terminal/idle boundary");
        }
        narf_scheduler::sleep_pumps::run();
    }
    Err("P2P retained native worker exceeded bounded poll budget")
}
fn smoke_iwl_p2p_sc_bz_actual_child_start_roc_management_ack_and_terminal_delete() -> TestResult {
    check(|| {
        for bz in [
            None,
            Some(super::super::super::bz_fixture::Case::FmDiscrete),
            Some(super::super::super::bz_fixture::Case::WhDiscrete),
        ] {
            let mut f = Fixture::new(bz)?;
            f.create()?;
            f.register()?;
            f.start()?;
            let roc_source = Arc::new(Source::new());
            f.roc_from(roc_source.clone(), 7)?;
            require(
                f.source.count(55) == 0 && roc_source.count(55) == 1,
                "P2P READY absent or duplicated before matching native START",
            )?;
            require(
                f.source.count(59) == 0,
                "P2P START retroactively admitted a same-drain RFH copy",
            )?;
            inject_management(1, 1);
            pump(&f)?;
            require(
                f.source.count(59) == 1,
                "P2P actual matching copy/filter not delivered",
            )?;
            require(f.frame(8, false)?, "P2P real ACK was not returned")?;
            HARNESS
                .lock()
                .as_mut()
                .unwrap()
                .1
                .native_p2p
                .as_mut()
                .unwrap()
                .ack = false;
            require(
                !f.frame(9, false)?,
                "P2P failed native TX became successful ACK",
            )?;
            f.stop()?;
            native_state(&f)?;
            require(
                f.source.count(56) == 0 && roc_source.count(56) == 1,
                "P2P EXPIRED before or without terminal native retirement",
            )?;
            HARNESS
                .lock()
                .as_mut()
                .unwrap()
                .1
                .native_p2p
                .as_mut()
                .unwrap()
                .ack = true;
            f.start()?;
            require(
                f.transmit(10, false, true)?,
                "P2P private management ROC native ACK missing",
            )?;
            f.stop()?;
            native_state(&f)?;
            require(
                f.source.count(55) == 0
                    && f.source.count(56) == 0
                    && roc_source.count(55) == 1
                    && roc_source.count(56) == 1,
                "P2P private FRAME leaked public ROC events or retargeted their original source",
            )?;
            f.delete()?;
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/p2p",
    smoke_iwl_p2p_sc_bz_actual_child_start_roc_management_ack_and_terminal_delete
);

fn smoke_iwl_p2p_command_ack_cannot_replace_actual_start_and_dropped_roc_keeps_cleanup(
) -> TestResult {
    check(|| {
        let mut f = Fixture::new(None)?;
        f.create()?;
        f.start()?;
        HARNESS
            .lock()
            .as_mut()
            .unwrap()
            .1
            .native_p2p
            .as_mut()
            .unwrap()
            .no_start = true;
        let authority = f.authority()?;
        let mut operation = Box::pin(
            f.child()
                .remain_on_channel_async(&authority, 11, 2437, INTERVAL),
        );
        let mut cx = Context::from_waker(Waker::noop());
        let deadline = narf_time::Deadline::after_ms(3000);
        let mut after_ack = None;
        loop {
            require(
                operation.as_mut().poll(&mut cx).is_pending(),
                "P2P ACK substituted for native START",
            )?;
            service()?;
            let observed = {
                HARNESS
                    .lock()
                    .as_ref()
                    .unwrap()
                    .1
                    .native_p2p
                    .as_ref()
                    .unwrap()
                    .activity
                    .is_some()
            };
            if observed && after_ack.is_none() {
                after_ack = Some(narf_time::Deadline::after_ms(5))
            }
            if after_ack.as_ref().is_some_and(narf_time::Deadline::expired) {
                break;
            }
            if deadline.expired() {
                return Err("P2P fixture did not reach its actual ROC ACK");
            }
            narf_scheduler::sleep_pumps::run();
        }
        let started = {
            HARNESS
                .lock()
                .as_ref()
                .unwrap()
                .1
                .native_p2p
                .as_ref()
                .unwrap()
                .activity
                .is_some()
        };
        require(
            started && f.source.count(55) == 0,
            "P2P pending receipt fixture never reached actual ROC",
        )?;
        inject_management(1, 1);
        drop(operation);
        drop(authority);
        pump(&f)?;
        let (tx, retired) = {
            let slot = HARNESS.lock();
            let p = slot.as_ref().unwrap().1.native_p2p.as_ref().unwrap();
            (p.tx.len(), p.retired)
        };
        require(
            tx == 0 && retired <= 1 && f.source.count(55) == 0 && f.source.count(59) == 0,
            "P2P dropped pending START published data/event or replayed REMOVE",
        )?;
        let state = f
            .device()
            .state
            .try_lock()
            .ok_or("P2P dropped waiter retained blocked native work")?;
        require(
            !state.hardware.p2p_granted(2437)
                && (state.hardware.is_failed() || !state.hardware.p2p_started()),
            "P2P dropped waiter lost retained physical cleanup",
        )?;
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/p2p",
    smoke_iwl_p2p_command_ack_cannot_replace_actual_start_and_dropped_roc_keeps_cleanup
);

fn smoke_iwl_p2p_raw_band_link_copy_epoch_and_original_filter_source_fail_closed() -> TestResult {
    check(|| {
        let mut f = Fixture::new(None)?;
        f.create()?;
        f.register()?;
        f.start()?;
        f.roc(17)?;
        for (band, link) in [(0, 1), (2, 1), (1, 0), (1, 2)] {
            inject_management(band, link)
        }
        pump(&f)?;
        require(
            f.source.count(59) == 0,
            "P2P wrong RFH band/link reached original filter",
        )?;
        inject_management(1, 1);
        pump(&f)?;
        require(f.source.count(59) == 1, "P2P current physical copy missing")?;
        inject_management(1, 1);
        f.source.retire_on_check.store(true, Ordering::Release);
        pump(&f)?;
        require(
            f.source.count(59) == 1,
            "P2P preparation callback revived a retired original source",
        )?;
        let state = f
            .device()
            .state
            .try_lock()
            .ok_or("P2P source-close native work not terminal")?;
        require(
            !state.hardware.p2p_granted(2437),
            "P2P source retirement preserved RF emission grant",
        )?;
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/p2p",
    smoke_iwl_p2p_raw_band_link_copy_epoch_and_original_filter_source_fail_closed
);

fn smoke_iwl_p2p_public_primary_roles_protected_frames_and_host_policy_do_not_invent_authority(
) -> TestResult {
    check(|| {
        let mut f = Fixture::new(None)?;
        require(
            f.device().p2p_interface_types() == [10] && f.device().async_control_interfaces(),
            "P2P device-only role advertisement",
        )?;
        {
            let authority = f.parent_authority()?;
            for mode in [8, 9] {
                require(
                    run(
                        Box::pin(f.device().new_control_interface_async(
                            &authority,
                            "p2p-iwl",
                            mode,
                            Some(NODE),
                        )),
                        service,
                    )?
                    .is_err(),
                    "P2P DEVICE-only frontend invented CLIENT/GO",
                )?;
            }
        }
        f.create()?;
        f.start()?;
        f.roc(19)?;
        require(
            f.device().set_iftype(3) == Err(WirelessError::Busy)
                && matches!(
                    run(Box::pin(f.device().scan(scan_request())), service)?,
                    Err(WirelessError::Busy)
                ),
            "P2P active owner did not serialize original parent AP/scan",
        )?;
        let before = {
            HARNESS
                .lock()
                .as_ref()
                .unwrap()
                .1
                .native_p2p
                .as_ref()
                .unwrap()
                .tx
                .len()
        };
        require(
            f.frame(20, true).is_err(),
            "P2P device accepted protected management without native peer/key owner",
        )?;
        let after = {
            HARNESS
                .lock()
                .as_ref()
                .unwrap()
                .1
                .native_p2p
                .as_ref()
                .unwrap()
                .tx
                .len()
        };
        require(
            before == after,
            "P2P rejected protected frame still published native DATA",
        )?;
        f.stop()?;
        native_state(&f)?;
        f.start()?;
        let mut domain = policy();
        domain.rules[0].flags = narf_wireless::reg::RegFlags::NO_IR;
        f.guard.policy_db.install(domain);
        let authority = f.authority()?;
        require(
            run(
                Box::pin(
                    f.child()
                        .remain_on_channel_async(&authority, 21, 2437, INTERVAL),
                ),
                service,
            )?
            .is_err(),
            "P2P host NO_IR was replaced by actual firmware role/count metadata",
        )?;
        let (tx, live) = {
            let slot = HARNESS.lock();
            let p = slot.as_ref().unwrap().1.native_p2p.as_ref().unwrap();
            (p.tx.len(), p.activity.is_some())
        };
        require(
            tx == after && !live,
            "P2P host refusal still opened native radiation",
        )?;
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/p2p",
    smoke_iwl_p2p_public_primary_roles_protected_frames_and_host_policy_do_not_invent_authority
);
