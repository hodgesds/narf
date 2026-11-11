//! API77 DEVICE conversations use the actual original publication, child
//! controls and posted TFH/RFH bytes. The inert peer grants no host state.
use super::*;
use narf_capabilities::Invoke;
use narf_net::netlink_generic::DeferredReplySink;
use narf_wireless::ap_control::RadioControlAuthority;
pub(super) const NODE: [u8; 6] = [2, 0x77, 9, 8, 7, 6];
const PEER: [u8; 6] = [2, 0x77, 1, 3, 5, 7];
fn require(value: bool, reason: &'static str) -> Result<(), &'static str> {
    value.then_some(()).ok_or(reason)
}
fn word(b: &[u8], n: usize) -> u32 {
    u32::from_le_bytes(b[n..n + 4].try_into().unwrap())
}
fn half(b: &[u8], n: usize) -> u16 {
    u16::from_le_bytes(b[n..n + 2].try_into().unwrap())
}
pub(super) fn profile(image: &mut Vec<u8>, versions: &mut Vec<u8>) -> Result<(), &'static str> {
    let parsed = super::super::super::parse_ucode(image).map_err(|_| "P2P Gen2 fixture image")?;
    let caps = parsed.api.capabilities[1] | 1 << 22;
    let api = parsed.api.api_changes[1] | 1 << 27;
    let mut body = 1u32.to_le_bytes().to_vec();
    body.extend_from_slice(&caps.to_le_bytes());
    tlv(image, 30, &body);
    body[4..].copy_from_slice(&api.to_le_bytes());
    tlv(image, 29, &body);
    for (tag, count) in [(0x100u32, 15u32), (0x101, 4)] {
        tlv(image, tag, &count.to_le_bytes());
    }
    versions.extend_from_slice(&[5, 3, 1, 0, 0xfb, 3, 99, 2]);
    Ok(())
}
pub(super) struct Model {
    mac: bool,
    link: bool,
    phy: bool,
    bound: bool,
    active: bool,
    station: bool,
    queue: bool,
    power: u8,
    activity: Option<u32>,
    started: bool,
    read: u16,
    write: u16,
    tx: usize,
}
impl Model {
    pub(super) fn new() -> Self {
        Self {
            mac: false,
            link: false,
            phy: false,
            bound: false,
            active: false,
            station: false,
            queue: false,
            power: 0,
            activity: None,
            started: false,
            read: 0,
            write: 0,
            tx: 0,
        }
    }
    pub(super) fn command(
        &mut self,
        g: u8,
        c: u8,
        b: &[u8],
        fw: &mut model::Firmware,
    ) -> Result<Option<Vec<u8>>, &'static str> {
        let mut reply = Vec::new();
        match (g, c) {
            (3, 8) if b.len() == 52 && word(b, 0) == 1 => {
                require(
                    word(b, 8) == 6
                        && b[12..18] == NODE
                        && word(b, 20) == 2
                        && b[26..].iter().all(|v| *v == 0),
                    "P2P Gen2 MAC1 DEVICE/filter identity",
                )?;
                match word(b, 4) {
                    1 => {
                        require(!self.mac, "P2P Gen2 duplicate MAC")?;
                        self.mac = true;
                        self.power = 0
                    }
                    3 => {
                        require(
                            !self.link && !self.phy && !self.station && !self.queue,
                            "P2P Gen2 MAC removed before dependencies",
                        )?;
                        self.mac = false
                    }
                    _ => return Err("P2P Gen2 MAC action"),
                }
            }
            (3, 9) if b.len() == 208 && word(b, 4) == 1 => {
                require(
                    self.mac && word(b, 8) == 1 && b[16..22] == NODE && word(b, 36) == 0,
                    "P2P Gen2 LINK1 physical MAC1/no CCK",
                )?;
                match (word(b, 0), word(b, 24), word(b, 28)) {
                    (1, 0, 0) => {
                        require(!self.link, "P2P Gen2 duplicate LINK")?;
                        self.link = true
                    }
                    (2, 0, 0) => {
                        require(
                            self.phy && word(b, 12) == 1,
                            "P2P Gen2 bind lacks PHY1 receipt",
                        )?;
                        self.bound = true
                    }
                    (2, 3, 1) => {
                        require(
                            self.bound && word(b, 12) == 1 && word(b, 40) == 0x15,
                            "P2P Gen2 active LINK preceded binding/rates",
                        )?;
                        self.active = true
                    }
                    (2, 3, 0) => {
                        require(
                            self.activity.is_none()
                                && !self.station
                                && !self.queue
                                && word(b, 12) == u32::MAX,
                            "P2P Gen2 unbind preceded terminal STA/queue",
                        )?;
                        self.bound = false;
                        self.active = false
                    }
                    (3, 0, 0) => {
                        require(
                            !self.phy && !self.bound && !self.station && !self.queue,
                            "P2P Gen2 LINK remove before PHY/STA",
                        )?;
                        self.link = false
                    }
                    _ => return Err("P2P Gen2 LINK action/mask"),
                }
            }
            (1, 0x9f) if self.mac => {
                require(b.len() == 44, "P2P Gen2 power v5 extent")?;
                if word(b, 0) == 2 {
                    require(
                        b[4..16] == [0; 12]
                            && b[36..] == [0; 8]
                            && (0..10).all(|i| half(b, 16 + 2 * i) == 80 + i as u16),
                        "P2P Gen2 actual tag8 chain limits",
                    )?;
                    self.power = 1;
                } else {
                    require(
                        word(b, 0) == 1
                            && self.power == 1
                            && word(b, 4) == 0
                            && half(b, 8) == 64
                            && b[10..].iter().all(|v| *v == 0),
                        "P2P Gen2 requires exact device ceiling after SAR, never AP SET_LINK",
                    )?;
                    self.power = 2;
                }
            }
            (1, 8) if b.len() >= 8 && word(b, 0) == 1 => {
                let tail = if b.len() == 40 { 24 } else { 20 };
                require(
                    self.link
                        && b.len() == tail + 16
                        && self.power == 2
                        && word(b, 8) == 0
                        && word(b, 12) == 0
                        && if tail == 24 {
                            word(b, 16) == 1 && b[20..24] == [1, 0, 0, 0]
                        } else {
                            b[16..20] == [1, 1, 0, 0]
                        }
                        && word(b, tail) == 3
                        && word(b, tail + 4) == 0x2806
                        && b[tail + 8..].iter().all(|v| *v == 0),
                    "P2P Gen2 actual legacy PHY1/RX antenna layout",
                )?;
                match word(b, 4) {
                    1 => {
                        require(!self.phy, "P2P Gen2 duplicate PHY")?;
                        self.phy = true
                    }
                    3 => {
                        require(
                            !self.bound && !self.active && !self.station && !self.queue,
                            "P2P Gen2 PHY removed while referenced",
                        )?;
                        self.phy = false
                    }
                    _ => return Err("P2P Gen2 PHY action"),
                }
            }
            (1, 0x18) if b.len() == 48 && b[16] == 14 => {
                let mut expected = [0; 48];
                expected[2..4].copy_from_slice(&u16::MAX.to_le_bytes());
                expected[4] = 1;
                expected[8..14].fill(255);
                expected[16] = 14;
                expected[35] = 1;
                require(
                    b == expected && self.active && self.phy && !self.station,
                    "P2P Gen2 BCAST14/MAC1 is not AUX/MLD STA_CFG",
                )?;
                self.station = true;
                reply = 1u32.to_le_bytes().to_vec();
            }
            (5, 0x17) if self.mac && b.len() == 36 && word(b, 4) == 1 << 14 => {
                require(
                    b[8] == 16 && b[9..16] == [0; 7],
                    "P2P Gen2 actual BCAST TID16",
                )?;
                match word(b, 0) {
                    0 => {
                        require(
                            self.station
                                && !self.queue
                                && word(b, 16) == 4
                                && b[20..28] != [0; 8]
                                && b[28..36] != [0; 8],
                            "P2P Gen2 queue needs received station and DMA",
                        )?;
                        self.queue = true;
                        self.read = 0;
                        self.write = 0
                    }
                    1 => {
                        require(
                            self.activity.is_none() && self.queue && self.read == self.write,
                            "P2P Gen2 TVQM removed before native session/flush",
                        )?;
                        self.queue = false
                    }
                    _ => return Err("P2P Gen2 TVQM action"),
                }
                reply = vec![1, 0, 0, 0, 0, 0, 0, 0];
            }
            (3, 5) if self.mac => {
                require(
                    b.len() == 24 && word(b, 0) == 1 && matches!(word(b, 8), 2 | 3),
                    "P2P Gen2 SESSION1 exact MAC1/conf",
                )?;
                match word(b, 4) {
                    1 => {
                        require(
                            self.active
                                && self.phy
                                && self.station
                                && self.queue
                                && self.power == 2
                                && self.activity.is_none()
                                && word(b, 12) == 4882
                                && b[16..] == [0; 8],
                            "P2P Gen2 SESSION1 preceded exact native dependencies",
                        )?;
                        self.activity = Some(word(b, 8));
                        self.started = true;
                        fw.inject(0xc1, 0, 0x8000, &management(1));
                        let mut n = vec![0; 16];
                        n[0] = 1;
                        n[4] = 1;
                        n[8] = 1;
                        n[12..].copy_from_slice(&word(b, 8).to_le_bytes());
                        fw.inject(0xfb, 3, 0x8000, &n);
                        fw.inject(0xc1, 0, 0x8000, &management(1));
                    }
                    3 => {
                        require(
                            self.activity == Some(word(b, 8)) && b[12..] == [0; 12],
                            "P2P Gen2 SESSION REMOVE original MAC/config",
                        )?;
                        self.activity = None;
                        self.started = false
                    }
                    _ => return Err("P2P Gen2 SESSION action"),
                }
            }
            (5, 2) if self.mac => {
                require(
                    b.len() == 20 && b[12..16] == [0, 0, 1, 0] && self.activity.is_none(),
                    "P2P Gen2 actual EMPTY sync1 prefix after SESSION end",
                )?;
                let mut marker = vec![8, 0, 0, 0, 0, 0, 1, 0];
                marker.extend_from_slice(&b[16..20]);
                fw.inject(0xff, 5, 0x8000, &marker);
            }
            (1, 0x1e) if self.mac => {
                require(
                    b == [14, 0, 0, 0, 255, 255, 0, 0] && self.activity.is_none(),
                    "P2P Gen2 flush original BCAST14",
                )?;
                reply = vec![0; 132];
                reply[0] = 14;
                reply[2] = u8::from(self.queue);
                if self.queue {
                    reply[4] = 16;
                    reply[6] = 1;
                    reply[8..10].copy_from_slice(&self.read.to_le_bytes());
                    reply[10..12].copy_from_slice(&self.write.to_le_bytes());
                    self.read = self.write
                }
            }
            (1, 0x19) if b == [14, 0, 0, 0] => {
                require(
                    self.station && !self.queue && self.activity.is_none(),
                    "P2P Gen2 REMOVE_STA before terminal queue",
                )?;
                self.station = false
            }
            (3, 0xa | 0xb | 0xc | 0xe) if self.mac => {
                return Err("P2P Gen2 aliased MLD STA/AUX/hotspot ROC")
            }
            _ => return Ok(None),
        }
        Ok(Some(reply))
    }
    pub(super) fn transmit(
        &mut self,
        p: &model::Published,
        fw: &mut model::Firmware,
    ) -> Result<(), &'static str> {
        let b = &p.bytes;
        require(
            self.mac
                && self.link
                && self.active
                && self.station
                && self.queue
                && self.started
                && self.activity.is_some()
                && p.queue == 1
                && b.len() >= 48
                && b[0] == 0x1c
                && half(b, 6) == 12 << 8
                && word(b, 8) == 3
                && word(b, 20) == 0x400d,
            "P2P Gen2 TX9 lacks current native SESSION/BCAST/OFDM6",
        )?;
        let f = &b[24..];
        require(
            f.len() == usize::from(half(b, 4))
                && f[0] == 0xd0
                && f[1] & 0xc7 == 0
                && f[10..16] == NODE,
            "P2P Gen2 actual TX9 physical header",
        )?;
        self.tx += 1;
        self.read = p.pointer;
        self.write = p.pointer;
        fw.tx_complete(p.queue, p.pointer);
        Ok(())
    }
}
fn management(mac: u8) -> Vec<u8> {
    let mut b = vec![0; 48 + 26];
    b[..2].copy_from_slice(&26u16.to_le_bytes());
    b[7] = 0x40 | mac;
    b[12] = 3;
    b[32] = 40;
    b[34] = 1;
    b[48] = 0xd0;
    b[52..58].copy_from_slice(&NODE);
    b[58..64].copy_from_slice(&PEER);
    b[64..70].copy_from_slice(&PEER);
    b[72..].copy_from_slice(&[4, 9]);
    b
}
#[derive(Debug)]
struct Source {
    lifetime: narf_net::native_emission::ProviderLifetime,
    children: IrqSafeSpinLock<Vec<narf_net::AdminHandle>>,
    events: IrqSafeSpinLock<Vec<u8>>,
}
impl Source {
    fn new() -> Self {
        Self {
            lifetime: Default::default(),
            children: IrqSafeSpinLock::new(Vec::new()),
            events: IrqSafeSpinLock::new(Vec::new()),
        }
    }
    fn count(&self, c: u8) -> usize {
        self.events.lock().iter().filter(|v| **v == c).count()
    }
}
impl DeferredReplySink for Source {
    fn current(&self) -> bool {
        self.lifetime.observe().current()
    }
    fn native_source(&self) -> Option<narf_net::native_emission::Lifetime> {
        Some(self.lifetime.observe())
    }
    fn retain_control_admin(&self, a: narf_net::AdminHandle) -> Result<(), i32> {
        if !self.current() {
            return Err(1);
        }
        self.children.lock().push(a);
        Ok(())
    }
    fn control_admin(&self, name: &str, namespace: u64) -> Option<narf_net::AdminHandle> {
        if !self.current() {
            return None;
        }
        let children = { self.children.lock().clone() };
        children
            .into_iter()
            .find(|a| a.authorize_interface(name, namespace).is_ok())
    }
    fn deliver(&self, b: Vec<u8>) -> Result<(), i32> {
        if !self.current() {
            return Err(1);
        }
        if let Some(c) = b.get(16) {
            self.events.lock().push(*c)
        }
        Ok(())
    }
}
struct Fixture {
    h: Harness,
    child: Option<Arc<dyn WirelessNetIface>>,
    source: Arc<Source>,
    admin: narf_net::AdminHandle,
    _daemon: Cap<narf_net::StackDaemon, Invoke>,
}
impl Fixture {
    #[inline(never)]
    fn new() -> Result<Self, &'static str> {
        let h = Harness::version_profile(false, false, 8, 4)?;
        // Primary CLIENT/GO (8/9) beside the DEVICE child (10), as iwlmvm
        // advertises them (mac80211.c iwl_mvm_mac_setup_register).
        require(
            h.device.supports_virtual_interfaces() && h.device.p2p_interface_types() == [8, 9, 10],
            "P2P Gen2 factual DEVICE subset absent",
        )?;
        let original = h
            .device
            .p2p
            .registration()
            .ok_or("P2P Gen2 original returned publication receipt absent")?;
        let daemon = Cap::<narf_net::StackDaemon, Invoke>::bootstrap();
        let admin = narf_net::stack::control_registered(&narf_net::StackAttach {
            iface: original.parent,
            daemon,
        })
        .map_err(|_| "P2P Gen2 original parent Admin")?
        .admin;
        Ok(Self {
            h,
            child: None,
            source: Arc::new(Source::new()),
            admin,
            _daemon: daemon,
        })
    }
    fn create(&mut self) -> Result<(), &'static str> {
        let iface: Arc<dyn WirelessNetIface> = self.h.device.clone();
        let link = narf_net::iface::lookup(iface.name()).ok_or("P2P Gen2 parent netdev absent")?;
        let authority = RadioControlAuthority::bind(
            self.admin.clone(),
            &iface,
            0,
            link.ifindex,
            self.source.clone(),
        )
        .and_then(RadioControlAuthority::reserve)
        .map_err(|_| "P2P Gen2 parent original source")?;
        let child =
            run(self
                .h
                .device
                .new_control_interface_async(&authority, "p2p-mvm", 10, Some(NODE)))?
            .map_err(|_| "P2P Gen2 actual NEW child")?;
        require(
            child.current_iftype() == 10
                && !child.link_up()
                && narf_net::iface::lookup(child.name()).is_none(),
            "P2P Gen2 DEVICE invented IFINDEX/UP",
        )?;
        self.child = Some(child);
        Ok(())
    }
    fn child(&self) -> &Arc<dyn WirelessNetIface> {
        self.child.as_ref().unwrap()
    }
    fn authority(&self) -> Result<RadioControlAuthority, &'static str> {
        let child = self.child();
        let wdev = narf_wireless::registry::control_for(child.as_ref())
            .ok_or("P2P Gen2 actual WDEV absent")?;
        let admin = self
            .source
            .control_admin(child.name(), 0)
            .ok_or("P2P Gen2 original socket child Admin absent")?;
        RadioControlAuthority::bind_wdev(admin, child, 0, wdev.id(), self.source.clone())
            .and_then(RadioControlAuthority::reserve)
            .map_err(|_| "P2P Gen2 original child source")
    }
    fn start(&self) -> Result<(), &'static str> {
        let a = self.authority()?;
        run(self.child().start_p2p_device_async(&a))?.map_err(|_| "P2P Gen2 native START")
    }
    fn roc(&self, cookie: u64) -> Result<(), &'static str> {
        let a = self.authority()?;
        run(self.child().remain_on_channel_async(&a, cookie, 2412, 5000))?
            .map_err(|_| "P2P Gen2 native SESSION1 ROC")
    }
    fn register(&self) -> Result<(), &'static str> {
        let a = self.authority()?;
        run(self
            .child()
            .register_mgmt_frame_radio_async(&a, 0xd0, &[4, 9]))?
        .map_err(|_| "P2P Gen2 original filter")
    }
    fn frame(&self, cookie: u64) -> Result<bool, &'static str> {
        let a = self.authority()?;
        let mut f = management(1)[48..].to_vec();
        f[4..10].copy_from_slice(&PEER);
        f[10..16].copy_from_slice(&NODE);
        run(self.child().mgmt_tx_radio_async(
            &a,
            cookie,
            narf_wireless::MgmtTxRequest {
                frequency_mhz: 2412,
                frame: f,
                offchannel_ok: false,
                duration: 0,
                no_cck: true,
            },
        ))?
        .map_err(|_| "P2P Gen2 native management status")
    }
    fn pump(&self) -> Result<(), &'static str> {
        let deadline = narf_time::Deadline::after_ms(3000);
        loop {
            self.h.actor.lock().serve()?;
            self.h.device.step(None);
            let idle = self.h.device.state.try_lock().is_some_and(|mut s| {
                s.owner.as_mut().is_some_and(|o| {
                    let hw = o.p2p_hardware();
                    !hw.has_pending_rx() && !hw.p2p_needs_retirement()
                })
            });
            if idle {
                return Ok(());
            }
            if deadline.expired() {
                return Err("P2P Gen2 retained native pump did not finish");
            }
            narf_scheduler::sleep_pumps::run();
        }
    }
    fn stop(&self) -> Result<(), &'static str> {
        let a = self.authority()?;
        run(self.child().stop_p2p_device_async(&a))?.map_err(|_| "P2P Gen2 terminal STOP")
    }
    fn delete(&mut self) -> Result<(), &'static str> {
        let child = self.child().clone();
        let a = self.authority()?;
        let receipt =
            run(child.delete_control_interface_async(&a))?.map_err(|_| "P2P Gen2 terminal DEL")?;
        require(
            receipt.current(),
            "P2P Gen2 DEL lost original typed identity",
        )?;
        drop(receipt);
        drop(a);
        require(
            narf_wireless::registry::control_for(child.as_ref()).is_none(),
            "P2P Gen2 DEL leaked metadata",
        )?;
        self.child = None;
        Ok(())
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.h.actor.lock().release();
        let _ = run(self.h.device.p2p.stop_retained());
        if self.h.device.p2p.active() {
            return;
        }
        if let Some(child) = self.child.take() {
            child.release_control_metadata()
        }
        narf_wireless::registry::unregister(self.h.device.name());
        if let Some(original) = self.h.device.p2p.registration() {
            narf_net::registry().unregister_for_handle(&original.parent);
        }
    }
}
fn codec_profiles() -> Result<(), &'static str> {
    let mut bytes = image();
    let mut versions = super::super::super::parse_ucode(&bytes)
        .unwrap()
        .api
        .commands
        .to_vec();
    ap_tests::profile(&mut bytes, &mut versions)?;
    profile(&mut bytes, &mut versions)?;
    tlv(&mut bytes, 48, &versions);
    let parsed = super::super::super::parse_ucode(&bytes).unwrap();
    let nvm = super::super::super::station_api::Nvm::parse(4, &nvm())?;
    for ultra in [false, true] {
        let mut api = parsed.api.clone();
        if ultra {
            api.capabilities[1] |= 1 << 16
        } else {
            api.capabilities[1] &= !(1 << 16)
        }
        let adapter = super::super::super::p2p_gen2_wire::Adapter::read(&api, &nvm)?;
        let (body, rlc) = adapter.phy(
            1,
            super::super::super::native_band::Channel::legacy(1).unwrap(),
        )?;
        let tail = if ultra { 24 } else { 20 };
        require(
            body.len() == tail + 16
                && word(&body, 0) == 1
                && word(&body, 4) == 1
                && word(&body, tail) == 3
                && word(&body, tail + 4) == 0x2806
                && rlc.is_none(),
            "P2P Gen2 raw PHY/RX contract lost original antenna or channel extent",
        )?;
        let station = adapter.broadcast();
        require(
            station[16] == 14
                && station[35] == 1
                && word(&station, 4) == 1
                && adapter.added(&[1, 0, 0, 0]).is_ok()
                && adapter.added(&[0, 0, 0, 0]).is_err(),
            "P2P Gen2 BCAST/native status became a metadata grant",
        )?;
        for missing in 0..3 {
            let mut bad = api.clone();
            match missing {
                0 => bad.num_stations = None,
                1 => bad.api_changes[1] &= !(1 << 27),
                _ => bad.capabilities[1] &= !(1 << 22),
            }
            require(
                super::super::super::p2p_gen2_wire::Adapter::read(&bad, &nvm).is_err(),
                "P2P Gen2 absent factual counts/band/session capability admitted",
            )?;
        }
    }
    Ok(())
}
fn native() -> Result<(), &'static str> {
    codec_profiles()?;
    let _platform = ap_tests::Platform::new();
    let mut f = Fixture::new()?;
    f.create()?;
    f.register()?;
    f.start()?;
    f.roc(71)?;
    require(
        f.source.count(55) == 1 && f.source.count(59) == 0,
        "P2P Gen2 ACK/same-drain copy replaced native START",
    )?;
    {
        let mut a = f.h.actor.lock();
        a.inject(0xc1, 0, 0x8000, &management(0));
        a.inject(0xc1, 0, 0x8000, &management(1));
    }
    f.pump()?;
    require(
        f.source.count(59) == 1 && f.frame(72)?,
        "P2P Gen2 physical MAC1 RX/TX9 owner",
    )?;
    require(
        f.h.device.set_iftype(3) == Err(WirelessError::Busy),
        "P2P Gen2 parent AP did not serialize native owner",
    )?;
    let request = run(f.h.device.p2p_power_request(NODE, 2412))??;
    require(
        request.name.contains("p2p-device-") && !request.name.contains("ap-power"),
        "P2P Gen2 qualification aliased tag7",
    )?;
    let before = f.h.actor.lock().commands.len();
    for tag in [1, 6, 7] {
        let mut bytes = power();
        bytes[8..40].copy_from_slice(&request.binding);
        bytes[40..46].copy_from_slice(&NODE);
        bytes[46] = tag;
        let wrong = asset("narf-test/mvm-p2p/wrong-power-tag", &bytes, true)?;
        require(
            super::super::super::mvm_boot::P2pPowerPlan::new(
                wrong,
                request.binding,
                NODE,
                1,
                &domain(),
            )
            .is_err(),
            "P2P Gen2 station/scan/AP record substituted for tag8",
        )?;
    }
    let unchanged = { before == f.h.actor.lock().commands.len() };
    require(
        unchanged,
        "P2P Gen2 rejected metadata still published a native power command",
    )?;
    f.stop()?;
    require(f.source.count(56) == 1, "P2P Gen2 terminal expiry absent")?;
    {
        let a = f.h.actor.lock();
        let m = a.native_p2p.as_ref().unwrap();
        require(
            !m.mac && !m.link && !m.phy && !m.station && !m.queue && m.tx == 1,
            "P2P Gen2 STOP missed native dependency receipts",
        )?;
    }
    f.start()?;
    f.roc(73)?;
    run(f.h.device.system_suspend())??;
    let stopped = {
        let mut state =
            f.h.device
                .state
                .try_lock()
                .ok_or("P2P Gen2 suspended State still owned")?;
        state
            .owner
            .as_mut()
            .is_some_and(|owner| !owner.p2p_hardware().p2p_started())
    };
    require(
        f.h.device.suspended.load(Ordering::Acquire) && stopped && f.frame(74).is_err(),
        "P2P Gen2 suspend did not retire retained native/copy owner before transport stop",
    )?;
    f.delete()?;
    Ok(())
}
fn smoke_iwl_p2p_gen2_original_publication_session1_physical_mac_and_terminal_receipts(
) -> TestResult {
    check(native)
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/p2p/gen2",
    smoke_iwl_p2p_gen2_original_publication_session1_physical_mac_and_terminal_receipts
);
fn held() -> Result<(), &'static str> {
    let _platform = ap_tests::Platform::new();
    let mut f = Fixture::new()?;
    f.create()?;
    f.register()?;
    f.start()?;
    f.h.actor.lock().hold_phy = Some(11);
    let authority = f.authority()?;
    let mut roc = Box::pin(
        f.child()
            .remain_on_channel_async(&authority, 81, 2412, 5000),
    );
    let deadline = narf_time::Deadline::after_ms(3000);
    loop {
        require(
            once(roc.as_mut()).is_pending(),
            "P2P Gen2 escaped held SET_DEVICE receipt",
        )?;
        f.h.actor.lock().serve()?;
        if f.h.actor.lock().held.is_some() {
            break;
        }
        if deadline.expired() {
            return Err("P2P Gen2 exact held device receipt absent");
        }
    }
    f.source.lifetime.retire().notify();
    drop(roc);
    drop(authority);
    f.h.actor.lock().release();
    run(f.h.device.p2p.stop_retained())?
        .map_err(|_| "P2P Gen2 dropped source lost retained stop")?;
    let no_tx = {
        let a = f.h.actor.lock();
        let m = a.native_p2p.as_ref().unwrap();
        m.tx == 0 && m.activity.is_none()
    };
    require(
        no_tx && f.source.count(55) == 0 && f.source.count(59) == 0,
        "P2P Gen2 held power/source loss opened RF/copy grant",
    )?;
    Ok(())
}
fn smoke_iwl_p2p_gen2_held_global_power_source_loss_and_dropped_waiter_keep_cleanup() -> TestResult
{
    check(held)
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/p2p/gen2",
    smoke_iwl_p2p_gen2_held_global_power_source_loss_and_dropped_waiter_keep_cleanup
);
