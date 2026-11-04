use super::*;
use alloc::{boxed::Box, collections::BTreeMap, vec, vec::Vec};
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

const OWN: [u8; 6] = [2, 4, 6, 8, 10, 12];
const STA: [u8; 6] = [2, 3, 5, 7, 11, 13];
const STA2: [u8; 6] = [2, 3, 5, 7, 11, 17];

#[derive(Default)]
struct Model {
    bytes: BTreeMap<u32, u8>,
    clock: u64,
    commands: Vec<(u8, u8, u8, Vec<u8>, bool)>,
    writes: Vec<(u32, u32)>,
    fail_command: Option<usize>,
    inside: bool,
}
impl Model {
    fn get32(&self, a: u32) -> u32 {
        u32::from_le_bytes(core::array::from_fn(|i| {
            *self.bytes.get(&(a + i as u32)).unwrap_or(&0)
        }))
    }
    fn put(&mut self, a: u32, v: &[u8]) {
        for (i, b) in v.iter().enumerate() {
            self.bytes.insert(a + i as u32, *b);
        }
    }
}
impl Io for Model {
    fn read8(&mut self, a: u32) -> Result<u8, Error> {
        Ok(*self.bytes.get(&a).unwrap_or(&0))
    }
    fn read16(&mut self, a: u32) -> Result<u16, Error> {
        Ok(u16::from_le_bytes([self.read8(a)?, self.read8(a + 1)?]))
    }
    fn read32(&mut self, a: u32) -> Result<u32, Error> {
        Ok(self.get32(a))
    }
    fn write8(&mut self, a: u32, v: u8) -> Result<(), Error> {
        self.put(a, &[v]);
        Ok(())
    }
    fn write16(&mut self, a: u32, v: u16) -> Result<(), Error> {
        self.put(a, &v.to_le_bytes());
        Ok(())
    }
    fn write32(&mut self, a: u32, v: u32) -> Result<(), Error> {
        self.writes.push((a, v));
        // TSFTR_RST self-clears like a strobe.
        let v = if a == PORT_CFG { v & !TSFTR_RST } else { v };
        self.put(a, &v.to_le_bytes());
        Ok(())
    }
    fn now_us(&self) -> u64 {
        self.clock
    }
    async fn delay_us(&mut self, us: u64) {
        assert!(!self.inside, "AP wait held a current transaction");
        self.clock += us;
    }
    async fn read_ecv(&mut self) -> Result<Option<u8>, Error> {
        Ok(None)
    }
}
#[async_trait::async_trait]
impl Interface for Model {
    fn preflight(&mut self, _indirect: bool) -> Result<(), Error> {
        Ok(())
    }
    fn with_current<T>(
        &mut self,
        operation: impl FnOnce(&mut Self) -> Result<T, Error>,
    ) -> Result<T, Error> {
        self.inside = true;
        let result = operation(self);
        self.inside = false;
        result
    }
    async fn command(
        &mut self,
        category: u8,
        class: u8,
        function: u8,
        body: &[u8],
        done_ack: bool,
        admission: Option<&Admission>,
    ) -> Result<(), Error> {
        if let Some(admission) = admission {
            admission.check()?;
        }
        if self.fail_command == Some(self.commands.len()) {
            return Err(Error::Timeout);
        }
        if (category, class, function) == (1, 9, 8) {
            // Firmware applies the masked pause groups.
            for group in 0..4u32 {
                let w = |i: usize| u32::from_le_bytes(body[i * 4..i * 4 + 4].try_into().unwrap());
                let (value, mask) = (w(group as usize), w(4 + group as usize));
                let register = 0x9eb0 + 4 * group;
                let old = self.get32(register);
                self.put(register, &(old & !mask | value & mask).to_le_bytes());
            }
        }
        self.commands
            .push((category, class, function, body.to_vec(), done_ack));
        Ok(())
    }
}

fn run<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(value) = future.as_mut().poll(&mut cx) {
            return value;
        }
    }
}
fn w(body: &[u8], index: usize) -> u32 {
    u32::from_le_bytes(body[index * 4..index * 4 + 4].try_into().unwrap())
}
fn ids(model: &Model) -> Vec<(u8, u8, u8)> {
    model.commands.iter().map(|c| (c.0, c.1, c.2)).collect()
}
const CONFIG: PortConfig = PortConfig {
    beacon_interval: 100,
    dtim_period: 2,
};
fn started(model: &mut Model, admission: &Admission) -> ApController {
    let mut ap = ApController::with_identity(OWN, false);
    run(ap.initialize(model, admission)).unwrap();
    run(ap.start(model, CONFIG, admission)).unwrap();
    ap
}

fn smoke_rtw89_ap_control_vif_init_and_start_match_linux_order() -> TestResult {
    let admission = Admission::new();
    let mut model = Model::default();
    let mut ap = ApController::with_identity(OWN, false);
    run(ap.initialize(&mut model, &admission)).unwrap();
    assert_eq!(ap.phase(), Phase::Ready);
    // rtw89_mac_vif_init: pause, ROLE_MAINTAIN, JOIN_INFO, CAM, default CMAC.
    assert_eq!(
        ids(&model),
        [(1, 9, 8), (1, 8, 4), (1, 8, 0), (1, 6, 0), (1, 5, 2)]
    );
    let c = &model.commands;
    assert!(!c[0].4 && c[1..].iter().all(|c| c.4));
    assert_eq!(w(&c[1].3, 0), 1 << 8 | 2 << 13); // SELF_ROLE_AP, CREATE, WIFI_ROLE_AP
    assert_eq!(w(&c[2].3, 0) >> 24, 3 | 2 << 2 | 1 << 6); // AP_MODE, WIFI_ROLE_AP, SELF_ROLE_AP
    assert_ne!(w(&c[2].3, 0) & (1 << 8), 0); // vif dis_conn
    assert_eq!(w(&c[3].3, 2) & 7, 1 | 3 << 1); // valid, AP_MODE
    assert_eq!(w(&c[3].3, 8), 0); // MACID0, port0
    assert_ne!(w(&c[4].3, 13) & (1 << 12), 0); // AP DATA_DCM mask
                                               // Fresh port: no func_sw; AP port program bits and timings.
    let cfg = model.get32(PORT_CFG);
    assert_eq!(cfg & NET_TYPE_MASK, 3 << 10);
    assert_eq!(
        cfg & (TBTT_PROHIB_EN | BRK_SETUP | BCNTX_EN | PORT_FUNC_EN),
        TBTT_PROHIB_EN | BRK_SETUP | BCNTX_EN | PORT_FUNC_EN
    );
    assert_eq!(
        cfg & (RX_BSSID_FIT_EN | TSF_UDT_EN | TXBCN_RPT_EN | RXBCN_RPT_EN),
        0
    );
    assert_eq!(model.get32(BCN_SPACE) & 0xffff, 100);
    assert_eq!(model.bytes[&HGQ_WINDOW], 16);
    assert_eq!(model.bytes[&MD_TSFT_STMP_CTL] & 3, 3);
    assert_eq!(model.get32(TBTT_PROHIB), 200 << 16 | 2);
    assert_eq!(model.get32(BCN_EARLY) & 0xfff, 160);
    assert_eq!(model.get32(TBTT_EARLY & !3) >> 16 & 0xfff, 5);
    assert_eq!(model.get32(TBTT_AGG & !3) >> 16 >> 8 & 0xff, 1);
    // DMAC/CMAC indirect table init for MACID0.
    assert!(model.writes.contains(&(0xc04, 0x1884_0000)));
    model.commands.clear();
    let before = model.clock;
    run(ap.start(&mut model, CONFIG, &admission)).unwrap();
    assert_eq!(ap.phase(), Phase::Started);
    // func_sw ran (FUNC_EN was set): beacon_int + 1 ms wait included.
    assert!(model.clock - before >= 101_000);
    assert!(model.writes.contains(&(BCN_CNT_TMR, 0)));
    assert_eq!(model.get32(DTIM_CTRL & !3) >> 16 >> 8 & 0xff, 2);
    assert_eq!(model.get32(BCN_DROP_ALL) & 1, 0);
    // rtw89_ops_start_ap: assoc CMAC, ROLE TYPE_CHANGE, JOIN_INFO, CAM.
    assert_eq!(ids(&model), [(1, 5, 2), (1, 8, 4), (1, 8, 0), (1, 6, 0)]);
    let c = &model.commands;
    assert_eq!(w(&c[0].3, 7) & (1 << 17), 0); // AP ULDL 0
    assert_eq!(w(&c[1].3, 0) >> 10 & 7, 2); // TYPE_CHANGE
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/uapsd",
    smoke_rtw89_ap_control_vif_init_and_start_match_linux_order
);

fn smoke_rtw89_ap_control_peer_lifecycle_allocates_macid_and_cam() -> TestResult {
    let admission = Admission::new();
    let mut model = Model::default();
    let mut ap = started(&mut model, &admission);
    model.commands.clear();
    assert_eq!(run(ap.add_peer(&mut model, STA, &admission)), Ok(1));
    assert_eq!(run(ap.add_peer(&mut model, STA2, &admission)), Ok(2));
    assert_eq!(
        run(ap.add_peer(&mut model, STA, &admission)),
        Err(Error::Unsupported)
    );
    // rtw89_core_sta_link_add: pause, ROLE CREATE (AP_CLIENT), default CMAC.
    assert_eq!(ids(&model)[..3], [(1, 9, 8), (1, 8, 4), (1, 5, 2)]);
    assert_eq!(w(&model.commands[1].3, 0), 1 | 2 << 8 | 2 << 13);
    assert_eq!(model.get32(0x9eb0) & 0b110, 0);
    model.commands.clear();
    let ra = codec::ra(0xff0).unwrap();
    run(ap.associate_peer(&mut model, STA2, 7, ra, &admission)).unwrap();
    // rtw89_core_sta_link_assoc: assoc CMAC, JOIN, CAM, RA.
    assert_eq!(ids(&model), [(1, 5, 2), (1, 8, 0), (1, 6, 0), (2, 1, 0)]);
    let c = &model.commands;
    assert_eq!(w(&c[0].3, 0) & 0x7f, 2);
    assert_eq!(w(&c[1].3, 0) & 0xff, 2);
    assert_eq!(w(&c[1].3, 0) >> 24 & 3, 3); // peer AP_MODE while connected
    assert_eq!(w(&c[2].3, 1) & 0xff, 1); // addr CAM 1 (vif holds 0)
    assert_eq!(w(&c[2].3, 8) & 0xff, 2);
    assert_eq!(w(&c[2].3, 9) & 0xfff, 7);
    assert_eq!(w(&c[3].3, 0) >> 8 & 0xff, 2);
    assert_eq!(ap.peer(STA2).unwrap().addr_cam, Some(1));
    assert_eq!(
        run(ap.associate_peer(&mut model, STA, 7, ra, &admission)),
        Err(Error::Unsupported)
    );
    model.commands.clear();
    run(ap.remove_peer(&mut model, STA2, &admission)).unwrap();
    // disconnect (CMAC, JOIN NO_LINK, CAM invalid) then ROLE REMOVE.
    assert_eq!(ids(&model), [(1, 5, 2), (1, 8, 0), (1, 6, 0), (1, 8, 4)]);
    let c = &model.commands;
    assert_eq!(w(&c[1].3, 0) >> 24 & 3, 0);
    assert_eq!(w(&c[2].3, 2) & 1, 0);
    assert_eq!(w(&c[2].3, 13) & 1, 1); // vif BSSID CAM stays valid
    assert_eq!(w(&c[3].3, 0) >> 10 & 7, 1);
    // Released MACID2 / CAM1 are reused lowest-first.
    assert_eq!(run(ap.add_peer(&mut model, STA2, &admission)), Ok(2));
    assert_eq!(
        run(ap.stop(&mut model, &admission)),
        Err(Error::Unsupported)
    );
    run(ap.remove_peer(&mut model, STA, &admission)).unwrap();
    run(ap.remove_peer(&mut model, STA2, &admission)).unwrap();
    model.commands.clear();
    run(ap.stop(&mut model, &admission)).unwrap();
    assert_eq!(ap.phase(), Phase::Stopped);
    assert_eq!(ids(&model), [(1, 5, 2), (1, 8, 0), (1, 8, 4), (1, 6, 0)]);
    assert_eq!(model.get32(PORT_CFG) & PORT_FUNC_EN, 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/uapsd",
    smoke_rtw89_ap_control_peer_lifecycle_allocates_macid_and_cam
);

fn smoke_rtw89_ap_control_beacon_publication_and_fail_closed() -> TestResult {
    let admission = Admission::new();
    let mut model = Model::default();
    let mut ap = ApController::with_identity(OWN, false);
    let mut beacon = vec![0x80, 0, 0, 0];
    beacon.resize(24, 0);
    beacon.extend_from_slice(&[0; 12]);
    let tim_at = beacon.len();
    beacon.extend_from_slice(&[5, 4, 0, 2, 0, 0]);
    // Not started: refused without any command.
    run(ap.initialize(&mut model, &admission)).unwrap();
    let before = model.commands.len();
    assert_eq!(
        run(ap.publish_beacon(&mut model, &beacon, tim_at, &admission)),
        Err(Error::Unsupported)
    );
    assert_eq!(model.commands.len(), before);
    run(ap.start(&mut model, CONFIG, &admission)).unwrap();
    model.commands.clear();
    run(ap.publish_beacon(&mut model, &beacon, tim_at, &admission)).unwrap();
    assert_eq!(ids(&model), [(1, 5, 5)]);
    let body = &model.commands[0].3;
    assert_eq!(w(body, 0) >> 24, 12 | 0x80);
    assert_eq!(&body[12..], &beacon[..]);
    // A failed peer command closes admission and fails the owner.
    model.fail_command = Some(model.commands.len() + 1);
    assert!(run(ap.add_peer(&mut model, STA, &admission)).is_err());
    assert!(admission.closed());
    assert_eq!(ap.phase(), Phase::Failed);
    assert!(run(ap.publish_beacon(&mut model, &beacon, tim_at, &admission)).is_err());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/uapsd",
    smoke_rtw89_ap_control_beacon_publication_and_fail_closed
);
