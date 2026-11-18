// SPDX-License-Identifier: GPL-2.0-or-later
//! Native BE thermal cases: real Prepared/Port/Memory, source BB/LSSI/IQK and
//! current capability closures. Initial radio/peer metadata deliberately bypass
//! over-air MLME and physical boot qualification; constant NBTH curves are
//! synthetic test data, never board measurements.
use super::super::tests::{BePort, Block};
use super::*;
use crate::rtlwifi::{
    btcoex::btc::*,
    rtl8723be::{self as be, adapter, envelope, init, tests as fixture, txpower, version},
};
use alloc::{boxed::Box, vec::Vec};
use core::{
    future::Future,
    pin::pin,
    sync::atomic::{AtomicBool, AtomicU64},
    task::{Context, Poll, Waker},
};
use narf_capabilities::{Cap, Read};
use narf_firmware::FirmwareBlob;
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;
struct Rf {
    values: [u32; 256],
    selected: usize,
    writes: Vec<(u16, u32)>,
    hold: bool,
    deny: bool,
    deny_reg: Option<u16>,
}
#[derive(Clone)]
pub(crate) struct Model {
    base: BePort,
    rf: Arc<IrqSafeSpinLock<Rf>>,
}
impl Model {
    fn new() -> Self {
        Self {
            base: BePort::new(),
            rf: Arc::new(IrqSafeSpinLock::new(Rf {
                values: [0; 256],
                selected: 0,
                writes: Vec::new(),
                hold: false,
                deny: false,
                deny_reg: None,
            })),
        }
    }
    fn sample(&self, raw: u8) {
        let mut r = self.rf.lock();
        r.values[0x42] = (r.values[0x42] & !0xfc00) | (u32::from(raw) << 10);
    }
    fn word(&self, r: u16, v: u32) {
        self.base.write32(r, v).unwrap();
    }
    pub(crate) fn hold_delays(&self, hold: bool) {
        self.rf.lock().hold = hold;
    }
}
#[async_trait::async_trait]
impl Io for Model {
    fn read8(&self, r: u16) -> Result<u8, Access> {
        if self.rf.lock().deny {
            return Err(Access::Gate);
        }
        self.base.read8(r)
    }
    fn read16(&self, r: u16) -> Result<u16, Access> {
        if self.rf.lock().deny {
            return Err(Access::Gate);
        }
        self.base.read16(r)
    }
    fn read32(&self, r: u16) -> Result<u32, Access> {
        let rf = self.rf.lock();
        if rf.deny {
            return Err(Access::Gate);
        }
        if r == 0x8a0 || r == 0x8b8 {
            return Ok(rf.values[rf.selected]);
        }
        drop(rf);
        self.base.read32(r)
    }
    fn write8(&self, r: u16, v: u8) -> Result<(), Access> {
        let denied = {
            let rf = self.rf.lock();
            rf.deny || rf.deny_reg == Some(r)
        };
        if denied {
            return Err(Access::Gate);
        }
        self.base.write8(r, v)?;
        self.rf.lock().writes.push((r, u32::from(v)));
        Ok(())
    }
    fn write16(&self, r: u16, v: u16) -> Result<(), Access> {
        let denied = {
            let rf = self.rf.lock();
            rf.deny || rf.deny_reg == Some(r)
        };
        if denied {
            return Err(Access::Gate);
        }
        self.base.write16(r, v)?;
        self.rf.lock().writes.push((r, u32::from(v)));
        Ok(())
    }
    fn write32(&self, r: u16, v: u32) -> Result<(), Access> {
        let denied = {
            let rf = self.rf.lock();
            rf.deny || rf.deny_reg == Some(r)
        };
        if denied {
            return Err(Access::Gate);
        }
        let rising = r == 0x824 && v & (1 << 31) != 0 && self.base.read32(r)? & (1 << 31) == 0;
        self.base.write32(r, v)?;
        let mut rf = self.rf.lock();
        rf.writes.push((r, v));
        if r == 0x840 {
            rf.values[((v >> 20) & 255) as usize] = v & 0xfffff;
        }
        if rising {
            rf.selected = ((v >> 23) & 255) as usize;
        }
        Ok(())
    }
    fn write_bytes(&self, r: u16, v: &[u8]) -> Result<(), Access> {
        let denied = {
            let rf = self.rf.lock();
            rf.deny || rf.deny_reg == Some(r)
        };
        if denied {
            return Err(Access::Gate);
        }
        self.base.write_bytes(r, v)
    }
    async fn delay_us(&self, _us: u64) {
        let mut first = true;
        core::future::poll_fn(|cx| {
            if self.rf.lock().hold && core::mem::take(&mut first) {
                cx.waker().wake_by_ref();
                Poll::Pending
            } else {
                Poll::Ready(())
            }
        })
        .await;
    }
}
impl Port for Model {
    type Buffer = Block;
    fn authority<T>(
        &self,
        active: bool,
        op: impl FnOnce() -> Result<T, Error>,
    ) -> Result<T, Error> {
        if self.rf.lock().deny {
            return Err(Error::State);
        }
        self.base.authority(active, op)
    }
    fn allocate_packet(&self, n: usize) -> Result<Block, Error> {
        self.base.allocate_packet(n)
    }
    fn master(&self, on: bool) -> Result<(), Error> {
        self.base.master(on)
    }
    fn kick(&self, bits: u16) -> Result<(), Error> {
        self.base.kick(bits)
    }
}
struct Env {
    now: AtomicU64,
    deny: AtomicBool,
}
impl Env {
    fn new() -> Self {
        Self {
            now: AtomicU64::new(0),
            deny: AtomicBool::new(false),
        }
    }
}
impl super::super::super::super::station::Environment for Env {
    fn now_ms(&self) -> u64 {
        self.now.load(Ordering::Acquire)
    }
    fn fresh_nonce(&self) -> Option<[u8; 32]> {
        None
    }
    fn domain(
        &self,
    ) -> Result<narf_wireless::reg::RegulatoryDomain, super::super::super::super::station::Error>
    {
        let mut d = fixture::be_us_domain();
        if self.deny.load(Ordering::Acquire) {
            d.rules.clear();
        }
        Ok(d)
    }
    async fn pause(&self) {}
}
fn run<F: Future>(f: F) -> F::Output {
    let mut f = pin!(f);
    for _ in 0..1024 {
        if let Poll::Ready(v) = f.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
            return v;
        }
    }
    panic!("BE native thermal model progress bound");
}
type Native = Prepared<Model, Block>;
struct Harness {
    owner: Box<Native>,
    model: Model,
    base: Arc<envelope::Calibration>,
    firmware: crate::rtlwifi::firmware_transport::Identity,
    grant: Arc<Grant>,
    base_cap: Cap<FirmwareBlob, Read>,
    fw_cap: Cap<FirmwareBlob, Read>,
    cap: Cap<FirmwareBlob, Read>,
    env: Env,
}
fn harness() -> Result<Harness, &'static str> {
    let model = Model::new();
    let mut owner = Box::new(
        Prepared::allocate_for(
            crate::rtlwifi::prepare::Chip::Rtl8723be,
            model.clone(),
            4,
            |n| model.allocate_packet(n),
        )
        .map_err(|_| "NBTH allocation")?,
    );
    for (r, m) in super::super::super::TX_BASES.iter().zip(&owner.tx) {
        model.word(*r, m.address() as u32);
    }
    model.word(
        super::super::super::RX_BASE,
        owner.receive.as_ref().unwrap().address() as u32,
    );
    let factory = fixture::be_factory();
    let bytes = fixture::be_napc_fixture(1, 0, 80, &[(6, 20, 0, fixture::be_rising)]);
    let base_cap = Cap::bootstrap();
    let fw_cap = Cap::bootstrap();
    let cap = Cap::bootstrap();
    let base = Arc::new(
        envelope::Calibration::from_verified(&bytes, Some([1; 32]), &factory)
            .map_err(|_| "NBTH original NAPC")?
            .with_fixture_source(base_cap),
    );
    let permission = base
        .permission_for(&fixture::be_us_domain(), envelope::Operating::twenty(6))
        .map_err(|_| "NBTH original permission")?;
    let logical = fixture::provisioned();
    let adapter = adapter::Adapter::from_hardware(
        version::Version::from_registers(version::CHIP_8723B, 0).unwrap(),
        adapter::CR9346_AUTOLOAD_OK,
        0,
        &logical,
        0,
    )
    .map_err(|_| "NBTH radio facts")?;
    let radio = init::Radio {
        adapter,
        cck_high_power: false,
        chnlval: [0xc06, 0],
        receive_config: 0xf4007a0e,
        efuse: txpower::Efuse::from_logical(&logical).unwrap(),
        by_rate: txpower::ByRate::from_table(),
        iqk: None,
    };
    owner.rtl8723be = Some(Box::new((
        crate::rtlwifi::radio::factory_identity(&factory),
        radio,
    )));
    owner.rtl8723be_power = Some(permission);
    owner.rtl8723be_coex = Some(Box::new(be::coex::Owner::bind(HwPg {
        bt_exist: false,
        ant_num: 2,
        single_ant_path: 0,
        chip_type: ChipType::Rtl8723b,
        package_type: 0,
        rfe_type: 0,
        interface: ChipInterface::Pci,
    })));
    owner.packet.local = Some(factory.mac);
    owner.phase = Phase::MacConfigured;
    owner.published = true;
    let mut indices = [0u8; 20];
    for (r, v) in indices.iter_mut().enumerate() {
        *v = permission.index(r as u8);
    }
    txpower::set_indices(&model, &indices).map_err(|_| "NBTH initial exact TXAGC")?;
    model.word(0xc80, 0x40000100);
    model.word(0xc94, 0x1234567);
    model.word(0xc4c, 1 << 11);
    model.rf.lock().values[0x18] = 0xc06;
    model.word(0xe94, 0x01000000);
    model.word(0xe9c, 0);
    model.word(0xea4, 0x01000000);
    model.word(0xeac, 0);
    owner
        .start_packets()
        .map_err(|_| "NBTH actual native MAC tail")?;
    run(owner.prepare_station_peer([2, 0x11, 0x22, 0x33, 0x44, 0x55], 0xfff, 0x15, 0x421))
        .map_err(|_| "NBTH typed peer binding")?;
    run(owner.install_rtl8723be_rate_mask(
        be::h2c::Peer {
            legacy: 0xfff,
            ht: None,
            sgi20: false,
            sgi40: false,
        },
        false,
        0,
    ))
    .map_err(|_| "NBTH actual native RA binding")?;
    let facts = owner
        .rtl8723be_tracking_facts(&base)
        .map_err(|_| "NBTH actual original facts")?;
    let firmware =
        crate::rtlwifi::firmware_transport::Identity::fixture_with_source(&[0x23, 0xb7, 1], fw_cap);
    let blob = tracking::artifact(&base, firmware, facts);
    let grant = Arc::new(
        Grant::parse(base.clone(), firmware, facts, &blob, Some([2; 32]), cap)
            .map_err(|_| "NBTH exact signed grant")?,
    );
    grant
        .permission_for(&fixture::be_us_domain(), permission.operating())
        .map_err(|_| "NBTH full-dimensional coverage")?;
    owner
        .rtl8723be_install_tracking(grant.clone())
        .map_err(|_| "NBTH native install")?;
    Ok(Harness {
        owner,
        model,
        base,
        firmware,
        grant,
        base_cap,
        fw_cap,
        cap,
        env: Env::new(),
    })
}
fn check(f: impl FnOnce() -> Result<(), &'static str>) -> TestResult {
    match f() {
        Ok(()) => TestResult::Pass,
        Err(e) => TestResult::Fail(e),
    }
}
fn require(ok: bool, why: &'static str) -> Result<(), &'static str> {
    if ok {
        Ok(())
    } else {
        Err(why)
    }
}
fn smoke_be_thermal_literal_history_and_signed_unsigned_copy_order() -> TestResult {
    check(|| {
        let mut s = tracking::source::History::default();
        let u = s.observe(32, 26).ok_or("BE first actual sample")?;
        require(
            u.write && !u.lck && !u.iqk && u.average == 32 && u.cck == 23 && u.ofdm == 33,
            "BE first delta is not literal up-table3",
        )?;
        s.written(u);
        let u = s.observe(48, 26).unwrap();
        require(
            u.average == 40
                && u.lck
                && u.iqk
                && u.cck == 27
                && u.ofdm == 37
                && s.ofdm_index == 36
                && s.swing_ofdm == 37,
            "BE copied-before-software-clamp or averaged drift order",
        )?;
        let mut below = tracking::source::History {
            cck_base: 1,
            ofdm_base: 1,
            ..Default::default()
        };
        let u = below.observe(1, 63).unwrap();
        require(
            u.cck == 32 && u.ofdm == 42 && below.cck_index == 0 && below.ofdm_index == 6,
            "BE negative s8 copied to unsigned physical swing was guessed/clamped early",
        )?;
        require(
            tracking::source::matrix(33, 0, 0) == (0x4c000130, 0, 0),
            "BE literal OFDM33",
        )?;
        require(
            tracking::source::matrix(42, 0x100, 0) == (0x7f8001fe, 0, 0),
            "BE actual IQK matrix scale",
        )
    })
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723be/tracking",
    smoke_be_thermal_literal_history_and_signed_unsigned_copy_order
);
fn smoke_be_thermal_joint_record_identity_unknown_and_current_sources() -> TestResult {
    check(|| {
        let h = harness()?;
        let f = h.grant.facts();
        let blob = tracking::artifact(&h.base, h.firmware, f);
        for at in [
            0, 4, 6, 8, 12, 16, 48, 80, 112, 144, 176, 177, 184, 204, 212, 248, 284, 292,
        ] {
            let mut bad = blob.clone();
            bad[at] ^= 1;
            require(
                Grant::parse(h.base.clone(), h.firmware, f, &bad, Some([2; 32]), h.cap).is_err(),
                "BE NBTH source/shape alias",
            )?;
        }
        require(
            Grant::parse(h.base.clone(), h.firmware, f, &blob, None, h.cap).is_err(),
            "BE unsigned tracking accepted",
        )?;
        // Last raw thermal row, last OFDM rate, highest physical state. It need
        // never be observed by the current watchdog: still mandatory before RF.
        let mut missing = blob.clone();
        let at = missing.len() - 2;
        missing[at..].copy_from_slice(&i16::MAX.to_le_bytes());
        let q = Grant::parse(
            h.base.clone(),
            h.firmware,
            f,
            &missing,
            Some([2; 32]),
            h.cap,
        )
        .map_err(|_| "BE unknown record parse")?;
        require(
            q.permission_for(&fixture::be_us_domain(), f.permission().operating())
                .is_err(),
            "BE missing remote state interpolated",
        )?;
        h.cap.revoke();
        require(
            h.grant
                .permission_for(&fixture::be_us_domain(), f.permission().operating())
                .is_err(),
            "BE joint cap not current",
        )
    })
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723be/tracking",
    smoke_be_thermal_joint_record_identity_unknown_and_current_sources
);
fn smoke_be_thermal_native_watchdog_source_program_restore_and_no_txagc_alias() -> TestResult {
    check(|| {
        let mut h = harness()?;
        let original = h.grant.facts().original();
        let before = h.model.rf.lock().writes.len();
        require(
            run(h.owner.rtl8723be_dm_watchdog_qualified(60, 0, &h.env)).is_ok(),
            "BE actual source watchdog trigger",
        )?;
        require(
            h.owner
                .packet
                .be8723
                .tracking
                .as_ref()
                .unwrap()
                .history
                .trigger,
            "BE retained thermal trigger",
        )?;
        h.model.sample(32);
        require(
            run(h.owner.rtl8723be_dm_watchdog_qualified(60, 2000, &h.env)).is_ok(),
            "BE actual source sample/BBSWING",
        )?;
        require(
            h.model.read32(0xc80).unwrap() == 0x4c000130,
            "BE actual OFDM33 not programmed",
        )?;
        require(
            !h.model.rf.lock().writes[before..]
                .iter()
                .any(|(r, _)| matches!(r, 0xe00 | 0xe04 | 0xe08 | 0xe10 | 0xe14 | 0x86c)),
            "BE thermal used EE TXAGC",
        )?;
        require(
            h.grant.facts().original() == original,
            "BE original IQK backup replaced by callback state",
        )?;
        require(
            run(h.owner.rtl8723be_restore_tracking(&h.env)).is_ok(),
            "BE actual old-grant baseline restore",
        )?;
        require(
            Snapshot::read(&h.model).unwrap() == original
                && h.owner.packet.be8723.tracking.is_some(),
            "BE restore lost original program or retired joint authority",
        )
    })
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723be/tracking",
    smoke_be_thermal_native_watchdog_source_program_restore_and_no_txagc_alias
);
fn smoke_be_thermal_native_cancel_and_each_lost_source_prevent_further_effects() -> TestResult {
    check(|| {
        for which in 0..4 {
            let mut h = harness()?;
            let n = h.model.rf.lock().writes.len();
            match which {
                0 => h.cap.revoke(),
                1 => h.base_cap.revoke(),
                2 => h.fw_cap.revoke(),
                _ => {
                    h.model.rf.lock().deny = true;
                }
            }
            require(
                run(h.owner.be8723_tracking_step(0, &h.env)).is_err(),
                "BE revoked source reached native thermal",
            )?;
            require(
                h.model.rf.lock().writes.len() == n && h.owner.phase == Phase::Failed,
                "BE lost source produced native effects or recovered",
            )?;
        }
        let mut h = harness()?;
        h.model.rf.lock().hold = true;
        let original = h.grant.facts().original();
        {
            let future = h.owner.be8723_tracking_step(0, &h.env);
            let mut future = pin!(future);
            require(
                future
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending(),
                "BE held native RF read did not pend",
            )?;
        }
        let state = h.owner.packet.be8723.tracking.as_ref().unwrap();
        require(
            h.owner.phase == Phase::Failed
                && state.uncertain
                && state.grant.facts().original() == original
                && !h.owner.transmit_ready(),
            "BE cancelled calibration resumed/discarded old backups",
        )
    })
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723be/tracking",
    smoke_be_thermal_native_cancel_and_each_lost_source_prevent_further_effects
);

fn smoke_be_thermal_native_lck_bbswing_iqk_order_and_actual_rf_restore() -> TestResult {
    check(|| {
        let mut h = harness()?;
        require(
            run(h.owner.be8723_tracking_step(0, &h.env)).is_ok(),
            "BE first trigger",
        )?;
        h.model.sample(32);
        require(
            run(h.owner.be8723_tracking_step(2000, &h.env)).is_ok(),
            "BE first swing",
        )?;
        require(
            run(h.owner.be8723_tracking_step(4000, &h.env)).is_ok(),
            "BE second trigger",
        )?;
        h.model.sample(48);
        let before = h.model.rf.lock().writes.len();
        let original = h.grant.facts().original();
        require(
            run(h.owner.be8723_tracking_step(6000, &h.env)).is_ok(),
            "BE actual LCK/BBSWING/IQK native sequence",
        )?;
        let rf = h.model.rf.lock();
        let writes = &rf.writes[before..];
        let lc = writes
            .iter()
            .position(|(r, v)| *r == 0x840 && (*v >> 20) & 255 == 0xb0)
            .ok_or("BE real LCK RFb0 absent")?;
        let swing = writes
            .iter()
            .position(|(r, _)| *r == 0xa22)
            .ok_or("BE CCK BBSWING absent")?;
        let iqk = writes
            .iter()
            .position(|(r, _)| *r == 0xe48)
            .ok_or("BE actual IQK shot absent")?;
        require(
            lc < swing && swing < iqk,
            "BE callback calibration/swing order changed",
        )?;
        require(
            rf.values[0x18] == 0xc06,
            "BE LCK constant channel escaped restoration",
        )?;
        drop(rf);
        let state = h.owner.packet.be8723.tracking.as_ref().unwrap();
        require(
            state.history.lck == 40
                && state.history.iqk == 40
                && state.history.swing_ofdm == 37
                && state.matrix[0] == 0x100,
            "BE actual thermal history/IQK result absent",
        )?;
        require(
            state.grant.facts().original() == original
                && h.owner.phase == Phase::Running
                && h.model.read8(0x522).unwrap() == 0
                && h.model.read8(0x100).unwrap() & 0xc0 == 0xc0,
            "BE calibration lost original ownership/gates",
        )
    })
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723be/tracking",
    smoke_be_thermal_native_lck_bbswing_iqk_order_and_actual_rf_restore
);

fn smoke_be_thermal_native_partial_bbswing_and_current_policy_close_owner() -> TestResult {
    check(|| {
        let mut h = harness()?;
        h.env.deny.store(true, Ordering::Release);
        let n = h.model.rf.lock().writes.len();
        require(
            run(h.owner.be8723_tracking_step(0, &h.env)).is_err()
                && h.model.rf.lock().writes.len() == n,
            "BE retired host domain reached thermal hardware",
        )?;
        let mut h = harness()?;
        require(
            run(h.owner.be8723_tracking_step(0, &h.env)).is_ok(),
            "BE partial initial trigger",
        )?;
        h.model.sample(32);
        h.model.rf.lock().deny_reg = Some(0xc94);
        let original = h.grant.facts().original();
        require(
            run(h.owner.be8723_tracking_step(2000, &h.env)).is_err(),
            "BE partial CCK/OFDM program returned success",
        )?;
        let state = h.owner.packet.be8723.tracking.as_ref().unwrap();
        require(
            h.model.read32(0xc80).unwrap() == 0x4c000130
                && h.owner.phase == Phase::Failed
                && state.uncertain
                && state.expected == original
                && state.grant.facts().original() == original,
            "BE partial program rolled back/published new expected state",
        )?;
        require(
            h.model.read8(0x522).unwrap() == 0xff
                && h.model.read8(0x100).unwrap() & 0xc0 == 0
                && h.owner.published
                && !h.owner.transmit_ready(),
            "BE partial program resumed/released DMA",
        )
    })
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723be/tracking",
    smoke_be_thermal_native_partial_bbswing_and_current_policy_close_owner
);

fn smoke_be_thermal_native_rf18_mismatch_never_enters_calibration() -> TestResult {
    check(|| {
        let mut h = harness()?;
        require(
            run(h.owner.be8723_tracking_step(0, &h.env)).is_ok(),
            "BE RF18 fixture trigger",
        )?;
        h.model.sample(32);
        h.model.rf.lock().values[0x18] = 0xc0a;
        let before = h.model.rf.lock().writes.len();
        require(
            run(h.owner.be8723_tracking_step(2000, &h.env)).is_err(),
            "BE mismatched actual RF18 admitted",
        )?;
        let rf = h.model.rf.lock();
        require(
            !rf.writes[before..]
                .iter()
                .any(|(r, v)| *r == 0xa22 || (*r == 0x840 && (*v >> 20) & 255 == 0xb0))
                && h.owner.phase == Phase::Failed
                && h.owner.packet.be8723.tracking.as_ref().unwrap().uncertain,
            "BE wrong-channel source entered BBSWING/LCK or resumed",
        )
    })
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723be/tracking",
    smoke_be_thermal_native_rf18_mismatch_never_enters_calibration
);

/// Source-only shared station cases reuse this same real RF/descriptor actor.
/// The fixture's radio/peer metadata still bypasses over-air/physical proof.
pub(crate) struct StationFixture {
    pub(crate) owner: Box<Native>,
    pub(crate) model: Model,
    pub(crate) base: Arc<envelope::Calibration>,
    pub(crate) firmware: crate::rtlwifi::firmware_transport::Identity,
    pub(crate) grant: Arc<Grant>,
    pub(crate) cap: Cap<FirmwareBlob, Read>,
}
pub(crate) fn shared_station_fixture() -> Result<StationFixture, &'static str> {
    let h = harness()?;
    Ok(StationFixture {
        owner: h.owner,
        model: h.model,
        base: h.base,
        firmware: h.firmware,
        grant: h.grant,
        cap: h.cap,
    })
}
