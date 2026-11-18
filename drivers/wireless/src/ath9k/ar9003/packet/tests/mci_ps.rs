// SPDX-License-Identifier: GPL-2.0-or-later
//! RAM-only signed-format inputs; no board measurement, over-air result or
//! physical qualification is asserted. The reactive AP reads actual EDMA
//! payload/controls and supplies native status/RX descriptors. The same
//! production Radio, receipt owner, autosleep hardware and FTP code run.
use super::*;
use crate::ath9k::{ar9003, calibration::Permission, ps as station_ps, station};
use core::{
    future::Future,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    task::{Context, Poll, Waker},
};
use narf_capabilities::Read;
use narf_firmware::FirmwareBlob;
use station_ps::hardware::Raw;
use zeroize::Zeroizing;

const WA: u32 = 0x0040_4000;
type Radio<'a> = station::Radio<&'a Model, Arc<station::tests::Env>, Packet<&'a Model>>;

impl Model {
    pub(in crate::ath9k) fn ps_access<T>(
        &self,
        action: impl FnOnce() -> Result<T, Error>,
    ) -> Result<T, Error> {
        if !self.ps_bound.get() {
            return action();
        }
        let source = self.ps.borrow().clone().ok_or(Error::Access)?;
        source.invoke(|| {
            if self.ps_failed.get() {
                return Err(Error::Access);
            }
            if self.ps_sleeping.get() {
                self.ps_failed.set(true);
                ar9003::ps::hardware::awake(self, source.ar9003_wa().ok_or(Error::Access)?)?;
                self.ps_sleeping.set(false);
                self.ps_failed.set(false);
            } else if Raw::read(self, 0x7044)? & 15 != 2 {
                self.ps_failed.set(true);
                return Err(Error::State);
            }
            action()
        })
    }
    pub(in crate::ath9k) fn enter_ps(&self) -> Result<(), Error> {
        if !self.ps_bound.get() || self.ps_failed.get() {
            return Err(Error::Access);
        }
        self.mci_admit(|| {
            let source = self.ps.borrow().clone().ok_or(Error::Access)?;
            source.invoke(|| {
                self.ps_failed.set(true);
                ar9003::ps::hardware::network_sleep(
                    self,
                    source.ar9003_wa().ok_or(Error::Access)?,
                )?;
                self.ps_sleeping.set(true);
                self.ps_failed.set(false);
                Ok(())
            })
        })
    }
}
impl Raw for Model {
    fn read(&self, register: u64) -> Result<u32, Error> {
        let source = self.ps.borrow().clone().ok_or(Error::Access)?;
        source.invoke(|| self.mci_bus(|| Ok(self.reg(register))))
    }
    fn write(&self, register: u64, value: u32) -> Result<(), Error> {
        let source = self.ps.borrow().clone().ok_or(Error::Access)?;
        source.invoke(|| self.mci_bus(|| self.write_register(register, value)))
    }
    fn delay(&self, us: u64) {
        self.now.set(self.now.get().saturating_add(us));
    }
    fn wait(&self, register: u64, mask: u32, expected: u32, budget_us: u64) -> Result<(), Error> {
        if Raw::read(self, register)? & mask == expected {
            Ok(())
        } else {
            self.now.set(self.now.get().saturating_add(budget_us));
            Err(Error::Timeout)
        }
    }
}

fn report(mask: u8) -> ar9003::calib::Report {
    ar9003::calib::Report {
        frequency_mhz: 2412,
        five_ghz: false,
        rx_chainmask: mask,
        tx_chainmask: mask,
        peak_caldac: [None; 3],
        carrier_leak: None,
        default_nf: [-95; 3],
        tx_iq_cal: None,
        tx_iq_cal_enabled: false,
        tx_clcal: None,
    }
}
fn record(base: &ar9003::ps::Base) -> Vec<u8> {
    let request = base.request();
    let mut bytes = vec![0; 128];
    bytes[..8].copy_from_slice(b"N46S\x01\0\x80\0");
    bytes[8..12].copy_from_slice(&128u32.to_le_bytes());
    bytes[12..16].copy_from_slice(&[0x8c, 0x16, 0x34, 0]);
    bytes[16..48].copy_from_slice(&request.identity);
    bytes[48..54].copy_from_slice(&request.mac);
    bytes[54..58].copy_from_slice(&base.body());
    bytes[58..60].copy_from_slice(&base.limits().0.to_le_bytes());
    bytes[60..62].copy_from_slice(&12i16.to_le_bytes());
    bytes[62..64].copy_from_slice(&40i16.to_le_bytes());
    bytes[64..80].copy_from_slice(&[1, 0, 0, 4, 255, 8, 0xd0, 7, 0, 4, 1, 1, 0, 0, 0, 0]);
    bytes[80..112].copy_from_slice(&base.digest());
    bytes
}
fn qualify(model: &Model, link: &SharedMciLink) -> Result<Cap<FirmwareBlob, Read>, &'static str> {
    let f = concurrent::tests::fixture(0x0034, 2412)?;
    model.mci_pci.set(Some(Cap::bootstrap()));
    model.set(0x7044, 2);
    model.set(0x704c, 3);
    model.set(0x4004, WA);
    concurrent::tests::install(model, &f).map_err(|_| "N46A model power")?;
    let domain = narf_wireless::reg::db::snapshot().ok_or("N46S policy")?;
    let permission = Permission::from_domain_dual(&domain, 2412)
        .map_err(|_| "N46S permission")?
        .with_ceiling(f.grant.ceiling(40));
    let base = ar9003::ps::Base::new(
        0x0034,
        f.grant.clone(),
        permission,
        &report(3),
        &f.base,
        WA,
        link.lock().ready(),
    )
    .map_err(|_| "N46S actual base")?
    .ok_or("N46S missing base")?;
    let cap = Cap::bootstrap();
    let source = station_ps::Source::Verified {
        bytes: record(&base),
        signer: Some([0x46; 32]),
        cap,
    }
    .load_ar9003(base.clone())
    .map_err(|_| "N46S model record")?;
    *model.ps_base.borrow_mut() = Some(base);
    *model.ps.borrow_mut() = Some(source);
    *model.mci_power.borrow_mut() = Some(f);
    Ok(cap)
}
fn inject(model: &Model, bytes: &[u8]) {
    // Device-side automatic TIM/beacon wake preserves the software
    // NETWORK_SLEEP owner until Native explicitly forces AWAKE.
    if model.ps_sleeping.get() {
        model.set(0x7044, 2);
    }
    model.receive(false, bytes, false);
}
fn tim(peer: &station::tests::Peer, tsf: u64, unicast: bool) -> Vec<u8> {
    let mut bytes = peer.beacon();
    bytes[24..32].copy_from_slice(&tsf.to_le_bytes());
    bytes[32..34].copy_from_slice(&100u16.to_le_bytes());
    bytes.extend_from_slice(&[5, 5, 0, 2, 4, 0, if unicast { 4 } else { 0 }]);
    bytes
}
#[derive(Default)]
struct Actor {
    seen: usize,
    hold_notice: bool,
    held: bool,
    received: Vec<Vec<u8>>,
}
impl Actor {
    fn service(
        &mut self,
        model: &Model,
        peer: &mut station::tests::Peer,
    ) -> Result<(), &'static str> {
        // These are device-consumed EDMA descriptors and bytes, not the
        // driver's pending frame or a fabricated host completion receipt.
        while self.seen < model.pushed.borrow().len() {
            let desc = model.pushed.borrow()[self.seen];
            self.seen += 1;
            let word = |i: u32| model.get(desc + i * 4);
            let address = word(2);
            let length = ((word(3) >> 16) & 0xfff) as usize;
            if word(0) & 0xf00 != 0 || !(16..=2304).contains(&length) {
                return Err("N46S native QCU/length");
            }
            // SAFETY: device validates the complete published payload map.
            let frame =
                unsafe { core::slice::from_raw_parts(model.pointer(address, length), length) }
                    .to_vec();
            let (replies, held) = if frame.len() == 24 && frame[0] == 0x48 {
                if !matches!(frame[1], 1 | 0x11)
                    || frame[4..10] != station::tests::AP
                    || frame[10..16] != LOCAL
                    || frame[16..22] != station::tests::AP
                    || word(12) & 0xf00000 != 0
                    || word(13) & 0x8000 == 0
                {
                    return Err("N46S actual legacy PM Null");
                }
                peer.ps_asleep = frame[1] & 0x10 != 0;
                peer.ps_notices.push(frame);
                (Vec::new(), self.hold_notice)
            } else if frame.len() == 16 && frame[0] == 0xa4 {
                if frame[..4] != [0xa4, 0x10, 42, 0xc0]
                    || frame[4..10] != station::tests::AP
                    || frame[10..16] != LOCAL
                    || !peer.ps_asleep
                    || word(12) & 0xf00000 != 2 << 20
                    || word(13) & 0x8000 != 0
                {
                    return Err("N46S actual PS-Poll frame/type/AID/duration");
                }
                peer.ps_polls.push(frame);
                let reply = if let Some(ethernet) = peer.ps_buffered.pop_front() {
                    peer.downlink(&ethernet)?
                } else {
                    let mut null = vec![0x48, 2, 0, 0];
                    null.extend_from_slice(&LOCAL);
                    null.extend_from_slice(&station::tests::AP);
                    null.extend_from_slice(&station::tests::AP);
                    null.extend_from_slice(&[0, 0]);
                    null
                };
                (vec![reply], false)
            } else {
                peer.react(&frame)?
            };
            if held {
                self.held = true;
            } else {
                model.complete(true);
            }
            for reply in replies {
                self.received.push(reply.clone());
                inject(model, &reply);
            }
        }
        Ok(())
    }
    fn release(&mut self, model: &Model) -> Result<(), &'static str> {
        if !self.held {
            return Err("N46S missing held native control");
        }
        self.held = false;
        self.hold_notice = false;
        model.complete(true);
        Ok(())
    }
}
fn poll(
    model: &Model,
    radio: &mut Radio<'_>,
    peer: &mut station::tests::Peer,
    actor: &mut Actor,
) -> Result<Vec<Vec<u8>>, &'static str> {
    if let Some(env) = model.station_env.borrow().as_ref() {
        env.now.store(model.now.get() / 1000, Ordering::Release);
    }
    let frames = radio.poll().map_err(|_| "N46S native Radio poll")?;
    actor.service(model, peer)?;
    clear_irq(model);
    model.set(0x80, 0);
    model.set(0x8c, 0);
    model.set(0xc0, 0);
    Ok(frames)
}
fn pump(
    model: &Model,
    radio: &mut Radio<'_>,
    peer: &mut station::tests::Peer,
    actor: &mut Actor,
) -> Result<Vec<Vec<u8>>, &'static str> {
    let mut frames = Vec::new();
    for _ in 0..12 {
        frames.extend(poll(model, radio, peer, actor)?);
    }
    Ok(frames)
}
fn joined<'a>(
    model: &'a Model,
    link: SharedMciLink,
    peer: &mut station::tests::Peer,
    actor: &mut Actor,
    protected: bool,
) -> Result<Radio<'a>, &'static str> {
    // SAFETY: isolated parked register model; real coherent allocations are
    // retained through native status/RX/stop, never published to physical RF.
    let packet = unsafe { Packet::prepare(model, LOCAL, link) }.map_err(|_| "N46S EDMA prepare")?;
    let env = Arc::new(station::tests::Env {
        now: AtomicU64::new(0),
        entropy: AtomicBool::new(true),
    });
    *model.station_env.borrow_mut() = Some(env.clone());
    let mut radio = Radio::new(packet, LOCAL, -95, env.clone());
    radio.start().map_err(|_| "N46S Radio start")?;
    inject(model, &peer.beacon());
    radio.poll().map_err(|_| "N46S passive beacon")?;
    {
        let mut future = core::pin::pin!(radio.associate(
            station::tests::AP,
            station::tests::SSID,
            protected.then(|| Zeroizing::new(station::tests::PMK)),
            &[]
        ));
        let mut cx = Context::from_waker(Waker::noop());
        let mut completed = false;
        for _ in 0..512 {
            if let Poll::Ready(result) = future.as_mut().poll(&mut cx) {
                result.map_err(|_| "N46S actual association")?;
                completed = true;
                break;
            }
            actor.service(model, peer)?;
            model.now.set(env.now.load(Ordering::Acquire) * 1000);
        }
        if !completed {
            return Err("N46S native association progress");
        }
    }
    if !radio.ready() || radio.peer() != Some(station::tests::AP) {
        return Err("N46S actual association absent");
    }
    Ok(radio)
}
fn enable(
    model: &Model,
    radio: &mut Radio<'_>,
    peer: &mut station::tests::Peer,
    actor: &mut Actor,
    tsf: u64,
) -> Result<(), &'static str> {
    radio.set_power_save(true).map_err(|_| "N46S setting")?;
    pump(model, radio, peer, actor)?;
    actor.hold_notice = true;
    inject(model, &tim(peer, tsf, false));
    pump(model, radio, peer, actor)?;
    if !actor.held || model.ps_sleeping.get() || model.reg(0x8004) & 0x40000 != 0 {
        return Err("N46S slept before real PM ACK");
    }
    actor.release(model)?;
    pump(model, radio, peer, actor)?;
    if !model.ps_sleeping.get()
        || model.reg(0x7044) & 15 != 4
        || model.reg(0x4004) != WA & !0x4000
        || model.reg(0x183c) & 0x23e != 0
        || model.reg(0x80d8) != 80 << 21
        || model.reg(0xac) & 0x67000000 != 0x67000000
    {
        return Err("N46S lacked actual autosleep/timer/MCI state");
    }
    Ok(())
}
fn controls_and_data(protected: bool) -> Result<(), &'static str> {
    let _policy = crate::ath9k::ht::tests::Policy::install();
    let model = Model::new();
    let link = live_link(&model, Chip::Ar9462)?;
    qualify(&model, &link)?;
    let mut peer = station::tests::Peer::new_rates(protected, None);
    let mut actor = Actor::default();
    let mut radio = joined(&model, link, &mut peer, &mut actor, protected)?;
    if radio.power_save() != Some(false)
        || radio.ps_request() != model.ps_base.borrow().as_ref().map(|b| b.request())
    {
        return Err("N46S request/default path");
    }
    let mut up = station::tests::AP.to_vec();
    up.extend_from_slice(&LOCAL);
    up.extend_from_slice(&[8, 0]);
    up.extend_from_slice(&[0x42; 32]);
    radio.send(&up).map_err(|_| "N46S pre-PS DATA")?;
    pump(&model, &mut radio, &mut peer, &mut actor)?;
    let before = peer.replay.last_seen_pn;
    enable(&model, &mut radio, &mut peer, &mut actor, 102400)?;
    let mut down = LOCAL.to_vec();
    down.extend_from_slice(&station::tests::AP);
    down.extend_from_slice(&[8, 0]);
    down.extend_from_slice(&[0x5a; 32]);
    peer.ps_buffered.push_back(down.clone());
    inject(&model, &tim(&peer, 204800, true));
    let received = pump(&model, &mut radio, &mut peer, &mut actor)?;
    if received != vec![down] || peer.ps_polls.len() != 1 || !model.ps_sleeping.get() {
        return Err("N46S buffered native DATA/control receipt");
    }
    if protected {
        let replay = actor
            .received
            .last()
            .ok_or("N46S missing native downlink")?
            .clone();
        inject(&model, &replay);
        if !pump(&model, &mut radio, &mut peer, &mut actor)?.is_empty() {
            return Err("N46S DATA replay admitted");
        }
    }
    let wake_start = model.writes.borrow().len();
    radio.send(&up).map_err(|_| "N46S PM DATA")?;
    {
        let writes = model.writes.borrow();
        let wake = &writes[wake_start..];
        let wa = wake.iter().position(|&(r, v)| r == 0x4004 && v == WA);
        let force = wake.iter().position(|&(r, v)| r == 0x704c && v & 1 != 0);
        let sta = wake
            .iter()
            .position(|&(r, v)| r == 0x8004 && v & 0x40000 == 0);
        let dma = wake.iter().position(|&(r, _)| r == QTXDP);
        if !matches!((wa,force,sta,dma),(Some(a),Some(b),Some(c),Some(d))if a<b&&b<c&&c<d) {
            return Err("N46S source WA/ForceWake/PM-clear/native DATA order");
        }
    }
    pump(&model, &mut radio, &mut peer, &mut actor)?;
    if protected && peer.replay.last_seen_pn != before + 1 {
        return Err("N46S control consumed CCMP PN");
    }
    // Empty advertised buffer receives a real plaintext Null descriptor;
    // it grants no Ethernet delivery, key or replay receipt.
    inject(&model, &tim(&peer, 307200, true));
    if !pump(&model, &mut radio, &mut peer, &mut actor)?.is_empty() || peer.ps_polls.len() != 2 {
        return Err("N46S Null PS-Poll response");
    }
    radio.set_power_save(false).map_err(|_| "N46S disable")?;
    pump(&model, &mut radio, &mut peer, &mut actor)?;
    if model.ps_sleeping.get() || peer.ps_asleep || model.reg(0x8240) & 0x31 != 0 {
        return Err("N46S native off notice/timer retirement");
    }
    radio.stop().map_err(|_| "N46S stop")?;
    if model.master.get() || model.released.borrow().is_empty() {
        return Err("N46S native DMA retirement");
    }
    Ok(())
}
fn smoke_ath9k_ar9462_native_station_ps_actual_control_and_buffered_data() -> TestResult {
    for protected in [false, true] {
        if let Err(error) = controls_and_data(protected) {
            return TestResult::Fail(error);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/ar9003",
    smoke_ath9k_ar9462_native_station_ps_actual_control_and_buffered_data
);

fn ftp_native() -> Result<(), &'static str> {
    let _policy = crate::ath9k::ht::tests::Policy::install();
    let model = Model::new();
    let link = live_link(&model, Chip::Ar9462)?;
    qualify(&model, &link)?;
    let mut peer = station::tests::Peer::new_rates(false, None);
    let mut actor = Actor::default();
    let mut radio = joined(&model, link.clone(), &mut peer, &mut actor, false)?;
    model.now.set(model.now.get() + 1);
    gpm(&model, &link, 0, [0x0004_050c, 0x0001_0101, 0]);
    poll(&model, &mut radio, &mut peer, &mut actor)?;
    // Five actual awake periods cannot create a sleeping callback.
    for _ in 0..5 {
        model.now.set(model.now.get() + 26_000);
        poll(&model, &mut radio, &mut peer, &mut actor)?;
    }
    if link.lock().ftp_counters().0 != 0 || link.lock().btcoex.mci.stomp_ftp {
        return Err("awake time fabricated FTP sleep feedback");
    }
    enable(&model, &mut radio, &mut peer, &mut actor, 102400)?;
    for window in 0..2 {
        if window == 0 {
            model.now.set(model.now.get() + 260_000);
            poll(&model, &mut radio, &mut peer, &mut actor)?;
            if link.lock().ftp_counters().0 != 26 {
                return Err("late native sleep service invented missed FTP callbacks");
            }
        }
        if window == 1 {
            enable(&model, &mut radio, &mut peer, &mut actor, 307200)?;
            let mut invalid = LOCAL.to_vec();
            invalid.extend_from_slice(&station::tests::AP);
            invalid.extend_from_slice(&[8, 0]);
            invalid.extend_from_slice(&[0x33; 24]);
            let frame = peer.downlink(&invalid)?;
            let address = model.lp.borrow()[0];
            model.receive(false, &frame, false);
            model.put(address + 44, 5);
            pump(&model, &mut radio, &mut peer, &mut actor)?;
            model.receive(false, &frame, true);
            pump(&model, &mut radio, &mut peer, &mut actor)?;
            model.receive(false, &frame, false);
            pump(&model, &mut radio, &mut peer, &mut actor)?;
            if link.lock().ftp_counters().1 != 0 {
                return Err("FTP malformed/continuation counted");
            }
            // Native/CRC/rate-admitted DATA count is independent of the
            // station's Ethernet policy. Exactly five suppresses FTP.
            for i in 0..5 {
                let mut ethernet = LOCAL.to_vec();
                ethernet.extend_from_slice(&station::tests::AP);
                ethernet.extend_from_slice(&[8, 0]);
                ethernet.extend_from_slice(&[i; 24]);
                let frame = peer.downlink(&ethernet)?;
                inject(&model, &frame);
                if pump(&model, &mut radio, &mut peer, &mut actor)? != vec![ethernet] {
                    return Err("FTP native DATA admission");
                }
            }
            if link.lock().ftp_counters().1 != 5 {
                return Err("FTP native five-packet threshold");
            }
        }
        // Advance real worker deadlines. The old no-stomp callback can wake
        // the chip; only a due period observed under the actual N46S sleep
        // owner increments wait. Late work never catches up in a loop.
        for _ in 0..12 {
            if link.lock().ftp_counters().0 > 100 {
                break;
            }
            let wait = radio
                .coex_wait_us()
                .ok_or("FTP missing live deadline")?
                .max(1);
            model.now.set(model.now.get() + wait);
            poll(&model, &mut radio, &mut peer, &mut actor)?;
        }
        if link.lock().ftp_counters().0 <= 100 {
            return Err("real NETWORK_SLEEP periods did not reach FTP threshold");
        }
        radio
            .set_power_save(false)
            .map_err(|_| "FTP awake request")?;
        pump(&model, &mut radio, &mut peer, &mut actor)?;
        let wait = radio.coex_wait_us().ok_or("FTP awake deadline")?.max(1);
        model.now.set(model.now.get() + wait);
        poll(&model, &mut radio, &mut peer, &mut actor)?;
        // A no-stomp deadline may precede the period which adjusts FTP.
        for _ in 0..3 {
            if link.lock().ftp_counters().0 == 0 {
                break;
            }
            let wait = radio.coex_wait_us().ok_or("FTP final deadline")?.max(1);
            model.now.set(model.now.get() + wait);
            poll(&model, &mut radio, &mut peer, &mut actor)?;
        }
        if link.lock().btcoex.mci.stomp_ftp != (window == 0) || link.lock().ftp_counters() != (0, 0)
        {
            return Err("FTP native sleep/payload predicates or reset");
        }
        if window == 0 && weights(&model) != [0x0101_7d01, 0x013b_0101, 0x3b3b_0101, 0x3b3b_013b] {
            return Err("FTP feedback did not reach source LOW_FTP native weights");
        }
    }
    radio.stop().map_err(|_| "FTP native stop")?;
    Ok(())
}
fn smoke_ath9k_ar9462_mci_ftp_requires_real_network_sleep_and_native_rx() -> TestResult {
    ftp_native().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
fn cancellation_and_revocation(revoke: bool) -> Result<(), &'static str> {
    let _policy = crate::ath9k::ht::tests::Policy::install();
    let model = Model::new();
    let link = live_link(&model, Chip::Ar9462)?;
    let source = qualify(&model, &link)?;
    let mut peer = station::tests::Peer::new_rates(false, None);
    let mut actor = Actor::default();
    let mut radio = joined(&model, link.clone(), &mut peer, &mut actor, false)?;
    radio.set_power_save(true).map_err(|_| "held PS enable")?;
    pump(&model, &mut radio, &mut peer, &mut actor)?;
    actor.hold_notice = true;
    inject(&model, &tim(&peer, 102400, false));
    pump(&model, &mut radio, &mut peer, &mut actor)?;
    if !actor.held || model.ps_sleeping.get() {
        return Err("held PS notice lacks original native owner");
    }
    if revoke {
        let pushed = model.pushed.borrow().len();
        let weights = weight_writes(&model);
        source.revoke();
        actor.release(&model)?;
        if radio.poll().is_ok()
            || model.ps_sleeping.get()
            || model.pushed.borrow().len() != pushed
            || weight_writes(&model) != weights
            || !model.released.borrow().is_empty()
            || link.lock().ftp_counters().0 != 0
        {
            return Err("revoked held PS source emitted, slept, counted or freed uncertain DMA");
        }
    } else {
        // The original on-notice remains retained after an off request;
        // only its ACK can cause the corrective off notice to be emitted.
        radio
            .set_power_save(false)
            .map_err(|_| "held PS supersession")?;
        let count = model.pushed.borrow().len();
        pump(&model, &mut radio, &mut peer, &mut actor)?;
        if model.pushed.borrow().len() != count || model.ps_sleeping.get() {
            return Err("superseded held PS notice emitted or slept early");
        }
        actor.release(&model)?;
        pump(&model, &mut radio, &mut peer, &mut actor)?;
        if peer.ps_notices.len() != 2
            || peer.ps_notices[1][1] != 1
            || peer.ps_asleep
            || model.ps_sleeping.get()
            || radio.power_save() != Some(false)
        {
            return Err("held PS current off-notice did not reach real native ACK");
        }
        radio.stop().map_err(|_| "held PS stop")?;
    }
    Ok(())
}
fn smoke_ath9k_ar9462_native_ps_held_notice_supersession_and_source_loss() -> TestResult {
    for revoke in [false, true] {
        if let Err(error) = cancellation_and_revocation(revoke) {
            return TestResult::Fail(error);
        }
    }
    TestResult::Pass
}
fn record_refusals() -> Result<(), &'static str> {
    let _policy = crate::ath9k::ht::tests::Policy::install();
    let model = Model::new();
    let link = live_link(&model, Chip::Ar9462)?;
    qualify(&model, &link)?;
    let base = model.ps_base.borrow().clone().ok_or("N46S fixture base")?;
    let good = record(&base);
    for at in [0, 4, 6, 8, 12, 14, 16, 48, 54, 55, 56, 57, 64, 80, 112] {
        let mut bytes = good.clone();
        bytes[at] ^= 1;
        if (station_ps::Source::Verified {
            bytes,
            signer: Some([0x46; 32]),
            cap: Cap::bootstrap(),
        })
        .load_ar9003(base.clone())
        .is_ok()
        {
            return Err("malformed/foreign N46S record admitted");
        }
    }
    if (station_ps::Source::Verified {
        bytes: good,
        signer: None,
        cap: Cap::bootstrap(),
    })
    .load_ar9003(base.clone())
    .is_ok()
    {
        return Err("unsigned N46S record admitted");
    }
    let mut changed = report(3);
    changed.default_nf[0] -= 1;
    let revised = base
        .recalibrated(&changed)
        .map_err(|_| "N46S revised calibration")?
        .ok_or("N46S revised facts")?;
    if revised.request().identity == base.request().identity || revised.digest() == base.digest() {
        return Err("N46S ignored actual changed calibration");
    }
    let foreign = concurrent::tests::fixture(0x0036, 2412)?;
    let domain = narf_wireless::reg::db::snapshot().unwrap();
    let permission =
        Permission::from_domain_dual(&domain, 2412).map_err(|_| "N65A host permission")?;
    if ar9003::ps::Base::new(
        0x0036,
        foreign.grant,
        permission,
        &report(1),
        &foreign.base,
        WA,
        true,
    )
    .map_err(|_| "N65A disjoint source")?
    .is_some()
    {
        return Err("AR9565 borrowed N46S FTP authority");
    }
    // Losing the actual original N46A also invalidates a still-current S.
    let retained = model.ps.borrow().clone().unwrap();
    let current = narf_wireless::reg::db::get_domain().ok_or("N46S current policy")?;
    let mut blocked = current.clone();
    blocked.rules[0].flags |= narf_wireless::reg::RegFlags::NO_IR;
    narf_wireless::reg::db::set_domain(blocked);
    let mut policy_entered = false;
    let refused = retained
        .invoke(|| {
            policy_entered = true;
            Ok(())
        })
        .is_err();
    narf_wireless::reg::db::set_domain(current);
    if !refused || policy_entered {
        return Err("N46S ignored original current occupied-span policy");
    }
    model.mci_power.borrow().as_ref().unwrap().cap.revoke();
    let mut entered = false;
    if retained
        .invoke(|| {
            entered = true;
            Ok(())
        })
        .is_ok()
        || entered
    {
        return Err("N46S bypassed revoked actual base grant");
    }
    Ok(())
}
fn smoke_ath9k_ar9462_ps_source_format_and_calibration_identity_refusals() -> TestResult {
    record_refusals().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
fn partial_sleep() -> Result<(), &'static str> {
    let _policy = crate::ath9k::ht::tests::Policy::install();
    for failed_register in [0x704c, 0x4004] {
        let model = Model::new();
        let link = live_link(&model, Chip::Ar9462)?;
        qualify(&model, &link)?;
        let mut peer = station::tests::Peer::new_rates(false, None);
        let mut actor = Actor::default();
        let mut radio = joined(&model, link.clone(), &mut peer, &mut actor, false)?;
        radio
            .set_power_save(true)
            .map_err(|_| "partial PS enable")?;
        pump(&model, &mut radio, &mut peer, &mut actor)?;
        actor.hold_notice = true;
        inject(&model, &tim(&peer, 102400, false));
        pump(&model, &mut radio, &mut peer, &mut actor)?;
        actor.release(&model)?;
        model.fail_write.set(Some(failed_register));
        if radio.poll().is_ok()
            || !model.ps_failed.get()
            || model.ps_sleeping.get()
            || !model.released.borrow().is_empty()
            || link.lock().ftp_counters().0 != 0
        {
            return Err("partial N46S clock mutation was treated as sleep/completion/free");
        }
        let pushed = model.pushed.borrow().len();
        let writes = model.writes.borrow().len();
        model.fail_write.set(None);
        model.now.set(model.now.get() + 200_000);
        let _ = radio.poll();
        if model.pushed.borrow().len() != pushed
            || model.writes.borrow().len() != writes
            || link.lock().ftp_counters().0 != 0
        {
            return Err("failed N46S clock owner reopened DMA or fabricated FTP wait");
        }
    }
    Ok(())
}
fn smoke_ath9k_ar9462_native_ps_partial_clock_effect_retains_dma_and_blocks_ftp() -> TestResult {
    partial_sleep().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/ath9k/ar9003",
    smoke_ath9k_ar9462_mci_ftp_requires_real_network_sleep_and_native_rx
);
kernel_test_in!(
    "drivers/wireless/ath9k/ar9003",
    smoke_ath9k_ar9462_native_ps_held_notice_supersession_and_source_loss
);
kernel_test_in!(
    "drivers/wireless/ath9k/ar9003",
    smoke_ath9k_ar9462_ps_source_format_and_calibration_identity_refusals
);
kernel_test_in!(
    "drivers/wireless/ath9k/ar9003",
    smoke_ath9k_ar9462_native_ps_partial_clock_effect_retains_dma_and_blocks_ftp
);
