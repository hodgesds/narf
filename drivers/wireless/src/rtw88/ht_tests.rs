//! Composed native HT cases shared by the two exact-chip fixture adapters.
//! Expected protocol/register values are authored literals, never production encoders.
use super::*;
use alloc::{sync::Arc, vec, vec::Vec};
use core::{
    future::Future,
    task::{Context, Poll, Waker},
};
use narf_capabilities::{Cap, Read};
use narf_firmware::FirmwareBlob;
use narf_net::{Interface, TxMeta};
use narf_wireless::{AssociateRequest, ScanRequest, SecurityConfig, WirelessNetIface};
pub(super) const OWN: [u8; 6] = [2, 4, 6, 8, 10, 12];
pub(super) const AP: [u8; 6] = [2, 0, 0, 0, 0, 1];
type Peer = firmware_transport::station_composition_tests::Peer;
pub(super) trait Fixture: Sized {
    type Io: firmware_transport::Io + 'static;
    fn make(protected: bool, mcs: u8, sgi: bool, qualified: bool) -> Result<Self, &'static str>;
    fn device(&self) -> &Arc<interface::Device<Self::Io>>;
    fn peer(&self) -> &Arc<narf_lib::sync::IrqSafeSpinLock<Peer>>;
    fn pump(&self);
    fn received(&self) -> Vec<Vec<u8>>;
    fn inject(&self, frame: &[u8], rate: u8, bw: u8);
    fn descriptor(&self) -> Option<[u8; 48]>;
    fn register(&self, r: u16) -> u32;
    fn lose(&self, r: u16);
    fn cap(&self) -> Cap<FirmwareBlob, Read>;
    fn request(&self) -> Result<ht::Request, &'static str>;
    fn stage(
        &self,
        b: Vec<u8>,
        c: Cap<FirmwareBlob, Read>,
    ) -> Result<(), firmware_transport::Error>;
    fn retained(&self) -> (usize, u64);
    fn after_descriptor(&self, f: Arc<dyn Fn() + Send + Sync>);
    fn after_idle(&self, f: Arc<dyn Fn() + Send + Sync>);
    fn clear_policy(&self);
    fn install_policy(&self);
    fn c21() -> bool;
    fn controls(&self) -> Arc<packet_core::tests::Controls>;
    fn sources(&self) -> Vec<Cap<FirmwareBlob, Read>>;
    fn conversions(&self) -> Option<usize>;
    fn inject_status(&self, frame: &[u8], status: &[u8], info: u8, present: bool, shift: u8);
    fn ba_request(&self) -> Result<super::RxBaRequest, firmware_transport::Error>;
    fn stage_ba(
        &self,
        bytes: Vec<u8>,
        cap: Cap<FirmwareBlob, Read>,
    ) -> Result<(), firmware_transport::Error>;
    fn advance_ms(&self, ms: u64);
    fn tx_request(&self) -> Result<super::TxBaRequest, firmware_transport::Error>;
    fn stage_tx(
        &self,
        bytes: Vec<u8>,
        cap: Cap<FirmwareBlob, Read>,
    ) -> Result<(), firmware_transport::Error>;
    fn descriptors(&self) -> Vec<[u8; 48]>;
}
pub(super) fn elements(sgi: bool) -> Vec<u8> {
    let mut b = vec![45, 26];
    let mut cap = [0; 26];
    cap[0] = 12 | if sgi { 32 } else { 0 };
    cap[2] = 16;
    cap[3] = 255;
    cap[15] = 1;
    b.extend_from_slice(&cap);
    b.extend_from_slice(&[61, 22]);
    let mut op = [0; 22];
    op[0] = 1;
    b.extend_from_slice(&op);
    b
}
pub(super) fn record(r: &ht::Request, mcs: u8, sgi: bool, c21: bool) -> Vec<u8> {
    let mut b = vec![0; 192];
    b[..4].copy_from_slice(if c21 { b"N21H" } else { b"N22H" });
    b[4..8].copy_from_slice(&[1, 0, 192, 0]);
    b[8..12].copy_from_slice(&192u32.to_le_bytes());
    b[12..16].copy_from_slice(if c21 {
        &[0xec, 0x10, 0x21, 0xc8]
    } else {
        &[0xec, 0x10, 0x22, 0xc8]
    });
    b[16..48].copy_from_slice(&r.identity);
    b[48..54].copy_from_slice(&r.mac);
    b[54..56].copy_from_slice(&[1, 20]);
    b[56..58].copy_from_slice(&4i16.to_le_bytes());
    b[58..60].copy_from_slice(&76i16.to_le_bytes());
    b[60..62].copy_from_slice(&60i16.to_le_bytes());
    b[62..64].copy_from_slice(&48i16.to_le_bytes());
    b[65] = 63;
    b[66] = mcs;
    b[67] = u8::from(sgi);
    b[68..76].copy_from_slice(&[2, 3, 4, 5, 6, 7, 8, 9]);
    for at in (76..132).step_by(2) {
        b[at..at + 2].copy_from_slice(&40i16.to_le_bytes());
    }
    b
}
fn run<T>(future: impl Future<Output = T>) -> Result<T, &'static str> {
    let mut f = core::pin::pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..16384 {
        if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return Ok(v);
        }
    }
    Err("native HT fixture future did not finish")
}
pub(super) fn request<F: Fixture>(f: &F) -> AssociateRequest {
    AssociateRequest {
        bssid: AP,
        ssid: b"narf-8822ce".to_vec(),
        frequency_mhz: 2412,
        channel: 1,
        security: if f.peer().lock().ap.protected() {
            SecurityConfig::Wpa2 { psk: [0x55; 32] }
        } else {
            SecurityConfig::Open
        },
        ie: Vec::new(),
    }
}
pub(super) fn scan<F: Fixture>(f: &F) -> Result<(), &'static str> {
    let r = run(f.device().scan(ScanRequest {
        ssids: vec![],
        frequencies_mhz: vec![2412],
        channels: vec![1],
        active: false,
        random_mac: None,
        colocated_6ghz: false,
        duration_tu: Some(1),
        duration_mandatory: false,
        extra_ies: vec![],
    }))?
    .map_err(|_| "native HT scan")?;
    if r.len() != 1 {
        return Err("native original HT beacon not observed");
    }
    Ok(())
}
pub(super) fn join<F: Fixture>(f: &F) -> Result<(), &'static str> {
    scan(f)?;
    run(f.device().associate(request(f)))?.map_err(|_| "native HT association/receipts")?;
    if !f.device().link_up() {
        return Err("native HT port not open");
    }
    Ok(())
}
/// The AP's real M3 and an original protected DATA reach native RX before
/// the M2 CCX. Only private EAPOL may cross the terminal reply data epoch.
pub(super) fn early_m3_control<F: Fixture>() -> Result<(), &'static str> {
    let f = F::make(true, 255, true, true)?;
    scan(&f)?;
    let expected = narf_wifi_fixtures::udp_ipv4(
        OWN,
        AP,
        [10, 88, 1, 1],
        [10, 88, 1, 42],
        7,
        49152,
        b"M3 before M2 CCX",
    );
    {
        let mut p = f.peer().lock();
        p.hold_m4 = true;
        p.m2_data = Some(expected.clone());
    }
    let controls = f.controls();
    let retained = f.retained();
    let mut cx = Context::from_waker(Waker::noop());
    let mut future = alloc::boxed::Box::pin(f.device().associate(request(&f)));
    let mut held = false;
    for _ in 0..16384 {
        if future.as_mut().poll(&mut cx).is_ready() {
            return Err("early M3 did not reach actual held M4");
        }
        if controls.held.load(core::sync::atomic::Ordering::Acquire) {
            held = true;
            break;
        }
    }
    if !held {
        return Err("M3 copied before terminal M2 was lost");
    }
    let original = f
        .peer()
        .lock()
        .m2_original
        .clone()
        .ok_or("actual native M2 did not generate early original")?;
    if f.device().link_up() {
        return Err("M2 or early M3 authorized DATA before actual M4 receipt");
    }
    f.peer().lock().hold_m4 = false;
    controls
        .release
        .store(true, core::sync::atomic::Ordering::Release);
    let mut finished = false;
    for _ in 0..16384 {
        if let Poll::Ready(r) = future.as_mut().poll(&mut cx) {
            r.map_err(|_| "private M3 after native terminal M2")?;
            finished = true;
            break;
        }
    }
    drop(future);
    if !finished || !f.device().link_up() || !f.received().is_empty() || f.retained() != retained {
        return Err("private EAPOL epoch exception granted early DATA or lost native owner");
    }
    f.inject(&original, 19, 0);
    f.pump();
    if f.received() != vec![expected] {
        return Err("closed M2-batch DATA consumed PN before current original retry");
    }
    Ok(())
}
fn packet(label: u8) -> Vec<u8> {
    narf_wifi_fixtures::udp_ipv4(
        AP,
        OWN,
        [10, 88, 1, 42],
        [10, 88, 1, 1],
        49152,
        7,
        &[label; 24],
    )
}
pub(super) fn composition<F: Fixture>(protected: bool) -> Result<(), &'static str> {
    for sgi in [false, true] {
        let f = F::make(protected, 255, sgi, true)?;
        let retained = f.retained();
        let conversions = f.conversions();
        join(&f)?;
        if conversions
            .zip(f.conversions())
            .is_some_and(|(old, new)| new != old + 1)
        {
            return Err("C21 HT did not issue genuine fresh SIPI RF42 conversion");
        }
        let a = f
            .peer()
            .lock()
            .association
            .clone()
            .ok_or("actual HT association missing")?;
        let body = a
            .windows(2)
            .position(|w| w == [45, 26])
            .ok_or("actual request has no HT IE")?;
        if a[body + 2] & 32 != 32
            || a[body + 4] >> 2 != 4
            || a[body + 5] != 255
            || a[body + 3] & 8 != 0
        {
            return Err("actual local HT/SGI/AMSDU/density bytes wrong");
        }
        if F::c21() {
            if f.register(0x1d0c) != 0x05040302 || f.register(0x1d10) != 0x09080706 {
                return Err("C21 native MCS absolute TXAGC words");
            }
        } else if f.register(0x18e8) & 0x1fc00 != 9 << 10
            || f.register(0x41e8) & 0x1fc00 != 9 << 10
            || f.register(0x3a04) != 0x77777777
            || f.register(0x3a0c) != 0x7c7b7a79
            || f.register(0x3a10) != 0x007f7e7d
        {
            return Err("C22 native MCS refs/signed7bit difference/legacy conservation");
        }
        let lease = narf_net::dhcp::dhcp_acquire(f.device().name(), 0)
            .map_err(|_| "native HT real DHCP")?;
        if !f.peer().lock().plan.matches_lease(&lease) {
            return Err("native HT lease identity");
        }
        // DHCP is intentionally published into the actual RX IPC ring too.
        // Retire that already-validated conversation before exact IP comparison.
        let _ = f.received();
        let up = packet(23);
        f.device()
            .enqueue(&up, TxMeta::default())
            .map_err(|_| "HT native enqueue")?;
        f.pump();
        if f.peer().lock().uplink.last() != Some(&up) {
            return Err("native HT real CCMP uplink");
        }
        let d = f.descriptor().ok_or("actual HT descriptor absent")?;
        if d[16] != 19
            || d[6] != 3
            || d[20] != u8::from(sgi) << 4
            || d[8..12] != [0; 4]
            || d[12..16] != 0x500u32.to_le_bytes()
        {
            return Err("native HT fixed MCS7/SGI/RAID/no-BA descriptor");
        }
        let mut down = up.clone();
        down[..6].copy_from_slice(&OWN);
        down[6..12].copy_from_slice(&AP);
        let raw = f.peer().lock().downlink(&down)?;
        f.inject(&raw, 19, 0);
        f.pump();
        if f.received() != vec![down] || !f.device().link_up() || f.retained() != retained {
            return Err("HT native RX/DMA/port changed");
        }
    }
    Ok(())
}
struct Ccm;
impl narf_wireless::ccmp::AesCcm for Ccm {
    fn encrypt(
        &self,
        key: &[u8; 16],
        nonce: &[u8; 13],
        aad: &[u8],
        body: &mut [u8],
    ) -> Result<[u8; 8], narf_wireless::ccmp::CcmpError> {
        narf_crypto::aes_ccm::seal(key, nonce, aad, body)
            .map_err(|_| narf_wireless::ccmp::CcmpError::AuthFailed)
    }
    fn decrypt(
        &self,
        key: &[u8; 16],
        nonce: &[u8; 13],
        aad: &[u8],
        body: &mut [u8],
        tag: &[u8; 8],
    ) -> Result<(), narf_wireless::ccmp::CcmpError> {
        narf_crypto::aes_ccm::open(key, nonce, aad, body, tag)
            .map_err(|_| narf_wireless::ccmp::CcmpError::AuthFailed)
    }
}
pub(super) fn aggregate<F: Fixture>(
    f: &F,
    frames: &[Vec<u8>],
    pn: u64,
    tid: u8,
) -> Result<Vec<u8>, &'static str> {
    aggregate_sequence(f, frames, pn, tid, 0)
}
pub(super) fn aggregate_sequence<F: Fixture>(
    f: &F,
    frames: &[Vec<u8>],
    pn: u64,
    tid: u8,
    sequence: u16,
) -> Result<Vec<u8>, &'static str> {
    aggregate_control(f, frames, pn, tid, sequence, 0)
}
pub(super) fn aggregate_block_ack<F: Fixture>(
    f: &F,
    frames: &[Vec<u8>],
    pn: u64,
    tid: u8,
    sequence: u16,
) -> Result<Vec<u8>, &'static str> {
    aggregate_control(f, frames, pn, tid, sequence, 0x60)
}
fn aggregate_control<F: Fixture>(
    f: &F,
    frames: &[Vec<u8>],
    pn: u64,
    tid: u8,
    sequence: u16,
    policy: u8,
) -> Result<Vec<u8>, &'static str> {
    let protected = f.peer().lock().ap.protected();
    let mut h = vec![0x88, if protected { 0x42 } else { 2 }, 0, 0];
    h.extend_from_slice(&OWN);
    h.extend_from_slice(&AP);
    h.extend_from_slice(&AP);
    h.extend_from_slice(&(sequence << 4).to_le_bytes());
    h.extend_from_slice(&[0x80 | tid | policy, 0]);
    let mut body = Vec::new();
    for (i, e) in frames.iter().enumerate() {
        body.extend_from_slice(&e[..12]);
        body.extend_from_slice(&((e.len() - 14 + 8) as u16).to_be_bytes());
        body.extend_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0]);
        body.extend_from_slice(&e[12..]);
        if i + 1 < frames.len() {
            body.resize(body.len().next_multiple_of(4), 0);
        }
    }
    if protected {
        let peer = f.peer().lock();
        let key = peer
            .ptk
            .as_ref()
            .ok_or("HT fixture PTK missing")?
            .tk
            .as_slice()
            .try_into()
            .map_err(|_| "HT TK extent")?;
        body = narf_wireless::ccmp::protect(&Ccm, &h, key, pn, 0, tid, false, &mut body)
            .map_err(|_| "HT aggregate CCMP protect")?;
    }
    h.extend_from_slice(&body);
    Ok(h)
}
pub(super) fn amsdu<F: Fixture>() -> Result<(), &'static str> {
    for protected in [false, true] {
        let f = F::make(protected, 255, true, true)?;
        join(&f)?;
        let mut expected = Vec::new();
        for (i, len) in [1514, 1514, 783].into_iter().enumerate() {
            let mut e = vec![i as u8; len];
            e[..6].copy_from_slice(&OWN);
            e[6..12].copy_from_slice(&AP);
            e[12..14].copy_from_slice(&[8, 0]);
            expected.push(e);
        }
        let raw = aggregate(&f, &expected, 1, 15)?;
        if raw.len() != 26 + 3839 + if protected { 16 } else { 0 } {
            return Err("authored mandatory3839 A-MSDU extent");
        }
        if protected {
            let mut bad = raw.clone();
            *bad.last_mut().unwrap() ^= 1;
            f.inject(&bad, 19, 0);
            f.pump();
            if !f.received().is_empty() {
                return Err("bad whole aggregate published prefix");
            }
        }
        f.inject(&raw, 19, 0);
        f.pump();
        let received = f.received();
        if received != expected || !f.device().link_up() {
            use core::fmt::Write;
            let _=writeln!(narf_console::Writer,"HT aggregate diagnostic protected={} raw={} received={:?} expected={:?} link={} retained={:?}",protected,raw.len(),received.iter().map(Vec::len).collect::<Vec<_>>(),expected.iter().map(Vec::len).collect::<Vec<_>>(),f.device().link_up(),f.retained());
            return Err("native full3839 authenticated aggregate not delivered atomically");
        }
        if protected {
            f.inject(&raw, 19, 0);
            f.pump();
            if !f.received().is_empty() {
                return Err("A-MSDU replay escaped perTID PN");
            }
        }
    }
    Ok(())
}
pub(super) fn refused_assets<F: Fixture>() -> Result<(), &'static str> {
    let f = F::make(false, 255, true, false)?;
    let r = f.request()?;
    let retained = f.retained();
    for fault in 0..8 {
        let mut b = record(&r, 255, true, F::c21());
        let cap = Cap::bootstrap();
        match fault {
            0 => b[..4].copy_from_slice(b"N22L"),
            1 => b[16] ^= 1,
            2 => b[48] ^= 1,
            3 => {
                b.pop();
            }
            4 => b[65] = 62,
            5 => b[76..78].copy_from_slice(&100i16.to_le_bytes()),
            6 => b[132] = 1,
            _ => cap.revoke(),
        };
        if f.stage(b, cap).is_ok() || f.retained() != retained {
            return Err("invalid new HT record consumed native legacy/DMA owner");
        }
    }
    join(&f)?;
    let p = packet(3);
    f.device()
        .enqueue(&p, TxMeta::default())
        .map_err(|_| "legacy fallback enqueue")?;
    f.pump();
    let d = f.descriptor().ok_or("legacy fallback descriptor")?;
    if d[16] != 11
        || d[20] != 0
        || f.peer()
            .lock()
            .association
            .as_ref()
            .is_some_and(|a| a.windows(2).any(|w| w == [45, 26]))
    {
        return Err("old L record granted HT or lost legacy fallback");
    }
    Ok(())
}
pub(super) fn rates_and_native_errors<F: Fixture>() -> Result<(), &'static str> {
    for rate in 0..8 {
        let f = F::make(false, 1 << rate, true, true)?;
        join(&f)?;
        let p = packet(rate);
        f.device()
            .enqueue(&p, TxMeta::default())
            .map_err(|_| "HT MCS enqueue")?;
        f.pump();
        let d = f.descriptor().ok_or("native individual MCS descriptor")?;
        if d[16] != 12 + rate || d[20] != 16 {
            return Err("native measured MCS subset/SGI did not reach DMA");
        }
        let mut down = p;
        down[..6].copy_from_slice(&OWN);
        down[6..12].copy_from_slice(&AP);
        let raw = f.peer().lock().downlink(&down)?;
        for (native_rate, bw) in [(20, 0), (44, 0), (19, 1), (19, 2)] {
            f.inject(&raw, native_rate, bw);
            f.pump();
            if !f.received().is_empty() {
                return Err("native HT RX admitted unsupported MCS/width");
            }
        }
        // RX is independent of the AP's RX mask and our selected TX subset.
        f.inject(&raw, 19, 0);
        f.pump();
        if f.received() != vec![down] {
            return Err("HT local RX set incorrectly narrowed to TX subset");
        }
    }
    let f = F::make(false, 255, true, true)?;
    f.lose(if F::c21() { 0x1d0c } else { 0x18e8 });
    scan(&f)?;
    if run(f.device().associate(request(&f)))?.is_ok() || !f.device().closed() {
        return Err("lost native HT gain write admitted station");
    }
    Ok(())
}
pub(super) fn decline_and_authority<F: Fixture>() -> Result<(), &'static str> {
    let f = F::make(true, 255, true, true)?;
    join(&f)?;
    let retained = f.retained();
    let mut action = vec![0xd0, 0, 0, 0];
    action.extend_from_slice(&OWN);
    action.extend_from_slice(&AP);
    action.extend_from_slice(&AP);
    action.extend_from_slice(&[0, 0, 3, 0, 9, 14, 16, 0, 0, 0, 0]);
    let mut foreign = action.clone();
    foreign[10] ^= 4;
    f.inject(&foreign, 0, 0);
    f.pump();
    if !f.peer().lock().declines.is_empty() {
        return Err("foreign ADDBA caused native RF reply");
    }
    f.peer().lock().hold_decline = true;
    f.inject(&action, 0, 0);
    f.pump();
    let sent = f.peer().lock().declines.clone();
    if sent.len() != 1 || sent[0][24..] != [3, 1, 9, 37, 0, 14, 0, 0, 0] {
        return Err("actual native ADDBA decline bytes");
    }
    f.cap().revoke();
    f.pump();
    if !f.device().closed() || f.retained() != retained || !f.received().is_empty() {
        return Err("held native ADDBA source loss released DMA or kept authority");
    }
    Ok(())
}

pub(super) fn held_m4<F: Fixture>() -> Result<(), &'static str> {
    let count = F::make(true, 255, true, true)?.sources().len();
    for fault in 0..count + 3 {
        let f = F::make(true, 255, true, true)?;
        f.peer().lock().hold_m4 = true;
        let retained = f.retained();
        let controls = f.controls();
        scan(&f)?;
        let mut future = alloc::boxed::Box::pin(f.device().associate(request(&f)));
        let mut cx = Context::from_waker(Waker::noop());
        let mut reached = false;
        for _ in 0..16384 {
            if future.as_mut().poll(&mut cx).is_ready() {
                return Err("HT join skipped actual held M4");
            }
            if controls.held.load(core::sync::atomic::Ordering::Acquire) {
                reached = true;
                break;
            }
        }
        if !reached || f.device().link_up() {
            return Err("HT M4 retained closed port not reached");
        }
        let mut e = packet(55);
        e[..6].copy_from_slice(&OWN);
        e[6..12].copy_from_slice(&AP);
        let raw = aggregate(&f, core::slice::from_ref(&e), 1, 0)?;
        controls
            .incoming_profiles
            .lock()
            .push_back((raw.clone(), 19, 0));
        for _ in 0..8 {
            if future.as_mut().poll(&mut cx).is_ready() {
                return Err("HT M4 opened without native receipt");
            }
        }
        if fault == 0 {
            drop(future);
            controls
                .release
                .store(true, core::sync::atomic::Ordering::Release);
            f.pump();
            if !f.device().closed() || f.retained() != retained || !f.received().is_empty() {
                return Err("cancelled HT M4 reopened preauthorization data or released DMA");
            }
            continue;
        }
        if fault <= count {
            f.sources()[fault - 1].revoke();
        } else if fault == count + 1 {
            controls
                .corrupt_receipt
                .store(true, core::sync::atomic::Ordering::Release);
        }
        controls
            .release
            .store(true, core::sync::atomic::Ordering::Release);
        let result = run(future)?;
        if fault == count + 2 {
            result.map_err(|_| "exact HT M4 terminal receipt")?;
            if !f.received().is_empty() {
                return Err("positive HT M4 authorized earlier captured aggregate");
            }
            f.inject(&raw, 19, 0);
            f.pump();
            if f.received() != vec![e] {
                return Err("discarded closed-port aggregate consumed PN");
            }
            run(f.device().disassociate())?.map_err(|_| "HT native disconnect")?;
            if !f.device().closed() || f.retained() != retained {
                return Err("HT native close lost retained DMA");
            }
        } else if result.is_ok()
            || !f.device().closed()
            || !f.received().is_empty()
            || f.retained() != retained
        {
            return Err("HT late M4 source/corruption admitted port or released DMA");
        }
    }
    Ok(())
}
pub(super) fn responses<F: Fixture>() -> Result<(), &'static str> {
    for fault in 0..6 {
        let f = F::make(false, 255, true, true)?;
        {
            let mut p = f.peer().lock();
            let mut h = elements(true);
            match fault {
                0 => p.ht = None,
                1 => {
                    let copy = h.clone();
                    h.extend_from_slice(&copy);
                    p.ht = Some(h);
                }
                2 => {
                    h[30] = 2;
                    p.ht = Some(h);
                }
                3 => {
                    h[37] = 1;
                    p.ht = Some(h);
                }
                4 => {
                    h[32] = 1;
                    p.ht = Some(h);
                }
                _ => {
                    h[2] &= !32;
                    h[5] = 1;
                    p.ht = Some(h);
                }
            }
        }
        scan(&f)?;
        let result = run(f.device().associate(request(&f)))?;
        if fault < 5 {
            if result.is_ok() || !f.device().closed() {
                return Err("native selected HT response mismatch admitted port");
            }
        } else {
            result.map_err(|_| "response HT narrowing")?;
            f.device()
                .enqueue(&packet(4), TxMeta::default())
                .map_err(|_| "response-narrow HT enqueue")?;
            f.pump();
            let d = f.descriptor().ok_or("narrow HT descriptor")?;
            if d[16] != 12 || d[20] != 0 {
                return Err("response MCS/SGI bound not used by native DMA");
            }
        }
    }
    // Original mandatory selector remains in its original IE stream. No
    // strip-and-reparse shortcut is used by observation or response admission.
    let f = F::make(false, 255, true, true)?;
    let mut beacon = f.peer().lock().ap.beacon();
    let mut at = 36;
    while at < beacon.len() {
        let len = usize::from(beacon[at + 1]);
        if beacon[at] == 50 {
            beacon[at + 1] += 1;
            beacon.insert(at + 2 + len, 255);
            break;
        }
        at += 2 + len;
    }
    {
        let mut p = f.peer().lock();
        p.response_rates = Some(vec![0x82, 4, 11, 22, 12, 18, 24, 36, 48, 72, 96, 108, 255]);
        beacon.extend_from_slice(p.wmm.as_ref().unwrap());
        beacon.extend_from_slice(p.ht.as_ref().unwrap());
    }
    f.inject(&beacon, 0, 0);
    join(&f)?;
    if !f.device().link_up() {
        return Err("native original HT membership selector not admitted");
    }
    Ok(())
}

/// Literal page1: HT_RXSC is LE32word1 bits12..15, channel (C22 only)
/// bits16..23; C21's RF_MODE fallback is LE32word3 bits28..29.
fn status(rxsc: u8, channel: u8, mode: u8) -> [u8; 32] {
    let mut p = [0; 32];
    p[0] = 1;
    p[5] = rxsc << 4;
    p[6] = channel;
    p[15] = mode << 4;
    p
}
pub(super) fn native_phy_status<F: Fixture>() -> Result<(), &'static str> {
    // Same original ciphertext/PN must remain usable after every metadata
    // refusal. Exercise both ordinary DATA and complete original A-MSDU.
    for amsdu in [false, true] {
        for case in 0..15 {
            let f = F::make(true, 255, true, true)?;
            join(&f)?;
            let retained = f.retained();
            let mut e = packet(43);
            e[..6].copy_from_slice(&OWN);
            e[6..12].copy_from_slice(&AP);
            let raw = if amsdu {
                aggregate(&f, core::slice::from_ref(&e), 1, 15)?
            } else {
                f.peer().lock().downlink(&e)?
            };
            let mut p = status(1, 1, 0);
            let mut info = 4;
            let mut present = true;
            let mut shift = 0;
            let mut invalid = true;
            match case {
                0 => p[5] = 0x90, // native page40MHz contradicts RXD W4=20
                1 => p[5] = 0xd0, // native page80MHz
                2 => p[0] = 2,    // unsupported status page
                3 => p[0] = 0,    // CCK page cannot establish HT PHY
                4 => {
                    p[5] = 0;
                    p[15] = 0x10;
                    invalid = F::c21();
                } // C21 RF40; C22 ignores this byte
                5 => {
                    p[5] = 0;
                    p[15] = 0x20;
                    invalid = F::c21();
                }
                6 => {
                    p[5] = 0;
                    p[15] = 0x30;
                    invalid = F::c21();
                } // reserved C21 RF mode
                7 => {
                    p[6] = 6;
                    invalid = !F::c21();
                } // C21 has NO channel byte
                8 => {
                    p[6] = 0;
                    invalid = !F::c21();
                }
                9 => info = 8,  // two32-byte blocks are not one4*8 status
                10 => info = 0, // PHYST without its actual driver-info extent
                11 => {
                    p[0] = 15;
                    present = false;
                    invalid = false;
                } // unused info, no claimed PHY
                12 => {
                    p[5] = 0;
                    invalid = false;
                } // actual source20MHz fallback
                13 => {
                    shift = 3;
                    invalid = false;
                }
                _ => {
                    p[5] = 0x80;
                    invalid = false;
                } // upper source20MHz RXSC code
            }
            if case == 9 {
                let mut duplicate = p.to_vec();
                duplicate.extend_from_slice(&p);
                f.inject_status(&raw, &duplicate, info, present, shift);
            } else if case == 10 {
                f.inject_status(&raw, &[], info, present, shift);
            } else {
                f.inject_status(&raw, &p, info, present, shift);
            }
            f.pump();
            let first = f.received();
            if invalid {
                if !first.is_empty() || !f.device().link_up() {
                    return Err("native PHY contradiction published data or poisoned valid peer");
                }
                f.inject_status(&raw, &status(1, 1, 0), 4, true, 2);
                f.pump();
                if f.received() != vec![e.clone()] {
                    return Err("rejected original PHY metadata consumed CCMP PN");
                }
            } else if first != vec![e.clone()] || !f.device().link_up() {
                return Err(
                    "source-specific/missing PHY semantics invented a restriction or channel",
                );
            }
            if f.retained() != retained {
                return Err("native PHY refusal replaced firmware/packet DMA");
            }
        }
    }
    // Physically truncated promised32-byte status/body is a native ownership
    // error, not an RX-idle indication or permission to reuse the old mapping.
    let f = F::make(true, 255, true, true)?;
    join(&f)?;
    let retained = f.retained();
    let mut e = packet(51);
    e[..6].copy_from_slice(&OWN);
    e[6..12].copy_from_slice(&AP);
    let raw = f.peer().lock().downlink(&e)?;
    f.inject_status(&raw, &status(1, 1, 0)[..31], 4, true, 0);
    f.pump();
    if !f.device().closed() || !f.received().is_empty() || f.retained() != retained {
        return Err("truncated native PHY extent lost terminal DMA ownership");
    }
    Ok(())
}

type RxHook = dyn Fn(&str, &mut [u8]) + Send + Sync;
static RX_HOOK: narf_lib::sync::IrqSafeSpinLock<Option<Arc<RxHook>>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);
fn intercepted_receive(name: &str, frame: &mut [u8]) {
    let hook = RX_HOOK.lock().clone();
    if let Some(h) = hook {
        h(name, frame);
    }
}
struct RestoreReceive;
impl Drop for RestoreReceive {
    fn drop(&mut self) {
        *RX_HOOK.lock() = None;
        narf_net::iface::install_rx_handler(narf_net::tcp_stack::rx_handler);
    }
}
pub(super) fn group_rekey<F: Fixture>(f: &F) -> Result<Vec<u8>, &'static str> {
    use narf_wireless::eapol::KeyFrame;
    let pdu = {
        let peer = f.peer().lock();
        let ptk = peer
            .ptk
            .as_ref()
            .ok_or("reentrant group fixture has no actual PTK")?;
        let mut clear = vec![48, 20];
        clear.extend_from_slice(&narf_wireless::rsn::RsnIe::wpa2_psk_ccmp().encode_body());
        clear.extend_from_slice(&[0xdd, 22, 0, 0x0f, 0xac, 1, 2, 0]);
        clear.extend_from_slice(&[0x66; 16]);
        if clear.len() % 8 != 0 {
            clear.push(0xdd);
        }
        while clear.len() % 8 != 0 {
            clear.push(0);
        }
        let mut key = KeyFrame::empty(16);
        key.key_information = 0x1382;
        key.key_length = 16;
        key.replay_counter = 3;
        key.key_data = narf_crypto::aes_kw::aes_wrap(
            ptk.kek
                .as_slice()
                .try_into()
                .map_err(|_| "group fixture KEK extent")?,
            &clear,
        )
        .ok_or("group fixture key wrap")?;
        let mut pdu = key.into_eapol();
        pdu[0] = 2;
        let mic = narf_crypto::pbkdf2_sha1::hmac_sha1(&ptk.kck, &pdu);
        pdu[81..97].copy_from_slice(&mic[..16]);
        pdu
    };
    let mut ethernet = OWN.to_vec();
    ethernet.extend_from_slice(&AP);
    ethernet.extend_from_slice(&[0x88, 0x8e]);
    ethernet.extend_from_slice(&pdu);
    f.peer().lock().downlink(&ethernet)
}
pub(super) fn reentrant_receive_epoch<F: Fixture + Send + Sync + 'static>(
) -> Result<(), &'static str> {
    use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    for mode in 0..3 {
        let f = Arc::new(F::make(true, 255, true, true)?);
        join(f.as_ref())?;
        let retained = f.retained();
        let group = group_rekey(f.as_ref())?;
        let controls = f.controls();
        let mut first = packet(71);
        first[..6].copy_from_slice(&OWN);
        first[6..12].copy_from_slice(&AP);
        let mut second = first.clone();
        *second.last_mut().unwrap() = 72;
        let original = aggregate(f.as_ref(), &[first.clone(), second.clone()], 1, 15)?;
        let seen = Arc::new(narf_lib::sync::IrqSafeSpinLock::new(Vec::<Vec<u8>>::new()));
        let calls = Arc::new(AtomicUsize::new(0));
        let okay = Arc::new(AtomicBool::new(true));
        let target = f.clone();
        let log = seen.clone();
        let count = calls.clone();
        let valid = okay.clone();
        let held = controls.clone();
        *RX_HOOK.lock() = Some(Arc::new(move |name, bytes| {
            if name != target.device().name() {
                return;
            }
            log.lock().push(bytes.to_vec());
            if count.fetch_add(1, Ordering::AcqRel) != 0 {
                return;
            }
            target.peer().lock().hold_data = true;
            if mode == 0 {
                if target
                    .device()
                    .enqueue(&packet(73), TxMeta::default())
                    .is_err()
                {
                    valid.store(false, Ordering::Release);
                }
            } else {
                target.inject(&group, 19, 0);
            }
            target.pump();
            if !held.held.load(Ordering::Acquire) {
                valid.store(false, Ordering::Release);
            }
            if mode != 0 {
                let peer = target.peer().lock();
                let checked = peer
                    .uplink
                    .last()
                    .and_then(|e| e.get(14..))
                    .and_then(|pdu| {
                        let key = narf_wireless::eapol::KeyFrame::decode(pdu.get(4..)?, 16)?;
                        if key.key_information != 0x0302
                            || key.replay_counter != 3
                            || !key.key_data.is_empty()
                        {
                            return None;
                        }
                        let mut authenticated = pdu.to_vec();
                        let expected = authenticated.get(81..97)?.to_vec();
                        authenticated[81..97].fill(0);
                        let mic = narf_crypto::pbkdf2_sha1::hmac_sha1(
                            &peer.ptk.as_ref()?.kck,
                            &authenticated,
                        );
                        (mic[..16] == expected).then_some(())
                    });
                if checked.is_none() {
                    valid.store(false, Ordering::Release);
                }
            }
            let open = target
                .device()
                .lifecycle
                .retained
                .try_lock()
                .and_then(|s| s.as_ref().map(|o| o.station_receive_open()))
                .unwrap_or(false);
            if open != (mode == 0) {
                valid.store(false, Ordering::Release);
            }
            if mode != 0 && !target.received().is_empty() {
                valid.store(false, Ordering::Release);
            }
            if mode == 2 {
                target.peer().lock().hold_data = false;
                held.release.store(true, Ordering::Release);
                target.pump();
                let open = target
                    .device()
                    .lifecycle
                    .retained
                    .try_lock()
                    .and_then(|s| s.as_ref().map(|o| o.station_receive_open()))
                    .unwrap_or(false);
                if !open {
                    valid.store(false, Ordering::Release);
                }
            }
        }));
        let restore = RestoreReceive;
        narf_net::iface::install_rx_handler(intercepted_receive);
        f.inject(&original, 19, 0);
        f.pump();
        let expected = if mode == 0 {
            vec![first, second]
        } else {
            vec![first]
        };
        if *seen.lock() != expected
            || !okay.load(Ordering::Acquire)
            || !f.device().link_up()
            || f.retained() != retained
        {
            return Err("actual reentrant original A-MSDU batch escaped receive epoch or confused TX credit");
        }
        f.peer().lock().hold_data = false;
        controls.release.store(true, Ordering::Release);
        f.pump();
        let mut fresh = packet(74);
        fresh[..6].copy_from_slice(&OWN);
        fresh[6..12].copy_from_slice(&AP);
        let raw = aggregate(f.as_ref(), core::slice::from_ref(&fresh), 2, 15)?;
        f.inject(&raw, 19, 0);
        f.pump();
        if seen.lock().last() != Some(&fresh) || !f.device().link_up() {
            return Err("new current receive epoch failed to accept fresh authenticated aggregate");
        }
        drop(restore);
        drop(f);
    }
    Ok(())
}

pub(super) fn publication_fences<F: Fixture>() -> Result<(), &'static str> {
    for point in 0..3 {
        let f = F::make(true, 255, true, true)?;
        join(&f)?;
        let retained = f.retained();
        if point == 0 {
            let cap = f.cap();
            f.after_descriptor(Arc::new(move || cap.revoke()));
            f.device()
                .enqueue(&packet(4), TxMeta::default())
                .map_err(|_| "HT fence enqueue")?;
        } else if point == 1 {
            let cap = f.cap();
            f.after_idle(Arc::new(move || cap.revoke()));
            let mut p = packet(7);
            p[..6].copy_from_slice(&OWN);
            p[6..12].copy_from_slice(&AP);
            let raw = f.peer().lock().downlink(&p)?;
            f.inject(&raw, 19, 0);
        } else {
            f.clear_policy();
        }
        f.pump();
        f.install_policy();
        f.pump();
        if !f.device().closed() || !f.received().is_empty() || f.retained() != retained {
            return Err(
                "HT source/current-policy publication loss resurrected port or released DMA",
            );
        }
    }
    Ok(())
}
