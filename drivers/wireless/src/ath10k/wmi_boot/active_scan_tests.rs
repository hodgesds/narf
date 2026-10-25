//! Authored active scan requests over the actual retained HTC/WMI/HTT owner.
//! Expected packets use reviewed Rust wire vectors and explicit field values.
use super::*;
use alloc::sync::Arc;
use core::pin::pin;
use core::sync::atomic::{AtomicBool, Ordering};
use narf_lib::sync::IrqSafeSpinLock;
use narf_wireless::{
    reg::{RegFlags, RegulatoryDomain},
    WirelessError,
};

include!("../wmi_runtime/station_wire_golden.rs");

type Policy = Arc<IrqSafeSpinLock<Option<RegulatoryDomain>>>;
// Literal Extended Capabilities + private vendor OUI/type, deliberately unaligned.
pub(super) const PROBE_IES: &[u8] = &[127, 1, 0x80, 221, 4, 0x12, 0x34, 0x56, 0x7f];
pub(super) struct Fixture {
    pub(super) done: bool,
    step: u8,
    sequence: u16,
    ssids: Vec<Vec<u8>>,
    pub(super) extra_ies: Vec<u8>,
    limits: [u8; 2],
    global: u8,
    stall: Option<u8>,
    fail: Option<u8>,
    change: Option<(u8, Policy)>,
    started: bool,
    stopped: bool,
    started_signal: Arc<AtomicBool>,
}
impl Fixture {
    pub(super) fn new(sequence: u16) -> Self {
        Self {
            done: false,
            step: 0,
            sequence,
            ssids: vec![b"narf".to_vec(), Vec::new()],
            extra_ies: Vec::new(),
            limits: [34, 34],
            global: 34,
            stall: None,
            fail: None,
            change: None,
            started: false,
            stopped: false,
            started_signal: Arc::new(AtomicBool::new(false)),
        }
    }
    pub(super) fn directed(sequence: u16) -> Self {
        let mut fixture = Self::new(sequence);
        fixture.ssids.pop();
        fixture
    }
}
impl core::fmt::Debug for Fixture {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ActiveScanFixture")
            .field("step", &self.step)
            .field("done", &self.done)
            .finish()
    }
}
const DIALECTS: [(u32, Dialect); 6] = [
    (1, Dialect::Main),
    (2, Dialect::TenOne),
    (3, Dialect::TenTwo),
    (4, Dialect::Tlv),
    (5, Dialect::TenTwoFour),
    (6, Dialect::TenFour),
];
fn packet_word(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}
fn channels(dialect: Dialect, limits: [u8; 2]) -> Vec<u8> {
    let mut out = match dialect {
        Dialect::Main => CHANNELS_MAIN,
        Dialect::Tlv => CHANNELS_TLV,
        _ => CHANNELS_10X,
    }
    .to_vec();
    let (mut at, stride) = if dialect == Dialect::Tlv {
        (20, 28)
    } else {
        (8, 24)
    };
    for (frequency, half_dbm) in [(2412, limits[0]), (2437, limits[1])] {
        u32at(&mut out, at, frequency);
        u32at(&mut out, at + 4, frequency);
        u32at(&mut out, at + 12, 1);
        out[at + 17] = half_dbm;
        out[at + 18] = half_dbm;
        out[at + 21] = half_dbm;
        at += stride;
    }
    out
}
fn scan(dialect: Dialect, sequence: u16, ssids: &[Vec<u8>], ies: &[u8]) -> Vec<u8> {
    let mut out = match dialect {
        Dialect::Main => SCAN_MAIN,
        Dialect::Tlv => SCAN_TLV,
        Dialect::TenFour => SCAN_104,
        _ => SCAN_10X,
    }
    .to_vec();
    let (base, common) = match dialect {
        Dialect::Tlv => (8, 100),
        Dialect::Main | Dialect::TenFour => (4, 64),
        _ => (4, 60),
    };
    u32at(&mut out, base, 0xa000 | u32::from(sequence));
    u32at(
        &mut out,
        base + 56,
        if dialect == Dialect::Tlv { 0x5c } else { 0x7c },
    );
    let channels = base + common + if dialect == Dialect::Tlv { 4 } else { 8 };
    u32at(&mut out, channels + 4, 2437);
    let mut names = Vec::new();
    if dialect == Dialect::Tlv {
        u32at(&mut out, base + 72, ssids.len() as u32);
        u32at(
            &mut out,
            channels + 8,
            (19 << 16) | (ssids.len() as u32 * 36),
        );
    } else {
        names.extend_from_slice(&2u32.to_le_bytes());
        names.extend_from_slice(&(ssids.len() as u32).to_le_bytes());
    }
    for ssid in ssids {
        names.extend_from_slice(&(ssid.len() as u32).to_le_bytes());
        let at = names.len();
        names.resize(at + 32, 0);
        names[at..at + ssid.len()].copy_from_slice(ssid);
    }
    let at = channels + 8 + usize::from(dialect == Dialect::Tlv) * 4;
    out.splice(at..at, names);
    if dialect == Dialect::Tlv {
        u32at(&mut out, 84, ies.len() as u32); // START_SCAN's raw ie_len.
        let at = out.len() - 4;
        u32at(
            &mut out,
            at,
            (17 << 16) | (ies.len().div_ceil(4) * 4) as u32,
        );
    } else if !ies.is_empty() {
        out.extend_from_slice(&4u32.to_le_bytes());
        out.extend_from_slice(&(ies.len() as u32).to_le_bytes());
    }
    out.extend_from_slice(ies);
    out.resize(out.len().next_multiple_of(4), 0);
    out
}
fn stop(dialect: Dialect, sequence: u16) -> Vec<u8> {
    let tlv = dialect == Dialect::Tlv;
    let mut out = vec![0; if tlv { 24 } else { 20 }];
    u32at(
        &mut out,
        0,
        if matches!(dialect, Dialect::Main | Dialect::Tlv) {
            0x3002
        } else {
            0x9001
        },
    );
    let at = if tlv {
        u32at(&mut out, 4, (78 << 16) | 16);
        8
    } else {
        4
    };
    u32at(&mut out, at, 0xa001);
    u32at(&mut out, at + 4, 0xa000 | u32::from(sequence));
    u32at(&mut out, at + 12, u32::from(sequence));
    out
}
fn restore(dialect: Dialect) -> &'static [u8] {
    match dialect {
        Dialect::Main => CHANNELS_MAIN,
        Dialect::Tlv => CHANNELS_TLV,
        _ => CHANNELS_10X,
    }
}
pub(super) fn receive_channels(dialect: Dialect) -> Vec<u8> {
    let mut out = restore(dialect).to_vec();
    let (base, stride) = if dialect == Dialect::Tlv {
        (20, 28)
    } else {
        (8, 24)
    };
    let last = out[out.len() - stride..].to_vec();
    out.extend_from_slice(&last);
    if dialect == Dialect::Tlv {
        u32at(&mut out, 8, 3);
        u32at(&mut out, 12, (18 << 16) | 84);
    } else {
        u32at(&mut out, 4, 3);
    }
    u32at(&mut out, base + stride, 2437);
    u32at(&mut out, base + stride + 4, 2437);
    u32at(&mut out, base + stride + 12, 0x81);
    out
}
fn credit(m: &mut RadioModel, bytes: &[u8]) {
    m.inner.inner.rx.push_back((
        2,
        vec![
            2,
            2,
            8,
            0,
            8,
            0,
            0,
            0,
            1,
            4,
            0,
            0,
            2,
            bytes.len().div_ceil(256) as u8,
            0,
            0,
        ],
    ));
}
pub(super) async fn send(m: &mut RadioModel, bytes: &[u8]) -> Result<(), BmiError> {
    let dialect = m.inner.inner.dialect;
    let fixture = m.active.as_mut().unwrap();
    let step = fixture.step;
    let stopping = bytes[8..] == stop(dialect, fixture.sequence);
    let starting = step == 3 && !stopping && !fixture.stopped;
    let expected = if stopping {
        fixture.stopped = true;
        fixture.done = false;
        stop(dialect, fixture.sequence)
    } else if fixture.stopped || step == 4 {
        fixture.done = true;
        receive_channels(dialect)
    } else {
        fixture.step += 1;
        match step {
            0 => match dialect {
                Dialect::Main => RD_MAIN,
                Dialect::TenOne => RD_10X,
                Dialect::TenTwo | Dialect::TenTwoFour => RD_102,
                Dialect::TenFour => RD_104,
                Dialect::Tlv => RD_TLV,
            }
            .to_vec(),
            1 => {
                let mut power = match dialect {
                    Dialect::Main => POWER_MAIN,
                    Dialect::TenOne => POWER_10X,
                    Dialect::TenTwo | Dialect::TenTwoFour => POWER_102,
                    Dialect::TenFour => POWER_104,
                    Dialect::Tlv => POWER_TLV,
                }
                .to_vec();
                let at = power.len() - 4;
                u32at(&mut power, at, u32::from(fixture.global));
                power
            }
            2 => channels(dialect, fixture.limits),
            3 => {
                fixture.started = true;
                fixture.started_signal.store(true, Ordering::Release);
                scan(
                    dialect,
                    fixture.sequence,
                    &fixture.ssids,
                    &fixture.extra_ies,
                )
            }
            _ => return Err(BmiError::BadResponse),
        }
    };
    if bytes[8..] != expected {
        return Err(BmiError::BadResponse);
    }
    m.sent.push(bytes.to_vec());
    if fixture.fail == Some(step) && !stopping {
        return Err(BmiError::BadResponse);
    }
    let stalled = fixture.stall == Some(step) && !stopping;
    if let Some((change_at, policy)) = &fixture.change {
        if *change_at == step && !stopping {
            policy.lock().as_mut().unwrap().rules[0].flags = RegFlags::NO_IR;
        }
    }
    if starting {
        m.scan = fixture.sequence;
        m.phase += 1;
        scan_event(m, 2, 0xa000 | m.scan.saturating_sub(1), 0xa001);
        scan_event(m, 2, 0xa000 | m.scan, 0xa002);
        scan_event(m, 1, 0xa000 | m.scan, 0xa001);
        management(m, true);
        management(m, false);
        if m.malformed {
            add_event(
                m,
                if dialect == Dialect::Tlv {
                    0x3001
                } else {
                    0x9000
                },
                &[0; 4],
            );
        } else {
            scan_event(m, 2, 0xa000 | m.scan, 0xa001);
        }
    }
    credit(m, bytes);
    if stalled {
        core::future::pending::<()>().await;
    }
    Ok(())
}
pub(super) fn handles(fixture: &Fixture, dialect: Dialect, packet: &[u8]) -> bool {
    !fixture.done
        || packet.get(..4)
            == Some(
                &if matches!(dialect, Dialect::Main | Dialect::Tlv) {
                    0x3002u32
                } else {
                    0x9001
                }
                .to_le_bytes(),
            )
}

fn ready(version: u32, dialect: Dialect) -> radio::Radio<RadioModel> {
    let mut r = radio_boot(version, dialect);
    r.htt.wmi.htc.transport.active = Some(Fixture::new(1));
    assert!(matches!(
        drive(r.start(&[2412, 2437, 5180])),
        Poll::Ready(Ok(_))
    ));
    r
}
fn policy() -> Policy {
    Arc::new(IrqSafeSpinLock::new(Some(station_tests::policy())))
}

fn smoke_ath10k_active_scan_all_dialects_power_probe_and_passive_restore() -> TestResult {
    for (version, dialect) in DIALECTS {
        let mut r = ready(version, dialect);
        // Preserve the physical receive list for restoration while the test
        // fixture's expected active list uses two different 2.4-GHz channels.
        let p = policy();
        let names = vec![b"narf".to_vec(), Vec::new()];
        let plan = r
            .prepare_active_scan(&[2412, 2437], &names, p.lock().as_ref().unwrap())
            .unwrap();
        let result =
            drive(r.active_scan(plan, || p.lock().clone().ok_or(radio::Error::Unsupported)));
        if !matches!(result, Poll::Ready(Ok(ref report)) if report.bss.len() == 1 && report.bss[0].ssid == b"narf" && report.ignored >= 3)
            || !r.htt.wmi.htc.transport.active.as_ref().unwrap().done
        {
            return TestResult::Fail(
                "native active scan power/probe/terminal/passive-restore chain",
            );
        }
        if !matches!(drive(r.passive_scan(&[2412, 5180])), Poll::Ready(Ok(_))) {
            return TestResult::Fail("active scan failed to restore passive continuation");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/active-scan",
    smoke_ath10k_active_scan_all_dialects_power_probe_and_passive_restore
);

fn smoke_ath10k_active_scan_global_minimum_and_per_channel_half_dbm() -> TestResult {
    for (version, dialect) in DIALECTS {
        let mut r = ready(version, dialect);
        let p = policy();
        let mut narrow = p.lock().as_ref().unwrap().rules[0].clone();
        narrow.freq_start_mhz = 2427;
        narrow.freq_end_mhz = 2447;
        narrow.max_power_dbm = 9;
        p.lock().as_mut().unwrap().rules.push(narrow);
        let fixture = r.htt.wmi.htc.transport.active.as_mut().unwrap();
        fixture.global = 18;
        fixture.limits = [34, 18];
        let plan = r
            .prepare_active_scan(
                &[2412, 2437],
                &[b"narf".to_vec(), Vec::new()],
                p.lock().as_ref().unwrap(),
            )
            .unwrap();
        if !matches!(
            drive(r.active_scan(plan, || p.lock().clone().ok_or(radio::Error::Unsupported))),
            Poll::Ready(Ok(_))
        ) {
            return TestResult::Fail(
                "active scan lost minimum band limit or per-channel half-dBm fields",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/active-scan",
    smoke_ath10k_active_scan_global_minimum_and_per_channel_half_dbm
);

fn smoke_ath10k_active_scan_preflight_denies_no_ir_dfs_and_bad_geometry_without_io() -> TestResult {
    let mut r = ready(4, Dialect::Tlv);
    let names = vec![b"narf".to_vec(), Vec::new()];
    let domain = station_tests::policy();
    let before = r.htt.wmi.htc.transport.sent.len();
    for frequencies in [&[][..], &[2412, 2412], &[5180], &[5955], &[2413]] {
        if r.prepare_active_scan(frequencies, &names, &domain).is_ok() {
            return TestResult::Fail("active scan admitted unsupported channel geometry");
        }
    }
    for names in [vec![], vec![vec![0; 33]], vec![vec![]; 17]] {
        if r.prepare_active_scan(&[2412, 2437], &names, &domain)
            .is_ok()
        {
            return TestResult::Fail("active scan admitted invalid SSID bounds");
        }
    }
    for flags in [RegFlags::NO_IR, RegFlags::DFS, RegFlags::INDOOR_ONLY] {
        let mut denied = domain.clone();
        denied.rules[0].flags = flags;
        if r.prepare_active_scan(&[2412, 2437], &names, &denied)
            .is_ok()
        {
            return TestResult::Fail(
                "active probes bypassed NO_IR, DFS or unproven indoor restrictions",
            );
        }
    }
    for kind in 0..4 {
        let mut denied = domain.clone();
        match kind {
            0 => denied.rules[0].max_power_dbm = -1,
            1 => denied.rules[0].max_bandwidth_mhz = 10,
            2 => denied.rules[0].freq_start_mhz = 2403,
            _ => denied.country_code = *b"00",
        }
        if r.prepare_active_scan(&[2412, 2437], &names, &denied)
            .is_ok()
        {
            return TestResult::Fail("active probes bypassed host geometry or representable power");
        }
    }
    let caps = r.htt.wmi.caps.as_mut().unwrap();
    let identity = caps.eeprom_domain;
    caps.eeprom_domain = 0xdead;
    if r.prepare_active_scan(&[2412, 2437], &names, &domain)
        .is_ok()
    {
        return TestResult::Fail("active probes bypassed unknown factory identity");
    }
    r.htt.wmi.caps.as_mut().unwrap().eeprom_domain = identity;
    let plan = r
        .prepare_active_scan(&[2412, 2437], &names, &domain)
        .unwrap();
    // A prepared request is not transferable factory authority for another
    // radio, even when both EEPROM pairs are independently recognized.
    if crate::ath10k::regulatory::Factory::from_eeprom(0x60).unwrap()
        == crate::ath10k::regulatory::Factory::from_eeprom(identity).unwrap()
    {
        return TestResult::Fail("factory identity fixture did not select a different known pair");
    }
    r.htt.wmi.caps.as_mut().unwrap().eeprom_domain = 0x60;
    if !matches!(
        drive(r.active_scan(plan, || Ok(domain.clone()))),
        Poll::Ready(Err(radio::Error::Unsupported))
    ) {
        return TestResult::Fail("active scan used a plan from a different factory identity");
    }
    r.htt.wmi.caps.as_mut().unwrap().eeprom_domain = identity;
    if r.htt.wmi.htc.transport.sent.len() != before
        || r.prepare_active_scan(&[2412, 2437], &names, &domain)
            .is_err()
    {
        return TestResult::Fail("denied active preflight changed or poisoned physical owner");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/active-scan",
    smoke_ath10k_active_scan_preflight_denies_no_ir_dfs_and_bad_geometry_without_io
);

fn smoke_ath10k_active_scan_each_publication_cancel_retains_owner_and_dma() -> TestResult {
    for stage in 0..5 {
        let mut r = ready(4, Dialect::Tlv);
        let names = vec![b"narf".to_vec(), Vec::new()];
        let p = policy();
        r.htt.wmi.htc.transport.active.as_mut().unwrap().stall = Some(stage);
        let before = r.htt.wmi.htc.transport.sent.len();
        let plan = r
            .prepare_active_scan(&[2412, 2437], &names, p.lock().as_ref().unwrap())
            .unwrap();
        if !drive(r.active_scan(plan, || p.lock().clone().ok_or(radio::Error::Unsupported)))
            .is_pending()
        {
            return TestResult::Fail("active publication cancellation fixture never suspended");
        }
        let m = &r.htt.wmi.htc.transport;
        if m.sent.len() != before + usize::from(stage) + 1
            || m.inner.storage.as_ref().unwrap().filled != 1023
            || m.inner.inner.retained.is_none()
            || !matches!(
                once(r.passive_scan(&[2412, 5180])),
                Poll::Ready(Err(radio::Error::Failed))
            )
            || r.prepare_active_scan(&[2412, 2437], &names, p.lock().as_ref().unwrap())
                .is_ok()
        {
            return TestResult::Fail(
                "cancelled active scan replayed a command or released retained DMA",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/active-scan",
    smoke_ath10k_active_scan_each_publication_cancel_retains_owner_and_dma
);

fn smoke_ath10k_active_scan_live_restriction_stops_exact_id_and_remains_terminal() -> TestResult {
    for stage in 0..5 {
        let mut r = ready(4, Dialect::Tlv);
        let p = policy();
        let names = vec![b"narf".to_vec(), Vec::new()];
        r.htt.wmi.htc.transport.active.as_mut().unwrap().change = Some((stage, p.clone()));
        let plan = r
            .prepare_active_scan(&[2412, 2437], &names, p.lock().as_ref().unwrap())
            .unwrap();
        if !matches!(
            drive(r.active_scan(plan, || p.lock().clone().ok_or(radio::Error::Unsupported))),
            Poll::Ready(Err(radio::Error::Unsupported))
        ) {
            return TestResult::Fail("active scan ignored policy change at a publication boundary");
        }
        let fixture = r.htt.wmi.htc.transport.active.as_ref().unwrap();
        if !fixture.stopped || !fixture.done || fixture.started != (stage >= 3) {
            return TestResult::Fail(
                "active policy failure did not stop exact scan or restore receive configuration",
            );
        }
        *p.lock() = Some(station_tests::policy());
        if r.prepare_active_scan(&[2412, 2437], &names, p.lock().as_ref().unwrap())
            .is_ok()
        {
            return TestResult::Fail("restored policy reopened a failed active owner");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/active-scan",
    smoke_ath10k_active_scan_live_restriction_stops_exact_id_and_remains_terminal
);

fn smoke_ath10k_active_scan_failed_or_malformed_terminal_cannot_reopen_owner() -> TestResult {
    for malformed in [false, true] {
        let mut r = ready(4, Dialect::Tlv);
        let p = policy();
        r.htt.wmi.htc.transport.malformed = malformed;
        r.htt.wmi.htc.transport.reason = if malformed { 0 } else { 4 };
        let names = vec![b"narf".to_vec(), Vec::new()];
        let plan = r
            .prepare_active_scan(&[2412, 2437], &names, p.lock().as_ref().unwrap())
            .unwrap();
        if !matches!(
            drive(r.active_scan(plan, || p.lock().clone().ok_or(radio::Error::Unsupported))),
            Poll::Ready(Err(radio::Error::Firmware(4) | radio::Error::Malformed))
        ) || !r.htt.wmi.htc.transport.active.as_ref().unwrap().stopped
            || r.prepare_active_scan(&[2412, 2437], &names, p.lock().as_ref().unwrap())
                .is_ok()
        {
            return TestResult::Fail("active terminal failure lost STOP or permitted owner reuse");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/active-scan",
    smoke_ath10k_active_scan_failed_or_malformed_terminal_cannot_reopen_owner
);

fn smoke_ath10k_active_scan_policy_change_during_rx_never_publishes_cache() -> TestResult {
    let mut r = ready(4, Dialect::Tlv);
    let p = policy();
    let names = vec![b"narf".to_vec(), Vec::new()];
    let started = r
        .htt
        .wmi
        .htc
        .transport
        .active
        .as_ref()
        .unwrap()
        .started_signal
        .clone();
    let plan = r
        .prepare_active_scan(&[2412, 2437], &names, p.lock().as_ref().unwrap())
        .unwrap();
    let result = {
        let mut scan =
            pin!(r.active_scan(plan, || p.lock().clone().ok_or(radio::Error::Unsupported)));
        let mut cx = Context::from_waker(Waker::noop());
        for _ in 0..64 {
            if !scan.as_mut().poll(&mut cx).is_pending() {
                return TestResult::Fail("active scan completed before retained RX pause");
            }
            if started.load(Ordering::Acquire) {
                break;
            }
        }
        if !started.load(Ordering::Acquire) {
            return TestResult::Fail("active START never published");
        }
        p.lock().as_mut().unwrap().rules[0].flags = RegFlags::NO_IR;
        drive(scan.as_mut())
    };
    if !matches!(result, Poll::Ready(Err(radio::Error::Unsupported)))
        || r.information_elements([2, 8, 9, 10, 11, 12]).is_some()
        || !r.htt.wmi.htc.transport.active.as_ref().unwrap().stopped
    {
        return TestResult::Fail("policy change while waiting for RX exposed stale scan cache");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/active-scan",
    smoke_ath10k_active_scan_policy_change_during_rx_never_publishes_cache
);

fn smoke_ath10k_active_scan_native_wildcard_normalization_and_no_ir_preflight() -> TestResult {
    let mut r = ready(4, Dialect::Tlv);
    r.htt.wmi.htc.transport.active.as_mut().unwrap().ssids = vec![Vec::new()];
    let before = r.htt.wmi.htc.transport.sent.len();
    let p = policy();
    let current = p.clone();
    let owner = Arc::new(narf_lib::mutex::Mutex::new(r));
    let device = crate::ath10k::interface::Device::for_test(
        "narf-test-active-scan",
        [2, 3, 4, 5, 6, 7],
        owner.clone(),
        move || current.lock().clone(),
    );
    let request = || narf_wireless::ScanRequest {
        ssids: Vec::new(),
        frequencies_mhz: vec![2412, 2437],
        channels: vec![1, 6],
        active: true,
        random_mac: None,
        colocated_6ghz: false,
        duration_tu: None,
        duration_mandatory: false,
        extra_ies: Vec::new(),
    };
    p.lock().as_mut().unwrap().rules[0].flags = RegFlags::NO_IR;
    if !matches!(
        drive(device.scan(request())),
        Poll::Ready(Err(WirelessError::NotSupported))
    ) || owner.try_lock().unwrap().htt.wmi.htc.transport.sent.len() != before
    {
        return TestResult::Fail("native active preflight wrote firmware or ignored NO_IR");
    }
    p.lock().as_mut().unwrap().rules[0].flags = RegFlags::empty();
    if !matches!(drive(device.scan(request())), Poll::Ready(Ok(ref bss)) if bss.len() == 1 && bss[0].ssid == b"narf")
    {
        return TestResult::Fail(
            "native wildcard request failed or denied preflight poisoned interface",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/active-scan",
    smoke_ath10k_active_scan_native_wildcard_normalization_and_no_ir_preflight
);

fn smoke_ath10k_active_scan_sixteen_binary_ssids_and_firmware_bounds() -> TestResult {
    for (version, dialect) in DIALECTS {
        let mut r = ready(version, dialect);
        let mut names = vec![vec![0x80; 32]; 15];
        names[0][0] = 0;
        names.push(Vec::new());
        r.htt.wmi.htc.transport.active.as_mut().unwrap().ssids = names.clone();
        let p = policy();
        let plan = r
            .prepare_active_scan(&[2412, 2437], &names, p.lock().as_ref().unwrap())
            .unwrap();
        if !matches!(
            drive(r.active_scan(plan, || p.lock().clone().ok_or(radio::Error::Unsupported))),
            Poll::Ready(Ok(_))
        ) {
            return TestResult::Fail("full 16-SSID scan or binary/32-byte SSID encoding failed");
        }
        let sent = &r.htt.wmi.htc.transport.sent[5];
        let base = if dialect == Dialect::Tlv { 16 } else { 12 };
        if packet_word(sent, base + 56) & 1 != 0 {
            return TestResult::Fail("full SSID request silently became a passive scan");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/active-scan",
    smoke_ath10k_active_scan_sixteen_binary_ssids_and_firmware_bounds
);

fn smoke_ath10k_active_scan_each_failed_command_is_terminal_and_retains_dma() -> TestResult {
    for stage in 0..5 {
        let mut r = ready(4, Dialect::Tlv);
        let p = policy();
        let names = vec![b"narf".to_vec(), Vec::new()];
        r.htt.wmi.htc.transport.active.as_mut().unwrap().fail = Some(stage);
        let plan = r
            .prepare_active_scan(&[2412, 2437], &names, p.lock().as_ref().unwrap())
            .unwrap();
        if !matches!(
            drive(r.active_scan(plan, || p.lock().clone().ok_or(radio::Error::Unsupported))),
            Poll::Ready(Err(_))
        ) || r
            .prepare_active_scan(&[2412, 2437], &names, p.lock().as_ref().unwrap())
            .is_ok()
            || r.htt.wmi.htc.transport.inner.inner.retained.is_none()
        {
            return TestResult::Fail(
                "failed active command reused its physical owner or freed DMA",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/active-scan",
    smoke_ath10k_active_scan_each_failed_command_is_terminal_and_retains_dma
);

fn smoke_ath10k_active_scan_host_close_stops_retained_control_before_result() -> TestResult {
    let r = ready(4, Dialect::Tlv);
    let started = r
        .htt
        .wmi
        .htc
        .transport
        .active
        .as_ref()
        .unwrap()
        .started_signal
        .clone();
    let p = policy();
    let current = p.clone();
    let owner = Arc::new(narf_lib::mutex::Mutex::new(r));
    let device = crate::ath10k::interface::Device::for_test(
        "narf-test-close-active",
        [2, 3, 4, 5, 6, 7],
        owner.clone(),
        move || current.lock().clone(),
    );
    let request = narf_wireless::ScanRequest {
        ssids: vec![b"narf".to_vec(), Vec::new()],
        frequencies_mhz: vec![2412, 2437],
        channels: vec![1, 6],
        active: true,
        random_mac: None,
        colocated_6ghz: false,
        duration_tu: None,
        duration_mandatory: false,
        extra_ies: Vec::new(),
    };
    let result = {
        let mut scan = pin!(device.scan(request));
        let mut cx = Context::from_waker(Waker::noop());
        for _ in 0..64 {
            if !scan.as_mut().poll(&mut cx).is_pending() {
                return TestResult::Fail("native active scan completed before concurrent close");
            }
            if started.load(Ordering::Acquire) {
                break;
            }
        }
        if !started.load(Ordering::Acquire) {
            return TestResult::Fail("close race did not publish active START");
        }
        device.close_before_lock_for_test();
        drive(scan.as_mut())
    };
    let radio = owner.try_lock().unwrap();
    let model = &radio.htt.wmi.htc.transport;
    let fixture = model.active.as_ref().unwrap();
    if !matches!(result, Poll::Ready(Err(WirelessError::HardwareError)))
        || !fixture.stopped
        || !fixture.done
        || model.inner.inner.retained.is_none()
        || model.inner.storage.as_ref().unwrap().filled != 1023
        || radio.information_elements([2, 8, 9, 10, 11, 12]).is_some()
    {
        return TestResult::Fail(
            "host close lost native STOP, leaked scan results or released uncertain DMA",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/active-scan",
    smoke_ath10k_active_scan_host_close_stops_retained_control_before_result
);

fn smoke_ath10k_probe_ies_all_dialects_padding_maximum_and_owned_bytes() -> TestResult {
    for (version, dialect) in DIALECTS {
        for length in [0, 2, 3, 4, 5, 9, 255, 256] {
            let mut r = ready(version, dialect);
            let names = vec![b"narf".to_vec(), Vec::new()];
            let mut ies = if length == 0 {
                Vec::new()
            } else {
                let mut bytes = vec![0xa5; length];
                bytes[0] = 200; // Opaque element; arbitrary binary body.
                bytes[1] = (length - 2) as u8;
                bytes
            };
            r.htt.wmi.htc.transport.active.as_mut().unwrap().extra_ies = ies.clone();
            let domain = station_tests::policy();
            let plan = r
                .prepare_active_scan(&[2412, 2437], &names, &domain)
                .unwrap()
                .with_extra_ies(&ies)
                .unwrap();
            // The prepared plan must own the caller bytes before suspension.
            ies.fill(0xff);
            if !matches!(drive(r.active_scan(plan, || Ok(domain.clone()))), Poll::Ready(Ok(ref report)) if report.bss.len() == 1)
                || !r.htt.wmi.htc.transport.active.as_ref().unwrap().done
            {
                return TestResult::Fail("probe IE content/length/padding changed on native WMI");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/active-scan",
    smoke_ath10k_probe_ies_all_dialects_padding_maximum_and_owned_bytes
);

fn smoke_ath10k_probe_ies_native_invalid_and_passive_preflight_remain_retryable() -> TestResult {
    let mut r = ready(4, Dialect::Tlv);
    r.htt.wmi.htc.transport.active.as_mut().unwrap().extra_ies = PROBE_IES.to_vec();
    let before = r.htt.wmi.htc.transport.sent.len();
    let owner = Arc::new(narf_lib::mutex::Mutex::new(r));
    let device = crate::ath10k::interface::Device::for_test(
        "narf-test-probe-ies",
        [2, 3, 4, 5, 6, 7],
        owner.clone(),
        || Some(station_tests::policy()),
    );
    let request = |ies: Vec<u8>, active| narf_wireless::ScanRequest {
        ssids: vec![b"narf".to_vec(), Vec::new()],
        frequencies_mhz: vec![2412, 2437],
        channels: vec![1, 6],
        active,
        random_mac: None,
        colocated_6ghz: false,
        duration_tu: None,
        duration_mandatory: false,
        extra_ies: ies,
    };
    for malformed in [
        vec![127],
        vec![127, 2, 1],
        vec![127, 0, 221],
        vec![221, 2, 1, 2],
        vec![255, 0],
    ] {
        if !matches!(
            drive(device.scan(request(malformed, true))),
            Poll::Ready(Err(WirelessError::InvalidArgs))
        ) {
            return TestResult::Fail("malformed probe element was published or misclassified");
        }
    }
    for unsupported in [
        vec![0, 0],
        vec![1, 1, 0x82],
        vec![50, 1, 12],
        vec![200; 257],
    ] {
        if !matches!(
            drive(device.scan(request(unsupported, true))),
            Poll::Ready(Err(WirelessError::NotSupported))
        ) {
            return TestResult::Fail("oversized or firmware-owned probe element was accepted");
        }
    }
    if !matches!(
        drive(device.scan(request(PROBE_IES.to_vec(), false))),
        Poll::Ready(Err(WirelessError::NotSupported))
    ) || owner.try_lock().unwrap().htt.wmi.htc.transport.sent.len() != before
        || !matches!(drive(device.scan(request(PROBE_IES.to_vec(), true))), Poll::Ready(Ok(ref bss)) if bss.len() == 1)
    {
        return TestResult::Fail(
            "probe IE preflight wrote transport, ignored passive IEs or poisoned retry",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/active-scan",
    smoke_ath10k_probe_ies_native_invalid_and_passive_preflight_remain_retryable
);

fn smoke_ath10k_probe_ies_sixteen_ssids_cancel_and_policy_failure_retain_dma() -> TestResult {
    for (version, dialect) in DIALECTS {
        for cancel in [false, true] {
            let mut r = ready(version, dialect);
            let names = vec![vec![0x80; 32]; 16];
            let p = policy();
            let mut ies = vec![0xa5; 256];
            ies[0] = 221;
            ies[1] = 254;
            let fixture = r.htt.wmi.htc.transport.active.as_mut().unwrap();
            fixture.ssids = names.clone();
            fixture.extra_ies = ies.clone();
            if cancel {
                fixture.stall = Some(3); // Actual START publication with maximum arrays.
            } else {
                fixture.change = Some((3, p.clone()));
            }
            let plan = r
                .prepare_active_scan(&[2412, 2437], &names, p.lock().as_ref().unwrap())
                .unwrap()
                .with_extra_ies(&ies)
                .unwrap();
            let result =
                drive(r.active_scan(plan, || p.lock().clone().ok_or(radio::Error::Unsupported)));
            let model = &r.htt.wmi.htc.transport;
            let fixture = model.active.as_ref().unwrap();
            let failed_as_expected = if cancel {
                result.is_pending()
            } else {
                matches!(result, Poll::Ready(Err(radio::Error::Unsupported)))
                    && fixture.stopped
                    && fixture.done
            };
            if !failed_as_expected
                || model.inner.inner.retained.is_none()
                || model.inner.storage.as_ref().unwrap().filled != 1023
                || r.prepare_active_scan(&[2412, 2437], &names, &station_tests::policy())
                    .is_ok()
                || r.information_elements([2, 8, 9, 10, 11, 12]).is_some()
            {
                return TestResult::Fail(
                    "maximum IE/SSID failure reopened owner, exposed cache or freed DMA",
                );
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/active-scan",
    smoke_ath10k_probe_ies_sixteen_ssids_cancel_and_policy_failure_retain_dma
);
