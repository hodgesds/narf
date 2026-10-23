use super::*;
use alloc::{vec, vec::Vec};
use core::{
    future::Future,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

// Full INIT packet goldens were emitted by compiling Linux's packed resource
// declarations with named field initializers (wmi.c gen_init variants), not by
// the Rust encoder. Numeric offsets/events below come from that same C oracle.
include!("init_golden.rs");
fn u32at(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn header(eid: u8, body: &[u8]) -> Vec<u8> {
    let mut frame = vec![eid, 0, 0, 0, 0, 0, 0, 0];
    frame[2..4].copy_from_slice(&(body.len() as u16).to_le_bytes());
    frame.extend_from_slice(body);
    frame
}
fn item(out: &mut Vec<u8>, tag: u16, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
    out.extend_from_slice(&tag.to_le_bytes());
    out.extend_from_slice(bytes);
}
fn literal_abi() -> Vec<u8> {
    vec![
        0, 0, 0, 1, 53, 0, 0, 0, 0x51, 0x43, 0x41, 0x5f, 0x4d, 0x4c, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ]
}
fn service_fixture(d: Dialect) -> Vec<u8> {
    let mut bitmap = vec![0u8; 64];
    // Legacy BSS_CHANNEL_INFO_64=25 (word6/bit1), PEER_CACHING=37
    // (word9/bit1), TLV RX_FULL_REORDER=65 (extended word0/bit1).
    for at in [0, 24, 36] {
        u32at(&mut bitmap, at, 2);
    }
    let mut reg = vec![0u8; 36];
    for (at, value) in [(0, 0x64), (20, 2412), (24, 2462), (28, 5180), (32, 5825)] {
        u32at(&mut reg, at, value);
    }
    let requests: [[u32; 4]; 4] = [
        [17, 5, 1, 127],
        [18, 8, 4, 127],
        [19, 1, 0, 3],
        [20, 1, 0, 0],
    ];
    let mut mem = Vec::new();
    for req in requests {
        let mut raw = Vec::new();
        for value in req {
            raw.extend_from_slice(&value.to_le_bytes());
        }
        if d == Dialect::Tlv {
            item(&mut mem, 34, &raw);
        } else {
            mem.extend_from_slice(&raw);
        }
    }
    if d == Dialect::Tlv {
        let mut ev = vec![0u8; 104];
        ev[4..28].copy_from_slice(&literal_abi());
        u32at(&mut ev, 36, 2);
        u32at(&mut ev, 40, 0x1234);
        u32at(&mut ev, 56, 20);
        u32at(&mut ev, 72, 4);
        let mut result = Vec::new();
        for (tag, body) in [(32, ev), (33, reg), (16, bitmap), (18, mem)] {
            item(&mut result, tag, &body);
        }
        result
    } else {
        let main = matches!(d, Dialect::Main | Dialect::TenFour);
        let mut result = vec![0u8; if main { 160 } else { 152 }];
        let rf = if main { 84 } else { 80 };
        u32at(&mut result, rf, 2);
        u32at(&mut result, rf + 4, 0x1234);
        u32at(&mut result, rf + 20, 20);
        result[rf - 64..rf].copy_from_slice(&bitmap);
        result[rf + 24..rf + 60].copy_from_slice(&reg);
        let count = if main { 156 } else { 148 };
        u32at(&mut result, count, 4);
        result.extend_from_slice(&mem);
        result
    }
}
fn ready_fixture(d: Dialect) -> Vec<u8> {
    let offset = if d == Dialect::Tlv { 24 } else { 8 };
    let mut ready = vec![0; offset + 12];
    if d == Dialect::Tlv {
        ready[..24].copy_from_slice(&literal_abi());
    } else {
        ready[..8].copy_from_slice(&[1, 0, 0, 0, 2, 0, 0, 0]);
    }
    ready[offset..offset + 6].copy_from_slice(&[2, 3, 4, 5, 6, 7]);
    if d == Dialect::Tlv {
        let mut bytes = Vec::new();
        item(&mut bytes, 35, &ready);
        bytes
    } else {
        ready
    }
}
fn event(d: Dialect, ready: bool) -> Vec<u8> {
    let mut bytes = Vec::new();
    let id = if matches!(d, Dialect::Main | Dialect::Tlv) {
        1u32
    } else {
        0x8000
    };
    bytes.extend_from_slice(&(id + u32::from(ready)).to_le_bytes());
    bytes.extend_from_slice(&if ready {
        ready_fixture(d)
    } else {
        service_fixture(d)
    });
    bytes
}
#[derive(Debug)]
struct Model {
    dialect: Dialect,
    rx: VecDeque<(u8, Vec<u8>)>,
    sent: Vec<(u8, Vec<u8>)>,
    retained: Option<Vec<MemoryPlan>>,
    expected: &'static [u8],
    stall_init: bool,
}
impl Model {
    fn new(dialect: Dialect) -> Self {
        let expected = match dialect {
            Dialect::Main => INIT_MAIN,
            Dialect::TenOne => INIT_TEN_ONE,
            Dialect::TenTwo | Dialect::TenTwoFour => INIT_TEN_TWO,
            Dialect::Tlv => INIT_TLV,
            Dialect::TenFour => INIT_TEN_FOUR,
        };
        Self {
            dialect,
            rx: VecDeque::from([(1, header(0, &[1, 0, 32, 0, 0, 1, 9, 0]))]),
            sent: Vec::new(),
            retained: None,
            expected,
            stall_init: false,
        }
    }
}
impl HostMemory for Model {
    fn retain_wmi_memory(&mut self, plans: &[MemoryPlan]) -> Result<Vec<MemoryChunk>, Error> {
        if self.retained.is_some() {
            return Err(Error::Failed);
        }
        self.retained = Some(plans.to_vec());
        Ok(plans
            .iter()
            .enumerate()
            .map(|(i, p)| MemoryChunk {
                id: p.id,
                address: 0x1000000 + i as u32 * 0x10000,
                bytes: p.bytes,
            })
            .collect())
    }
}
impl Hif for Model {
    async fn receive(&mut self, _: u64) -> Result<(u8, Vec<u8>), super::super::bmi::BmiError> {
        self.rx
            .pop_front()
            .ok_or(super::super::bmi::BmiError::Timeout)
    }
    async fn send(&mut self, pipe: u8, bytes: &[u8]) -> Result<(), super::super::bmi::BmiError> {
        use super::super::bmi::BmiError;
        self.sent.push((pipe, bytes.to_vec()));
        if pipe == 0 {
            if bytes == [0, 0, 8, 0, 0, 0, 0, 0, 2, 0, 0, 3, 8, 0, 0, 0] {
                self.rx.push_back((1, header(0, &[3, 0, 0, 3, 0, 1, 0, 1])));
            } else if bytes == [0, 0, 8, 0, 0, 1, 0, 0, 2, 0, 0, 1, 0, 32, 0, 0] {
                self.rx
                    .push_back((2, header(2, &event(self.dialect, false))));
                self.rx.push_back((1, header(0, &[3, 0, 0, 1, 0, 2, 0, 8])));
            } else if bytes != [0, 0, 12, 0, 0, 2, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] {
                return Err(BmiError::BadResponse);
            }
        } else {
            if pipe != 3
                || bytes.get(0..2) != Some(&[2, 1])
                || bytes[5] != 0
                || bytes[8..] != *self.expected
                || self.retained.is_none()
            {
                return Err(BmiError::BadResponse);
            }
            if self.stall_init {
                core::future::pending::<()>().await;
            }
            self.rx
                .push_back((2, header(2, &event(self.dialect, true))));
        }
        Ok(())
    }
}
fn once<F: Future>(f: F) -> Poll<F::Output> {
    let mut f = core::pin::pin!(f);
    f.as_mut().poll(&mut Context::from_waker(Waker::noop()))
}
fn smoke_ath10k_wmi_owned_init_all_dialects() -> TestResult {
    for (version, dialect) in [
        (1, Dialect::Main),
        (2, Dialect::TenOne),
        (3, Dialect::TenTwo),
        (4, Dialect::Tlv),
        (5, Dialect::TenTwoFour),
        (6, Dialect::TenFour),
    ] {
        let mut htc = Session::new(Model::new(dialect), HwRev::Qca9984);
        if once(htc.start()) != Poll::Ready(Ok(())) {
            return TestResult::Fail("actual HTC service handshake failed before WMI");
        }
        let mut wmi = Runtime::new(
            htc,
            Dialect::from_version(version).unwrap(),
            HwRev::Qca9984,
            0,
        );
        let result = once(wmi.start());
        if !matches!(
            result,
            Poll::Ready(Ok(Ready {
                mac: [2, 3, 4, 5, 6, 7],
                ..
            }))
        ) {
            return TestResult::Fail(
                "service-ready→retained memory→native INIT golden→READY failed",
            );
        }
        let caps = wmi.caps.as_ref().unwrap();
        if caps.rf_chains != 2
            || caps.ht != 0x1234
            || caps.low_2ghz != 2412
            || caps.high_5ghz != 5825
            || caps.max_tx_power != 20
        {
            return TestResult::Fail("native service-ready capability offsets wrong");
        }
        let chunks = wmi.htc.transport.retained.as_ref().unwrap();
        if chunks.len() != 3
            || chunks[2] != (MemoryPlan { id: 19, bytes: 12 })
            || once(wmi.start()) != Poll::Ready(Err(Error::Failed))
        {
            return TestResult::Fail(
                "resource-dependent memory alignment/zero-unit skip or one-shot state wrong",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/wmi-runtime",
    smoke_ath10k_wmi_owned_init_all_dialects
);
fn smoke_ath10k_wmi_cancelled_init_retains_owner() -> TestResult {
    let mut model = Model::new(Dialect::Tlv);
    model.stall_init = true;
    let mut htc = Session::new(model, HwRev::Qca6174);
    assert_eq!(once(htc.start()), Poll::Ready(Ok(())));
    let mut wmi = Runtime::new(htc, Dialect::Tlv, HwRev::Qca6174, 0);
    if once(wmi.start()) != Poll::Pending
        || wmi
            .htc
            .transport
            .retained
            .as_ref()
            .is_none_or(|p| p.len() != 3)
    {
        return TestResult::Fail("INIT cancellation did not publish retained memory");
    }
    let sent = wmi.htc.transport.sent.len();
    if once(wmi.start()) != Poll::Ready(Err(Error::Failed))
        || wmi.htc.transport.sent.len() != sent
        || wmi.ready.is_some()
    {
        return TestResult::Fail("cancelled INIT replayed or opened ready state");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/wmi-runtime",
    smoke_ath10k_wmi_cancelled_init_retains_owner
);
fn smoke_ath10k_wmi_native_bounds_abi_and_resources() -> TestResult {
    let tlv = service_fixture(Dialect::Tlv);
    for end in 0..tlv.len() {
        if service_ready(Dialect::Tlv, &tlv[..end]).is_ok() {
            return TestResult::Fail("truncated TLV service-ready accepted");
        }
    }
    let mut bad = tlv.clone();
    bad[8] ^= 1;
    if !matches!(service_ready(Dialect::Tlv, &bad), Err(Error::Abi)) {
        return TestResult::Fail("unsupported TLV ABI admitted");
    }
    for d in [Dialect::Main, Dialect::TenOne, Dialect::TenFour] {
        let mut bad = service_fixture(d);
        let count = if d == Dialect::TenOne { 148 } else { 156 };
        u32at(&mut bad, count, 17);
        if !matches!(service_ready(d, &bad), Err(Error::Memory)) {
            return TestResult::Fail("host memory request count exceeded16");
        }
    }
    let service = service_ready(Dialect::TenFour, &service_fixture(Dialect::TenFour)).unwrap();
    let cfg = resources(Dialect::TenFour, HwRev::Qca9888, &service.caps, 1 << 13).unwrap();
    if cfg.peers != 528
        || cfg.active_peers != 51
        || cfg.words[6] != 102
        || cfg.words[8] != 3
        || cfg.words[29] != 2500
    {
        return TestResult::Fail("10.4 PFC/cache/two-chain native resource profile wrong");
    }
    let req = MemoryRequest {
        id: 99,
        unit_size: 5,
        flags: 7,
        units: 999,
    };
    if memory_plans(&[req], &cfg) != Ok(vec![MemoryPlan { id: 99, bytes: 416 }])
        || memory_plans(
            &[MemoryRequest {
                unit_size: u32::MAX,
                ..req
            }],
            &cfg,
        ) != Err(Error::Memory)
    {
        return TestResult::Fail("memory resource flag priority or size overflow wrong");
    }
    let mut ready_bad = ready_fixture(Dialect::Main);
    u32at(&mut ready_bad, 16, 7);
    if ready(Dialect::Main, &ready_bad) != Err(Error::Firmware(7)) {
        return TestResult::Fail("nonzero firmware READY status admitted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/wmi-runtime",
    smoke_ath10k_wmi_native_bounds_abi_and_resources
);
