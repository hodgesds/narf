use super::*;
use alloc::{sync::Arc, vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

#[derive(Default)]
struct Model {
    next: u64,
    rx: Option<u64>,
    tx: Option<u64>,
    rx_result: Option<Result<Vec<u8>, UsbError>>,
    tx_result: Option<Result<usize, UsbError>>,
    posted: Vec<(u8, usize)>,
    sent: Vec<(u8, Vec<u8>)>,
    unsafe_reuse: usize,
    polls: usize,
    stops: Vec<u64>,
    pause_stop: bool,
}
#[derive(Clone)]
struct Fake(Arc<IrqSafeSpinLock<Model>>);
impl Fake {
    fn new() -> Self {
        Self(Arc::new(IrqSafeSpinLock::new(Model::default())))
    }
}
struct Receipt(u64);
#[async_trait::async_trait]
impl Io for Fake {
    type Receipt = Receipt;
    fn begin_receive(&self, dci: u8, length: usize) -> Result<Receipt, UsbError> {
        let mut m = self.0.lock();
        if m.rx.is_some() {
            m.unsafe_reuse += 1;
            return Err(UsbError::Stall);
        }
        m.next += 1;
        let id = m.next;
        m.rx = Some(id);
        m.posted.push((dci, length));
        Ok(Receipt(id))
    }
    fn poll_receive(&self, r: &Receipt, out: &mut [u8]) -> Result<Option<usize>, UsbError> {
        let mut m = self.0.lock();
        m.polls += 1;
        if m.rx != Some(r.0) {
            return Err(UsbError::Stall);
        }
        let Some(value) = m.rx_result.take() else {
            return Ok(None);
        };
        let bytes = value?;
        out[..bytes.len()].copy_from_slice(&bytes);
        m.rx = None;
        Ok(Some(bytes.len()))
    }
    fn begin_send(&self, dci: u8, bytes: &[u8]) -> Result<Receipt, UsbError> {
        let mut m = self.0.lock();
        if m.tx.is_some() {
            m.unsafe_reuse += 1;
            return Err(UsbError::Stall);
        }
        m.next += 1;
        let id = m.next;
        m.tx = Some(id);
        m.sent.push((dci, bytes.to_vec()));
        Ok(Receipt(id))
    }
    fn poll_send(&self, r: &Receipt) -> Result<Option<usize>, UsbError> {
        let mut m = self.0.lock();
        m.polls += 1;
        if m.tx != Some(r.0) {
            return Err(UsbError::Stall);
        }
        let Some(value) = m.tx_result.take() else {
            return Ok(None);
        };
        let len = value?;
        m.tx = None;
        Ok(Some(len))
    }
    async fn stop(&self, r: &Receipt) -> Result<(), UsbError> {
        let pause = {
            let mut m = self.0.lock();
            m.stops.push(r.0);
            m.pause_stop
        };
        if pause {
            core::future::pending::<()>().await;
        }
        let mut m = self.0.lock();
        if m.rx == Some(r.0) {
            m.rx = None;
            Ok(())
        } else if m.tx == Some(r.0) {
            m.tx = None;
            Ok(())
        } else {
            Err(UsbError::Stall)
        }
    }
}
fn endpoints(n: u8) -> Endpoints {
    Endpoints {
        input: 0x81,
        output: [2, 3, 4],
        output_count: n,
        input_packet: 512,
        output_packets: [512; 3],
    }
}
fn frame(kind: Kind) -> Vec<u8> {
    let mut f = vec![0; 30];
    f[0] = if kind == Kind::Management { 0xb0 } else { 8 };
    f[1] = if kind == Kind::Data { 1 } else { 0 };
    f[4..10].copy_from_slice(&[2, 0, 0, 0, 0, 2]);
    f[10..16].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
    f[16..22].copy_from_slice(&[2, 0, 0, 0, 0, 2]);
    f[22..24].copy_from_slice(&0x1230u16.to_le_bytes());
    f
}
fn descriptor(body: &[u8], kind: u8, info: usize, shift: usize, count: u8) -> Vec<u8> {
    let mut out = vec![0; 24 + info + shift + body.len()];
    let d0 = body.len() as u32
        | ((info / 8) as u32) << 16
        | (shift as u32) << 24
        | 1 << 26
        | 1 << 27
        | 1 << 28
        | 1 << 29;
    out[..4].copy_from_slice(&d0.to_le_bytes());
    out[4..8].copy_from_slice(&(7u32 << 5).to_le_bytes());
    out[8..12].copy_from_slice(&(u32::from(count) << 16).to_le_bytes());
    out[12..16].copy_from_slice(&(u32::from(kind) << 14 | 3).to_le_bytes());
    out[20..24].copy_from_slice(&0x12345678u32.to_le_bytes());
    out[24..24 + info].fill(0x55);
    out[24 + info + shift..].copy_from_slice(body);
    out
}
fn smoke_rtl8188eu_native_rx_24byte_shift_report_and_128_alignment() -> TestResult {
    let mpdu = frame(Kind::Management);
    let mut bytes = descriptor(&mpdu, 0, 32, 2, 3);
    bytes.resize(128, 0xee);
    let mut report = descriptor(&[0xb0; 16], 1, 0, 0, 0);
    report.resize(128, 0xdd);
    bytes.extend_from_slice(&report);
    bytes.extend_from_slice(&descriptor(&mpdu, 0, 0, 0, 0));
    let got = packet_codec::receive(&bytes).unwrap();
    if got.len() != 3
        || !matches!(&got[0],Record::Frame(f)if f.bytes==mpdu&&f.phy==[0x55;32]&&f.timestamp==0x12345678&&f.rate==3&&f.tid==7&&!f.decrypted)
        || !matches!(&got[1],Record::Report{kind:1,bytes}if bytes==&[0xb0;16])
        || !matches!(&got[2],Record::Frame(f)if f.bytes==mpdu)
    {
        return TestResult::Fail(
            "native RX descriptor, shift, alignment or report separation wrong",
        );
    }
    let report = descriptor(&[0xb0; 16], 2, 8, 2, 1);
    if !matches!(&packet_codec::receive(&report).unwrap()[0],
        Record::Report { kind:2, bytes } if bytes.len()==26
            && bytes[..8]==[0x55;8] && bytes[10..]==[0xb0;16])
    {
        return TestResult::Fail("report path incorrectly removed MPDU-only PHY/shift prefix");
    }
    let mut bad = descriptor(&mpdu, 0, 0, 0, 1);
    bad[1] |= 0x40;
    if !packet_codec::receive(&bad).unwrap().is_empty() {
        return TestResult::Fail("CRC-bad MPDU reached native dispatch");
    }
    for remove in [1, 12, 24] {
        let mut bad = descriptor(&mpdu, 0, 32, 2, 1);
        bad.truncate(bad.len() - remove);
        if packet_codec::receive(&bad).is_ok() {
            return TestResult::Fail("truncated descriptor/info/native MPDU accepted");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/packet",
    smoke_rtl8188eu_native_rx_24byte_shift_report_and_128_alignment
);
fn smoke_rtl8188eu_native_tx_linux_descriptor_vector() -> TestResult {
    let frame = frame(Kind::Management);
    let bytes = packet_codec::transmit(&frame, Kind::Management).unwrap();
    let expected = [
        0x1e, 0, 0x20, 0x8c, 0, 0x12, 0, 0, 0, 0, 1, 3, 0, 0, 0x23, 1, 0, 1, 0, 0, 0, 0, 0x1a, 0,
        0, 0, 0, 0, 6, 0xbd, 0, 0x20,
    ];
    if bytes[..32] != expected || bytes[32..] != frame {
        return TestResult::Fail("Linux txdesc32 fixed-rate/sequence/antenna/checksum vector");
    }
    let checksum = bytes[..32]
        .chunks_exact(2)
        .fold(0u16, |v, b| v ^ u16::from_le_bytes([b[0], b[1]]));
    if checksum != 0 {
        return TestResult::Fail("TX descriptor checksum does not cover all32 bytes");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/packet",
    smoke_rtl8188eu_native_tx_linux_descriptor_vector
);
fn smoke_rtl8188eu_persistent_quiet_rx_and_serialized_tx() -> TestResult {
    for n in 1..=3 {
        let io = Fake::new();
        let mut owner = Owner::new(io.clone(), endpoints(n), 6).unwrap();
        owner.start().unwrap();
        for _ in 0..1000 {
            if owner.poll_receive() != Ok(None) {
                return TestResult::Fail("quiet persistent RX became error");
            }
        }
        if io.0.lock().posted != [(3, 4096)] {
            return TestResult::Fail("quiet RX was cancelled/reposted");
        }
        for kind in [Kind::Management, Kind::Data] {
            let native = frame(kind);
            owner.submit(kind, &native).unwrap();
            if owner.submit(kind, &native) != Err(Error::Busy) {
                return TestResult::Fail("in-flight TX was overwritten");
            }
            for _ in 0..10 {
                if owner.poll_transmit() != Ok(None) {
                    return TestResult::Fail("pending TX reported completion");
                }
            }
            let (dci, bytes) = io.0.lock().sent.last().cloned().unwrap();
            let expected = if kind == Kind::Management {
                4
            } else {
                (n + 1) * 2
            };
            if dci != expected || bytes[32..] != native {
                return TestResult::Fail("endpoint-count queue mapping/native TX bytes");
            }
            io.0.lock().tx_result = Some(Ok(bytes.len()));
            if owner.poll_transmit()
                != Ok(Some(Delivered {
                    native_bytes: native.len(),
                }))
            {
                return TestResult::Fail("USB TX terminal delivery length");
            }
        }
        let native = frame(Kind::Management);
        io.0.lock().rx_result = Some(Ok(descriptor(&native, 0, 32, 1, 1)));
        if !matches!(owner.poll_receive(),Ok(Some(records))if matches!(&records[0],Record::Frame(f)if f.bytes==native))
        {
            return TestResult::Fail("terminal RX not parsed/reposted");
        }
        if io.0.lock().posted.len() != 2 || io.0.lock().unsafe_reuse != 0 {
            return TestResult::Fail("completed RX failed exact receipt reuse");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/packet",
    smoke_rtl8188eu_persistent_quiet_rx_and_serialized_tx
);
fn smoke_rtl8188eu_packet_error_and_drop_retain_td() -> TestResult {
    for receive in [false, true] {
        let io = Fake::new();
        let mut owner = Owner::new(io.clone(), endpoints(3), 1).unwrap();
        owner.start().unwrap();
        if receive {
            io.0.lock().rx_result = Some(Err(UsbError::Stall));
            if owner.poll_receive() != Err(Error::Usb(UsbError::Stall)) {
                return TestResult::Fail("RX transport error ignored");
            }
        } else {
            owner
                .submit(Kind::Management, &frame(Kind::Management))
                .unwrap();
            io.0.lock().tx_result = Some(Err(UsbError::Stall));
            if owner.poll_transmit() != Err(Error::Usb(UsbError::Stall)) {
                return TestResult::Fail("TX transport error ignored");
            }
        }
        let saved = {
            let m = io.0.lock();
            (m.posted.len(), m.sent.len(), m.polls)
        };
        if owner.poll_receive() != Err(Error::Failed)
            || owner.submit(Kind::Management, &frame(Kind::Management)) != Err(Error::Failed)
            || owner.poll_transmit() != Err(Error::Failed)
        {
            return TestResult::Fail("poisoned owner continued USB operations");
        }
        drop(owner);
        let m = io.0.lock();
        if saved != (m.posted.len(), m.sent.len(), m.polls)
            || m.rx.is_none()
            || (!receive && m.tx.is_none())
            || m.unsafe_reuse != 0
        {
            return TestResult::Fail("error/Drop retired active TD without quiescence");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/packet",
    smoke_rtl8188eu_packet_error_and_drop_retain_td
);

fn smoke_rtl8188eu_packet_stop_future_cancellation_is_terminal() -> TestResult {
    use core::{
        future::Future,
        task::{Context, Poll, Waker},
    };
    let io = Fake::new();
    let mut owner = Owner::new(io.clone(), endpoints(3), 6).unwrap();
    owner.start().unwrap();
    owner
        .submit(Kind::Management, &frame(Kind::Management))
        .unwrap();
    io.0.lock().pause_stop = true;
    {
        let mut future = Box::pin(owner.stop());
        if !matches!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Pending
        ) {
            return TestResult::Fail("submitted stop did not reach pending ownership");
        }
    }
    if !owner.is_failed()
        || owner.start() != Err(Error::Failed)
        || owner.poll_receive() != Err(Error::Failed)
    {
        return TestResult::Fail("dropped packet stop allowed live endpoint reuse");
    }
    let m = io.0.lock();
    if m.stops.len() != 1
        || m.rx.is_none()
        || m.tx.is_none()
        || m.posted.len() != 1
        || m.unsafe_reuse != 0
    {
        return TestResult::Fail("cancelled packet stop dropped active receipts/reposted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/packet",
    smoke_rtl8188eu_packet_stop_future_cancellation_is_terminal
);
fn smoke_rtl8188eu_packet_stop_allows_only_after_terminal_quiescence() -> TestResult {
    let io = Fake::new();
    let mut owner = Owner::new(io.clone(), endpoints(2), 6).unwrap();
    owner.start().unwrap();
    owner
        .submit(Kind::Management, &frame(Kind::Management))
        .unwrap();
    if narf_scheduler::block_on(owner.stop()).is_err()
        || owner.is_failed()
        || owner.channel() != 6
        || owner.receive.is_some()
        || owner.transmit.is_some()
    {
        return TestResult::Fail("proven stop retained invalid receipt state");
    }
    owner.start().unwrap();
    let m = io.0.lock();
    if m.stops.len() != 2 || m.posted.len() != 2 || m.tx.is_some() || m.unsafe_reuse != 0 {
        return TestResult::Fail("post-quiescence packet reuse unsafe");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/packet",
    smoke_rtl8188eu_packet_stop_allows_only_after_terminal_quiescence
);
