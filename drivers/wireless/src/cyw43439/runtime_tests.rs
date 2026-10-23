use super::super::{Function, Transport};
use super::*;
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

#[derive(Default)]
struct Bus {
    rx: VecDeque<Vec<u8>>,
    tx: Vec<Vec<u8>>,
    auto_reply: bool,
    fail_write: bool,
    header_only: bool,
    firmware_error: Option<u32>,
}
impl Transport for Bus {
    fn read32(&mut self, _: Function, _: u32) -> Result<u32, TransportError> {
        Ok(0)
    }
    fn write32(&mut self, _: Function, _: u32, _: u32) -> Result<(), TransportError> {
        Ok(())
    }
    fn read_burst(&mut self, _: Function, _: u32, _: &mut [u8]) -> Result<(), TransportError> {
        Err(TransportError::NotReady)
    }
    fn write_burst(&mut self, _: Function, _: u32, _: &[u8]) -> Result<(), TransportError> {
        Err(TransportError::NotReady)
    }
}
impl PacketTransport for Bus {
    fn receive_packet(&mut self, out: &mut [u8]) -> Result<usize, TransportError> {
        let Some(packet) = self.rx.pop_front() else {
            return Ok(0);
        };
        out[..packet.len()].copy_from_slice(&packet);
        Ok(packet.len())
    }
    fn transmit_packet(&mut self, packet: &[u8]) -> Result<(), TransportError> {
        if self.fail_write {
            return Err(TransportError::Timeout);
        }
        self.tx.push(packet.to_vec());
        if self.auto_reply {
            let request = BcdcHeader::decode(&packet[12..]).unwrap();
            // A stale ERROR reply must not terminate the matching waiter.
            let mut stale = request;
            stale.flags ^= 1 << 16;
            stale.flags |= bcdc_flag::ERROR;
            stale.status = 9;
            stale.len = 0;
            self.rx
                .push_back(frame(1, CHANNEL_CONTROL, 8, &stale.encode()));
            // Events/data interleaved before a reply must stay in their queues.
            let mut data = vec![0x20, 0, 0, 0];
            data.extend_from_slice(&ethernet());
            self.rx.push_back(frame(2, CHANNEL_DATA, 8, &data));
            let mut reply = request;
            if !self.header_only {
                reply.len = 4;
            }
            if let Some(error) = self.firmware_error {
                reply.flags |= bcdc_flag::ERROR;
                reply.status = error;
            }
            let mut body = reply.encode().to_vec();
            if !self.header_only {
                body.extend_from_slice(&[1, 2, 3, 4]);
            }
            self.rx.push_back(frame(3, CHANNEL_CONTROL, 8, &body));
        }
        Ok(())
    }
}

fn frame(sequence: u8, channel: u8, maximum: u8, payload: &[u8]) -> Vec<u8> {
    let length = 12 + payload.len();
    let mut out = HwHeader {
        length: length as u16,
    }
    .encode()
    .to_vec();
    out.extend_from_slice(
        &SwHeader {
            seq: sequence,
            channel,
            flags: 0,
            next_len_16: 0,
            data_offset: 12,
            fc_mask: 0,
            max_seq: maximum,
        }
        .encode(),
    );
    out.extend_from_slice(payload);
    out
}

fn ethernet() -> Vec<u8> {
    vec![2, 1, 2, 3, 4, 5, 2, 6, 7, 8, 9, 10, 8, 0, 11, 12]
}

fn ready<F: Future>(future: F) -> Option<F::Output> {
    let mut future = pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(value) => Some(value),
        Poll::Pending => None,
    }
}

fn smoke_cyw_f2_control_correlates_and_demultiplexes() -> TestResult {
    let mut bus = Bus {
        auto_reply: true,
        ..Bus::default()
    };
    bus.rx.push_back(frame(0, CHANNEL_CONTROL, 8, &[]));
    let mut runtime = Runtime::new(bus);
    if ready(runtime.command(ioctl::Direction::Get, 1, &[0; 4], 4)) != Some(Ok(vec![1, 2, 3, 4]))
        || runtime.pop_data() != Some(ethernet())
        || runtime.transport.tx.len() != 1
        || runtime.tx_sequence != 1
        || runtime.pending.is_some()
        || runtime.is_failed()
    {
        return TestResult::Fail("F2 IOCTL credit/correlation/data dispatch");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/cyw43439/runtime",
    smoke_cyw_f2_control_correlates_and_demultiplexes
);

fn smoke_cyw_f2_get_query_zero_fills_linux_wire_extent() -> TestResult {
    // Logical output lengths may exceed the 1502-byte transmit prefix.
    // Exact fixtures also cover a query input longer than its output value.
    for (command, input, maximum, logical, wire) in [
        (1, &[][..], 4usize, 4usize, 4usize),
        (217, &[64, 0, 0, 0][..], 260, 260, 260),
        (262, &b"country\0"[..], 4, 8, 8),
        (262, &b"dump\0"[..], 8192, 8192, 1502),
    ] {
        let mut runtime = Runtime::new(Bus {
            auto_reply: true,
            ..Bus::default()
        });
        runtime.tx_max = 8;
        if ready(runtime.command(ioctl::Direction::Get, command, input, maximum))
            != Some(Ok(vec![1, 2, 3, 4]))
        {
            return TestResult::Fail("query wire fixture did not complete");
        }
        let bytes = &runtime.transport.tx[0];
        let length = HwHeader::decode(bytes).unwrap().length as usize;
        let header = BcdcHeader::decode(&bytes[12..]).unwrap();
        if header.cmd != command
            || header.len != logical as u32
            || header.is_set()
            || length != 28 + wire
            || bytes.len() != length.next_multiple_of(4)
            || bytes[28..28 + input.len()] != *input
            || bytes[28 + input.len()..].iter().any(|&byte| byte != 0)
        {
            return TestResult::Fail(
                "GET advertised length, query prefix, or zero-filled wire extent wrong",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/cyw43439/runtime",
    smoke_cyw_f2_get_query_zero_fills_linux_wire_extent
);

fn smoke_cyw_f2_header_only_set_and_error_use_status() -> TestResult {
    let unsupported = (-23i32) as u32;
    for (direction, command, input, maximum, error, expected) in [
        (
            ioctl::Direction::Set,
            0x77,
            &[9; 12][..],
            1502,
            None,
            Ok(Vec::new()),
        ),
        (
            ioctl::Direction::Get,
            262,
            &b"sup_wpa\0"[..],
            4,
            Some(unsupported),
            Err(Error::Firmware(unsupported)),
        ),
    ] {
        let mut runtime = Runtime::new(Bus {
            auto_reply: true,
            header_only: true,
            firmware_error: error,
            ..Bus::default()
        });
        runtime.tx_max = 8;
        if ready(runtime.command(direction, command, input, maximum)) != Some(expected)
            || runtime.is_failed()
            || runtime.pending.is_some()
        {
            return TestResult::Fail(
                "header-only SET/error incorrectly required a reply information buffer",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/cyw43439/runtime",
    smoke_cyw_f2_header_only_set_and_error_use_status
);

fn smoke_cyw_f2_credit_wrap_and_priority_flow_control() -> TestResult {
    let mut runtime = Runtime::new(Bus::default());
    if runtime.send_data(&ethernet(), 0) != Err(Error::Busy) {
        return TestResult::Fail("TX used ungranted initial credit");
    }
    runtime.tx_sequence = 254;
    runtime
        .transport
        .rx
        .push_back(frame(0, CHANNEL_CONTROL, 3, &[]));
    if runtime.poll() != Ok(1) {
        return TestResult::Fail("credit wrap update");
    }
    runtime.flow_control = 1 << 5;
    if runtime.send_data(&ethernet(), 5) != Err(Error::Busy) {
        return TestResult::Fail("TX ignored per-priority stop");
    }
    for expected in [255, 0, 1] {
        if runtime.send_data(&ethernet(), 0).is_err() || runtime.tx_sequence != expected {
            return TestResult::Fail("TX credit sequence wrap");
        }
    }
    if runtime.send_data(&ethernet(), 0) != Err(Error::Busy)
        || runtime.transport.tx.len() != 3
        || runtime.transport.tx[0][4] != 254
        || runtime.transport.tx[0][12..16] != [0x20, 0, 0, 0]
    {
        return TestResult::Fail("data consumed reserved control credit or invalid BDC header");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/cyw43439/runtime",
    smoke_cyw_f2_credit_wrap_and_priority_flow_control
);

fn smoke_cyw_f2_cancel_and_bus_error_fail_session() -> TestResult {
    let mut runtime = Runtime::new(Bus::default());
    // The waiter drives RX and yields on the timer while awaiting a window.
    if ready(runtime.command(ioctl::Direction::Set, 2, &[], 0)).is_some()
        || !runtime.is_failed()
        || ready(runtime.command(ioctl::Direction::Get, 1, &[], 4)) != Some(Err(Error::Failed))
        || !runtime.transport.tx.is_empty()
    {
        return TestResult::Fail("cancelled control request could be replayed");
    }
    let mut runtime = Runtime::new(Bus {
        fail_write: true,
        ..Bus::default()
    });
    runtime.tx_max = 8;
    if runtime.send_data(&ethernet(), 0) != Err(Error::Transport(TransportError::Timeout))
        || !runtime.is_failed()
        || runtime.tx_sequence != 0
    {
        return TestResult::Fail("ambiguous failed write advanced sequence or stayed usable");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/cyw43439/runtime",
    smoke_cyw_f2_cancel_and_bus_error_fail_session
);

fn event_body() -> Vec<u8> {
    // Literal Linux brcmf_event envelope: Ethernet + vendor-long + v2 event.
    let mut bytes = vec![0; 4 + events::EVENT_ENVELOPE_LEN];
    bytes[..4].copy_from_slice(&[0x20, 0, 0, 0]);
    let e = &mut bytes[4..];
    e[12..14].copy_from_slice(&[0x88, 0x6c]);
    e[14..16].copy_from_slice(&[0x80, 1]);
    e[19..22].copy_from_slice(&[0, 0x10, 0x18]);
    e[22..24].copy_from_slice(&[0, 1]);
    e[24..26].copy_from_slice(&[0, 2]);
    e[28..32].copy_from_slice(&16u32.to_be_bytes());
    bytes
}

fn smoke_cyw_f2_bounded_events_and_bad_packets() -> TestResult {
    let event = event_body();
    let mut runtime = Runtime::new(Bus::default());
    for seq in 0..17 {
        runtime
            .transport
            .rx
            .push_back(frame(seq, CHANNEL_EVENT, 8, &event));
    }
    if runtime.poll() != Ok(16) || runtime.events.len() != 16 || runtime.transport.rx.len() != 1 {
        return TestResult::Fail("F2 worker exceeded RX budget");
    }
    if runtime.poll() != Ok(1) || runtime.pop_event().map(|e| e.header.event_type) != Some(16) {
        return TestResult::Fail("Linux event was not dispatched");
    }
    // Repeated sequence does not dispatch the last event twice.
    runtime
        .transport
        .rx
        .push_back(frame(16, CHANNEL_EVENT, 8, &event));
    if runtime.poll() != Ok(1) || runtime.events.len() != 16 {
        return TestResult::Fail("duplicate event dispatched twice");
    }
    for mut bad in [
        frame(0, CHANNEL_DATA, 8, &[0x20; 3]),
        frame(0, CHANNEL_DATA, 8, &[0x10; 20]),
        frame(0, CHANNEL_GLOM, 8, &[0; 20]),
    ] {
        let mut runtime = Runtime::new(Bus::default());
        runtime.transport.rx.push_back(bad.clone());
        if runtime.poll().is_ok() || !runtime.is_failed() {
            return TestResult::Fail("unsupported or malformed packet admitted");
        }
        bad[2] ^= 1;
        let mut runtime = Runtime::new(Bus::default());
        runtime.transport.rx.push_back(bad);
        if runtime.poll() != Err(Error::Malformed) {
            return TestResult::Fail("bad checksum accepted");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/cyw43439/runtime",
    smoke_cyw_f2_bounded_events_and_bad_packets
);
