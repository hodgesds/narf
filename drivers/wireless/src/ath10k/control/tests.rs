use super::*;
use alloc::{vec, vec::Vec};
use core::{
    future::Future,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

#[derive(Default, Debug)]
struct Model {
    wire: Vec<(u8, Vec<u8>)>,
    rx: VecDeque<(u8, Vec<u8>)>,
    stall: bool,
    duplicate: bool,
    wmi_sent: u8,
}
fn wire(eid: u8, body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![eid, 0, body.len() as u8, 0, 0, 0, 0, 0];
    bytes.extend_from_slice(body);
    bytes
}
impl Model {
    fn new() -> Self {
        let mut m = Self::default();
        m.rx.push_back((1, wire(0, &[1, 0, 2, 0, 16, 0, 9, 0])));
        m
    }
}
impl Hif for Model {
    async fn receive(&mut self, _: u64) -> Result<(u8, Vec<u8>), BmiError> {
        self.rx.pop_front().ok_or(BmiError::Timeout)
    }
    async fn send(&mut self, pipe: u8, bytes: &[u8]) -> Result<(), BmiError> {
        self.wire.push((pipe, bytes.to_vec()));
        if self.stall {
            core::future::pending::<()>().await;
        }
        // Literal Linux HTC header/message bytes, independent of the encoder.
        if pipe == 0 {
            if bytes == [0, 0, 8, 0, 0, 0, 0, 0, 2, 0, 0, 3, 8, 0, 0, 0] {
                self.rx.push_back((1, wire(0, &[3, 0, 0, 3, 0, 1, 0, 1])));
            } else if bytes == [0, 0, 8, 0, 0, 1, 0, 0, 2, 0, 0, 1, 0, 2, 0, 0] {
                // WMI service-ready can race its endpoint's connect response.
                self.rx.push_back((2, wire(2, &[1, 0, 0, 0])));
                self.rx.push_back((
                    1,
                    wire(
                        0,
                        &[3, 0, 0, 1, 0, if self.duplicate { 1 } else { 2 }, 0, 8],
                    ),
                ));
            } else if bytes != [0, 0, 12, 0, 0, 2, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] {
                return Err(BmiError::BadResponse);
            }
        } else {
            if pipe != 3 || bytes[0] != 2 || bytes[1] != 1 || bytes[5] != self.wmi_sent {
                return Err(BmiError::BadResponse);
            }
            self.wmi_sent += 1;
            if self.wmi_sent == 2 {
                self.rx
                    .push_back((2, vec![2, 2, 8, 0, 8, 0, 0, 0, 1, 4, 0, 0, 2, 2, 0, 0]));
            }
        }
        Ok(())
    }
}
fn once<F: Future>(f: F) -> Poll<F::Output> {
    let mut f = core::pin::pin!(f);
    f.as_mut().poll(&mut Context::from_waker(Waker::noop()))
}
fn smoke_ath10k_htc_owned_wire_and_credit_progress() -> TestResult {
    for hardware in [HwRev::Qca988x, HwRev::Qca6174] {
        let mut session = Session::new(Model::new(), hardware);
        if once(session.start()) != Poll::Ready(Ok(())) || session.wmi != 2 || session.htt != 1 {
            return TestResult::Fail(
                "HTC READY/connect/setup bytes or endpoint assignment differ from Linux",
            );
        }
        if once(session.receive()) != Poll::Ready(Ok((2, vec![1, 0, 0, 0]))) {
            return TestResult::Fail("early WMI service-ready lost during connect");
        }
        for _ in 0..3 {
            if once(session.send_wmi(&[0x11; 8])) != Poll::Ready(Ok(())) {
                return TestResult::Fail("WMI did not progress returned HTC credits");
            }
        }
        if session.endpoints[2].credits != 1 || session.transport.wmi_sent != 3 {
            return TestResult::Fail("WMI credit accounting wrong");
        }
        let pipe = if hardware == HwRev::Qca6174 { 1 } else { 5 };
        session.transport.rx.push_back((pipe, wire(1, &[7, 8])));
        if once(session.receive()) != Poll::Ready(Ok((1, vec![7, 8]))) {
            return TestResult::Fail("HTT endpoint routed to wrong per-family CE");
        }
        session
            .transport
            .rx
            .push_back((2, vec![2, 2, 8, 0, 8, 0, 0, 0, 1, 8, 0, 0, 2, 2, 0, 0]));
        if once(session.receive()) != Poll::Ready(Err(Error::Malformed))
            || once(session.send_wmi(&[0x11; 8])) != Poll::Ready(Err(Error::Failed))
        {
            return TestResult::Fail("malformed HTC trailer did not close session");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/control",
    smoke_ath10k_htc_owned_wire_and_credit_progress
);
fn smoke_ath10k_htc_duplicate_and_cancel_are_terminal() -> TestResult {
    let mut model = Model::new();
    model.duplicate = true;
    let mut session = Session::new(model, HwRev::Qca988x);
    if once(session.start()) != Poll::Ready(Err(Error::Malformed))
        || session.transport.wire.len() != 2
    {
        return TestResult::Fail("duplicate HTC endpoint accepted or setup continued");
    }
    let mut model = Model::new();
    model.stall = true;
    let mut session = Session::new(model, HwRev::Qca988x);
    if once(session.start()) != Poll::Pending {
        return TestResult::Fail("HTC cancellation fixture did not publish");
    }
    let sent = session.transport.wire.len();
    if once(session.start()) != Poll::Ready(Err(Error::Failed))
        || session.transport.wire.len() != sent
    {
        return TestResult::Fail("cancelled HTC start was replayed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/control",
    smoke_ath10k_htc_duplicate_and_cancel_are_terminal
);
