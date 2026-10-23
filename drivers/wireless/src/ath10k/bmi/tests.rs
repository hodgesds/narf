use super::*;
use alloc::{collections::VecDeque, vec, vec::Vec};
use core::{
    future::Future,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

#[derive(Debug, Default)]
struct FakeTransport {
    requests: Vec<Vec<u8>>,
    responses: VecDeque<Result<Vec<u8>, BmiError>>,
}

impl Transport for FakeTransport {
    async fn exchange(&mut self, request: &[u8], response: &mut [u8]) -> Result<usize, BmiError> {
        self.requests.push(request.to_vec());
        let answer = self.responses.pop_front().unwrap_or(Ok(Vec::new()))?;
        let copied = answer.len().min(response.len());
        response[..copied].copy_from_slice(&answer[..copied]);
        Ok(answer.len())
    }
}

fn ready<F: Future>(future: F) -> Option<F::Output> {
    let mut future = core::pin::pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(value) => Some(value),
        Poll::Pending => None,
    }
}

fn smoke_ath10k_bmi_target_info_and_short_reply() -> TestResult {
    let mut bus = FakeTransport::default();
    bus.responses
        .push_back(Ok(vec![12, 0, 0, 0, 0x6c, 1, 0, 0x41, 8, 0, 0, 0]));
    let mut bmi = Bmi::new(bus);
    if ready(bmi.target_info())
        != Some(Ok(TargetInfo {
            version: 0x4100016c,
            target_type: 8,
        }))
        || bmi.transport.requests != [vec![8, 0, 0, 0]]
    {
        return TestResult::Fail("ath10k target-info exchange differs from Linux BMI");
    }
    for size in 0..12 {
        bmi.transport.responses.push_back(Ok(vec![0; size]));
        if ready(bmi.target_info()) != Some(Err(BmiError::BadResponse)) {
            return TestResult::Fail("ath10k accepted a truncated BMI target info");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/bmi",
    smoke_ath10k_bmi_target_info_and_short_reply
);

fn smoke_ath10k_bmi_write_chunks_and_zero_padding() -> TestResult {
    let mut bmi = Bmi::new(FakeTransport::default());
    if ready(bmi.write_memory(0x400800, &[0xab; 247])) != Some(Ok(())) {
        return TestResult::Fail("ath10k BMI memory write failed");
    }
    let calls = &bmi.transport.requests;
    if calls.len() != 2
        || calls[0].len() != 256
        || calls[1].len() != 16
        || calls[0][..12] != [3, 0, 0, 0, 0, 8, 0x40, 0, 244, 0, 0, 0]
        || calls[0][12..] != [0xab; 244]
        || calls[1]
            != [
                3, 0, 0, 0, 0xf4, 8, 0x40, 0, 4, 0, 0, 0, 0xab, 0xab, 0xab, 0,
            ]
    {
        return TestResult::Fail("ath10k BMI write chunk/address/padding wrong");
    }
    let before = calls.len();
    if ready(bmi.write_memory(u32::MAX - 1, &[1; 3])) != Some(Err(BmiError::AddressOverflow))
        || bmi.transport.requests.len() != before
    {
        return TestResult::Fail("overflowing BMI write reached the transport");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/bmi",
    smoke_ath10k_bmi_write_chunks_and_zero_padding
);

fn smoke_ath10k_bmi_read_chunks_and_short_reply() -> TestResult {
    let mut bus = FakeTransport::default();
    bus.responses.push_back(Ok(vec![0x55; 256]));
    bus.responses.push_back(Ok(vec![0x66; 3]));
    let mut bmi = Bmi::new(bus);
    let mut out = [0; 259];
    if ready(bmi.read_memory(0x400800, &mut out)) != Some(Ok(()))
        || out[..256] != [0x55; 256]
        || out[256..] != [0x66; 3]
        || bmi.transport.requests[1] != [2, 0, 0, 0, 0, 9, 0x40, 0, 3, 0, 0, 0]
    {
        return TestResult::Fail("ath10k BMI read chunk/address/copy wrong");
    }
    bmi.transport.responses.push_back(Ok(vec![1; 3]));
    if ready(bmi.read_u32(0x400800)) != Some(Err(BmiError::BadResponse)) {
        return TestResult::Fail("ath10k BMI read accepted short completion");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/bmi",
    smoke_ath10k_bmi_read_chunks_and_short_reply
);

fn smoke_ath10k_bmi_compressed_download_and_done_gate() -> TestResult {
    let mut bmi = Bmi::new(FakeTransport::default());
    if ready(bmi.fast_download(0x1234, &[0xab; 251])) != Some(Ok(())) {
        return TestResult::Fail("ath10k BMI compressed download failed");
    }
    let calls = &bmi.transport.requests;
    if calls.len() != 4
        || calls[0] != [13, 0, 0, 0, 0x34, 0x12, 0, 0]
        || calls[1].len() != 256
        || calls[1][..8] != [14, 0, 0, 0, 248, 0, 0, 0]
        || calls[2] != [14, 0, 0, 0, 4, 0, 0, 0, 0xab, 0xab, 0xab, 0]
        || calls[3] != [13, 0, 0, 0, 0, 0, 0, 0]
    {
        return TestResult::Fail("ath10k compressed BMI stream/flush layout wrong");
    }
    bmi.transport.responses.push_back(Err(BmiError::Timeout));
    if ready(bmi.done()) != Some(Err(BmiError::Timeout)) {
        return TestResult::Fail("BMI_DONE transport failure lost");
    }
    let count = bmi.transport.requests.len();
    if ready(bmi.target_info()) != Some(Err(BmiError::AfterDone))
        || ready(bmi.write_u32(0x400800, 1)) != Some(Err(BmiError::AfterDone))
        || ready(bmi.done()) != Some(Err(BmiError::AfterDone))
        || bmi.transport.requests.len() != count
    {
        return TestResult::Fail("ath10k reused BMI after DONE handoff");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/bmi",
    smoke_ath10k_bmi_compressed_download_and_done_gate
);
