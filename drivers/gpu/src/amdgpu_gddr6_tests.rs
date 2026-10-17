use super::*;
use alloc::vec;
use core::{
    future::Future,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

#[derive(Debug)]
struct Fake {
    memory: Vec<u8>,
    heartbeat: u32,
    status: u32,
    completion: Option<u32>,
    writes: Vec<(u32, u32)>,
    copied: usize,
    restored: usize,
    flushed: bool,
    result: bool,
    setup: bool,
    enabled: bool,
    violation: bool,
}
impl Io for Fake {
    fn read(&mut self, reg: u32) -> u32 {
        match reg {
            SOS => self.heartbeat,
            STATUS => self.status,
            _ => panic!("unexpected training register"),
        }
    }
    fn write(&mut self, reg: u32, value: u32) {
        self.writes.push((reg, value));
        if reg == STATUS {
            self.violation |= self.copied != self.memory.len() || value != LONG_TRAIN;
            self.memory.fill(0xee); // BIST encroaches on the boot framebuffer.
            self.status = self.completion.unwrap_or(0);
        }
    }
    fn setup(&mut self) -> bool {
        self.setup
    }
    fn training_enabled(&mut self) -> Result<bool, Error> {
        Ok(self.enabled)
    }
    fn read_prefix(&mut self, offset: usize, bytes: &mut [u8]) {
        self.violation |= !self.writes.is_empty();
        bytes.copy_from_slice(&self.memory[offset..offset + bytes.len()]);
        self.copied += bytes.len();
    }
    fn write_prefix(&mut self, offset: usize, bytes: &[u8]) {
        self.violation |= self.status & DONE == 0 || self.status == u32::MAX;
        self.memory[offset..offset + bytes.len()].copy_from_slice(bytes);
        self.restored += bytes.len();
    }
    fn flush(&mut self) {
        self.violation |= self.restored != self.memory.len();
        self.flushed = true;
    }
    fn read_result(&mut self, offset: u64, bytes: &mut [u8]) -> Result<(), Error> {
        self.violation |= !self.flushed || offset != (12 << 30) - 0x8000 || bytes.len() != 4096;
        bytes.fill(0xa5);
        if self.result {
            bytes[..4].copy_from_slice(&SIGNATURE.to_le_bytes());
        }
        Ok(())
    }
}
fn engine() -> Engine<Fake> {
    Engine {
        io: Fake {
            memory: (0..CHUNK * 2).map(|i| (i % 239) as u8).collect(),
            heartbeat: 0,
            status: DONE,
            completion: Some(DONE),
            writes: Vec::new(),
            copied: 0,
            restored: 0,
            flushed: false,
            result: true,
            setup: true,
            enabled: true,
            violation: false,
        },
        authority: Cap::bootstrap(),
        exchange: Training {
            c2p: (12 << 30) - (9 << 20),
            p2c: (12 << 30) - 0x8000,
            size: 4096,
        },
        backup: vec![0; CHUNK * 2],
        cache: vec![0; 4096],
        state: State::Prepared,
    }
}
fn run<T>(future: impl Future<Output = T>) -> T {
    narf_scheduler::block_on_spin(future)
}

fn gddr6_long_training_restores_preimage_before_caching() -> TestResult {
    let mut e = engine();
    let original = e.io.memory.clone();
    if run(e.run()).is_err()
        || e.state != State::Ready
        || e.io.violation
        || e.io.memory != original
        || e.backup != original
        || !e.io.flushed
        || e.io.writes != [(ADDRESS, 12279), (STATUS, 0x10_0000)]
        || u32::from_le_bytes(e.cache[..4].try_into().unwrap()) != SIGNATURE
        || run(e.run()) != Err(Error::Busy)
    {
        return TestResult::Fail(
            "training order, VRAM-relative address, preimage or single-attempt contract",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gddr6",
    gddr6_long_training_restores_preimage_before_caching
);

fn gddr6_resident_sos_and_bad_preconditions_do_not_train() -> TestResult {
    let mut disabled = engine();
    disabled.io.enabled = false;
    if run(disabled.run()).is_err()
        || disabled.state != State::Disabled
        || disabled.io.copied != 0
        || !disabled.io.writes.is_empty()
    {
        return TestResult::Fail("PSP boot configuration disabling training ignored");
    }
    for (heartbeat, setup, result) in [
        (1, true, Ok(())),
        (u32::MAX, true, Err(Error::DeviceGone)),
        (0, false, Err(Error::Invalid)),
    ] {
        let mut e = engine();
        e.io.heartbeat = heartbeat;
        e.io.setup = setup;
        if run(e.run()) != result
            || e.io.copied != 0
            || !e.io.writes.is_empty()
            || (heartbeat == 1 && e.state != State::ResidentSos)
        {
            return TestResult::Fail("resident SOS or failed setup touched training buffers");
        }
    }
    let mut e = engine();
    e.authority.revoke();
    if run(e.run()) != Err(Error::Revoked) || !e.io.writes.is_empty() || e.io.copied != 0 {
        return TestResult::Fail("revoked authority performed initial I/O");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gddr6",
    gddr6_resident_sos_and_bad_preconditions_do_not_train
);

fn gddr6_terminal_rejection_restores_but_unknown_completion_does_not() -> TestResult {
    // psp_v11_0_memory_training_send_msg waits on bit 31 only: low status
    // bits after completion are not a failure.
    let mut e = engine();
    let original = e.io.memory.clone();
    e.io.completion = Some(DONE | 7);
    if run(e.run()).is_err() || e.state != State::Ready || e.io.memory != original {
        return TestResult::Fail("completed training with status bits treated as failure");
    }
    if TRAINING_TIMEOUT_MS < 3000 {
        return TestResult::Fail("long-training deadline below MEM_TRAIN_SEND_MSG_TIMEOUT_US");
    }
    for (completion, expected, restored) in [
        (Some(u32::MAX), Error::DeviceGone, false),
        (None, Error::Timeout, false),
    ] {
        let mut e = engine();
        let original = e.io.memory.clone();
        e.io.completion = completion;
        if run(e.run()) != Err(expected)
            || e.state != State::Failed
            || e.io.violation
            || (e.io.restored != 0) != restored
            || e.backup != original
            || (restored && e.io.memory != original)
            || run(e.run()) != Err(Error::Busy)
        {
            return TestResult::Fail("failed training lost preimage, raced PSP or allowed replay");
        }
    }
    // Linux checks the BIST signature only when deciding resume reuse.
    let mut e = engine();
    e.io.result = false;
    let original = e.io.memory.clone();
    if run(e.run()).is_err()
        || e.state != State::Ready
        || e.io.memory != original
        || !e.io.flushed
        || (e.state == State::Ready && e.cache_valid())
    {
        return TestResult::Fail("missing BIST signature failed boot or cache trusted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gddr6",
    gddr6_terminal_rejection_restores_but_unknown_completion_does_not
);

fn gddr6_cancellation_and_revocation_preserve_ownership() -> TestResult {
    for (polls, complete) in [(1, false), (3, false), (3, true)] {
        for revoke in [false, true] {
            let mut e = engine();
            if !complete {
                e.io.completion = None;
            }
            let cap = e.authority;
            {
                let mut future = core::pin::pin!(e.run());
                for _ in 0..polls {
                    if future
                        .as_mut()
                        .poll(&mut Context::from_waker(Waker::noop()))
                        != Poll::Pending
                    {
                        return TestResult::Fail(
                            "training unexpectedly completed before cancellation point",
                        );
                    }
                }
                if revoke {
                    cap.revoke();
                    if run(future) != Err(Error::Revoked) {
                        return TestResult::Fail("training ignored revocation across await");
                    }
                }
            }
            if run(e.run()) != Err(Error::Busy)
                || e.io.violation
                || e.io.writes.len() != if polls == 1 { 0 } else { 2 }
                || e.io.restored != if complete { CHUNK } else { 0 }
            {
                return TestResult::Fail(
                    "cancel/revoke restarted training or wrote beyond last authorized chunk",
                );
            }
            if polls == 3
                && e.backup
                    .iter()
                    .enumerate()
                    .any(|(i, b)| *b != (i % 239) as u8)
            {
                return TestResult::Fail("cancellation lost the complete VRAM preimage");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gddr6",
    gddr6_cancellation_and_revocation_preserve_ownership
);

fn gddr6_training_exchange_validation() -> TestResult {
    let size = 12 << 30;
    let exchange = engine().exchange;
    if validate_exchange(size, 256 << 20, exchange).is_err() {
        return TestResult::Fail(
            "small BAR cannot address training buffers through the index port",
        );
    }
    for bad in [
        Training {
            c2p: 31 << 20,
            ..exchange
        },
        Training {
            c2p: exchange.c2p + 4096,
            ..exchange
        },
        Training {
            size: 0,
            ..exchange
        },
        Training { p2c: 0, ..exchange },
        Training {
            c2p: 12 << 30,
            ..exchange
        },
    ] {
        if validate_exchange(size, 256 << 20, bad) != Err(Error::Invalid) {
            return TestResult::Fail("invalid training exchange accepted");
        }
    }
    if validate_exchange(size, ENCROACHED as u64 - 1, exchange) != Err(Error::Invalid) {
        return TestResult::Fail("32 MiB preimage did not fit in BAR0");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/gddr6", gddr6_training_exchange_validation);

fn gddr6_runtime_training_policy_is_bounded() -> TestResult {
    let mut db = vec![0; 0x10000];
    let policy = |db: &[u8]| {
        training_policy(|offset, bytes| {
            let source = db.get(offset..offset + bytes.len()).ok_or(Error::Invalid)?;
            bytes.copy_from_slice(source);
            Ok(())
        })
    };
    if policy(&db) != Ok(true) {
        return TestResult::Fail("absent runtime DB must preserve enable default");
    }
    db[..8].copy_from_slice(&[0xd5, 0x0e, 0, 1, 1, 0, 0, 0]);
    db[8..16].copy_from_slice(&[5, 0, 0, 0, 0, 4, 8, 0]);
    if policy(&db) != Ok(false) {
        return TestResult::Fail("disabled training flag ignored");
    }
    db[1024] = 2;
    if policy(&db) != Ok(true) {
        return TestResult::Fail("enabled training flag ignored");
    }
    // psp_get_runtime_db_entry ignores the version and treats a malformed
    // directory or entry as absent (training stays enabled), never an error.
    let mut other = db.clone();
    other[1024] = 0;
    other[2] = 1;
    if policy(&other) != Ok(false) {
        return TestResult::Fail("runtime DB version must not be checked");
    }
    for (offset, value) in [(4, 64), (12, 1), (13, 0), (14, 4), (15, 255)] {
        let mut bad = db.clone();
        bad[1024] = 0;
        bad[offset] = value;
        if policy(&bad) != Ok(true) {
            return TestResult::Fail("malformed runtime DB must read as absent");
        }
    }
    // The first matching entry wins, as in Linux's lookup loop.
    db[1024] = 0;
    db[4] = 2;
    db[16..24].copy_from_slice(&[5, 0, 0, 0, 0, 8, 8, 0]);
    db[2048] = 2;
    if policy(&db) != Ok(false) {
        return TestResult::Fail("duplicate boot configuration did not use the first entry");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gddr6",
    gddr6_runtime_training_policy_is_bounded
);
