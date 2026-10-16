use super::*;
use alloc::sync::Arc;
use core::{
    cell::Cell,
    future::Future,
    pin::pin,
    sync::atomic::{AtomicUsize, Ordering},
    task::{Context, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

fn firmware(bytes: usize) -> Firmware {
    let mut patch = vec![0u8; 96 + 64 + bytes];
    patch[44..48].copy_from_slice(&1u32.to_be_bytes());
    patch[96..100].copy_from_slice(&2u32.to_be_bytes());
    patch[100..104].copy_from_slice(&160u32.to_be_bytes());
    patch[104..108].copy_from_slice(&(bytes as u32).to_be_bytes());
    patch[108..112].copy_from_slice(&0x900000u32.to_be_bytes());
    patch[112..116].copy_from_slice(&(bytes as u32).to_be_bytes());
    patch[116..120].copy_from_slice(&u32::MAX.to_be_bytes());
    patch[160..].fill(0x55);
    let mut ram = vec![0u8; bytes + 40 + 36];
    ram[..bytes].fill(0xaa);
    ram[bytes + 16..bytes + 20].copy_from_slice(&0x400000u32.to_le_bytes());
    ram[bytes + 20..bytes + 24].copy_from_slice(&(bytes as u32).to_le_bytes());
    ram[bytes + 40 + 2] = 1;
    ram[bytes + 40 + 3] = 1;
    Firmware::prepare(&patch, &ram).unwrap()
}
fn event(cmd: u8, seq: u8, status: u8) -> Vec<u8> {
    let mut event = vec![0; 36];
    event[..4].copy_from_slice(&((7u32 << 27) | 36).to_le_bytes());
    event[24..26].copy_from_slice(&12u16.to_le_bytes());
    event[28] = if cmd == 0x10 { 4 } else { 1 };
    event[29] = seq;
    event[32] = status;
    event
}
#[derive(Debug)]
struct Model {
    ticks: Cell<u64>,
    live: bool,
    owner: Retained<Lease>,
    active: bool,
    frames: Vec<(bool, Vec<u8>)>,
    replies: VecDeque<Vec<u8>>,
    loaded: bool,
    tx_stall: bool,
    rx_stall: bool,
    idle_stall: bool,
    malformed: bool,
    semaphore: u8,
    notifications: usize,
    revoke_on_submit: bool,
    resources: Arc<AtomicUsize>,
}
impl Model {
    fn new() -> Self {
        let resources = Arc::new(AtomicUsize::new(1));
        Self {
            ticks: Cell::new(0),
            live: true,
            owner: Retained {
                storage: Some(Lease(resources.clone())),
                published: false,
            },
            active: false,
            frames: Vec::new(),
            replies: VecDeque::new(),
            loaded: false,
            tx_stall: false,
            rx_stall: false,
            idle_stall: false,
            malformed: false,
            semaphore: 2,
            notifications: 0,
            revoke_on_submit: false,
            resources,
        }
    }
}
#[derive(Debug)]
struct Lease(Arc<AtomicUsize>);
impl Drop for Lease {
    fn drop(&mut self) {
        self.0.store(0, Ordering::SeqCst);
    }
}
impl Backend for Model {
    fn now_ns(&self) -> u64 {
        let now = self.ticks.get();
        self.ticks.set(now + 1_000_000);
        now
    }
    fn check(&self) -> Result<(), Error> {
        if self.live {
            Ok(())
        } else {
            Err(Error::Authority)
        }
    }
    fn quiesce(&mut self) -> Result<(), Error> {
        Ok(())
    }
    fn idle(&mut self) -> Result<bool, Error> {
        Ok(!self.idle_stall)
    }
    fn initialize(&mut self) -> Result<(), Error> {
        self.owner.published = true;
        Ok(())
    }
    fn request_driver_own(&mut self) -> Result<(), Error> {
        Ok(())
    }
    fn driver_owned(&mut self) -> Result<bool, Error> {
        Ok(true)
    }
    fn fw_state(&mut self) -> Result<u32, Error> {
        Ok(if self.loaded { 3 } else { 1 })
    }
    fn submit(&mut self, scatter: bool, frame: &[u8]) -> Result<(), Error> {
        if self.active {
            return Err(Error::Busy);
        }
        self.active = true;
        self.frames.push((scatter, frame.to_vec()));
        if !scatter {
            let cmd = frame[36];
            if cmd == 2 {
                self.loaded = true;
            }
            if cmd != 4 {
                for _ in 0..self.notifications {
                    self.replies.push_back(event(1, 0, 0));
                }
                self.notifications = 0;
                let status = if cmd == 0x10 {
                    if frame[64] == 1 {
                        self.semaphore
                    } else {
                        3
                    }
                } else {
                    0
                };
                let mut reply = event(cmd, frame[39], status);
                if self.malformed {
                    reply.truncate(10);
                }
                self.replies.push_back(reply);
            }
        }
        if self.revoke_on_submit {
            self.live = false;
        }
        Ok(())
    }
    fn tx_complete(&mut self, _: bool) -> Result<bool, Error> {
        if self.tx_stall {
            Ok(false)
        } else {
            self.active = false;
            Ok(true)
        }
    }
    fn receive(&mut self) -> Result<Option<Vec<u8>>, Error> {
        if self.rx_stall {
            Ok(None)
        } else {
            Ok(self.replies.pop_front())
        }
    }
    fn release(&mut self) -> Result<(), Error> {
        self.owner.published = false;
        Ok(())
    }
}
fn run<T>(future: impl Future<Output = T>) -> T {
    let mut future = pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..20000 {
        if let Poll::Ready(value) = future.as_mut().poll(&mut cx) {
            return value;
        }
    }
    panic!("transport wait was not bounded")
}
fn mcu_firmware_header_matches_linux_and_scatter_is_headerless() -> TestResult {
    let frame = command_frame(0x10, 15, &[1, 0, 0, 0]).unwrap();
    if frame.len() != 68
        || frame[..8] != [68, 0, 0, 0x41, 0, 0, 1, 0x80]
        || frame[32..40] != [36, 0, 0, 0x80, 0x10, 0xa0, 3, 15]
    {
        return TestResult::Fail("MCU TXD differs from Linux connac2 framing");
    }
    let mut session = Session::new(Model::new(), firmware(9000));
    let report = match run(session.run()) {
        Ok(report) => report,
        Err(_) => return TestResult::Fail("firmware boot model failed"),
    };
    let scatter: Vec<_> = session
        .backend
        .frames
        .iter()
        .filter(|frame| frame.0)
        .collect();
    if report.bytes_transferred != 18000
        || scatter.len() != 6
        || scatter
            .iter()
            .any(|(_, frame)| frame.len() > 4096 || !matches!(frame[0], 0x55 | 0xaa))
        || !session.backend.owner.published
        || !matches!(session.state, State::Ready(_))
        || run(session.run()) != Err(Error::Busy)
    {
        return TestResult::Fail("scatter framing, ownership or single-attempt state");
    }
    let commands: Vec<_> = session
        .backend
        .frames
        .iter()
        .filter(|frame| !frame.0)
        .map(|(_, frame)| frame[36])
        .collect();
    if commands != [4, 0x10, 5, 7, 0x10, 1, 2] {
        return TestResult::Fail("firmware command order differs from Linux");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/transport",
    mcu_firmware_header_matches_linux_and_scatter_is_headerless
);

fn mcu_firmware_preflight_rejects_truncation_and_metadata_overlap() -> TestResult {
    let fw = firmware(32);
    for length in [0, 31, 92, 95, 96, 159] {
        if Firmware::prepare(&fw.patch[..length], &fw.ram).is_ok() {
            return TestResult::Fail("truncated patch accepted");
        }
    }
    let mut patch = fw.patch.to_vec();
    patch[100..104].copy_from_slice(&100u32.to_be_bytes());
    if Firmware::prepare(&patch, &fw.ram).is_ok() {
        return TestResult::Fail("patch copied its own metadata");
    }
    let mut ram = fw.ram.to_vec();
    ram[32 + 20..32 + 24].copy_from_slice(&u32::MAX.to_le_bytes());
    if Firmware::prepare(&fw.patch, &ram).is_ok() {
        return TestResult::Fail("RAM region exceeded payload");
    }
    let mut patch = fw.patch.to_vec();
    patch[44..48].copy_from_slice(&u32::MAX.to_be_bytes());
    if Firmware::prepare(&patch, &fw.ram).is_ok() {
        return TestResult::Fail("patch region count overflow");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/transport",
    mcu_firmware_preflight_rejects_truncation_and_metadata_overlap
);

fn mcu_firmware_timeouts_and_revocation_preserve_published_memory() -> TestResult {
    for failure in 0..5 {
        let mut model = Model::new();
        let expected = match failure {
            0 => {
                model.tx_stall = true;
                Error::Timeout
            }
            1 => {
                model.rx_stall = true;
                Error::Timeout
            }
            2 => {
                model.malformed = true;
                Error::MalformedEvent
            }
            3 => {
                model.revoke_on_submit = true;
                Error::Authority
            }
            _ => {
                model.semaphore = 0;
                Error::Rejected(0)
            }
        };
        let resources = model.resources.clone();
        let mut session = Session::new(model, firmware(32));
        if run(session.run()) != Err(expected)
            || !matches!(session.state, State::Failed { .. })
            || run(session.run()) != Err(Error::Busy)
        {
            return TestResult::Fail("failed session continued/replayed");
        }
        drop(session);
        if resources.load(Ordering::SeqCst) != 1 {
            return TestResult::Fail("failure released published buffers");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/transport",
    mcu_firmware_timeouts_and_revocation_preserve_published_memory
);

fn mcu_firmware_cancelled_future_cannot_replay_or_free_dma() -> TestResult {
    let mut model = Model::new();
    model.tx_stall = true;
    let resources = model.resources.clone();
    let mut session = Session::new(model, firmware(32));
    {
        let mut future = pin!(session.run());
        if future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_ready()
        {
            return TestResult::Fail("stalled submission completed");
        }
    }
    if session.state != State::Running(Stage::Restart) || run(session.run()) != Err(Error::Busy) {
        return TestResult::Fail("cancelled firmware sequence replayed");
    }
    drop(session);
    if resources.load(Ordering::SeqCst) != 1 {
        return TestResult::Fail("cancellation freed DMA");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/transport",
    mcu_firmware_cancelled_future_cannot_replay_or_free_dma
);

fn mcu_firmware_notifications_are_bounded_and_patch_skip_is_explicit() -> TestResult {
    let mut model = Model::new();
    model.notifications = 2;
    model.semaphore = 1;
    let mut session = Session::new(model, firmware(32));
    if !matches!(
        run(session.run()),
        Ok(Report {
            patch_already_loaded: true,
            bytes_transferred: 32,
            ..
        })
    ) || session.events.len() != 2
    {
        return TestResult::Fail("patch skip or notification preservation");
    }
    let mut model = Model::new();
    model.notifications = 33;
    if run(Session::new(model, firmware(32)).run()) != Err(Error::EventOverflow) {
        return TestResult::Fail("unsolicited events exhausted an unbounded queue");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/transport",
    mcu_firmware_notifications_are_bounded_and_patch_skip_is_explicit
);

fn mcu_firmware_shutdown_frees_only_after_verified_idle() -> TestResult {
    for stuck in [false, true] {
        let model = Model::new();
        let resources = model.resources.clone();
        let mut session = Session::new(model, firmware(32));
        if run(session.run()).is_err() {
            return TestResult::Fail("setup boot failed");
        }
        session.backend.idle_stall = stuck;
        if run(session.shutdown()) != if stuck { Err(Error::Timeout) } else { Ok(()) } {
            return TestResult::Fail("shutdown idle result");
        }
        drop(session);
        if resources.load(Ordering::SeqCst) != if stuck { 1 } else { 0 } {
            return TestResult::Fail("shutdown reclaimed DMA before idle");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/transport",
    mcu_firmware_shutdown_frees_only_after_verified_idle
);

// Match the installed MT7922 format-2 image layout, including its opaque
// trailer gap and the non-downloadable CLC region; no firmware bytes embedded.
fn mcu_dma_mt7922_image_layout() -> TestResult {
    let mut patch = vec![0u8; 137632];
    patch[44..48].copy_from_slice(&1u32.to_be_bytes());
    for (offset, value) in [
        (96, 0x40002u32),
        (100, 160),
        (104, 137472),
        (108, 0x900000),
        (112, 137472),
        (116, 0x01000000),
    ] {
        patch[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
    }
    let mut ram = vec![0u8; 1231252];
    let table = ram.len() - 36 - 6 * 40;
    let lengths = [341904u32, 292816, 15312, 8144, 97168, 475488];
    let addresses = [9547776u32, 33643520, 4211712, 34643968, 3760193536, 0];
    for i in 0..6 {
        let region = table + i * 40;
        ram[region + 16..region + 20].copy_from_slice(&addresses[i].to_le_bytes());
        ram[region + 20..region + 24].copy_from_slice(&lengths[i].to_le_bytes());
        ram[region + 24] = if i == 0 {
            33
        } else if i == 5 {
            64
        } else {
            1
        };
    }
    let tail = ram.len() - 36;
    ram[tail + 2] = 6;
    ram[tail + 3] = 2;
    let Ok(fw) = Firmware::prepare(&patch, &ram) else {
        return TestResult::Fail("real MT7922 layout rejected");
    };
    if fw.patch_regions.len() != 1
        || fw.patch_regions[0].mode != 0x80000009
        || fw.ram_regions.len() != 5
        || fw.override_addr != 9547776
        || fw.ram_regions.iter().any(|r| r.mode != 0x80000009)
        || fw.ram_regions.last().unwrap().bytes.end != 755344
    {
        return TestResult::Fail("MT7922 encrypted or non-downloadable regions");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/transport",
    mcu_dma_mt7922_image_layout
);
