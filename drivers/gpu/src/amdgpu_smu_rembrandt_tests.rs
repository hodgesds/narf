use super::*;
use alloc::{collections::VecDeque, vec, vec::Vec};
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

/// PMFW's side of the mailbox: each message write takes the next scripted
/// (response, output) pair; `None` leaves the response at zero.
#[derive(Debug)]
struct Fake {
    response: u32,
    argument: u32,
    replies: VecDeque<Option<(u32, u32)>>,
    log: Vec<(u32, u32)>,
    reads: usize,
}
impl Io for Fake {
    fn read(&mut self, address: u32) -> u32 {
        self.reads += 1;
        match address {
            RESPONSE => self.response,
            ARGUMENT => self.argument,
            _ => u32::MAX,
        }
    }
    fn write(&mut self, address: u32, value: u32) {
        self.log.push((address, value));
        match address {
            RESPONSE => self.response = value,
            ARGUMENT => self.argument = value,
            MSG => {
                if let Some((response, output)) = self.replies.pop_front().flatten() {
                    self.response = response;
                    self.argument = output;
                }
            }
            _ => {}
        }
    }
    fn wait_poll_limit(&self) -> Option<u32> {
        Some(3)
    }
}
fn engine(replies: &[Option<(u32, u32)>]) -> Engine<Fake> {
    Engine {
        io: Fake {
            response: 0,
            argument: 0,
            replies: replies.iter().copied().collect(),
            log: Vec::new(),
            reads: 0,
        },
        authority: Cap::bootstrap(),
        first: true,
        hung: false,
        versions: None,
    }
}
fn run<T>(future: impl Future<Output = T>) -> T {
    let mut future = pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(value) = future.as_mut().poll(&mut cx) {
            return value;
        }
    }
}

/// `MP1_C2PMSG_66/82/90`'s byte offsets within the MP1 window (`0x240 + N`,
/// times four): argument 0xA08, message 0xA48, response 0xA68.
fn smu_rembrandt_mailbox_offsets_follow_linux() -> TestResult {
    if (ARGUMENT, MSG, RESPONSE) != (0xA08, 0xA48, 0xA68) {
        return TestResult::Fail("SMU 13.0.1/13.0.3 mailbox offsets");
    }
    if (MSG_GFX_DEVICE_DRIVER_RESET, MODE2_RESET, DRIVER_IF_VERSION) != (0x11, 2, 4) {
        return TestResult::Fail("GfxDeviceDriverReset message, argument or driver-if version");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/smu-rembrandt",
    smu_rembrandt_mailbox_offsets_follow_linux
);

/// `start` sends TestMessage with the sentinel first and checks the echo,
/// then GetSmuVersion and GetDriverIfVersion in `bring_up`'s order; each send
/// clears the response, writes the argument, then the id.
fn smu_rembrandt_start_echoes_and_reads_versions_in_linux_order() -> TestResult {
    let mut e = engine(&[
        Some((RESP_OK, SENTINEL)),
        Some((RESP_OK, 0x0050_4800)),
        Some((RESP_OK, 4)),
        Some((RESP_OK, 0)),
    ]);
    let versions = run(e.start());
    let expected_writes = vec![
        (RESPONSE, 0),
        (ARGUMENT, SENTINEL),
        (MSG, MSG_TEST_MESSAGE),
        (RESPONSE, 0),
        (ARGUMENT, 0),
        (MSG, MSG_GET_SMU_VERSION),
        (RESPONSE, 0),
        (ARGUMENT, 0),
        (MSG, MSG_GET_DRIVER_IF_VERSION),
    ];
    let wanted = Versions {
        smu: 0x0050_4800,
        driver_if: 4,
    };
    if versions != Ok(wanted)
        || !wanted.driver_if_matches()
        || e.versions != Some(wanted)
        || e.io.log != expected_writes
    {
        return TestResult::Fail("start sequence or versions");
    }
    if run(e.started(MSG_DISALLOW_GFXOFF)).is_err()
        || e.io.log.last() != Some(&(MSG, MSG_DISALLOW_GFXOFF))
    {
        return TestResult::Fail("GFXOFF message after start");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/smu-rembrandt",
    smu_rembrandt_start_echoes_and_reads_versions_in_linux_order
);

/// GfxDeviceDriverReset (0x11) with MODE2_RESET (2) as its argument, only
/// once PMFW's versions are known.
fn smu_rembrandt_mode2_reset_message() -> TestResult {
    let mut cold = engine(&[Some((RESP_OK, 0))]);
    if run(cold.started_with(MSG_GFX_DEVICE_DRIVER_RESET, MODE2_RESET)) != Err(Error::NotStarted)
        || !cold.io.log.is_empty()
    {
        return TestResult::Fail("mode 2 sent before start");
    }
    let mut e = engine(&[
        Some((RESP_OK, SENTINEL)),
        Some((RESP_OK, 0x0050_4800)),
        Some((RESP_OK, 4)),
        Some((RESP_OK, 0)),
    ]);
    if run(e.start()).is_err()
        || run(e.started_with(MSG_GFX_DEVICE_DRIVER_RESET, MODE2_RESET)).is_err()
        || e.io.log[e.io.log.len() - 3..]
            != [
                (RESPONSE, 0),
                (ARGUMENT, 2),
                (MSG, MSG_GFX_DEVICE_DRIVER_RESET),
            ]
    {
        return TestResult::Fail("mode 2 reset message");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/smu-rembrandt",
    smu_rembrandt_mode2_reset_message
);

/// Nothing is sent before PMFW is proven running, and an echo that does not
/// round-trip is refused rather than trusted.
fn smu_rembrandt_refuses_messages_before_running_firmware() -> TestResult {
    let mut e = engine(&[]);
    if run(e.started(MSG_ALLOW_GFXOFF)) != Err(Error::NotStarted) || !e.io.log.is_empty() {
        return TestResult::Fail("message sent before start");
    }
    let mut echo = engine(&[Some((RESP_OK, 0x1234_5678))]);
    if run(echo.start()) != Err(Error::EchoMismatch) {
        return TestResult::Fail("mismatched TestMessage echo accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/smu-rembrandt",
    smu_rembrandt_refuses_messages_before_running_firmware
);

/// A refusal is the firmware's status and leaves the mailbox usable; an
/// unknown response marks it hung, after which nothing is sent.
fn smu_rembrandt_rejection_and_hang_follow_smu_cmn() -> TestResult {
    let mut e = engine(&[
        Some((RESP_OK, SENTINEL)),
        Some((RESP_OK, 1)),
        Some((RESP_OK, 4)),
        Some((RESP_PREREQ, 0)),
        Some((RESP_OK, 0)),
        Some((0x42, 0)),
    ]);
    run(e.start()).unwrap();
    if run(e.started(MSG_POWER_UP_VCN)) != Err(Error::Rejected(RESP_PREREQ)) {
        return TestResult::Fail("rejection not reported with its status");
    }
    if run(e.started(MSG_POWER_UP_JPEG)).is_err() {
        return TestResult::Fail("mailbox unusable after a rejection");
    }
    if run(e.started(MSG_ALLOW_GFXOFF)) != Err(Error::Hung) {
        return TestResult::Fail("unknown response not treated as hung firmware");
    }
    let writes = e.io.log.len();
    let reads = e.io.reads;
    if run(e.started(MSG_DISALLOW_GFXOFF)) != Err(Error::Hung)
        || e.io.log.len() != writes
        || e.io.reads != reads
    {
        return TestResult::Fail("message sent to hung firmware");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/smu-rembrandt",
    smu_rembrandt_rejection_and_hang_follow_smu_cmn
);

/// A message that never answers times out; the next one waits for it first
/// and is not written while the previous is still outstanding.
fn smu_rembrandt_unanswered_message_blocks_the_next() -> TestResult {
    let mut e = engine(&[
        Some((RESP_OK, SENTINEL)),
        Some((RESP_OK, 1)),
        Some((RESP_OK, 4)),
        None,
    ]);
    run(e.start()).unwrap();
    if run(e.started(MSG_POWER_UP_VCN)) != Err(Error::Timeout) {
        return TestResult::Fail("unanswered message did not time out");
    }
    let writes = e.io.log.len();
    if run(e.started(MSG_POWER_UP_JPEG)) != Err(Error::Timeout) || e.io.log.len() != writes {
        return TestResult::Fail("message written over an outstanding one");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/smu-rembrandt",
    smu_rembrandt_unanswered_message_blocks_the_next
);

/// Revoked PCI authority stops the mailbox before any MMIO access.
fn smu_rembrandt_revocation_blocks_every_access() -> TestResult {
    let mut e = engine(&[
        Some((RESP_OK, SENTINEL)),
        Some((RESP_OK, 1)),
        Some((RESP_OK, 4)),
    ]);
    e.authority.revoke();
    if run(e.start()) != Err(Error::Revoked) || e.io.reads != 0 || !e.io.log.is_empty() {
        return TestResult::Fail("revoked authority reached the mailbox");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/smu-rembrandt",
    smu_rembrandt_revocation_blocks_every_access
);

/// The constructor admits only Rembrandt with MP1 13.0.1/13.0.3 on window 0
/// (the window the generic `psp_v13_0` family puts C2PMSG on).
fn smu_rembrandt_resolves_only_the_audited_layout() -> TestResult {
    use crate::amdgpu_discovery as d;
    let gpu = || {
        let mut gpu = crate::amdgpu_navi22_boot::tests::gpu();
        gpu.chip = crate::amdgpu::__test_chip_info_for_pci_id(
            crate::amdgpu::AMD_VENDOR,
            crate::amdgpu::REMBRANDT,
        )
        .unwrap();
        let template = gpu.ip_blocks[0];
        let ip = |id, v: (u8, u8, u8), base: u32, bases: u8| {
            let mut block = template;
            block.hw_id = id;
            (block.major, block.minor, block.revision) = v;
            block.num_bases = bases;
            block.base_addrs[0] = base;
            block
        };
        gpu.ip_blocks = vec![ip(d::HW_ID_MP1, (13, 0, 1), 0x1_6000, 1)];
        gpu
    };
    if resolve(&gpu()) != Ok(0x1_6000 * 4) {
        return TestResult::Fail("Rembrandt SMU layout refused");
    }
    let mut mp1_3 = gpu();
    mp1_3.ip_blocks[0].revision = 3;
    if resolve(&mp1_3) != Ok(0x1_6000 * 4) {
        return TestResult::Fail("Rembrandt SMU layout refused MP1 13.0.3");
    }
    let mut navi22 = gpu();
    navi22.chip = crate::amdgpu::__test_chip_info_for_pci_id(
        crate::amdgpu::AMD_VENDOR,
        crate::amdgpu::NAVI22,
    )
    .unwrap();
    let mut smu5 = gpu();
    smu5.ip_blocks[0].revision = 5;
    let mut smu4 = gpu();
    smu4.ip_blocks[0].revision = 4;
    let mut no_window = gpu();
    no_window.ip_blocks[0].num_bases = 0;
    for (bad, why) in [
        (navi22, "SMU 13.0.1/13.0.3 mailbox admitted a discrete GPU"),
        (smu5, "SMU 13.0.1/13.0.3 mailbox admitted MP1 13.0.5"),
        (smu4, "SMU 13.0.1/13.0.3 mailbox admitted MP1 13.0.4"),
        (
            no_window,
            "SMU 13.0.1/13.0.3 mailbox admitted an MP1 without window 0",
        ),
    ] {
        if resolve(&bad) != Err(Error::Unsupported) {
            return TestResult::Fail(why);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/smu-rembrandt",
    smu_rembrandt_resolves_only_the_audited_layout
);
