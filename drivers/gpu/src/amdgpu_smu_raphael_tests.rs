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
    flags: u32,
    response: u32,
    argument: u32,
    replies: VecDeque<Option<(u32, u32)>>,
    log: Vec<(u32, u32)>,
    reads: usize,
}
impl Io for Fake {
    fn read_smn(&mut self, address: u32) -> u32 {
        self.reads += 1;
        match address {
            FIRMWARE_FLAGS => self.flags,
            RESPONSE => self.response,
            ARGUMENT => self.argument,
            _ => u32::MAX,
        }
    }
    fn write_smn(&mut self, address: u32, value: u32) {
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
            flags: INTERRUPTS_ENABLED,
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

/// `smu_v13_0_5_ppt.c`'s offsets on MP1 segment 0x16000, as SMN byte
/// addresses: the graphics mailbox sits beside the display's C2PMSG_3
/// (0x3b1050c), which the clock manager writes.
fn smu_raphael_mailbox_addresses_follow_linux() -> TestResult {
    if (MSG, RESPONSE, ARGUMENT, FIRMWARE_FLAGS) != (0x3b1_0508, 0x3b1_0984, 0x3b1_0988, 0x3b1_0024)
    {
        return TestResult::Fail("SMU 13.0.5 mailbox addresses");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/smu-raphael",
    smu_raphael_mailbox_addresses_follow_linux
);

/// `start` checks the firmware flags, then sends GetDriverIfVersion without
/// waiting on a previous message (`SMU_FW_INIT`) and GetSmuVersion after the
/// pre-poll; each send clears the response, writes the argument, then the id.
fn smu_raphael_start_reads_versions_in_linux_order() -> TestResult {
    let mut e = engine(&[
        Some((RESP_OK, 5)),
        Some((RESP_OK, 0x0050_4800)),
        Some((RESP_OK, 0)),
    ]);
    let versions = run(e.start());
    let expected_writes = vec![
        (RESPONSE, 0),
        (ARGUMENT, 0),
        (MSG, MSG_GET_DRIVER_IF_VERSION),
        (RESPONSE, 0),
        (ARGUMENT, 0),
        (MSG, MSG_GET_SMU_VERSION),
    ];
    let wanted = Versions {
        smu: 0x0050_4800,
        driver_if: 5,
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
    "drivers/gpu/smu-raphael",
    smu_raphael_start_reads_versions_in_linux_order
);

/// Nothing is sent before PMFW is proven running, and nothing but `start`
/// before the versions are read.
fn smu_raphael_refuses_messages_before_running_firmware() -> TestResult {
    let mut e = engine(&[]);
    if run(e.started(MSG_ALLOW_GFXOFF)) != Err(Error::NotStarted) || !e.io.log.is_empty() {
        return TestResult::Fail("message sent before start");
    }
    e.io.flags = 0;
    if run(e.start()) != Err(Error::NotRunning) || !e.io.log.is_empty() {
        return TestResult::Fail("message sent to stopped PMFW");
    }
    e.io.flags = u32::MAX;
    if run(e.start()) != Err(Error::DeviceGone) {
        return TestResult::Fail("vanished device read as running PMFW");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/smu-raphael",
    smu_raphael_refuses_messages_before_running_firmware
);

/// A refusal is the firmware's status and leaves the mailbox usable; an
/// unknown response marks it hung, after which nothing is sent.
fn smu_raphael_rejection_and_hang_follow_smu_cmn() -> TestResult {
    let mut e = engine(&[
        Some((RESP_OK, 5)),
        Some((RESP_OK, 1)),
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
    "drivers/gpu/smu-raphael",
    smu_raphael_rejection_and_hang_follow_smu_cmn
);

/// A message that never answers times out; the next one waits for it first
/// and is not written while the previous is still outstanding.
fn smu_raphael_unanswered_message_blocks_the_next() -> TestResult {
    let mut e = engine(&[Some((RESP_OK, 5)), Some((RESP_OK, 1)), None]);
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
    "drivers/gpu/smu-raphael",
    smu_raphael_unanswered_message_blocks_the_next
);

/// Revoked PCI authority stops the mailbox before any SMN access.
fn smu_raphael_revocation_blocks_every_access() -> TestResult {
    let mut e = engine(&[Some((RESP_OK, 5)), Some((RESP_OK, 1))]);
    e.authority.revoke();
    if run(e.start()) != Err(Error::Revoked) || e.io.reads != 0 || !e.io.log.is_empty() {
        return TestResult::Fail("revoked authority reached the mailbox");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/smu-raphael",
    smu_raphael_revocation_blocks_every_access
);

/// The constructor admits only Raphael with MP1 13.0.5 at segment 0x16000
/// (the base the fixed SMN addresses assume) and an NBIO 7.2/7.7 index pair.
fn smu_raphael_resolves_only_the_audited_layout() -> TestResult {
    use crate::amdgpu_discovery as d;
    let gpu = || {
        let mut gpu = crate::amdgpu_navi22_boot::tests::gpu();
        gpu.chip = crate::amdgpu::__test_chip_info_for_pci_id(
            crate::amdgpu::AMD_VENDOR,
            crate::amdgpu::RAPHAEL,
        )
        .unwrap();
        let template = gpu.ip_blocks[0];
        let ip = |id, v: (u8, u8, u8), base: u32| {
            let mut block = template;
            block.hw_id = id;
            (block.major, block.minor, block.revision) = v;
            block.num_bases = 1;
            block.base_addrs[0] = base;
            block
        };
        gpu.ip_blocks = vec![
            ip(d::HW_ID_MP1, (13, 0, 5), 0x1_6000),
            ip(d::HW_ID_NBIF, (7, 7, 1), 0x3000),
        ];
        gpu
    };
    if resolve(&gpu()) != Ok(0x3000 * 4) {
        return TestResult::Fail("Raphael SMU layout refused");
    }
    let mut navi22 = gpu();
    navi22.chip = crate::amdgpu::__test_chip_info_for_pci_id(
        crate::amdgpu::AMD_VENDOR,
        crate::amdgpu::NAVI22,
    )
    .unwrap();
    let mut moved = gpu();
    moved.ip_blocks[0].base_addrs[0] = 0x1_7000;
    let mut smu11 = gpu();
    smu11.ip_blocks[0].major = 11;
    let mut nbio23 = gpu();
    (nbio23.ip_blocks[1].major, nbio23.ip_blocks[1].minor) = (2, 3);
    for (bad, why) in [
        (navi22, "SMU 13.0.5 mailbox admitted a discrete GPU"),
        (moved, "SMU 13.0.5 mailbox admitted MP1 off its SMN segment"),
        (smu11, "SMU 13.0.5 mailbox admitted another MP1"),
        (
            nbio23,
            "SMU 13.0.5 mailbox admitted an NBIO without its index pair",
        ),
    ] {
        if resolve(&bad) != Err(Error::Unsupported) {
            return TestResult::Fail(why);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/smu-raphael",
    smu_raphael_resolves_only_the_audited_layout
);
