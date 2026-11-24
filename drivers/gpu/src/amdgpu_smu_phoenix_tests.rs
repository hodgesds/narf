use super::*;
use alloc::{collections::VecDeque, vec, vec::Vec};
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

/// PMFW's side of the MMIO mailbox: the response register starts at
/// `RESP_OK` (idle); each message write takes the next scripted
/// (response, output) pair; `None` leaves the response at zero, so the
/// shared mailbox poll spins to its budget and times out.
#[derive(Debug)]
struct Fake {
    response: u32,
    argument: u32,
    replies: VecDeque<Option<(u32, u32)>>,
    log: Vec<(u32, u32)>,
    reads: usize,
}
const MP1_BASE: u32 = 0x1000;
const RESP: u32 = MP1_BASE + MP1_C2PMSG_RESP_REL;
const ARG: u32 = MP1_BASE + MP1_C2PMSG_ARG_REL;
const MSG: u32 = MP1_BASE + MP1_C2PMSG_MSG_REL;
impl SmuMmio for Fake {
    fn read(&mut self, off: u32) -> u32 {
        self.reads += 1;
        match off {
            x if x == RESP => self.response,
            x if x == ARG => self.argument,
            _ => 0,
        }
    }
    fn write(&mut self, off: u32, value: u32) {
        self.log.push((off, value));
        match off {
            x if x == RESP => self.response = value,
            x if x == ARG => self.argument = value,
            x if x == MSG => {
                if let Some((response, output)) = self.replies.pop_front().flatten() {
                    self.response = response;
                    self.argument = output;
                }
            }
            _ => {}
        }
    }
}
fn engine(replies: &[Option<(u32, u32)>]) -> Engine<Fake> {
    Engine {
        io: Fake {
            response: RESP_OK,
            argument: 0,
            replies: replies.iter().copied().collect(),
            log: Vec::new(),
            reads: 0,
        },
        authority: Cap::bootstrap(),
        mp1_base: MP1_BASE,
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

/// The shared MMIO mailbox offsets (`(0x240 + n) * 4`) and the 13.0.4
/// opcodes this owner sends, against `smu_v13_0_4_ppsmc.h`.
fn smu_phoenix_mailbox_offsets_follow_linux() -> TestResult {
    if (MP1_C2PMSG_ARG_REL, MP1_C2PMSG_MSG_REL, MP1_C2PMSG_RESP_REL) != (0xA08, 0xA48, 0xA68) {
        return TestResult::Fail("C2PMSG_66/82/90 offsets");
    }
    if (
        v13::V13_MSG_TEST,
        v13::V13_MSG_GET_PMFW_VERSION,
        v13::V13_MSG_GET_DRIVER_IF,
    ) != (0x01, 0x02, 0x03)
        || (v13::V13_MSG_ALLOW_GFX_OFF, v13::V13_MSG_DISALLOW_GFX_OFF) != (0x19, 0x1A)
        || (v13::V13_MSG_POWER_UP_VCN, v13::V13_MSG_POWER_DOWN_VCN) != (0x07, 0x06)
        || (v13::V13_MSG_POWER_UP_JPEG, v13::V13_MSG_POWER_DOWN_JPEG) != (0x22, 0x21)
        || v13::V13_MSG_GFX_DEVICE_DRIVER_RESET != 0x11
    {
        return TestResult::Fail("SMU 13.0.4 opcodes");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/smu-phoenix",
    smu_phoenix_mailbox_offsets_follow_linux
);

/// `start` runs the shared bring-up order — TestMessage echo, then
/// GetPmfwVersion, then GetDriverIfVersion — and each send clears the
/// response, writes the argument, then the id.
fn smu_phoenix_start_reads_versions_in_linux_order() -> TestResult {
    let mut e = engine(&[
        Some((RESP_OK, TEST_SENTINEL)),
        Some((RESP_OK, 0x0050_4800)),
        Some((RESP_OK, SMU_13_0_4_DRIVER_IF_VERSION)),
        Some((RESP_OK, 0)),
    ]);
    let versions = run(e.start());
    let expected_writes = vec![
        (RESP, 0),
        (ARG, TEST_SENTINEL),
        (MSG, v13::V13_MSG_TEST),
        (RESP, 0),
        (ARG, 0),
        (MSG, v13::V13_MSG_GET_PMFW_VERSION),
        (RESP, 0),
        (ARG, 0),
        (MSG, v13::V13_MSG_GET_DRIVER_IF),
    ];
    let wanted = Versions {
        smu: 0x0050_4800,
        driver_if: SMU_13_0_4_DRIVER_IF_VERSION,
    };
    if versions != Ok(wanted)
        || !wanted.driver_if_matches()
        || e.versions != Some(wanted)
        || e.io.log != expected_writes
    {
        return TestResult::Fail("start sequence or versions");
    }
    if run(e.started(v13::V13_MSG_DISALLOW_GFX_OFF)).is_err()
        || e.io.log.last() != Some(&(MSG, v13::V13_MSG_DISALLOW_GFX_OFF))
    {
        return TestResult::Fail("GFXOFF message after start");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/smu-phoenix",
    smu_phoenix_start_reads_versions_in_linux_order
);

/// A firmware reporting the 7.4-rc2 driver-IF value 8 is accepted and
/// recorded (but does not match NARF's carried 0x07); anything else fails
/// closed and leaves the versions unread.
fn smu_phoenix_accepts_driver_if_8_refuses_9() -> TestResult {
    let mut e = engine(&[
        Some((RESP_OK, TEST_SENTINEL)),
        Some((RESP_OK, 0x0050_4800)),
        Some((RESP_OK, DRIVER_IF_VERSION_7_4_RC2)),
    ]);
    let versions = run(e.start());
    if versions
        != Ok(Versions {
            smu: 0x0050_4800,
            driver_if: DRIVER_IF_VERSION_7_4_RC2,
        })
        || versions.unwrap().driver_if_matches()
    {
        return TestResult::Fail("driver-IF 8 not accepted-and-recorded");
    }
    let mut e = engine(&[
        Some((RESP_OK, TEST_SENTINEL)),
        Some((RESP_OK, 0x0050_4800)),
        Some((RESP_OK, 9)),
    ]);
    if run(e.start()) != Err(Error::DriverIfMismatch(9)) || e.versions.is_some() {
        return TestResult::Fail("driver-IF 9 not refused");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/smu-phoenix",
    smu_phoenix_accepts_driver_if_8_refuses_9
);

/// A TestMessage that does not echo the sentinel fails start before any
/// version is read.
fn smu_phoenix_echo_mismatch_fails_start() -> TestResult {
    let mut e = engine(&[Some((RESP_OK, 0x1234))]);
    if run(e.start())
        != Err(Error::EchoMismatch {
            sent: TEST_SENTINEL,
            got: 0x1234,
        })
        || e.versions.is_some()
    {
        return TestResult::Fail("bad echo not refused");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/smu-phoenix",
    smu_phoenix_echo_mismatch_fails_start
);

/// `smu_v13_0_4_mode2_reset`: GfxDeviceDriverReset (0x11) with
/// MODE2_RESET (2) as its argument, only once PMFW's versions are known.
fn smu_phoenix_mode2_reset_message() -> TestResult {
    if (v13::V13_MSG_GFX_DEVICE_DRIVER_RESET, MODE2_RESET) != (0x11, 2) {
        return TestResult::Fail("GfxDeviceDriverReset message or argument");
    }
    let mut cold = engine(&[Some((RESP_OK, 0))]);
    if run(cold.started_with(v13::V13_MSG_GFX_DEVICE_DRIVER_RESET, MODE2_RESET))
        != Err(Error::NotStarted)
        || !cold.io.log.is_empty()
    {
        return TestResult::Fail("mode 2 sent before start");
    }
    let mut e = engine(&[
        Some((RESP_OK, TEST_SENTINEL)),
        Some((RESP_OK, 0x0050_4800)),
        Some((RESP_OK, SMU_13_0_4_DRIVER_IF_VERSION)),
        Some((RESP_OK, 0)),
    ]);
    if run(e.start()).is_err()
        || run(e.started_with(v13::V13_MSG_GFX_DEVICE_DRIVER_RESET, MODE2_RESET)).is_err()
        || e.io.log[e.io.log.len() - 3..]
            != [
                (RESP, 0),
                (ARG, 2),
                (MSG, v13::V13_MSG_GFX_DEVICE_DRIVER_RESET),
            ]
    {
        return TestResult::Fail("mode 2 reset message");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/smu-phoenix", smu_phoenix_mode2_reset_message);

/// VCN and JPEG power use the 13.0.4 ids (0x06/0x07 and 0x21/0x22), and
/// GFXOFF uses 0x19/0x1A — not Raphael's 0x05/0x06, 0x12/0x13, 0x16/0x17.
fn smu_phoenix_vcn_jpeg_gfxoff_messages() -> TestResult {
    let mut e = engine(&[
        Some((RESP_OK, TEST_SENTINEL)),
        Some((RESP_OK, 0x0050_4800)),
        Some((RESP_OK, SMU_13_0_4_DRIVER_IF_VERSION)),
        Some((RESP_OK, 0)),
        Some((RESP_OK, 0)),
        Some((RESP_OK, 0)),
        Some((RESP_OK, 0)),
        Some((RESP_OK, 0)),
    ]);
    if run(e.start()).is_err() {
        return TestResult::Fail("start failed");
    }
    let base = e.io.log.len();
    // Each control message writes (RESP, 0), (ARG, 0), (MSG, id).
    if run(e.set_vcn_power(true)).is_err()
        || e.io.log.last() != Some(&(MSG, v13::V13_MSG_POWER_UP_VCN))
        || run(e.set_vcn_power(false)).is_err()
        || e.io.log.last() != Some(&(MSG, v13::V13_MSG_POWER_DOWN_VCN))
        || run(e.set_jpeg_power(true)).is_err()
        || e.io.log.last() != Some(&(MSG, v13::V13_MSG_POWER_UP_JPEG))
        || run(e.set_jpeg_power(false)).is_err()
        || e.io.log.last() != Some(&(MSG, v13::V13_MSG_POWER_DOWN_JPEG))
        || run(e.set_gfxoff(true)).is_err()
        || e.io.log.last() != Some(&(MSG, v13::V13_MSG_ALLOW_GFX_OFF))
        || e.io.log.len() != base + 5 * 3
    {
        return TestResult::Fail("VCN/JPEG/GFXOFF message ids");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/smu-phoenix",
    smu_phoenix_vcn_jpeg_gfxoff_messages
);

/// A refusal is the firmware's status and leaves the mailbox usable; an
/// unknown response marks it hung, after which nothing is sent.
fn smu_phoenix_rejection_and_hang_follow_smu_cmn() -> TestResult {
    let mut e = engine(&[
        Some((RESP_OK, TEST_SENTINEL)),
        Some((RESP_OK, 1)),
        Some((RESP_OK, SMU_13_0_4_DRIVER_IF_VERSION)),
        Some((RESP_PREREQ, 0)),
        Some((RESP_OK, 0)),
        Some((0x42, 0)),
    ]);
    run(e.start()).unwrap();
    if run(e.started(v13::V13_MSG_POWER_UP_VCN)) != Err(Error::Rejected(RESP_PREREQ)) {
        return TestResult::Fail("rejection not reported with its status");
    }
    if run(e.started(v13::V13_MSG_POWER_UP_JPEG)).is_err() {
        return TestResult::Fail("mailbox unusable after a rejection");
    }
    if run(e.started(v13::V13_MSG_ALLOW_GFX_OFF)) != Err(Error::Hung) {
        return TestResult::Fail("unknown response not treated as hung firmware");
    }
    let writes = e.io.log.len();
    let reads = e.io.reads;
    if run(e.started(v13::V13_MSG_DISALLOW_GFX_OFF)) != Err(Error::Hung)
        || e.io.log.len() != writes
        || e.io.reads != reads
    {
        return TestResult::Fail("message sent to hung firmware");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/smu-phoenix",
    smu_phoenix_rejection_and_hang_follow_smu_cmn
);

/// A message that never answers times out.
fn smu_phoenix_unanswered_message_times_out() -> TestResult {
    let mut e = engine(&[
        Some((RESP_OK, TEST_SENTINEL)),
        Some((RESP_OK, 1)),
        Some((RESP_OK, SMU_13_0_4_DRIVER_IF_VERSION)),
        None,
    ]);
    run(e.start()).unwrap();
    if run(e.started(v13::V13_MSG_POWER_UP_VCN)) != Err(Error::Timeout) {
        return TestResult::Fail("unanswered message did not time out");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/smu-phoenix",
    smu_phoenix_unanswered_message_times_out
);

/// Revoked PCI authority stops the mailbox before any MMIO access.
fn smu_phoenix_revocation_blocks_every_access() -> TestResult {
    let mut e = engine(&[
        Some((RESP_OK, TEST_SENTINEL)),
        Some((RESP_OK, 1)),
        Some((RESP_OK, SMU_13_0_4_DRIVER_IF_VERSION)),
    ]);
    e.authority.revoke();
    if run(e.start()) != Err(Error::Revoked) || e.io.reads != 0 || !e.io.log.is_empty() {
        return TestResult::Fail("revoked authority reached the mailbox");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/smu-phoenix",
    smu_phoenix_revocation_blocks_every_access
);

/// A vanished device reads back all ones; the liveness check reports it
/// instead of mistaking the ones for a response.
fn smu_phoenix_vanished_device_reports_device_gone() -> TestResult {
    let mut e = engine(&[
        Some((RESP_OK, TEST_SENTINEL)),
        Some((RESP_OK, 1)),
        Some((RESP_OK, SMU_13_0_4_DRIVER_IF_VERSION)),
    ]);
    e.io.response = u32::MAX;
    if run(e.start()) != Err(Error::DeviceGone) {
        return TestResult::Fail("vanished device not reported");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/smu-phoenix",
    smu_phoenix_vanished_device_reports_device_gone
);

/// The constructor admits only Phoenix (HawkPoint1 / Phoenix1 / Phoenix2)
/// with MP1 13.0.4 or 13.0.11 at BASE_IDX 1. Strix shares
/// `Family::Phoenix` but is RDNA3.5 and must not take this mailbox.
fn smu_phoenix_resolves_only_the_audited_layout() -> TestResult {
    use crate::amdgpu_discovery as d;
    let gpu = || {
        let mut gpu = crate::amdgpu_navi22_boot::tests::gpu();
        gpu.chip = crate::amdgpu::__test_chip_info_for_pci_id(
            crate::amdgpu::AMD_VENDOR,
            crate::amdgpu::PHOENIX1,
        )
        .unwrap();
        let template = gpu.ip_blocks[0];
        let ip = |id, v: (u8, u8, u8), base1: u32| {
            let mut block = template;
            block.hw_id = id;
            (block.major, block.minor, block.revision) = v;
            block.num_bases = 2;
            block.base_addrs[1] = base1;
            block
        };
        gpu.ip_blocks = vec![ip(d::HW_ID_MP1, (13, 0, 4), 0x2000)];
        gpu
    };
    if resolve(&gpu()) != Ok(0x2000 * 4) {
        return TestResult::Fail("Phoenix SMU layout refused");
    }
    let mut mp1_11 = gpu();
    mp1_11.ip_blocks[0].minor = 0;
    mp1_11.ip_blocks[0].revision = 11;
    if resolve(&mp1_11) != Ok(0x2000 * 4) {
        return TestResult::Fail("MP1 13.0.11 not admitted");
    }
    let mut strix = gpu();
    strix.chip = crate::amdgpu::__test_chip_info_for_pci_id(
        crate::amdgpu::AMD_VENDOR,
        crate::amdgpu::STRIX_POINT,
    )
    .unwrap();
    let mut navi22 = gpu();
    navi22.chip = crate::amdgpu::__test_chip_info_for_pci_id(
        crate::amdgpu::AMD_VENDOR,
        crate::amdgpu::NAVI22,
    )
    .unwrap();
    let mut smu5 = gpu();
    (smu5.ip_blocks[0].minor, smu5.ip_blocks[0].revision) = (0, 5);
    let mut window0 = gpu();
    window0.ip_blocks[0].num_bases = 1;
    for (bad, why) in [
        (strix, "SMU 13.0.4 mailbox admitted Strix"),
        (navi22, "SMU 13.0.4 mailbox admitted a discrete GPU"),
        (smu5, "SMU 13.0.4 mailbox admitted MP1 13.0.5"),
        (window0, "SMU 13.0.4 mailbox admitted a window-0-only MP1"),
    ] {
        if resolve(&bad) != Err(Error::Unsupported) {
            return TestResult::Fail(why);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/smu-phoenix",
    smu_phoenix_resolves_only_the_audited_layout
);
