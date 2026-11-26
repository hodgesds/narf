use super::*;
use crate::amdgpu_smu::{MP1_C2PMSG_ARG_REL, MP1_C2PMSG_MSG_REL};
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
    /// Scripted `MP1_FIRMWARE_FLAGS` value for the SMN read, and the
    /// addresses the engine read through it.
    smn_flags: u32,
    smn_reads: Vec<u32>,
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
    fn read_smn(&mut self, address: u32) -> u32 {
        self.smn_reads.push(address);
        self.smn_flags
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
            smn_flags: FIRMWARE_FLAGS_INTERRUPTS_ENABLED,
            smn_reads: Vec::new(),
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
/// Fixture PMFW version (arbitrary): the test checks the value is read
/// and stored, not what it decodes to.
const PMFW_VERSION: u32 = 0x000E_0100;

/// The Strix mailbox offsets are the Phoenix offsets — the same MP1
/// window-1 C2PMSG_66/82/90 mailbox — and the v14 opcodes are the
/// `smu_v14_0_0_ppsmc.h` ids, not the v13 ids.
fn smu_strix_mailbox_offsets_and_v14_opcodes() -> TestResult {
    if (MP1_C2PMSG_ARG_REL, MP1_C2PMSG_MSG_REL, MP1_C2PMSG_RESP_REL) != (0xA08, 0xA48, 0xA68) {
        return TestResult::Fail("C2PMSG_66/82/90 offsets");
    }
    if (
        v14::V14_MSG_TEST,
        v14::V14_MSG_GET_PMFW_VERSION,
        v14::V14_MSG_GET_DRIVER_IF,
    ) != (0x01, 0x02, 0x03)
        || (v14::V14_MSG_ALLOW_GFX_OFF, v14::V14_MSG_DISALLOW_GFX_OFF) != (0x19, 0x1A)
        || (v14::V14_MSG_POWER_UP_VCN0, v14::V14_MSG_POWER_DOWN_VCN0) != (0x07, 0x06)
        || (v14::V14_MSG_POWER_UP_VCN1, v14::V14_MSG_POWER_DOWN_VCN1) != (0x05, 0x04)
        || (v14::V14_MSG_POWER_UP_JPEG0, v14::V14_MSG_POWER_DOWN_JPEG0) != (0x22, 0x21)
        || (v14::V14_MSG_POWER_UP_JPEG1, v14::V14_MSG_POWER_DOWN_JPEG1) != (0x27, 0x26)
        || v14::V14_MSG_GFX_DEVICE_DRIVER_RESET != 0x11
    {
        return TestResult::Fail("SMU 14.0.0 opcodes");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/smu-strix",
    smu_strix_mailbox_offsets_and_v14_opcodes
);

/// `start` runs the shared bring-up order — TestMessage echo, then
/// GetPmfwVersion, then GetDriverIfVersion — and each send clears the
/// response, writes the argument, then the id.
fn smu_strix_start_reads_versions_in_linux_order() -> TestResult {
    let mut e = engine(&[
        Some((RESP_OK, TEST_SENTINEL)),
        Some((RESP_OK, PMFW_VERSION)),
        Some((RESP_OK, SMU_14_0_0_DRIVER_IF_VERSION)),
        Some((RESP_OK, 0)),
    ]);
    let versions = run(e.start());
    let expected_writes = vec![
        (RESP, 0),
        (ARG, TEST_SENTINEL),
        (MSG, v14::V14_MSG_TEST),
        (RESP, 0),
        (ARG, 0),
        (MSG, v14::V14_MSG_GET_PMFW_VERSION),
        (RESP, 0),
        (ARG, 0),
        (MSG, v14::V14_MSG_GET_DRIVER_IF),
    ];
    let wanted = Versions {
        smu: PMFW_VERSION,
        driver_if: SMU_14_0_0_DRIVER_IF_VERSION,
    };
    if versions != Ok(wanted)
        || !wanted.driver_if_matches()
        || e.versions != Some(wanted)
        || e.io.log != expected_writes
    {
        return TestResult::Fail("start sequence or versions");
    }
    if run(e.started(v14::V14_MSG_DISALLOW_GFX_OFF)).is_err()
        || e.io.log.last() != Some(&(MSG, v14::V14_MSG_DISALLOW_GFX_OFF))
    {
        return TestResult::Fail("GFXOFF message after start");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/smu-strix",
    smu_strix_start_reads_versions_in_linux_order
);

/// A driver-IF of 0x6 — the value MP1 14.0.1 (Strix Halo) reports — is
/// refused and leaves the versions unread. There is no accepted newer
/// value on 14.0.0, unlike Phoenix's 8.
fn smu_strix_driver_if_six_is_refused() -> TestResult {
    let mut e = engine(&[
        Some((RESP_OK, TEST_SENTINEL)),
        Some((RESP_OK, PMFW_VERSION)),
        Some((RESP_OK, 6)),
    ]);
    if run(e.start()) != Err(Error::DriverIfMismatch(6)) || e.versions.is_some() {
        return TestResult::Fail("driver-IF 6 was accepted or the versions leaked");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/smu-strix", smu_strix_driver_if_six_is_refused);

/// The firmware-flags gate runs before any message: a clear
/// INTERRUPTS_ENABLED bit fails `start` with `FirmwareNotReady` and
/// sends nothing, while a set bit lets the mailbox sequence run. The
/// SMN read goes to `MP1_FIRMWARE_FLAGS` (0x03b10028).
fn smu_strix_firmware_flags_gate() -> TestResult {
    let mut cold = engine(&[
        Some((RESP_OK, TEST_SENTINEL)),
        Some((RESP_OK, PMFW_VERSION)),
        Some((RESP_OK, SMU_14_0_0_DRIVER_IF_VERSION)),
    ]);
    cold.io.smn_flags = 0;
    if run(cold.start()) != Err(Error::FirmwareNotReady)
        || !cold.io.log.is_empty()
        || cold.io.reads != 0
        || cold.versions.is_some()
    {
        return TestResult::Fail("firmware-flags gate did not fail closed first");
    }
    if cold.io.smn_reads != [MP1_FIRMWARE_FLAGS] {
        return TestResult::Fail("firmware-flags read went to the wrong address");
    }
    let mut e = engine(&[
        Some((RESP_OK, TEST_SENTINEL)),
        Some((RESP_OK, PMFW_VERSION)),
        Some((RESP_OK, SMU_14_0_0_DRIVER_IF_VERSION)),
    ]);
    if run(e.start()).is_err() || e.io.smn_reads != [MP1_FIRMWARE_FLAGS] {
        return TestResult::Fail("firmware-flags gate blocked a ready firmware");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/smu-strix", smu_strix_firmware_flags_gate);

/// A TestMessage that does not echo the sentinel fails start before any
/// version is read.
fn smu_strix_echo_mismatch_fails_start() -> TestResult {
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
kernel_test_in!("drivers/gpu/smu-strix", smu_strix_echo_mismatch_fails_start);

/// `smu_v14_0_0_mode2_reset`: GfxDeviceDriverReset (0x11) with
/// MODE2_RESET (2) as its argument, only once PMFW's versions are known.
fn smu_strix_mode2_reset_message() -> TestResult {
    if (v14::V14_MSG_GFX_DEVICE_DRIVER_RESET, MODE2_RESET) != (0x11, 2) {
        return TestResult::Fail("GfxDeviceDriverReset message or argument");
    }
    let mut cold = engine(&[Some((RESP_OK, 0))]);
    if run(cold.started_with(v14::V14_MSG_GFX_DEVICE_DRIVER_RESET, MODE2_RESET))
        != Err(Error::NotStarted)
        || !cold.io.log.is_empty()
    {
        return TestResult::Fail("mode 2 sent before start");
    }
    let mut e = engine(&[
        Some((RESP_OK, TEST_SENTINEL)),
        Some((RESP_OK, PMFW_VERSION)),
        Some((RESP_OK, SMU_14_0_0_DRIVER_IF_VERSION)),
        Some((RESP_OK, 0)),
    ]);
    if run(e.start()).is_err()
        || run(e.started_with(v14::V14_MSG_GFX_DEVICE_DRIVER_RESET, MODE2_RESET)).is_err()
        || e.io.log[e.io.log.len() - 3..]
            != [
                (RESP, 0),
                (ARG, 2),
                (MSG, v14::V14_MSG_GFX_DEVICE_DRIVER_RESET),
            ]
    {
        return TestResult::Fail("mode 2 reset message");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/smu-strix", smu_strix_mode2_reset_message);

/// VCN and JPEG power are per-instance on v14 — VCN0 0x07/0x06, VCN1
/// 0x05/0x04, JPEG0 0x22/0x21, JPEG1 0x27/0x26 — and GFXOFF is 0x19/0x1A.
/// There is no generic VCN/JPEG message and no instance 2.
fn smu_strix_vcn_jpeg_gfxoff_messages() -> TestResult {
    if v14::vcn_power_msg(0, true) != Some(v14::V14_MSG_POWER_UP_VCN0)
        || v14::vcn_power_msg(0, false) != Some(v14::V14_MSG_POWER_DOWN_VCN0)
        || v14::vcn_power_msg(1, true) != Some(v14::V14_MSG_POWER_UP_VCN1)
        || v14::vcn_power_msg(1, false) != Some(v14::V14_MSG_POWER_DOWN_VCN1)
        || v14::vcn_power_msg(2, true).is_some()
        || v14::jpeg_power_msg(0, true) != Some(v14::V14_MSG_POWER_UP_JPEG0)
        || v14::jpeg_power_msg(0, false) != Some(v14::V14_MSG_POWER_DOWN_JPEG0)
        || v14::jpeg_power_msg(1, true) != Some(v14::V14_MSG_POWER_UP_JPEG1)
        || v14::jpeg_power_msg(1, false) != Some(v14::V14_MSG_POWER_DOWN_JPEG1)
        || v14::jpeg_power_msg(2, false).is_some()
    {
        return TestResult::Fail("per-instance VCN/JPEG message ids");
    }
    let mut e = engine(&[
        Some((RESP_OK, TEST_SENTINEL)),
        Some((RESP_OK, PMFW_VERSION)),
        Some((RESP_OK, SMU_14_0_0_DRIVER_IF_VERSION)),
        Some((RESP_OK, 0)),
        Some((RESP_OK, 0)),
        Some((RESP_OK, 0)),
        Some((RESP_OK, 0)),
        Some((RESP_OK, 0)),
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
    let messages = [
        v14::V14_MSG_POWER_UP_VCN0,
        v14::V14_MSG_POWER_DOWN_VCN0,
        v14::V14_MSG_POWER_UP_VCN1,
        v14::V14_MSG_POWER_DOWN_VCN1,
        v14::V14_MSG_POWER_UP_JPEG0,
        v14::V14_MSG_POWER_DOWN_JPEG0,
        v14::V14_MSG_POWER_UP_JPEG1,
        v14::V14_MSG_POWER_DOWN_JPEG1,
        v14::V14_MSG_ALLOW_GFX_OFF,
        v14::V14_MSG_DISALLOW_GFX_OFF,
    ];
    for message in messages {
        if run(e.started(message)).is_err() || e.io.log.last() != Some(&(MSG, message)) {
            return TestResult::Fail("a v14 power message failed after start");
        }
    }
    if e.io.log.len() != base + messages.len() * 3 {
        return TestResult::Fail("the v14 power messages did not all log");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/smu-strix", smu_strix_vcn_jpeg_gfxoff_messages);

/// A refusal is the firmware's status and leaves the mailbox usable; an
/// unknown response marks it hung, after which nothing is sent.
fn smu_strix_rejection_and_hang_follow_smu_cmn() -> TestResult {
    let mut e = engine(&[
        Some((RESP_OK, TEST_SENTINEL)),
        Some((RESP_OK, PMFW_VERSION)),
        Some((RESP_OK, SMU_14_0_0_DRIVER_IF_VERSION)),
        Some((RESP_PREREQ, 0)),
        Some((RESP_OK, 0)),
        Some((0x42, 0)),
    ]);
    run(e.start()).unwrap();
    if run(e.started(v14::V14_MSG_POWER_UP_VCN0)) != Err(Error::Rejected(RESP_PREREQ)) {
        return TestResult::Fail("rejection not reported with its status");
    }
    if run(e.started(v14::V14_MSG_POWER_UP_JPEG0)).is_err() {
        return TestResult::Fail("mailbox unusable after a rejection");
    }
    if run(e.started(v14::V14_MSG_ALLOW_GFX_OFF)) != Err(Error::Hung) {
        return TestResult::Fail("unknown response not treated as hung firmware");
    }
    let writes = e.io.log.len();
    let reads = e.io.reads;
    if run(e.started(v14::V14_MSG_DISALLOW_GFX_OFF)) != Err(Error::Hung)
        || e.io.log.len() != writes
        || e.io.reads != reads
    {
        return TestResult::Fail("message sent to hung firmware");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/smu-strix",
    smu_strix_rejection_and_hang_follow_smu_cmn
);

/// A message that never answers times out.
fn smu_strix_unanswered_message_times_out() -> TestResult {
    let mut e = engine(&[
        Some((RESP_OK, TEST_SENTINEL)),
        Some((RESP_OK, PMFW_VERSION)),
        Some((RESP_OK, SMU_14_0_0_DRIVER_IF_VERSION)),
        None,
    ]);
    run(e.start()).unwrap();
    if run(e.started(v14::V14_MSG_POWER_UP_VCN0)) != Err(Error::Timeout) {
        return TestResult::Fail("unanswered message did not time out");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/smu-strix",
    smu_strix_unanswered_message_times_out
);

/// Revoked PCI authority stops the mailbox before any MMIO access.
fn smu_strix_revocation_blocks_every_access() -> TestResult {
    let mut e = engine(&[
        Some((RESP_OK, TEST_SENTINEL)),
        Some((RESP_OK, PMFW_VERSION)),
        Some((RESP_OK, SMU_14_0_0_DRIVER_IF_VERSION)),
    ]);
    e.authority.revoke();
    if run(e.start()) != Err(Error::Revoked) || e.io.reads != 0 || !e.io.log.is_empty() {
        return TestResult::Fail("revoked authority reached the mailbox");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/smu-strix",
    smu_strix_revocation_blocks_every_access
);

/// A vanished device reads back all ones; the liveness check reports it
/// instead of mistaking the ones for a response.
fn smu_strix_vanished_device_reports_device_gone() -> TestResult {
    let mut e = engine(&[
        Some((RESP_OK, TEST_SENTINEL)),
        Some((RESP_OK, PMFW_VERSION)),
        Some((RESP_OK, SMU_14_0_0_DRIVER_IF_VERSION)),
    ]);
    e.io.response = u32::MAX;
    if run(e.start()) != Err(Error::DeviceGone) {
        return TestResult::Fail("vanished device not reported");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/smu-strix",
    smu_strix_vanished_device_reports_device_gone
);

/// `resolve` admits only Strix Point (1002:150E) with MP1 14.0.0 at
/// BASE_IDX 1 and an NBIO 7.11 bank at BASE_IDX 0. Phoenix, Navi22, a
/// 13.0.4 mailbox, the 14.0.1 mailbox #2486 admitted (Strix Halo, not
/// Strix Point), a window-0-only layout, and a missing or 7.11.6 NBIO
/// are all refused. NBIO 7.11.5 resolves too: the SMN pair is at the
/// same dwords in both 7.11 headers.
fn smu_strix_resolves_only_the_audited_layout() -> TestResult {
    use crate::amdgpu_discovery as d;
    let gpu = || {
        let mut gpu = crate::amdgpu_navi22_boot::tests::gpu();
        gpu.chip = crate::amdgpu::__test_chip_info_for_pci_id(
            crate::amdgpu::AMD_VENDOR,
            crate::amdgpu::STRIX_POINT,
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
        let mut nbif = template;
        nbif.hw_id = d::HW_ID_NBIF;
        (nbif.major, nbif.minor, nbif.revision) = (7, 11, 0);
        nbif.num_bases = 1;
        nbif.base_addrs[0] = 0x3000;
        gpu.ip_blocks = vec![ip(d::HW_ID_MP1, (14, 0, 0), 0x2000), nbif];
        gpu
    };
    if resolve(&gpu()) != Ok((0x2000 * 4, 0x3000 * 4)) {
        return TestResult::Fail("Strix SMU layout refused");
    }
    let mut nbif5 = gpu();
    nbif5.ip_blocks[1].revision = 5;
    if resolve(&nbif5) != Ok((0x2000 * 4, 0x3000 * 4)) {
        return TestResult::Fail("Strix SMU layout refused NBIO 7.11.5");
    }
    let mut phoenix = gpu();
    phoenix.chip = crate::amdgpu::__test_chip_info_for_pci_id(
        crate::amdgpu::AMD_VENDOR,
        crate::amdgpu::PHOENIX1,
    )
    .unwrap();
    let mut navi22 = gpu();
    navi22.chip = crate::amdgpu::__test_chip_info_for_pci_id(
        crate::amdgpu::AMD_VENDOR,
        crate::amdgpu::NAVI22,
    )
    .unwrap();
    let mut smu1401 = gpu();
    smu1401.ip_blocks[0].revision = 1;
    let mut smu1304 = gpu();
    (smu1304.ip_blocks[0].minor, smu1304.ip_blocks[0].revision) = (0, 4);
    smu1304.ip_blocks[0].major = 13;
    let mut window0 = gpu();
    window0.ip_blocks[0].num_bases = 1;
    let mut no_nbio = gpu();
    no_nbio.ip_blocks.truncate(1);
    let mut nbif716 = gpu();
    nbif716.ip_blocks[1].revision = 6;
    for (bad, why) in [
        (phoenix, "SMU 14.0.0 mailbox admitted Phoenix"),
        (navi22, "SMU 14.0.0 mailbox admitted a discrete GPU"),
        (smu1401, "SMU 14.0.0 mailbox admitted MP1 14.0.1"),
        (smu1304, "SMU 14.0.0 mailbox admitted MP1 13.0.4"),
        (window0, "SMU 14.0.0 mailbox admitted a window-0-only MP1"),
        (no_nbio, "SMU 14.0.0 mailbox admitted a missing NBIO"),
        (nbif716, "SMU 14.0.0 mailbox admitted NBIO 7.11.6"),
    ] {
        if resolve(&bad) != Err(Error::Unsupported) {
            return TestResult::Fail(why);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/smu-strix",
    smu_strix_resolves_only_the_audited_layout
);
