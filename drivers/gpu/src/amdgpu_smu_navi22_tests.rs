use super::*;
use alloc::{vec, vec::Vec};
use core::{
    future::Future,
    task::{Context, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

fn put(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn container() -> Vec<u8> {
    let mut bytes = vec![0; 278];
    for (offset, value) in [
        (0, 278),
        (4, 44),
        (8, 2),
        (12, 11),
        (16, 0x413f00),
        (20, 16),
        (24, 256),
        (32, 0x20000),
        (36, 272),
        (40, 6),
    ] {
        put(&mut bytes, offset, value);
    }
    bytes[256..272].fill(0xa5);
    bytes[272..].fill(0x5a);
    bytes
}
fn smc_container_separates_microcode_and_file_relative_ppt() -> TestResult {
    let bytes = container();
    let image = firmware::Image::parse(&bytes).unwrap();
    if image.payload() != [0xa5; 16]
        || image.powerplay() != Some(&[0x5a; 6][..])
        || image.version() != 0x413f00
    {
        return TestResult::Fail("header/PPT selected as microcode or wrong version");
    }
    for len in 0..bytes.len() {
        if firmware::Image::parse(&bytes[..len]).is_ok() {
            return TestResult::Fail("truncation accepted");
        }
    }
    for (offset, value) in [
        (0, 0),
        (4, 36),
        (8, 1),
        (8, 0x10002),
        (12, 13),
        (20, 0),
        (20, 15),
        (20, u32::MAX),
        (24, 32),
        (24, 255),
        (24, u32::MAX),
        (36, 0),
        (36, 256),
        (36, 268),
        (36, u32::MAX),
        (40, 0),
        (40, u32::MAX),
    ] {
        let mut bad = bytes.clone();
        put(&mut bad, offset, value);
        if firmware::Image::parse(&bad).is_ok() {
            return TestResult::Fail("invalid header or overlapping PPT accepted");
        }
    }
    let mut no_ppt = bytes;
    put(&mut no_ppt, 36, 0);
    put(&mut no_ppt, 40, 0);
    if firmware::Image::parse(&no_ppt)
        .unwrap()
        .powerplay()
        .is_some()
    {
        return TestResult::Fail("absent PPT fabricated");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/smu-navi22",
    smc_container_separates_microcode_and_file_relative_ppt
);

struct Fake {
    response: u32,
    argument: u32,
    interface: u32,
    firmware: u32,
    stall: Option<u32>,
    reject: Option<(u32, u32)>,
    writes: Vec<(u32, u32)>,
    reads: usize,
}
impl Io for Fake {
    fn read(&mut self, register: u32) -> u32 {
        self.reads += 1;
        match register {
            RESPONSE => self.response,
            ARGUMENT => self.argument,
            _ => panic!("unexpected SMU read"),
        }
    }
    fn write(&mut self, register: u32, value: u32) {
        self.writes.push((register, value));
        match register {
            RESPONSE => self.response = value,
            ARGUMENT => self.argument = value,
            MESSAGE => {
                assert_eq!(self.response, 0);
                assert_eq!(self.argument, 0);
                if self.stall != Some(value) {
                    self.response = self
                        .reject
                        .filter(|(msg, _)| *msg == value)
                        .map_or(1, |(_, result)| result);
                    self.argument = match value {
                        GET_INTERFACE => self.interface,
                        GET_VERSION => self.firmware,
                        _ => panic!("unexpected SMU command"),
                    };
                }
            }
            _ => panic!("wrong SMU register"),
        }
    }
}
fn engine() -> Engine<Fake> {
    Engine {
        io: Fake {
            response: 0,
            argument: 0xdeadbeef,
            interface: DRIVER_INTERFACE,
            firmware: 0x413f00,
            stall: None,
            reject: None,
            writes: Vec::new(),
            reads: 0,
        },
        authority: Cap::bootstrap(),
        state: State::Prepared,
    }
}
fn run<T>(future: impl Future<Output = T>) -> T {
    narf_scheduler::block_on_spin(future)
}
fn smu_navi22_cold_mailbox_and_versions() -> TestResult {
    let mut e = engine();
    if run(e.verify())
        != Ok(Versions {
            firmware: 0x413f00,
            interface: 0xe,
        })
        || e.state != State::Ready
    {
        return TestResult::Fail("cold response=0 was not accepted or wrong versions returned");
    }
    if e.io.writes
        != [
            (0x29a, 0),
            (0x292, 0),
            (0x282, 3),
            (0x29a, 0),
            (0x292, 0),
            (0x282, 2),
        ]
    {
        return TestResult::Fail("used APU mailbox roles or sent a power-management command");
    }
    if run(e.verify()) != Err(Error::Busy) || e.io.writes.len() != 6 {
        return TestResult::Fail("handshake replayed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/smu-navi22",
    smu_navi22_cold_mailbox_and_versions
);

fn smu_navi22_rejects_bad_interface_response_and_absent_device() -> TestResult {
    for interface in [0, 0xd, 0xf, 0x40, u32::MAX] {
        let mut e = engine();
        e.io.interface = interface;
        let expected = if interface == u32::MAX {
            Error::DeviceGone
        } else {
            Error::InterfaceMismatch(interface)
        };
        if run(e.verify()) != Err(expected) || e.state != State::Failed || e.io.writes.len() != 3 {
            return TestResult::Fail("unsupported interface accepted or second query issued");
        }
    }
    for message in [GET_INTERFACE, GET_VERSION] {
        for status in [0xfc, 0xfd, 0xfe, 0xff, u32::MAX] {
            let mut e = engine();
            e.io.reject = Some((message, status));
            let expected = if status == u32::MAX {
                Error::DeviceGone
            } else {
                Error::Rejected(status)
            };
            if run(e.verify()) != Err(expected) || e.state != State::Failed {
                return TestResult::Fail("SMU rejection/removal accepted as success");
            }
        }
    }
    for version in [0, u32::MAX] {
        let mut e = engine();
        e.io.firmware = version;
        let expected = if version == 0 {
            Error::Invalid
        } else {
            Error::DeviceGone
        };
        if run(e.verify()) != Err(expected) {
            return TestResult::Fail("invalid runtime firmware version accepted");
        }
    }
    let mut e = engine();
    e.io.response = u32::MAX;
    if run(e.verify()) != Err(Error::DeviceGone) || !e.io.writes.is_empty() {
        return TestResult::Fail("absent device received a command");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/smu-navi22",
    smu_navi22_rejects_bad_interface_response_and_absent_device
);

fn smu_navi22_timeout_cancellation_and_revocation() -> TestResult {
    for message in [GET_INTERFACE, GET_VERSION] {
        let mut e = engine();
        e.io.stall = Some(message);
        {
            let mut future = core::pin::pin!(e.verify());
            if future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_ready()
            {
                return TestResult::Fail("stale argument completed unacknowledged query");
            }
        }
        let before = e.io.writes.len();
        if e.state != State::Querying
            || run(e.verify()) != Err(Error::Busy)
            || e.io.writes.len() != before
        {
            return TestResult::Fail("cancelled query replayed");
        }
    }
    let mut e = engine();
    e.authority.revoke();
    if run(e.verify()) != Err(Error::Revoked) || e.io.reads != 0 || !e.io.writes.is_empty() {
        return TestResult::Fail("revoked authority touched mailbox");
    }
    let mut e = engine();
    e.io.stall = Some(GET_INTERFACE);
    let authority = e.authority;
    {
        let mut future = core::pin::pin!(e.verify());
        if future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_ready()
        {
            return TestResult::Fail("query did not wait");
        }
        authority.revoke();
        if run(future) != Err(Error::Revoked) {
            return TestResult::Fail("suspended query ignored revocation");
        }
    }
    if e.io.reads != 2 || e.io.writes.len() != 3 {
        return TestResult::Fail("I/O continued after revoke");
    }
    let mut e = engine();
    e.io.stall = Some(GET_VERSION);
    if run(e.verify()) != Err(Error::Timeout) || e.state != State::Failed {
        return TestResult::Fail("SMU query lacked bounded timeout");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/smu-navi22",
    smu_navi22_timeout_cancellation_and_revocation
);

fn gpu() -> AmdGpu {
    let map = MmioRegion {
        phys: narf_memory::PhysAddr::new(0),
        virt: 0,
        len: 0x10000,
        kind: narf_bus::BarKind::Mmio32 {
            prefetchable: false,
        },
    };
    let ip = |id, version: (u8, u8, u8)| {
        let mut base_addrs = [0x10000; discovery::MAX_BASE_ADDRS];
        base_addrs[0] = 0x1000;
        discovery::IpBlock {
            hw_id: id,
            instance: 0,
            major: version.0,
            minor: version.1,
            revision: version.2,
            sub_revision: 0,
            variant: 0,
            base_addrs,
            num_bases: 2,
        }
    };
    AmdGpu {
        regs: map,
        fb_bar: map,
        chip: crate::amdgpu::__test_chip_info_for_pci_id(
            crate::amdgpu::AMD_VENDOR,
            crate::amdgpu::NAVI22,
        )
        .unwrap(),
        vram: crate::amdgpu::VramInfo {
            base: 0,
            size: 12 << 30,
            visible_size: 256 << 20,
        },
        mode: None,
        fw_loaded: false,
        gc_info: None,
        vbios: None,
        ip_blocks: vec![
            ip(discovery::HW_ID_GC, (10, 3, 2)),
            ip(discovery::HW_ID_MP1, (11, 0, 11)),
        ],
    }
}
fn smu_navi22_exact_ip_selection_and_revoked_firmware_open() -> TestResult {
    let gpu = gpu();
    if mp1_bank(&gpu) != Ok(0x4000) {
        return TestResult::Fail("MP1 used base index 1");
    }
    // SAFETY: constructor performs no I/O; only the derived address is inspected.
    let smu = unsafe { Smu::after_upload(&gpu, Cap::bootstrap()) }.unwrap();
    if smu.engine.io.base != 0x4000 || smu.state() != State::Prepared {
        return TestResult::Fail("wrong SMU constructor state");
    }
    for case in 0..8 {
        let mut bad = self::gpu();
        match case {
            0 => bad.chip.did = crate::amdgpu::PHOENIX1,
            1 => bad.ip_blocks[0].revision = 1,
            2 => bad.ip_blocks[1].revision = 7,
            3 => bad.ip_blocks.push(bad.ip_blocks[0]),
            4 => bad.ip_blocks.push(bad.ip_blocks[1]),
            5 => bad.ip_blocks[1].num_bases = 0,
            6 => bad.regs.len = 0x4000 + u64::from(RESPONSE) * 4,
            _ => bad.ip_blocks.clear(),
        }
        if mp1_bank(&bad).is_ok() {
            return TestResult::Fail("unaudited MP1/GC or truncated window accepted");
        }
    }
    let authority = Cap::bootstrap();
    authority.revoke();
    if !matches!(Firmware::open(&gpu, &authority), Err(Error::Revoked)) {
        return TestResult::Fail("firmware registry read bypassed live authority");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/smu-navi22",
    smu_navi22_exact_ip_selection_and_revoked_firmware_open
);
