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
pub(crate) fn firmware() -> Firmware {
    Firmware { bytes: container() }
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
    staged: Vec<u8>,
    stage_error: Option<Error>,
    revoke_on: Option<(u32, Cap<BusDeviceCap, Write>)>,
    running: u64,
    gfx_limits: (u32, u32),
}
impl Io for Fake {
    fn stage_power(
        &mut self,
        _memory: &crate::amdgpu_vram::Reservation,
        bytes: &[u8],
    ) -> Result<(), Error> {
        if bytes.len() != crate::amdgpu_power_navi22::SMC_BYTES {
            return Err(Error::Invalid);
        }
        if let Some(error) = self.stage_error {
            return Err(error);
        }
        self.staged.extend_from_slice(bytes);
        Ok(())
    }
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
                if matches!(value, SET_DRIVER_HIGH | SET_DRIVER_LOW | TRANSFER_TABLE) {
                    assert_eq!(self.staged.len(), crate::amdgpu_power_navi22::SMC_BYTES);
                } else if !matches!(value, ALLOWED_HIGH | ALLOWED_LOW) {
                    assert_eq!(self.argument, 0);
                }
                if let Some((message, cap)) = self.revoke_on {
                    if message == value {
                        cap.revoke();
                    }
                }
                if self.stall != Some(value) {
                    self.response = self
                        .reject
                        .filter(|(msg, _)| *msg == value)
                        .map_or(1, |(_, result)| result);
                    self.argument = match value {
                        GET_INTERFACE => self.interface,
                        GET_VERSION => self.firmware,
                        SET_DRIVER_HIGH | SET_DRIVER_LOW | TRANSFER_TABLE => self.argument,
                        RUN_DC_BTC | ALLOWED_HIGH | ALLOWED_LOW | ENABLE_FEATURES => 0,
                        RUNNING_LOW => self.running as u32,
                        RUNNING_HIGH => (self.running >> 32) as u32,
                        MIN_DPM_FREQ => self.gfx_limits.0,
                        MAX_DPM_FREQ => self.gfx_limits.1,
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
            staged: Vec::new(),
            stage_error: None,
            revoke_on: None,
            running: crate::amdgpu_power_navi22::BootPolicy::from_features(u64::MAX)
                .unwrap()
                .allowed(),
            gfx_limits: (500, 2600),
        },
        authority: Cap::bootstrap(),
        state: State::Prepared,
        power_memory: None,
        power_policy: None,
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

fn power_pool() -> crate::amdgpu_vram::Pool {
    // SAFETY: fake IO only; address bookkeeping never dereferences this map.
    unsafe {
        crate::amdgpu_vram::Pool::from_owned_range(
            narf_bus::MmioRegion {
                phys: narf_memory::PhysAddr::new(0x9000_0000),
                virt: 0,
                len: 4096,
                kind: narf_bus::BarKind::Mmio64 { prefetchable: true },
            },
            0x12_3456_0000,
        )
        .unwrap()
    }
}
fn ready_engine() -> Engine<Fake> {
    let mut engine = engine();
    run(engine.verify()).unwrap();
    engine.io.writes.clear();
    engine
}
fn smu_navi22_power_upload_orders_addresses_and_retains_buffer() -> TestResult {
    let mut engine = ready_engine();
    let pool = power_pool();
    let table = vec![0xa5; crate::amdgpu_power_navi22::SMC_BYTES];
    if run(engine.upload(&table, &pool)) != Ok(())
        || engine.state != State::PowerTableReady
        || engine.io.staged != table
        || engine.io.writes
            != [
                (RESPONSE, 0),
                (ARGUMENT, 0x12),
                (MESSAGE, SET_DRIVER_HIGH),
                (RESPONSE, 0),
                (ARGUMENT, 0x3456_0000),
                (MESSAGE, SET_DRIVER_LOW),
                (RESPONSE, 0),
                (ARGUMENT, 0),
                (MESSAGE, TRANSFER_TABLE),
            ]
        || engine
            .power_memory
            .as_ref()
            .is_none_or(|memory| memory.reusable_for_test())
        || run(engine.upload(&table, &pool)) != Err(Error::Busy)
    {
        return TestResult::Fail("SMU table publication/address/command ordering");
    }
    drop(engine);
    if pool.reserve(4096).is_ok() {
        return TestResult::Fail("SMU's retained driver address was recycled");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/smu-navi22",
    smu_navi22_power_upload_orders_addresses_and_retains_buffer
);

fn smu_navi22_power_upload_faults_quarantine_every_published_address() -> TestResult {
    let table = vec![0; crate::amdgpu_power_navi22::SMC_BYTES];
    for (index, command) in [SET_DRIVER_HIGH, SET_DRIVER_LOW, TRANSFER_TABLE]
        .into_iter()
        .enumerate()
    {
        for cancel in [false, true] {
            let mut engine = ready_engine();
            let pool = power_pool();
            if cancel {
                engine.io.stall = Some(command);
                let mut future = core::pin::pin!(engine.upload(&table, &pool));
                let mut context = Context::from_waker(Waker::noop());
                if future.as_mut().poll(&mut context).is_ready() {
                    return TestResult::Fail("stalled SMU command completed");
                }
            } else {
                engine.io.reject = Some((command, 0xfe));
                if run(engine.upload(&table, &pool)) != Err(Error::Rejected(0xfe)) {
                    return TestResult::Fail("SMU table rejection ignored");
                }
            }
            let writes = engine.io.writes.len();
            if writes != (index + 1) * 3
                || engine.power_memory.is_none()
                || run(engine.upload(&table, &pool)) != Err(Error::Busy)
                || engine.io.writes.len() != writes
            {
                return TestResult::Fail("cancelled/failed SMU upload replayed");
            }
            drop(engine);
            if pool.reserve(4096).is_ok() {
                return TestResult::Fail("failed SMU address publication reused");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/smu-navi22",
    smu_navi22_power_upload_faults_quarantine_every_published_address
);

fn smu_navi22_power_upload_policy_and_revocation_precede_commands() -> TestResult {
    let table = vec![0; crate::amdgpu_power_navi22::SMC_BYTES];
    for revoked in [false, true] {
        let mut engine = ready_engine();
        let pool = power_pool();
        let error = if revoked {
            engine.authority.revoke();
            Error::Revoked
        } else {
            engine.io.stage_error = Some(Error::PowerPolicy(1));
            Error::PowerPolicy(1)
        };
        if run(engine.upload(&table, &pool)) != Err(error)
            || !engine.io.writes.is_empty()
            || engine.power_memory.is_some()
            || pool.reserve(4096).is_err()
        {
            return TestResult::Fail("policy/revocation published an SMU address");
        }
    }
    let mut engine = ready_engine();
    let pool = power_pool();
    engine.io.revoke_on = Some((SET_DRIVER_HIGH, engine.authority));
    if run(engine.upload(&table, &pool)) != Err(Error::Revoked) || engine.io.writes.len() != 3 {
        return TestResult::Fail("revoked transfer continued after first address command");
    }
    drop(engine);
    if pool.reserve(4096).is_ok() {
        return TestResult::Fail("revoked transfer buffer freed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/smu-navi22",
    smu_navi22_power_upload_policy_and_revocation_precede_commands
);

fn smu_navi22_scpm_runtime_policy_fails_closed() -> TestResult {
    let mut db = vec![0u8; 64];
    let read = |bytes: &[u8]| {
        power_policy(|offset, out| {
            out.copy_from_slice(
                bytes
                    .get(offset..offset + out.len())
                    .ok_or(crate::amdgpu_gddr6::Error::Invalid)?,
            );
            Ok(())
        })
    };
    if read(&db) != Ok(()) {
        return TestResult::Fail("absent runtime DB refused");
    }
    db[..8].copy_from_slice(&[0xd5, 0xe, 0, 1, 1, 0, 0, 0]);
    db[8..16].copy_from_slice(&[6, 0, 0, 0, 32, 0, 4, 0]);
    for policy in [0, 1, 2, u32::MAX] {
        put(&mut db, 32, policy);
        let want = if policy == 0 {
            Ok(())
        } else {
            Err(Error::PowerPolicy(policy))
        };
        if read(&db) != want {
            return TestResult::Fail("PSP power ownership ignored");
        }
    }
    for (offset, value) in [(2, 1), (4, 64), (12, 8), (12, 33), (14, 3)] {
        let mut bad = db.clone();
        bad[offset] = value;
        if read(&bad) != Err(Error::Invalid) {
            return TestResult::Fail("malformed runtime policy accepted");
        }
    }
    db[4] = 2;
    let entry = db[8..16].to_vec();
    db[16..24].copy_from_slice(&entry);
    if read(&db) != Err(Error::Invalid) {
        return TestResult::Fail("duplicate SCPM entries accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/smu-navi22",
    smu_navi22_scpm_runtime_policy_fails_closed
);

fn uploaded_engine() -> (Engine<Fake>, crate::amdgpu_vram::Pool) {
    let mut engine = ready_engine();
    let pool = power_pool();
    run(engine.upload(&vec![0; crate::amdgpu_power_navi22::SMC_BYTES], &pool)).unwrap();
    engine.power_policy =
        Some(crate::amdgpu_power_navi22::BootPolicy::from_features(u64::MAX).unwrap());
    engine.io.writes.clear();
    (engine, pool)
}
fn smu_navi22_calibrates_protects_and_reports_board_limits() -> TestResult {
    let (mut engine, _pool) = uploaded_engine();
    let status = run(engine.configure_power()).unwrap();
    let commands: Vec<_> = engine
        .io
        .writes
        .chunks_exact(3)
        .map(|writes| (writes[2].1, writes[1].1))
        .collect();
    if commands
        != [
            (0x36, 0),
            (5, (status.allowed >> 32) as u32),
            (4, status.allowed as u32),
            (6, 0),
            (0xc, 0),
            (0xd, 0),
            (0x1d, 0),
            (0x1e, 0),
        ]
        || status.enabled != status.allowed
        || status.gfx_min_mhz != 500
        || status.gfx_max_mhz != 2600
        || engine.state != State::PowerReady
        || run(engine.configure_power()) != Err(Error::Busy)
    {
        return TestResult::Fail("calibration/feature policy/clock limit protocol");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/smu-navi22",
    smu_navi22_calibrates_protects_and_reports_board_limits
);

fn smu_navi22_power_setup_faults_never_replay_or_release() -> TestResult {
    for (index, message) in [0x36, 5, 4, 6, 0xc, 0xd, 0x1d, 0x1e]
        .into_iter()
        .enumerate()
    {
        for fault in 0..3 {
            let (mut engine, pool) = uploaded_engine();
            match fault {
                0 => {
                    engine.io.reject = Some((message, 0xfd));
                    if run(engine.configure_power()) != Err(Error::Rejected(0xfd)) {
                        return TestResult::Fail("power setup rejection ignored");
                    }
                }
                1 => {
                    engine.io.stall = Some(message);
                    let mut future = core::pin::pin!(engine.configure_power());
                    if future
                        .as_mut()
                        .poll(&mut Context::from_waker(Waker::noop()))
                        .is_ready()
                    {
                        return TestResult::Fail("stalled power setup finished");
                    }
                }
                _ => {
                    engine.io.revoke_on = Some((message, engine.authority));
                    if run(engine.configure_power()) != Err(Error::Revoked) {
                        return TestResult::Fail("power setup bypassed revocation");
                    }
                }
            }
            let writes = engine.io.writes.len();
            if writes != (index + 1) * 3
                || run(engine.configure_power()) != Err(Error::Busy)
                || engine.io.writes.len() != writes
            {
                return TestResult::Fail("power setup continued or replayed after a fault");
            }
            drop(engine);
            if pool.reserve(4096).is_ok() {
                return TestResult::Fail("SMU driver buffer released after power setup fault");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/smu-navi22",
    smu_navi22_power_setup_faults_never_replay_or_release
);

fn smu_navi22_power_setup_rejects_unprotected_dpm_and_bad_limits() -> TestResult {
    for case in 0..6 {
        let (mut engine, _pool) = uploaded_engine();
        match case {
            0 => engine.io.running &= !(1 << 33), // thermal protection absent
            1 => engine.io.running |= 1 << 3,     // UCLK transitions unowned
            2 => engine.io.running = u64::MAX,
            3 => engine.io.gfx_limits = (0, 2600),
            4 => engine.io.gfx_limits = (2600, 500),
            _ => engine.io.gfx_limits = (500, u32::MAX),
        }
        if run(engine.configure_power()).is_ok() || engine.state != State::Failed {
            return TestResult::Fail("bad feature acknowledgement or clock limits accepted");
        }
    }
    let mut engine = ready_engine();
    if run(engine.configure_power()) != Err(Error::Busy) || !engine.io.writes.is_empty() {
        return TestResult::Fail("power setup ran before table upload");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/smu-navi22",
    smu_navi22_power_setup_rejects_unprotected_dpm_and_bad_limits
);
