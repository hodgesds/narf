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
    /// PSP runtime DB SCPM status the staging reports.
    scpm: u32,
    revoke_on: Option<(u32, Cap<BusDeviceCap, Write>)>,
    running: u64,
    gfx_limits: (u32, u32),
    /// Retained transfer buffer contents and the PMFW metrics it receives.
    buffer: Vec<u8>,
    metrics: Vec<u8>,
    flushes: usize,
    invalidates: usize,
    ppt_limit: u32,
    thm: [u32; 0x6d],
    smuio_vid: u32,
    mp1_sw: [u32; 2],
    banks: bool,
    /// MP1_FIRMWARE_FLAGS reads before INTERRUPTS_ENABLED is reported.
    fw_not_ready: usize,
    fw_reads: usize,
    /// Feature bits PMFW refuses to change.
    sticky: u64,
}
impl Io for Fake {
    fn write_table(
        &mut self,
        _memory: &crate::amdgpu_vram::Reservation,
        bytes: &[u8],
    ) -> Result<(), Error> {
        self.buffer[..bytes.len()].copy_from_slice(bytes);
        self.flushes += 1;
        Ok(())
    }
    fn read_table(
        &mut self,
        _memory: &crate::amdgpu_vram::Reservation,
        out: &mut [u8],
    ) -> Result<(), Error> {
        self.invalidates += 1;
        out.copy_from_slice(&self.buffer[..out.len()]);
        Ok(())
    }
    fn thm(&mut self, register: u32) -> Result<u32, Error> {
        if !self.banks {
            return Err(Error::Unsupported);
        }
        Ok(self.thm[register as usize])
    }
    fn set_thm(&mut self, register: u32, value: u32) -> Result<(), Error> {
        if !self.banks {
            return Err(Error::Unsupported);
        }
        self.writes.push((0x1_0000 | register, value));
        self.thm[register as usize] = value;
        Ok(())
    }
    fn smuio(&mut self, register: u32) -> Result<u32, Error> {
        assert_eq!(register, SVI0_TEL_PLANE0);
        if !self.banks {
            return Err(Error::Unsupported);
        }
        Ok(self.smuio_vid)
    }
    fn firmware_flags(&mut self) -> Result<u32, Error> {
        assert!(
            self.writes.is_empty(),
            "PPSMC message before firmware ready"
        );
        self.fw_reads += 1;
        Ok(if self.fw_reads > self.fw_not_ready {
            1
        } else {
            0
        })
    }
    fn stage_power(
        &mut self,
        _memory: &crate::amdgpu_vram::Reservation,
        bytes: &[u8],
    ) -> Result<u32, Error> {
        if bytes.len() != crate::amdgpu_power_navi22::SMC_BYTES {
            return Err(Error::Invalid);
        }
        if let Some(error) = self.stage_error {
            return Err(error);
        }
        self.staged.extend_from_slice(bytes);
        Ok(self.scpm)
    }
    fn read(&mut self, register: u32) -> u32 {
        self.reads += 1;
        match register {
            RESPONSE => self.response,
            ARGUMENT => self.argument,
            MP1_SW_INT => self.mp1_sw[0],
            MP1_SW_INT_CTRL => self.mp1_sw[1],
            _ => panic!("unexpected SMU read"),
        }
    }
    fn write(&mut self, register: u32, value: u32) {
        self.writes.push((register, value));
        match register {
            RESPONSE => self.response = value,
            ARGUMENT => self.argument = value,
            MP1_SW_INT => self.mp1_sw[0] = value,
            MP1_SW_INT_CTRL => self.mp1_sw[1] = value,
            MESSAGE => {
                assert_eq!(self.response, 0);
                if matches!(value, SET_DRIVER_HIGH | SET_DRIVER_LOW | TRANSFER_TABLE) {
                    assert_eq!(self.staged.len(), crate::amdgpu_power_navi22::SMC_BYTES);
                } else if value == TRANSFER_TO_DRIVER {
                    // table id in the low 16 bits, argument (0) above.
                    assert_eq!(self.argument, METRICS_TABLE);
                    assert_eq!(self.flushes, 1, "staging not flushed before transfer");
                    let metrics = self.metrics.clone();
                    self.buffer[..metrics.len()].copy_from_slice(&metrics);
                } else if !matches!(
                    value,
                    ALLOWED_HIGH
                        | ALLOWED_LOW
                        | ENABLE_FEATURES_LOW
                        | ENABLE_FEATURES_HIGH
                        | DISABLE_FEATURES_LOW
                        | DISABLE_FEATURES_HIGH
                ) {
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
                        TRANSFER_TO_DRIVER | REENABLE_ACDC_INTERRUPT => 0,
                        ENABLE_FEATURES_LOW
                        | ENABLE_FEATURES_HIGH
                        | DISABLE_FEATURES_LOW
                        | DISABLE_FEATURES_HIGH => {
                            let shift = if value & 1 == 0 { 0 } else { 32 };
                            let bits = u64::from(self.argument) << shift & !self.sticky;
                            if value < DISABLE_FEATURES_LOW {
                                self.running |= bits;
                            } else {
                                self.running &= !bits;
                            }
                            0
                        }
                        ALLOW_GFXOFF | DISALLOW_GFXOFF => 0,
                        GET_PPT_LIMIT => self.ppt_limit,
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
            // The host's RX 6750 XT: PMFW 0x413f00 reports interface 0x12
            // while the driver (smu11_driver_if_sienna_cichlid.h) is 0xe.
            interface: 0x12,
            firmware: 0x413f00,
            stall: None,
            reject: None,
            writes: Vec::new(),
            reads: 0,
            staged: Vec::new(),
            stage_error: None,
            scpm: 0,
            revoke_on: None,
            running: crate::amdgpu_power_navi22::BootPolicy::from_features(u64::MAX)
                .unwrap()
                .allowed(),
            gfx_limits: (500, 2600),
            buffer: vec![0x5a; 4096],
            metrics: Vec::new(),
            flushes: 0,
            invalidates: 0,
            ppt_limit: 186,
            thm: [0; 0x6d],
            smuio_vid: 0x0040_0000,
            mp1_sw: [0, 1],
            banks: true,
            fw_not_ready: 0,
            fw_reads: 0,
            sticky: 0,
        },
        authority: Cap::bootstrap(),
        state: State::Prepared,
        power_memory: None,
        power_policy: None,
        versions: None,
        limits: None,
        protection: None,
        scpm: false,
        gating_allowed: 0,
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
            interface: 0x12,
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

/// smu_v11_0_check_fw_status gates the first message on
/// MP1_FIRMWARE_FLAGS.INTERRUPTS_ENABLED; never message a PMFW still booting.
fn smu_navi22_waits_for_firmware_interrupts_before_first_message() -> TestResult {
    let mut e = engine();
    e.io.fw_not_ready = 3;
    if run(e.verify()).is_err() || e.io.fw_reads != 4 || e.io.writes.len() != 6 {
        return TestResult::Fail("first PPSMC message did not wait for INTERRUPTS_ENABLED");
    }
    let mut e = engine();
    e.io.fw_not_ready = usize::MAX;
    if run(e.verify()) != Err(Error::Timeout) || !e.io.writes.is_empty() || e.state != State::Failed
    {
        return TestResult::Fail("unready PMFW was messaged or wait unbounded");
    }
    if MESSAGE_TIMEOUT_MS < 2000 {
        return TestResult::Fail("SMU message deadline shorter than Linux's default_timeout");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/smu-navi22",
    smu_navi22_waits_for_firmware_interrupts_before_first_message
);

fn smu_navi22_tolerates_interface_mismatch_rejects_absent_device() -> TestResult {
    // smu_cmn_check_fw_version only logs the interface pair: any value but
    // all-ones (device gone) proceeds to GET_VERSION and succeeds.
    for interface in [0, 0xd, DRIVER_INTERFACE, 0xf, 0x12, 0x40, u32::MAX] {
        let mut e = engine();
        e.io.interface = interface;
        let result = run(e.verify());
        if interface == u32::MAX {
            if result != Err(Error::DeviceGone)
                || e.state != State::Failed
                || e.io.writes.len() != 3
            {
                return TestResult::Fail("absent device accepted or second query issued");
            }
        } else if result
            != Ok(Versions {
                firmware: 0x413f00,
                interface,
            })
            || e.state != State::Ready
            || e.io.writes.len() != 6
        {
            return TestResult::Fail("PMFW interface mismatch was fatal");
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
    smu_navi22_tolerates_interface_mismatch_rejects_absent_device
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
            engine.io.stage_error = Some(Error::Invalid);
            Error::Invalid
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

fn smu_navi22_scpm_runtime_policy_reads_like_psp_sw_init() -> TestResult {
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
    if read(&db) != Ok(0) {
        return TestResult::Fail("absent runtime DB is not SCPM disabled");
    }
    db[..8].copy_from_slice(&[0xd5, 0xe, 0, 1, 1, 0, 0, 0]);
    db[8..16].copy_from_slice(&[6, 0, 0, 0, 32, 0, 4, 0]);
    // A nonzero status is scpm_enabled, never an error.
    for policy in [0, 1, 2, u32::MAX] {
        put(&mut db, 32, policy);
        if read(&db) != Ok(policy) {
            return TestResult::Fail("SCPM status misread or treated as fatal");
        }
    }
    // psp_sw_init: a malformed DB/entry is "no SCPM entry", i.e. SCPM
    // disabled and the driver uploads the PPTable. The version is ignored.
    let mut other = db.clone();
    other[2] = 1;
    if read(&other) != Ok(u32::MAX) {
        return TestResult::Fail("runtime DB version must not be checked");
    }
    for (offset, value) in [(4, 64), (12, 8), (12, 33), (14, 3)] {
        let mut bad = db.clone();
        bad[offset] = value;
        if read(&bad) != Ok(0) {
            return TestResult::Fail("malformed runtime policy must read as absent");
        }
    }
    db[4] = 2;
    db[16..24].copy_from_slice(&[6, 0, 0, 0, 40, 0, 4, 0]);
    put(&mut db, 40, 0);
    if read(&db) != Ok(u32::MAX) {
        return TestResult::Fail("duplicate SCPM entries did not use the first");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/smu-navi22",
    smu_navi22_scpm_runtime_policy_reads_like_psp_sw_init
);

/// smu_smc_hw_setup with scpm_enabled: the driver table location is still
/// set, but the PPTable transfer and SetAllowedFeaturesMask{High,Low} are
/// skipped ("not needed and permitted"); the boot continues.
fn smu_navi22_scpm_skips_pptable_and_allowed_mask() -> TestResult {
    let mut engine = ready_engine();
    let pool = power_pool();
    engine.io.scpm = 1;
    if run(engine.upload(&vec![0; crate::amdgpu_power_navi22::SMC_BYTES], &pool)).is_err()
        || !engine.scpm
        || commands(&engine.io.writes)
            .iter()
            .map(|c| c.0)
            .collect::<Vec<_>>()
            != [SET_DRIVER_HIGH, SET_DRIVER_LOW]
    {
        return TestResult::Fail("SCPM upload sent the PPTable or failed");
    }
    engine.power_policy =
        Some(crate::amdgpu_power_navi22::BootPolicy::from_features(u64::MAX).unwrap());
    engine.io.writes.clear();
    if run(engine.configure_power()).is_err()
        || commands(&engine.io.writes)
            .iter()
            .any(|c| c.0 == ALLOWED_HIGH || c.0 == ALLOWED_LOW)
    {
        return TestResult::Fail("SCPM boot sent the allowed-feature mask");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/smu-navi22",
    smu_navi22_scpm_skips_pptable_and_allowed_mask
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

fn smu_navi22_display_policy_requires_retained_protected_power() -> TestResult {
    let (mut e, _pool) = uploaded_engine();
    if run(e.enable_display_power()) != Err(Error::Busy) {
        return TestResult::Fail("display DPM before boot power");
    }
    run(e.configure_power()).unwrap();
    let allowed = e.power_policy.unwrap().display_allowed().unwrap();
    e.io.running = allowed;
    e.io.writes.clear();
    run(e.enable_display_power()).unwrap();
    let commands: Vec<_> =
        e.io.writes
            .chunks_exact(3)
            .map(|w| (w[2].1, w[1].1))
            .collect();
    if commands
        != [
            (5, (allowed >> 32) as u32),
            (4, allowed as u32),
            (6, 0),
            (12, 0),
            (13, 0),
        ]
        || e.state != State::DisplayPowerReady
    {
        return TestResult::Fail("display power transition protocol");
    }
    let n = e.io.writes.len();
    if run(e.enable_display_power()).is_err() || e.io.writes.len() != n {
        return TestResult::Fail("display power replayed");
    }
    e.authority.revoke();
    if run(e.enable_display_power()) != Err(Error::Revoked) {
        return TestResult::Fail("revoked power token accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/smu-navi22",
    smu_navi22_display_policy_requires_retained_protected_power
);
fn smu_navi22_display_policy_failure_and_cancellation_are_terminal() -> TestResult {
    for fault in 0..5 {
        let (mut e, _pool) = uploaded_engine();
        run(e.configure_power()).unwrap();
        e.io.running = e.power_policy.unwrap().display_allowed().unwrap();
        match fault {
            0 => e.io.reject = Some((ENABLE_FEATURES, 0xfd)),
            1 => e.io.running &= !(1 << 8),
            2 => e.io.running |= 1 << 17,
            3 => e.io.revoke_on = Some((ALLOWED_LOW, e.authority)),
            _ => e.io.stall = Some(ENABLE_FEATURES),
        }
        if fault == 4 {
            let mut f = core::pin::pin!(e.enable_display_power());
            if f.as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_ready()
            {
                return TestResult::Fail("stalled display DPM did not pend");
            }
        } else if run(e.enable_display_power()).is_ok() {
            return TestResult::Fail("bad display DPM accepted");
        }
        let n = e.io.writes.len();
        if run(e.enable_display_power()) != Err(Error::Busy) || e.io.writes.len() != n {
            return TestResult::Fail("uncertain display power replayed");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/smu-navi22",
    smu_navi22_display_policy_failure_and_cancellation_are_terminal
);

/// PowerReady owner with the uploaded table's limits and a PMFW metrics table.
fn powered_engine(firmware: u32) -> (Engine<Fake>, crate::amdgpu_vram::Pool) {
    let mut engine = engine();
    engine.io.firmware = firmware;
    run(engine.verify()).unwrap();
    let pool = power_pool();
    run(engine.upload(&vec![0; crate::amdgpu_power_navi22::SMC_BYTES], &pool)).unwrap();
    engine.power_policy =
        Some(crate::amdgpu_power_navi22::BootPolicy::from_features(u64::MAX).unwrap());
    run(engine.configure_power()).unwrap();
    engine.limits = Some(Limits {
        edge_crit_milli: 100_000,
        edge_emergency_milli: 105_000,
        hotspot_crit_milli: 110_000,
        hotspot_emergency_milli: 115_000,
        mem_crit_milli: 100_000,
        mem_emergency_milli: 105_000,
        software_shutdown_c: 118,
        fan_max_rpm: Some(3300),
        ppt_table_w: 203,
        thermal_controller: 0x13,
        dc_by_gpio: false,
    });
    let mut metrics = vec![0u8; METRICS_BYTES];
    metrics[76..78].copy_from_slice(&63u16.to_le_bytes()); // TemperatureHotspot
    metrics[122..124].copy_from_slice(&1350u16.to_le_bytes()); // V2 CurrFanSpeed
    metrics[102..104].copy_from_slice(&900u16.to_le_bytes()); // V1 CurrFanSpeed
    engine.io.metrics = metrics;
    engine.io.thm[CG_FDO_CTRL1 as usize] = 0xff;
    engine.io.thm[CG_THERMAL_STATUS as usize] = 0x80 << 9;
    engine.io.writes.clear();
    engine.io.flushes = 0;
    (engine, pool)
}
fn commands(writes: &[(u32, u32)]) -> Vec<(u32, u32)> {
    // (message, argument) of each RESPONSE/ARGUMENT/MESSAGE publication.
    writes
        .iter()
        .filter(|(r, _)| *r < 0x1_0000)
        .collect::<Vec<_>>()
        .windows(3)
        .filter(|w| w[0].0 == RESPONSE && w[1].0 == ARGUMENT && w[2].0 == MESSAGE)
        .map(|w| (w[2].1, w[1].1))
        .collect()
}

fn smu_navi22_telemetry_transfers_metrics_through_retained_buffer() -> TestResult {
    let (mut engine, _pool) = powered_engine(0x413f00);
    let t = match run(engine.read_telemetry()) {
        Ok(t) => t,
        Err(_) => return TestResult::Fail("telemetry refresh failed"),
    };
    if commands(&engine.io.writes)
        != [
            (TRANSFER_TO_DRIVER, METRICS_TABLE),
            (RUNNING_LOW, 0),
            (RUNNING_HIGH, 0),
            (GET_PPT_LIMIT, 0),
        ]
    {
        return TestResult::Fail("smu_cmn_get_metrics_table / GetPptLimit order");
    }
    if engine.io.flushes != 1 || engine.io.invalidates != 1 {
        return TestResult::Fail("HDP flush before / invalidate after the transfer");
    }
    if t.layout != Layout::V2
        || t.metrics.hotspot_milli != 63_000
        || t.metrics.fan_rpm != 1350
        || t.ppt_limit_w != 186
        || t.vddgfx_mv != 1150
        || t.fan_pwm != Some(128)
        || engine.state != State::PowerReady
        || !engine.protected(t.enabled)
        || engine.protected(t.enabled & !(1 << 31))
    {
        return TestResult::Fail("decoded telemetry / protection / state");
    }
    // Old PMFW: V1 layout. PPT not running: the table's AC limit, no query.
    let (mut engine, _pool) = powered_engine(0x412c00);
    engine.io.running &= !(1 << 24);
    let t = run(engine.read_telemetry()).unwrap();
    if t.layout != Layout::V1
        || t.metrics.fan_rpm != 900
        || t.ppt_limit_w != 203
        || commands(&engine.io.writes).contains(&(GET_PPT_LIMIT, 0))
    {
        return TestResult::Fail("V1 PMFW / PPT fallback");
    }
    // A rejected PPT query falls back as in sienna_cichlid_get_power_limit.
    let (mut engine, _pool) = powered_engine(0x413f00);
    engine.io.reject = Some((GET_PPT_LIMIT, 0xfe));
    if run(engine.read_telemetry()).map(|t| t.ppt_limit_w) != Ok(203)
        || engine.state != State::PowerReady
    {
        return TestResult::Fail("rejected GetPptLimit");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/smu-navi22",
    smu_navi22_telemetry_transfers_metrics_through_retained_buffer
);

fn smu_navi22_telemetry_requires_power_and_fails_terminally() -> TestResult {
    let mut engine = ready_engine();
    if run(engine.read_telemetry()) != Err(Error::Invalid) {
        return TestResult::Fail("telemetry before the board table");
    }
    // Rejected transfer: idle mailbox, reusable owner.
    let (mut engine, _pool) = powered_engine(0x413f00);
    engine.io.reject = Some((TRANSFER_TO_DRIVER, 0xff));
    if run(engine.read_telemetry()) != Err(Error::Rejected(0xff))
        || engine.state != State::PowerReady
    {
        return TestResult::Fail("rejection made the owner unusable");
    }
    engine.io.reject = None;
    engine.io.flushes = 0;
    if run(engine.read_telemetry()).is_err() {
        return TestResult::Fail("owner not reusable after rejection");
    }
    // Timeout is terminal and cancellation retains Runtime (no replay).
    let (mut engine, _pool) = powered_engine(0x413f00);
    engine.io.stall = Some(TRANSFER_TO_DRIVER);
    if run(engine.read_telemetry()) != Err(Error::Timeout)
        || engine.state != State::Failed
        || run(engine.read_telemetry()) != Err(Error::Busy)
    {
        return TestResult::Fail("timeout not terminal");
    }
    let (mut engine, _pool) = powered_engine(0x413f00);
    engine.io.stall = Some(TRANSFER_TO_DRIVER);
    {
        let mut future = core::pin::pin!(engine.read_telemetry());
        let mut cx = Context::from_waker(Waker::noop());
        if future.as_mut().poll(&mut cx).is_ready() {
            return TestResult::Fail("stalled transfer completed");
        }
    }
    if engine.state != State::Runtime || run(engine.read_telemetry()) != Err(Error::Busy) {
        return TestResult::Fail("cancelled refresh replayable");
    }
    // A removed device (all-ones sensors) is terminal.
    let (mut engine, _pool) = powered_engine(0x413f00);
    engine.io.smuio_vid = u32::MAX;
    if run(engine.read_telemetry()) != Err(Error::DeviceGone) || engine.state != State::Failed {
        return TestResult::Fail("device loss accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/smu-navi22",
    smu_navi22_telemetry_requires_power_and_fails_terminally
);

fn smu_navi22_thermal_alert_programs_smu_v11_0_set_irq_state() -> TestResult {
    let (mut engine, _pool) = powered_engine(0x413f00);
    // Masked/disabled reset values plus unrelated TEMP_THRESHOLD/PROCHOT bits.
    engine.io.thm[THM_INT_CTRL as usize] = 0x0f12_3456 | (3 << 24) | (1 << 26);
    engine.io.mp1_sw = [0x1ab, 0x1];
    let alert = run(engine.enable_thermal_alert()).unwrap();
    if alert
        != (Alert {
            armed: true,
            window: (0, 118),
            acdc_rearmed: false,
        })
    {
        return TestResult::Fail("alert result");
    }
    // MAX_IH_CREDIT=5, IH_HW_ENA, INTH/INTL unmasked, TRIGGER unmasked,
    // DIG_THERM_INTH=118, INTL=0; TEMP_THRESHOLD and PROCHOT preserved.
    let ctrl = (5 << 29) | (1 << 28) | (1 << 27) | (0x12 << 16) | 118;
    if engine.io.writes
        != [
            (0x1_0000 | THM_INT_CTRL, ctrl),
            (0x1_0000 | THM_INT_ENA, 0x38),
            (MP1_SW_INT, 0xfe),
            (MP1_SW_INT_CTRL, 0),
        ]
    {
        return TestResult::Fail("THM window / MP1 SW interrupt programming");
    }
    if engine.state != State::PowerReady {
        return TestResult::Fail("alert left the owner busy");
    }
    // No thermal controller: Linux skips amdgpu_irq_get entirely.
    let (mut engine, _pool) = powered_engine(0x413f00);
    engine.limits.as_mut().unwrap().thermal_controller = 0;
    if run(engine.enable_thermal_alert()).map(|a| a.armed) != Ok(false)
        || !engine.io.writes.is_empty()
    {
        return TestResult::Fail("alert programmed without a thermal controller");
    }
    // GPIO-signalled DC with ACDC running re-arms AC/DC delivery.
    let (mut engine, _pool) = powered_engine(0x413f00);
    engine.limits.as_mut().unwrap().dc_by_gpio = true;
    engine.io.running |= crate::amdgpu_smu_navi22_telemetry::FEATURE_ACDC;
    let alert = run(engine.enable_thermal_alert()).unwrap();
    if !alert.acdc_rearmed
        || commands(&engine.io.writes)
            != [
                (RUNNING_LOW, 0),
                (RUNNING_HIGH, 0),
                (REENABLE_ACDC_INTERRUPT, 0),
            ]
    {
        return TestResult::Fail("process_pending_interrupt");
    }
    // Missing THM bank and absent device fail closed; before power, Busy.
    let (mut engine, _pool) = powered_engine(0x413f00);
    engine.io.banks = false;
    if run(engine.enable_thermal_alert()) != Err(Error::Unsupported) {
        return TestResult::Fail("missing THM bank");
    }
    let (mut engine, _pool) = powered_engine(0x413f00);
    engine.io.thm[THM_INT_CTRL as usize] = u32::MAX;
    if run(engine.enable_thermal_alert()) != Err(Error::DeviceGone) || engine.state != State::Failed
    {
        return TestResult::Fail("absent device armed");
    }
    let limits = powered_engine(0x413f00).0.limits;
    let mut engine = ready_engine();
    engine.limits = limits;
    if run(engine.enable_thermal_alert()) != Err(Error::Busy) {
        return TestResult::Fail("alert before boot power setup");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/smu-navi22",
    smu_navi22_thermal_alert_programs_smu_v11_0_set_irq_state
);

/// Opt-in gating bits: `smu_cmn_feature_update_enable_state` (Low then
/// High) after the allowed mask, running set read back; GFXOFF messages only
/// after FEATURE_GFXOFF; nothing outside GATING_FEATURES.
fn smu_navi22_gating_features_follow_smu_cmn() -> TestResult {
    use crate::amdgpu_navi22_power_policy::{SMU_DEEP_SLEEP, SMU_GFXOFF, SMU_HUB_PG};
    let (mut e, _pool) = powered_engine(0x413f00);
    // GFXOFF control is refused before the feature was enabled.
    if run(e.gfx_off_control(true)) != Err(Error::Invalid) || !e.io.writes.is_empty() {
        return TestResult::Fail("GFXOFF message before FEATURE_GFXOFF");
    }
    for bad in [0, 1 << 24, 1 << 33, SMU_GFXOFF | 1 << 1] {
        if run(e.update_features(bad, true)) != Err(Error::Invalid) || !e.io.writes.is_empty() {
            return TestResult::Fail("non-gating feature bits accepted");
        }
    }
    let base = e.power_policy.unwrap().allowed();
    let mask = SMU_GFXOFF | SMU_HUB_PG;
    let running = match run(e.update_features(mask, true)) {
        Ok(running) => running,
        Err(_) => return TestResult::Fail("enable failed"),
    };
    let allowed = base | mask;
    if commands(&e.io.writes)
        != [
            (ALLOWED_HIGH, (allowed >> 32) as u32),
            (ALLOWED_LOW, allowed as u32),
            (ENABLE_FEATURES_LOW, mask as u32),
            (ENABLE_FEATURES_HIGH, (mask >> 32) as u32),
            (RUNNING_LOW, 0),
            (RUNNING_HIGH, 0),
        ]
        || running & mask != mask
        || e.state != State::PowerReady
        || e.gating_allowed != mask
    {
        return TestResult::Fail("enable protocol");
    }
    e.io.writes.clear();
    run(e.gfx_off_control(false)).unwrap();
    run(e.gfx_off_control(true)).unwrap();
    if commands(&e.io.writes) != [(DISALLOW_GFXOFF, 0), (ALLOW_GFXOFF, 0)] {
        return TestResult::Fail("smu_v11_0_gfx_off_control messages");
    }
    e.io.writes.clear();
    run(e.update_features(SMU_HUB_PG, false)).unwrap();
    if commands(&e.io.writes)
        != [
            (DISABLE_FEATURES_LOW, 0),
            (DISABLE_FEATURES_HIGH, (SMU_HUB_PG >> 32) as u32),
            (RUNNING_LOW, 0),
            (RUNNING_HIGH, 0),
        ]
        || e.io.running & SMU_HUB_PG != 0
        || e.io.running & SMU_GFXOFF == 0
    {
        return TestResult::Fail("disable protocol");
    }
    // EnableSmuFeaturesLow accepted, High rejected: the Low half may now
    // run, so it is recorded for the opt-in's removal; the High half is not.
    let (mut half, _pool2) = powered_engine(0x413f00);
    half.io.reject = Some((ENABLE_FEATURES_HIGH, 0xfe));
    if run(half.update_features(SMU_GFXOFF | SMU_HUB_PG, true)) != Err(Error::Rejected(0xfe))
        || half.gating_allowed != SMU_GFXOFF & 0xffff_ffff
        || SMU_HUB_PG & 0xffff_ffff != 0
    {
        return TestResult::Fail("Low bits enabled before a High failure were not recorded");
    }
    // A clean PMFW rejection leaves the owner usable.
    e.io.reject = Some((ENABLE_FEATURES_LOW, 0xfe));
    if run(e.update_features(SMU_DEEP_SLEEP, true)) != Err(Error::Rejected(0xfe))
        || e.state != State::PowerReady
    {
        return TestResult::Fail("rejection");
    }
    e.io.reject = None;
    // A feature that does not come up is reported and terminal.
    // (The fake applied the rejected enable; PMFW would not have.)
    e.io.running &= !SMU_DEEP_SLEEP;
    e.io.sticky = SMU_DEEP_SLEEP;
    if !matches!(
        run(e.update_features(SMU_DEEP_SLEEP, true)),
        Err(Error::Features { .. })
    ) || e.state != State::Failed
    {
        return TestResult::Fail("feature mismatch was not terminal");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/smu-navi22",
    smu_navi22_gating_features_follow_smu_cmn
);
