//! amd_pmf smokes: APMF buffer checks, the static-slider tables (v1 and
//! v2/APTS), the SMU message sequences per profile and power source,
//! the boot parameter, and one real AML round trip.

use super::*;
use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::RefCell;
use narf_kernel_test::{kernel_test_in, TestResult};

use crate::amd_smu::{SmuMailbox, RESULT_OK};

/// What reached firmware or the SMU, in order.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Ev {
    Apmf(u32, Option<Vec<u8>>),
    Apts(u32),
    Smu(u32, u32),
}

type Log = Rc<RefCell<Vec<Ev>>>;

// ── Buffers ──────────────────────────────────────────────────────────

fn verify_buf(version: u16, notifications: u32, supported: u32) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&12u16.to_le_bytes());
    b.extend_from_slice(&version.to_le_bytes());
    b.extend_from_slice(&notifications.to_le_bytes());
    b.extend_from_slice(&supported.to_le_bytes());
    b
}

fn sysparams_buf(heartbeat: u32) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&15u16.to_le_bytes());
    b.extend_from_slice(&0xffu32.to_le_bytes()); // valid_mask
    b.extend_from_slice(&0u32.to_le_bytes()); // flags
    b.push(0); // command_code
    b.extend_from_slice(&heartbeat.to_le_bytes());
    b
}

/// A v1 entry whose fields encode (src, mode) so a sequence names its row.
fn prop(src: u32, mode: u32) -> SpsProp {
    let base = 1000 * (src + 1) + 100 * (mode + 1);
    SpsProp {
        fppt: base + 1,
        sppt: base + 2,
        sppt_apu_only: base + 3,
        spl: base + 4,
        stt_min: base + 5,
        stt_skin_temp_apu: (40 + src * 10 + mode) as u8,
        stt_skin_temp_hs2: (60 + src * 10 + mode) as u8,
        fan_id: 7,
    }
}

fn sps_v1_buf() -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&(SPS_V1_SIZE as u16).to_le_bytes());
    for src in 0..2 {
        for mode in 0..3 {
            let p = prop(src, mode);
            for w in [p.fppt, p.sppt, p.sppt_apu_only, p.spl, p.stt_min] {
                b.extend_from_slice(&w.to_le_bytes());
            }
            b.push(p.stt_skin_temp_apu);
            b.push(p.stt_skin_temp_hs2);
            b.extend_from_slice(&p.fan_id.to_le_bytes());
        }
    }
    b
}

fn sps_v2_buf(states: [[u8; 4]; 2]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&(SPS_V2_SIZE as u16).to_le_bytes());
    for row in states {
        b.extend_from_slice(&row);
    }
    b
}

fn apts_buf(i: u32) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&(AptsProp::SIZE as u16).to_le_bytes());
    b.extend_from_slice(&2u16.to_le_bytes()); // table_version
    for w in [i, 5000 + i, 6000 + i, 7000 + i] {
        // fan_table_idx, pmf_ppt, ppt_pmf_apu_only, stt_min_limit
        b.extend_from_slice(&w.to_le_bytes());
    }
    b.push(30 + i as u8);
    b.push(50 + i as u8);
    b
}

// ── Fakes ────────────────────────────────────────────────────────────

struct FakeFw {
    log: Log,
    verify: Value,
    sysparams: Vec<u8>,
    sps: Vec<u8>,
    ac: bool,
}

impl FakeFw {
    fn new(log: &Log, version: u16, supported: u32) -> Self {
        Self {
            log: log.clone(),
            verify: Value::Buffer(verify_buf(version, 0x6, supported)),
            sysparams: sysparams_buf(0),
            sps: if version == PMF_IF_V2 {
                sps_v2_buf([[3, 2, 1, 0], [7, 6, 5, 4]])
            } else {
                sps_v1_buf()
            },
            ac: true,
        }
    }
}

impl Firmware for FakeFw {
    fn apmf(&mut self, func: u32, param: Option<&[u8]>) -> Result<Value, FwError> {
        self.log
            .borrow_mut()
            .push(Ev::Apmf(func, param.map(|p| p.to_vec())));
        match func {
            APMF_FUNC_VERIFY_INTERFACE => Ok(self.verify.clone()),
            APMF_FUNC_GET_SYS_PARAMS => Ok(Value::Buffer(self.sysparams.clone())),
            APMF_FUNC_STATIC_SLIDER_GRANULAR => Ok(Value::Buffer(self.sps.clone())),
            _ => Ok(Value::Integer(0)),
        }
    }

    fn apts(&mut self, index: u32) -> Result<Value, FwError> {
        self.log.borrow_mut().push(Ev::Apts(index));
        Ok(Value::Buffer(apts_buf(index)))
    }

    fn on_ac(&mut self) -> bool {
        self.ac
    }
}

/// A PMF mailbox: a message write replaces the response with `answer`.
struct FakeSmu {
    log: Log,
    regs: [u32; 0x400],
    pending_arg: u32,
    answer: u32,
    now: u64,
}

impl FakeSmu {
    fn new(log: &Log, answer: u32) -> Self {
        let mut regs = [0; 0x400];
        regs[PMF_REGS.response as usize / 4] = RESULT_OK;
        Self {
            log: log.clone(),
            regs,
            pending_arg: 0,
            answer,
            now: 0,
        }
    }
}

impl SmuMailbox for FakeSmu {
    fn read32(&mut self, offset: u32) -> u32 {
        self.regs[offset as usize / 4]
    }
    fn write32(&mut self, offset: u32, value: u32) {
        self.regs[offset as usize / 4] = value;
        if offset == PMF_REGS.argument {
            self.pending_arg = value;
        }
        if offset == PMF_REGS.message {
            self.log.borrow_mut().push(Ev::Smu(value, self.pending_arg));
            self.regs[PMF_REGS.response as usize / 4] = self.answer;
        }
    }
    fn now_ns(&mut self) -> u64 {
        self.now += 1_000;
        self.now
    }
}

const SPS: u32 = 1 << (APMF_FUNC_STATIC_SLIDER_GRANULAR - 1);
const SLIDER: u32 = 1 << (APMF_FUNC_OS_POWER_SLIDER_UPDATE - 1);
const SYSPARAMS: u32 = 1 << (APMF_FUNC_GET_SYS_PARAMS - 1);

fn v1_messages(src: u32, mode: u32) -> Vec<Ev> {
    let p = prop(src, mode);
    alloc::vec![
        Ev::Smu(SET_SPL, p.spl),
        Ev::Smu(SET_FPPT, p.fppt),
        Ev::Smu(SET_SPPT, p.sppt),
        Ev::Smu(SET_SPPT_APU_ONLY, p.sppt_apu_only),
        Ev::Smu(SET_STT_MIN_LIMIT, p.stt_min),
        Ev::Smu(SET_STT_LIMIT_APU, u32::from(p.stt_skin_temp_apu) << 8),
        Ev::Smu(SET_STT_LIMIT_HS2, u32::from(p.stt_skin_temp_hs2) << 8),
    ]
}

fn take(log: &Log) -> Vec<Ev> {
    core::mem::take(&mut *log.borrow_mut())
}

// ── Tests ────────────────────────────────────────────────────────────

fn smoke_pmf_store_buffer_checks() -> TestResult {
    let ok = Value::Buffer(alloc::vec![4, 0, 0xaa, 0xbb, 0xcc]);
    let cases: [(Value, usize, Result<Vec<u8>, FwError>); 4] = [
        (Value::Integer(3), 2, Err(FwError::BadBuffer)),
        (Value::Buffer(alloc::vec![1]), 1, Err(FwError::BadBuffer)),
        // Header claims more than the buffer holds.
        (
            Value::Buffer(alloc::vec![9, 0, 1, 2]),
            2,
            Err(FwError::BadBuffer),
        ),
        // Header shorter than the structure read from it.
        (ok.clone(), 5, Err(FwError::BadBuffer)),
    ];
    for (value, out_sz, want) in cases {
        if store_buffer(&value, out_sz).map(|b| b.to_vec()) != want {
            return TestResult::Fail("store_buffer must apply apmf_if_call_store_buffer's checks");
        }
    }
    if store_buffer(&ok, 3) != Ok(&[4u8, 0, 0xaa][..]) {
        return TestResult::Fail("store_buffer must return the leading out_sz bytes");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/platform/amd_pmf", smoke_pmf_store_buffer_checks);

fn smoke_pmf_function_bits_and_modes() -> TestResult {
    let log: Log = Rc::new(RefCell::new(Vec::new()));
    let Some(st) = probe_state(&mut FakeFw::new(&log, PMF_IF_V1, SLIDER)) else {
        return TestResult::Fail("probe_state failed on a valid verify buffer");
    };
    if !st.supported(APMF_FUNC_OS_POWER_SLIDER_UPDATE)
        || st.supported(APMF_FUNC_STATIC_SLIDER_GRANULAR)
        || st.supported(APMF_FUNC_VERIFY_INTERFACE)
    {
        return TestResult::Fail("bit n-1 must mean APMF function n (is_apmf_func_supported)");
    }
    let modes = [
        (PlatformProfile::Performance, Some(PowerMode::Performance)),
        (
            PlatformProfile::BalancedPerformance,
            Some(PowerMode::Performance),
        ),
        (PlatformProfile::Balanced, Some(PowerMode::BalancedPower)),
        (PlatformProfile::LowPower, Some(PowerMode::PowerSaver)),
        (PlatformProfile::Quiet, Some(PowerMode::PowerSaver)),
        (PlatformProfile::Cool, None),
    ];
    if modes.iter().any(|&(p, m)| mode_for(p) != m) {
        return TestResult::Fail("profile → mode differs from amd_pmf_get_pprof_modes");
    }
    let flags = [
        (PowerSource::Dc, PowerMode::Performance, 0x01),
        (PowerSource::Dc, PowerMode::BalancedPower, 0x02),
        (PowerSource::Dc, PowerMode::PowerSaver, 0x08),
        (PowerSource::Ac, PowerMode::Performance, 0x10),
        (PowerSource::Ac, PowerMode::BalancedPower, 0x20),
        (PowerSource::Ac, PowerMode::PowerSaver, 0x40),
    ];
    if flags.iter().any(|&(s, m, f)| slider_flag(s, m) != f) {
        return TestResult::Fail("slider flags differ from DC_BEST_PERF..AC_BETTER_BATTERY");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/platform/amd_pmf",
    smoke_pmf_function_bits_and_modes
);

fn smoke_pmf_v1_limits_follow_profile_and_source() -> TestResult {
    let log: Log = Rc::new(RefCell::new(Vec::new()));
    let mut fw = FakeFw::new(&log, PMF_IF_V1, SPS | SLIDER | SYSPARAMS);
    fw.sysparams = sysparams_buf(30);
    let mut smu = FakeSmu::new(&log, RESULT_OK);
    let Some(mut st) = probe_state(&mut fw) else {
        return TestResult::Fail("probe_state failed");
    };
    if st.hb_interval != 30 || st.profile != PlatformProfile::Balanced {
        return TestResult::Fail("probe must read the heartbeat and start balanced");
    }
    let probe_calls = take(&log);
    if probe_calls
        != [
            Ev::Apmf(APMF_FUNC_VERIFY_INTERFACE, None),
            Ev::Apmf(APMF_FUNC_GET_SYS_PARAMS, None),
            Ev::Apmf(APMF_FUNC_STATIC_SLIDER_GRANULAR, None),
        ]
    {
        return TestResult::Fail("probe must verify, read system params, then load the v1 table");
    }

    // amd_pmf_profile_set: tell the BIOS first, then push AC/performance.
    if set_profile(&mut st, PlatformProfile::Performance, &mut fw, &mut smu).is_err() {
        return TestResult::Fail("set_profile failed");
    }
    let mut want = alloc::vec![Ev::Apmf(
        APMF_FUNC_OS_POWER_SLIDER_UPDATE,
        Some(alloc::vec![3, 0, 0x10])
    )];
    want.extend(v1_messages(0, 0));
    if take(&log) != want {
        return TestResult::Fail("performance on AC must send slider 0x10 then prop[AC][PERF]");
    }

    // Unplug: limits first, then the BIOS (amd_pmf_pwr_src_notify_call).
    fw.ac = false;
    power_source_changed(&st, &mut fw, &mut smu);
    let mut want = v1_messages(1, 0);
    want.push(Ev::Apmf(
        APMF_FUNC_OS_POWER_SLIDER_UPDATE,
        Some(alloc::vec![3, 0, 0x01]),
    ));
    if take(&log) != want {
        return TestResult::Fail("an unplug must push prop[DC][PERF], then slider 0x01");
    }

    let _ = set_profile(&mut st, PlatformProfile::LowPower, &mut fw, &mut smu);
    let events = take(&log);
    if events.get(1..) != Some(&v1_messages(1, 2)[..]) {
        return TestResult::Fail("low-power on DC must push prop[DC][POWER_SAVER]");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/platform/amd_pmf",
    smoke_pmf_v1_limits_follow_profile_and_source
);

fn smoke_pmf_v2_limits_come_from_apts() -> TestResult {
    let log: Log = Rc::new(RefCell::new(Vec::new()));
    let mut fw = FakeFw::new(&log, PMF_IF_V2, SPS);
    let mut smu = FakeSmu::new(&log, RESULT_OK);
    let Some(mut st) = probe_state(&mut fw) else {
        return TestResult::Fail("probe_state failed");
    };
    let apts: Vec<Ev> = take(&log)
        .into_iter()
        .filter(|e| matches!(e, Ev::Apts(_)))
        .collect();
    if apts != (0..16).map(Ev::Apts).collect::<Vec<_>>() {
        return TestResult::Fail("a v2 probe must read all 16 APTS states");
    }
    fw.ac = false;
    let _ = set_profile(&mut st, PlatformProfile::LowPower, &mut fw, &mut smu);
    // power_states[DC][BEST_POWER_EFFICIENCY] = 5 → APTS entry 5.
    let want = alloc::vec![
        Ev::Smu(SET_PMF_PPT, 5005),
        Ev::Smu(SET_PMF_PPT_APU_ONLY, 6005),
        Ev::Smu(SET_STT_MIN_LIMIT, 7005),
        Ev::Smu(SET_STT_LIMIT_APU, 35 << 8),
        Ev::Smu(SET_STT_LIMIT_HS2, 55 << 8),
    ];
    if take(&log) != want {
        return TestResult::Fail("v2 low-power on DC must push APTS[power_states[DC][2]]");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/platform/amd_pmf",
    smoke_pmf_v2_limits_come_from_apts
);

fn smoke_pmf_missing_or_bad_tables_push_nothing() -> TestResult {
    let log: Log = Rc::new(RefCell::new(Vec::new()));
    // Slider updates only: the BIOS hears the profile, the SMU nothing.
    let mut fw = FakeFw::new(&log, PMF_IF_V1, SLIDER);
    let mut smu = FakeSmu::new(&log, RESULT_OK);
    let mut st = probe_state(&mut fw).expect("probe");
    let _ = take(&log);
    let _ = set_profile(&mut st, PlatformProfile::Performance, &mut fw, &mut smu);
    if take(&log).iter().any(|e| matches!(e, Ev::Smu(..))) || st.sps.is_some() {
        return TestResult::Fail("without STATIC_SLIDER_GRANULAR no limits may be pushed");
    }
    // A short table is unreadable: never push zeroed limits.
    let mut fw = FakeFw::new(&log, PMF_IF_V1, SPS);
    fw.sps.truncate(40);
    let mut st = probe_state(&mut fw).expect("probe");
    let _ = take(&log);
    let _ = set_profile(&mut st, PlatformProfile::Performance, &mut fw, &mut smu);
    if st.sps.is_some() || take(&log).iter().any(|e| matches!(e, Ev::Smu(..))) {
        return TestResult::Fail("an unreadable table must leave the limits to firmware");
    }
    // verify_interface failing: no functions at all.
    let mut fw = FakeFw::new(&log, PMF_IF_V1, SPS);
    fw.verify = Value::Integer(0);
    if probe_state(&mut fw).is_some() {
        return TestResult::Fail("a non-buffer verify result must leave PMF without functions");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/platform/amd_pmf",
    smoke_pmf_missing_or_bad_tables_push_nothing
);

fn smoke_pmf_smu_rejections_do_not_stop_the_table() -> TestResult {
    let log: Log = Rc::new(RefCell::new(Vec::new()));
    let mut fw = FakeFw::new(&log, PMF_IF_V1, SPS);
    // AMD_PMF_RESULT_CMD_REJECT_PREREQ on every message.
    let mut smu = FakeSmu::new(&log, 0xFD);
    let st = probe_state(&mut fw).expect("probe");
    let _ = take(&log);
    apply_limits(&st, PowerSource::Ac, &mut smu);
    if take(&log) != v1_messages(0, 1) {
        return TestResult::Fail("Linux sends every limit even when the SMU rejects one");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/platform/amd_pmf",
    smoke_pmf_smu_rejections_do_not_stop_the_table
);

fn smoke_pmf_heartbeat_v2_and_force_load() -> TestResult {
    let log: Log = Rc::new(RefCell::new(Vec::new()));
    let mut fw = FakeFw::new(&log, PMF_IF_V2, 0);
    let _ = heartbeat_v2_load(&mut fw);
    if take(&log)
        != [Ev::Apmf(
            APMF_FUNC_SBIOS_HEARTBEAT_V2,
            Some(alloc::vec![6, 0, 1, 0, 0, 0]),
        )]
    {
        return TestResult::Fail("ON_LOAD must send sbios_hb_event_v2 { size 6, load 1 }");
    }
    let bools = [
        ("1", Some(true)),
        ("Y", Some(true)),
        ("true", Some(true)),
        ("on", Some(true)),
        ("0", Some(false)),
        ("no", Some(false)),
        ("off", Some(false)),
        ("", None),
        ("2", None),
        ("o", None),
    ];
    if bools.iter().any(|&(v, b)| kstrtobool(v) != b) {
        return TestResult::Fail("kstrtobool differs from lib/kstrtox.c");
    }
    let cmdlines = [
        ("quiet", false),
        ("amd_pmf.force_load", true),
        ("amd_pmf.force_load=1", true),
        ("amd-pmf.force-load=y", true),
        ("amd_pmf.force_load=1 amd_pmf.force_load=0", false),
        ("amd_pmf.force_load=1 amd_pmf.force_load=bogus", true),
        ("amd_pmf.force_loader=1", false),
    ];
    if cmdlines
        .iter()
        .any(|&(c, v)| force_load_param(c.split_whitespace()) != v)
    {
        return TestResult::Fail("force_load parsing differs from param_set_bool + parameq");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/platform/amd_pmf",
    smoke_pmf_heartbeat_v2_and_force_load
);

// ── AML round trip ───────────────────────────────────────────────────

fn aml_pkglen(rest: usize) -> Vec<u8> {
    if rest + 1 < 64 {
        alloc::vec![(rest + 1) as u8]
    } else {
        let v = rest + 2;
        alloc::vec![0x40 | (v as u8 & 0x0F), (v >> 4) as u8]
    }
}

/// `Device(\PMFX) { Name(FNUM, 0xFF) Name(RBUF, Buffer{verify})
/// Method(APMF, 2) { Store(Arg0, FNUM) Return(RBUF) } }`.
fn pmfx_device(verify: &[u8]) -> Vec<u8> {
    let mut inside = Vec::new();
    inside.extend_from_slice(&[0x08, b'F', b'N', b'U', b'M', 0x0A, 0xFF]);
    // Name(RBUF, Buffer(0x0A n) {...})
    let mut buf = alloc::vec![0x0A, verify.len() as u8];
    buf.extend_from_slice(verify);
    inside.extend_from_slice(&[0x08, b'R', b'B', b'U', b'F', 0x11]);
    inside.extend_from_slice(&aml_pkglen(buf.len()));
    inside.extend_from_slice(&buf);
    // Method(APMF, 2) { Store(Arg0, FNUM) Return(RBUF) }
    let body = [
        0x70, 0x68, b'F', b'N', b'U', b'M', // Store(Arg0, FNUM)
        0xA4, b'R', b'B', b'U', b'F', // Return(RBUF)
    ];
    let mut method = alloc::vec![0x14];
    method.extend_from_slice(&aml_pkglen(4 + 1 + body.len()));
    method.extend_from_slice(b"APMF");
    method.push(0x02);
    method.extend_from_slice(&body);
    inside.extend_from_slice(&method);
    // Device(\PMFX) { … }
    let mut dev = alloc::vec![0x5B, 0x82];
    dev.extend_from_slice(&aml_pkglen(1 + 4 + inside.len()));
    dev.push(b'\\');
    dev.extend_from_slice(b"PMFX");
    dev.extend_from_slice(&inside);
    dev
}

fn fnum() -> Option<u64> {
    match narf_aml::find_node("\\PMFX.FNUM").and_then(|n| n.value) {
        Some(narf_aml::NameValue::Integer(v)) => Some(v),
        _ => None,
    }
}

fn smoke_pmf_aml_firmware_evaluates_apmf() -> TestResult {
    // SAFETY: serialized test; the scope restores the boot namespace.
    let _ns = unsafe { narf_aml::__test_namespace_scope() };
    let blob = pmfx_device(&verify_buf(PMF_IF_V1, 0x6, SLIDER));
    if narf_aml::__parse_body_for_test(&blob, "\\").is_err() {
        return TestResult::Fail("fixture APMF device did not parse");
    }
    let mut fw = AmlFirmware {
        device: alloc::string::String::from("\\PMFX"),
    };
    let Some(st) = probe_state(&mut fw) else {
        return TestResult::Fail("APMF(0) through AML did not return the verify buffer");
    };
    if st.version != PMF_IF_V1 || st.supported != SLIDER || st.notifications != 0x6 {
        return TestResult::Fail("verify-interface fields decoded wrongly");
    }
    if fnum() != Some(u64::from(APMF_FUNC_VERIFY_INTERFACE)) {
        return TestResult::Fail("Arg0 must carry the APMF function index");
    }
    if fw
        .apmf(APMF_FUNC_OS_POWER_SLIDER_UPDATE, Some(&[3, 0, 0x20]))
        .is_err()
        || fnum() != Some(u64::from(APMF_FUNC_OS_POWER_SLIDER_UPDATE))
    {
        return TestResult::Fail("a buffer-argument APMF call must evaluate");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/platform/amd_pmf",
    smoke_pmf_aml_firmware_evaluates_apmf
);
