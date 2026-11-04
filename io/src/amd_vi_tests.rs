//! AMD-Vi backend smokes (`io/iommu/amdvi`).
//!
//! Synthetic IVRS tables, Linux bit-for-bit DTE / command encodings, and
//! the bring-up / attach / detach / event-log paths driven against
//! [`RegModel`], a software register block that consumes the real command
//! ring and performs `COMPLETION_WAIT` stores. The model proves ordering
//! and encodings only — not any AMD-Vi silicon behaviour.

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

use crate::amd_vi::ivrs::{self, IvrsInfo};
use crate::amd_vi::*;
use crate::iommu::{self, Bdf, IommuHw};

// ── Synthetic IVRS ────────────────────────────────────────────────

fn ivrs_header(body_len: usize) -> Vec<u8> {
    let mut t = Vec::new();
    t.extend_from_slice(b"IVRS");
    t.extend_from_slice(&((48 + body_len) as u32).to_le_bytes());
    t.resize(36, 0);
    t.extend_from_slice(&0x0020_3043u32.to_le_bytes()); // IVinfo
    t.resize(48, 0);
    t
}

fn ivhd(ty: u8, flags: u8, mmio: u64, entries: &[u8]) -> Vec<u8> {
    let hdr = ivrs::ivhd_header_size(ty);
    let mut b = Vec::new();
    b.push(ty);
    b.push(flags);
    b.extend_from_slice(&((hdr + entries.len()) as u16).to_le_bytes());
    b.extend_from_slice(&0x0002u16.to_le_bytes()); // IOMMU devid 00:00.2
    b.extend_from_slice(&0x0040u16.to_le_bytes()); // cap ptr
    b.extend_from_slice(&mmio.to_le_bytes());
    b.extend_from_slice(&0u16.to_le_bytes()); // segment 0
    b.extend_from_slice(&0u16.to_le_bytes()); // info
    b.extend_from_slice(&0u32.to_le_bytes()); // efr attr
    if hdr == 40 {
        b.extend_from_slice(&FEATURE_IA.to_le_bytes());
        b.extend_from_slice(&0u64.to_le_bytes());
    }
    b.extend_from_slice(entries);
    b
}

fn e4(ty: u8, devid: u16, flags: u8) -> [u8; 4] {
    let d = devid.to_le_bytes();
    [ty, d[0], d[1], flags]
}

fn e8(ty: u8, devid: u16, flags: u8, ext: u32) -> [u8; 8] {
    let d = devid.to_le_bytes();
    let x = ext.to_le_bytes();
    [ty, d[0], d[1], flags, x[0], x[1], x[2], x[3]]
}

fn ivmd(ty: u8, flags: u8, devid: u16, aux: u16, start: u64, len: u64) -> Vec<u8> {
    let mut b = alloc::vec![ty, flags];
    b.extend_from_slice(&32u16.to_le_bytes());
    b.extend_from_slice(&devid.to_le_bytes());
    b.extend_from_slice(&aux.to_le_bytes());
    b.extend_from_slice(&0u16.to_le_bytes());
    b.extend_from_slice(&[0; 6]);
    b.extend_from_slice(&start.to_le_bytes());
    b.extend_from_slice(&len.to_le_bytes());
    b
}

const MMIO: u64 = 0xfd20_0000;
/// mt7921-style endpoint 01:00.0.
const WIFI: u16 = 0x0100;
/// Device behind a bridge aliased to 02:00.0.
const ALIASED: u16 = 0x0308;
const ALIAS_TARGET: u16 = 0x0200;

fn synthetic_ivrs() -> Vec<u8> {
    let mut entries = Vec::new();
    entries.extend_from_slice(&e4(ivrs::IVHD_DEV_SELECT, 0x0000, 0));
    entries.extend_from_slice(&e4(ivrs::IVHD_DEV_SELECT_RANGE_START, 0x0008, 0));
    entries.extend_from_slice(&e4(ivrs::IVHD_DEV_RANGE_END, 0x00ff, 0));
    entries.extend_from_slice(&e4(ivrs::IVHD_DEV_SELECT, WIFI, ivrs::ACPI_DEVFLAG_LINT0));
    entries.extend_from_slice(&e8(
        ivrs::IVHD_DEV_ALIAS_RANGE,
        0x0300,
        0,
        (ALIAS_TARGET as u32) << 8,
    ));
    entries.extend_from_slice(&e4(ivrs::IVHD_DEV_RANGE_END, 0x031f, 0));
    entries.extend_from_slice(&e8(ivrs::IVHD_DEV_EXT_SELECT, 0x0400, 0, 1 << 31));
    entries.extend_from_slice(&e8(
        ivrs::IVHD_DEV_SPECIAL,
        0,
        ivrs::ACPI_DEVFLAG_SYSMGT1,
        // handle 0x21, devid 00:14.0 (0x00a0), IOAPIC
        0x21 | (0x00a0 << 8) | ((ivrs::IVHD_SPECIAL_IOAPIC as u32) << 24),
    ));
    entries.extend_from_slice(&e8(
        ivrs::IVHD_DEV_SPECIAL,
        0,
        0,
        // HPET 0, devid 00:14.0
        (0x00a0 << 8) | ((ivrs::IVHD_SPECIAL_HPET as u32) << 24),
    ));
    let mut body = Vec::new();
    // Same IOMMU described twice: 10h then 40h — only 40h must be used.
    body.extend_from_slice(&ivhd(0x10, 0x3f, MMIO, &e4(ivrs::IVHD_DEV_ALL, 0, 0)));
    body.extend_from_slice(&ivhd(0x40, ivrs::IVHD_FLAG_PASSPW_EN, MMIO, &entries));
    body.extend_from_slice(&ivmd(
        ivrs::ACPI_IVMD_TYPE,
        ivrs::IVMD_FLAG_UNITY_MAP | ivrs::IVMD_FLAG_IR,
        WIFI,
        0,
        0x9d00_0800,
        0x1800,
    ));
    body.extend_from_slice(&ivmd(
        ivrs::ACPI_IVMD_TYPE_RANGE,
        ivrs::IVMD_FLAG_EXCL_RANGE,
        0x0300,
        0x0301,
        0x8000_0000,
        0x1000,
    ));
    let mut t = ivrs_header(body.len());
    t.extend_from_slice(&body);
    t
}

fn ivrs_parse_selects_highest_type_and_decodes_entries() -> TestResult {
    let info = match ivrs::parse(&synthetic_ivrs()) {
        Ok(i) => i,
        Err(_) => return TestResult::Fail("synthetic IVRS rejected"),
    };
    if info.ivhd_type != 0x40 || info.units.len() != 1 {
        return TestResult::Fail("IVHD 10h/40h duplicate not collapsed to 40h");
    }
    let u = &info.units[0];
    if u.mmio_phys != MMIO || u.flags != ivrs::IVHD_FLAG_PASSPW_EN || u.efr_reg != FEATURE_IA {
        return TestResult::Fail("IVHD header fields");
    }
    let covers = |id: u16| u.devices.iter().any(|d| d.first <= id && id <= d.last);
    if !covers(0) || !covers(0x80) || !covers(WIFI) || !covers(ALIASED) || !covers(0x0400) {
        return TestResult::Fail("device entry coverage");
    }
    if !covers(ALIAS_TARGET) || covers(0x0500) {
        return TestResult::Fail("alias target / uncovered requester");
    }
    if !u
        .aliases
        .iter()
        .any(|a| a.first == 0x0300 && a.last == 0x031f && a.alias == ALIAS_TARGET)
    {
        return TestResult::Fail("alias range");
    }
    if !u
        .devices
        .iter()
        .any(|d| d.first == 0x0400 && d.ext == 1 << 31)
    {
        return TestResult::Fail("extended select flags");
    }
    let ioapic = u
        .specials
        .iter()
        .find(|s| s.kind == ivrs::IVHD_SPECIAL_IOAPIC);
    let hpet = u
        .specials
        .iter()
        .find(|s| s.kind == ivrs::IVHD_SPECIAL_HPET);
    match (ioapic, hpet) {
        (Some(a), Some(h)) if a.handle == 0x21 && a.devid == 0x00a0 && h.devid == 0x00a0 => {}
        _ => return TestResult::Fail("special IOAPIC / HPET entries"),
    }
    if info.unity.len() != 2 {
        return TestResult::Fail("IVMD count");
    }
    let w = info.unity[0];
    // Linux: start = PAGE_ALIGN(0x9d000800), end = start + PAGE_ALIGN(0x1800).
    if (w.first, w.last, w.start, w.end, w.prot) != (WIFI, WIFI, 0x9d00_1000, 0x9d00_3000, 1) {
        return TestResult::Fail("IVMD unity decode");
    }
    let x = info.unity[1];
    if (x.first, x.last, x.prot) != (0x0300, 0x0301, 3) {
        return TestResult::Fail("IVMD exclusion range must be r/w unity");
    }
    TestResult::Pass
}
kernel_test_in!(
    "io/iommu/amdvi",
    ivrs_parse_selects_highest_type_and_decodes_entries
);

fn ivrs_parse_rejects_malformed() -> TestResult {
    let mut t = synthetic_ivrs();
    if ivrs::parse(&t[..40]) != Err(ivrs::IvrsError::Truncated) {
        return TestResult::Fail("short table accepted");
    }
    t[0] = b'X';
    if ivrs::parse(&t) != Err(ivrs::IvrsError::BadSignature) {
        return TestResult::Fail("bad signature accepted");
    }
    let mut t = synthetic_ivrs();
    // First IVHD length 0.
    t[50] = 0;
    t[51] = 0;
    if ivrs::parse(&t).is_ok() {
        return TestResult::Fail("zero-length IVHD accepted");
    }
    if ivrs::parse(&ivrs_header(0)) != Err(ivrs::IvrsError::NoUnits) {
        return TestResult::Fail("IVRS without IVHD accepted");
    }
    TestResult::Pass
}
kernel_test_in!("io/iommu/amdvi", ivrs_parse_rejects_malformed);

fn dte_encoding_matches_linux() -> TestResult {
    let root = 0x1234_5000u64;
    let d = dte_translated([0; 4], root, 4, 0x2a);
    // amd_iommu_set_dte_v1: V | TV | Mode(4) << 9 | root | IR | IW; domid.
    let want0 = 1 | 2 | (4 << 9) | root | (1 << 61) | (1 << 62);
    if d != [want0, 0x2a, 0, 0] {
        return TestResult::Fail("v1 DTE");
    }
    if dte_passthrough([0; 4]) != [1 | 2 | (1 << 61) | (1 << 62), 0, 0, 0] {
        return TestResult::Fail("identity DTE (set_dte_passthrough)");
    }
    if dte_blocked([0; 4]) != [1 | 2, 0, 0, 0] {
        return TestResult::Fail("blocking DTE");
    }
    // set_dev_entry_from_acpi: INITPASS bit 0xb8 = data[2] bit 56, LINT1
    // 0xbf = data[2] bit 63, SYSMGT1 0x68 = data[1] bit 40 (+ erratum 63 IW).
    let i = dte_initial(ivrs::ACPI_DEVFLAG_INITPASS | ivrs::ACPI_DEVFLAG_LINT1);
    if i != [0, 0, (1 << 56) | (1 << 63), 0] {
        return TestResult::Fail("IVHD interrupt-pass bits");
    }
    if dte_initial(ivrs::ACPI_DEVFLAG_SYSMGT1) != [1 << 62, 1 << 40, 0, 0] {
        return TestResult::Fail("erratum 63 (SysMgt=01b => IW)");
    }
    if dte_initial(ivrs::ACPI_DEVFLAG_SYSMGT1 | ivrs::ACPI_DEVFLAG_SYSMGT2) != [0, 3 << 40, 0, 0] {
        return TestResult::Fail("SysMgt=11b must not set IW");
    }
    TestResult::Pass
}
kernel_test_in!("io/iommu/amdvi", dte_encoding_matches_linux);

fn command_encodings_match_linux() -> TestResult {
    // build_completion_wait: lo(paddr) | STORE, hi(paddr) | type << 28, data.
    let cw = cmd_completion_wait(0x1_2345_6788, 0xdead_beef_0000_0007);
    if cw != [0x2345_6789, 0x1000_0001, 0x0000_0007, 0xdead_beef] {
        return TestResult::Fail("COMPLETION_WAIT");
    }
    if cmd_inv_dte(0x0308) != [0x0308, 0x2000_0000, 0, 0] {
        return TestResult::Fail("INVALIDATE_DEVTAB_ENTRY");
    }
    // One page: no S bit, PDE set.
    if cmd_inv_iommu_pages(7, 0x5000, 0x5fff) != [0, 0x3000_0007, 0x5002, 0] {
        return TestResult::Fail("INVALIDATE_IOMMU_PAGES 4K");
    }
    // 8 KiB at 0: S, no extra ones.
    if build_inv_address(0, 0x1fff) != 0x1 {
        return TestResult::Fail("8K size encoding");
    }
    // 16 KiB at 0x10000: S + bit 12.
    if build_inv_address(0x1_0000, 0x1_3fff) != 0x1_1001 {
        return TestResult::Fail("16K size encoding");
    }
    // Unaligned span 0x3000..=0x4fff covers 0..0x7fff (32K): bits 12,13.
    if build_inv_address(0x3000, 0x4fff) != 0x3001 {
        return TestResult::Fail("unaligned span encoding");
    }
    let all = cmd_inv_iommu_pages(9, 0, u64::MAX);
    if all != [0, 0x3000_0009, 0xffff_f003, 0x7fff_ffff] {
        return TestResult::Fail("INVALIDATE_IOMMU_PAGES all");
    }
    if cmd_inv_all() != [0, 0x8000_0000, 0, 0] {
        return TestResult::Fail("INVALIDATE_IOMMU_ALL");
    }
    TestResult::Pass
}
kernel_test_in!("io/iommu/amdvi", command_encodings_match_linux);

fn cmdline_opt_in_is_explicit() -> TestResult {
    let ok = iommu::per_domain_requested_in("quiet iommu.passthrough=0")
        && iommu::per_domain_requested_in("iommu.passthrough=off")
        && !iommu::per_domain_requested_in("")
        && !iommu::per_domain_requested_in("iommu.passthrough=1")
        && !iommu::per_domain_requested_in("iommu=pt amd_iommu=on");
    if ok {
        TestResult::Pass
    } else {
        TestResult::Fail("iommu.passthrough parsing")
    }
}
kernel_test_in!("io/iommu/amdvi", cmdline_opt_in_is_explicit);

// ── Register model ────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Op {
    Write64(u64, u64),
    Write32(u64, u32),
    /// A command consumed from the ring.
    Cmd([u32; 4]),
}

struct ModelState {
    regs: IrqSafeSpinLock<alloc::collections::BTreeMap<u64, u64>>,
    log: IrqSafeSpinLock<Vec<Op>>,
}

/// Register block that executes queued commands on every tail write
/// while `CmdBufEn` is set.
#[derive(Clone)]
struct RegModel(Arc<ModelState>);

impl RegModel {
    fn new(efr: u64, control: u64) -> Self {
        let mut m = alloc::collections::BTreeMap::new();
        m.insert(MMIO_EXT_FEATURES, efr);
        m.insert(MMIO_CONTROL, control);
        Self(Arc::new(ModelState {
            regs: IrqSafeSpinLock::new(m),
            log: IrqSafeSpinLock::new(Vec::new()),
        }))
    }
    fn get(&self, off: u64) -> u64 {
        *self.0.regs.lock().get(&off).unwrap_or(&0)
    }
    fn set(&self, off: u64, v: u64) {
        self.0.regs.lock().insert(off, v);
    }
    fn log(&self) -> Vec<Op> {
        self.0.log.lock().clone()
    }
    fn cmds(&self) -> Vec<[u32; 4]> {
        self.log()
            .into_iter()
            .filter_map(|o| match o {
                Op::Cmd(c) => Some(c),
                _ => None,
            })
            .collect()
    }
    fn clear_log(&self) {
        self.0.log.lock().clear();
    }
    fn process(&self, tail: u32) {
        if self.get(MMIO_CONTROL) & (1 << CONTROL_CMDBUF_EN) == 0 {
            return;
        }
        let base = self.get(MMIO_CMD_BUF) & 0x000f_ffff_ffff_f000;
        let mut head = self.get(MMIO_CMD_HEAD) as u32;
        while head != tail {
            let p = narf_memory::PhysAddr::new(base + head as u64).kernel_ptr::<u32>();
            // SAFETY: the backend's command ring, in the direct map.
            let c: [u32; 4] =
                core::array::from_fn(|i| unsafe { core::ptr::read_volatile(p.add(i)) });
            self.0.log.lock().push(Op::Cmd(c));
            if c[1] >> 28 == CMD_COMPL_WAIT && c[0] & CMD_COMPL_WAIT_STORE != 0 {
                let addr = ((c[1] as u64 & 0xf_ffff) << 32) | (c[0] as u64 & !7);
                let data = ((c[3] as u64) << 32) | c[2] as u64;
                let s = narf_memory::PhysAddr::new(addr).kernel_mut_ptr::<u64>();
                // SAFETY: the backend's semaphore page.
                unsafe { core::ptr::write_volatile(s, data) };
            }
            head = (head + CMD_ENTRY_SIZE) % CMD_BUFFER_SIZE;
        }
        self.set(MMIO_CMD_HEAD, head as u64);
    }
}

impl AmdViRegs for RegModel {
    fn read64(&self, off: u64) -> u64 {
        self.get(off)
    }
    fn write64(&self, off: u64, val: u64) {
        self.0.log.lock().push(Op::Write64(off, val));
        if off == MMIO_STATUS {
            // W1C
            let s = self.get(off) & !val;
            self.set(off, s);
        } else {
            self.set(off, val);
        }
    }
    fn read32(&self, off: u64) -> u32 {
        self.get(off) as u32
    }
    fn write32(&self, off: u64, val: u32) {
        self.0.log.lock().push(Op::Write32(off, val));
        self.set(off, val as u64);
        if off == MMIO_CMD_TAIL {
            self.process(val);
        }
    }
}

fn bring_up_model(
    efr: u64,
    firmware_control: u64,
) -> Result<(AmdVi, RegModel, IvrsInfo), &'static str> {
    let info = ivrs::parse(&synthetic_ivrs()).map_err(|_| "ivrs")?;
    let model = RegModel::new(efr, firmware_control);
    let m2 = model.clone();
    let map = move |u: &ivrs::IvhdUnit| -> Option<Box<dyn AmdViRegs>> {
        (u.mmio_phys == MMIO).then(|| Box::new(m2.clone()) as Box<dyn AmdViRegs>)
    };
    match bring_up(&info, &map) {
        Ok(hw) => Ok((hw, model, info)),
        Err(BringUpError::NoMemory) => Err("frame allocator unavailable"),
        Err(_) => Err("bring_up failed against the model"),
    }
}

fn result(r: Result<(), &'static str>) -> TestResult {
    match r {
        Ok(()) => TestResult::Pass,
        Err("frame allocator unavailable") => TestResult::Skip("frame allocator unavailable"),
        Err(e) => TestResult::Fail(e),
    }
}

fn control_writes(log: &[Op]) -> Vec<u64> {
    log.iter()
        .filter_map(|o| match o {
            Op::Write64(MMIO_CONTROL, v) => Some(*v),
            _ => None,
        })
        .collect()
}

fn position(log: &[Op], f: impl Fn(&Op) -> bool) -> Option<usize> {
    log.iter().position(f)
}

fn enable_sequence_against_register_model() -> TestResult {
    result((|| {
        // Firmware left the unit enabled with logging + HT tunnel on.
        let fw = (1 << CONTROL_IOMMU_EN) | (1 << CONTROL_EVT_LOG_EN) | (1 << CONTROL_HT_TUN_EN);
        let (hw, model, _) = bring_up_model(FEATURE_IA, fw)?;
        let log = model.log();
        let ctl = model.get(MMIO_CONTROL);
        let bit = |b: u32| ctl & (1 << b) != 0;
        if !(bit(CONTROL_IOMMU_EN)
            && bit(CONTROL_CMDBUF_EN)
            && bit(CONTROL_EVT_LOG_EN)
            && bit(CONTROL_COHERENT_EN)
            && bit(CONTROL_PASSPW_EN))
        {
            return Err("final control: IommuEn/CmdBufEn/EvtLogEn/Coherent/PassPW");
        }
        if bit(CONTROL_HT_TUN_EN) || bit(CONTROL_ISOC_EN) || bit(CONTROL_EVT_INT_EN) {
            return Err("HT tunnel / Isoc / event interrupt must follow IVHD flags (off)");
        }
        if (ctl >> CONTROL_INV_TIMEOUT) & CTRL_INV_TO_MASK != CTRL_INV_TO_1S {
            return Err("invalidation timeout not 1 s");
        }
        // iommu_disable first: the very first control write clears CmdBufEn,
        // and IommuEn is cleared before anything is programmed.
        let ctls = control_writes(&log);
        if ctls.is_empty() || ctls[0] & (1 << CONTROL_CMDBUF_EN) != 0 {
            return Err("sequence must start with iommu_disable");
        }
        let disabled = position(
            &log,
            |o| matches!(o, Op::Write64(MMIO_CONTROL, v) if v & 1 == 0),
        );
        let dev_tbl = position(&log, |o| matches!(o, Op::Write64(MMIO_DEV_TABLE, _)));
        let cmd_buf = position(&log, |o| matches!(o, Op::Write64(MMIO_CMD_BUF, _)));
        let enabled = disabled.and_then(|a| {
            position(
                &log[a..],
                |o| matches!(o, Op::Write64(MMIO_CONTROL, v) if v & 1 != 0),
            )
            .map(|i| a + i)
        });
        let inv_all = position(&log, |o| matches!(o, Op::Cmd(c) if *c == cmd_inv_all()));
        let evt_buf = position(&log, |o| matches!(o, Op::Write64(MMIO_EVT_BUF, _)));
        match (disabled, dev_tbl, cmd_buf, enabled, inv_all, evt_buf) {
            (Some(a), Some(b), Some(c), Some(d), Some(e), Some(f))
                if a < b && b < c && c < d && d < e && e < f => {}
            _ => return Err("order: disable < devtbl < cmdbuf < IommuEn < INV_ALL < evtlog"),
        }
        let (cmd_phys, evt_phys, _) = hw.unit_rings(0).ok_or("unit")?;
        if model.get(MMIO_DEV_TABLE) != hw.dev_table_phys() | 0x1ff {
            return Err("device table base | size 0x1ff (2 MiB)");
        }
        if hw.dev_table_phys() & ((2 << 20) - 1) != 0 {
            return Err("device table not 2 MiB aligned");
        }
        if model.get(MMIO_CMD_BUF) != cmd_phys | MMIO_CMD_SIZE_512 {
            return Err("command buffer base | 512 entries");
        }
        if model.get(MMIO_EVT_BUF) != evt_phys | EVTLOG_LEN_MASK_DEF {
            return Err("event log base | 512 entries");
        }
        // Every DTE is identity; IVHD flags are folded in.
        for id in [0u16, WIFI, ALIASED, 0x0500, 0xffff] {
            if hw.read_dte(id)
                != dte_passthrough(dte_initial(if id == WIFI {
                    ivrs::ACPI_DEVFLAG_LINT0
                } else {
                    0
                }))
            {
                return Err("DTE not initialised to pass-through");
            }
        }
        Ok(())
    })())
}
kernel_test_in!("io/iommu/amdvi", enable_sequence_against_register_model);

fn flush_without_ia_invalidates_every_dte_and_domain() -> TestResult {
    result((|| {
        let (_hw, model, _) = bring_up_model(1 << 0, 0)?;
        let cmds = model.cmds();
        let dte = cmds
            .iter()
            .filter(|c| c[1] >> 28 == CMD_INV_DEV_ENTRY)
            .count();
        let pages = cmds
            .iter()
            .filter(|c| c[1] >> 28 == CMD_INV_IOMMU_PAGES)
            .count();
        if dte != 0x1_0000 || pages != 0x1_0000 {
            return Err("no FEATURE_IA: flush_dte_all + flush_tlb_all");
        }
        if cmds.contains(&cmd_inv_all()) {
            return Err("INVALIDATE_IOMMU_ALL without FEATURE_IA");
        }
        Ok(())
    })())
}
kernel_test_in!(
    "io/iommu/amdvi",
    flush_without_ia_invalidates_every_dte_and_domain
);

fn is_cw(c: &[u32; 4]) -> bool {
    c[1] >> 28 == CMD_COMPL_WAIT
}

fn attach_detach_ordering() -> TestResult {
    result((|| {
        let (hw, model, _) = bring_up_model(FEATURE_IA, 0)?;
        model.clear_log();
        let root = 0x0055_5000;
        hw.attach(Bdf(WIFI), 3, root, 4).map_err(|_| "attach")?;
        let want = dte_translated(dte_initial(ivrs::ACPI_DEVFLAG_LINT0), root, 4, 3);
        if hw.read_dte(WIFI) != want {
            return Err("attached DTE");
        }
        let c = model.cmds();
        if c.len() != 2 || c[0] != cmd_inv_dte(WIFI) || !is_cw(&c[1]) {
            return Err("attach: INV_DEVTAB_ENTRY then COMPLETION_WAIT");
        }
        if hw.attach(Bdf(WIFI), 4, root, 4).is_ok() {
            return Err("second domain on one requester accepted");
        }
        if hw.attach(Bdf(0x0500), 3, root, 4).is_ok() {
            return Err("requester without IVHD coverage accepted");
        }
        model.clear_log();
        hw.flush_iotlb(3, 0x8000, 0x2000).map_err(|_| "flush")?;
        let c = model.cmds();
        if c.len() != 2 || c[0] != cmd_inv_iommu_pages(3, 0x8000, 0x9fff) || !is_cw(&c[1]) {
            return Err("flush_iotlb: INV_IOMMU_PAGES then COMPLETION_WAIT");
        }
        model.clear_log();
        hw.detach(Bdf(WIFI), 3).map_err(|_| "detach")?;
        if hw.read_dte(WIFI) != dte_blocked(dte_initial(ivrs::ACPI_DEVFLAG_LINT0)) {
            return Err("detached DTE must block");
        }
        let c = model.cmds();
        if c.len() != 3
            || c[0] != cmd_inv_dte(WIFI)
            || c[1] != cmd_inv_iommu_pages(3, 0, u64::MAX)
            || !is_cw(&c[2])
        {
            return Err("detach: INV_DEVTAB, INV_PAGES(all), COMPLETION_WAIT");
        }
        if hw.detach(Bdf(WIFI), 3).is_ok() {
            return Err("double detach accepted");
        }
        // Alias: both the requester and its alias are programmed + flushed.
        model.clear_log();
        hw.attach(Bdf(ALIASED), 9, root, 4)
            .map_err(|_| "alias attach")?;
        if hw.read_dte(ALIAS_TARGET)[1] & DTE_DOMID_MASK != 9
            || hw.read_dte(ALIASED)[1] & 0xffff != 9
        {
            return Err("alias DTE not cloned");
        }
        let c = model.cmds();
        if c.len() != 3 || c[0] != cmd_inv_dte(ALIASED) || c[1] != cmd_inv_dte(ALIAS_TARGET) {
            return Err("alias attach flushes");
        }
        // Sibling behind the same alias joins the same domain only.
        if hw.attach(Bdf(ALIASED + 1), 10, root, 4).is_ok() {
            return Err("alias sibling in a different domain accepted");
        }
        hw.attach(Bdf(ALIASED + 1), 9, root, 4)
            .map_err(|_| "alias sibling attach")?;
        hw.detach(Bdf(ALIASED), 9).map_err(|_| "alias detach")?;
        if hw.read_dte(ALIAS_TARGET)[0] & DTE_FLAG_IR == 0 {
            return Err("shared alias blocked while a sibling is attached");
        }
        hw.detach(Bdf(ALIASED + 1), 9)
            .map_err(|_| "sibling detach")?;
        if hw.read_dte(ALIAS_TARGET) != dte_blocked([0; 4]) {
            return Err("alias not blocked after last user");
        }
        Ok(())
    })())
}
kernel_test_in!("io/iommu/amdvi", attach_detach_ordering);

fn event_log_decode_and_page_fault_count() -> TestResult {
    result((|| {
        let (hw, model, _) = bring_up_model(FEATURE_IA, 0)?;
        let (_, evt, _) = hw.unit_rings(0).ok_or("unit")?;
        // IO_PAGE_FAULT: devid 01:00.0, domain 3, RW (write), addr.
        let e = [
            WIFI as u32,
            (3) | (0x020 << 16) | (2 << 28),
            0xdead_b000,
            0x1,
        ];
        let p = narf_memory::PhysAddr::new(evt).kernel_mut_ptr::<u32>();
        for (i, w) in e.iter().enumerate() {
            // SAFETY: the backend's event log.
            unsafe { core::ptr::write_volatile(p.add(i), *w) };
        }
        model.set(MMIO_EVT_TAIL, 16);
        model.set(MMIO_STATUS, MMIO_STATUS_EVT_OVERFLOW);
        if hw.poll_events() != 1 || hw.event_count(EVENT_TYPE_IO_FAULT) != 1 {
            return Err("IO_PAGE_FAULT not counted");
        }
        let ev = *hw.recent_events().last().ok_or("no event")?;
        if ev.devid != WIFI
            || ev.domid_or_pasid != 3
            || ev.address != 0x1_dead_b000
            || !ev.is_write()
        {
            return Err("event decode");
        }
        if model.get(MMIO_EVT_HEAD) != 16 {
            return Err("event head not advanced");
        }
        // SAFETY: as above.
        if unsafe { core::ptr::read_volatile(p) } != 0 {
            return Err("consumed entry not cleared (erratum 732)");
        }
        if hw.event_overflows() != 1 || model.get(MMIO_STATUS) & MMIO_STATUS_EVT_OVERFLOW != 0 {
            return Err("overflow not restarted");
        }
        // A zero (not yet written) entry is left for the next poll.
        model.set(MMIO_EVT_TAIL, 32);
        if hw.poll_events() != 0 || model.get(MMIO_EVT_HEAD) != 16 {
            return Err("zero entry consumed");
        }
        Ok(())
    })())
}
kernel_test_in!("io/iommu/amdvi", event_log_decode_and_page_fault_count);

fn per_domain_end_to_end_with_unity_map() -> TestResult {
    let r = (|| {
        let (hw, model, _) = bring_up_model(FEATURE_IA, 0)?;
        let hw: &'static AmdVi = Box::leak(Box::new(hw));
        iommu::__reset_for_test();
        iommu::enable_per_domain(hw).map_err(|_| "enable_per_domain")?;
        let domain = iommu::default_domain(Bdf(WIFI)).map_err(|_| "default domain")?;
        let (_, root) = domain.page_table_root().ok_or("no root")?;
        let dte = hw.read_dte(WIFI);
        if dte[0] & DTE_HOST_TRP != root || dte[1] & 0xffff != domain.domain_id() as u64 {
            return Err("default domain DTE");
        }
        // IVMD unity range 0x9d001000..0x9d003000 (read) mapped 1:1.
        match domain.translate(0x9d00_2000) {
            Some((0x9d00_2000, p)) if p.read() && !p.write() => {}
            _ => return Err("IVMD unity range not identity-mapped"),
        }
        let dev = crate::DmaDevice::coherent().with_iommu_domain(domain.clone());
        let buf = crate::alloc_coherent_for(&dev, 4096, narf_lib::id::DomainId::DRIVER_0, u64::MAX)
            .map_err(|_| "alloc_coherent_for")?;
        let iova = buf.dma_addr().raw();
        if domain.translate(iova).map(|t| t.0) != Some(buf.phys_addr().as_u64()) {
            return Err("IOVA does not translate to the buffer");
        }
        model.clear_log();
        drop(buf);
        let c = model.cmds();
        if c.len() != 2 || c[0] != cmd_inv_iommu_pages(domain.domain_id(), iova, iova + 0xfff) {
            return Err("unmap must INV_IOMMU_PAGES + COMPLETION_WAIT");
        }
        Ok(())
    })();
    iommu::__reset_for_test();
    result(r)
}
kernel_test_in!("io/iommu/amdvi", per_domain_end_to_end_with_unity_map);
