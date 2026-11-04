//! Display-20 (Xe2_LPD) DC service fixtures (§17 10.5). Expected values
//! are worked by hand from Linux b90c984d: intel_dmc.c (`dmc_firmware_default`
//! `xe2lpd_dmc.bin`, `XE2LPD_DMC_MAX_FW_SIZE`, `intel_dmc_load_program`'s
//! display >= 20 `DMC_FQ_W2_PTS_CFG_SEL`), intel_display_power.c
//! (`get_allowed_dc_mask`, display >= 20 `max_dc` 2) and xe_mmio.c /
//! xe_device_wa_oob.rules (Wa_15015404425). The container is laid out field
//! by field, independently of the production parser.
use super::*;
use alloc::collections::BTreeMap;
use core::cell::RefCell;
use narf_kernel_test::{kernel_test_in, TestResult};

#[derive(Default)]
struct Regs {
    regs: RefCell<BTreeMap<u64, u32>>,
    writes: RefCell<Vec<(u64, u32)>>,
}
impl Regs {
    fn get(&self, off: u64) -> u32 {
        *self.regs.borrow().get(&off).unwrap_or(&0)
    }
    fn wrote(&self, off: u64) -> bool {
        self.writes.borrow().iter().any(|(o, _)| *o == off)
    }
}
impl MmioWindow for Regs {
    fn read32(&self, off: u64) -> u32 {
        self.get(off)
    }
    fn write32(&self, off: u64, val: u32) {
        self.writes.borrow_mut().push((off, val));
        self.regs.borrow_mut().insert(off, val);
    }
}

fn put32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

/// One wildcard main v3 program at 0x80000 (CSS 128 bytes, package v2
/// with 32 entries) carrying `payload_dwords` dwords and a two-entry MMIO
/// table.
fn container(payload_dwords: usize) -> Vec<u8> {
    let package = 16 + 32 * 12;
    let mut blob = alloc::vec![0u8; 128 + package];
    put32(&mut blob, 0, 0x09);
    put32(&mut blob, 4, 32);
    put32(&mut blob, 8, 0x1_0000);
    put32(&mut blob, 88, 0x0002_001d);
    blob[128] = (package / 4) as u8;
    blob[129] = 2;
    put32(&mut blob, 128 + 12, 1);
    let entry = 128 + 16;
    blob[entry + 2] = b'*';
    blob[entry + 3] = b'*';
    let prog = blob.len();
    blob.resize(prog + 256 + payload_dwords * 4, 0);
    put32(&mut blob, prog, 0x4040_3E3E);
    blob[prog + 4] = 64;
    blob[prog + 5] = 3;
    put32(&mut blob, prog + 12, payload_dwords as u32);
    put32(&mut blob, prog + 16, 0x0002_001d);
    put32(&mut blob, prog + 20, 0x80000);
    put32(&mut blob, prog + 92, 2);
    put32(&mut blob, prog + 96, 0x8F074);
    put32(&mut blob, prog + 100, 0x8F034);
    put32(&mut blob, prog + 176, 0x2FC0);
    put32(&mut blob, prog + 180, 0x8003_3200);
    for i in 0..payload_dwords {
        put32(&mut blob, prog + 256 + 4 * i, 0xD200_0000 | i as u32);
    }
    blob
}

fn smoke_xe2lpd_dc_service_profile_and_firmware() -> TestResult {
    use crate::intel_gpu::Generation;
    // KMS-owned generations: display 14 and display 20 install a service;
    // both target DC6 only; only display 20 flushes reads.
    assert_eq!(
        service_profile(Generation::MeteorLake),
        Some((DmcPlatform::Xelpdp, DC_STATE_EN_UPTO_DC6, false))
    );
    assert_eq!(
        service_profile(Generation::LunarLake),
        Some((DmcPlatform::Xe2Lpd, DC_STATE_EN_UPTO_DC6, true))
    );
    for other in [
        Generation::TigerLake,
        Generation::AlderLake,
        Generation::PantherLake,
    ] {
        assert_eq!(service_profile(other), None);
    }
    assert_eq!(XE2LPD_ALLOWED_DC_MASK, 2);
    assert_eq!(XE2LPD_ALLOWED_DC_MASK & DC_STATE_EN_DC3CO, 0);
    assert_eq!(firmware_path(DmcPlatform::Xelpdp), "i915/mtl_dmc.bin");
    assert_eq!(firmware_path(DmcPlatform::Xe2Lpd), "i915/xe2lpd_dmc.bin");
    // The ceilings: 0x7800 payload bytes exceed display 14's 0x7000 and
    // fit display 20's 0x8000; 0x8004 fits neither.
    let big = container(0x7800 / 4);
    assert!(parse_for(DmcPlatform::Xelpdp, &big).is_err());
    assert!(parse_for(DmcPlatform::Xe2Lpd, &big).is_ok());
    assert!(parse_for(DmcPlatform::Xe2Lpd, &container(0x8004 / 4)).is_err());

    // Wa_15015404425 on the service's view: four dummy writes to
    // 0x130030 precede every display-20 read; display 14 has none.
    let mut memory = alloc::vec![0u32; 0x140000 / 4];
    let bar = narf_bus::bar::MmioRegion {
        phys: narf_memory::PhysAddr::new(0x1000_0000),
        virt: memory.as_mut_ptr() as u64,
        len: 0x140000,
        kind: narf_bus::bar::BarKind::Mmio64 {
            prefetchable: false,
        },
    };
    let cap = Cap::<narf_bus::BusDeviceCap, narf_capabilities::Write>::bootstrap();
    for (flush_reads, dummy) in [(true, 0), (false, 0xffff_ffff)] {
        memory[0x130030 / 4] = 0xffff_ffff;
        memory[DC_STATE_EN as usize / 4] = 0x802;
        let view = ServiceWindow {
            window: crate::intel_gpu_gt_hw::AuthorizedWindow::new(bar, cap),
            flush_reads,
        };
        assert_eq!(view.read32(DC_STATE_EN), 0x802);
        assert_eq!(memory[0x130030 / 4], dummy);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe2lpd_dc",
    smoke_xe2lpd_dc_service_profile_and_firmware
);

fn smoke_xe2lpd_dc_service_loads_xe2lpd_dmc_and_enters_dc6() -> TestResult {
    // Display 20: firmware left DC states disabled; the Init reference
    // holds DC_off until a 0x7800-byte main program loads, then DC6 is
    // entered 17 ms after the last release.
    let regs = Regs::default();
    let core = IrqSafeSpinLock::new(DcCore::new_for(DmcPlatform::Xe2Lpd, XE2LPD_ALLOWED_DC_MASK));
    {
        let mut c = core.lock();
        c.sanitize(&regs).unwrap();
        c.get(&regs, DcUser::Init).unwrap();
        assert_eq!(c.platform(), DmcPlatform::Xe2Lpd);
    }
    let due = publication_step(&core, &regs, 0, || Ok(Arc::new(container(0x7800 / 4))))
        .expect("Init released after the load");
    assert_eq!(due, DC_REENABLE_DELAY_NS);
    assert!(matches!(core.lock().program(), ProgramState::Loaded { .. }));
    assert_eq!(core.lock().refs(DcUser::Init), 0);
    // intel_dmc_load_program, display >= 20: no Wa_16015201720 clock-gate
    // write, the W2 PTS select after the program and before the masks.
    assert!(!regs.wrote(crate::intel_gpu_dmc::GEN9_CLKGATE_DIS_0));
    let writes = regs.writes.borrow().clone();
    let program_end = writes
        .iter()
        .rposition(|(o, _)| (0x80000..0x8F000).contains(o))
        .unwrap();
    let w2 = writes
        .iter()
        .position(|w| *w == (0x8f240, 0x0302_0100))
        .unwrap();
    assert!(program_end < w2);
    assert_eq!(regs.get(0x80000), 0xD200_0000);
    assert_eq!(
        regs.get(0x80000 + 0x7800 - 4),
        0xD200_0000 | (0x7800 / 4 - 1)
    );
    // DC6 re-entry once due, with the main program re-verified.
    assert_eq!(
        core.lock().arm_if_due(&regs, due - 1, ArmGates::default()),
        Err(ArmBlock::NotDue(due))
    );
    assert_eq!(
        core.lock().arm_if_due(&regs, due, ArmGates::default()),
        Ok(DC_STATE_EN_UPTO_DC6)
    );
    assert!(core.lock().armed());
    assert_eq!(regs.get(DC_STATE_EN) & GEN12_DC_MASK, DC_STATE_EN_UPTO_DC6);

    // The same container under the display-14 rules refuses at parse:
    // the Init reference stays held (DC0) and no program RAM is written.
    let regs = Regs::default();
    let core = IrqSafeSpinLock::new(DcCore::new(XELPDP_ALLOWED_DC_MASK));
    {
        let mut c = core.lock();
        c.sanitize(&regs).unwrap();
        c.get(&regs, DcUser::Init).unwrap();
        assert_eq!(c.platform(), DmcPlatform::Xelpdp);
    }
    assert_eq!(
        publication_step(&core, &regs, 0, || Ok(Arc::new(container(0x7800 / 4)))),
        None
    );
    assert!(matches!(
        core.lock().program(),
        ProgramState::Refused(DcRefusal::Parse(_))
    ));
    assert_eq!(core.lock().refs(DcUser::Init), 1);
    assert!(!regs.wrote(0x80000));
    assert!(!regs.wrote(0x8f240));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe2lpd_dc",
    smoke_xe2lpd_dc_service_loads_xe2lpd_dmc_and_enters_dc6
);
