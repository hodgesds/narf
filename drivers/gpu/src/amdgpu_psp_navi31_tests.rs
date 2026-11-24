//! Navi31 PSP13.0.0 ring claim, kind gates, and the step-1 ring dispatch
//! sequence, with no device I/O.
//!
//! The shared gap lane 2 found was that `psp_dispatch_one` fails closed
//! for Navi31 because no GPCOM ring exists for MP0 13.0.0: `Psp` knew
//! Phoenix (13.0.4), Raphael (13.0.5), PSP11 and PSP14, but nothing
//! claimed 13.0.0. These fixtures pin the claim (`new_navi31` +
//! `Layout`), the kind gates, and the dispatch sequence step 1 needs —
//! ring create, LOAD_TOC, LOAD_IP_FW (SMU) then SETUP_TMR, the
//! PMFW-centralized order `load_smc_centralized` lists 13.0.0 under —
//! through the model PSP, which is the failure point moved past
//! `psp_dispatch_one`: the same commands the sync entry point refuses
//! now execute through the ring.
use super::*;
use alloc::vec;
use narf_kernel_test::{kernel_test_in, TestResult};

fn ip(id: u16, version: (u8, u8, u8), index: usize, base: u32) -> discovery::IpBlock {
    let mut bases = [0x20000; discovery::MAX_BASE_ADDRS];
    bases[index] = base;
    if id == discovery::HW_ID_GC {
        bases[1] = 0x4000;
    }
    discovery::IpBlock {
        hw_id: id,
        instance: 0,
        major: version.0,
        minor: version.1,
        revision: version.2,
        sub_revision: 0,
        variant: 0,
        base_addrs: bases,
        num_bases: 3,
    }
}

/// A Navi31 discovery set: MP0 13.0.0, NBIF (ungated version), HDP 5.2.0,
/// GC 11.0.0. The NBIF version is deliberately the tinygrad lead
/// (gfx1100 → NBIO 4.3.0): the layout does not gate on it, so the
/// fixture pins the bank resolution, not the version. The HDP minor is
/// likewise the fixture's representative choice — the layout accepts
/// 5.2.0/5.2.1 and the constructor test covers both invalidate
/// behaviours; the exact silicon minor is unverified (no 7000-series
/// card in the programme).
fn gpu(regs: &mut [u32]) -> AmdGpu {
    AmdGpu {
        regs: MmioRegion {
            phys: narf_memory::PhysAddr::new(0xa000_0000),
            virt: regs.as_mut_ptr() as u64,
            len: regs.len() as u64 * 4,
            kind: narf_bus::BarKind::Mmio32 {
                prefetchable: false,
            },
        },
        fb_bar: MmioRegion {
            phys: narf_memory::PhysAddr::new(0x9000_0000),
            virt: 0,
            len: 256 << 20,
            kind: narf_bus::BarKind::Mmio64 { prefetchable: true },
        },
        vram: crate::amdgpu::VramInfo {
            base: 0x9000_0000,
            size: 12 << 30,
            visible_size: 256 << 20,
        },
        chip: crate::amdgpu::__test_chip_info_for_pci_id(
            crate::amdgpu::AMD_VENDOR,
            crate::amdgpu::NAVI31,
        )
        .unwrap(),
        mode: None,
        backlight_percent: None,
        fw_loaded: false,
        vbios: None,
        gc_info: None,
        ip_blocks: vec![
            ip(discovery::HW_ID_MP0, (13, 0, 0), 0, 0x10000),
            ip(discovery::HW_ID_NBIF, (4, 3, 0), 2, 0xd20),
            ip(discovery::HW_ID_HDP, (5, 2, 0), 0, 0xb00),
            ip(discovery::HW_ID_GC, (11, 0, 0), 0, 0x2000),
        ],
    }
}

fn pool() -> Pool {
    // SAFETY: bookkeeping-only pool; construction reserves from it but
    // never dereferences its mapping (the ring is never started here).
    unsafe {
        Pool::from_owned_range(
            narf_bus::MmioRegion {
                phys: narf_memory::PhysAddr::new(0x9000_3000),
                virt: 0x3000,
                len: 16 << 20,
                kind: narf_bus::BarKind::Mmio64 { prefetchable: true },
            },
            0x8_0000_3000,
        )
    }
    .unwrap()
}

fn session_with_pool(mapping: narf_bus::MmioRegion, address: u64) -> (Pool, Session<Fake>) {
    let (_, engine) = fixture();
    // SAFETY: Fake implements every ring and payload access; bookkeeping only.
    let pool = unsafe { Pool::from_owned_range(mapping, address) }.unwrap();
    let engine = Engine {
        memory: pool.reserve(BUFFER_SIZE).unwrap(),
        ..engine
    };
    (
        pool.clone(),
        Session {
            engine,
            pool,
            payload: None,
            tmr: None,
            tmr_ready: false,
            smc_state: SmcState::Absent,
            smc_resident: false,
            gfx_state: GfxLoadState::Absent,
            gfx_status: None,
            media_firmware: MediaFirmware::default(),
            dmub_image: None,
            gfx12_vcn_version: None,
            fb_base: 0x8_0000_0000,
            fb_offset: 0x1_0000_0000,
            secure_dmub: None,
        },
    )
}
fn session() -> (Pool, Session<Fake>) {
    session_with_pool(
        narf_bus::MmioRegion {
            phys: narf_memory::PhysAddr::new(0x9000_3000),
            virt: 0x3000,
            len: 16 << 20,
            kind: narf_bus::BarKind::Mmio64 { prefetchable: true },
        },
        0x8_0000_3000,
    )
}

fn psp_navi31_constructor_uses_gc1100_and_exact_ip_banks() -> TestResult {
    let mut regs = vec![0; 0x80000 / 4];
    let gpu = gpu(&mut regs);
    // GC 11.0.0 framebuffer location: BASE 0x1678, TOP 0x1679,
    // OFFSET 0x15a7 (`gc_11_0_0_offset.h`).
    regs[0x2000 + 0x1678] = 0x800;
    regs[0x2000 + 0x1679] = 0xaff;
    regs[0x2000 + 0x15a7] = 0x100;
    let pool = pool();
    let before = regs.clone();
    // SAFETY: register reads are backed by regs; unpublished VRAM is bookkeeping-only.
    let mut psp = unsafe { Psp::new_navi31(&gpu, Cap::bootstrap(), &pool) }.unwrap();
    let mmio = &psp.session.engine.io;
    if mmio.mp0 != 0x40000
        || mmio.nbio != 0x3480
        || mmio.invalidate_reg != Some(0x2f44)
        || mmio.gfx_status_regs.is_some()
        || psp.session.fb_base != 0x8_0000_0000
        || psp.session.fb_offset != 0x1_0000_0000
        || psp.session.engine.lenient
        || regs != before
    {
        return TestResult::Fail("wrong PSP/NBIO/HDP/GMC bank or constructor performed writes");
    }
    // HDP 5.2.1 has no invalidate step; 5.2.0 does.
    let mut hdp521 = self::gpu(&mut regs);
    hdp521.ip_blocks[2].revision = 1;
    let layout521 = Layout::resolve(&hdp521, Kind::Navi31).unwrap();
    if layout521.invalidate_reg.is_some() {
        return TestResult::Fail("HDP 5.2.1 must not take the invalidate register");
    }
    // Navi31-only operations are refused on the wrong kinds, and the
    // Navi31 gates pass on the right kind (Busy: the ring was never
    // started, so the failure is the unstarted ring, not the gate).
    if run(psp.setup_tmr(&[1; 4096])) != Err(Error::Unsupported)
        || run(psp.load_dmub(&[1])) != Err(Error::Unsupported)
        || run(psp.setup_tmr_navi22(&crate::amdgpu_psp_boot::tests::firmware14()))
            != Err(Error::Unsupported)
        || run(psp.setup_tmr_navi31(&[1; 4096])) != Err(Error::Busy)
        || run(psp.load_smc_navi31(&[1; 8])) != Err(Error::Busy)
        || regs != before
    {
        return TestResult::Fail("Navi31 kind gates wrong");
    }
    drop(psp);
    for case in 0..12 {
        let mut bad = self::gpu(&mut regs);
        match case {
            // Corrected die pairing: Navi32 (11.0.3) and Navi33 (11.0.2)
            // are refused, as is Phoenix's 11.0.1.
            0 => bad.ip_blocks[3].revision = 3,
            1 => bad.ip_blocks[3].revision = 2,
            2 => bad.ip_blocks[3].revision = 1,
            // MP0 13.0.4 (Phoenix) and 13.0.5 (Raphael) are not 13.0.0.
            3 => bad.ip_blocks[0].revision = 4,
            4 => bad.ip_blocks[0].revision = 5,
            5 => bad.chip.did = crate::amdgpu::PHOENIX1,
            6 => bad.ip_blocks.push(bad.ip_blocks[0]),
            7 => bad.ip_blocks[1].num_bases = 2,
            8 => bad.ip_blocks[0].num_bases = 0,
            9 => bad.ip_blocks[3].num_bases = 0,
            10 => bad.ip_blocks[3].base_addrs[0] = 0x20000 - 0x1679,
            _ => bad.regs.len -= 0x80000,
        }
        if Layout::resolve(&bad, Kind::Navi31).is_ok() {
            return TestResult::Fail("unaudited IP/register window accepted");
        }
    }
    if Layout::resolve(&gpu, Kind::Phoenix).is_ok()
        || Layout::resolve(&gpu, Kind::Raphael).is_ok()
        || Layout::resolve(&gpu, Kind::Navi22).is_ok()
    {
        return TestResult::Fail("Navi31 entered another kind's path");
    }
    let authority = Cap::bootstrap();
    authority.revoke();
    // SAFETY: register reads are backed by regs; the revoked authority
    // fails the pool validation before any reservation is made.
    let revoked = unsafe { Psp::new_navi31(&gpu, authority, &pool) };
    if revoked.err() != Some(Error::Revoked) {
        return TestResult::Fail("revoked authority claimed the ring");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/psp-ring",
    psp_navi31_constructor_uses_gc1100_and_exact_ip_banks
);

/// initialize() step 1, past `psp_dispatch_one`: ring create, LOAD_TOC,
/// LOAD_IP_FW (SMU, `GFX_FW_TYPE_SMU` 18), SETUP_TMR — the exact
/// dispatch the sync entry point fails closed on — through the model
/// PSP, with the PSP's rejection and a lost fence as failure modes.
fn psp_navi31_step1_ring_dispatch() -> TestResult {
    let (_, mut s) = session();
    run(s.engine.start()).unwrap();
    let toc = vec![0u8; 4096];
    if run(s.init_tmr(Some(&toc))).is_err() || s.tmr.is_none() || s.tmr_ready {
        return TestResult::Fail("Navi31 LOAD_TOC did not reserve the TMR");
    }
    let smc = vec![0xAAu8; 64];
    if run(s.load_smc_centralized(&smc)).is_err() || !s.tmr_ready || s.smc_state != SmcState::Loaded
    {
        return TestResult::Fail("Navi31 SMU dispatch did not complete the TMR setup");
    }
    let ids: Vec<u32> = s.engine.io.submissions.iter().map(|c| c[2]).collect();
    if ids != [0x20, 6, 5] {
        return TestResult::Fail("Navi31 step-1 ring commands out of order");
    }
    // LOAD_IP_FW carries the firmware type in words[10]: 18 (SMU) for the
    // SMU load, 0 for the LOAD_TOC.
    let load_ip = s.engine.io.submissions[1];
    if load_ip[10] != 18 || s.engine.io.submissions[0][10] != 0 {
        return TestResult::Fail("Navi31 LOAD_IP_FW/LOAD_TOC firmware type wrong");
    }
    // Failure modes: a PSP rejection of the SMU load, and a lost
    // SETUP_TMR fence after the upload was accepted.
    let (_, mut s) = session();
    run(s.engine.start()).unwrap();
    run(s.init_tmr(Some(&toc))).unwrap();
    s.engine.io.reject = 9;
    s.engine.io.reject_command = Some(6);
    s.engine.io.reject_type = Some(18);
    if run(s.load_smc_centralized(&smc)) != Err(Error::Rejected(9))
        || s.smc_state != SmcState::Failed
    {
        return TestResult::Fail("Navi31 SMU rejection not reported");
    }
    let (_, mut s) = session();
    run(s.engine.start()).unwrap();
    run(s.init_tmr(Some(&toc))).unwrap();
    s.engine.io.stall_command = Some(5);
    if run(s.load_smc_centralized(&smc)) != Err(Error::Timeout) {
        return TestResult::Fail("Navi31 lost SETUP_TMR fence not fatal");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/psp-ring", psp_navi31_step1_ring_dispatch);
