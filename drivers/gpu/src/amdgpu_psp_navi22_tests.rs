//! Navi22 register selection and the shared TMR lifecycle, with no device I/O.
use super::*;
use alloc::vec;
use core::{
    future::Future,
    task::{Context, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

#[path = "amdgpu_psp_gfx_tests.rs"]
mod gfx;

fn session() -> (Pool, Session<Fake>) {
    let (_, engine) = fixture();
    // Deliberately unaligned GPU pool start, different from the PCI BAR address
    // and the TMR physical address. Construction below never dereferences BAR0.
    let mapping = narf_bus::MmioRegion {
        phys: narf_memory::PhysAddr::new(0x9000_3000),
        virt: 0x3000,
        len: 16 << 20,
        kind: narf_bus::BarKind::Mmio64 { prefetchable: true },
    };
    // SAFETY: Fake implements every ring and payload access; bookkeeping only.
    let pool = unsafe { Pool::from_owned_range(mapping, 0x8_0000_3000) }.unwrap();
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
            gfx_state: GfxLoadState::Absent,
            gfx_status: None,
            media_firmware: MediaFirmware::default(),
            gfx12_vcn_version: None,
            fb_base: 0x8_0000_0000,
            fb_offset: 0x1_0000_0000,
        },
    )
}
fn psp_navi22_tmr_embedded_toc_and_address_spaces() -> TestResult {
    let (pool, mut session) = session();
    run(session.engine.start()).unwrap();
    let toc = [0x11, 0x22, 0x33, 0x44, 0x55];
    if run(session.setup_tmr_payload(Some(&toc))).is_err() || !session.tmr_ready {
        return TestResult::Fail("embedded TOC/TMR setup failed");
    }
    let io = &session.engine.io;
    if io.payload != [0x11, 0x22, 0x33, 0x44, 0x55, 0, 0, 0] || io.violation {
        return TestResult::Fail("TOC not copied/padded/flushed before publication");
    }
    let load_toc = io.submissions[0];
    let setup = io.submissions[1];
    if load_toc[2] != 0x20
        || load_toc[7..11] != [0x6000, 8, 5, 0]
        || setup[2] != 5
        || setup[7..13] != [0x100000, 8, 4 << 20, 2, 0x100000, 1]
        || setup[13..].iter().any(|v| *v != 0)
    {
        return TestResult::Fail("wrong GPCOM ABI or confused GPU/VRAM/PCI addresses");
    }
    if session.payload.is_some()
        || pool.available() != (16 << 20) - BUFFER_SIZE - (4 << 20)
        || run(session.setup_tmr_payload(None)) != Err(Error::Busy)
    {
        return TestResult::Fail("TOC retained or duplicate TMR installed");
    }
    // SAFETY: Fake has no hardware firmware consumers.
    unsafe { run(session.stop()) }.unwrap();
    if session.engine.io.submissions.last().unwrap()[2] != 7 || session.tmr_ready {
        return TestResult::Fail("TMR was not destroyed before ring teardown");
    }
    drop(session);
    if pool.available() != 16 << 20 {
        return TestResult::Fail("verified stop leaked VRAM");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/psp-ring",
    psp_navi22_tmr_embedded_toc_and_address_spaces
);

/// MP0 11.0.11 has PMFW-centralized C-state management
/// (psp_check_pmfw_centralized_cstate_management): psp_hw_start sends
/// LOAD_TOC (psp_tmr_init), then SMC LOAD_IP_FW (psp_load_smu_fw), and only
/// then SETUP_TMR (psp_tmr_load).
fn psp_navi22_pmfw_centralized_toc_smc_then_setup_tmr() -> TestResult {
    let (pool, mut s) = session();
    let bytes = [0xa5; 16];
    run(s.engine.start()).unwrap();
    if run(s.load_smc_centralized(&bytes)) != Err(Error::Busy) {
        return TestResult::Fail("SMC loaded before LOAD_TOC/TMR reservation");
    }
    if run(s.init_tmr(Some(&[0x11, 0x22, 0x33, 0x44]))).is_err()
        || s.tmr_ready
        || s.tmr.is_none()
        || s.engine.io.submissions.len() != 1
    {
        return TestResult::Fail("psp_tmr_init sent SETUP_TMR before PMFW");
    }
    if run(s.load_smc_centralized(&bytes)).is_err()
        || s.smc_state != SmcState::Loaded
        || !s.tmr_ready
    {
        return TestResult::Fail("SMC then SETUP_TMR failed");
    }
    let ids: Vec<u32> = s.engine.io.submissions.iter().map(|c| c[2]).collect();
    let smc = s.engine.io.submissions[1];
    let setup = s.engine.io.submissions[2];
    if ids != [0x20, 6, 5]
        || smc[10] != 18
        || setup[7..13] != [0x100000, 8, 4 << 20, 2, 0x100000, 1]
    {
        return TestResult::Fail("Linux LOAD_TOC -> LOAD_IP_FW(SMU) -> SETUP_TMR order");
    }
    if run(s.load_smc_centralized(&bytes)) != Err(Error::Busy)
        || run(s.load_smc(&bytes)) != Err(Error::Busy)
        || s.engine.io.submissions.len() != 3
    {
        return TestResult::Fail("SMC reloaded");
    }
    // SAFETY: fake SMU/PSP have no running firmware consumers.
    unsafe { run(s.stop()) }.unwrap();
    drop(s);
    if pool.available() != 16 << 20 {
        return TestResult::Fail("centralized TMR session leaked memory");
    }
    // A rejected SETUP_TMR leaves PMFW loaded but no usable TMR.
    let (_, mut s) = session();
    run(s.engine.start()).unwrap();
    run(s.init_tmr(None)).unwrap();
    s.engine.io.reject = 9;
    s.engine.io.reject_command = Some(5);
    if run(s.load_smc_centralized(&bytes)) != Err(Error::Rejected(9))
        || s.smc_state != SmcState::Loaded
        || s.tmr_ready
    {
        return TestResult::Fail("failed SETUP_TMR reported a ready TMR");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/psp-ring",
    psp_navi22_pmfw_centralized_toc_smc_then_setup_tmr
);

/// Linux psp_cmd_submit_buf only warns on nonzero response status on bare
/// metal and waits ~2 s for the fence; Navi22 sessions do the same except for
/// DESTROY_TMR, whose refusal must keep the trusted memory.
fn psp_navi22_nonzero_status_warns_like_linux() -> TestResult {
    if FENCE_TIMEOUT_MS < 2000 {
        return TestResult::Fail("PSP fence deadline shorter than psp_cmd_submit_buf");
    }
    let (pool, mut s) = session();
    s.engine.lenient = true;
    run(s.engine.start()).unwrap();
    s.engine.io.reject = 0xffff000a;
    if run(s.init_tmr(Some(&[1, 2, 3, 4]))).is_err() || s.tmr.is_none() {
        return TestResult::Fail("nonzero LOAD_TOC status aborted the boot");
    }
    if run(s.load_smc_centralized(&[1, 2, 3, 4])).is_err() || !s.tmr_ready {
        return TestResult::Fail("nonzero LOAD_IP_FW/SETUP_TMR status aborted the boot");
    }
    // SAFETY: model only; firmware refuses the TMR teardown.
    if unsafe { run(s.stop()) } != Err(Error::Rejected(0xffff000a)) || s.tmr.is_none() {
        return TestResult::Fail("refused DESTROY_TMR recycled trusted memory");
    }
    drop(s);
    if pool.available() != (16 << 20) - BUFFER_SIZE - (4 << 20) {
        return TestResult::Fail("refused teardown released TMR");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/psp-ring",
    psp_navi22_nonzero_status_warns_like_linux
);

fn psp_navi22_tmr_defaults_bounds_and_rejection() -> TestResult {
    let (_, mut s) = session();
    if run(s.setup_tmr_payload(None)) != Err(Error::Busy) || s.tmr.is_some() {
        return TestResult::Fail("TMR allocated before ring readiness");
    }
    run(s.engine.start()).unwrap();
    run(s.setup_tmr_payload(None)).unwrap();
    if s.engine.io.submissions.len() != 1 || s.engine.io.submissions[0][9] != 4 << 20 {
        return TestResult::Fail("no-TOC path sent LOAD_TOC or wrong default TMR size");
    }
    // SAFETY: no real firmware consumers.
    unsafe { run(s.stop()) }.unwrap();
    for size in [0, 1, 4095, (64 << 20) + 4096, u32::MAX, 32 << 20] {
        let (pool, mut s) = session();
        run(s.engine.start()).unwrap();
        s.engine.io.tmr_size = size;
        let expected = if size == 32 << 20 {
            Error::Allocation
        } else {
            Error::Invalid
        };
        if run(s.setup_tmr_payload(Some(&[1, 2, 3, 4]))) != Err(expected)
            || s.tmr.is_some()
            || s.payload.is_some()
            || s.engine.io.submissions.len() != 1
            || pool.available() != (16 << 20) - BUFFER_SIZE
        {
            return TestResult::Fail("untrusted TMR size allocated/published or leaked TOC");
        }
        // SAFETY: model has no consumers.
        unsafe { run(s.stop()) }.unwrap();
    }
    let (pool, mut s) = session();
    run(s.engine.start()).unwrap();
    s.engine.io.reject = 0xffff000a;
    if run(s.setup_tmr_payload(Some(&[1, 2, 3, 4]))) != Err(Error::Rejected(0xffff000a))
        || s.tmr.is_some()
        || s.payload.is_some()
        || pool.available() != (16 << 20) - BUFFER_SIZE
    {
        return TestResult::Fail("rejected TOC retained or proceeded to TMR setup");
    }
    // SAFETY: no TMR was published and the ring is model-only.
    unsafe { run(s.stop()) }.unwrap();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/psp-ring",
    psp_navi22_tmr_defaults_bounds_and_rejection
);

fn psp_navi22_cancelled_toc_and_tmr_keep_device_ownership() -> TestResult {
    for command_id in [0x20, 5] {
        let (pool, mut s) = session();
        run(s.engine.start()).unwrap();
        s.engine.io.stall_command = Some(command_id);
        {
            let mut future = core::pin::pin!(s.setup_tmr_payload(Some(&[1, 2, 3, 4])));
            for _ in 0..4 {
                if future
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_ready()
                {
                    return TestResult::Fail("stalled GPCOM completed");
                }
            }
        }
        if s.tmr_ready
            || s.engine.state != State::Pending
            || run(s.setup_tmr_payload(None)) != Err(Error::Busy)
        {
            return TestResult::Fail("cancelled TMR setup published readiness or allowed replay");
        }
        if command_id == 0x20 {
            if s.tmr.is_some() || s.payload.is_none() {
                return TestResult::Fail("TOC ownership lost");
            }
            // SAFETY: model ring destruction can stop the in-flight TOC read.
            unsafe { run(s.stop()) }.unwrap();
            drop(s);
            if pool.available() != 16 << 20 {
                return TestResult::Fail("stopped TOC leaked memory");
            }
        } else {
            // SAFETY: consumers are absent, but ring completion is uncertain.
            if unsafe { run(s.stop()) } != Err(Error::Busy) || s.tmr.is_none() {
                return TestResult::Fail("unacknowledged TMR reclaimed by ring destruction");
            }
            drop(s);
            if pool.available() != (16 << 20) - BUFFER_SIZE - (4 << 20) {
                return TestResult::Fail("cancelled TMR or ring memory recycled");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/psp-ring",
    psp_navi22_cancelled_toc_and_tmr_keep_device_ownership
);

fn psp_navi22_tmr_revocation_and_failed_teardown() -> TestResult {
    let (pool, mut s) = session();
    run(s.engine.start()).unwrap();
    let authority = s.engine.authority;
    {
        let mut future = core::pin::pin!(s.setup_tmr_payload(Some(&[1, 2, 3, 4])));
        if future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_ready()
        {
            return TestResult::Fail("staging did not yield");
        }
        authority.revoke();
        if run(future) != Err(Error::Revoked) {
            return TestResult::Fail("revoked TOC submitted");
        }
    }
    if !s.engine.io.submissions.is_empty() || s.tmr.is_some() {
        return TestResult::Fail("revoked firmware wrote commands");
    }
    // SAFETY: teardown removes an existing ring; no consumers exist in the model.
    unsafe { run(s.stop()) }.unwrap();
    drop(s);
    if pool.available() != 16 << 20 {
        return TestResult::Fail("unpublished TOC not reclaimed");
    }

    let (pool, mut s) = session();
    run(s.engine.start()).unwrap();
    run(s.setup_tmr_payload(None)).unwrap();
    s.engine.io.reject = 7;
    // SAFETY: no firmware consumers, but firmware will reject TMR teardown.
    if unsafe { run(s.stop()) } != Err(Error::Rejected(7)) || !s.tmr_ready || s.tmr.is_none() {
        return TestResult::Fail("failed destroy lost TMR ownership");
    }
    drop(s);
    if pool.available() != (16 << 20) - BUFFER_SIZE - (4 << 20) {
        return TestResult::Fail("failed destroy recycled trusted memory");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/psp-ring",
    psp_navi22_tmr_revocation_and_failed_teardown
);

fn psp_hdp_failure_precedes_ring_publication() -> TestResult {
    let (pool, mut engine) = fixture();
    engine.io.fail_hdp = true;
    if run(engine.start()) != Err(Error::Invalid) || !engine.io.writes.is_empty() {
        return TestResult::Fail("bad HDP mapping published a ring");
    }
    drop(engine);
    if pool.available() != BUFFER_SIZE + 4096 {
        return TestResult::Fail("unpublished ring quarantined");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/psp-ring",
    psp_hdp_failure_precedes_ring_publication
);

fn psp_navi22_smc_payload_type_and_one_upload() -> TestResult {
    let (pool, mut s) = session();
    let bytes = [0xa5; 16];
    if run(s.load_smc(&bytes)) != Err(Error::Busy) || s.smc_state != SmcState::Absent {
        return TestResult::Fail("SMC accepted before ring/TMR readiness");
    }
    run(s.engine.start()).unwrap();
    if run(s.load_smc(&bytes)) != Err(Error::Busy) || s.payload.is_some() {
        return TestResult::Fail("SMC staged without trusted memory");
    }
    run(s.setup_tmr_payload(None)).unwrap();
    if run(s.load_smc(&bytes)).is_err() || s.smc_state != SmcState::Loaded {
        return TestResult::Fail("SMC load failed");
    }
    let cmd = s.engine.io.submissions[1];
    if cmd[2] != 6
        || cmd[7..11] != [0x6000, 8, 16, 18]
        || cmd[11..].iter().any(|v| *v != 0)
        || s.engine.io.payload != bytes
        || s.engine.io.violation
        || s.payload.is_some()
        || pool.available() != (16 << 20) - BUFFER_SIZE - (4 << 20)
    {
        return TestResult::Fail(
            "wrong SMC command/address/type, unflushed payload or retained staging",
        );
    }
    if run(s.load_smc(&bytes)) != Err(Error::Busy) || s.engine.io.submissions.len() != 2 {
        return TestResult::Fail("SMC reloaded without resetting consumers");
    }
    // SAFETY: fake SMU has no running firmware consumers.
    unsafe { run(s.stop()) }.unwrap();
    drop(s);
    if pool.available() != 16 << 20 {
        return TestResult::Fail("stopped SMC session leaked memory");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/psp-ring",
    psp_navi22_smc_payload_type_and_one_upload
);

fn psp_navi22_smc_rejection_and_timeout() -> TestResult {
    for timeout in [false, true] {
        let (pool, mut s) = session();
        run(s.engine.start()).unwrap();
        run(s.setup_tmr_payload(None)).unwrap();
        s.engine.io.reject = 0xffff000a;
        s.engine.io.stall_command = timeout.then_some(6);
        let expected = if timeout {
            Error::Timeout
        } else {
            Error::Rejected(0xffff000a)
        };
        if run(s.load_smc(&[1, 2, 3, 4])) != Err(expected)
            || s.smc_state != SmcState::Failed
            || run(s.load_smc(&[1, 2, 3, 4])) != Err(Error::Busy)
        {
            return TestResult::Fail("failed SMC acknowledged or allowed replay");
        }
        if timeout {
            // SAFETY: fake has no consumers, but incomplete PSP command prevents teardown.
            if unsafe { run(s.stop()) } != Err(Error::Busy) || s.payload.is_none() {
                return TestResult::Fail("timed out SMC lost device ownership");
            }
            drop(s);
            if pool.available() != (16 << 20) - BUFFER_SIZE - (4 << 20) - 4096 {
                return TestResult::Fail("timeout recycled PSP-owned ring/TMR/SMC payload");
            }
        } else {
            if s.payload.is_some() {
                return TestResult::Fail("fenced rejection retained SMC staging");
            }
            s.engine.io.reject = 0;
            // SAFETY: no real consumers and PSP teardown succeeds in this model.
            unsafe { run(s.stop()) }.unwrap();
            drop(s);
            if pool.available() != 16 << 20 {
                return TestResult::Fail("rejected SMC cleanup leaked memory");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/psp-ring", psp_navi22_smc_rejection_and_timeout);

fn psp_navi22_smc_cancellation_and_revocation() -> TestResult {
    for published in [false, true] {
        for revoke in [false, true] {
            let (pool, mut s) = session();
            run(s.engine.start()).unwrap();
            run(s.setup_tmr_payload(None)).unwrap();
            s.engine.io.stall_command = Some(6);
            let authority = s.engine.authority;
            {
                let mut future = core::pin::pin!(s.load_smc(&[1, 2, 3, 4]));
                for _ in 0..if published { 3 } else { 1 } {
                    if future
                        .as_mut()
                        .poll(&mut Context::from_waker(Waker::noop()))
                        .is_ready()
                    {
                        return TestResult::Fail("stalled SMC completed");
                    }
                }
                if revoke {
                    authority.revoke();
                    if run(future) != Err(Error::Revoked) {
                        return TestResult::Fail("revoked SMC continued");
                    }
                }
            }
            let expected_state = if revoke {
                SmcState::Failed
            } else {
                SmcState::Pending
            };
            if s.smc_state != expected_state
                || run(s.load_smc(&[1, 2, 3, 4])) != Err(Error::Busy)
                || s.engine.io.submissions.len() != if published { 2 } else { 1 }
            {
                return TestResult::Fail("cancel/revoke lost state or sent extra commands");
            }
            if !published && !revoke {
                // SAFETY: payload was never published, no modeled TMR consumers.
                unsafe { run(s.stop()) }.unwrap();
                drop(s);
                if pool.available() != 16 << 20 {
                    return TestResult::Fail("unpublished SMC leaked after stop");
                }
            } else {
                drop(s);
                let retained = BUFFER_SIZE + (4 << 20) + if published { 4096 } else { 0 };
                if pool.available() != (16 << 20) - retained {
                    return TestResult::Fail("cancel/revoke recycled device-owned SMC memory");
                }
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/psp-ring",
    psp_navi22_smc_cancellation_and_revocation
);

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
            crate::amdgpu::NAVI22,
        )
        .unwrap(),
        mode: None,
        fw_loaded: false,
        vbios: None,
        gc_info: None,
        ip_blocks: vec![
            ip(discovery::HW_ID_MP0, (11, 0, 11), 0, 0x10000),
            ip(discovery::HW_ID_NBIF, (3, 3, 0), 2, 0xd20),
            ip(discovery::HW_ID_HDP, (5, 0, 2), 0, 0xb00),
            ip(discovery::HW_ID_GC, (10, 3, 2), 0, 0x2000),
            ip(discovery::HW_ID_MP1, (11, 0, 11), 0, 0x11000),
            ip(discovery::HW_ID_SDMA0, (5, 2, 2), 0, 0x12000),
        ],
    }
}
fn psp_navi22_constructor_uses_gmc10_and_exact_ip_banks() -> TestResult {
    let mut regs = vec![0; 0x80000 / 4];
    let gpu = gpu(&mut regs);
    regs[0x2000 + 0x16fc] = 0x800;
    regs[0x2000 + 0x16fd] = 0xaff;
    regs[0x2000 + 0x16e7] = 0x100;
    regs[0x2000 + 0xf40] = 0x1234;
    regs[0x4000 + 0x4e8d] = 1 << 31;
    let (pool, s) = session();
    drop(s);
    let before = regs.clone();
    // SAFETY: register reads are backed by regs; unpublished VRAM is bookkeeping-only.
    let mut psp = unsafe { Psp::new_navi22(&gpu, Cap::bootstrap(), &pool) }.unwrap();
    let mmio = &psp.session.engine.io;
    if mmio.mp0 != 0x40000
        || mmio.nbio != 0x3480
        || mmio.invalidate_reg != Some(0x2f44)
        || mmio.gfx_status_regs != Some(((0x2000 + 0xf40) * 4, (0x4000 + 0x4e8d) * 4))
        || psp.session.fb_base != 0x8_0000_0000
        || psp.session.fb_offset != 0x1_0000_0000
        || psp.fb_location() != (0x8_0000_0000, 0x1_0000_0000)
        || !psp.session.engine.lenient
        || regs != before
    {
        return TestResult::Fail("wrong PSP/NBIO/HDP/GMC bank or constructor performed writes");
    }
    if psp
        .session
        .engine
        .access(|io| io.gfx_boot_status())
        .unwrap()
        .unwrap()
        != (GfxBootStatus {
            cp_stat: 0x1234,
            rlc_bootload: 1 << 31,
        })
    {
        return TestResult::Fail("GC status used the wrong discovery base index");
    }
    if run(psp.setup_tmr(&[])) != Err(Error::Unsupported)
        || run(psp.setup_tmr_navi22(&crate::amdgpu_psp_boot::tests::firmware14()))
            != Err(Error::Unsupported)
        || run(psp.load_dmub(&[1])) != Err(Error::Unsupported)
        || regs != before
    {
        return TestResult::Fail("Navi22 accepted a Phoenix firmware operation");
    }
    drop(psp);
    for case in 0..14 {
        let mut bad = self::gpu(&mut regs);
        match case {
            0 => bad.ip_blocks[0].revision = 7,
            1 => bad.ip_blocks[3].revision = 1,
            2 => bad.ip_blocks[1].major = 4,
            3 => bad.ip_blocks[2].minor = 2,
            4 => bad.ip_blocks.push(bad.ip_blocks[0]),
            5 => bad.ip_blocks[0].num_bases = 0,
            6 => bad.regs.len -= 4,
            7 => bad.chip.did = crate::amdgpu::PHOENIX1,
            8 => bad.ip_blocks[4].revision = 7,
            9 => bad.ip_blocks.push(bad.ip_blocks[4]),
            10 => bad.ip_blocks[5].revision = 0,
            11 => bad.ip_blocks.push(bad.ip_blocks[5]),
            12 => bad.ip_blocks[3].num_bases = 1,
            _ => bad.ip_blocks[3].base_addrs[1] = 0x20000 - 0x4e8d,
        }
        if Layout::resolve(&bad, Kind::Navi22).is_ok() {
            return TestResult::Fail("unaudited IP/register window accepted");
        }
    }
    if Layout::resolve(&gpu, Kind::Phoenix).is_ok() {
        return TestResult::Fail("Navi22 entered Phoenix path");
    }
    let authority = Cap::bootstrap();
    authority.revoke();
    // SAFETY: same backed register model; revoked capability must block all reads.
    let revoked = unsafe { Psp::new_navi22(&gpu, authority, &pool) };
    if !matches!(revoked, Err(Error::Revoked)) {
        return TestResult::Fail("revoked constructor read registers");
    }
    if pool.available() != 16 << 20 {
        return TestResult::Fail("constructor failures allocated memory");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/psp-ring",
    psp_navi22_constructor_uses_gmc10_and_exact_ip_banks
);

fn psp_navi22_constructor_rejects_unmapped_vram() -> TestResult {
    let mut regs = vec![0; 0x80000 / 4];
    let (pool, s) = session();
    drop(s);
    for case in 0..6 {
        let mut gpu = gpu(&mut regs);
        regs[0x2000 + 0x16fc] = 0x800;
        regs[0x2000 + 0x16fd] = 0xaff;
        regs[0x2000 + 0x16e7] = 0x100;
        match case {
            0 => regs[0x2000 + 0x16fc] = u32::MAX,
            // amdgpu_gmc_vram_location: the aperture is fb_start +
            // MEMSIZE, so a pool past MEMSIZE is refused whatever TOP says.
            1 => gpu.vram.size = 1 << 20,
            2 => regs[0x2000 + 0x16fc] = 0x801,
            3 => gpu.vram.visible_size = 1 << 20,
            4 => gpu.fb_bar.len = 1 << 20,
            _ => gpu.fb_bar.virt = 4096,
        }
        // SAFETY: no hardware writes, all tested reads backed by regs.
        if unsafe { Psp::new_navi22(&gpu, Cap::bootstrap(), &pool) }.is_ok() {
            return TestResult::Fail("unmapped or mismatched TMR pool accepted");
        }
        if pool.available() != 16 << 20 {
            return TestResult::Fail("invalid pool allocated ring");
        }
    }
    // The host card's 12272 MiB with a stale FB_LOCATION_TOP: TOP is not
    // the aperture end, MEMSIZE is.
    let mut gpu = gpu(&mut regs);
    gpu.vram.size = 12272 << 20;
    regs[0x2000 + 0x16fc] = 0x800;
    regs[0x2000 + 0x16fd] = 0x7ff;
    regs[0x2000 + 0x16e7] = 0x100;
    // SAFETY: as above.
    if unsafe { Psp::new_navi22(&gpu, Cap::bootstrap(), &pool) }.is_err() {
        return TestResult::Fail("FB_LOCATION_TOP used as the aperture end");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/psp-ring",
    psp_navi22_constructor_rejects_unmapped_vram
);

fn navi48_gpu(regs: &mut [u32], revision: u8) -> AmdGpu {
    let mut gpu = gpu(regs);
    gpu.chip = crate::amdgpu::__test_chip_info_for_pci_id(0x1002, 0x7550).unwrap();
    gpu.ip_blocks = vec![
        ip(discovery::HW_ID_MP0, (14, 0, revision), 0, 0x10000),
        ip(discovery::HW_ID_NBIF, (7, 7, 0), 2, 0xd20),
        ip(discovery::HW_ID_HDP, (6, 1, 0), 0, 0xb00),
        ip(discovery::HW_ID_GC, (12, 0, 1), 0, 0x2000),
        ip(discovery::HW_ID_MP1, (14, 0, 3), 1, 0x11000),
        ip(discovery::HW_ID_SDMA0, (7, 0, 1), 0, 0x12000),
        ip(discovery::HW_ID_VCN, (5, 0, 0), 0, 0x13000),
        ip(discovery::HW_ID_DCN, (4, 1, 0), 0, 0x14000),
    ];
    gpu.vram.size = 16 << 30;
    regs[0x2000 + 0x1614] = 0x800;
    regs[0x2000 + 0x1615] = 0xbff;
    regs[0x2000 + 0x15a7] = 0x100;
    gpu
}

fn psp_navi48_gmc12_hdp6_and_target_isolation() -> TestResult {
    for revision in [2, 3] {
        let mut regs = vec![0; 0x80000 / 4];
        let mut gpu = navi48_gpu(&mut regs, revision);
        let (pool, s) = session();
        drop(s);
        for nbio in [(7, 7, 0), (7, 7, 1), (6, 3, 1)] {
            gpu.ip_blocks[1] = ip(discovery::HW_ID_NBIF, nbio, 2, 0xd20);
            let before = regs.clone();
            // SAFETY: array-backed registers; no device receives the unused pool.
            let mut psp = unsafe { Psp::new_navi48(&gpu, Cap::bootstrap(), &pool) }.unwrap();
            if psp.kind != Kind::Navi48(revision)
                || psp.session.fb_base != 0x8_0000_0000
                || psp.session.fb_offset != 0x1_0000_0000
                || psp.session.engine.io.invalidate_reg.is_some()
                || psp.session.engine.lenient
                || regs != before
                || run(psp.setup_tmr(&[])) != Err(Error::Unsupported)
                || run(psp.load_dmub(&[0; 4])) != Err(Error::Unsupported)
                || run(psp.wait_gfx_boot_navi22()) != Err(Error::Unsupported)
            {
                return TestResult::Fail("PSP14 used another generation's addresses or API");
            }
            let gfx = crate::amdgpu_navi48_firmware::fixture();
            if run(psp.load_smc_navi48(&gfx)) != Err(Error::Busy)
                || run(psp.load_gfx_navi48(&gfx)) != Err(Error::Busy)
                || psp.session.engine.io.gfx_status_regs
                    != Some(((0x2000 + 0xf40) * 4, (0x4000 + 0x4e7c) * 4))
            {
                return TestResult::Fail("GC12 firmware readiness or status register profile");
            }
            let firmware = crate::amdgpu_psp_boot::tests::firmware14();
            let expected = if revision == 3 {
                Error::Busy
            } else {
                Error::Unsupported
            };
            if run(psp.setup_tmr_navi48(&firmware)) != Err(expected)
                || run(psp.setup_tmr_navi22(&crate::amdgpu_psp_boot::tests::firmware()))
                    != Err(Error::Unsupported)
            {
                return TestResult::Fail("PSP14 TOC ignored target or ring readiness");
            }
            let io = &mut psp.session.engine.io;
            if !io.setup_hdp() {
                return TestResult::Fail("Navi48 HDP remap failed");
            }
            io.invalidate();
            if regs[0xd20 + 0x12d] != HDP_HOLE as u32 || regs[0xb00 + 0xd1] != 0 {
                return TestResult::Fail("HDP6 used obsolete HDP5 invalidate register");
            }
            regs[0xd20 + 0x12d] = 0;
        }
        let authority = Cap::bootstrap();
        authority.revoke();
        // SAFETY: revoked constructor cannot access even the array-backed MMIO.
        if !matches!(
            // SAFETY: revoked construction cannot touch registers.
            unsafe { Psp::new_navi48(&gpu, authority, &pool) },
            Err(Error::Revoked)
        ) {
            return TestResult::Fail("Navi48 ring ignored revocation");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/psp-ring",
    psp_navi48_gmc12_hdp6_and_target_isolation
);

fn psp_navi48_rejects_incompatible_or_ambiguous_discovery() -> TestResult {
    for bad in 0..9 {
        let mut regs = vec![0; 0x80000 / 4];
        let mut gpu = navi48_gpu(&mut regs, 3);
        match bad {
            0 => gpu.chip = crate::amdgpu::__test_chip_info_for_pci_id(0x1002, 0x73df).unwrap(),
            1 => gpu.ip_blocks[0].major = 11,
            2 => gpu.ip_blocks[0].revision = 5,
            3 => gpu.ip_blocks[1].major = 3,
            4 => gpu.ip_blocks[2].major = 5,
            5 => gpu.ip_blocks[3].revision = 2, // GC 12.0.2: no RDNA4 die
            6 => gpu.ip_blocks.push(gpu.ip_blocks[0]),
            7 => gpu.ip_blocks[1].num_bases = 2,
            _ => gpu.regs.len = 0x70000,
        }
        let (pool, s) = session();
        drop(s);
        let available = pool.available();
        let before = regs.clone();
        // SAFETY: unsupported profiles must fail before MMIO or allocations.
        if unsafe { Psp::new_navi48(&gpu, Cap::bootstrap(), &pool) }.is_ok()
            || pool.available() != available
            || regs != before
        {
            return TestResult::Fail("Navi48 accepted wrong/ambiguous/out-of-bounds IP layout");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/psp-ring",
    psp_navi48_rejects_incompatible_or_ambiguous_discovery
);

fn gddr6_navi48_constructor_keeps_vram_unmodified() -> TestResult {
    let mut regs = vec![0; 0x80000 / 4];
    let gpu = navi48_gpu(&mut regs, 3);
    let before = regs.clone();
    let exchange = crate::amdgpu_vram_boot::Training {
        c2p: (16 << 30) - (9 << 20),
        p2c: (16 << 30) - 0x8000,
        size: 4096,
    };
    // SAFETY: constructor only validates/allocates; run is never called.
    let trainer =
        unsafe { crate::amdgpu_gddr6::Trainer::new_navi48(&gpu, Cap::bootstrap(), exchange) }
            .unwrap();
    if trainer.state() != crate::amdgpu_gddr6::State::Prepared || regs != before {
        return TestResult::Fail("PSP14 training touched VRAM before run");
    }
    drop(trainer);
    let cap = Cap::bootstrap();
    cap.revoke();
    // SAFETY: revoked construction fails before touching mappings.
    if !matches!(
        // SAFETY: revoked construction cannot touch registers.
        unsafe { crate::amdgpu_gddr6::Trainer::new_navi48(&gpu, cap, exchange) },
        Err(crate::amdgpu_gddr6::Error::Revoked)
    ) {
        return TestResult::Fail("PSP14 training constructor ignored authority");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gddr6",
    gddr6_navi48_constructor_keeps_vram_unmodified
);

fn rdna2_gpu(regs: &mut [u32], profile: &crate::amdgpu_rdna2::Profile, did: u16) -> AmdGpu {
    let mut gpu = self::gpu(regs);
    gpu.chip = crate::amdgpu::__test_chip_info_for_pci_id(0x1002, did).unwrap();
    for (index, version) in [
        (0, profile.psp_version),
        (3, profile.gc_version),
        (4, profile.psp_version),
        (5, profile.sdma_version),
    ] {
        let ip = &mut gpu.ip_blocks[index];
        (ip.major, ip.minor, ip.revision) = version;
    }
    regs[0x2000 + 0x16fc] = 0x800;
    regs[0x2000 + 0x16fd] = 0xaff;
    regs[0x2000 + 0x16e7] = 0x100;
    gpu
}

fn rdna2_psp_constructor_resolves_every_asic_without_writes() -> TestResult {
    for profile in crate::amdgpu_rdna2::PROFILES {
        let mut regs = vec![0; 0x80000 / 4];
        for &did in profile.pci_ids {
            let gpu = rdna2_gpu(&mut regs, profile, did);
            let (pool, s) = session();
            drop(s);
            let before = regs.clone();
            // SAFETY: register reads are backed by regs; no device memory is published.
            let psp = unsafe { Psp::new_rdna2(&gpu, Cap::bootstrap(), &pool) }.unwrap();
            let io = &psp.session.engine.io;
            if psp.kind.rdna2_profile() != Some(profile)
                || io.mp0 != 0x40000
                || io.nbio != 0x3480
                || io.invalidate_reg != Some(0x2f44)
                || io.gfx_status_regs != Some(((0x2000 + 0xf40) * 4, (0x4000 + 0x4e8d) * 4))
                || psp.fb_location() != (0x8_0000_0000, 0x1_0000_0000)
                || !psp.session.engine.lenient
                || regs != before
            {
                return TestResult::Fail(
                    "RDNA2 PSP resolved wrong registers or wrote during construction",
                );
            }
            drop(psp);
            let authority = Cap::bootstrap();
            authority.revoke();
            // SAFETY: revoked authority prevents even construction-time register reads.
            if unsafe { Psp::new_rdna2(&gpu, authority, &pool) }.err() != Some(Error::Revoked) {
                return TestResult::Fail(
                    "RDNA2 PSP pool validation bypassed capability revocation",
                );
            }
        }
        let gpu = rdna2_gpu(&mut regs, profile, profile.pci_ids[0]);
        for block in 0..gpu.ip_blocks.len() {
            for change in 0..4 {
                let mut bad = rdna2_gpu(&mut regs, profile, profile.pci_ids[0]);
                match change {
                    0 => bad.ip_blocks[block].major = 0xff,
                    1 => bad.ip_blocks.push(bad.ip_blocks[block]),
                    2 => bad.ip_blocks[block].num_bases = 0,
                    _ => {
                        bad.ip_blocks.remove(block);
                    }
                }
                if Layout::resolve(&bad, Kind::Rdna2(profile)).is_ok() {
                    return TestResult::Fail("RDNA2 PSP accepted missing/duplicate/foreign bank");
                }
            }
        }
        for other in crate::amdgpu_rdna2::PROFILES {
            if other != profile && Layout::resolve(&gpu, Kind::Rdna2(other)).is_ok() {
                return TestResult::Fail("RDNA2 ring accepted another ASIC's layout");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/rdna2",
    rdna2_psp_constructor_resolves_every_asic_without_writes
);

fn rdna2_psp_rejects_cross_chip_sos_smc_and_graphics_before_submission() -> TestResult {
    for profile in crate::amdgpu_rdna2::PROFILES {
        let mut regs = vec![0; 0x80000 / 4];
        let gpu = rdna2_gpu(&mut regs, profile, profile.pci_ids[0]);
        let (pool, s) = session();
        drop(s);
        // SAFETY: inert register storage; tested entry points reject before device writes.
        let mut psp = unsafe { Psp::new_rdna2(&gpu, Cap::bootstrap(), &pool) }.unwrap();
        let before = regs.clone();
        let free = pool.available();
        for other in crate::amdgpu_rdna2::PROFILES {
            let sos = crate::amdgpu_psp_boot::tests::firmware_for(other);
            let smc = crate::amdgpu_smu_navi22::tests::firmware_for(other);
            let gfx = crate::amdgpu_gfx_navi22::tests::fixture_for(other);
            // A matching target reaches the still-unstarted session and gets Busy;
            // a sibling must be refused before that state machine or any allocation.
            let expected = if profile == other {
                Error::Busy
            } else {
                Error::Unsupported
            };
            if run(psp.setup_tmr_rdna2(&sos)) != Err(expected)
                || run(psp.load_smc_rdna2(&smc)) != Err(expected)
                || run(psp.load_gfx_rdna2(&gfx)) != Err(expected)
                || regs != before
                || pool.available() != free
                || psp.state() != State::Prepared
            {
                return TestResult::Fail(
                    "RDNA2 firmware crossed targets or mutated unstarted session",
                );
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/rdna2",
    rdna2_psp_rejects_cross_chip_sos_smc_and_graphics_before_submission
);

fn rdna2_psp_tmr_smc_graphics_lifecycle_follows_linux_order() -> TestResult {
    for profile in crate::amdgpu_rdna2::PROFILES {
        let (pool, mut s) = session();
        s.engine.lenient = Kind::Rdna2(profile).rdna2_profile().is_some();
        run(s.engine.start()).unwrap();
        let sos = crate::amdgpu_psp_boot::tests::firmware_for(profile);
        let smc = crate::amdgpu_smu_navi22::tests::firmware_for(profile);
        let gfx = crate::amdgpu_gfx_navi22::tests::fixture_for(profile);
        run(s.init_tmr(sos.image().unwrap().toc())).unwrap();
        if s.tmr_ready || s.tmr.is_none() {
            return TestResult::Fail("RDNA2 installed TMR before PMFW upload");
        }
        run(s.load_smc_centralized(smc.image().unwrap().payload())).unwrap();
        if !s.tmr_ready || s.smc_state != SmcState::Loaded {
            return TestResult::Fail("RDNA2 PMFW upload did not install TMR");
        }
        run(s.load_gfx(&gfx.images().unwrap())).unwrap();
        let cmds = &s.engine.io.submissions;
        if cmds.len() < 4
            || cmds[0][2] != 0x20
            || cmds[1][2] != 6
            || cmds[1][10] != 18
            || cmds[2][2] != 5
            || !cmds[3..].iter().any(|c| c[2] == 0x21)
            || s.gfx_state != GfxLoadState::Accepted
            || s.engine.io.violation
        {
            return TestResult::Fail("RDNA2 violated TOC/PMFW/TMR/autoload or coherency order");
        }
        // SAFETY: model engines have no real firmware consumers.
        unsafe { run(s.stop()) }.unwrap();
        drop(s);
        if pool.available() != 16 << 20 {
            return TestResult::Fail("RDNA2 verified shutdown retained pool memory");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/rdna2",
    rdna2_psp_tmr_smc_graphics_lifecycle_follows_linux_order
);
