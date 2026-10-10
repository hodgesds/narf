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
    let (pool, s) = session();
    drop(s);
    let before = regs.clone();
    // SAFETY: register reads are backed by regs; unpublished VRAM is bookkeeping-only.
    let mut psp = unsafe { Psp::new_navi22(&gpu, Cap::bootstrap(), &pool) }.unwrap();
    let mmio = &psp.session.engine.io;
    if mmio.mp0 != 0x40000
        || mmio.nbio != 0x3480
        || mmio.invalidate_reg != Some(0x2f44)
        || psp.session.fb_base != 0x8_0000_0000
        || psp.session.fb_offset != 0x1_0000_0000
        || regs != before
    {
        return TestResult::Fail("wrong PSP/NBIO/HDP/GMC bank or constructor performed writes");
    }
    if run(psp.setup_tmr(&[])) != Err(Error::Unsupported)
        || run(psp.load_dmub(&[1])) != Err(Error::Unsupported)
        || regs != before
    {
        return TestResult::Fail("Navi22 accepted a Phoenix firmware operation");
    }
    drop(psp);
    for case in 0..12 {
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
            _ => bad.ip_blocks.push(bad.ip_blocks[5]),
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
            1 => regs[0x2000 + 0x16fd] = 0x7ff,
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
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/psp-ring",
    psp_navi22_constructor_rejects_unmapped_vram
);
