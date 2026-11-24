use super::*;
use alloc::{vec, vec::Vec};
use core::{
    future::Future,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

struct Fake {
    regs: [u32; 0x92],
    memory: Vec<u32>,
    writes: Vec<(u32, u32)>,
    complete: bool,
    reject: u32,
    reject_command: Option<u32>,
    reject_type: Option<u32>,
    destroy: bool,
    dirty: bool,
    violation: bool,
    submissions: Vec<[u32; 256]>,
    payload: Vec<u8>,
    tmr_size: u32,
    stall_command: Option<u32>,
    stall_type: Option<u32>,
    /// Polls before a stalled wait times out (see `wait_poll_limit`).
    poll_limit: u32,
    fail_hdp: bool,
    gfx_samples: Vec<GfxBootStatus>,
    gfx_reads: usize,
    media_address: Option<u64>,
    tmr_address: u64,
    /// `(resp.status, resp.uresp.fw_reserve_info)` for FB_FW_RESERV_ADDR
    /// and FB_FW_RESERV_EXT_ADDR.
    fw_reserve: [(u32, [u32; 3]); 2],
}
impl Io for Fake {
    fn wait_poll_limit(&self) -> Option<u32> {
        // The model completes every wait synchronously in write(): the
        // response bit is set by the CTRL write, the fence word by the
        // WPTR write, and the gfx boot status is a scripted sample list
        // whose longest completion is the third read. A wait still
        // incomplete after sixteen polls is a designed non-completion
        // (a stalled command) whose outcome is the timeout — reached by
        // count instead of burning the wall-clock deadline under the
        // spin executor (#879). Interruption fixtures that must keep a
        // stalled command outstanding for longer raise `poll_limit`.
        Some(self.poll_limit)
    }
    fn read(&mut self, reg: u32) -> u32 {
        self.regs[reg as usize]
    }
    fn write(&mut self, reg: u32, value: u32) {
        self.writes.push((reg, value));
        self.regs[reg as usize] = value;
        // Literal Linux values: KM ring create 2 << 16, DESTROY_RINGS 3 << 16.
        if reg == CTRL && (value == 0x0002_0000 || value == 0x0003_0000 && self.destroy) {
            self.regs[CTRL as usize] = RESPONSE;
        }
        if reg == WPTR {
            if self.dirty {
                self.violation = true;
            }
            let offset = ((value + 1024 - 16) % 1024) as usize;
            let frame = &self.memory[offset..offset + 16];
            if frame[2] != 0 || frame[6..].iter().any(|v| *v != 0) {
                self.violation = true;
            }
            let seq = frame[5];
            self.submissions
                .push(self.memory[1024..1280].try_into().unwrap());
            let id = self.memory[1026];
            let kind = self.memory[1034];
            if id == 5 {
                self.tmr_address =
                    u64::from(self.memory[1031]) | (u64::from(self.memory[1032]) << 32);
            }
            let stalled = self.stall_command == Some(id)
                && (id != 6 || self.stall_type.is_none_or(|t| t == kind));
            if self.complete && !stalled {
                self.memory[(FENCE / 4) as usize] = seq;
                self.memory[(COMMAND / 4) as usize + 216] =
                    if self.reject_command.is_none_or(|c| c == id)
                        && self.reject_type.is_none_or(|t| id == 6 && t == kind)
                    {
                        self.reject
                    } else {
                        0
                    };
                self.memory[(COMMAND / 4) as usize + 220] = self.tmr_size;
                if matches!(id, 0x50 | 0x51) {
                    let (status, info) = self.fw_reserve[(id - 0x50) as usize];
                    self.memory[(COMMAND / 4) as usize + 216] = status;
                    let uresp = (COMMAND / 4) as usize + 232;
                    self.memory[uresp..uresp + 3].copy_from_slice(&info);
                }
                if id == 6 && matches!(kind, 13 | 51 | 58) {
                    let offset = match kind {
                        13 => 0x1000,
                        58 => 0x80000,
                        _ => 0x100000,
                    };
                    let address = self.media_address.unwrap_or(self.tmr_address + offset);
                    self.memory[(COMMAND / 4) as usize + 218] = address as u32;
                    self.memory[(COMMAND / 4) as usize + 219] = (address >> 32) as u32;
                }
            }
        }
    }
    fn read_mem(&mut self, offset: u64) -> u32 {
        self.memory[(offset / 4) as usize]
    }
    fn write_mem(&mut self, offset: u64, value: u32) {
        self.dirty = true;
        self.memory[(offset / 4) as usize] = value;
    }
    fn setup_hdp(&mut self) -> bool {
        !self.fail_hdp
    }
    fn write_payload(&mut self, _: MmioRegion, offset: u64, value: u32) {
        self.dirty = true;
        let offset = offset as usize;
        if self.payload.len() < offset + 4 {
            self.payload.resize(offset + 4, 0xff);
        }
        self.payload[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn flush(&mut self) {
        self.dirty = false;
    }
    fn invalidate(&mut self) {}
    fn gfx_boot_status(&mut self) -> Result<GfxBootStatus, Error> {
        let index = self.gfx_reads.min(self.gfx_samples.len() - 1);
        self.gfx_reads += 1;
        Ok(self.gfx_samples[index])
    }
}
fn fixture() -> (Pool, Engine<Fake>) {
    let map = MmioRegion {
        phys: narf_memory::PhysAddr::new(0),
        virt: 0,
        len: BUFFER_SIZE + 4096,
        kind: narf_bus::BarKind::Mmio32 { prefetchable: true },
    };
    // SAFETY: bookkeeping-only pool; Fake implements all memory accesses.
    let pool = unsafe { Pool::from_owned_range(map, 0x2_0000_0000) }.unwrap();
    let memory = pool.reserve(BUFFER_SIZE).unwrap();
    let mut io = Fake {
        regs: [0; 0x92],
        memory: vec![0; BUFFER_SIZE as usize / 4],
        writes: Vec::new(),
        complete: true,
        reject: 0,
        reject_command: None,
        reject_type: None,
        destroy: true,
        dirty: false,
        violation: false,
        submissions: Vec::new(),
        payload: Vec::new(),
        tmr_size: DEFAULT_TMR_SIZE as u32,
        stall_command: None,
        stall_type: None,
        poll_limit: 16,
        fail_hdp: false,
        gfx_samples: vec![GfxBootStatus {
            cp_stat: 0,
            rlc_bootload: 1 << 31,
        }],
        gfx_reads: 0,
        media_address: None,
        tmr_address: 0,
        fw_reserve: [(0x100, [0; 3]); 2],
    };
    io.regs[CTRL as usize] = RESPONSE;
    io.regs[SOS as usize] = 1;
    (
        pool,
        Engine {
            io,
            authority: Cap::bootstrap(),
            memory,
            state: State::Prepared,
            sequence: 0,
            lenient: false,
        },
    )
}
fn run<T>(future: impl Future<Output = T>) -> T {
    narf_scheduler::block_on_spin(future)
}
fn psp_ring_linux_wire_and_wrap() -> TestResult {
    let (pool, mut engine) = fixture();
    if run(engine.start()).is_err() {
        return TestResult::Fail("ring create");
    }
    let address = engine.memory.address();
    if !engine.io.writes.windows(4).any(|w| {
        w == [
            (RING_LO, address as u32),
            (RING_HI, (address >> 32) as u32),
            (RING_SIZE, 4096),
            (CTRL, 0x0002_0000),
        ]
    }) {
        return TestResult::Fail("Linux mailbox sequence");
    }
    for _ in 0..65 {
        let cmd = load_command(6, 0x123_4567_8000, 73, 51);
        if run(engine.submit(&cmd)).is_err() {
            return TestResult::Fail("ring submit/wrap");
        }
    }
    if engine.io.violation || engine.io.regs[WPTR as usize] != 16 {
        return TestResult::Fail("flush, reserved fields, or DWORD wrap");
    }
    let words = engine.io.submissions[0];
    if words[0..7] != [0, 0, 6, 0, 0, 0, 0]
        || words[7..11] != [0x45678000, 0x123, 73, 51]
        || words[11..].iter().any(|v| *v != 0)
    {
        return TestResult::Fail("1024-byte command ABI");
    }
    if run(engine.stop()).is_err() {
        return TestResult::Fail("ring destroy");
    }
    drop(engine);
    if pool.available() != BUFFER_SIZE + 4096 {
        return TestResult::Fail("stopped buffer retained");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/psp-ring", psp_ring_linux_wire_and_wrap);
fn psp_ring_rejection_and_stale_fence() -> TestResult {
    let (_, mut engine) = fixture();
    run(engine.start()).unwrap();
    engine.io.reject = 0xffff000a;
    if run(engine.submit(&command(7, &[]))) != Err(Error::Rejected(0xffff000a)) {
        return TestResult::Fail("PSP rejection ignored");
    }
    engine.io.complete = false;
    let cmd = command(7, &[]);
    {
        let mut future = core::pin::pin!(engine.submit(&cmd));
        if !matches!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Pending
        ) {
            return TestResult::Fail("stale fence accepted");
        }
    }
    if engine.state != State::Pending || run(engine.submit(&cmd)) != Err(Error::Busy) {
        return TestResult::Fail("cancelled command reused");
    }
    if run(engine.stop()).is_err() {
        return TestResult::Fail("cancel cleanup");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/psp-ring", psp_ring_rejection_and_stale_fence);
fn psp_ring_revocation_and_quarantine() -> TestResult {
    let (pool, mut engine) = fixture();
    run(engine.start()).unwrap();
    engine.authority.revoke();
    let before = engine.io.writes.len();
    if run(engine.submit(&command(7, &[]))) != Err(Error::Revoked)
        || engine.io.writes.len() != before
    {
        return TestResult::Fail("revoked submit touched hardware");
    }
    if run(engine.stop()).is_err() {
        return TestResult::Fail("revoked teardown failed");
    }
    drop(engine);
    if pool.available() != BUFFER_SIZE + 4096 {
        return TestResult::Fail("revoked teardown retained ring");
    }
    let (pool, mut engine) = fixture();
    run(engine.start()).unwrap();
    drop(engine);
    if pool.available() != 4096 {
        return TestResult::Fail("published ring recycled on drop");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/psp-ring", psp_ring_revocation_and_quarantine);
fn psp_ring_invalid_pointer_does_not_publish() -> TestResult {
    let (_, mut engine) = fixture();
    run(engine.start()).unwrap();
    for pointer in [1, 15, 1024, u32::MAX] {
        engine.io.regs[WPTR as usize] = pointer;
        let before = engine.io.writes.len();
        if run(engine.submit(&command(7, &[]))) != Err(Error::Invalid)
            || engine.io.writes.len() != before
        {
            return TestResult::Fail("invalid pointer published");
        }
    }
    run(engine.stop()).unwrap();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/psp-ring",
    psp_ring_invalid_pointer_does_not_publish
);
fn psp_tmr_gpu_alignment_and_padding() -> TestResult {
    let map = MmioRegion {
        phys: narf_memory::PhysAddr::new(0),
        virt: 0,
        len: 4 << 20,
        kind: narf_bus::BarKind::Mmio32 { prefetchable: true },
    };
    // SAFETY: bookkeeping only, no MMIO dereferences.
    let pool = unsafe { Pool::from_owned_range(map, 0x2_0000_1000) }.unwrap();
    let a = pool.reserve_aligned(1 << 20, 1 << 20).unwrap();
    if a.address() != 0x2_0010_0000 || pool.reserve(4096).unwrap().address() != 0x2_0000_1000 {
        return TestResult::Fail("GPU alignment or padding lost");
    }
    if pool.reserve_aligned(4096, 8191).is_ok() || pool.reserve_aligned(u64::MAX, 4096).is_ok() {
        return TestResult::Fail("invalid alignment/overflow");
    }
    drop(a);
    if pool.available() != 4 << 20 {
        return TestResult::Fail("alignment leaked padding");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/psp-ring", psp_tmr_gpu_alignment_and_padding);

/// psp_update_fw_reservation: the SOS gates per MP0, the two queries in
/// order, PSP_ERR_UNKNOWN_COMMAND as an empty answer, the top-of-VRAM
/// validity check, 1 MiB rounding, and a lost fence failing the call.
fn psp_fw_reservation_follows_psp_update_fw_reservation() -> TestResult {
    const VRAM: u64 = 16 << 30;
    let top = VRAM - (12 << 20);
    let info = |address: u64, size: u32| [(address >> 32) as u32, address as u32, size];
    for (revision, sos) in [(3, 0x3a0e13), (2, 0x3b0e0c), (4, u32::MAX), (0, u32::MAX)] {
        let (_, mut engine) = fixture();
        run(engine.start()).unwrap();
        engine.io.fw_reserve[0] = (0, info(top, 12 << 20));
        if run(engine.update_fw_reservation(revision, sos, VRAM)) != Ok(None)
            || !engine.io.submissions.is_empty()
        {
            return TestResult::Fail("reservation queried below the SOS gate or off 14.0.2/3");
        }
    }
    for (revision, sos) in [(3, 0x3a0e14), (2, 0x3b0e0d)] {
        let (_, mut engine) = fixture();
        run(engine.start()).unwrap();
        engine.io.fw_reserve = [
            (0, info(top, 12 << 20)),
            (0, info(0x1_2340_0000, 0x18_0001)),
        ];
        let got = run(engine.update_fw_reservation(revision, sos, VRAM));
        let ids: Vec<_> = engine.io.submissions.iter().map(|c| c[2]).collect();
        if got
            != Ok(Some(FwReservation {
                fw: top..VRAM,
                ext: 0x1_2340_0000..0x1_2360_0000,
            }))
            || ids != [0x50, 0x51]
            || engine
                .io
                .submissions
                .iter()
                .any(|c| c[7..].iter().any(|v| *v != 0))
        {
            return TestResult::Fail("FW_RESERV queries, decoding or 1 MiB rounding");
        }
    }
    let (_, mut engine) = fixture();
    run(engine.start()).unwrap();
    // An SOS without the commands answers PSP_ERR_UNKNOWN_COMMAND: (0, 0),
    // which is not a region ending at the top of VRAM.
    if run(engine.update_fw_reservation(3, 0x3a0e14, VRAM)) != Ok(None) {
        return TestResult::Fail("unknown command not treated as no reservation");
    }
    // Any other status is only warned about; the answer is used.
    engine.io.fw_reserve = [(0x7, info(top, 12 << 20)), (0x100, [0xff; 3])];
    if run(engine.update_fw_reservation(3, 0x3a0e14, VRAM))
        != Ok(Some(FwReservation {
            fw: top..VRAM,
            ext: 0..0,
        }))
    {
        return TestResult::Fail("nonzero status or empty extension");
    }
    // A region that does not end at the top of VRAM is not reserved.
    engine.io.fw_reserve = [(0, info(top - 4096, 12 << 20)), (0, [0; 3])];
    if run(engine.update_fw_reservation(3, 0x3a0e14, VRAM)) != Ok(None) {
        return TestResult::Fail("invalid fw region reserved");
    }
    engine.io.fw_reserve = [(0, info(top, 12 << 20)), (0, [0; 3])];
    engine.io.stall_command = Some(0x51);
    if run(engine.update_fw_reservation(3, 0x3a0e14, VRAM)) != Err(Error::Timeout) {
        return TestResult::Fail("lost reservation fence not fatal");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/psp-ring",
    psp_fw_reservation_follows_psp_update_fw_reservation
);

#[path = "amdgpu_psp_navi22_tests.rs"]
mod navi22;

#[path = "amdgpu_psp_navi31_tests.rs"]
mod navi31;

/// A Raphael discovery set: MP0 13.0.5, NBIO 7.7.1, DCN 3.1.5, HDP 5.2.1,
/// GC 10.3.6. MP0's segments 0 and 1 differ so the base index is observable.
fn raphael_gpu() -> AmdGpu {
    use crate::amdgpu_discovery as d;
    let mut gpu = crate::amdgpu_navi22_boot::tests::gpu();
    gpu.chip = crate::amdgpu::__test_chip_info_for_pci_id(
        crate::amdgpu::AMD_VENDOR,
        crate::amdgpu::RAPHAEL,
    )
    .unwrap();
    let template = gpu.ip_blocks[0];
    let ip = |id, v: (u8, u8, u8), bases: [u32; 3]| {
        let mut block = template;
        block.hw_id = id;
        (block.major, block.minor, block.revision) = v;
        block.num_bases = 3;
        block.base_addrs[..3].copy_from_slice(&bases);
        block
    };
    gpu.ip_blocks = vec![
        ip(d::HW_ID_MP0, (13, 0, 5), [0x1000, 0x2000, 0]),
        ip(d::HW_ID_NBIF, (7, 7, 1), [0, 0, 0x3000]),
        ip(d::HW_ID_DCN, (3, 1, 5), [0, 0, 0x4000]),
        ip(d::HW_ID_HDP, (5, 2, 1), [0x5000, 0, 0]),
        ip(d::HW_ID_GC, (10, 3, 6), [0x6000, 0x7000, 0]),
    ];
    gpu
}

/// PSP 13.0.5 (`psp_v13_0`): the MP0 C2PMSG registers on `_BASE_IDX` 0
/// (`mp_13_0_5_offset.h`), NBIO's HDP remap on index 2, and the DCN
/// framebuffer location at 0x475..0x477 of DCN 3.1.5. The Phoenix layout,
/// pinned to PSP 13.0.4 on index 1, refuses it, and the reverse.
fn psp_raphael_layout_uses_mp0_segment_zero_and_dcn315() -> TestResult {
    let gpu = raphael_gpu();
    let Ok(layout) = Layout::resolve(&gpu, Kind::Raphael) else {
        return TestResult::Fail("Raphael PSP layout");
    };
    if layout.mp0 != 0x1000 * 4
        || layout.nbio != 0x3000 * 4
        || (layout.fb_base, layout.fb_top, layout.fb_offset)
            != (
                (0x4000 + 0x475) * 4,
                (0x4000 + 0x476) * 4,
                (0x4000 + 0x477) * 4,
            )
        || layout.invalidate_reg.is_some()
        // CP_STAT (GC index 0) and RLC_RLCS_BOOTLOAD_STATUS (GC index 1).
        || layout.gfx_status_regs != Some(((0x6000 + 0xf40) * 4, (0x7000 + 0x4e8d) * 4))
    {
        return TestResult::Fail("Raphael PSP banks");
    }
    if Layout::resolve(&gpu, Kind::Phoenix).is_ok() {
        return TestResult::Fail("PSP 13.0.5 taken by the 13.0.4 layout");
    }
    let mut phoenix_mp0 = raphael_gpu();
    phoenix_mp0.ip_blocks[0].revision = 4;
    if Layout::resolve(&phoenix_mp0, Kind::Raphael).is_ok() {
        return TestResult::Fail("PSP 13.0.4 taken by the 13.0.5 layout");
    }
    let mut other_dcn = raphael_gpu();
    other_dcn.ip_blocks[2].revision = 4;
    if Layout::resolve(&other_dcn, Kind::Raphael).is_ok() {
        return TestResult::Fail("Raphael PSP beside a DCN 3.1.4");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/psp-ring",
    psp_raphael_layout_uses_mp0_segment_zero_and_dcn315
);

/// A Renoir discovery set: MP0 11.0.3, NBIO (ungated by the Psp12
/// arm, so the fixture version is arbitrary), DCN 2.1, HDP 5.2.1,
/// GC 9.3.0. MP0's segments 0 and 1 differ so the base index is
/// observable.
fn renoir_gpu() -> AmdGpu {
    use crate::amdgpu_discovery as d;
    let mut gpu = crate::amdgpu_navi22_boot::tests::gpu();
    gpu.chip = crate::amdgpu::__test_chip_info_for_pci_id(
        crate::amdgpu::AMD_VENDOR,
        crate::amdgpu::RENOIR,
    )
    .unwrap();
    let template = gpu.ip_blocks[0];
    let ip = |id, v: (u8, u8, u8), bases: [u32; 3]| {
        let mut block = template;
        block.hw_id = id;
        (block.major, block.minor, block.revision) = v;
        block.num_bases = 3;
        block.base_addrs[..3].copy_from_slice(&bases);
        block
    };
    gpu.ip_blocks = vec![
        ip(d::HW_ID_MP0, (11, 0, 3), [0x1000, 0x2000, 0]),
        ip(d::HW_ID_NBIF, (7, 2, 0), [0, 0, 0x3000]),
        ip(d::HW_ID_DCN, (2, 1, 0), [0, 0, 0x4000]),
        ip(d::HW_ID_HDP, (5, 2, 1), [0x5000, 0, 0]),
        ip(d::HW_ID_GC, (9, 3, 0), [0x6000, 0x7000, 0]),
    ];
    gpu
}
/// Cezanne differs from Renoir only in the MP0 revision (12.0.1)
/// and the PCI DID.
fn cezanne_gpu() -> AmdGpu {
    let mut gpu = renoir_gpu();
    gpu.chip = crate::amdgpu::__test_chip_info_for_pci_id(
        crate::amdgpu::AMD_VENDOR,
        crate::amdgpu::CEZANNE,
    )
    .unwrap();
    gpu.ip_blocks[0].revision = 1;
    gpu.ip_blocks[0].minor = 0;
    gpu.ip_blocks[0].major = 12;
    gpu
}

/// PSP 12.0 (`psp_v12_0`): the MP0 C2PMSG registers on `_BASE_IDX` 0
/// (`mp_12_0_0_offset.h`), NBIO ungated, and the DCN framebuffer
/// location at 0x493..0x495 of DCN 2.1. Both Renoir (MP0 11.0.3) and
/// Cezanne (MP0 12.0.1) resolve through the same arm; Phoenix MP0
/// (13.0.4) and DCN 3.1.4 are refused by it, and the reverse.
fn psp_psp12_layout_uses_mp0_segment_zero_and_dcn21() -> TestResult {
    let gpu = renoir_gpu();
    let Ok(layout) = Layout::resolve(&gpu, Kind::Psp12) else {
        return TestResult::Fail("Renoir PSP12 layout");
    };
    if layout.mp0 != 0x1000 * 4
        || layout.nbio != 0x3000 * 4
        || (layout.fb_base, layout.fb_top, layout.fb_offset)
            != (
                (0x4000 + 0x493) * 4,
                (0x4000 + 0x494) * 4,
                (0x4000 + 0x495) * 4,
            )
        || layout.invalidate_reg.is_some()
        || layout.gfx_status_regs.is_some()
    {
        return TestResult::Fail("Renoir PSP12 banks");
    }
    if Layout::resolve(&cezanne_gpu(), Kind::Psp12).is_err() {
        return TestResult::Fail("Cezanne PSP12 layout");
    }
    if Layout::resolve(&gpu, Kind::Phoenix).is_ok() {
        return TestResult::Fail("PSP 12.0 taken by the 13.0.4 layout");
    }
    let mut phoenix_mp0 = renoir_gpu();
    phoenix_mp0.ip_blocks[0].major = 13;
    phoenix_mp0.ip_blocks[0].minor = 0;
    phoenix_mp0.ip_blocks[0].revision = 4;
    if Layout::resolve(&phoenix_mp0, Kind::Psp12).is_ok() {
        return TestResult::Fail("PSP 13.0.4 taken by the 12.0 layout");
    }
    let mut dcn314 = renoir_gpu();
    dcn314.ip_blocks[2].major = 3;
    dcn314.ip_blocks[2].minor = 1;
    dcn314.ip_blocks[2].revision = 4;
    if Layout::resolve(&dcn314, Kind::Psp12).is_ok() {
        return TestResult::Fail("PSP 12.0 beside a DCN 3.1.4");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/psp-ring",
    psp_psp12_layout_uses_mp0_segment_zero_and_dcn21
);

/// A synthetic PSP v1 ASD container: 44-byte header + payload.
/// `version` is the header version pair; `asd_payload` must not pin it.
fn asd_container(payload_len: usize, version: (u16, u16)) -> Vec<u8> {
    let mut bytes = vec![0u8; 44 + payload_len];
    bytes[0..4].copy_from_slice(&(bytes.len() as u32).to_le_bytes());
    bytes[4..8].copy_from_slice(&44u32.to_le_bytes());
    bytes[8..10].copy_from_slice(&version.0.to_le_bytes());
    bytes[10..12].copy_from_slice(&version.1.to_le_bytes());
    bytes[16..20].copy_from_slice(&0x0100_0001u32.to_le_bytes());
    bytes[20..24].copy_from_slice(&(payload_len as u32).to_le_bytes());
    bytes[24..28].copy_from_slice(&44u32.to_le_bytes());
    bytes[44..].fill(0xa5);
    bytes
}

fn psp_asd_payload_parses_without_version_pin() -> TestResult {
    // A v1 container with a (2, 0) header: toc_payload refuses it
    // (it pins (1, 0)); asd_payload must not — Linux's
    // parse_psp_v1_bin_descriptor performs no validation at all.
    let bytes = asd_container(256, (2, 0));
    if toc_payload(&bytes).is_ok() {
        return TestResult::Fail("TOC pin did not refuse a (2, 0) header");
    }
    let Ok(payload) = asd_payload(&bytes) else {
        return TestResult::Fail("ASD payload rejected");
    };
    if payload.len() != 256 || payload != &bytes[44..] {
        return TestResult::Fail("ASD payload slice");
    }
    // Truncated and empty-ucode containers are refused.
    if asd_payload(&bytes[..bytes.len() - 1]).is_ok()
        || asd_payload(&asd_container(0, (1, 0))).is_ok()
    {
        return TestResult::Fail("invalid ASD container accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/psp-ring",
    psp_asd_payload_parses_without_version_pin
);

/// A `Session` on the small ring engine, with a pool big enough for
/// the 4 MiB TOC-less TMR plus payload staging. The small pool stays
/// alive beside the session: it owns the ring memory.
fn session_fixture() -> (Pool, Session<Fake>) {
    let (small_pool, engine) = fixture();
    let map = MmioRegion {
        phys: narf_memory::PhysAddr::new(0),
        virt: 0,
        len: 8 << 20,
        kind: narf_bus::BarKind::Mmio32 { prefetchable: true },
    };
    // SAFETY: bookkeeping-only pool; Fake implements all memory accesses.
    let pool = unsafe { Pool::from_owned_range(map, 0x2_0000_0000) }.unwrap();
    let session = Session {
        engine,
        pool: pool.clone(),
        payload: None,
        tmr: None,
        tmr_ready: false,
        smc_state: SmcState::Absent,
        smc_resident: true,
        gfx_state: GfxLoadState::Absent,
        gfx_status: None,
        media_firmware: MediaFirmware::default(),
        dmub_image: None,
        gfx12_vcn_version: None,
        fb_base: 0x2_0000_0000,
        fb_offset: 0x8000_0000,
        secure_dmub: None,
    };
    (small_pool, session)
}

/// PSP 12.0 TMR + ASD load: no TOC, the default 4 MiB TMR via
/// SETUP_TMR (cmd 5), then LOAD_ASD (cmd 4) with the staged ucode
/// payload address/length and zero shared address/length.
fn psp_psp12_tmr_and_asd_load() -> TestResult {
    let (_small_pool, mut session) = session_fixture();
    if run(session.engine.start()).is_err() {
        return TestResult::Fail("ring create");
    }
    let asd = asd_container(256, (1, 0));
    if run(session.load_asd(&asd)) != Err(Error::Busy) {
        return TestResult::Fail("ASD load without TMR accepted");
    }
    if run(session.setup_tmr_payload(None)).is_err()
        || !session.tmr_ready
        || session.tmr.as_ref().map(|tmr| tmr.size()) != Some(DEFAULT_TMR_SIZE)
    {
        return TestResult::Fail("TOC-less TMR setup");
    }
    let tmr_frame = session.engine.io.submissions[0];
    if tmr_frame[2] != 5
        || tmr_frame[7..13] != [0, 2, 0x400000, 2, 0x8000_0000, 0]
        || session.engine.io.tmr_address != 0x2_0000_0000
    {
        return TestResult::Fail("SETUP_TMR command ABI");
    }
    if run(session.load_asd(&asd_container(0, (1, 0)))) != Err(Error::Invalid) {
        return TestResult::Fail("empty ASD container accepted");
    }
    if run(session.load_asd(&asd)).is_err() {
        return TestResult::Fail("ASD load");
    }
    let frame = session.engine.io.submissions[1];
    if frame[0..2] != [0, 0]
        || frame[2] != 4
        || frame[3..7] != [0, 0, 0, 0]
        || frame[7..13] != [0x0040_0000, 2, 256, 0, 0, 0]
        || frame[13..].iter().any(|v| *v != 0)
    {
        return TestResult::Fail("LOAD_ASD command ABI");
    }
    if session.engine.io.payload != vec![0xa5; 256] {
        return TestResult::Fail("ASD payload not staged");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/psp-ring", psp_psp12_tmr_and_asd_load);
