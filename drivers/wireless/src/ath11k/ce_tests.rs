//! Copy Engine tests.
//!
//! [`FakeChip`] is a WCN6855 CE block model behind [`ChipIo`]: it keeps
//! a register file, records every access, mirrors writes to the shadow
//! registers (`0x8fc + 4n`) into the ring HP/TP register the QMI shadow
//! list names (as the firmware does), and — from the ring base / size /
//! pointer-address registers the host programmed, nothing else —
//! consumes source descriptors and produces destination + status
//! descriptors in the host's real DMA32 ring memory through the kernel
//! direct map. Expected register values are hand-derived from Linux
//! `hal.c` / `ce.c` / `pcic.c` for WCN6855.

#![cfg(target_arch = "x86_64")]

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};
use core::future::Future;
use core::pin::pin;
use core::sync::atomic::{AtomicU64, Ordering};
use core::task::{Context, Poll, Waker};

use narf_kernel_test::{kernel_test_in, TestResult};

use super::ce::*;
use super::hal::*;
use super::hal_tests::{wcn6855, Op, WCN6855_SHADOW_REG_V2};
use super::hw::*;
use super::power::ChipIo;

macro_rules! check {
    ($cond:expr, $msg:literal) => {
        if !($cond) {
            return TestResult::Fail($msg);
        }
    };
}

static NOW: AtomicU64 = AtomicU64::new(0);

fn fake_clock() -> u64 {
    NOW.load(Ordering::Relaxed)
}

fn run<F: Future>(f: F) -> F::Output {
    let mut f = pin!(f);
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..100_000 {
        if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
    }
    panic!("ce test future did not complete");
}

// ── physical memory (the device side of DMA) ──────────────────────

fn phys_rd32(pa: u64) -> u32 {
    // SAFETY: `pa` lies inside a live DMA32 coherent buffer the CE under
    // test allocated and owns; the kernel direct map covers it and it is
    // 4-byte aligned.
    unsafe { core::ptr::read_volatile(narf_memory::PhysAddr::new(pa).kernel_ptr::<u32>()) }
}

fn phys_wr32(pa: u64, v: u32) {
    // SAFETY: as `phys_rd32`; the host only reads the words the device
    // model writes.
    unsafe { core::ptr::write_volatile(narf_memory::PhysAddr::new(pa).kernel_mut_ptr::<u32>(), v) }
}

fn phys_read(pa: u64, out: &mut [u8]) {
    // SAFETY: `pa..pa + out.len()` is inside one live DMA buffer slot
    // (a ring slot of `src_sz_max` bytes, checked by the caller).
    unsafe {
        core::ptr::copy_nonoverlapping(
            narf_memory::PhysAddr::new(pa).kernel_ptr::<u8>(),
            out.as_mut_ptr(),
            out.len(),
        )
    }
}

fn phys_write(pa: u64, src: &[u8]) {
    // SAFETY: as `phys_read`; the slot is a posted RX buffer the host
    // does not touch until the status descriptor reports it.
    unsafe {
        core::ptr::copy_nonoverlapping(
            src.as_ptr(),
            narf_memory::PhysAddr::new(pa).kernel_mut_ptr::<u8>(),
            src.len(),
        )
    }
}

// ── the fake chip ─────────────────────────────────────────────────

const CE_SRC0: u32 = 0x01b8_0000;
const CE_DST0: u32 = 0x01b8_1000;
const STRIDE: u32 = 0x2000;
const SHADOW_BASE: u32 = 0x8fc;

#[derive(Copy, Clone, Default)]
struct DevCe {
    src_tp: u32,
    dst_tp: u32,
    status_hp: u32,
}

struct FakeChip {
    regs: RefCell<BTreeMap<u32, u32>>,
    ops: RefCell<Vec<Op>>,
    /// Shadow register n mirrors into `shadow[n]` (the QMI list).
    shadow: Vec<u32>,
    dev: RefCell<[DevCe; CE_COUNT_MAX]>,
    pending: Cell<u32>,
}

impl FakeChip {
    fn new(shadow: &[u32]) -> Self {
        let chip = FakeChip {
            regs: RefCell::new(BTreeMap::new()),
            ops: RefCell::new(Vec::new()),
            shadow: shadow.to_vec(),
            dev: RefCell::new([DevCe::default(); CE_COUNT_MAX]),
            pending: Cell::new(0),
        };
        // DEST_CTRL reset value with bits outside MAX_LEN set, so the
        // read-modify-write is observable.
        for ce in 0..CE_COUNT_MAX as u32 {
            chip.regs
                .borrow_mut()
                .insert(CE_DST0 + ce * STRIDE + 0xb0, 0xabcd_0000);
        }
        chip
    }
    fn reg(&self, off: u32) -> u32 {
        *self.regs.borrow().get(&off).unwrap_or(&0)
    }
    fn ops(&self) -> Vec<Op> {
        self.ops.borrow().clone()
    }
    fn clear(&self) {
        self.ops.borrow_mut().clear();
    }
    fn take_pending(&self) -> u32 {
        self.pending.replace(0)
    }
    /// (base, size in words) from BASE_LSB / BASE_MSB at `r0`.
    fn ring(&self, r0: u32) -> (u64, u32) {
        let msb = self.reg(r0 + 4);
        (
            self.reg(r0) as u64 | ((msb & 0xff) as u64) << 32,
            (msb >> 8) & 0xf_ffff,
        )
    }
    fn addr(&self, lsb: u32) -> u64 {
        self.reg(lsb) as u64 | (self.reg(lsb + 4) as u64) << 32
    }

    /// The target drains CE `ce`'s source ring up to the host HP:
    /// `(meta, payload)` per descriptor; TP written back through the
    /// programmed TP address.
    fn target_consume(&self, ce: u32) -> Vec<(u32, Vec<u8>)> {
        let r0 = CE_SRC0 + ce * STRIDE;
        let (base, size) = self.ring(r0);
        let hp = self.reg(r0 + 0x400);
        let tp_addr = self.addr(r0 + 0x1c);
        let mut out = Vec::new();
        let mut dev = self.dev.borrow_mut();
        let d = &mut dev[ce as usize];
        while d.src_tp != hp && size != 0 {
            let desc = base + d.src_tp as u64 * 4;
            let w0 = phys_rd32(desc);
            let w1 = phys_rd32(desc + 4);
            let w2 = phys_rd32(desc + 8);
            let addr = w0 as u64 | ((w1 & 0xff) as u64) << 32;
            let mut data = vec![0u8; (w1 >> 16) as usize];
            phys_read(addr, &mut data);
            out.push((w2 & 0xffff, data));
            d.src_tp = (d.src_tp + 4) % size;
            phys_wr32(tp_addr, d.src_tp);
        }
        if !out.is_empty() && self.reg(r0 + 0x4c) & (1 << 8) != 0 {
            self.pending.set(self.pending.get() | 1 << ce);
        }
        out
    }

    /// The target copies `data` into the next posted buffer of CE `ce`
    /// and reports `len` (default `data.len()`) in a status descriptor.
    /// `false` when no buffer is posted or the status ring is full.
    fn target_deliver(&self, ce: u32, data: &[u8], len: Option<u32>) -> bool {
        let d0 = CE_DST0 + ce * STRIDE;
        let (dbase, dsize) = self.ring(d0);
        let host_hp = self.reg(d0 + 0x400);
        let max = self.reg(d0 + 0xb0) & 0xffff;
        let s0 = CE_DST0 + 0x58 + ce * STRIDE;
        let (sbase, ssize) = self.ring(s0);
        let host_tp = self.reg(CE_DST0 + 0x40c + ce * STRIDE);
        let mut dev = self.dev.borrow_mut();
        let d = &mut dev[ce as usize];
        if dsize == 0 || ssize == 0 || d.dst_tp == host_hp || data.len() as u32 > max {
            return false;
        }
        let next = (d.status_hp + 4) % ssize;
        if next == host_tp {
            return false;
        }
        let desc = dbase + d.dst_tp as u64 * 4;
        let w0 = phys_rd32(desc);
        let w1 = phys_rd32(desc + 4);
        phys_write(w0 as u64 | ((w1 & 0xff) as u64) << 32, data);
        d.dst_tp = (d.dst_tp + 2) % dsize;
        phys_wr32(self.addr(d0 + 0x1c), d.dst_tp);

        let st = sbase + d.status_hp as u64 * 4;
        let len = len.unwrap_or(data.len() as u32);
        phys_wr32(st, len << 16);
        phys_wr32(st + 4, 0);
        phys_wr32(st + 8, 0);
        phys_wr32(st + 12, (1 << 28) | ((80 + ce) << 20));
        d.status_hp = next;
        phys_wr32(self.addr(s0 + 0x14), d.status_hp);
        self.pending.set(self.pending.get() | 1 << ce);
        true
    }
}

impl ChipIo for FakeChip {
    fn read32(&self, offset: u32) -> u32 {
        self.ops.borrow_mut().push(Op::R(offset));
        self.reg(offset)
    }
    fn write32(&self, offset: u32, value: u32) {
        self.ops.borrow_mut().push(Op::W(offset, value));
        let mut regs = self.regs.borrow_mut();
        regs.insert(offset, value);
        if offset >= SHADOW_BASE && offset < SHADOW_BASE + 4 * HAL_SHADOW_NUM_REGS as u32 {
            if let Some(&target) = self.shadow.get(((offset - SHADOW_BASE) / 4) as usize) {
                regs.insert(target, value);
            }
        }
    }
    fn delay_ms(&self, _ms: u32) {}
    fn restore_window(&self) {}
}

/// Interrupt source for the async paths: each wait advances the clock
/// and, once, delivers a scripted payload at a given time.
struct FakeIrq<'a> {
    chip: &'a FakeChip,
    script: RefCell<Option<(u64, u32, Vec<u8>)>>,
}

impl CeIrq for FakeIrq<'_> {
    fn take_pending(&self) -> u32 {
        self.chip.take_pending()
    }
    fn wait(&self, ms: u32) -> impl Future<Output = ()> + Send {
        let now = NOW.fetch_add(ms as u64, Ordering::Relaxed) + ms as u64;
        let due = matches!(&*self.script.borrow(), Some((at, _, _)) if now >= *at);
        if due {
            if let Some((_, ce, data)) = self.script.borrow_mut().take() {
                self.chip.target_deliver(ce, &data, None);
            }
        }
        core::future::ready(())
    }
}

const EP: u32 = 0x40;

fn msi(config: &'static MsiConfig) -> CeMsi {
    CeMsi {
        addr: 0xfee0_1000,
        ep_base_data: EP,
        config,
    }
}

/// `Ce::alloc` + `init_pipes` + `start` on a fresh chip.
fn bring_up() -> Result<(Ce, FakeChip), &'static str> {
    NOW.store(0, Ordering::Relaxed);
    let mut ce = Ce::alloc(&wcn6855(), msi(&MSI_CONFIG_QCA6390), fake_clock)
        .map_err(|_| "Ce::alloc failed")?;
    let chip = FakeChip::new(ce.shadow_reg_v2());
    ce.init_pipes(&chip).map_err(|_| "init_pipes failed")?;
    ce.start(&chip);
    set_ce_irqs_enabled(false);
    Ok((ce, chip))
}

// ── golden register programming ───────────────────────────────────

/// `ath11k_hal_srng_src_hw_init` with wcn6855 `HAL_TCL1_RING_*`
/// offsets: MSI1 0x48/0x4c/0x50, BASE_MSB 0x4, ID 0x8, MISC 0x10,
/// TP_ADDR 0x1c/0x20, CONSR_INT_SETUP_IX0/IX1 0x30/0x34; R2 TP +4.
#[allow(clippy::too_many_arguments)]
fn src_hw_init_golden(
    r0: u32,
    r2: u32,
    base: u64,
    size_words: u32,
    entry_words: u32,
    msi_data: Option<u32>,
    ix0: u32,
    ix1: u32,
    tp_addr: u64,
) -> Vec<Op> {
    let mut v = Vec::new();
    if let Some(data) = msi_data {
        v.push(Op::W(r0 + 0x48, 0xfee0_1000));
        v.push(Op::W(r0 + 0x4c, 1 << 8));
        v.push(Op::W(r0 + 0x50, data));
    }
    v.extend([
        Op::W(r0, base as u32),
        Op::W(r0 + 0x4, (base >> 32) as u32 | (size_words << 8)),
        Op::W(r0 + 0x8, entry_words),
        Op::W(r0 + 0x30, ix0),
        Op::W(r0 + 0x34, ix1),
        Op::W(r0 + 0x1c, tp_addr as u32),
        Op::W(r0 + 0x20, (tp_addr >> 32) as u32),
        Op::W(r2, 0),
        Op::W(r2 + 4, 0),
        Op::W(r0 + 0x10, 0x42),
    ]);
    v
}

/// `ath11k_hal_srng_dst_hw_init` with wcn6855 `HAL_REO1_RING_*`
/// offsets: MSI1 0x48/0x4c/0x50, BASE_MSB 0x4, ID 0x8, MISC 0x10,
/// HP_ADDR 0x14/0x18, PRODUCER_INT_SETUP 0x24; R2 TP +4.
#[allow(clippy::too_many_arguments)]
fn dst_hw_init_golden(
    r0: u32,
    r2: u32,
    base: u64,
    size_words: u32,
    ring_id: u32,
    entry_words: u32,
    msi_data: Option<u32>,
    int_setup: u32,
    hp_addr: u64,
) -> Vec<Op> {
    let mut v = Vec::new();
    if let Some(data) = msi_data {
        v.push(Op::W(r0 + 0x48, 0xfee0_1000));
        v.push(Op::W(r0 + 0x4c, 1 << 8));
        v.push(Op::W(r0 + 0x50, data));
    }
    v.extend([
        Op::W(r0, base as u32),
        Op::W(r0 + 0x4, (base >> 32) as u32 | (size_words << 8)),
        Op::W(r0 + 0x8, (ring_id << 8) | entry_words),
        Op::W(r0 + 0x24, int_setup),
        Op::W(r0 + 0x14, hp_addr as u32),
        Op::W(r0 + 0x18, (hp_addr >> 32) as u32),
        Op::W(r2, 0),
        Op::W(r2 + 4, 0),
        Op::W(r0 + 0x10, 0x40),
    ]);
    v
}

fn smoke_ath11k_ce_init_pipes_golden_wcn6855() -> TestResult {
    NOW.store(0, Ordering::Relaxed);
    let mut ce = match Ce::alloc(&wcn6855(), msi(&MSI_CONFIG_QCA6390), fake_clock) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail("Ce::alloc failed"),
    };
    check!(ce.ce_count() == 9, "9 CEs on WCN6855");
    check!(
        ce.shadow_reg_v2() == WCN6855_SHADOW_REG_V2,
        "CE shadow list"
    );
    let chip = FakeChip::new(ce.shadow_reg_v2());
    if ce.init_pipes(&chip).is_err() {
        return TestResult::Fail("init_pipes failed");
    }
    let rdp = ce.hal.rdp.paddr();
    let base = |id: u32| ce.hal.srng(id).map_or(0, |s| s.ring_base_paddr);

    // CE0 src (ring 32), literally: 16 entries x 4 words, MSI data =
    // ep + CE base vector 3 + msi_data_idx 0; batch 1 entry = 4 words.
    let b = base(32);
    let ce0 = [
        Op::W(0x01b8_0048, 0xfee0_1000),
        Op::W(0x01b8_004c, 0x100),
        Op::W(0x01b8_0050, EP + 3),
        Op::W(0x01b8_0000, b as u32),
        Op::W(0x01b8_0004, (64 << 8) | (b >> 32) as u32),
        Op::W(0x01b8_0008, 4),
        Op::W(0x01b8_0030, 4),
        Op::W(0x01b8_0034, 0),
        Op::W(0x01b8_001c, (rdp + 32 * 4) as u32),
        Op::W(0x01b8_0020, ((rdp + 32 * 4) >> 32) as u32),
        Op::W(0x01b8_0400, 0),
        Op::W(0x01b8_0404, 0),
        Op::W(0x01b8_0010, 0x42),
    ];
    let ops = chip.ops();
    check!(
        ops.len() > ce0.len() && ops[..ce0.len()] == ce0,
        "CE0 src programming"
    );

    // CE1 dst (ring 57, a SRC-type ring): 512 x 2 words; timer 1024 µs,
    // low threshold (512 - 3) * 2 words; then DEST_CTRL MAX_LEN = 2048.
    let b = base(57);
    let mut ce1 = vec![
        Op::W(0x01b8_3048, 0xfee0_1000),
        Op::W(0x01b8_304c, 0x100),
        Op::W(0x01b8_3050, EP + 4),
        Op::W(0x01b8_3000, b as u32),
        Op::W(0x01b8_3004, (1024 << 8) | (b >> 32) as u32),
        Op::W(0x01b8_3008, 2),
        Op::W(0x01b8_3030, 1024 << 16),
        Op::W(0x01b8_3034, 1018),
        Op::W(0x01b8_301c, (rdp + 57 * 4) as u32),
        Op::W(0x01b8_3020, ((rdp + 57 * 4) >> 32) as u32),
        Op::W(0x01b8_3400, 0),
        Op::W(0x01b8_3404, 0),
        Op::W(0x01b8_3010, 0x42),
        Op::R(0x01b8_30b0),
        Op::W(0x01b8_30b0, 0xabcd_0000 | 2048),
    ];
    // CE1 dst status (ring 81, DST): R0 0x1b81058 + 0x2000, R2
    // 0x1b81408 + 0x2000; ring id 81 | entry 4; timer 0x1000 µs >> 3,
    // batch 1 entry = 4 words.
    let b = base(81);
    ce1.extend([
        Op::W(0x01b8_30a0, 0xfee0_1000),
        Op::W(0x01b8_30a4, 0x100),
        Op::W(0x01b8_30a8, EP + 4),
        Op::W(0x01b8_3058, b as u32),
        Op::W(0x01b8_305c, (2048 << 8) | (b >> 32) as u32),
        Op::W(0x01b8_3060, (81 << 8) | 4),
        Op::W(0x01b8_307c, (0x200 << 16) | 4),
        Op::W(0x01b8_306c, (rdp + 81 * 4) as u32),
        Op::W(0x01b8_3070, ((rdp + 81 * 4) >> 32) as u32),
        Op::W(0x01b8_3408, 0),
        Op::W(0x01b8_340c, 0),
        Op::W(0x01b8_3068, 0x40),
    ]);
    let n0 = ce0.len();
    check!(
        ops[n0..n0 + ce1.len()] == ce1[..],
        "CE1 dst + status programming"
    );

    // Every ring, in ath11k_ce_init_pipes order. MSI data index skips
    // the interrupt-less CE4 / CE6: CE5 → 4, CE7 → 5.
    let mut want: Vec<Op> = Vec::new();
    let src = |want: &mut Vec<Op>, ce: u32, n: u32, msi: Option<u32>| {
        let id = 32 + ce;
        let r0 = CE_SRC0 + ce * STRIDE;
        let ix0 = if msi.is_some() { 4 } else { 0 };
        want.extend(src_hw_init_golden(
            r0,
            r0 + 0x400,
            base(id),
            n * 4,
            4,
            msi,
            ix0,
            0,
            rdp + id as u64 * 4,
        ));
    };
    let dst = |want: &mut Vec<Op>, ce: u32, n: u32, msi: u32| {
        let id = 56 + ce;
        let r0 = CE_DST0 + ce * STRIDE;
        want.extend(src_hw_init_golden(
            r0,
            r0 + 0x400,
            base(id),
            n * 2,
            2,
            Some(msi),
            1024 << 16,
            (n - 3) * 2,
            rdp + id as u64 * 4,
        ));
        want.push(Op::R(r0 + 0xb0));
        want.push(Op::W(r0 + 0xb0, 0xabcd_0000 | 2048));
        let id = 80 + ce;
        want.extend(dst_hw_init_golden(
            CE_DST0 + 0x58 + ce * STRIDE,
            CE_DST0 + 0x408 + ce * STRIDE,
            base(id),
            n * 4,
            id,
            4,
            Some(msi),
            (0x200 << 16) | 4,
            rdp + id as u64 * 4,
        ));
    };
    src(&mut want, 0, 16, Some(EP + 3));
    dst(&mut want, 1, 512, EP + 4);
    dst(&mut want, 2, 512, EP + 5);
    src(&mut want, 3, 32, Some(EP + 6));
    src(&mut want, 4, 2048, None);
    dst(&mut want, 5, 512, EP + 7);
    src(&mut want, 7, 32, Some(EP + 8));
    check!(
        ops == want,
        "full WCN6855 CE ring programming differs from Linux"
    );

    // Each ring's SW pointer is its shadow register.
    for (id, slot) in [
        (32, 20),
        (57, 21),
        (81, 22),
        (58, 23),
        (82, 24),
        (35, 25),
        (36, 26),
    ] {
        if ce.hal.srng(id).map(|s| s.sw_ptr) != Some(SwPtr::Reg(0x8fc + 4 * slot)) {
            return TestResult::Fail("CE ring not on its shadow register");
        }
    }
    // CE4 got the shadow HP refresh timer (ATH11K_SHADOW_CTRL_TIMER_INTERVAL).
    let t = ce.pipe(4).unwrap().hp_timer();
    check!(
        t.init && t.ring_id == 36 && t.interval_ms == 10,
        "CE4 hp timer"
    );
    check!(
        !ce.pipe(3).unwrap().hp_timer().init,
        "only CE4 has the timer"
    );
    // Second init is refused, not silently re-programmed.
    chip.clear();
    check!(ce.init_pipes(&chip).is_err(), "init_pipes twice must fail");
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_ce_init_pipes_golden_wcn6855
);

fn smoke_ath11k_ce_start_posts_rx_buffers() -> TestResult {
    let (ce, chip) = match bring_up() {
        Ok(v) => v,
        Err(e) => return TestResult::Fail(e),
    };
    for (pipe, shadow) in [(1u32, 0x950u32), (2, 0x958), (5, 0x968)] {
        let p = ce.pipe(pipe).unwrap();
        // ath11k_ce_init_pipes: rx_buf_needed = nentries - 2.
        check!(
            p.dest_indices() == Some((512, 0, 510)),
            "510 buffers posted"
        );
        check!(p.rx_buf_needed == 0, "rx_buf_needed drained");
        check!(
            chip.reg(shadow) == 1020,
            "dest HP (510 * 2 words) via its shadow register"
        );
        let id = 56 + pipe;
        for k in [0u32, 1, 509] {
            let pa = p.rx_slot_paddr(k).unwrap();
            if ce.hal.desc_rd(id, k * 2, 0) != pa as u32
                || ce.hal.desc_rd(id, k * 2, 1) != (pa >> 32) as u32
            {
                return TestResult::Fail("dest descriptor does not point at its RX slot");
            }
        }
        check!(
            ce.hal.desc_rd(id, 510 * 2, 0) == 0,
            "slot 510 left unposted"
        );
    }
    check!(
        chip.reg(0x01b8_3400) == 1020,
        "the shadow write reached the CE1 dst HP register"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_ce_start_posts_rx_buffers
);

// ── send / receive ────────────────────────────────────────────────

fn smoke_ath11k_ce_send_recv_roundtrip() -> TestResult {
    let (mut ce, chip) = match bring_up() {
        Ok(v) => v,
        Err(e) => return TestResult::Fail(e),
    };
    // HTC control on CE0.
    chip.clear();
    check!(ce.send(&chip, 0, b"hello", 0x1234).is_ok(), "send on CE0");
    let tx0 = ce.hal.desc_rd(32, 0, 0) as u64 | (ce.hal.desc_rd(32, 0, 1) as u64 & 0xff) << 32;
    check!(
        ce.hal.desc_rd(32, 0, 1) == (5 << 16) | (tx0 >> 32) as u32
            && ce.hal.desc_rd(32, 0, 2) == 0x1234,
        "src descriptor: len 5, meta = transfer id"
    );
    check!(
        chip.ops() == [Op::W(0x94c, 4)],
        "one HP publish through shadow register 20"
    );
    let got = chip.target_consume(0);
    check!(
        got == [(0x1234, b"hello".to_vec())],
        "target received the payload"
    );
    let pend = chip.take_pending();
    check!(pend == 1, "CE0 interrupt");
    ce.service(&chip, pend);
    let p = ce.pipe(0).unwrap();
    check!(
        p.stats.tx_completed == 1 && p.src_indices() == Some((16, 1, 1)),
        "CE0 completion"
    );
    check!(ce.take_tx_done(0).is_none(), "credit flow: no send_cb");

    // WMI on CE3, then the reply on CE2.
    check!(
        ce.send(&chip, 3, &[0xa5; 2048], 7).is_ok(),
        "max-size send on CE3"
    );
    let got = chip.target_consume(3);
    check!(
        got.len() == 1 && got[0].0 == 7 && got[0].1 == [0xa5; 2048],
        "2048-byte payload"
    );
    let reply: Vec<u8> = (0..300u32).map(|i| i as u8).collect();
    check!(
        chip.target_deliver(2, &reply, None),
        "target delivers on CE2"
    );
    chip.clear();
    let pend = chip.take_pending();
    check!(ce.service(&chip, pend) == 2, "CE3 completion + CE2 receive");
    check!(
        ce.take_rx(2).as_deref() == Some(&reply[..]),
        "payload received on CE2"
    );
    check!(ce.take_rx(2).is_none(), "exactly one");
    let p = ce.pipe(2).unwrap();
    check!(
        p.dest_indices() == Some((512, 1, 511)),
        "buffer re-posted (write_index 511)"
    );
    check!(
        p.rx_buf_needed == 0 && p.stats.rx_completed == 1,
        "rx accounting"
    );
    // ath11k_ce_completed_recv_next does access_begin/end per call, so
    // CE2's status TP (shadow 24) is published by the hit and again by
    // the empty call that ends the loop; then the re-posted dest HP
    // (shadow 23). The poll of the idle CE1 / CE5 status rings
    // publishes their unchanged TP (shadow 22 / 28).
    check!(
        chip.ops()
            == [
                Op::W(0x95c, 4),
                Op::W(0x95c, 4),
                Op::W(0x958, 1022),
                Op::W(0x954, 0),
                Op::W(0x96c, 0),
            ],
        "status TP, then dest HP, published through their shadow registers"
    );
    check!(
        ce.stats.irqs[2] == 1 && ce.stats.irqs[3] == 1,
        "irq counters"
    );
    check!(
        ce.stats.polled_without_irq == 0,
        "no completion found by polling"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_ce_send_recv_roundtrip
);

fn smoke_ath11k_ce_ring_wraparound() -> TestResult {
    let (mut ce, chip) = match bring_up() {
        Ok(v) => v,
        Err(e) => return TestResult::Fail(e),
    };
    // TX: 70 sends through a 32-entry ring.
    for i in 0..70u32 {
        let msg = vec![i as u8; 1 + (i as usize * 29) % 2048];
        if ce.send(&chip, 3, &msg, i as u16).is_err() {
            return TestResult::Fail("send during wrap failed");
        }
        let got = chip.target_consume(3);
        if got.len() != 1 || got[0].0 != i || got[0].1 != msg {
            return TestResult::Fail("payload corrupted across the TX wrap");
        }
        let pend = chip.take_pending();
        ce.service(&chip, pend);
    }
    check!(
        ce.pipe(3).unwrap().src_indices() == Some((32, 70 % 32, 70 % 32)),
        "TX indices wrapped"
    );
    check!(
        ce.pipe(3).unwrap().stats.tx_completed == 70,
        "70 completions"
    );
    // RX: 1100 payloads through 512-entry dest + status rings.
    for i in 0..1100u32 {
        let msg = vec![(i * 7) as u8; 4 + (i as usize * 13) % 2045];
        if !chip.target_deliver(1, &msg, None) {
            return TestResult::Fail("no RX buffer posted during wrap");
        }
        let pend = chip.take_pending();
        ce.service(&chip, pend);
        if ce.take_rx(1).as_deref() != Some(&msg[..]) {
            return TestResult::Fail("payload corrupted across the RX wrap");
        }
    }
    let p = ce.pipe(1).unwrap();
    check!(
        p.dest_indices() == Some((512, 1100 % 512, (510 + 1100) % 512)),
        "dest sw/write index wrapped"
    );
    check!(
        ce.hal.srng(81).unwrap().tp == (1100 % 512) * 4,
        "status ring TP wrapped"
    );
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_ce_ring_wraparound);

fn smoke_ath11k_ce_ring_full() -> TestResult {
    let (mut ce, chip) = match bring_up() {
        Ok(v) => v,
        Err(e) => return TestResult::Fail(e),
    };
    // CE0: 16 entries, one always empty → 15 sends.
    for i in 0..15u16 {
        if ce.send(&chip, 0, &[i as u8; 8], i).is_err() {
            return TestResult::Fail("send below the ring limit failed");
        }
    }
    chip.clear();
    match ce.send(&chip, 0, b"overflow", 99) {
        Err(e) => check!(
            e.step == super::ce::step::RING_FULL && e.detail == 0 && e.errno == errno::ENOBUFS,
            "16th send: RING_FULL / -ENOBUFS"
        ),
        Ok(()) => return TestResult::Fail("send on a full ring must fail"),
    }
    // Linux still calls access_end: the unchanged HP is re-published.
    check!(
        chip.ops() == [Op::W(0x94c, 60)],
        "full ring re-publishes HP 15 * 4"
    );
    check!(ce.pipe(0).unwrap().stats.tx_full == 1, "tx_full counted");
    check!(chip.target_consume(0).len() == 15, "target drains 15");
    let pend = chip.take_pending();
    ce.service(&chip, pend);
    check!(
        ce.send(&chip, 0, b"again", 1).is_ok(),
        "space again after completions"
    );
    check!(
        chip.target_consume(0) == [(1, b"again".to_vec())],
        "payload after refill"
    );

    // RX: no host service → the posted 510 buffers run out.
    for i in 0..510u32 {
        if !chip.target_deliver(5, &i.to_le_bytes(), None) {
            return TestResult::Fail("posted buffer missing");
        }
    }
    check!(
        !chip.target_deliver(5, b"x", None),
        "no buffer left for a 511th payload"
    );
    let pend = chip.take_pending();
    ce.service(&chip, pend);
    check!(ce.rx_pending(5) == 510, "510 payloads queued");
    for i in 0..510u32 {
        if ce.take_rx(5).as_deref() != Some(&i.to_le_bytes()[..]) {
            return TestResult::Fail("RX order lost after exhaustion");
        }
    }
    check!(
        chip.target_deliver(5, b"x", None),
        "buffers re-posted after service"
    );
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_ce_ring_full);

fn smoke_ath11k_ce_send_negatives() -> TestResult {
    use super::ce::step;
    NOW.store(0, Ordering::Relaxed);
    let mut ce = match Ce::alloc(&wcn6855(), msi(&MSI_CONFIG_QCA6390), fake_clock) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail("Ce::alloc failed"),
    };
    let chip = FakeChip::new(ce.shadow_reg_v2());
    let e = ce.send(&chip, 0, b"x", 0).unwrap_err();
    check!(
        e.step == step::BAD_PIPE && e.errno == errno::EINVAL,
        "send before init_pipes"
    );
    check!(ce.init_pipes(&chip).is_ok(), "init");
    for pipe in [1u32, 2, 5, 6, 8, 9, 12, 255] {
        match ce.send(&chip, pipe, b"x", 0) {
            Err(e) if e.step == step::BAD_PIPE && e.detail == pipe => {}
            _ => return TestResult::Fail("send on a pipe without a source ring: BAD_PIPE"),
        }
    }
    let e = ce.send(&chip, 0, &[0; 2049], 0).unwrap_err();
    check!(
        e.step == step::OVERSIZE && e.detail == 2049 && e.errno == errno::EINVAL,
        "2049 bytes on CE0: OVERSIZE"
    );
    let e = ce.send(&chip, 4, &[0; 257], 0).unwrap_err();
    check!(
        e.step == step::OVERSIZE && e.detail == (4 << 24) | 257,
        "257 bytes on CE4: OVERSIZE"
    );
    check!(
        ce.send(&chip, 4, &[0; 256], 0).is_ok(),
        "256 bytes on CE4 fit"
    );
    ce.crash_flush = true;
    let e = ce.send(&chip, 3, b"x", 0).unwrap_err();
    check!(
        e.step == step::SHUTDOWN && e.errno == errno::ESHUTDOWN,
        "crash flush: -ESHUTDOWN"
    );
    check!(
        ce.take_rx(1).is_none() && ce.take_rx(40).is_none(),
        "nothing to receive"
    );
    check!(
        ce.per_engine_service(&chip, 40) == 0,
        "service of a missing CE is a no-op"
    );
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_ce_send_negatives);

/// Run `f` with the Wi-Fi diag latch cleared, return what it latched,
/// and restore the previous diag state.
fn latched_by(f: impl FnOnce()) -> (u32, u32) {
    use narf_memory::diag;
    let s = diag::snapshot();
    diag::__reset_for_test();
    f();
    let got = diag::snapshot();
    diag::__reset_for_test();
    diag::set_phase(s.phase);
    diag::set_heap_kb(s.heap_used_kb, s.heap_total_kb);
    if s.first_pf_seen {
        diag::note_pf(s.first_pf_cr2, s.first_pf_rip);
    }
    if s.panic_latched {
        diag::latch_panic(s.panic_marker);
    }
    diag::set_wifi_stage(s.wifi_stage);
    diag::latch_wifi_error(s.wifi_err, s.wifi_detail);
    (got.wifi_err, got.wifi_detail)
}

fn smoke_ath11k_ce_rx_bad_length() -> TestResult {
    let (mut ce, chip) = match bring_up() {
        Ok(v) => v,
        Err(e) => return TestResult::Fail(e),
    };
    // ath11k_ce_recv_process_cb drops nbytes == 0 and nbytes > buffer.
    check!(chip.target_deliver(1, b"zero", Some(0)), "deliver len 0");
    let pend = chip.take_pending();
    let (err, detail) = latched_by(|| {
        ce.service(&chip, pend);
    });
    check!(
        err == super::ce::step::RX_BAD_LEN && detail == 1 << 24,
        "length 0 latches RX_BAD_LEN (ce 1, len 0)"
    );
    check!(ce.take_rx(1).is_none(), "zero-length payload dropped");
    check!(
        chip.target_deliver(1, b"huge", Some(4096)),
        "deliver len 4096"
    );
    let pend = chip.take_pending();
    let (err, detail) = latched_by(|| {
        ce.service(&chip, pend);
    });
    check!(
        err == super::ce::step::RX_BAD_LEN && detail == (1 << 24) | 4096,
        "length > 2048 latches RX_BAD_LEN"
    );
    check!(ce.take_rx(1).is_none(), "oversize payload dropped");
    let p = ce.pipe(1).unwrap();
    check!(p.stats.rx_bad_len == 2, "two bad lengths counted");
    check!(
        p.dest_indices() == Some((512, 2, 512 % 512)),
        "dropped buffers re-posted"
    );
    check!(p.rx_buf_needed == 0, "rx_buf_needed back to 0");
    check!(chip.target_deliver(1, b"good", None), "next payload");
    let pend = chip.take_pending();
    ce.service(&chip, pend);
    check!(
        ce.take_rx(1).as_deref() == Some(&b"good"[..]),
        "good payload after bad ones"
    );
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_ce_rx_bad_length);

fn smoke_ath11k_ce_poll_without_irq() -> TestResult {
    let (mut ce, chip) = match bring_up() {
        Ok(v) => v,
        Err(e) => return TestResult::Fail(e),
    };
    check!(chip.target_deliver(2, b"lost msi", None), "deliver");
    let _ = chip.take_pending(); // the MSI never arrives
    check!(ce.service(&chip, 0) == 1, "the poll finds the completion");
    check!(
        ce.take_rx(2).as_deref() == Some(&b"lost msi"[..]),
        "payload via polling"
    );
    check!(
        ce.stats.polled_without_irq == 1 && ce.stats.irqs[2] == 0,
        "counted as found without an interrupt"
    );
    check!(chip.target_deliver(2, b"msi ok", None), "deliver");
    let pend = chip.take_pending();
    ce.service(&chip, pend);
    check!(
        ce.stats.irqs[2] == 1 && ce.stats.polled_without_irq == 1,
        "interrupt-driven completion not counted as polled"
    );
    check!(ce.service(&chip, 0) == 0, "idle poll does nothing");
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_ce_poll_without_irq);

fn smoke_ath11k_ce4_shadow_timer_and_reap() -> TestResult {
    let (mut ce, chip) = match bring_up() {
        Ok(v) => v,
        Err(e) => return TestResult::Fail(e),
    };
    NOW.store(100, Ordering::Relaxed);
    check!(ce.send(&chip, 4, b"htt", 1).is_ok(), "CE4 send");
    let t = ce.pipe(4).unwrap().hp_timer();
    check!(
        t.started && t.deadline_ms == 110 && t.tx_num == 1,
        "timer armed for 10 ms"
    );
    NOW.store(105, Ordering::Relaxed);
    check!(ce.send(&chip, 4, b"htt", 2).is_ok(), "second CE4 send");
    NOW.store(110, Ordering::Relaxed);
    chip.clear();
    ce.service_timers(&chip);
    check!(
        chip.ops().is_empty(),
        "TX during the interval: re-arm, no write"
    );
    check!(
        ce.pipe(4).unwrap().hp_timer().deadline_ms == 120,
        "re-armed"
    );
    NOW.store(120, Ordering::Relaxed);
    ce.service_timers(&chip);
    // TP (rdp) 0 != HP 8: HP re-published to shadow register 26.
    check!(
        chip.ops() == [Op::W(0x964, 8)],
        "HP refresh through shadow 26"
    );
    check!(
        !ce.pipe(4).unwrap().hp_timer().started && ce.stats.shadow_refresh == 1,
        "timer stopped"
    );
    // When the target has consumed everything there is nothing to refresh.
    check!(chip.target_consume(4).len() == 2, "target drains CE4");
    check!(ce.send(&chip, 4, b"htt", 3).is_ok(), "third send");
    let _ = chip.target_consume(4);
    NOW.store(200, Ordering::Relaxed);
    chip.clear();
    ce.service_timers(&chip);
    check!(chip.ops().is_empty(), "TP == HP: no refresh");

    // CE4 has no interrupt: completions are reaped by ath11k_ce_send
    // once more than ATH11K_CE_USAGE_THRESHOLD (32) are in flight.
    check!(
        ce.pipe(4).unwrap().stats.tx_completed == 0,
        "nothing reaped yet"
    );
    for i in 0..30u16 {
        let _ = ce.send(&chip, 4, b"h", i);
    }
    let _ = chip.target_consume(4);
    // 33 in flight now (3 + 30): the next send polls them.
    check!(
        ce.pipe(4).unwrap().src_indices() == Some((2048, 0, 33)),
        "33 in flight"
    );
    check!(
        ce.send(&chip, 4, b"h", 99).is_ok(),
        "send past the threshold"
    );
    check!(
        ce.pipe(4).unwrap().stats.tx_completed == 33,
        "33 reaped by the send"
    );
    check!(
        ce.service(&chip, 0) == 0,
        "the poll skips the interrupt-less CE"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_ce4_shadow_timer_and_reap
);

// ── MSI wiring ────────────────────────────────────────────────────

fn smoke_ath11k_ce_msi_assignment() -> TestResult {
    let cfg = &HOST_CE_CONFIG_QCA6390;
    // ath11k_pcic_config_irq: vector = (msi_data_idx % 10) + 3.
    let want = [
        Some(3),
        Some(4),
        Some(5),
        Some(6),
        None,
        Some(7),
        None,
        Some(8),
        Some(9),
    ];
    for (ce, w) in want.iter().enumerate() {
        if ce_irq_vector(cfg, &MSI_CONFIG_QCA6390, ce as u32) != *w {
            return TestResult::Fail("CE MSI vector differs from Linux");
        }
    }
    check!(
        ce_irq_vector(cfg, &MSI_CONFIG_QCA6390, 9).is_none(),
        "CE9 does not exist"
    );
    check!(
        ce_vector_cookie(cfg, &MSI_CONFIG_QCA6390, 7) == Some(1 << 5),
        "vector 7 → CE5"
    );
    check!(
        ce_vector_cookie(cfg, &MSI_CONFIG_QCA6390, 0).is_none(),
        "vector 0 is MHI"
    );
    check!(
        ce_vector_cookie(cfg, &MSI_CONFIG_QCA6390, 13).is_none(),
        "vector 13 is WAKE"
    );
    let m = msi(&MSI_CONFIG_QCA6390);
    check!(
        ce_ring_msi(cfg, &m, 7) == Some((0xfee0_1000, EP + 8)),
        "CE7 ring MSI data"
    );
    // Single shared vector: every CE ring signals ep_base_data.
    let one = msi(&MSI_CONFIG_ONE);
    for ce in [0u32, 1, 2, 3, 5, 7, 8] {
        if ce_ring_msi(cfg, &one, ce) != Some((0xfee0_1000, EP)) {
            return TestResult::Fail("single-MSI ring data must be ep_base_data");
        }
    }
    check!(
        ce_vector_cookie(cfg, &MSI_CONFIG_ONE, 0) == Some(0b1_1010_1111),
        "vector 0 carries every interrupt-enabled CE"
    );
    // The programmed rings use it.
    NOW.store(0, Ordering::Relaxed);
    let mut ce = Ce::alloc(&wcn6855(), one, fake_clock).expect("alloc");
    let chip = FakeChip::new(ce.shadow_reg_v2());
    ce.init_pipes(&chip).expect("init");
    check!(
        chip.reg(0x01b8_e050) == EP && chip.reg(0x01b8_b0a8) == EP,
        "CE7 src / CE5 status MSI data with one vector"
    );
    check!(
        chip.reg(0x01b8_8048) == 0,
        "CE4 (interrupt-less) has no MSI"
    );
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_ce_msi_assignment);

// ── async rx stream ───────────────────────────────────────────────

fn smoke_ath11k_ce_async_recv() -> TestResult {
    let (mut ce, chip) = match bring_up() {
        Ok(v) => v,
        Err(e) => return TestResult::Fail(e),
    };
    let irq = FakeIrq {
        chip: &chip,
        script: RefCell::new(Some((75, 1, b"ready event".to_vec()))),
    };
    let got = run(ce.recv(&chip, &irq, 1, 25, 1000));
    check!(
        got.as_deref() == Some(&b"ready event"[..]),
        "recv returns the payload"
    );
    check!(fake_clock() == 75, "after three 25 ms slices");
    check!(ce.stats.irqs[1] == 1, "woken by the CE1 interrupt");
    // Timeout: nothing arrives.
    let got = run(ce.recv(&chip, &irq, 2, 25, 200));
    check!(
        got.is_none() && fake_clock() >= 275,
        "recv times out on the CE clock"
    );
    // A payload already queued is returned without waiting.
    check!(chip.target_deliver(5, b"queued", None), "deliver");
    let pend = chip.take_pending();
    ce.service(&chip, pend);
    let before = fake_clock();
    let got = run(ce.recv(&chip, &irq, 5, 25, 0));
    check!(
        got.as_deref() == Some(&b"queued"[..]) && fake_clock() == before,
        "no wait"
    );
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_ce_async_recv);
