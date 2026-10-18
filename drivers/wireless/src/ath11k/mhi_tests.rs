//! MHI protocol + host-controller tests.
//!
//! A scripted fake MHI device ([`FakeMhi`]) implements [`MhiBus`]:
//! it keeps a register file, logs every access, and reacts to the
//! host's register writes the way WCN6855 does (BHI download → SBL
//! READY, M0 → state-change + EE events, BHIe download → AMSS EE
//! event, command doorbell → command completions, channel doorbells →
//! transfer completions), reading and writing the host's real DMA32
//! rings through the kernel direct map. The expected values are the
//! ones Linux `drivers/bus/mhi/host/` writes for ath11k's QCA6390 /
//! WCN6855 configuration.

#![cfg(target_arch = "x86_64")]

extern crate alloc;

use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::fmt::Write as _;
use core::future::Future;
use core::pin::pin;
use core::task::{Context, Poll, Waker};

use narf_kernel_test::{kernel_test_in, TestResult};

use super::hw::HwRev;
use super::mhi::*;
use super::mhi_host::*;

// ── harness ───────────────────────────────────────────────────────

macro_rules! check {
    ($cond:expr, $msg:literal) => {
        if !($cond) {
            return TestResult::Fail($msg);
        }
    };
}

/// Drive a future whose every await is immediately ready (the fake's
/// waits only advance its clock).
fn run<F: Future>(f: F) -> F::Output {
    let mut f = pin!(f);
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..16 {
        if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
    }
    panic!("mhi test future did not complete");
}

const REG_LEN: u32 = 0x20_0000;
const BHI: u32 = 0x2_4000;
const BHIE: u32 = 0x2_4100;
const CHDB: u32 = 0x800;
const ERDB: u32 = 0xc00;
const MHICFG_INIT: u32 = 0x0000_0080;
const SESSION: u32 = 0x0123_4567;
const DMA32: u64 = 0xffff_ffff;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Op {
    R(u32, u32),
    W(u32, u32),
    Sleep(u32),
    Wait(u32),
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Xfer {
    Success,
    Error(u32),
    Hang,
}

/// What the fake device does.
#[derive(Copy, Clone, Debug)]
struct Behaviour {
    initial_ee: u32,
    initial_mhistatus: u32,
    bhi_off: u32,
    bhie_off: u32,
    chdb_off: u32,
    erdb_off: u32,
    bhi: Xfer,
    bhie: Xfer,
    /// Set MHISTATUS.READY once SBL runs.
    sets_ready: bool,
    /// Clear MHICTRL.RESET when the host sets it.
    reset_clears: bool,
    /// EE `BHI_EXECENV` reports once the BHIe download finished.
    ee_after_bhie: u32,
    /// EE carried by the event posted after the BHIe download.
    ee_event_after_bhie: u32,
    /// Post a SYS_ERR state change instead of the EE event.
    syserr_event_after_bhie: bool,
    /// Put MHISTATUS into SYS_ERR right after the BHI download.
    syserr_after_bhi: bool,
    cmd_ccs: u32,
    /// Deliver MSIs.
    irqs: bool,
    /// Complete UL transfers as soon as their doorbell rings.
    ul_auto_complete: bool,
}

impl Default for Behaviour {
    fn default() -> Self {
        Behaviour {
            initial_ee: MhiEe::PBL.0,
            initial_mhistatus: 0,
            bhi_off: BHI,
            bhie_off: BHIE,
            chdb_off: CHDB,
            erdb_off: ERDB,
            bhi: Xfer::Success,
            bhie: Xfer::Success,
            sets_ready: true,
            reset_clears: true,
            ee_after_bhie: MhiEe::AMSS.0,
            ee_event_after_bhie: MhiEe::AMSS.0,
            syserr_event_after_bhie: false,
            syserr_after_bhi: false,
            cmd_ccs: ccs::SUCCESS,
            irqs: true,
            ul_auto_complete: true,
        }
    }
}

#[derive(Default)]
struct Dev {
    regs: BTreeMap<u32, u32>,
    ops: Vec<Op>,
    now: u64,
    irqs: u32,
    rand_calls: u32,
    logs: Vec<String>,
    notes: Vec<MhiNotify>,
    /// Device write position per event ring (DMA address), plus the
    /// last doorbell the host rang for it.
    ev_db: [u64; 2],
    ev_pending: [VecDeque<MhiRingElement>; 2],
    cmd_dev_rp: u64,
    cmds: Vec<(u32, u32)>,
    chan_dev_rp: BTreeMap<u32, u64>,
    chan_db: BTreeMap<u32, u64>,
    bhi_image: Vec<u8>,
    bhie_image: Vec<u8>,
    bhie_vec: Vec<(u64, u64)>,
    ul_rx: Vec<Vec<u8>>,
    wake_writes: Vec<u64>,
    /// `MhiBus::hif_power` steps, in order.
    hif: Vec<HifPower>,
    /// BHI downloads seen.
    bhi_loads: u32,
}

struct FakeMhi {
    beh: Behaviour,
    d: RefCell<Dev>,
}

// ── host memory access (the fake device's DMA) ───────────────────

fn phys_rd32(pa: u64) -> u32 {
    // SAFETY: `pa` comes from a context / ring / descriptor the host
    // controller allocated with `alloc_coherent_masked` and still owns;
    // the kernel direct map covers it and it is 4-byte aligned.
    unsafe { core::ptr::read_volatile(narf_memory::PhysAddr::new(pa).kernel_ptr::<u32>()) }
}
fn phys_wr32(pa: u64, v: u32) {
    // SAFETY: as `phys_rd32`; the fake writes only fields the device
    // owns (context rp, event ring elements, DL payloads).
    unsafe { core::ptr::write_volatile(narf_memory::PhysAddr::new(pa).kernel_mut_ptr::<u32>(), v) }
}
fn phys_rd64(pa: u64) -> u64 {
    phys_rd32(pa) as u64 | ((phys_rd32(pa + 4) as u64) << 32)
}
fn phys_wr64(pa: u64, v: u64) {
    phys_wr32(pa, v as u32);
    phys_wr32(pa + 4, (v >> 32) as u32);
}
fn phys_read(pa: u64, len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    // SAFETY: `pa..pa+len` is a host DMA buffer the host described to
    // the device (image / segment / UL payload) and still owns.
    unsafe {
        core::ptr::copy_nonoverlapping(
            narf_memory::PhysAddr::new(pa).kernel_ptr::<u8>(),
            out.as_mut_ptr(),
            len,
        )
    };
    out
}
fn phys_write(pa: u64, data: &[u8]) {
    // SAFETY: `pa` is a DL buffer the host queued on a TRE whose length
    // the caller checked `data` against.
    unsafe {
        core::ptr::copy_nonoverlapping(
            data.as_ptr(),
            narf_memory::PhysAddr::new(pa).kernel_mut_ptr::<u8>(),
            data.len(),
        )
    };
}
fn rd_el(pa: u64) -> MhiRingElement {
    MhiRingElement {
        ptr: phys_rd64(pa),
        dword: [phys_rd32(pa + 8), phys_rd32(pa + 12)],
    }
}
fn wr_el(pa: u64, e: &MhiRingElement) {
    phys_wr64(pa, e.ptr);
    phys_wr32(pa + 8, e.dword[0]);
    phys_wr32(pa + 12, e.dword[1]);
}

impl FakeMhi {
    fn new(beh: Behaviour) -> Self {
        let mut d = Dev::default();
        d.regs.insert(BHIOFF, beh.bhi_off);
        d.regs.insert(BHIEOFF, beh.bhie_off);
        d.regs.insert(CHDBOFF, beh.chdb_off);
        d.regs.insert(ERDBOFF, beh.erdb_off);
        d.regs.insert(MHICFG, MHICFG_INIT);
        d.regs.insert(MHISTATUS, beh.initial_mhistatus);
        d.regs.insert(beh.bhi_off + BHI_EXECENV, beh.initial_ee);
        d.regs.insert(beh.bhi_off + BHI_SERIALNU, 0x5e71_a10e);
        for off in (BHIE_RXVECADDR_LOW_OFFS..=BHIE_RXVECSTATUS_OFFS).step_by(4) {
            d.regs.insert(beh.bhie_off + off, 0xdead_beef);
        }
        FakeMhi {
            beh,
            d: RefCell::new(d),
        }
    }

    fn reg(d: &Dev, off: u32) -> u32 {
        *d.regs.get(&off).unwrap_or(&0)
    }

    fn raise(&self, d: &mut Dev, irq: u32) {
        if self.beh.irqs {
            d.irqs |= 1 << irq;
        }
    }

    fn ctxt_base(d: &Dev, lo: u32, hi: u32) -> u64 {
        Self::reg(d, lo) as u64 | ((Self::reg(d, hi) as u64) << 32)
    }

    /// Post `el` on event ring `i` if the host left room, else queue it.
    fn post(&self, d: &mut Dev, i: usize, el: MhiRingElement) {
        d.ev_pending[i].push_back(el);
        self.flush(d, i);
    }

    fn flush(&self, d: &mut Dev, i: usize) {
        let ctx = Self::ctxt_base(d, ECABAP_LOWER, ECABAP_HIGHER) + (i * CTXT_SIZE) as u64;
        if ctx == 0 {
            return;
        }
        let rbase = phys_rd64(ctx + CTXT_RBASE as u64);
        let rlen = phys_rd64(ctx + CTXT_RLEN as u64);
        let mut posted = false;
        while let Some(el) = d.ev_pending[i].front().copied() {
            let rp = phys_rd64(ctx + CTXT_RP as u64);
            // The host's doorbell marks the last element it handed back;
            // the device may not write there.
            if rp == d.ev_db[i] {
                break;
            }
            wr_el(rp, &el);
            let mut next = rp + 16;
            if next >= rbase + rlen {
                next = rbase;
            }
            phys_wr64(ctx + CTXT_RP as u64, next);
            d.ev_pending[i].pop_front();
            posted = true;
        }
        if posted {
            // ath11k: ring 0 → irq 1, ring 1 → irq 2.
            self.raise(d, i as u32 + 1);
        }
    }

    fn on_write(&self, d: &mut Dev, off: u32, v: u32) {
        let b = self.beh;
        if off == MHICTRL {
            if v & MHICTRL_RESET_MASK != 0 && b.reset_clears {
                let st = Self::reg(d, MHISTATUS);
                d.regs.insert(MHICTRL, v & !MHICTRL_RESET_MASK);
                if field_get(MHISTATUS_MHISTATE_MASK, st) == MhiState::SYS_ERR.0 {
                    d.regs.insert(MHISTATUS, 0);
                }
            }
            let state = field_get(MHICTRL_MHISTATE_MASK, v);
            let st = Self::reg(d, MHISTATUS);
            if state == MhiState::M0.0 && st & MHISTATUS_READY_MASK != 0 {
                d.regs.insert(
                    MHISTATUS,
                    (st & !MHISTATUS_MHISTATE_MASK) | (MhiState::M0.0 << 8),
                );
                self.post(d, 0, MhiRingElement::state_change_event(MhiState::M0.0));
                let ee = Self::reg(d, b.bhi_off + BHI_EXECENV);
                if ee == MhiEe::SBL.0 || ee == MhiEe::AMSS.0 {
                    self.post(d, 0, MhiRingElement::ee_event(ee));
                }
            }
        } else if off == b.bhi_off + BHI_IMGTXDB {
            let addr =
                Self::ctxt_base(d, b.bhi_off + BHI_IMGADDR_LOW, b.bhi_off + BHI_IMGADDR_HIGH);
            let size = Self::reg(d, b.bhi_off + BHI_IMGSIZE) as usize;
            d.bhi_image = phys_read(addr, size);
            d.bhi_loads += 1;
            match b.bhi {
                Xfer::Success => {
                    d.regs
                        .insert(b.bhi_off + BHI_STATUS, BHI_STATUS_SUCCESS << 30);
                    d.regs.insert(b.bhi_off + BHI_EXECENV, MhiEe::SBL.0);
                    if b.sets_ready {
                        let st = Self::reg(d, MHISTATUS);
                        d.regs.insert(MHISTATUS, st | MHISTATUS_READY_MASK);
                    }
                    if b.syserr_after_bhi {
                        d.regs
                            .insert(MHISTATUS, (0xff << 8) | MHISTATUS_SYSERR_MASK);
                    }
                }
                Xfer::Error(code) => {
                    d.regs
                        .insert(b.bhi_off + BHI_STATUS, BHI_STATUS_ERROR << 30);
                    d.regs.insert(b.bhi_off + BHI_ERRCODE, code);
                    d.regs.insert(b.bhi_off + BHI_ERRDBG1, code + 1);
                    d.regs.insert(b.bhi_off + BHI_ERRDBG2, code + 2);
                    d.regs.insert(b.bhi_off + BHI_ERRDBG3, code + 3);
                }
                Xfer::Hang => {}
            }
            self.raise(d, 0);
        } else if off == b.bhie_off + BHIE_TXVECDB_OFFS {
            let seq = v & BHIE_TXVECDB_SEQNUM_BMSK;
            let addr = Self::ctxt_base(
                d,
                b.bhie_off + BHIE_TXVECADDR_LOW_OFFS,
                b.bhie_off + BHIE_TXVECADDR_HIGH_OFFS,
            );
            let size = Self::reg(d, b.bhie_off + BHIE_TXVECSIZE_OFFS) as u64;
            d.bhie_vec.clear();
            d.bhie_image.clear();
            for k in 0..size / 16 {
                let a = phys_rd64(addr + k * 16);
                let l = phys_rd64(addr + k * 16 + 8);
                d.bhie_vec.push((a, l));
                let seg = phys_read(a, l as usize);
                d.bhie_image.extend_from_slice(&seg);
            }
            match b.bhie {
                Xfer::Success => {
                    d.regs.insert(
                        b.bhie_off + BHIE_TXVECSTATUS_OFFS,
                        (BHIE_TXVECSTATUS_STATUS_XFER_COMPL << 30) | seq,
                    );
                    d.regs.insert(b.bhi_off + BHI_EXECENV, b.ee_after_bhie);
                    if b.syserr_event_after_bhie {
                        d.regs
                            .insert(MHISTATUS, (0xff << 8) | MHISTATUS_SYSERR_MASK);
                        self.post(d, 0, MhiRingElement::state_change_event(0xff));
                    } else {
                        self.post(d, 0, MhiRingElement::ee_event(b.ee_event_after_bhie));
                    }
                }
                Xfer::Error(_) => {
                    d.regs.insert(
                        b.bhie_off + BHIE_TXVECSTATUS_OFFS,
                        (BHIE_TXVECSTATUS_STATUS_ERROR << 30) | seq,
                    );
                }
                Xfer::Hang => {}
            }
            self.raise(d, 0);
        } else if off == CRDB_LOWER {
            let db = v as u64 | ((Self::reg(d, CRDB_HIGHER) as u64) << 32);
            let ctx = Self::ctxt_base(d, CRCBAP_LOWER, CRCBAP_HIGHER);
            let rbase = phys_rd64(ctx + CTXT_RBASE as u64);
            let rlen = phys_rd64(ctx + CTXT_RLEN as u64);
            if d.cmd_dev_rp == 0 {
                d.cmd_dev_rp = rbase;
            }
            while d.cmd_dev_rp != db {
                let el = rd_el(d.cmd_dev_rp);
                d.cmds.push((el.cmd_type(), el.cmd_chid()));
                let at = d.cmd_dev_rp;
                d.cmd_dev_rp += 16;
                if d.cmd_dev_rp >= rbase + rlen {
                    d.cmd_dev_rp = rbase;
                }
                phys_wr64(ctx + CTXT_RP as u64, d.cmd_dev_rp);
                self.post(d, 0, MhiRingElement::cmd_completion_event(at, b.cmd_ccs));
            }
        } else if off >= b.erdb_off && off < b.erdb_off + 16 && off % 8 == 0 {
            let i = ((off - b.erdb_off) / 8) as usize;
            d.ev_db[i] = v as u64 | ((Self::reg(d, off + 4) as u64) << 32);
            self.flush(d, i);
        } else if off >= b.chdb_off && off < b.chdb_off + 128 * 8 && off % 8 == 0 {
            let ch = (off - b.chdb_off) / 8;
            let db = v as u64 | ((Self::reg(d, off + 4) as u64) << 32);
            if ch == MHI_DEV_WAKE_DB {
                d.wake_writes.push(db);
            } else {
                d.chan_db.insert(ch, db);
                if ch == 20 && b.ul_auto_complete {
                    self.consume_ul(d, ch);
                }
            }
        }
    }

    fn chan_ring(d: &Dev, ch: u32) -> (u64, u64, u64) {
        let ctx =
            Self::ctxt_base(d, CCABAP_LOWER, CCABAP_HIGHER) + (ch as usize * CTXT_SIZE) as u64;
        (
            ctx,
            phys_rd64(ctx + CTXT_RBASE as u64),
            phys_rd64(ctx + CTXT_RLEN as u64),
        )
    }

    fn consume_ul(&self, d: &mut Dev, ch: u32) {
        let (ctx, rbase, rlen) = Self::chan_ring(d, ch);
        let db = *d.chan_db.get(&ch).unwrap_or(&rbase);
        let mut rp = *d.chan_dev_rp.get(&ch).unwrap_or(&rbase);
        let er = phys_rd32(ctx + 8) as usize;
        while rp != db {
            let tre = rd_el(rp);
            d.ul_rx.push(phys_read(tre.ptr, tre.data_len() as usize));
            let at = rp;
            rp += 16;
            if rp >= rbase + rlen {
                rp = rbase;
            }
            phys_wr64(ctx + CTXT_RP as u64, rp);
            self.post(
                d,
                er,
                MhiRingElement::tx_event(at, ccs::EOT, tre.data_len(), ch),
            );
        }
        d.chan_dev_rp.insert(ch, rp);
    }

    /// Device → host: write `data` into the next queued DL buffer of
    /// `ch` and post its completion. `false` if no buffer is queued.
    fn send_dl(&self, ch: u32, data: &[u8], code: u32) -> bool {
        let d = &mut *self.d.borrow_mut();
        let (ctx, rbase, rlen) = Self::chan_ring(d, ch);
        let db = *d.chan_db.get(&ch).unwrap_or(&rbase);
        let rp = *d.chan_dev_rp.get(&ch).unwrap_or(&rbase);
        if rp == db {
            return false;
        }
        let tre = rd_el(rp);
        if (tre.data_len() as usize) < data.len() {
            return false;
        }
        phys_write(tre.ptr, data);
        let mut next = rp + 16;
        if next >= rbase + rlen {
            next = rbase;
        }
        phys_wr64(ctx + CTXT_RP as u64, next);
        d.chan_dev_rp.insert(ch, next);
        let er = phys_rd32(ctx + 8) as usize;
        self.post(
            d,
            er,
            MhiRingElement::tx_event(rp, code, data.len() as u32, ch),
        );
        true
    }

    fn post_ctrl(&self, el: MhiRingElement) {
        let d = &mut *self.d.borrow_mut();
        self.post(d, 0, el);
    }

    fn ops(&self) -> Vec<Op> {
        self.d.borrow().ops.clone()
    }
    fn writes(&self) -> Vec<(u32, u32)> {
        self.d
            .borrow()
            .ops
            .iter()
            .filter_map(|o| match *o {
                Op::W(a, v) => Some((a, v)),
                _ => None,
            })
            .collect()
    }
    fn logged(&self, needle: &str) -> bool {
        self.d.borrow().logs.iter().any(|l| l.contains(needle))
    }
}

impl MhiBus for FakeMhi {
    fn read32(&self, offset: u32) -> u32 {
        let d = &mut *self.d.borrow_mut();
        let v = Self::reg(d, offset);
        d.ops.push(Op::R(offset, v));
        v
    }
    fn write32(&self, offset: u32, value: u32) {
        let d = &mut *self.d.borrow_mut();
        d.ops.push(Op::W(offset, value));
        d.regs.insert(offset, value);
        self.on_write(d, offset, value);
    }
    fn take_irqs(&self) -> u32 {
        core::mem::take(&mut self.d.borrow_mut().irqs)
    }
    fn irqs_pending(&self) -> bool {
        self.d.borrow().irqs != 0
    }
    fn hif_power(&self, step: HifPower) {
        let d = &mut *self.d.borrow_mut();
        d.hif.push(step);
        if step == HifPower::Reset {
            // ath11k_pci_sw_reset: the SoC restarts in PBL, MHI in RESET,
            // and forgets every ring position.
            d.regs.insert(self.beh.bhi_off + BHI_EXECENV, MhiEe::PBL.0);
            d.regs.insert(MHISTATUS, 0);
            d.regs.insert(MHICTRL, 0);
            d.ev_db = [0; 2];
            d.ev_pending = Default::default();
            d.cmd_dev_rp = 0;
            d.chan_dev_rp.clear();
            d.chan_db.clear();
            d.irqs = 0;
        }
    }
    fn wait_irq(&self, ms: u32) -> impl Future<Output = ()> + Send {
        let d = &mut *self.d.borrow_mut();
        d.ops.push(Op::Wait(ms));
        d.now += ms as u64;
        core::future::ready(())
    }
    fn sleep(&self, ms: u32) -> impl Future<Output = ()> + Send {
        let d = &mut *self.d.borrow_mut();
        d.ops.push(Op::Sleep(ms));
        d.now += ms as u64;
        core::future::ready(())
    }
    fn now_ms(&self) -> u64 {
        self.d.borrow().now
    }
    fn random_nonzero(&self, max: u32) -> u32 {
        let d = &mut *self.d.borrow_mut();
        d.rand_calls += 1;
        (SESSION + d.rand_calls - 1) & max
    }
    fn notify(&self, ev: MhiNotify) {
        self.d.borrow_mut().notes.push(ev);
    }
    fn log(&self, args: core::fmt::Arguments<'_>) {
        let mut s = String::new();
        let _ = s.write_fmt(args);
        self.d.borrow_mut().logs.push(s);
    }
}

type Host = MhiController<FakeMhi>;

fn host(beh: Behaviour) -> Host {
    MhiController::new(
        FakeMhi::new(beh),
        &ATH11K_MHI_CONFIG_QCA6390,
        ControllerParams::ath11k(REG_LEN, 3),
    )
    .expect("ath11k config accepted")
}

/// A recognisable firmware image of `len` bytes.
fn firmware(len: usize, second_elf: bool) -> Vec<u8> {
    let mut v: Vec<u8> = (0..len)
        .map(|i| (i as u32).wrapping_mul(2_654_435_761).rotate_right(13) as u8)
        .collect();
    v[..4].copy_from_slice(b"\x7fELF");
    if second_elf && len >= ATH11K_SBL_SIZE + 4 {
        v[ATH11K_SBL_SIZE..ATH11K_SBL_SIZE + 4].copy_from_slice(b"\x7fELF");
    } else if len >= ATH11K_SBL_SIZE + 4 {
        v[ATH11K_SBL_SIZE] = 0;
    }
    v
}

fn boot(beh: Behaviour, fw: Vec<u8>) -> (Host, Result<(), MhiError>) {
    let mut h = host(beh);
    if let Err(e) = h.prepare_for_power_up() {
        return (h, Err(e));
    }
    h.set_firmware(fw);
    let r = run(h.sync_power_up());
    (h, r)
}

/// Index of the first write of `(off, val)` at or after `from`.
fn find_write(w: &[(u32, u32)], from: usize, off: u32) -> Option<usize> {
    (from..w.len()).find(|&i| w[i].0 == off)
}

// ── wire definitions ─────────────────────────────────────────────

fn smoke_mhi_context_and_element_layouts() -> TestResult {
    use core::mem::{align_of, size_of};
    // `__le64 __packed __aligned(4)` after three u32: 44 bytes, align 4.
    check!(
        size_of::<MhiChanCtxt>() == 44,
        "mhi_chan_ctxt must be 44 bytes"
    );
    check!(
        size_of::<MhiEventCtxt>() == 44,
        "mhi_event_ctxt must be 44 bytes"
    );
    check!(
        size_of::<MhiCmdCtxt>() == 44,
        "mhi_cmd_ctxt must be 44 bytes"
    );
    check!(
        align_of::<MhiChanCtxt>() == 4,
        "context alignment must be 4"
    );
    check!(
        size_of::<MhiRingElement>() == 16,
        "ring element must be 16 bytes"
    );
    check!(
        size_of::<BhiVecEntry>() == 16,
        "bhi_vec_entry must be 16 bytes"
    );
    let c = MhiChanCtxt::default();
    let base = core::ptr::addr_of!(c) as usize;
    check!(
        core::ptr::addr_of!(c.chtype) as usize - base == 4,
        "chtype at 4"
    );
    check!(
        core::ptr::addr_of!(c.erindex) as usize - base == 8,
        "erindex at 8"
    );
    check!(
        core::ptr::addr_of!(c.rbase) as usize - base == CTXT_RBASE,
        "rbase at 12"
    );
    check!(
        core::ptr::addr_of!(c.rlen) as usize - base == CTXT_RLEN,
        "rlen at 20"
    );
    check!(
        core::ptr::addr_of!(c.rp) as usize - base == CTXT_RP,
        "rp at 28"
    );
    check!(
        core::ptr::addr_of!(c.wp) as usize - base == CTXT_WP,
        "wp at 36"
    );
    let e = MhiEventCtxt::default();
    let base = core::ptr::addr_of!(e) as usize;
    check!(
        core::ptr::addr_of!(e.msivec) as usize - base == 8,
        "msivec at 8"
    );
    check!(
        core::ptr::addr_of!(e.rp) as usize - base == CTXT_RP,
        "event rp at 28"
    );
    // Register map spot checks against common.h.
    check!(
        MHICFG == 0x10 && CHDBOFF == 0x18 && ERDBOFF == 0x20,
        "MHI cfg/db offsets"
    );
    check!(
        BHIOFF == 0x28 && BHIEOFF == 0x2c && MHICTRL == 0x38,
        "BHI/BHIe/MHICTRL offsets"
    );
    check!(
        MHISTATUS == 0x48 && CCABAP_LOWER == 0x58 && CRDB_LOWER == 0x70,
        "status/ctxt/crdb"
    );
    check!(
        MHICTRLBASE_LOWER == 0x80 && MHIDATALIMIT_HIGHER == 0xa4,
        "iova window regs"
    );
    check!(
        BHI_IMGTXDB == 0x18 && BHI_INTVEC == 0x20 && BHI_STATUS == 0x2c,
        "BHI regs"
    );
    check!(
        BHI_ERRCODE == 0x30 && BHI_SERIALNU == 0x40,
        "BHI error/serial regs"
    );
    check!(
        BHIE_TXVECADDR_LOW_OFFS == 0x2c && BHIE_TXVECDB_OFFS == 0x3c,
        "BHIe tx regs"
    );
    check!(
        BHIE_TXVECSTATUS_OFFS == 0x44 && BHIE_RXVECSTATUS_OFFS == 0x78,
        "BHIe status regs"
    );
    check!(
        MHICFG_NER_MASK == 0x00ff_0000 && MHICFG_NHWER_MASK == 0xff00_0000,
        "MHICFG masks"
    );
    check!(
        BHI_STATUS_MASK == 0xc000_0000 && BHI_TXDB_SEQNUM_BMSK == 0x3fff_ffff,
        "BHI masks"
    );
    check!(
        MHICTRL_MHISTATE_MASK == 0xff00 && MHICTRL_RESET_MASK == 2,
        "MHICTRL masks"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_mhi_context_and_element_layouts
);

fn smoke_mhi_ring_element_encodings() -> TestResult {
    // MHI_TRE_DATA_DWORD1(bei, ieot, ieob, chain): type in 23:16, BEI
    // bit 10, IEOT bit 9, IEOB bit 8, CHAIN bit 0.
    let t = MhiRingElement::data(0x1234_5000, 8192, true, true, false, false);
    check!(t.ptr == 0x1234_5000, "TRE ptr");
    check!(t.dword[0] == 8192, "TRE length in dword0[15:0]");
    check!(
        t.dword[1] == 0x0002_0600,
        "QRTR DL TRE (BEI|IEOT) must be 0x00020600"
    );
    check!(
        MhiRingElement::data(0, 0, false, false, true, false).dword[1] == 0x0002_0100,
        "IEOB is bit 8"
    );
    check!(
        MhiRingElement::data(0, 0, false, false, false, true).dword[1] == 0x0002_0001,
        "CHAIN is bit 0"
    );
    // Length is a 16-bit field.
    check!(
        MhiRingElement::data(0, 0x1_0010, false, false, false, false).dword[0] == 0x10,
        "TRE length truncates to 16 bits like FIELD_PREP"
    );
    let r = MhiRingElement::data(0, 64, true, false, true, true);
    check!(
        r.data_bei() && r.data_ieob() && r.data_chain() && !r.data_ieot(),
        "TRE getters"
    );
    // Commands.
    let s = MhiRingElement::command(cmd::START_CHAN, 20).unwrap();
    check!(
        s.ptr == 0 && s.dword[0] == 0 && s.dword[1] == 0x1412_0000,
        "START ch20"
    );
    let rs = MhiRingElement::command(cmd::RESET_CHAN, 21).unwrap();
    check!(rs.dword[1] == 0x1510_0000, "RESET ch21");
    let st = MhiRingElement::command(cmd::STOP_CHAN, 21).unwrap();
    check!(st.dword[1] == 0x1511_0000, "STOP ch21");
    check!(
        MhiRingElement::command(cmd::NOP, 5).unwrap().dword[1] == 0x0001_0000,
        "NOP carries no channel"
    );
    check!(
        MhiRingElement::command(0x33, 1).is_none(),
        "unknown command rejected"
    );
    check!(s.cmd_type() == 18 && s.cmd_chid() == 20, "command getters");
    // Events.
    let sc = MhiRingElement::state_change_event(MhiState::M0.0);
    check!(
        sc.dword[0] == 0x0200_0000 && sc.dword[1] == 0x0020_0000,
        "SC event layout"
    );
    check!(
        sc.ev_type() == pkt::STATE_CHANGE_EVENT && sc.ev_state() == 2,
        "SC getters"
    );
    let ee = MhiRingElement::ee_event(MhiEe::AMSS.0);
    check!(
        ee.dword[0] == 0x0200_0000 && ee.dword[1] == 0x0040_0000,
        "EE event layout"
    );
    let cc = MhiRingElement::cmd_completion_event(0xabc0, ccs::SUCCESS);
    check!(
        cc.ptr == 0xabc0 && cc.dword[0] == 0x0100_0000,
        "CC event layout"
    );
    check!(
        cc.dword[1] == 0x0021_0000 && cc.ev_code() == 1,
        "CC getters"
    );
    let tx = MhiRingElement::tx_event(0x1000, ccs::EOT, 0x1234, 21);
    check!(
        tx.dword[0] == 0x0200_1234 && tx.dword[1] == 0x1522_0000,
        "TX event layout"
    );
    check!(
        tx.ev_len() == 0x1234 && tx.ev_chid() == 21 && tx.ev_code() == 2,
        "TX getters"
    );
    let bw = MhiRingElement {
        ptr: 0,
        dword: [0x0000_0004, 0x0350_0000],
    };
    check!(bw.ev_type() == pkt::BW_REQ_EVENT, "BW_REQ type 0x50");
    check!(
        bw.ev_linkspeed() == 3 && bw.ev_linkwidth() == 4,
        "BW_REQ speed/width"
    );
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_mhi_ring_element_encodings);

fn smoke_mhi_ee_and_state_decoding() -> TestResult {
    // enum mhi_ee_type values.
    check!(
        MhiEe::PBL.0 == 0 && MhiEe::SBL.0 == 1 && MhiEe::AMSS.0 == 2 && MhiEe::RDDM.0 == 3,
        "EE values 0..3"
    );
    check!(
        MhiEe::WFW.0 == 4 && MhiEe::PTHRU.0 == 5 && MhiEe::EDL.0 == 6 && MhiEe::FP.0 == 7,
        "EE values 4..7"
    );
    check!(
        MhiEe::DISABLE_TRANSITION.0 == 8 && MhiEe::NOT_SUPPORTED.0 == 9 && MhiEe::MAX.0 == 10,
        "local EE values"
    );
    // Linux predicates, every EE.
    for v in 0..12u32 {
        let e = MhiEe(v);
        let pbl = v == 0 || v == 5 || v == 6;
        check!(e.in_pbl() == pbl, "MHI_IN_PBL");
        check!(
            e.power_up_capable() == (pbl || v == 2),
            "MHI_POWER_UP_CAPABLE"
        );
        check!(
            e.fw_load_capable() == (v == 0 || v == 6),
            "MHI_FW_LOAD_CAPABLE"
        );
        check!(
            e.in_mission_mode() == (v == 2 || v == 4 || v == 7),
            "MHI_IN_MISSION_MODE"
        );
    }
    // The old decoder masked BHI_EXECENV with 7, turning 0xa into AMSS.
    check!(
        !MhiEe(0xa).in_mission_mode(),
        "raw EE 0xa is not mission mode"
    );
    check!(MhiEe(0xa).name() == "INVALID_EE", "out-of-range EE name");
    check!(MhiEe::AMSS.name() == "MISSION MODE", "AMSS name");
    check!(
        MhiEe::AMSS.bit() & 0x4 != 0 && MhiEe::SBL.bit() & 0x4 == 0,
        "ee_mask 0x4 = AMSS"
    );
    check!(MhiEe(40).bit() == 0, "EE beyond the mask word");
    // enum mhi_state.
    check!(
        MhiState::M0.0 == 2 && MhiState::BHI.0 == 7,
        "MHI state values"
    );
    check!(MhiState::SYS_ERR.0 == 0xff, "SYS_ERR is 0xff");
    check!(MhiState::SYS_ERR.name() == "SYS ERROR", "SYS_ERR name");
    check!(
        MhiState(0x42).name() == "Unknown state",
        "unknown state name"
    );
    // mhi_pkt_type / mhi_ev_ccs / mhi_cmd_type.
    check!(
        pkt::TX_EVENT == 0x22 && pkt::EE_EVENT == 0x40 && pkt::BW_REQ_EVENT == 0x50,
        "pkt types"
    );
    check!(
        ccs::EOT == 2 && ccs::OVERFLOW == 3 && ccs::BAD_TRE == 0x11,
        "completion codes"
    );
    check!(
        cmd::START_CHAN == 18 && cmd::RESET_CHAN == 16,
        "command types"
    );
    check!(
        BrstMode::Disable as u32 == 2 && BrstMode::Enable as u32 == 3,
        "burst modes"
    );
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_mhi_ee_and_state_decoding);

fn smoke_mhi_pm_state_machine() -> TestResult {
    use pm::*;
    check!(tryset(DISABLE, POR) == POR, "DISABLE -> POR");
    check!(tryset(DISABLE, M0) == DISABLE, "DISABLE -> M0 refused");
    check!(tryset(POR, M0) == M0, "POR -> M0");
    check!(tryset(POR, FW_DL_ERR) == FW_DL_ERR, "POR -> FW_DL_ERR");
    check!(tryset(M0, M2) == M2 && tryset(M2, M0) == M0, "M0 <-> M2");
    check!(tryset(M2, M3_ENTER) == M2, "M2 -> M3_ENTER refused");
    check!(
        tryset(FW_DL_ERR, M0) == FW_DL_ERR,
        "FW_DL_ERR -> M0 refused"
    );
    check!(
        tryset(SYS_ERR_DETECT, POR) == SYS_ERR_DETECT,
        "SYS_ERR_DETECT -> POR refused"
    );
    check!(
        tryset(SYS_ERR_DETECT, SYS_ERR_DETECT) == SYS_ERR_DETECT,
        "no self loop"
    );
    check!(
        tryset(SYS_ERR_PROCESS, POR) == POR,
        "SYS_ERR_PROCESS -> POR"
    );
    check!(
        tryset(LD_ERR_FATAL_DETECT, DISABLE) == DISABLE,
        "LD_ERR -> DISABLE"
    );
    check!(
        tryset(LD_ERR_FATAL_DETECT, M0) == LD_ERR_FATAL_DETECT,
        "LD_ERR -> M0 refused"
    );
    check!(
        tryset(POR | M0, M0) == POR | M0,
        "a non-single-bit state is refused"
    );
    check!(
        reg_access_valid(POR) && reg_access_valid(FW_DL_ERR),
        "register access states"
    );
    check!(
        !reg_access_valid(DISABLE) && !reg_access_valid(LD_ERR_FATAL_DETECT),
        "no access"
    );
    check!(!reg_access_valid(M3), "M3 is not register-accessible");
    check!(
        in_error_state(FW_DL_ERR) && !in_error_state(M3_EXIT),
        "error states"
    );
    check!(
        fatal_error(FW_DL_ERR) && fatal_error(SYS_ERR_FAIL),
        "fatal errors"
    );
    check!(
        !fatal_error(SYS_ERR_DETECT) && !fatal_error(SYS_ERR_PROCESS),
        "non-fatal errors"
    );
    check!(
        event_access_invalid(DISABLE) && !event_access_invalid(POR),
        "event access"
    );
    check!(
        wake_db_set_valid(M2) && !wake_db_set_valid(M0),
        "WAKE_DB_SET_VALID"
    );
    check!(
        wake_db_force_set_valid(M0) && !wake_db_force_set_valid(POR),
        "FORCE_SET_VALID"
    );
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_mhi_pm_state_machine);

fn smoke_mhi_config_matches_ath11k() -> TestResult {
    for rev in [
        HwRev::Qca6390Hw20,
        HwRev::Wcn6855Hw20,
        HwRev::Wcn6855Hw21,
        HwRev::Qca2066Hw21,
        HwRev::Qca6698aqHw21,
    ] {
        check!(
            config_for(rev) == Some(&ATH11K_MHI_CONFIG_QCA6390),
            "WCN6855-class parts use ath11k_mhi_config_qca6390"
        );
    }
    check!(
        config_for(HwRev::Qcn9074Hw10) == Some(&ATH11K_MHI_CONFIG_QCN9074),
        "QCN9074 config"
    );
    check!(
        config_for(HwRev::Unknown).is_none(),
        "unknown hw_rev has no MHI config"
    );
    let c = &ATH11K_MHI_CONFIG_QCA6390;
    check!(
        c.max_channels == 128 && c.timeout_ms == 2000 && c.buf_len == 8192,
        "qca6390 cfg"
    );
    check!(
        !c.use_bounce_buf && c.ready_timeout_ms == 0,
        "qca6390 cfg flags"
    );
    check!(
        c.ch_cfg.len() == 2 && c.event_cfg.len() == 2,
        "two channels, two event rings"
    );
    let (ul, dl) = (&c.ch_cfg[0], &c.ch_cfg[1]);
    check!(
        ul.num == 20 && ul.dir == DmaDir::ToDevice && ul.name == "IPCR",
        "ch20 IPCR UL"
    );
    check!(
        dl.num == 21 && dl.dir == DmaDir::FromDevice && dl.name == "IPCR",
        "ch21 IPCR DL"
    );
    for ch in c.ch_cfg {
        check!(
            ch.num_elements == 64 && ch.event_ring == 1,
            "64 elements on event ring 1"
        );
        check!(
            ch.ee_mask == 0x4 && ch.doorbell == BrstMode::Disable,
            "AMSS-only, no burst"
        );
        check!(
            ch.pollcfg == 0 && !ch.offload_channel && !ch.lpm_notify,
            "channel flags"
        );
    }
    let (e0, e1) = (&c.event_cfg[0], &c.event_cfg[1]);
    check!(
        e0.num_elements == 32 && e0.irq == 1 && e0.irq_moderation_ms == 0,
        "event ring 0"
    );
    check!(
        e0.data_type == ErDataType::Ctrl && e0.mode == BrstMode::Disable,
        "ring 0 is ctrl"
    );
    check!(
        e1.num_elements == 256 && e1.irq == 2 && e1.irq_moderation_ms == 1,
        "event ring 1"
    );
    check!(
        e1.data_type == ErDataType::Data && e1.priority == 1,
        "ring 1 is data"
    );
    check!(
        ATH11K_MHI_CONFIG_QCN9074.ch_cfg[0].ee_mask == 0x14,
        "qcn9074 ee_mask"
    );
    check!(
        ATH11K_MHI_CONFIG_QCN9074.timeout_ms == 10000,
        "qcn9074 timeout"
    );
    let p = ControllerParams::ath11k(REG_LEN, 3);
    check!(
        p.iova_start == 0 && p.iova_stop == 0xf_ffff_ffff,
        "iova = 0..DMA_BIT_MASK(36)"
    );
    check!(
        p.coherent_mask == 0xffff_ffff,
        "coherent mask = DMA_BIT_MASK(32)"
    );
    check!(
        p.timeout_ms == 20000,
        "ath11k_mhi_start sets MHI_TIMEOUT_DEFAULT_MS"
    );
    check!(
        p.sbl_size == 0x8_0000 && p.seg_len == 0x8_0000 && p.fbc_download,
        "FBC 512K"
    );
    check!(ATH11K_RDDM_DUMP_SIZE == 0x420000, "RDDM_DUMP_SIZE");
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_mhi_config_matches_ath11k);

static BAD_CH: [ChannelConfig; 1] = [ChannelConfig {
    num: 128,
    ..ATH11K_MHI_CHANNELS_QCA6390[0]
}];
static ZERO_EL: [ChannelConfig; 1] = [ChannelConfig {
    num_elements: 0,
    ..ATH11K_MHI_CHANNELS_QCA6390[0]
}];
static BAD_CH_CFG: ControllerConfig = ControllerConfig {
    ch_cfg: &BAD_CH,
    ..ATH11K_MHI_CONFIG_QCA6390
};
static ZERO_EL_CFG: ControllerConfig = ControllerConfig {
    ch_cfg: &ZERO_EL,
    ..ATH11K_MHI_CONFIG_QCA6390
};

fn smoke_mhi_register_rejects_bad_config() -> TestResult {
    let p = ControllerParams::ath11k(REG_LEN, 3);
    let reject = |cfg: &'static ControllerConfig, p: ControllerParams| {
        matches!(
            MhiController::new(FakeMhi::new(Behaviour::default()), cfg, p),
            Err(MhiError { step, errno, .. }) if step == step::BAD_CONFIG && errno == errno::EINVAL
        )
    };
    check!(
        reject(&BAD_CH_CFG, p),
        "channel >= max_channels must be rejected"
    );
    check!(
        reject(&ZERO_EL_CFG, p),
        "zero-element channel must be rejected"
    );
    // mhi_init_irq_setup: event ring irq 2 needs nr_irqs >= 3.
    check!(
        reject(
            &ATH11K_MHI_CONFIG_QCA6390,
            ControllerParams::ath11k(REG_LEN, 2)
        ),
        "event ring irq beyond nr_irqs must be rejected"
    );
    check!(
        reject(&ATH11K_MHI_CONFIG_QCA6390, ControllerParams::ath11k(0, 3)),
        "zero reg_len must be rejected"
    );
    check!(
        MhiController::new(
            FakeMhi::new(Behaviour::default()),
            &ATH11K_MHI_CONFIG_QCA6390,
            p
        )
        .is_ok(),
        "the real config must be accepted"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_mhi_register_rejects_bad_config
);

// ── mhi_init_dev_ctxt / mhi_prepare_for_power_up ─────────────────

fn smoke_mhi_init_dev_ctxt_matches_linux() -> TestResult {
    let mut h = host(Behaviour::default());
    if h.prepare_for_power_up().is_err() {
        return TestResult::Fail("prepare_for_power_up failed");
    }
    let (chan, er, cmdc) = h.ctxt_addrs().unwrap();
    check!(chan + 128 * 44 - 1 <= DMA32, "channel contexts below 4 GiB");
    check!(
        er + 2 * 44 - 1 <= DMA32 && cmdc + 44 - 1 <= DMA32,
        "event/cmd contexts below 4 GiB"
    );
    // Channel contexts: configured ones carry brstmode + type + erindex.
    let ch = |n: u64, off: u64| phys_rd32(chan + n * 44 + off);
    check!(
        ch(20, 0) == 0x200,
        "ch20 chcfg = DISABLED | BRSTMODE_DISABLE<<8"
    );
    check!(
        ch(20, 4) == 1 && ch(20, 8) == 1,
        "ch20 chtype OUTBOUND, erindex 1"
    );
    check!(
        ch(21, 0) == 0x200 && ch(21, 4) == 2 && ch(21, 8) == 1,
        "ch21 INBOUND, erindex 1"
    );
    check!(
        ch(0, 0) == 0 && ch(0, 4) == 0 && ch(0, 8) == 0,
        "unconfigured channel all zero"
    );
    check!(
        phys_rd64(chan + 20 * 44 + 12) == 0,
        "channel ring not allocated until prepared"
    );
    // Event contexts.
    let ev = |n: u64, off: u64| phys_rd32(er + n * 44 + off);
    check!(
        ev(0, 0) == 0 && ev(0, 4) == 1 && ev(0, 8) == 1,
        "er0 intmod 0, VALID, msivec 1"
    );
    check!(
        ev(1, 0) == 1 << 16 && ev(1, 4) == 1 && ev(1, 8) == 2,
        "er1 INTMODT=1, msivec 2"
    );
    for (n, len) in [(0u64, 512u64), (1, 4096)] {
        let base = er + n * 44;
        let rbase = phys_rd64(base + 12);
        check!(
            phys_rd64(base + 20) == len,
            "event ring rlen = elements * 16"
        );
        check!(rbase % len == 0, "event ring aligned to its length");
        check!(rbase + len - 1 <= DMA32, "event ring below 4 GiB");
        check!(
            phys_rd64(base + 28) == rbase && phys_rd64(base + 36) == rbase,
            "er rp = wp = base"
        );
        check!(
            h.event_ring_info(n as usize) == Some((rbase, len as usize)),
            "host ring = ctxt"
        );
    }
    // Command context: 128 elements.
    let crbase = phys_rd64(cmdc + 12);
    check!(
        phys_rd64(cmdc + 20) == 2048 && crbase % 2048 == 0,
        "cmd ring 2048 bytes, aligned"
    );
    check!(
        phys_rd64(cmdc + 28) == crbase && phys_rd64(cmdc + 36) == crbase,
        "cmd rp = wp"
    );
    // BHI / BHIe offsets read, BHIe RX registers cleared (rddm_size set).
    check!(
        h.bhi_offsets() == (BHI, BHIE),
        "BHI/BHIe offsets taken from BHIOFF/BHIEOFF"
    );
    let w = h.bus.writes();
    let expect: Vec<(u32, u32)> = (0x60..=0x78).step_by(4).map(|o| (BHIE + o, 0)).collect();
    check!(
        w == expect,
        "prepare writes exactly the seven BHIe RX registers, zeroed"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_mhi_init_dev_ctxt_matches_linux
);

fn smoke_mhi_prepare_rejects_bad_offsets() -> TestResult {
    let mut h = host(Behaviour {
        bhi_off: REG_LEN,
        ..Behaviour::default()
    });
    let e = h.prepare_for_power_up();
    check!(
        matches!(
            e,
            Err(MhiError {
                step: step::BHI_OFFSET_RANGE,
                detail: REG_LEN,
                errno: errno::ERANGE
            })
        ),
        "BHIOFF >= reg_len must fail with -ERANGE"
    );
    check!(
        h.ctxt_addrs().is_none(),
        "context memory released on failure"
    );
    let mut h = host(Behaviour {
        bhie_off: REG_LEN + 4,
        ..Behaviour::default()
    });
    check!(
        matches!(
            h.prepare_for_power_up(),
            Err(MhiError {
                step: step::BHIE_OFFSET_RANGE,
                ..
            })
        ),
        "BHIEOFF >= reg_len must fail"
    );
    // A coherent mask no RAM satisfies: allocation fails, nothing high.
    let mut p = ControllerParams::ath11k(REG_LEN, 3);
    p.coherent_mask = 0xfff;
    let mut h = MhiController::new(
        FakeMhi::new(Behaviour::default()),
        &ATH11K_MHI_CONFIG_QCA6390,
        p,
    )
    .unwrap();
    check!(
        matches!(
            h.prepare_for_power_up(),
            Err(MhiError {
                step: step::NO_DMA_MEMORY,
                errno: errno::ENOMEM,
                ..
            })
        ),
        "unsatisfiable DMA mask must fail with -ENOMEM"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_mhi_prepare_rejects_bad_offsets
);

// ── full boot ────────────────────────────────────────────────────

const FW_LEN: usize = 3 * ATH11K_SBL_SIZE + 1000;

fn smoke_mhi_boot_to_mission_mode() -> TestResult {
    let fw = firmware(FW_LEN, false);
    let (mut h, r) = boot(Behaviour::default(), fw.clone());
    check!(r.is_ok(), "sync_power_up must reach mission mode");
    check!(
        h.ee == MhiEe::AMSS && h.pm_state == pm::M0,
        "AMSS + M0 after power up"
    );
    check!(h.serial_number() == 0x5e71_a10e, "BHI_SERIALNU captured");
    let w = h.bus.writes();
    let (chan, er, cmdc) = h.ctxt_addrs().unwrap();

    // mhi_async_power_up: BHI_INTVEC = 0 first after prepare.
    let i0 = find_write(&w, 0, BHI + BHI_INTVEC).unwrap_or(usize::MAX);
    check!(
        i0 == 7 && w[i0].1 == 0,
        "power up starts by zeroing BHI_INTVEC"
    );

    // mhi_fw_load_bhi: STATUS, ADDR_HIGH, ADDR_LOW, SIZE, TXDB in order.
    let b = find_write(&w, i0, BHI + BHI_STATUS).unwrap_or(0);
    check!(b > i0, "BHI programming present");
    check!(w[b].1 == 0, "BHI_STATUS cleared first");
    check!(w[b + 1].0 == BHI + BHI_IMGADDR_HIGH, "IMGADDR_HIGH second");
    check!(w[b + 2].0 == BHI + BHI_IMGADDR_LOW, "IMGADDR_LOW third");
    check!(
        w[b + 3] == (BHI + BHI_IMGSIZE, 0x8_0000),
        "IMGSIZE = sbl_size (512 KiB)"
    );
    check!(
        w[b + 4] == (BHI + BHI_IMGTXDB, SESSION),
        "IMGTXDB = random session id"
    );
    let img = ((w[b + 1].1 as u64) << 32) | w[b + 2].1 as u64;
    check!(
        w[b + 1].1 == 0 && img + 0x8_0000 - 1 <= DMA32,
        "SBL image below 4 GiB"
    );
    check!(
        h.bus.d.borrow().bhi_image == fw[..ATH11K_SBL_SIZE],
        "BHI carries the first 512 KiB"
    );

    // mhi_init_mmio: the 14 writes in Linux's reg_info order.
    let m = find_write(&w, b, CCABAP_HIGHER).unwrap_or(0);
    check!(m > b, "MMIO programmed after BHI");
    let expect = [
        (CCABAP_HIGHER, (chan >> 32) as u32),
        (CCABAP_LOWER, chan as u32),
        (ECABAP_HIGHER, (er >> 32) as u32),
        (ECABAP_LOWER, er as u32),
        (CRCBAP_HIGHER, (cmdc >> 32) as u32),
        (CRCBAP_LOWER, cmdc as u32),
        (MHICTRLBASE_HIGHER, 0),
        (MHICTRLBASE_LOWER, 0),
        (MHIDATABASE_HIGHER, 0),
        (MHIDATABASE_LOWER, 0),
        (MHICTRLLIMIT_HIGHER, 0xf),
        (MHICTRLLIMIT_LOWER, 0xffff_ffff),
        (MHIDATALIMIT_HIGHER, 0xf),
        (MHIDATALIMIT_LOWER, 0xffff_ffff),
        // MHICFG: NER = 2 (read-modify-write keeps the device's NCH),
        // then NHWER = 0.
        (MHICFG, 0x0002_0080),
        (MHICFG, 0x0002_0080),
    ];
    check!(
        w[m..m + expect.len()] == expect,
        "mhi_init_mmio register writes differ from Linux"
    );
    // Then every SW event ring gets base + len - 16 via its doorbell
    // (upper half first), then M0 is requested.
    let (r0, l0) = h.event_ring_info(0).unwrap();
    let (r1, l1) = h.event_ring_info(1).unwrap();
    let n = m + expect.len();
    let db0 = r0 + l0 as u64 - 16;
    let db1 = r1 + l1 as u64 - 16;
    check!(
        w[n] == (ERDB + 4, (db0 >> 32) as u32),
        "er0 doorbell upper half first"
    );
    check!(
        w[n + 1] == (ERDB, db0 as u32),
        "er0 doorbell = base + len - el"
    );
    check!(
        w[n + 2] == (ERDB + 12, (db1 >> 32) as u32),
        "er1 doorbell upper"
    );
    check!(
        w[n + 3] == (ERDB + 8, db1 as u32),
        "er1 doorbell = base + len - el"
    );
    check!(w[n + 4] == (MHICTRL, 0x200), "MHICTRL MHISTATE = M0");

    // M0 transition: wake doorbell (CHDB + 8*127) set then cleared.
    let wake = CHDB + 8 * 127;
    let k = find_write(&w, n + 4, wake + 4).unwrap_or(0);
    check!(k > n && w[k + 1] == (wake, 1), "M0 asserts device wake");
    check!(
        w[k + 2] == (wake + 4, 0) && w[k + 3] == (wake, 0),
        "then de-asserts it"
    );

    // mhi_fw_load_bhie: vector table address, size, doorbell.
    let v = find_write(&w, n, BHIE + BHIE_TXVECADDR_HIGH_OFFS).unwrap_or(0);
    check!(v > n, "BHIe programmed after SBL");
    check!(
        w[v + 1].0 == BHIE + BHIE_TXVECADDR_LOW_OFFS,
        "TXVECADDR_LOW"
    );
    let segs = FW_LEN.div_ceil(ATH11K_SEG_LEN);
    check!(
        w[v + 2] == (BHIE + BHIE_TXVECSIZE_OFFS, 16 * segs as u32),
        "TXVECSIZE = 16 * segments"
    );
    check!(
        w[v + 3] == (BHIE + BHIE_TXVECDB_OFFS, SESSION + 1),
        "TXVECDB = sequence id"
    );
    {
        let d = h.bus.d.borrow();
        check!(d.bhie_vec.len() == segs, "one vector entry per segment");
        for (i, &(a, l)) in d.bhie_vec.iter().enumerate() {
            let want = if i == segs - 1 {
                FW_LEN - i * ATH11K_SEG_LEN
            } else {
                ATH11K_SEG_LEN
            };
            check!(l == want as u64, "segment sizes: 512 KiB, last = remainder");
            check!(a + l - 1 <= DMA32, "segment below 4 GiB");
        }
        check!(
            d.bhie_image == fw,
            "BHIe carries the whole image (no second ELF header)"
        );
    }
    check!(h.fbc_table().map(|t| t.2) == Some(segs), "fbc table kept");
    let notes = h.bus.d.borrow().notes.clone();
    check!(notes.contains(&MhiNotify::FirstM0), "FirstM0 notified");
    check!(
        notes.contains(&MhiNotify::EeMissionMode),
        "MHI_CB_EE_MISSION_MODE notified"
    );
    check!(h.dev_wake_count() == 0, "wake votes balanced");
    check!(
        h.stats.events_without_irq == 0,
        "every event arrived with an MSI"
    );

    // ── mhi_prepare_for_transfer("IPCR") ─────────────────────────
    let before = h.bus.writes().len();
    check!(
        run(h.prepare_for_transfer("IPCR")).is_ok(),
        "IPCR channels start"
    );
    check!(
        h.bus.d.borrow().cmds == vec![(cmd::START_CHAN, 20), (cmd::START_CHAN, 21)],
        "START for ch20 then ch21"
    );
    check!(
        h.channel_state(20) == Some(ch_state::ENABLED),
        "ch20 enabled"
    );
    check!(
        h.channel_state(21) == Some(ch_state::ENABLED),
        "ch21 enabled"
    );
    for c in [20u64, 21] {
        let base = chan + c * 44;
        let rbase = phys_rd64(base + 12);
        check!(
            phys_rd32(base) == 0x201,
            "chcfg = ENABLED | BRSTMODE_DISABLE<<8"
        );
        check!(
            phys_rd64(base + 20) == 1024 && rbase % 1024 == 0,
            "64-element ring, aligned"
        );
        check!(rbase + 1023 <= DMA32, "transfer ring below 4 GiB");
    }
    // 63 receive buffers of buf_len on ch21, doorbell at the last.
    check!(h.free_desc_count(21) == 0, "every DL descriptor filled");
    check!(h.free_desc_count(20) == 63, "UL ring empty");
    let (t21, _) = h.chan_ring_info(21).unwrap();
    check!(
        h.bus.d.borrow().chan_db.get(&21) == Some(&(t21 + 63 * 16)),
        "ch21 doorbell = base + 63 elements"
    );
    check!(
        phys_rd64(chan + 21 * 44 + 36) == t21 + 63 * 16,
        "ch21 ctxt wp matches doorbell"
    );
    for i in 0..63u64 {
        let tre = rd_el(t21 + i * 16);
        check!(
            tre.dword[0] == 8192 && tre.dword[1] == 0x0002_0600,
            "DL TRE: 8192, BEI|IEOT"
        );
        check!(
            tre.ptr != 0 && tre.ptr + 8191 <= DMA32,
            "DL buffer below 4 GiB"
        );
    }
    let w = h.bus.writes();
    let dbs = w[before..].iter().filter(|x| x.0 == CHDB + 21 * 8).count();
    check!(
        dbs == 63,
        "one ch21 doorbell per queued buffer (MHI_DB_BRST_DISABLE)"
    );
    check!(
        h.dev_wake_count() == 0,
        "wake votes balanced after channel start"
    );
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_mhi_boot_to_mission_mode);

fn smoke_mhi_fbc_second_elf_header() -> TestResult {
    let fw = firmware(FW_LEN, true);
    let (h, r) = boot(Behaviour::default(), fw.clone());
    check!(r.is_ok(), "boot with combined SBL+WLAN image");
    let d = h.bus.d.borrow();
    check!(
        d.bhi_image == fw[..ATH11K_SBL_SIZE],
        "BHI still carries the SBL"
    );
    check!(
        d.bhie_image == fw[ATH11K_SBL_SIZE..],
        "BHIe skips the SBL when a 2nd ELF follows"
    );
    check!(
        d.bhie_vec.len() == (FW_LEN - ATH11K_SBL_SIZE).div_ceil(ATH11K_SEG_LEN),
        "segments counted from fw_sz - sbl_size"
    );
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_mhi_fbc_second_elf_header);

fn smoke_mhi_bhie_table_sizing_edges() -> TestResult {
    // Exact multiple of seg_len: full-size last segment.
    let fw = firmware(2 * ATH11K_SEG_LEN, false);
    let (h, r) = boot(Behaviour::default(), fw.clone());
    check!(r.is_ok(), "boot with a 1 MiB image");
    {
        let d = h.bus.d.borrow();
        check!(d.bhie_vec.len() == 2, "two segments for exactly 1 MiB");
        check!(
            d.bhie_vec.iter().all(|e| e.1 == 0x8_0000),
            "both segments full"
        );
        check!(d.bhie_image == fw, "image intact");
    }
    check!(
        h.fbc_table().map(|t| t.1) == Some(32),
        "vector table = 2 * 16 bytes"
    );
    // Image smaller than sbl_size: BHI gets the whole file.
    let fw = firmware(100 * 1024, false);
    let (h, r) = boot(Behaviour::default(), fw.clone());
    check!(r.is_ok(), "boot with a small image");
    let w = h.bus.writes();
    let s = find_write(&w, 0, BHI + BHI_IMGSIZE).unwrap();
    check!(w[s].1 == 100 * 1024, "IMGSIZE = min(sbl_size, fw size)");
    let d = h.bus.d.borrow();
    check!(
        d.bhie_vec.len() == 1 && d.bhie_vec[0].1 == 100 * 1024,
        "one short BHIe segment"
    );
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_mhi_bhie_table_sizing_edges);

fn smoke_mhi_power_up_from_amss_skips_download() -> TestResult {
    // MHI_POWER_UP_CAPABLE(AMSS): READY transition, no BHI.
    let beh = Behaviour {
        initial_ee: MhiEe::AMSS.0,
        initial_mhistatus: MHISTATUS_READY_MASK,
        ..Behaviour::default()
    };
    let (h, r) = boot(beh, firmware(FW_LEN, false));
    check!(r.is_ok(), "power up in AMSS reaches mission mode");
    let w = h.bus.writes();
    check!(
        find_write(&w, 0, BHI + BHI_IMGTXDB).is_none(),
        "no BHI download from AMSS"
    );
    check!(
        find_write(&w, 0, BHIE + BHIE_TXVECDB_OFFS).is_none(),
        "no BHIe download"
    );
    check!(
        find_write(&w, 0, CCABAP_LOWER).is_some(),
        "MMIO still programmed"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_mhi_power_up_from_amss_skips_download
);

// ── negative paths ───────────────────────────────────────────────

fn smoke_mhi_bhi_error_dumps_registers() -> TestResult {
    let beh = Behaviour {
        bhi: Xfer::Error(0xdead),
        ..Behaviour::default()
    };
    let (h, r) = boot(beh, firmware(FW_LEN, false));
    check!(
        r == Err(MhiError::new(step::BHI_ERROR, 0xdead, errno::EIO)),
        "BHI error must report BHI_ERRCODE with -EIO"
    );
    check!(
        h.pm_state == pm::FW_DL_ERR,
        "PM state FW_DL_ERR after a failed download"
    );
    check!(
        h.bus.logged("Reg: ERROR_CODE value: 0xdead"),
        "ERROR_CODE dumped"
    );
    check!(
        h.bus.logged("Reg: ERROR_DBG1 value: 0xdeae"),
        "ERROR_DBG1 dumped"
    );
    check!(
        h.bus.logged("Reg: ERROR_DBG3 value: 0xdeb0"),
        "ERROR_DBG3 dumped"
    );
    check!(
        find_write(&h.bus.writes(), 0, CCABAP_LOWER).is_none(),
        "no MMIO init after failure"
    );
    let fatal_wait = h.bus.now_ms();
    check!(
        fatal_wait < 1000,
        "FW_DL_ERR ends the power-up wait at once"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_mhi_bhi_error_dumps_registers
);

fn smoke_mhi_bhi_timeout() -> TestResult {
    let beh = Behaviour {
        bhi: Xfer::Hang,
        ..Behaviour::default()
    };
    let (h, r) = boot(beh, firmware(FW_LEN, false));
    check!(
        matches!(
            r,
            Err(MhiError {
                step: step::BHI_TIMEOUT,
                errno: errno::ETIMEDOUT,
                ..
            })
        ),
        "silent BHI must time out with -ETIMEDOUT"
    );
    let t = h.bus.now_ms();
    check!(
        (20000..20100).contains(&t),
        "BHI wait bounded by timeout_ms = 20000"
    );
    check!(h.pm_state == pm::FW_DL_ERR, "FW_DL_ERR after timeout");
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_mhi_bhi_timeout);

fn smoke_mhi_bhie_error() -> TestResult {
    let beh = Behaviour {
        bhie: Xfer::Error(0),
        ..Behaviour::default()
    };
    let (h, r) = boot(beh, firmware(FW_LEN, false));
    let raw = (BHIE_TXVECSTATUS_STATUS_ERROR << 30) | (SESSION + 1);
    check!(
        r == Err(MhiError::new(step::BHIE_ERROR, raw, errno::EIO)),
        "BHIe error must report TXVECSTATUS with -EIO"
    );
    check!(h.pm_state == pm::FW_DL_ERR, "FW_DL_ERR after BHIe failure");
    check!(h.ee == MhiEe::SBL, "stuck in SBL");
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_mhi_bhie_error);

fn smoke_mhi_sys_err_event_stops_boot() -> TestResult {
    let beh = Behaviour {
        syserr_event_after_bhie: true,
        ..Behaviour::default()
    };
    let (h, r) = boot(beh, firmware(FW_LEN, false));
    check!(
        matches!(
            r,
            Err(MhiError {
                step: step::SYS_ERR,
                ..
            })
        ),
        "SYS_ERR state-change event must fail bring-up"
    );
    check!(h.pm_state == pm::SYS_ERR_DETECT, "PM state SYS_ERR_DETECT");
    check!(
        h.bus.d.borrow().notes.contains(&MhiNotify::SysError),
        "MHI_CB_SYS_ERROR notified"
    );
    check!(
        h.bus.now_ms() < 1000,
        "SYS_ERR ends the wait without a timeout"
    );
    // MHISTATUS-detected SYS_ERR (intvec path) during SBL bring-up.
    let beh = Behaviour {
        syserr_after_bhi: true,
        ..Behaviour::default()
    };
    let (h, r) = boot(beh, firmware(FW_LEN, false));
    check!(
        matches!(r, Err(MhiError { step: step::SYS_ERR, detail, .. }) if detail == (1 << 8) | 0xff),
        "intvec SYS_ERR must report EE SBL"
    );
    check!(
        h.pm_state == pm::SYS_ERR_DETECT,
        "intvec SYS_ERR sets SYS_ERR_DETECT"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_mhi_sys_err_event_stops_boot
);

fn smoke_mhi_power_up_bad_ee() -> TestResult {
    for ee in [MhiEe::RDDM.0, MhiEe::SBL.0, 0xa] {
        let beh = Behaviour {
            initial_ee: ee,
            ..Behaviour::default()
        };
        let (h, r) = boot(beh, firmware(FW_LEN, false));
        check!(
            r == Err(MhiError::new(step::POWER_UP_BAD_EE, ee, errno::EIO)),
            "EE not power-up capable must be rejected with -EIO"
        );
        check!(h.pm_state == pm::DISABLE, "PM state back to DISABLE");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_mhi_power_up_bad_ee);

fn smoke_mhi_syserr_at_power_up_is_reset() -> TestResult {
    let syserr = (0xff << 8) | MHISTATUS_SYSERR_MASK;
    let beh = Behaviour {
        initial_mhistatus: syserr,
        ..Behaviour::default()
    };
    let (h, r) = boot(beh, firmware(FW_LEN, false));
    check!(r.is_ok(), "SYS_ERR at power up is reset and boot proceeds");
    let w = h.bus.writes();
    check!(w[7] == (BHI + BHI_INTVEC, 0), "INTVEC zeroed");
    check!(
        w[8] == (MHICTRL, MHICTRL_RESET_MASK),
        "MHICTRL.RESET requested"
    );
    check!(
        w[9] == (BHI + BHI_INTVEC, 0),
        "INTVEC re-programmed after reset"
    );
    let beh = Behaviour {
        initial_mhistatus: syserr,
        reset_clears: false,
        ..Behaviour::default()
    };
    let (h, r) = boot(beh, firmware(FW_LEN, false));
    check!(
        matches!(
            r,
            Err(MhiError {
                step: step::SYSERR_RESET_TIMEOUT,
                errno: errno::ETIMEDOUT,
                ..
            })
        ),
        "a reset that never clears must time out"
    );
    check!(
        h.pm_state == pm::DISABLE,
        "DISABLE after failed SYS_ERR reset"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_mhi_syserr_at_power_up_is_reset
);

fn smoke_mhi_ready_timeout() -> TestResult {
    let beh = Behaviour {
        sets_ready: false,
        ..Behaviour::default()
    };
    let (h, r) = boot(beh, firmware(FW_LEN, false));
    check!(
        matches!(
            r,
            Err(MhiError {
                step: step::READY_TIMEOUT,
                errno: errno::ETIMEDOUT,
                ..
            })
        ),
        "never-READY device must time out"
    );
    check!(h.pm_state == pm::FW_DL_ERR, "FW_DL_ERR after READY timeout");
    check!(
        h.fbc_table().is_none(),
        "fbc image freed (error_ready_state)"
    );
    // mhi_poll_reg_field: timeout_ms * 1000 / 25000 reads of MHISTATUS
    // for READY (plus the intvec reads between them).
    let sleeps = h.bus.ops().iter().filter(|o| **o == Op::Sleep(25)).count();
    check!(sleeps == 800, "READY polled 800 times, 25 ms apart");
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_mhi_ready_timeout);

fn smoke_mhi_mission_mode_bad_ee() -> TestResult {
    // EE event says AMSS but BHI_EXECENV still reads SBL.
    let beh = Behaviour {
        ee_after_bhie: MhiEe::SBL.0,
        ..Behaviour::default()
    };
    let (h, r) = boot(beh, firmware(FW_LEN, false));
    check!(
        r == Err(MhiError::new(
            step::MISSION_BAD_EE,
            MhiEe::SBL.0,
            errno::EIO
        )),
        "mission mode transition must re-read the EE"
    );
    check!(
        h.pm_state == pm::LD_ERR_FATAL_DETECT,
        "LD_ERR_FATAL_DETECT, as Linux"
    );
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_mhi_mission_mode_bad_ee);

fn smoke_mhi_no_firmware() -> TestResult {
    let mut h = host(Behaviour::default());
    check!(h.prepare_for_power_up().is_ok(), "prepare");
    let r = run(h.sync_power_up());
    check!(
        r == Err(MhiError::new(step::NO_FIRMWARE_IMAGE, 0, errno::EIO)),
        "PBL with no image must fail"
    );
    check!(h.pm_state == pm::FW_DL_ERR, "FW_DL_ERR without an image");
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_mhi_no_firmware);

fn smoke_mhi_works_without_msi() -> TestResult {
    let beh = Behaviour {
        irqs: false,
        ..Behaviour::default()
    };
    let (mut h, r) = boot(beh, firmware(FW_LEN, false));
    check!(
        r.is_ok(),
        "polling fallback reaches mission mode with no MSI"
    );
    check!(
        h.stats.events_without_irq > 0,
        "events found without an MSI are counted"
    );
    check!(h.stats.irqs == [0; 4], "no interrupts were seen");
    check!(
        run(h.prepare_for_transfer("IPCR")).is_ok(),
        "channels start without MSI"
    );
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_mhi_works_without_msi);

// ── channels ─────────────────────────────────────────────────────

fn booted() -> Option<Host> {
    let (mut h, r) = boot(
        Behaviour::default(),
        firmware(ATH11K_SBL_SIZE + 4096, false),
    );
    r.ok()?;
    run(h.prepare_for_transfer("IPCR")).ok()?;
    Some(h)
}

fn smoke_mhi_channel_start_failure() -> TestResult {
    let (mut h, r) = boot(
        Behaviour {
            cmd_ccs: ccs::UNDEFINED_ERR,
            ..Behaviour::default()
        },
        firmware(ATH11K_SBL_SIZE + 4096, false),
    );
    check!(r.is_ok(), "boot");
    let e = run(h.prepare_for_transfer("IPCR"));
    check!(
        e == Err(MhiError::new(
            step::CHAN_START,
            (20 << 8) | 0x10,
            errno::EIO
        )),
        "START completion with a non-success code must fail with -EIO"
    );
    let (chan, _, _) = h.ctxt_addrs().unwrap();
    check!(
        phys_rd64(chan + 20 * 44 + 12) == 0,
        "failed channel context torn down"
    );
    check!(
        phys_rd32(chan + 20 * 44) & 0xff == ch_state::DISABLED,
        "ctxt state DISABLED"
    );
    check!(
        h.channel_state(20) == Some(ch_state::DISABLED),
        "host state DISABLED"
    );
    check!(
        h.bus.d.borrow().cmds.len() == 1,
        "DL channel not started after UL failed"
    );
    check!(h.dev_wake_count() == 0, "wake vote released on failure");
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_mhi_channel_start_failure);

fn smoke_mhi_channel_wrong_ee() -> TestResult {
    let mut h = host(Behaviour::default());
    check!(h.prepare_for_power_up().is_ok(), "prepare");
    h.ee = MhiEe::SBL;
    let e = run(h.prepare_for_transfer("IPCR"));
    check!(
        e == Err(MhiError::new(
            step::CHAN_WRONG_EE,
            (20 << 8) | 1,
            errno::ENOTCONN
        )),
        "IPCR in SBL must be -ENOTCONN"
    );
    check!(h.bus.writes().len() == 7, "nothing written to the device");
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_mhi_channel_wrong_ee);

fn smoke_mhi_dl_and_event_ring_wraparound() -> TestResult {
    let mut h = match booted() {
        Some(h) => h,
        None => return TestResult::Fail("boot + IPCR start failed"),
    };
    // 300 packets: the 64-TRE channel ring wraps 4+ times and the
    // 256-element data event ring wraps once.
    let mut sent = 0u32;
    let mut got = 0u32;
    while sent < 300 {
        for _ in 0..10 {
            let len = 1 + (sent as usize * 37) % 8000;
            let payload: Vec<u8> = (0..len).map(|i| (i as u32 ^ sent) as u8).collect();
            check!(
                h.bus.send_dl(21, &payload, ccs::EOT),
                "device found a posted DL buffer"
            );
            sent += 1;
        }
        h.poll();
        while let Some(p) = h.take_dl() {
            let len = 1 + (got as usize * 37) % 8000;
            check!(p.data.len() == len, "DL length = event length");
            check!(
                p.data
                    .iter()
                    .enumerate()
                    .all(|(i, &b)| b == (i as u32 ^ got) as u8),
                "DL payload intact and in order"
            );
            got += 1;
        }
        check!(h.free_desc_count(21) == 0, "every consumed buffer recycled");
    }
    check!(got == 300, "all 300 DL packets delivered");
    check!(h.stats.dl_completed == 300, "300 DL completions");
    // Control ring (32 elements): 40 BW_REQ events in batches of 8.
    let before = h.stats.events[0];
    for _ in 0..5 {
        for _ in 0..8 {
            h.bus.post_ctrl(MhiRingElement {
                ptr: 0,
                dword: [0x2, 0x0150_0000],
            });
        }
        h.poll();
    }
    check!(
        h.stats.events[0] - before == 40,
        "40 control events across the ring wrap"
    );
    let bw = h
        .bus
        .d
        .borrow()
        .notes
        .iter()
        .filter(|n| **n == MhiNotify::BwReq { speed: 1, width: 2 })
        .count();
    check!(bw == 40, "MHI_CB_BW_REQ for each");
    // Event-ring doorbell keeps one element back: device side never
    // blocked, nothing left pending.
    check!(
        h.bus.d.borrow().ev_pending.iter().all(|q| q.is_empty()),
        "host returned every event element"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_mhi_dl_and_event_ring_wraparound
);

fn smoke_mhi_dl_overflow_drops_buffer() -> TestResult {
    let mut h = match booted() {
        Some(h) => h,
        None => return TestResult::Fail("boot + IPCR start failed"),
    };
    check!(
        h.bus.send_dl(21, b"too big", ccs::OVERFLOW),
        "device posts overflow"
    );
    h.poll();
    check!(
        h.take_dl().is_none(),
        "-EOVERFLOW is not delivered (qrtr dl callback)"
    );
    check!(
        h.free_desc_count(21) == 1,
        "and the buffer is not recycled, as in QRTR"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_mhi_dl_overflow_drops_buffer
);

fn smoke_mhi_ul_queue() -> TestResult {
    // Before the channel exists.
    let mut h = host(Behaviour::default());
    check!(
        matches!(
            h.queue_ul(b"x"),
            Err(MhiError {
                errno: errno::ENODEV,
                ..
            })
        ),
        "UL before prepare_for_transfer must be -ENODEV"
    );
    let mut h = match booted() {
        Some(h) => h,
        None => return TestResult::Fail("boot + IPCR start failed"),
    };
    check!(h.queue_ul(b"hello qrtr").is_ok(), "queue one UL packet");
    let (t20, _) = h.chan_ring_info(20).unwrap();
    let tre = rd_el(t20);
    check!(
        tre.dword[0] == 10 && tre.dword[1] == 0x0002_0600,
        "UL TRE: len, BEI|IEOT"
    );
    check!(tre.ptr + 9 <= DMA32, "UL bounce buffer below 4 GiB");
    h.poll();
    check!(
        h.bus.d.borrow().ul_rx == vec![b"hello qrtr".to_vec()],
        "device got the bytes"
    );
    check!(h.stats.ul_completed == 1, "UL completion processed");
    check!(h.free_desc_count(20) == 63, "UL descriptor released");
    check!(
        matches!(
            h.queue_ul(&vec![0u8; 0x1_0000]),
            Err(MhiError {
                errno: errno::EINVAL,
                ..
            })
        ),
        "a packet over the 16-bit TRE length must be rejected"
    );
    // Ring full: a device that never completes.
    let (mut h, r) = boot(
        Behaviour {
            ul_auto_complete: false,
            ..Behaviour::default()
        },
        firmware(ATH11K_SBL_SIZE + 4096, false),
    );
    check!(r.is_ok(), "boot");
    check!(run(h.prepare_for_transfer("IPCR")).is_ok(), "IPCR start");
    for _ in 0..63 {
        check!(h.queue_ul(b"q").is_ok(), "63 UL packets fit");
    }
    check!(
        matches!(
            h.queue_ul(b"q"),
            Err(MhiError {
                errno: errno::EAGAIN,
                ..
            })
        ),
        "the 64th must be -EAGAIN (ring full)"
    );
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_mhi_ul_queue);

fn smoke_mhi_msi_vector_layout() -> TestResult {
    use super::hw::{MSI_CONFIG_ONE, MSI_CONFIG_QCA6390};
    use super::pci::mhi_vector_cookie;
    // ath11k_mhi_get_msi with 32 vectors: irq[0..3] = vectors 0, 1, 2.
    for (i, want) in [
        (0u8, Some(1u64)),
        (1, Some(2)),
        (2, Some(4)),
        (3, None),
        (31, None),
    ] {
        check!(
            mhi_vector_cookie(&MSI_CONFIG_QCA6390, 0x40, 32, i) == want,
            "32-vector layout: MHI owns vectors 0..3, one irq[] entry each"
        );
    }
    // One shared vector: all three irq[] entries are vector 0.
    check!(
        mhi_vector_cookie(&MSI_CONFIG_ONE, 0x40, 1, 0) == Some(0b111),
        "single MSI carries irq[0..3]"
    );
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_mhi_msi_vector_layout);

// ── after mission mode (the runtime's MHI service) ───────────────

fn raise_intvec(h: &Host, mhistatus: u32, ee: MhiEe) {
    let d = &mut *h.bus.d.borrow_mut();
    d.regs.insert(MHISTATUS, mhistatus);
    d.regs.insert(BHI + BHI_EXECENV, ee.0);
    d.irqs |= 1;
}

fn smoke_mhi_runtime_state_changes() -> TestResult {
    let mut h = match booted() {
        Some(h) => h,
        None => return TestResult::Fail("boot + IPCR start failed"),
    };
    h.service();
    check!(h.take_reset_request().is_none(), "quiet device: no reset");
    check!(!h.irqs_pending(), "nothing pending");

    // The device enters M1: mhi_pm_m1_transition moves the host to M2
    // (MHICTRL.MHISTATE = M2) and, with no wake vote or pending packet,
    // reports MHI_CB_IDLE.
    let w0 = h.bus.writes().len();
    h.bus
        .post_ctrl(MhiRingElement::state_change_event(MhiState::M1.0));
    check!(h.irqs_pending(), "event-ring MSI pending");
    h.service();
    check!(
        h.pm_state == pm::M2 && h.dev_state == MhiState::M2,
        "M1 → M2"
    );
    let m2 = h.bus.writes()[w0..]
        .iter()
        .any(|&(a, v)| a == MHICTRL && field_get(MHICTRL_MHISTATE_MASK, v) == MhiState::M2.0);
    check!(m2, "host writes MHISTATE M2");
    check!(
        h.bus.d.borrow().notes.last() == Some(&MhiNotify::Idle),
        "MHI_CB_IDLE"
    );
    check!(h.take_reset_request().is_none(), "M2 is no crash");

    // Back to M0 (device-initiated): mhi_pm_m0_transition.
    let m0 = h.stats.m0_entries;
    h.bus
        .post_ctrl(MhiRingElement::state_change_event(MhiState::M0.0));
    h.service();
    check!(
        h.pm_state == pm::M0 && h.stats.m0_entries == m0 + 1,
        "M2 → M0"
    );
    check!(h.dev_wake_count() == 0, "M0 entry balances its wake vote");

    // A UL send from M2 rings the channel doorbell (db_access has M2).
    h.bus
        .post_ctrl(MhiRingElement::state_change_event(MhiState::M1.0));
    h.service();
    check!(h.pm_state == pm::M2, "M2 again");
    check!(h.queue_ul(b"hello").is_ok(), "UL in M2");
    h.service();
    check!(
        h.bus.d.borrow().ul_rx.last().map(|v| v.as_slice()) == Some(&b"hello"[..]),
        "UL reached the device from M2"
    );

    // An EE event re-announcing mission mode: the st_worker item is
    // dropped, not run.
    h.bus.post_ctrl(MhiRingElement::ee_event(MhiEe::AMSS.0));
    h.service();
    check!(h.pending_transitions() == 0, "transition dropped");
    check!(
        h.bus.logged("after mission mode ignored"),
        "dropped transition logged"
    );
    check!(h.take_reset_request().is_none(), "no reset for it");
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_mhi_runtime_state_changes);

fn smoke_mhi_runtime_crash_requests_reset() -> TestResult {
    let syserr = (0xff << 8) | MHISTATUS_SYSERR_MASK;
    // SYS_ERR in mission mode (intvec): MHI_CB_SYS_ERROR → reset.
    let mut h = match booted() {
        Some(h) => h,
        None => return TestResult::Fail("boot + IPCR start failed"),
    };
    raise_intvec(&h, syserr, MhiEe::AMSS);
    check!(h.irqs_pending(), "BHI / intvec MSI pending");
    h.service();
    check!(h.pm_state == pm::SYS_ERR_DETECT, "SYS_ERR_DETECT");
    check!(
        h.take_reset_request() == Some(MhiNotify::SysError),
        "SYS_ERROR queues reset_work"
    );
    check!(h.take_reset_request().is_none(), "taken once");
    check!(
        h.bus.logged("firmware crashed: MHI_CB_SYS_ERROR"),
        "ath11k_warn line"
    );
    // Another MSI while still in SYS_ERR: no second request.
    raise_intvec(&h, syserr, MhiEe::AMSS);
    h.service();
    check!(
        h.take_reset_request().is_none(),
        "consecutive SYS_ERROR not queued"
    );
    // In SYS_ERR_DETECT the control ring is not processed
    // (MHI_EVENT_ACCESS_INVALID), so an RDDM EE event is not seen there.
    h.bus.post_ctrl(MhiRingElement::ee_event(MhiEe::RDDM.0));
    h.service();
    check!(h.ee != MhiEe::RDDM, "ctrl ring idle in SYS_ERR_DETECT");
    // The device enters RDDM and raises the intvec: MHI_CB_EE_RDDM
    // queues a reset (the previous reason was SYS_ERROR), EE = RDDM.
    raise_intvec(&h, syserr, MhiEe::RDDM);
    h.service();
    check!(h.ee == MhiEe::RDDM, "EE RDDM");
    check!(
        h.take_reset_request() == Some(MhiNotify::EeRddm),
        "EE_RDDM queues reset_work"
    );
    // "do not queue again for consecutive RDDM event"
    raise_intvec(&h, syserr, MhiEe::RDDM);
    h.service();
    check!(
        h.take_reset_request().is_none(),
        "consecutive RDDM not queued"
    );
    check!(
        h.bus
            .logged("do not queue again for consecutive RDDM event"),
        "consecutive RDDM logged"
    );

    // The RDDM EE event on the control ring while in M0: EE_RDDM.
    let mut h = match booted() {
        Some(h) => h,
        None => return TestResult::Fail("boot + IPCR start failed"),
    };
    h.bus.post_ctrl(MhiRingElement::ee_event(MhiEe::RDDM.0));
    h.service();
    check!(
        h.take_reset_request() == Some(MhiNotify::EeRddm) && h.ee == MhiEe::RDDM,
        "RDDM EE event → EE_RDDM"
    );

    // SYS_ERR with the EE already RDDM (intvec): EE_RDDM, no SYS_ERROR.
    let mut h = match booted() {
        Some(h) => h,
        None => return TestResult::Fail("boot + IPCR start failed"),
    };
    raise_intvec(&h, syserr, MhiEe::RDDM);
    h.service();
    check!(
        h.take_reset_request() == Some(MhiNotify::EeRddm) && h.ee == MhiEe::RDDM,
        "intvec RDDM → EE_RDDM"
    );
    check!(
        !h.bus.d.borrow().notes.contains(&MhiNotify::SysError),
        "RDDM is not a SYS_ERROR"
    );

    // Not active (dev_state below M0): the RDDM intvec is ignored, as
    // Linux's mhi_is_active() check.
    let mut h = match booted() {
        Some(h) => h,
        None => return TestResult::Fail("boot + IPCR start failed"),
    };
    h.dev_state = MhiState::READY;
    raise_intvec(&h, syserr, MhiEe::RDDM);
    h.service();
    check!(h.take_reset_request().is_none(), "inactive: no RDDM");
    check!(h.ee != MhiEe::RDDM, "EE untouched");

    // A fatal error in PBL: MHI_CB_FATAL_ERROR then the SYS_ERR handler.
    let mut h = match booted() {
        Some(h) => h,
        None => return TestResult::Fail("boot + IPCR start failed"),
    };
    raise_intvec(&h, syserr, MhiEe::PBL);
    h.service();
    let notes = h.bus.d.borrow().notes.clone();
    check!(
        notes.ends_with(&[MhiNotify::FatalError, MhiNotify::SysError]),
        "FATAL_ERROR, SYS_ERROR"
    );
    check!(
        h.take_reset_request() == Some(MhiNotify::SysError),
        "PBL crash → reset"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_mhi_runtime_crash_requests_reset
);

// ── power cycle (ath11k_core_reset) ──────────────────────────────

fn smoke_mhi_power_cycle_reboots_firmware() -> TestResult {
    let mut h = match booted() {
        Some(h) => h,
        None => return TestResult::Fail("boot + IPCR start failed"),
    };
    // A crash first: the request is pending when the reset starts.
    raise_intvec(&h, (0xff << 8) | MHISTATUS_SYSERR_MASK, MhiEe::RDDM);
    h.service();
    check!(h.ee == MhiEe::RDDM, "crashed into RDDM");
    let w0 = h.bus.writes().len();
    let r = run(h.power_cycle());
    check!(r.is_ok(), "power cycle reaches mission mode with IPCR");
    let d = h.bus.d.borrow();
    check!(
        d.hif == [HifPower::Down, HifPower::Reset, HifPower::Up],
        "ath11k_pci_power_down then ath11k_pci_power_up"
    );
    check!(d.bhi_loads == 2, "firmware downloaded again over BHI");
    drop(d);
    let w = h.bus.writes();
    // mhi_pm_disable_transition: MHI RESET, then INTVEC re-programmed.
    let reset = w[w0..]
        .iter()
        .position(|&(a, v)| a == MHICTRL && v & MHICTRL_RESET_MASK != 0)
        .map(|i| i + w0);
    check!(reset.is_some(), "MHI RESET requested");
    let reset = reset.unwrap();
    check!(
        w[reset + 1..].first() == Some(&(BHI + BHI_INTVEC, 0)),
        "INTVEC re-programmed after the reset"
    );
    check!(h.ee.in_mission_mode(), "mission mode again");
    check!(h.pm_state == pm::M0, "M0");
    check!(
        h.channel_state(20) == Some(ch_state::ENABLED)
            && h.channel_state(21) == Some(ch_state::ENABLED),
        "IPCR started again"
    );
    check!(h.free_desc_count(21) == 0, "DL buffers queued again");
    check!(
        h.take_reset_request().is_none(),
        "old crash request dropped"
    );
    check!(h.failure.is_none(), "no failure");
    // QRTR traffic flows on the new rings.
    check!(h.queue_ul(b"after").is_ok(), "UL after the power cycle");
    h.service();
    check!(
        h.bus.d.borrow().ul_rx.last().map(|v| v.as_slice()) == Some(&b"after"[..]),
        "UL delivered"
    );
    check!(h.bus.send_dl(21, b"down", ccs::EOT), "DL buffer posted");
    h.service();
    check!(
        h.take_dl().map(|p| p.data) == Some(b"down".to_vec()),
        "DL delivered"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_mhi_power_cycle_reboots_firmware
);

fn smoke_mhi_power_down_states() -> TestResult {
    // Powered down twice: the second is "Already powered down".
    let mut h = match booted() {
        Some(h) => h,
        None => return TestResult::Fail("boot + IPCR start failed"),
    };
    run(h.power_down());
    check!(h.pm_state == pm::DISABLE, "PM DISABLE");
    check!(h.ee == MhiEe::DISABLE_TRANSITION, "EE DISABLE");
    check!(h.ctxt_addrs().is_none(), "contexts freed");
    check!(h.channel_state(20) == Some(ch_state::DISABLED), "IPCR down");
    check!(h.fbc_table().is_none(), "BHIe table freed");
    let n = h.bus.writes().len();
    run(h.power_down());
    check!(
        h.bus.writes().len() == n,
        "second power down touches nothing"
    );
    // A device that never clears MHI RESET: logged, power-down goes on.
    let beh = Behaviour {
        reset_clears: false,
        ..Behaviour::default()
    };
    let (mut h, r) = boot(beh, firmware(ATH11K_SBL_SIZE + 4096, false));
    check!(r.is_ok(), "boot");
    run(h.power_down());
    check!(
        h.bus.logged("device failed to clear MHI Reset"),
        "reset timeout logged"
    );
    check!(h.pm_state == pm::DISABLE, "still DISABLE");
    // A firmware image that fails BHI after the reset: the power cycle
    // reports it.
    let mut h = match booted() {
        Some(h) => h,
        None => return TestResult::Fail("boot"),
    };
    h.bus.beh.bhi = Xfer::Error(7);
    let r = run(h.power_cycle());
    check!(r.is_err(), "power-up failure surfaces");
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_mhi_power_down_states);
