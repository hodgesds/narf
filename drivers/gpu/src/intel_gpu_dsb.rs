//! Fixed MTL/Arrow Pipe-A DSB color transport. MIT Linux b90c984d:
//! intel_dsb.c (evasion, chain, DEwake, interrupt, idle/disable),
//! intel_color.c::icl_load_luts, skl_watermark.c::mtl_read_wm_latency,
//! intel_vblank.c (eDP scanline offset), xe/display/xe_dsb_buffer.c.
//! No IRQ delivery is needed: fresh engine status is polled by the KMS owner.
use crate::{
    intel_gpu_aux::MmioWindow,
    intel_gpu_gem::{GemObject, GemState, Placement},
    intel_gpu_ggtt_ranges::{Lease, Ledger},
    intel_gpu_gtt::{PteFormat, GGTT_ARRAY_BASE},
    intel_gpu_scanout_io::DisplayAccess,
};
use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::{fence, Ordering};
use narf_filesystem::FsError;

const PAGE: u64 = 4096;
const HALF: u64 = 8192;
const BYTES: u64 = HALF * 2;
const ENABLE: u32 = 1 << 31;
const BUSY: u32 = 1;
const PROG: u32 = 1;
const ERRORS: u32 = 0x1e; // MTL ATS + GTT + response timeout + poll failure
const INTS: u32 = PROG | ERRORS;
const PIPE_BITS: u32 = 3 << 13;
const IMR: u64 = 0x44404;
const IIR: u64 = 0x44408;
const IER: u64 = 0x4440c;
const FRAME: u64 = 0x70040;
fn reg(id: usize, offset: u64) -> u64 {
    0x70b00 + id as u64 * 0x100 + offset
}
fn cursor_watermark(register: u64) -> bool {
    matches!(
        register,
        0x70140
            | 0x70144
            | 0x70148
            | 0x7014c
            | 0x70150
            | 0x70154
            | 0x70158
            | 0x7015c
            | 0x70168
            | 0x7017c
    )
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Timing {
    pub(crate) clock: u32,
    pub(crate) width: u16,
    pub(crate) height: u16,
    pub(crate) htotal: u16,
    pub(crate) vtotal: u16,
    pub(crate) flags: u32,
}
impl Timing {
    pub(crate) fn valid(self) -> bool {
        self.clock != 0
            && self.width != 0
            && self.height > 1
            && self.width < self.htotal
            && self.height < self.vtotal
            && self.vtotal <= 8192
            && self.htotal <= 8192
            && self.flags & !15 == 0
    }
    fn lines(self, us: u32) -> u32 {
        (u64::from(us) * u64::from(self.clock)).div_ceil(u64::from(self.htotal) * 1000) as u32
    }
    fn hw(self, line: u32) -> u32 {
        (line + u32::from(self.vtotal) - 1) % u32::from(self.vtotal)
    }
    fn check(self, io: &impl MmioWindow) -> Result<u32, FsError> {
        if !self.valid() {
            return Err(FsError::Unsupported);
        }
        let packed = |high: u16, low: u16| (u32::from(high) - 1) << 16 | (u32::from(low) - 1);
        if io.read32(0x60000) != packed(self.htotal, self.width)
            || io.read32(0x6000c) != packed(self.vtotal, self.height)
            || io.read32(0x60010) != packed(self.vtotal, self.height)
            || io.read32(0x60420) & (ENABLE | (1 << 28) | (1 << 27)) != 0
            || io.read32(0x70008) & ((3 << 21) | (3 << 30)) != 3 << 30
            || io.read32(0x60800) & ENABLE != 0
            || io.read32(0x60900) & ENABLE != 0
        {
            return Err(FsError::Unsupported);
        }
        // MTL uses six 13-bit MMIO latencies, not the Gen12 pcode mailbox.
        let mut latency = [0u32; 6];
        for (pair, register) in [0x45780, 0x45784, 0x45788].into_iter().enumerate() {
            let value = io.read32(register);
            if value == u32::MAX {
                return Err(FsError::NoDevice);
            }
            latency[pair * 2] = value & 0x1fff;
            latency[pair * 2 + 1] = (value >> 16) & 0x1fff;
        }
        let first_zero = latency
            .iter()
            .enumerate()
            .skip(1)
            .find(|(_, v)| **v == 0)
            .map_or(6, |(i, _)| i);
        latency[first_zero..].fill(0);
        for i in 1..first_zero {
            latency[i] = latency[i].max(latency[i - 1]);
        }
        if latency[0] == 0 {
            latency[0] = 6;
            for v in &mut latency[1..first_zero] {
                *v += 6;
            }
        }
        let latency_lines = self.lines(*latency.iter().max().unwrap());
        if latency_lines + 1 >= u32::from(self.height)
            || self.lines(20) >= u32::from(self.height)
            || self.lines(100) >= u32::from(self.vtotal - self.height)
        {
            return Err(FsError::Unsupported);
        }
        Ok(u32::from(self.height) - latency_lines)
    }
}

struct Commands(Vec<u32>);
impl Commands {
    fn emit(&mut self, low: u32, high: u32) {
        if self.0.len() & 1 != 0 {
            self.0.push(0);
        }
        self.0.extend([low, high]);
    }
    fn write(&mut self, r: u64, value: u32) {
        self.emit(value, (1 << 24) | (15 << 20) | r as u32);
    }
    fn byte_write(&mut self, r: u64, value: u32, byte: u32) {
        self.emit(value, (1 << 24) | (byte << 20) | r as u32);
    }
    fn wait_out(&mut self, timing: Timing, low: u32, high: u32) {
        let low = timing.hw(low);
        let high = timing.hw(high);
        let window = (u64::from(high) << 20) | u64::from(low);
        self.emit(window as u32, (6 << 24) | (window >> 32) as u32);
    }
    fn finish(&mut self) {
        while self.0.len() % 16 != 0 {
            self.0.push(0);
        }
    }
    fn bytes(&self) -> Vec<u8> {
        self.0.iter().flat_map(|v| v.to_le_bytes()).collect()
    }
}

#[derive(Debug)]
pub(crate) struct Owner<M: DisplayAccess + Clone> {
    io: M,
    lease: Option<Lease>,
    object: Option<Arc<GemObject>>,
    installed: bool,
    armed: bool,
    chain: bool,
    heads: [u32; 2],
    tails: [u32; 2],
    saved: [[u32; 5]; 2], // control/chicken/interrupt enables/PMCTRL/PMCTRL2
    saved_ier: u32,
    saved_imr: u32,
    frame: u32,
    deadline: u64,
    complete: bool,
}
impl<M: DisplayAccess + Clone> Owner<M> {
    pub(crate) fn reserve(io: M, bar_len: u64) -> Result<Self, FsError> {
        if !io.access_ok() || io.read32(0x4804) != 4 {
            return Err(FsError::NoDevice);
        }
        let key = io.ggtt_key().ok_or(FsError::Unsupported)?;
        let lease = Ledger::for_bar(key, bar_len)?.reserve_dsb(BYTES)?;
        for page in 0..BYTES / PAGE {
            let r = GGTT_ARRAY_BASE + (lease.start / PAGE + page) * 8;
            if io.read32(r) != 0 || io.read32(r + 4) != 0 {
                return Err(FsError::Unsupported);
            }
        }
        let mut saved = [[0; 5]; 2];
        for (id, values) in saved.iter_mut().enumerate() {
            *values = [
                io.read32(reg(id, 8)),
                io.read32(reg(id, 0xf0)),
                io.read32(reg(id, 0x28)) & 0xffff0000,
                io.read32(reg(id, 0x38)),
                io.read32(reg(id, 0x3c)),
            ];
            if values.contains(&u32::MAX)
                || values[0] & (ENABLE | BUSY) != 0
                || values[4] & (1 << 23) != 0
            {
                return Err(FsError::Unsupported);
            }
            let head = io.read32(reg(id, 0));
            let tail = io.read32(reg(id, 4));
            let current = io.read32(reg(id, 0x2c));
            if io.read32(reg(id, 0x28)) == u32::MAX
                || head == u32::MAX
                || tail == u32::MAX
                || current == u32::MAX
                || head > tail
                || current != tail
                || head % 64 != 0
                || tail % 64 != 0
            {
                return Err(FsError::Unsupported);
            }
        }
        let gem = GemState::new();
        let handle = gem.create_placed(BYTES, None, Placement::SystemWc, |_, _| Ok(()))?;
        let object = gem.object(handle)?;
        gem.close(handle)?;
        let saved_ier = io.read32(IER);
        let saved_imr = io.read32(IMR);
        if saved_ier == u32::MAX || !io.access_ok() {
            return Err(FsError::NoDevice);
        }
        Ok(Self {
            io,
            lease: Some(lease),
            object: Some(object),
            installed: false,
            armed: false,
            chain: false,
            heads: [0; 2],
            tails: [0; 2],
            saved,
            saved_ier: saved_ier & PIPE_BITS,
            saved_imr: saved_imr & PIPE_BITS,
            frame: 0,
            deadline: 0,
            complete: false,
        })
    }
    pub(crate) fn armed(&self) -> bool {
        self.armed
    }
    pub(crate) fn exposed(&self) -> bool {
        self.installed || self.armed
    }
    fn read(&self, r: u64) -> Result<u32, FsError> {
        if !self.io.access_ok() {
            return Err(FsError::NoDevice);
        }
        let value = self.io.read32(r);
        if !self.io.access_ok() || (value == u32::MAX && r != IMR) {
            Err(FsError::NoDevice)
        } else {
            Ok(value)
        }
    }
    fn write(&self, r: u64, v: u32) -> Result<(), FsError> {
        self.read(r)?;
        self.io.write32(r, v);
        if !self.io.access_ok() {
            Err(FsError::NoDevice)
        } else {
            Ok(())
        }
    }
    fn checked(&self, r: u64, v: u32) -> Result<(), FsError> {
        self.write(r, v)?;
        if self.read(r)? != v {
            Err(FsError::NoDevice)
        } else {
            Ok(())
        }
    }
    pub(crate) fn arm(
        &mut self,
        timing: Timing,
        registers: &[(u64, u32)],
        lut: Option<&[u32]>,
        now: u64,
    ) -> Result<(), FsError> {
        if self.armed {
            return Err(FsError::Busy);
        }
        if !self.io.access_ok() {
            return Err(FsError::NoDevice);
        }
        let timing_check = timing.check(&self.io);
        // An unavailable read is a hard authority/power failure, even when
        // its all-ones value also resembles unsupported live timing flags.
        if !self.io.access_ok() {
            return Err(FsError::NoDevice);
        }
        let dewake = timing_check?;
        if lut.is_some_and(|lut| lut.len() != 1024) {
            return Err(FsError::InvalidData);
        }
        for id in 0..2 {
            if self.read(reg(id, 8))? & (ENABLE | BUSY) != 0 {
                return Err(FsError::Unsupported);
            }
        }
        self.complete = false;
        self.saved_ier = self.read(IER)? & PIPE_BITS;
        self.saved_imr = self.read(IMR)? & PIPE_BITS;
        let lease = self.lease.as_ref().ok_or(FsError::NoDevice)?;
        self.heads = [lease.start as u32, (lease.start + HALF) as u32];
        self.chain = lut.is_some();
        let mut sub = Commands(Vec::new());
        if let Some(lut) = lut {
            sub.write(0x4a400, 0);
            sub.write(0x4a400, 1 << 15);
            sub.emit(lut.len() as u32, (9 << 24) | 0x4a404);
            sub.0.extend_from_slice(lut);
            sub.write(0x4a400, 0);
            for r in [0x4a420, 0x4a424, 0x4a428, 0x4a430, 0x4a434, 0x4a438] {
                sub.write(r, 1 << 16);
            }
            sub.emit(1, 2 << 24); // +1us, mode's delayed-vblank interval is zero
            sub.emit(0, 7 << 24);
            sub.finish();
        }
        self.tails[1] = self.heads[1] + (sub.0.len() * 4) as u32;
        let mut main = Commands(Vec::new());
        // Non-arming offsets/coefficients precede Linux's hardware evasion.
        for &(r, v) in registers.iter().filter(|&&(r, _)| {
            !cursor_watermark(r)
                && !matches!(
                    r,
                    0x49028 | 0x4a480 | 0x701a4 | 0x7019c | 0x70080 | 0x70088 | 0x70084
                )
        }) {
            main.write(r, v);
        }
        main.emit(0, 6 << 24); // PSR wake race: PIPEDSL must leave zero
        main.wait_out(
            timing,
            u32::from(timing.height) - timing.lines(20),
            u32::from(timing.height),
        );
        for &(r, v) in registers.iter().filter(|&&(r, _)| r == 0x4a480) {
            main.write(r, v);
        }
        for &(r, v) in registers.iter().filter(|&&(r, _)| r == 0x49028) {
            main.write(r, v);
        }
        // intel_atomic_dsb_finish: color arm precedes plane arm within the
        // same evaded safe window. skl_plane_update_arm emits the linear
        // source OFFSET before SURF; it must not escape into the earlier
        // non-arming coefficient prefix when the viewport changes.
        for &(r, v) in registers.iter().filter(|&&(r, _)| r == 0x701a4) {
            main.write(r, v);
        }
        for &(r, v) in registers.iter().filter(|&&(r, _)| r == 0x7019c) {
            main.write(r, v);
        }
        // intel_cursor.c::i9xx_cursor_update_arm writes WM/DDB immediately
        // before CTL/POS/BASE. Keep all of them after the same evasion: zero
        // watermarks must not latch before an old visible cursor is disabled.
        for &(r, v) in registers.iter().filter(|&&(r, _)| cursor_watermark(r)) {
            main.write(r, v);
        }
        // CTL may arm cursor enable; POS/BASE retain the source ordering.
        for register in [0x70080, 0x70088, 0x70084] {
            for &(r, v) in registers.iter().filter(|&&(r, _)| r == register) {
                main.write(r, v);
            }
        }
        if self.chain {
            main.write(reg(1, 8), ENABLE | (1 << 28));
            main.write(reg(1, 0xf0), 0);
            main.write(reg(1, 0x28), INTS | (INTS << 16));
            main.write(reg(1, 0x38), ENABLE | timing.hw(dewake));
            main.write(reg(1, 0), self.heads[1]);
            main.write(reg(1, 4), self.tails[1]);
            main.byte_write(reg(0, 0x3c), 1 << 23, 4);
            main.wait_out(timing, dewake, u32::from(timing.height));
            main.byte_write(reg(0, 0x3c), 0, 4);
        } else {
            main.emit(1, 4 << 24);
            main.emit(1, 2 << 24);
            main.emit(0, 7 << 24);
        }
        main.finish();
        self.tails[0] = self.heads[0] + (main.0.len() * 4) as u32;
        if main.0.len() * 4 > HALF as usize || sub.0.len() * 4 > HALF as usize {
            return Err(FsError::InvalidData);
        }
        let object = self.object.as_ref().ok_or(FsError::NoDevice)?;
        object.write(0, &main.bytes())?;
        if self.chain {
            object.write(HALF, &sub.bytes())?;
        }
        if !object.publish_for_device() {
            return Err(FsError::NoDevice);
        }
        let pages: Vec<u64> = object.pages().collect();
        // From the first PTE write every failure retains the BO and lease.
        self.installed = true;
        for (page, phys) in pages.into_iter().enumerate() {
            let pte = PteFormat::XeLpg
                .encode_ggtt(phys, 1)
                .map_err(|_| FsError::InvalidData)?;
            let r = GGTT_ARRAY_BASE + (lease.start / PAGE + page as u64) * 8;
            if self.read(r)? != 0 && self.read(r)? != pte as u32 {
                return Err(FsError::NoDevice);
            }
            if self.read(r + 4)? != 0 && self.read(r + 4)? != (pte >> 32) as u32 {
                return Err(FsError::NoDevice);
            }
            self.checked(r, pte as u32)?;
            self.checked(r + 4, (pte >> 32) as u32)?;
        }
        fence(Ordering::SeqCst);
        self.checked(IMR, self.read(IMR)? | PIPE_BITS)?;
        self.checked(IER, self.read(IER)? | PIPE_BITS)?;
        for id in 0..2 {
            self.write(reg(id, 0x28), INTS | (INTS << 16))?;
            if self.read(reg(id, 0x28))? & INTS != 0 {
                return Err(FsError::NoDevice);
            }
        }
        for _ in 0..2 {
            self.write(IIR, PIPE_BITS)?;
        }
        self.frame = self.read(FRAME)?;
        self.deadline = now.saturating_add(1_000_000_000);
        // Publish pending before the tail trigger; a dropped waiter is no stop.
        self.armed = true;
        self.checked(reg(0, 8), ENABLE)?;
        self.checked(reg(0, 0xf0), 0)?;
        self.checked(reg(0, 0x38), 0)?;
        self.checked(reg(0, 0), self.heads[0])?;
        self.checked(reg(0, 4), self.tails[0])?;
        Ok(())
    }
    pub(crate) fn stamp(&self, now: u64) -> Result<crate::drm::card::FlipStamp, FsError> {
        if !self.complete {
            return Err(FsError::Busy);
        }
        Ok(crate::drm::card::FlipStamp {
            ns: now,
            sequence: self.read(FRAME)?,
        })
    }
    fn terminal(&self, id: usize) -> Result<bool, FsError> {
        let ctl = self.read(reg(id, 8))?;
        Ok(ctl & BUSY == 0 && self.read(reg(id, 0x2c))? == self.tails[id])
    }
    /// DSB0 can start DSB1. Prove/disable 0 first, then prove/disable 1;
    /// neither a fresh primary latch nor GT reset is command-DMA retirement.
    pub(crate) fn poll(&mut self, now: u64) -> Result<bool, FsError> {
        if self.complete {
            return Ok(true);
        }
        if !self.armed {
            return Err(FsError::Busy);
        }
        for id in 0..=usize::from(self.chain) {
            if self.read(reg(id, 0x28))? & ERRORS != 0 {
                return Err(FsError::NoDevice);
            }
        }
        let leaf = usize::from(self.chain);
        if !self.terminal(0)? || self.read(reg(leaf, 0x28))? & PROG == 0 {
            return if now >= self.deadline {
                Err(FsError::TimedOut)
            } else {
                Ok(false)
            };
        }
        self.checked(reg(0, 8), 0)?;
        if self.chain {
            if !self.terminal(1)? {
                return if now >= self.deadline {
                    Err(FsError::TimedOut)
                } else {
                    Ok(false)
                };
            }
            self.checked(reg(1, 8), 0)?;
        }
        let before = self.read(FRAME)?;
        let after = self.read(FRAME)?;
        if before != after || before == self.frame {
            return if now >= self.deadline {
                Err(FsError::TimedOut)
            } else {
                Ok(false)
            };
        }
        self.complete = true;
        Ok(true)
    }
    /// Only a fresh, independently authorized view may observe old transport
    /// after reset. Failure keeps all old DMA mappings and lease retained.
    pub(crate) fn recover_view(&mut self, fresh: M, now: u64) {
        self.io = fresh;
        self.deadline = now.saturating_add(1_000_000_000);
    }
    pub(crate) fn shutdown(&mut self) -> Result<(), FsError> {
        if self.armed && !self.complete {
            return Err(FsError::Busy);
        }
        // Even failed pre-trigger mapping may be cleared only after disabled
        // idle evidence. Never infer retirement from a HALT write or timeout.
        for id in 0..2 {
            if self.read(reg(id, 8))? & (ENABLE | BUSY) != 0 {
                return Err(FsError::Busy);
            }
        }
        if self.installed {
            // Keep the same WC BO/PTE/VA for this Device's entire lifetime.
            // Xe GGTT removal requires a global invalidation owner; disabled
            // DSB alone is not a translation-cache invalidation witness.
            for id in 0..2 {
                self.checked(reg(id, 8), self.saved[id][0])?;
                self.checked(reg(id, 0xf0), self.saved[id][1])?;
                self.write(reg(id, 0x28), INTS | self.saved[id][2])?;
                self.checked(reg(id, 0x38), self.saved[id][3])?;
                self.checked(reg(id, 0x3c), self.saved[id][4])?;
            }
            for _ in 0..2 {
                self.write(IIR, PIPE_BITS)?;
            }
            self.checked(IER, (self.read(IER)? & !PIPE_BITS) | self.saved_ier)?;
            self.checked(IMR, (self.read(IMR)? & !PIPE_BITS) | self.saved_imr)?;
        }
        self.armed = false;
        self.complete = false;
        Ok(())
    }
}
impl<M: DisplayAccess + Clone> Drop for Owner<M> {
    fn drop(&mut self) {
        if self.installed || self.armed {
            // No MMIO from Drop. Even after natural command retirement the
            // installed same-BO/VA mapping stays retained: we do not own a
            // global GGTT translation invalidation/rebind protocol.
            if let Some(object) = self.object.take() {
                core::mem::forget(object);
            }
            if let Some(lease) = self.lease.take() {
                core::mem::forget(lease);
            }
            core::mem::forget(self.io.clone());
        }
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "intel_gpu_dsb_tests.rs"]
mod tests;
