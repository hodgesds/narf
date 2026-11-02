//! Gen12 Wa22011802037 before GRDOM_FULL, after GuC is stopped.
//!
//! MIT Linux b90c984d: i915/gt/intel_engine_cs.c __intel_engine_stop_cs,
//! __cs_pending_mi_force_wakes, __gpm_wait_for_fw_complete; intel_reset.c
//! intel_engine_reset_needs_wa_22011802037. Engine bases/fuse polarity and
//! media forcewake domains: xe_hw_engine.c read_media_fuses / engine_infos,
//! xe_force_wake.c and regs/xe_{gt,engine}_regs.h. No GuC-only reset uses
//! this workaround and no fused-off engine register is accessed.
use crate::{intel_gpu_aux::MmioWindow, intel_gpu_gt_hw::HardwareError};
use core::task::Poll;

const WAKE_NS: u64 = 50_000_000;
const IDLE_NS: u64 = 100_000_000;
const GPM_NS: u64 = 5_000_000;
const SETTLE_NS: u64 = 1_000;

#[derive(Clone, Copy)]
struct Engine {
    base: u64,
    msg: u64,
    request: u64,
    ack: u64,
}
const ENGINES: [Engine; 14] = [
    Engine {
        base: 0x2000,
        msg: 0x8000,
        request: 0,
        ack: 0,
    },
    Engine {
        base: 0x22000,
        msg: 0x800c,
        request: 0,
        ack: 0,
    },
    Engine {
        base: 0x1c0000,
        msg: 0x8004,
        request: 0xa540,
        ack: 0xd50,
    },
    Engine {
        base: 0x1c4000,
        msg: 0x8008,
        request: 0xa544,
        ack: 0xd54,
    },
    Engine {
        base: 0x1d0000,
        msg: 0x80c0,
        request: 0xa548,
        ack: 0xd58,
    },
    Engine {
        base: 0x1d4000,
        msg: 0x80c4,
        request: 0xa54c,
        ack: 0xd5c,
    },
    Engine {
        base: 0x1e0000,
        msg: 0x80c8,
        request: 0xa550,
        ack: 0xd60,
    },
    Engine {
        base: 0x1e4000,
        msg: 0x80cc,
        request: 0xa554,
        ack: 0xd64,
    },
    Engine {
        base: 0x1f0000,
        msg: 0x80d0,
        request: 0xa558,
        ack: 0xd68,
    },
    Engine {
        base: 0x1f4000,
        msg: 0x80d4,
        request: 0xa55c,
        ack: 0xd6c,
    },
    Engine {
        base: 0x1c8000,
        msg: 0x8010,
        request: 0xa560,
        ack: 0xd70,
    },
    Engine {
        base: 0x1d8000,
        msg: 0x80d8,
        request: 0xa564,
        ack: 0xd74,
    },
    Engine {
        base: 0x1e8000,
        msg: 0x80dc,
        request: 0xa568,
        ack: 0xd78,
    },
    Engine {
        base: 0x1f8000,
        msg: 0x80e0,
        request: 0xa56c,
        ack: 0xd7c,
    },
];
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    Discover,
    Acquire,
    Idle,
    Receive,
    Power,
    Acknowledge,
    Prepared,
    Held,
    Release,
    Done,
}

/// Owns only kernel forcewake bit0 of physically present media domains.
/// Failure does not clear a request or return an engine/firmware DMA owner.
#[derive(Debug)]
pub(crate) struct Reset {
    stage: Stage,
    present: Option<u16>,
    owned: u16,
    pending: u32,
    deadline: u64,
    failed: Option<HardwareError>,
}
impl Reset {
    pub(crate) fn new(now: u64) -> Result<Self, HardwareError> {
        Ok(Self {
            stage: Stage::Discover,
            present: None,
            owned: 0,
            pending: 0,
            deadline: until(now, WAKE_NS)?,
            failed: None,
        })
    }
    /// A new reset attempt keeps uncertain prior media ownership. Only a
    /// fresh complete stop/GPM/full-reset/DMA/ACK proof may release it.
    pub(crate) fn restart(&mut self, now: u64) -> Result<(), HardwareError> {
        self.stage = Stage::Discover;
        self.pending = 0;
        self.deadline = until(now, WAKE_NS)?;
        self.failed = None;
        Ok(())
    }
    pub(crate) fn released(&self) -> bool {
        self.stage == Stage::Done && self.owned == 0
    }
    pub(crate) fn releasing(&self) -> bool {
        self.stage == Stage::Release
    }
    /// Keep the exact already-owned media requests through scheduling. No
    /// release/reacquire gap and no second wake owner is introduced.
    /// # Safety
    /// The caller freshly proved GuC reset/DMA idle and GRDOM_FULL self-clear
    /// after poll_prepare. It retains this owner until a complete stop.
    pub(crate) unsafe fn retain_after_full_reset(
        &mut self,
        mmio: &impl MmioWindow,
        mut current: impl FnMut() -> bool,
    ) -> Result<(), HardwareError> {
        if self.failed.is_some() || self.stage != Stage::Prepared {
            return Err(HardwareError::Busy);
        }
        {
            let mut io = Io::new(mmio, &mut current);
            io.guc_stopped()?;
            if io.read(0x941c)? != 0 {
                return Err(HardwareError::Unavailable);
            }
        }
        self.stage = Stage::Held;
        self.held_current(mmio, &mut current)
    }
    pub(crate) fn held_current(
        &self,
        mmio: &impl MmioWindow,
        current: impl FnMut() -> bool,
    ) -> Result<(), HardwareError> {
        if self.failed.is_some() || self.stage != Stage::Held {
            return Err(HardwareError::WakeLost);
        }
        let mut io = Io::new(mmio, current);
        io.awake()?;
        let fuse = io.read(0x9140)?;
        let present = 3 | (((!fuse & 255) as u16) << 2) | (((!fuse >> 16 & 15) as u16) << 10);
        if self.present != Some(present) || self.owned != present & !3 {
            return Err(HardwareError::WakeLost);
        }
        for (index, engine) in ENGINES.iter().enumerate().skip(2) {
            if self.owned & (1 << index) != 0 {
                io.media_awake(engine)?;
            }
        }
        Ok(())
    }
    pub(crate) fn poll_prepare(
        &mut self,
        mmio: &impl MmioWindow,
        now: u64,
        current: impl FnMut() -> bool,
    ) -> Poll<Result<(), HardwareError>> {
        if let Some(error) = self.failed {
            return Poll::Ready(Err(error));
        }
        let result = self.prepare_inner(&mut Io::new(mmio, current), now);
        if let Poll::Ready(Err(error)) = result {
            self.failed = Some(error);
        }
        result
    }
    fn prepare_inner(
        &mut self,
        io: &mut Io<'_, impl MmioWindow, impl FnMut() -> bool>,
        now: u64,
    ) -> Poll<Result<(), HardwareError>> {
        // A partial initial bring-up can reach teardown before it ever
        // stopped inherited firmware. Wake alone never supplies that proof.
        // Recheck on every phase so GuC cannot reschedule during CS/GPM drain.
        io.guc_stopped()?;
        match self.stage {
            Stage::Discover => {
                let fuse = io.read(0x9140)?;
                if fuse != io.read(0x9140)? {
                    return Poll::Ready(Err(HardwareError::Unavailable));
                }
                let present =
                    3 | (((!fuse & 255) as u16) << 2) | (((!fuse >> 16 & 15) as u16) << 10);
                if self.present.is_some_and(|old| old != present) {
                    return Poll::Ready(Err(HardwareError::Unavailable));
                }
                self.present = Some(present);
                for (index, engine) in ENGINES.iter().enumerate().skip(2) {
                    let bit = 1 << index;
                    if present & bit == 0 {
                        continue;
                    }
                    let request = io.read(engine.request)?;
                    let ack = io.read(engine.ack)?;
                    if self.owned & bit == 0 && (request | ack) & 1 != 0 {
                        return Poll::Ready(Err(HardwareError::Busy));
                    }
                    self.owned |= bit; // Retain before exposing the write.
                    io.write(engine.request, 0x00010001)?;
                    if io.read(engine.request)? & 1 == 0 {
                        return Poll::Ready(Err(HardwareError::Unavailable));
                    }
                }
                self.deadline = until(now, WAKE_NS)?;
                self.stage = Stage::Acquire;
            }
            Stage::Acquire => {
                let mut ready = true;
                for (index, engine) in ENGINES.iter().enumerate().skip(2) {
                    if self.owned & (1 << index) == 0 {
                        continue;
                    }
                    if io.read(engine.request)? & 1 == 0 {
                        return Poll::Ready(Err(HardwareError::WakeLost));
                    }
                    ready &= io.read(engine.ack)? & 1 != 0;
                }
                if !ready {
                    if now >= self.deadline {
                        return Poll::Ready(Err(HardwareError::Timeout));
                    }
                    return Poll::Pending;
                }
                for (index, engine) in ENGINES.iter().enumerate() {
                    if self.present.unwrap_or(0) & (1 << index) == 0 {
                        continue;
                    }
                    io.media_awake(engine)?;
                    io.write(engine.base + 0x9c, 0x01000100)?;
                    io.write(engine.base + 0x29c, 0x04000400)?;
                    if io.read(engine.base + 0x29c)? & 0x400 == 0 {
                        return Poll::Ready(Err(HardwareError::Unavailable));
                    }
                }
                self.deadline = until(now, IDLE_NS)?;
                self.stage = Stage::Idle;
            }
            Stage::Idle => {
                if !self.cs_idle(io)? {
                    if now >= self.deadline {
                        return Poll::Ready(Err(HardwareError::Timeout));
                    }
                    return Poll::Pending;
                }
                self.deadline = until(now, SETTLE_NS)?;
                self.stage = Stage::Receive;
            }
            Stage::Receive => {
                if now < self.deadline {
                    return Poll::Pending;
                }
                self.pending = 0;
                for (index, engine) in ENGINES.iter().enumerate() {
                    if self.present.unwrap_or(0) & (1 << index) == 0 {
                        continue;
                    }
                    io.media_awake(engine)?;
                    let value = io.read(engine.msg)?;
                    self.pending |= (value & (value >> 16) & 0x3e00) >> 9;
                }
                self.deadline = until(now, GPM_NS)?;
                self.stage = Stage::Power;
            }
            Stage::Power => {
                if io.read(0xa2a0)? & self.pending != self.pending {
                    if now >= self.deadline {
                        return Poll::Ready(Err(HardwareError::Timeout));
                    }
                    return Poll::Pending;
                }
                self.deadline = until(now, SETTLE_NS)?;
                self.stage = Stage::Acknowledge;
            }
            Stage::Acknowledge => {
                if now < self.deadline {
                    return Poll::Pending;
                }
                if !self.cs_idle(io)? {
                    return Poll::Ready(Err(HardwareError::Unavailable));
                }
                self.stage = Stage::Prepared;
                return Poll::Ready(Ok(()));
            }
            Stage::Prepared => {
                io.awake()?;
                return Poll::Ready(Ok(()));
            }
            _ => return Poll::Ready(Err(HardwareError::Busy)),
        }
        Poll::Pending
    }
    fn cs_idle(
        &self,
        io: &mut Io<'_, impl MmioWindow, impl FnMut() -> bool>,
    ) -> Result<bool, HardwareError> {
        let mut idle = true;
        for (index, engine) in ENGINES.iter().enumerate() {
            if self.present.unwrap_or(0) & (1 << index) == 0 {
                continue;
            }
            io.media_awake(engine)?;
            let mode = io.read(engine.base + 0x9c)?;
            idle &= mode & 0x300 == 0x300;
            if io.read(engine.base + 0x29c)? & 0x400 == 0 {
                return Err(HardwareError::Unavailable);
            }
        }
        Ok(idle)
    }
    /// # Safety
    /// The caller proved GRDOM_FULL self-clear, GuC reset status and idle
    /// firmware DMA after poll_prepare succeeded. No engine can submit work.
    /// Keep all GT/DMA owners and both base wake holds through poll_release.
    pub(crate) unsafe fn begin_release_after_full_reset(
        &mut self,
        mmio: &impl MmioWindow,
        now: u64,
        current: impl FnMut() -> bool,
    ) -> Result<(), HardwareError> {
        if self.failed.is_some() || self.stage != Stage::Prepared {
            return Err(HardwareError::Busy);
        }
        let mut io = Io::new(mmio, current);
        self.deadline = until(now, WAKE_NS)?;
        self.stage = Stage::Release;
        let result = (|| {
            for (index, engine) in ENGINES.iter().enumerate().skip(2) {
                if self.owned & (1 << index) == 0 {
                    continue;
                }
                io.write(engine.request, 0x00010000)?;
                if io.read(engine.request)? & 1 != 0 {
                    return Err(HardwareError::Unavailable);
                }
            }
            Ok(())
        })();
        if let Err(error) = result {
            self.failed = Some(error);
        }
        result
    }
    pub(crate) fn poll_release(
        &mut self,
        mmio: &impl MmioWindow,
        now: u64,
        current: impl FnMut() -> bool,
    ) -> Poll<Result<(), HardwareError>> {
        if let Some(error) = self.failed {
            return Poll::Ready(Err(error));
        }
        let mut io = Io::new(mmio, current);
        let result = (|| {
            io.awake()?;
            if self.stage == Stage::Done {
                return Poll::Ready(Ok(()));
            }
            if self.stage != Stage::Release {
                return Poll::Ready(Err(HardwareError::Busy));
            }
            if io.read(0x941c)? & 9 != 0 || io.read(0xc000)? & 1 == 0 || io.read(0xc314)? & 1 != 0 {
                return Poll::Ready(Err(HardwareError::Unavailable));
            }
            for (index, engine) in ENGINES.iter().enumerate().skip(2) {
                let bit = 1 << index;
                if self.owned & bit == 0 {
                    continue;
                }
                if io.read(engine.request)? & 1 != 0 {
                    return Poll::Ready(Err(HardwareError::Unavailable));
                }
                if io.read(engine.ack)? & 1 == 0 {
                    self.owned &= !bit;
                }
            }
            if self.owned != 0 {
                if now >= self.deadline {
                    return Poll::Ready(Err(HardwareError::Timeout));
                }
                return Poll::Pending;
            }
            self.stage = Stage::Done;
            Poll::Ready(Ok(()))
        })();
        if let Poll::Ready(Err(error)) = result {
            self.failed = Some(error);
        }
        result
    }
}
fn until(now: u64, duration: u64) -> Result<u64, HardwareError> {
    now.checked_add(duration).ok_or(HardwareError::Timeout)
}
struct Io<'a, M, F> {
    mmio: &'a M,
    current: F,
    lost: bool,
}
impl<'a, M: MmioWindow, F: FnMut() -> bool> Io<'a, M, F> {
    fn new(mmio: &'a M, current: F) -> Self {
        Self {
            mmio,
            current,
            lost: false,
        }
    }
    fn raw(&mut self, reg: u64) -> Result<u32, HardwareError> {
        if self.lost || !(self.current)() {
            self.lost = true;
            return Err(HardwareError::Unavailable);
        }
        let value = self.mmio.read32(reg);
        if value == u32::MAX {
            self.lost = true;
            return Err(HardwareError::Unavailable);
        }
        Ok(value)
    }
    fn awake(&mut self) -> Result<(), HardwareError> {
        for reg in [0xa188, 0x130044, 0xa278, 0xd84] {
            if self.raw(reg)? & 1 == 0 {
                self.lost = true;
                return Err(HardwareError::WakeLost);
            }
        }
        Ok(())
    }
    fn read(&mut self, reg: u64) -> Result<u32, HardwareError> {
        self.awake()?;
        self.raw(reg)
    }
    fn guc_stopped(&mut self) -> Result<(), HardwareError> {
        if self.read(0x941c)? & 9 != 0 || self.read(0xc000)? & 1 == 0 || self.read(0xc314)? & 1 != 0
        {
            self.lost = true;
            return Err(HardwareError::Unavailable);
        }
        Ok(())
    }
    fn write(&mut self, reg: u64, value: u32) -> Result<(), HardwareError> {
        self.awake()?;
        if !(self.current)() {
            self.lost = true;
            return Err(HardwareError::Unavailable);
        }
        self.mmio.write32(reg, value);
        Ok(())
    }
    fn media_awake(&mut self, engine: &Engine) -> Result<(), HardwareError> {
        if engine.request != 0 && (self.read(engine.request)? & self.read(engine.ack)? & 1 == 0) {
            self.lost = true;
            return Err(HardwareError::WakeLost);
        }
        Ok(())
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "intel_gpu_gen12_reset_tests.rs"]
mod tests;
