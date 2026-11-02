//! Retained fixed64x64 ARGB cursor DMA. MIT Linux b90c984d intel_cursor.c:
//! i9xx_cursor_update_arm (CTL,POS,BASE ordering), intel_cursor_regs.h,
//! skl_watermark.c::skl_cursor_allocation. DSB terminal+next-vblank and live
//! cursor base/readbacks are independent of primary/GT retirement.
use crate::{
    intel_gpu_display_resources::Profile,
    intel_gpu_dsb::Timing,
    intel_gpu_gem::{GemObject, GemState, Placement},
    intel_gpu_ggtt_ranges::{Lease, Ledger},
    intel_gpu_gtt::{PteFormat, GGTT_ARRAY_BASE},
    intel_gpu_scanout_io::DisplayAccess,
};
use alloc::{sync::Arc, vec::Vec};
use narf_filesystem::FsError;
const SLOT: u64 = 64 * 64 * 4;
const BYTES: u64 = SLOT * 2;
#[derive(Clone, Copy, Debug)]
struct Target {
    slot: Option<usize>,
    x: i32,
    y: i32,
    enabled: bool,
    visible: bool,
    base: u32,
    pos: u32,
}
#[derive(Debug)]
pub(crate) struct Owner<M: DisplayAccess + Clone> {
    io: M,
    lease: Option<Lease>,
    object: Option<Arc<GemObject>>,
    installed: bool,
    front: Option<usize>,
    x: i32,
    y: i32,
    enabled: bool,
    pending: Option<Target>,
    confirmed: Option<Target>,
    pub(crate) timing: Timing,
}
impl<M: DisplayAccess + Clone> Owner<M> {
    pub(crate) fn new(io: M, bar_len: u64, timing: Timing) -> Result<Self, FsError> {
        if !io.access_ok() || io.read32(0x4804) != 4 {
            return Err(FsError::NoDevice);
        }
        if io.read32(0x70080) != 0 {
            return Err(FsError::Unsupported);
        }
        let key = io.ggtt_key().ok_or(FsError::Unsupported)?;
        let lease = Ledger::for_bar(key, bar_len)?.reserve_cursor(BYTES)?;
        for page in 0..BYTES / 4096 {
            let r = GGTT_ARRAY_BASE + (lease.start / 4096 + page) * 8;
            if io.read32(r) != 0 || io.read32(r + 4) != 0 {
                return Err(FsError::Unsupported);
            }
        }
        let gem = GemState::new();
        let handle = gem.create_placed(BYTES, None, Placement::SystemWc, |_, _| Ok(()))?;
        let object = gem.object(handle)?;
        Ok(Self {
            io,
            lease: Some(lease),
            object: Some(object),
            installed: false,
            front: None,
            x: 0,
            y: 0,
            enabled: false,
            pending: None,
            confirmed: None,
            timing,
        })
    }
    fn read(&self, r: u64) -> Result<u32, FsError> {
        if !self.io.access_ok() {
            return Err(FsError::NoDevice);
        }
        let v = self.io.read32(r);
        if v == u32::MAX || !self.io.access_ok() {
            Err(FsError::NoDevice)
        } else {
            Ok(v)
        }
    }
    fn checked(&self, r: u64, v: u32) -> Result<(), FsError> {
        self.read(r)?;
        self.io.write32(r, v);
        if self.read(r)? == v {
            Ok(())
        } else {
            Err(FsError::NoDevice)
        }
    }
    pub(crate) fn exposed(&self) -> bool {
        self.installed
    }
    pub(crate) fn active(&self) -> bool {
        self.enabled || self.pending.is_some()
    }
    pub(crate) fn pending(&self) -> bool {
        self.pending.is_some()
    }
    pub(crate) fn timing_matches(&self, timing: Timing) -> bool {
        let old = self.timing;
        (
            old.clock, old.width, old.height, old.htotal, old.vtotal, old.flags,
        ) == (
            timing.clock,
            timing.width,
            timing.height,
            timing.htotal,
            timing.vtotal,
            timing.flags,
        )
    }
    pub(crate) fn replace_io(&mut self, io: M) {
        self.io = io;
    }
    fn install(&mut self) -> Result<(), FsError> {
        let lease = self.lease.as_ref().ok_or(FsError::NoDevice)?;
        let object = self.object.as_ref().ok_or(FsError::NoDevice)?;
        if !object.publish_for_device() {
            return Err(FsError::NoDevice);
        }
        // Before first exposure, any failure may drop an empty reservation.
        // Afterward this exact BO/VA is retained forever: no display/cursor
        // translation-cache invalidation or speculative reset is assumed.
        self.installed = true;
        for (i, phys) in object.pages().enumerate() {
            let pte = PteFormat::XeLpg
                .encode_ggtt(phys, 1)
                .map_err(|_| FsError::InvalidData)?;
            let r = GGTT_ARRAY_BASE + (lease.start / 4096 + i as u64) * 8;
            let old = self.read(r)?;
            let high = self.read(r + 4)?;
            if (old != 0 && old != pte as u32) || (high != 0 && high != (pte >> 32) as u32) {
                return Err(FsError::NoDevice);
            }
            self.checked(r, pte as u32)?;
            self.checked(r + 4, (pte >> 32) as u32)?;
        }
        Ok(())
    }
    pub(crate) fn stage(
        &mut self,
        profile: Profile,
        image: Option<&Arc<GemObject>>,
        replace: bool,
        position: Option<(i32, i32)>,
    ) -> Result<Vec<(u64, u32)>, FsError> {
        if self.pending.is_some() {
            return Err(FsError::Busy);
        }
        if self.read(0x44408)? & ((1 << 7) | (1 << 25) | (1 << 31) | (1 << 18) | (1 << 24)) != 0 {
            return Err(FsError::NoDevice);
        }
        let (x, y) = position.unwrap_or((self.x, self.y));
        if !(-32767..=32767).contains(&x) || !(-32767..=32767).contains(&y) {
            return Err(FsError::Unsupported);
        }
        let enabled = if replace {
            image.is_some()
        } else {
            self.enabled
        };
        let mut slot = self.front;
        if let Some(image) = image {
            if image.size() < SLOT
                || image.is_vram()
                || image.is_userptr()
                || !image.sync_for_cpu_read()
            {
                return Err(FsError::Unsupported);
            }
            slot = Some(self.front.map_or(0, |old| 1 - old));
            let mut bytes = alloc::vec![0;SLOT as usize];
            image.read(0, &mut bytes)?;
            self.object
                .as_ref()
                .ok_or(FsError::NoDevice)?
                .write(slot.unwrap() as u64 * SLOT, &bytes)?;
            self.install()?;
        }
        let visible = enabled
            && x < i32::from(self.timing.width)
            && y < i32::from(self.timing.height)
            && x + 64 > 0
            && y + 64 > 0;
        let base = if visible {
            (self.lease.as_ref().ok_or(FsError::NoDevice)?.start
                + slot.ok_or(FsError::InvalidData)? as u64 * SLOT) as u32
        } else {
            0
        };
        let encode = |v: i32| v.unsigned_abs() | if v < 0 { 1 << 15 } else { 0 };
        let pos = if visible {
            encode(x) | (encode(y) << 16)
        } else {
            0
        };
        let mut regs = profile.cursor_registers(enabled);
        regs.extend([
            (0x70080, if visible { 0x27 } else { 0 }),
            (0x70088, pos),
            (0x70084, base),
        ]);
        self.pending = Some(Target {
            slot,
            x,
            y,
            enabled,
            visible,
            base,
            pos,
        });
        Ok(regs)
    }
    /// Only a strict DSB refusal before exposure may roll back staged metadata.
    /// After independently stopping DSB0 then1, discard only its stale
    /// software target to stage an explicit cursor disable. This does not
    /// retire cursor fetches, free PTEs or authorize another image arm.
    pub(crate) fn begin_recovery_stop(&mut self) {
        self.pending = None;
    }
    pub(crate) fn cancel_unarmed(&mut self) {
        self.pending = None;
    }
    fn verify(&self, target: Target) -> Result<(), FsError> {
        if self.read(0x44408)? & ((1 << 7) | (1 << 25) | (1 << 31) | (1 << 18) | (1 << 24)) != 0 {
            return Err(FsError::NoDevice);
        }
        let before = self.read(0x70040)?;
        if self.read(0x70080)? != if target.visible { 0x27 } else { 0 }
            || self.read(0x70084)? != target.base
            || self.read(0x70088)? != target.pos
            || self.read(0x700ac)? != target.base
            || self.read(0x70040)? != before
        {
            return Err(FsError::NoDevice);
        }
        Ok(())
    }
    pub(crate) fn current_valid(&self) -> Result<(), FsError> {
        self.verify(self.confirmed.unwrap_or(Target {
            slot: None,
            x: 0,
            y: 0,
            enabled: false,
            visible: false,
            base: 0,
            pos: 0,
        }))
    }
    pub(crate) fn complete(&mut self) -> Result<(), FsError> {
        let target = self.pending.ok_or(FsError::Busy)?;
        self.verify(target)?;
        self.confirmed = Some(target);
        self.front = target.slot;
        self.x = target.x;
        self.y = target.y;
        self.enabled = target.enabled;
        self.pending = None;
        Ok(())
    }
}
impl<M: DisplayAccess + Clone> Drop for Owner<M> {
    fn drop(&mut self) {
        if self.installed {
            // Installed cursor translations are never rebound/freed without an exact
            // platform invalidation owner. Stable BO+VA reuse avoids that requirement.
            if let Some(lease) = self.lease.take() {
                core::mem::forget(lease)
            }
            if let Some(object) = self.object.take() {
                core::mem::forget(object)
            }
            core::mem::forget(self.io.clone());
        }
    }
}
