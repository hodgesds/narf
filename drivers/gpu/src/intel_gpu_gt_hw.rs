//! Physical GT cache policy and render-well initialization.
//!
//! Reference: ~/git/linux b90c984d615e8ce2af96f5b1411a962d83fed2ad,
//! MIT xe_{force_wake,gt_mcr,mocs,pat}.c. The enclosing GuCGt owns the
//! graphics-GT wake request and serializes every host steering/reset user.

use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_gt::GtPlatform;
use core::task::Poll;
use narf_capabilities::{Cap, CapOp, Write};

/// A permanent PCI mapping whose every register access invokes current
/// authority. Revocation becomes an unavailable read, closing GT admission.
#[derive(Clone, Debug)]
pub struct AuthorizedWindow {
    bar: narf_bus::bar::MmioRegion,
    cap: Cap<narf_bus::BusDeviceCap, Write>,
    headless: Option<alloc::sync::Arc<HeadlessAccess>>,
}
impl AuthorizedWindow {
    pub(crate) fn new(
        bar: narf_bus::bar::MmioRegion,
        cap: Cap<narf_bus::BusDeviceCap, Write>,
    ) -> Self {
        Self {
            bar,
            cap,
            headless: None,
        }
    }
    /// Exact source-profile constructor. It performs only the Linux bootstrap
    /// four-zero root writes + VF_CAP probe before recording PF permission.
    /// Every raw access independently invokes current capability and validates
    /// current PCI identity/BAR/command/D0 and inherited-VF exclusion.
    pub(crate) fn for_device(
        bar: narf_bus::bar::MmioRegion,
        cap: Cap<narf_bus::BusDeviceCap, Write>,
        device: narf_bus::BusDevice,
    ) -> Self {
        if !GtPlatform::from_pci(device.id.vendor, device.id.device)
            .is_some_and(|p| p.is_headless_integrated())
        {
            return Self::new(bar, cap);
        }
        let this = Self {
            bar,
            cap,
            headless: Some(alloc::sync::Arc::new(HeadlessAccess {
                device,
                pf: core::sync::atomic::AtomicBool::new(false),
            })),
        };
        let _ = this.read32(0x1901f8);
        this
    }
    fn raw(&self, offset: u64, write: Option<u32>, bootstrap: bool) -> Option<u32> {
        let result = self
            .cap
            .invoke(Register {
                bar: self.bar,
                offset,
                write,
                headless: self.headless.as_deref(),
                bootstrap,
            })
            .ok()
            .flatten();
        if result.is_none() {
            if let Some(h) = &self.headless {
                h.pf.store(false, core::sync::atomic::Ordering::Release);
            }
        }
        result
    }
}

const DUMMY_MMIO: u64 = 0x130030;
const VF_CAP: u64 = 0x1901f8;

/// No recursive MmioWindow access: each callback is one separately authorized
/// raw operation. Stop immediately after a partial sequence loses authority.
fn ordered_read(
    offset: u64,
    flush: bool,
    mut raw: impl FnMut(u64, Option<u32>) -> Option<u32>,
) -> u32 {
    if flush {
        for _ in 0..4 {
            if raw(DUMMY_MMIO, Some(0)).is_none() {
                return u32::MAX;
            }
        }
    }
    raw(offset, None).unwrap_or(u32::MAX)
}
fn bootstrap_access(offset: u64, write: Option<u32>) -> bool {
    matches!((offset, write), (DUMMY_MMIO, Some(0)) | (VF_CAP, None))
}

fn profile_read(
    offset: u64,
    pf: Option<&core::sync::atomic::AtomicBool>,
    mut raw: impl FnMut(u64, Option<u32>, bool) -> Option<u32>,
) -> u32 {
    use core::sync::atomic::Ordering::{Acquire, Release};
    let bootstrap = pf.is_some_and(|p| !p.load(Acquire));
    if bootstrap && offset != VF_CAP {
        return u32::MAX;
    }
    let mut failed = false;
    let value = ordered_read(offset, pf.is_some(), |r, w| {
        let result = raw(r, w, bootstrap);
        failed |= result.is_none();
        result
    });
    if let Some(p) = pf {
        if offset == VF_CAP || failed {
            p.store(
                value != u32::MAX && value & 1 == 0 && offset == VF_CAP,
                Release,
            );
        }
    }
    value
}
fn access_allowed(pf: bool, bootstrap: bool, offset: u64, write: Option<u32>) -> bool {
    if bootstrap {
        bootstrap_access(offset, write)
    } else {
        pf
    }
}

/// Bounded PCI extended-cap traversal: missing SR-IOV is permissible, malformed
/// or cyclic walks are not. An inherited enabled VF can DMA independently of
/// NARF's PF client gate, so both VFEnable and NumVFs must remain zero.
fn no_inherited_vfs(mut read: impl FnMut(u16) -> Option<u32>) -> bool {
    let mut offset = 0x100u16;
    let mut seen = [0u64; 16];
    let mut sriov = false;
    let mut first = true;
    loop {
        if !(0x100..=0xffc).contains(&offset) || offset & 3 != 0 {
            return false;
        }
        let bit = usize::from(offset / 4);
        if seen[bit / 64] & (1u64 << (bit % 64)) != 0 {
            return false;
        }
        seen[bit / 64] |= 1u64 << (bit % 64);
        let Some(header) = read(offset).filter(|v| *v != u32::MAX) else {
            return false;
        };
        if header == 0 {
            return first;
        } // missing only at the initial header
        first = false;
        if header & 0xffff == 0 || header & 0xf0000 == 0 {
            return false;
        }
        if header & 0xffff == 0x10 {
            if sriov || offset > 0xfec {
                return false;
            }
            sriov = true;
            let Some(control) = read(offset + 8).filter(|v| *v != u32::MAX) else {
                return false;
            };
            let Some(count) = read(offset + 0x10).filter(|v| *v != u32::MAX) else {
                return false;
            };
            if control & 1 != 0 || count & 0xffff != 0 {
                return false;
            }
        }
        let next = (header >> 20) as u16;
        if next == 0 {
            return true;
        }
        offset = next;
    }
}

#[derive(Debug)]
struct HeadlessAccess {
    device: narf_bus::BusDevice,
    pf: core::sync::atomic::AtomicBool,
}
impl HeadlessAccess {
    fn current(
        &self,
        cap: &Cap<narf_bus::BusDeviceCap, Write>,
        bar: narf_bus::bar::MmioRegion,
    ) -> bool {
        let read = |offset| {
            narf_bus::pci::read_config32(cap, &self.device, offset)
                .ok()
                .filter(|v| *v != u32::MAX)
        };
        let expected = u32::from(self.device.id.device) << 16 | u32::from(self.device.id.vendor);
        if read(0) != Some(expected)
            || read(4).is_none_or(|v| v & 6 != 6)
            || read(8).is_none_or(|v| v >> 8 != self.device.id.class)
            || bar.len < 16 * 1024 * 1024
            || narf_bus::pci::power_state(cap, &self.device).ok().flatten()
                != Some(narf_bus::pci::PciPowerState::D0)
        {
            return false;
        }
        let Some(low) = read(0x10) else {
            return false;
        };
        if low & 1 != 0 || !matches!(low & 6, 0 | 4) {
            return false;
        }
        let high = if low & 6 == 4 {
            let Some(high) = read(0x14) else {
                return false;
            };
            high
        } else {
            0
        };
        if u64::from(high) << 32 | u64::from(low & !15) != bar.phys.raw() {
            return false;
        }
        no_inherited_vfs(read)
    }
}
struct Register<'a> {
    bar: narf_bus::bar::MmioRegion,
    offset: u64,
    write: Option<u32>,
    headless: Option<&'a HeadlessAccess>,
    bootstrap: bool,
}
impl CapOp<narf_bus::BusDeviceCap, Write> for Register<'_> {
    type Output = Option<u32>;
    fn execute(
        self,
        cap: &Cap<narf_bus::BusDeviceCap, Write>,
    ) -> Result<Option<u32>, narf_capabilities::CapError> {
        if self.offset % 4 != 0
            || self
                .offset
                .checked_add(4)
                .is_none_or(|end| end > self.bar.len)
        {
            return Ok(None);
        }
        if let Some(access) = self.headless {
            let allowed = access_allowed(
                access.pf.load(core::sync::atomic::Ordering::Acquire),
                self.bootstrap,
                self.offset,
                self.write,
            );
            if !allowed || !access.current(cap, self.bar) {
                access
                    .pf
                    .store(false, core::sync::atomic::Ordering::Release);
                return Ok(None);
            }
        }
        // SAFETY: the PCI probe owns this permanent mapping; the invocation
        // validated current authority and the aligned offset is inside BAR0.
        Ok(Some(unsafe {
            if let Some(value) = self.write {
                self.bar.write32(self.offset, value);
                0
            } else {
                self.bar.read32(self.offset)
            }
        }))
    }
}
impl MmioWindow for AuthorizedWindow {
    fn read32(&self, offset: u64) -> u32 {
        if offset & 3 != 0 || offset.checked_add(4).is_none_or(|end| end > self.bar.len) {
            return u32::MAX;
        }
        profile_read(offset, self.headless.as_ref().map(|h| &h.pf), |r, w, b| {
            self.raw(r, w, b)
        })
    }
    fn write32(&self, offset: u64, value: u32) {
        let _ = self.raw(offset, Some(value), false);
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HardwareError {
    Unsupported,
    Busy,
    Unavailable,
    Timeout,
    WakeLost,
}

/// Policy installed for this owner's system-memory GGTT mappings. A numeric
/// index is not sufficient: this proof is created only after the MMIO writes.
#[derive(Copy, Clone, Debug)]
pub struct CachePolicy {
    pub(crate) platform: GtPlatform,
    pub(crate) ggtt_pat: u8,
    pub(crate) media: Option<crate::intel_gpu_gt::lnl::MediaProof>,
}

impl CachePolicy {
    pub fn platform(self) -> GtPlatform {
        self.platform
    }
    pub fn ggtt_pat(self) -> u8 {
        self.ggtt_pat
    }
}

#[derive(Debug)]
pub(crate) struct HardwareInit {
    platform: GtPlatform,
    deadline: u64,
    requested: bool,
    releasing: bool,
    ready: bool,
    quiesce: u8,
    gen12_reset: Option<crate::intel_gpu_gt::gen12::reset::Reset>,
    gen12_prepare_budget: bool,
    lnl_media: Option<crate::intel_gpu_gt::lnl::MediaQuiesce>,
    media_proof: Option<crate::intel_gpu_gt::lnl::MediaProof>,
}

impl HardwareInit {
    pub(crate) fn take_gen12_reset(&mut self) -> Option<crate::intel_gpu_gt::gen12::reset::Reset> {
        self.ready = false;
        self.gen12_reset.take()
    }
    pub(crate) fn ready(&self) -> bool {
        self.ready
    }
    pub(crate) fn recover(
        &mut self,
        mmio: &impl MmioWindow,
        now: u64,
    ) -> Result<(), HardwareError> {
        self.deadline = now.checked_add(50_000_000).ok_or(HardwareError::Timeout)?;
        if self.platform.is_gen12() {
            self.quiesce = 0;
            self.ready = false;
            self.gen12_prepare_budget = false;
            if let Some(reset) = &mut self.gen12_reset {
                reset.restart(now)?;
            }
        }
        if self.requested {
            mmio.write32(0xa278, 0x00010001);
        }
        Ok(())
    }
    pub(crate) fn new(platform: GtPlatform) -> Result<Self, HardwareError> {
        platform.guc().ok_or(HardwareError::Unsupported)?;
        Ok(Self {
            platform,
            deadline: 0,
            requested: false,
            releasing: false,
            ready: false,
            quiesce: 0,
            gen12_reset: None,
            gen12_prepare_budget: false,
            lnl_media: platform
                .is_headless_integrated()
                .then(|| crate::intel_gpu_gt::lnl::MediaQuiesce::for_platform(platform)),
            media_proof: None,
        })
    }

    pub(crate) fn begin(&mut self, mmio: &impl MmioWindow, now: u64) -> Result<(), HardwareError> {
        let request = mmio.read32(0xa278);
        let ack = mmio.read32(0xd84);
        if request == u32::MAX || ack == u32::MAX {
            return Err(HardwareError::Unavailable);
        }
        if request & 1 != 0 || ack & 1 != 0 {
            return Err(HardwareError::Busy);
        }
        self.deadline = now.checked_add(50_000_000).ok_or(HardwareError::Timeout)?;
        mmio.write32(0xa278, 0x00010001);
        let _ = mmio.read32(0xa278);
        self.requested = true;
        Ok(())
    }

    pub(crate) fn awake(&self, mmio: &impl MmioWindow) -> Result<(), HardwareError> {
        let request = mmio.read32(0xa278);
        let ack = mmio.read32(0xd84);
        if request == u32::MAX || ack == u32::MAX {
            return Err(HardwareError::Unavailable);
        }
        if self.ready {
            if let Some(proof) = self.media_proof {
                proof.current(mmio).map_err(|_| HardwareError::WakeLost)?;
            }
        }
        if !self.requested || request & 1 == 0 || ack & 1 == 0 {
            return Err(HardwareError::WakeLost);
        }
        if self.ready && self.platform.is_gen12() {
            self.gen12_reset
                .as_ref()
                .ok_or(HardwareError::WakeLost)?
                .held_current(mmio, || true)?;
        }
        Ok(())
    }

    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) fn poll(
        &mut self,
        mmio: &impl MmioWindow,
        now: u64,
    ) -> Poll<Result<CachePolicy, HardwareError>> {
        self.poll_with_access(mmio, now, || true)
    }
    pub(crate) fn poll_with_access(
        &mut self,
        mmio: &impl MmioWindow,
        now: u64,
        mut current: impl FnMut() -> bool,
    ) -> Poll<Result<CachePolicy, HardwareError>> {
        if !current() {
            return Poll::Ready(Err(HardwareError::Unavailable));
        }
        if now >= self.deadline {
            return Poll::Ready(Err(HardwareError::Timeout));
        }
        let ack = mmio.read32(0xd84);
        if ack == u32::MAX {
            return Poll::Ready(Err(HardwareError::Unavailable));
        }
        if ack & 1 == 0 {
            return Poll::Pending;
        }
        self.awake(mmio)?;
        if self.platform.is_headless_integrated() {
            // The exact source graphics IP must match under current wake before
            // cache setup can authorize even the first staged GGTT PTE.
            crate::intel_gpu_gt::GraphicsIp::read(mmio, self.platform)
                .map_err(|_| HardwareError::Unsupported)?;
        }
        if let Some(media) = &mut self.lnl_media {
            match media.poll(mmio, now) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(result) => {
                    self.media_proof = Some(result.map_err(|_| HardwareError::Unavailable)?)
                }
            }
        }
        if self
            .gen12_reset
            .as_ref()
            .is_some_and(|reset| reset.releasing())
        {
            match self
                .gen12_reset
                .as_mut()
                .expect("owned Gen12 media release")
                .poll_release(mmio, now, &mut current)
            {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(result) => result?,
            }
            self.quiesce = 3;
            self.deadline = now.checked_add(50_000_000).ok_or(HardwareError::Timeout)?;
        }
        if self.quiesce != 3 {
            let reset = mmio.read32(0x941c);
            if reset == u32::MAX {
                return Poll::Ready(Err(HardwareError::Unavailable));
            }
            if self.quiesce == 0 {
                if reset != 0 {
                    return Poll::Ready(Err(HardwareError::Busy));
                }
                // No new GGTT entry has been published yet. Retire the inherited
                // graphics GuC before resetting its engines or cache policy.
                mmio.write32(0x941c, 8);
                self.quiesce = 1;
                self.deadline = now.checked_add(5_000_000).ok_or(HardwareError::Timeout)?;
                return Poll::Pending;
            }
            if reset & if self.quiesce == 1 { 8 } else { 1 } != 0 {
                return Poll::Pending;
            }
            let status = mmio.read32(0xc000);
            let dma = mmio.read32(0xc314);
            if status == u32::MAX || dma == u32::MAX {
                return Poll::Ready(Err(HardwareError::Unavailable));
            }
            if status & 1 == 0 || dma & 1 != 0 {
                return Poll::Pending;
            }
            if self.quiesce == 1 {
                if self.platform.is_gen12() {
                    if !self.gen12_prepare_budget {
                        // One encompassing bound for the independently timed
                        // 50ms wake +100ms CS +5ms GPM phases and settles.
                        self.deadline =
                            now.checked_add(200_000_000).ok_or(HardwareError::Timeout)?;
                        self.gen12_prepare_budget = true;
                    }
                    if self.gen12_reset.is_none() {
                        self.gen12_reset =
                            Some(crate::intel_gpu_gt::gen12::reset::Reset::new(now)?);
                    }
                    match self
                        .gen12_reset
                        .as_mut()
                        .expect("owned Gen12 reset")
                        .poll_prepare(mmio, now, &mut current)
                    {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(result) => result?,
                    }
                }
                mmio.write32(0x941c, 1);
                self.quiesce = 2;
                self.deadline = now.checked_add(5_000_000).ok_or(HardwareError::Timeout)?;
                return Poll::Pending;
            }
            if let Some(reset) = &mut self.gen12_reset {
                // SAFETY: inherited GuC reset/DMA idle and GRDOM_FULL
                // self-clear were freshly proven above. Transfer these same
                // wake holds into scheduling, then back into verified stop.
                unsafe {
                    reset.retain_after_full_reset(mmio, &mut current)?;
                }
                self.deadline = now.checked_add(50_000_000).ok_or(HardwareError::Timeout)?;
            }
            self.quiesce = 3;
        }
        if self.platform.is_gen12() {
            crate::intel_gpu_gt::gen12::cache(mmio)?;
            self.ready = true;
            let mask = mmio.read32(0x1900e8);
            if mask == u32::MAX {
                return Poll::Ready(Err(HardwareError::Unavailable));
            }
            mmio.write32(0x1900e8, mask | 0x80000000);
            return Poll::Ready(Ok(CachePolicy {
                platform: self.platform,
                ggtt_pat: 0,
                media: None,
            }));
        }
        let modern = self.platform != GtPlatform::Alchemist;
        if modern {
            let sem = mmio.read32(0xfd0);
            if sem == u32::MAX {
                return Poll::Ready(Err(HardwareError::Unavailable));
            }
            if sem & 1 == 0 {
                return Poll::Pending;
            }
        }
        // No await or return while owning the hardware steering semaphore.
        let selector = if modern { 0xfd4 } else { 0xfdc };
        let old = mmio.read32(selector);
        if old == u32::MAX {
            if modern {
                mmio.write32(0xfd0, 1);
            }
            return Poll::Ready(Err(HardwareError::Unavailable));
        }
        mmio.write32(selector, old | 0x80000000);
        let pat = match self.platform {
            GtPlatform::Gen12(_) => unreachable!("separate pre-GMD cache policy"),
            GtPlatform::Integrated(_) if !self.platform.is_headless_integrated() => {
                // Xe-LPG PAT3: WB L4, one-way coherent. PAT0, used by the
                // inherited display, is deliberately not redefined.
                mmio.write32(0x480c, 2);
                mmio.write32(0x4810, 3); // Xe-LPG PAT4: two-way coherent WB
                                         // XELPG_PAT_1_WT, non-coherent: Mesa's scanout and
                                         // write-combining index, admitted for WC objects only.
                mmio.write32(0x4804, 4);
                // xe_pat.c: PAT2 is UC. Non-snooping Xe-LPG PPGTT walks
                // use this policy independently of coherent WB leaf BOs.
                mmio.write32(0x4808, 0xc);
                let global = [
                    0, 0x100, 0x100, 0x10c, 0x100, 0x10c, 0x100, 0x10c, 0x100, 0x10c, 0x100, 0x100,
                    0x100, 0x100, 0x104, 0x100,
                ];
                let l3 = [
                    0xb0, 0xb0, 0x90, 0x90, 0xd0, 0xd0, 0x10, 0x10, 0x50, 0x50, 0xb0, 0xb0, 0xb0,
                    0xb0, 0xb0, 0x50,
                ];
                for (i, value) in global.into_iter().enumerate() {
                    mmio.write32(0x4000 + i as u64 * 4, value);
                }
                for (i, pair) in l3.chunks_exact(2).enumerate() {
                    mmio.write32(0xb020 + i as u64 * 4, pair[0] | pair[1] << 16);
                }
                3
            }
            GtPlatform::Alchemist => {
                mmio.write32(0x4800, 3); // Xe-LP PAT0: WB, coherent
                let l3 = [0x90, 0xd0, 0x50, 0xb0];
                for i in 0..32 {
                    let low = *l3.get(i * 2).unwrap_or(&0xb0);
                    let high = *l3.get(i * 2 + 1).unwrap_or(&0xb0);
                    mmio.write32(0xb020 + i as u64 * 4, low | high << 16);
                }
                0
            }
            GtPlatform::Battlemage | GtPlatform::Integrated(_) => {
                mmio.write32(0x4804, 0xe); // Xe2 coherent PAT1,4,5,7
                if self.platform.is_headless_integrated() {
                    mmio.write32(0x480c, 0x3c);
                } // Xe2 UC PAT3
                mmio.write32(0x4808, 0xf); // Xe2 default WB PAT2: L3 WB, L4 UC, two-way coherent
                mmio.write32(0x4810, 0x32);
                mmio.write32(0x4814, 0x3e);
                mmio.write32(0x481c, 0x33);
                let table = [0xc, 0x10c, 0x130, 0x13c, 0x100];
                for i in 0..16 {
                    mmio.write32(0x4000 + i as u64 * 4, *table.get(i).unwrap_or(&0x100));
                }
                2
            }
        };
        let posted = mmio.read32(selector);
        mmio.write32(selector, old);
        if modern {
            mmio.write32(0xfd0, 1);
        }
        if posted == u32::MAX {
            return Poll::Ready(Err(HardwareError::Unavailable));
        }
        self.ready = true;
        // CT is pumped by the per-card task. Mask only graphics GuC-to-host
        // interrupts, preserving media/display ownership (xe_irq_regs.h).
        mmio.write32(0x1900e8, mmio.read32(0x1900e8) | 0x80000000);
        Poll::Ready(Ok(CachePolicy {
            platform: self.platform,
            ggtt_pat: pat,
            media: self.media_proof,
        }))
    }

    pub(crate) fn begin_release(
        &mut self,
        mmio: &impl MmioWindow,
        now: u64,
    ) -> Result<(), HardwareError> {
        if self
            .gen12_reset
            .as_ref()
            .is_some_and(|reset| !reset.released())
        {
            return Err(HardwareError::Busy);
        }
        self.deadline = now.checked_add(50_000_000).ok_or(HardwareError::Timeout)?;
        if self.requested {
            mmio.write32(0xa278, 0x00010000);
            let _ = mmio.read32(0xa278);
        }
        self.releasing = true;
        Ok(())
    }

    pub(crate) fn poll_release(
        &mut self,
        mmio: &impl MmioWindow,
        now: u64,
    ) -> Poll<Result<(), HardwareError>> {
        if !self.releasing {
            return Poll::Ready(Err(HardwareError::Busy));
        }
        if let Some(media) = &mut self.lnl_media {
            match media.release(mmio, now) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(result) => result.map_err(|_| HardwareError::Unavailable)?,
            }
            self.media_proof = None;
        }
        let ack = mmio.read32(0xd84);
        if ack == u32::MAX {
            return Poll::Ready(Err(HardwareError::Unavailable));
        }
        if now >= self.deadline {
            return Poll::Ready(Err(HardwareError::Timeout));
        }
        if self.requested && ack & 1 != 0 {
            return Poll::Pending;
        }
        self.requested = false;
        self.ready = false;
        Poll::Ready(Ok(()))
    }
}

#[cfg(feature = "kernel-test")]
mod read_order_tests {
    use super::*;
    use alloc::{collections::BTreeMap, vec::Vec};
    use core::sync::atomic::{AtomicBool, Ordering};
    use narf_kernel_test::{kernel_test_in, TestResult};
    fn smoke_lnl_ptl_mmio_bootstrap_four_zero_order_current_loss_and_vf_exclusion() -> TestResult {
        use crate::{intel_gpu::Generation, intel_gpu_gt::Gen12Platform};
        // Actual production CapOp distinguishes refused access from a real
        // all-ones scalar. This fake BAR is owned RAM, never hardware/ECAM.
        {
            let mut words = alloc::vec![0u32;1024];
            words[4] = u32::MAX;
            let bar = narf_bus::bar::MmioRegion {
                phys: narf_memory::PhysAddr::new(0x10000000),
                virt: words.as_mut_ptr() as u64,
                len: 4096,
                kind: narf_bus::bar::BarKind::Mmio64 {
                    prefetchable: false,
                },
            };
            let cap = Cap::<narf_bus::BusDeviceCap, Write>::bootstrap();
            let window = AuthorizedWindow::new(bar, cap);
            assert_eq!(window.raw(16, None, false), Some(u32::MAX));
            assert_eq!(window.raw(4096, None, false), None);
            let pf = AtomicBool::new(true);
            assert_eq!(
                profile_read(16, Some(&pf), |r, w, _| {
                    if w.is_some() {
                        Some(0)
                    } else {
                        window.raw(r, w, false)
                    }
                }),
                u32::MAX
            );
            assert!(pf.load(Ordering::Acquire));
            assert_eq!(
                profile_read(4096, Some(&pf), |r, w, _| {
                    if w.is_some() {
                        Some(0)
                    } else {
                        window.raw(r, w, false)
                    }
                }),
                u32::MAX
            );
            assert!(!pf.load(Ordering::Acquire));
        }

        for platform in [
            GtPlatform::Gen12(Gen12Platform::TigerLake),
            GtPlatform::Gen12(Gen12Platform::AlderLakeP),
            GtPlatform::Gen12(Gen12Platform::AlderLakeS),
            GtPlatform::Gen12(Gen12Platform::AlderLakeN),
            GtPlatform::Integrated(Generation::MeteorLake),
            GtPlatform::Alchemist,
            GtPlatform::Battlemage,
            GtPlatform::Integrated(Generation::LunarLake),
            GtPlatform::Integrated(Generation::PantherLake),
        ] {
            let pf = AtomicBool::new(false);
            let proof = platform.is_headless_integrated().then_some(&pf);
            let mut ops = Vec::new();
            // Before PF classification only the explicit bootstrap VF read is
            // allowed. Normal reads and all unrelated writes stay forbidden.
            if proof.is_some() {
                assert_eq!(
                    profile_read(0xc000, proof, |r, w, _| {
                        ops.push((r, w));
                        Some(9)
                    }),
                    u32::MAX
                );
                assert!(ops.is_empty());
                assert!(!access_allowed(false, false, 0x101010, Some(0x80000000)));
                assert!(!access_allowed(false, true, 0x380d8c, Some(0)));
                assert!(!access_allowed(false, true, 0x130030, Some(1)));
            }
            assert_eq!(
                profile_read(0x1901f8, proof, |r, w, bootstrap| {
                    if proof.is_some() {
                        assert!(access_allowed(pf.load(Ordering::Acquire), bootstrap, r, w));
                    }
                    ops.push((r, w));
                    Some(0)
                }),
                0
            );
            if proof.is_some() {
                assert!(pf.load(Ordering::Acquire));
                assert_eq!(
                    ops,
                    [
                        (0x130030, Some(0)),
                        (0x130030, Some(0)),
                        (0x130030, Some(0)),
                        (0x130030, Some(0)),
                        (0x1901f8, None)
                    ]
                );
            } else {
                assert_eq!(ops, [(0x1901f8, None)]);
            }
            ops.clear();
            assert_eq!(
                profile_read(0x380d8c, proof, |r, w, bootstrap| {
                    assert!(!bootstrap);
                    ops.push((r, w));
                    Some(0x07800000)
                }),
                0x07800000
            );
            if proof.is_some() {
                assert_eq!(
                    ops,
                    [
                        (0x130030, Some(0)),
                        (0x130030, Some(0)),
                        (0x130030, Some(0)),
                        (0x130030, Some(0)),
                        (0x380d8c, None)
                    ]
                );
                // Every loss position, including before the first write and
                // after all four writes, prevents the actual target read.
                for lost in 0..5 {
                    pf.store(true, Ordering::Release);
                    let mut attempt = 0;
                    let mut partial = Vec::new();
                    assert_eq!(
                        profile_read(0x380d8c, proof, |r, w, _| {
                            let current = attempt != lost;
                            attempt += 1;
                            if !current {
                                return None;
                            }
                            partial.push((r, w));
                            Some(0)
                        }),
                        u32::MAX
                    );
                    assert_eq!(attempt, lost + 1);
                    assert_eq!(partial.len(), lost);
                    assert!(partial.iter().all(|op| *op == (0x130030, Some(0))));
                    assert!(!pf.load(Ordering::Acquire));
                }
                // RING_IMR legitimately reads all ones; that scalar is not
                // evidence that the physical function changed role.
                pf.store(true, Ordering::Release);
                assert_eq!(
                    profile_read(0x20a8, proof, |_, _, _| Some(u32::MAX)),
                    u32::MAX
                );
                assert!(pf.load(Ordering::Acquire));
                for vf in [1, u32::MAX] {
                    pf.store(false, Ordering::Release);
                    ops.clear();
                    assert_eq!(
                        profile_read(0x1901f8, proof, |r, w, _| {
                            ops.push((r, w));
                            Some(vf)
                        }),
                        vf
                    );
                    assert!(!pf.load(Ordering::Acquire));
                    ops.clear();
                    assert_eq!(
                        profile_read(0xc000, proof, |r, w, _| {
                            ops.push((r, w));
                            Some(0)
                        }),
                        u32::MAX
                    );
                    assert!(ops.is_empty());
                }
            } else {
                assert_eq!(ops, [(0x380d8c, None)]);
            }
        }
        // PCI-only exclusion runs before any bootstrap dummy. Missing SR-IOV
        // is allowed; present disabled PF, active VFs, malformed walks differ.
        for (cfg, valid) in [
            (BTreeMap::from([(0x100, 0)]), true),
            (
                BTreeMap::from([(0x100, 0x00010010), (0x108, 0), (0x110, 0)]),
                true,
            ),
            (
                BTreeMap::from([(0x100, 0x00010010), (0x108, 1), (0x110, 0)]),
                false,
            ),
            (
                BTreeMap::from([(0x100, 0x00010010), (0x108, 0), (0x110, 1)]),
                false,
            ),
            (BTreeMap::from([(0x100, 0x10010001)]), false), // self-loop
            (BTreeMap::from([(0x100, 0x10410001), (0x104, 0)]), false),
            (BTreeMap::from([(0x100, 0x10210001)]), false), // unaligned
            (BTreeMap::from([(0x100, u32::MAX)]), false),
        ] {
            assert_eq!(no_inherited_vfs(|r| cfg.get(&r).copied()), valid);
            let pf = AtomicBool::new(false);
            let mut ops = Vec::new();
            let result = profile_read(0x1901f8, Some(&pf), |r, w, _| {
                if !no_inherited_vfs(|offset| cfg.get(&offset).copied()) {
                    return None;
                }
                ops.push((r, w));
                Some(0)
            });
            assert_eq!(result, if valid { 0 } else { u32::MAX });
            assert_eq!(ops.len(), if valid { 5 } else { 0 });
            assert_eq!(pf.load(Ordering::Acquire), valid);
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gt",
        smoke_lnl_ptl_mmio_bootstrap_four_zero_order_current_loss_and_vf_exclusion
    );
}
