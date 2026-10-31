//! Owned GuC bootstrap for Meteor/Arrow Lake, DG2 and BMG.
//!
//! Source: ~/git/linux b90c984d615e8ce2af96f5b1411a962d83fed2ad,
//! xe_guc.c, xe_uc_fw.c, xe_wopcm.c, xe_guc_ads.c, xe_guc_fwif.h and
//! regs/xe_guc_regs.h (MIT). Minimal ADS has no enabled engines. Successful
//! firmware boot allows CT/HWCONFIG discovery, not userspace submission.

use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_gt::{GtPlatform, GUC_GGTT_MIN};
use crate::intel_gpu_guc::CssImage;
use crate::intel_gpu_guc_firmware::GuCFirmware;
use crate::intel_gpu_guc_transport::{TransportError, XeLpgTransport};
use crate::intel_gpu_guc_wa::GuCWorkarounds;
use crate::intel_gpu_hwconfig::{HardwareConfig, HwconfigError};
use crate::intel_gpu_rcs::{GpuAllocator, GpuBacking, SubmitError};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::mem::ManuallyDrop;
use core::sync::atomic::{fence, Ordering};
use core::task::Poll;

const PAGE: u32 = 4096;
const GDRST: u64 = 0x941c;
const STATUS: u64 = 0xc000;
const DMA_CTRL: u64 = 0xc314;
const ADS_PRIVATE: u32 = 0x6000;
const LOG_BYTES: u32 = 0x115000; // state page + 16K crash + 64K events + 1M capture
const POLICIES: u64 = 0x11dc;
const SYSINFO: u64 = 0x123c;
const WA_KLVS: u64 = 0x3000; // reserved ADS page, separate from register saves/private data

fn invalidate_guc_tlb(mmio: &impl MmioWindow, platform: GtPlatform) {
    let _ = mmio.read32(0x1901f8);
    if platform == GtPlatform::Battlemage {
        mmio.write32(0xcf80, 1 << 6);
        mmio.write32(0xcf7c, 1);
        let _ = mmio.read32(0xcf7c);
    } else {
        mmio.write32(0xcee8, 1);
        let _ = mmio.read32(0xcee8);
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BootError {
    Unsupported,
    Device,
    Address,
    State,
    NotAwake,
    Busy,
    Cache,
    Allocation(SubmitError),
    Wopcm,
    Reset,
    Unavailable,
    Timeout,
    Poisoned,
    Firmware { status: u32 },
    Transport(TransportError),
    Hwconfig(HwconfigError),
    Scheduling(crate::intel_gpu_guc_sched::SchedulingError),
    Graphics(crate::intel_gpu_gt::GraphicsError),
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BootState {
    Staged,
    Resetting,
    Dma,
    Authenticating,
    Ready,
    Stopping,
    Stopped,
    Lost,
}

/// Memory publication must clean dirty CPU cache lines as well as order
/// stores. Discrete GPUs cannot inherit an integrated-GPU LLC assumption.
pub trait BootAllocator: GpuAllocator {
    fn configure_cache(
        &mut self,
        _backing: &mut Self::Backing,
        _policy: crate::intel_gpu_gt_hw::CachePolicy,
    ) -> Result<(), BootError> {
        Err(BootError::Cache)
    }
    fn sync_for_device(&mut self, backing: &Self::Backing) -> Result<(), BootError>;

    /// Invalidate possible clean speculative CPU fills after exclusive device
    /// writes have completed. No CPU writes may occur between the two syncs.
    /// Default refusal prevents mistaking a one-way DMA adapter for a reader.
    fn sync_for_cpu(&mut self, _backing: &Self::Backing) -> Result<(), BootError> {
        Err(BootError::Cache)
    }
}

impl BootAllocator for crate::intel_gpu_rcs::SharedArena {
    fn configure_cache(
        &mut self,
        backing: &mut Self::Backing,
        policy: crate::intel_gpu_gt_hw::CachePolicy,
    ) -> Result<(), BootError> {
        crate::intel_gpu_rcs::SharedArena::configure_cache(self, backing, policy)
            .map_err(BootError::Allocation)
    }
    fn sync_for_device(&mut self, backing: &Self::Backing) -> Result<(), BootError> {
        if backing.publish_for_device() {
            Ok(())
        } else {
            Err(BootError::Cache)
        }
    }

    fn sync_for_cpu(&mut self, backing: &Self::Backing) -> Result<(), BootError> {
        // This destination was cleaned before publication and is CPU-read-only
        // afterwards, so no dirty CPU line can overwrite the device response.
        self.sync_for_device(backing)
    }
}

#[derive(Copy, Clone, Debug)]
pub struct BootConfig {
    pub device_id: u16,
    pub revision: u8,
    /// Actual HuC upload extent; zero means this bootstrap reserves no HuC image.
    pub huc_upload_bytes: u32,
    /// BMG requires an uncached MOCS entry already programmed by the GT owner.
    pub uncached_mocs: Option<u8>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct WopcmLayout {
    pub base: u32,
    pub size: u32,
}

impl WopcmLayout {
    fn validate(self, total: u32, upload: u32, huc: u32) -> Result<Self, BootError> {
        if self.base == 0
            || self.base % 0x4000 != 0
            || self.size % PAGE != 0
            || total
                .checked_sub(0x9000)
                .is_none_or(|top| self.base.checked_add(self.size).is_none_or(|end| end > top))
            || upload
                .checked_add(0x6000)
                .is_none_or(|need| self.size < need)
            || huc.checked_add(0x4000).is_none_or(|need| self.base < need)
        {
            return Err(BootError::Wopcm);
        }
        Ok(self)
    }

    fn plan(upload: u32, huc: u32) -> Result<Self, BootError> {
        let base = huc.checked_add(0x7fff).ok_or(BootError::Wopcm)? & !0x3fff;
        let size = 0x400000u32
            .checked_sub(0x9000)
            .and_then(|top| top.checked_sub(base))
            .ok_or(BootError::Wopcm)?
            & !0xfff;
        Self { base, size }.validate(0x400000, upload, huc)
    }
}

struct HwconfigDma<B: GpuBacking> {
    backing: B,
    bytes: u32,
}

struct Resources<A: BootAllocator> {
    allocator: A,
    image: A::Backing,
    ads: A::Backing,
    logs: A::Backing,
    hwconfig: Option<HwconfigDma<A::Backing>>,
}
impl<A: BootAllocator> Resources<A> {
    fn free(mut self) {
        self.allocator.free(self.image);
        self.allocator.free(self.ads);
        self.allocator.free(self.logs);
        if let Some(output) = self.hwconfig {
            self.allocator.free(output.backing);
        }
    }
}

pub struct GuCBoot<M: MmioWindow, A: BootAllocator> {
    mmio: M,
    resources: ManuallyDrop<Resources<A>>,
    platform: GtPlatform,
    config: BootConfig,
    upload: u32,
    state: BootState,
    deadline: u64,
    released: bool,
    hwconfig: Option<Arc<HardwareConfig>>,
    scheduling: Option<crate::intel_gpu_guc_sched::SchedulingAds>,
    reload: bool,
    submission_version: (u8, u8, u8),
    workarounds: Option<GuCWorkarounds>,
}

impl<M: MmioWindow, A: BootAllocator> core::fmt::Debug for GuCBoot<M, A> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GuCBoot")
            .field("platform", &self.platform)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

fn extent(backing: &impl GpuBacking, pages: u32) -> Result<(), BootError> {
    let base = backing.ggtt_offset();
    if pages == 0
        || backing.size_pages() != pages
        || base < GUC_GGTT_MIN
        || base % PAGE != 0
        || base
            .checked_add(pages.checked_mul(PAGE).ok_or(BootError::Address)?)
            .is_none_or(|end| end > 0xfee00000)
    {
        return Err(BootError::Address);
    }
    Ok(())
}

impl<M: MmioWindow, A: BootAllocator> GuCBoot<M, A> {
    pub(crate) fn submission_version(&self) -> (u8, u8, u8) {
        self.submission_version
    }

    pub fn stage(
        mmio: M,
        allocator: A,
        firmware: &GuCFirmware,
        config: BootConfig,
    ) -> Result<Self, BootError> {
        Self::stage_image(
            mmio,
            allocator,
            firmware.platform(),
            firmware.image(),
            config,
        )
    }

    fn stage_image(
        mmio: M,
        mut allocator: A,
        platform: GtPlatform,
        image: CssImage<'_>,
        config: BootConfig,
    ) -> Result<Self, BootError> {
        let profile = platform.guc().ok_or(BootError::Unsupported)?;
        if GtPlatform::from_pci(0x8086, config.device_id) != Some(platform)
            || image.version < profile.minimum_version
            || image.signature.len() != 384
        {
            return Err(BootError::Device);
        }
        if (platform == GtPlatform::Battlemage
            && config.uncached_mocs.is_none_or(|index| index > 15))
            || (platform != GtPlatform::Battlemage && config.uncached_mocs.is_some())
        {
            return Err(BootError::Cache);
        }
        let upload = u32::try_from(image.upload.len()).map_err(|_| BootError::Address)?;
        WopcmLayout::plan(upload, config.huc_upload_bytes)?;
        let image_pages = (upload + 384).div_ceil(PAGE);
        let ads_pages = (ADS_PRIVATE + image.private_data_bytes).div_ceil(PAGE);
        let mut allocations: Vec<A::Backing> = Vec::new();
        allocations
            .try_reserve_exact(3)
            .map_err(|_| BootError::Allocation(SubmitError::OutOfMemory))?;
        for pages in [image_pages, ads_pages, LOG_BYTES / PAGE] {
            let backing = match allocator.alloc(pages).map_err(BootError::Allocation) {
                Ok(backing) => backing,
                Err(error) => {
                    for backing in allocations {
                        allocator.free(backing);
                    }
                    return Err(error);
                }
            };
            let range = extent(&backing, pages).and_then(|()| {
                if allocations.iter().any(|old| {
                    let start = backing.ggtt_offset() as u64;
                    let old_start = old.ggtt_offset() as u64;
                    start < old_start + old.size_pages() as u64 * 4096
                        && old_start < start + backing.size_pages() as u64 * 4096
                }) {
                    Err(BootError::Address)
                } else {
                    Ok(())
                }
            });
            if let Err(error) = range {
                allocator.free(backing);
                for backing in allocations {
                    allocator.free(backing);
                }
                return Err(error);
            }
            allocations.push(backing);
        }
        let logs = allocations.pop().expect("logs");
        let ads = allocations.pop().expect("ADS");
        let backing = allocations.pop().expect("image");
        backing.zero_fill();
        ads.zero_fill();
        logs.zero_fill();
        for (i, word) in image
            .upload
            .chunks_exact(4)
            .chain(image.signature.chunks_exact(4))
            .enumerate()
        {
            backing.write32(
                i as u64 * 4,
                u32::from_le_bytes(word.try_into().expect("CSS dword")),
            );
        }
        // Minimal ADS: 16 classes * 32 instances, no enabled engines or golden
        // contexts. Invalid mapping value is 32, not zero (render instance 0).
        let base = ads.ggtt_offset();
        ads.write32(0x1004, base + POLICIES as u32);
        ads.write32(0x1008, base + SYSINFO as u32);
        ads.write32(0x1094, base + ADS_PRIVATE);
        ads.write32(POLICIES + 64, 500_000);
        ads.write32(POLICIES + 68, 1);
        ads.write32(POLICIES + 72, 15);
        for offset in (0..512u64).step_by(4) {
            ads.write32(SYSINFO + offset, 0x20202020);
        }
        Ok(Self {
            mmio,
            resources: ManuallyDrop::new(Resources {
                allocator,
                image: backing,
                ads,
                logs,
                hwconfig: None,
            }),
            platform,
            config,
            upload,
            state: BootState::Staged,
            deadline: 0,
            released: false,
            hwconfig: None,
            scheduling: None,
            reload: false,
            submission_version: image.submission_version,
            workarounds: None,
        })
    }

    pub fn state(&self) -> BootState {
        self.state
    }

    pub(crate) fn platform(&self) -> GtPlatform {
        self.platform
    }

    pub(crate) fn device_id(&self) -> u16 {
        self.config.device_id
    }

    pub(crate) fn revision(&self) -> u8 {
        self.config.revision
    }

    pub(crate) fn configure_cache(
        &mut self,
        policy: crate::intel_gpu_gt_hw::CachePolicy,
    ) -> Result<(), BootError> {
        if self.state != BootState::Staged || policy.platform() != self.platform {
            return Err(BootError::State);
        }
        let r = &mut *self.resources;
        r.allocator.configure_cache(&mut r.image, policy)?;
        r.allocator.configure_cache(&mut r.ads, policy)?;
        r.allocator.configure_cache(&mut r.logs, policy)?;
        Ok(())
    }

    pub(crate) fn scheduler(&self) -> Result<crate::intel_gpu_guc_sched::GuCScheduler<A>, BootError>
    where
        A: Clone,
    {
        if self.state != BootState::Ready
            || self.hwconfig.is_none()
            || self.submission_version.0 != 1
        {
            return Err(BootError::Unsupported);
        }
        crate::intel_gpu_guc_sched::GuCScheduler::allocate(
            self.resources.allocator.clone(),
            self.platform,
        )
        .map_err(BootError::Scheduling)
    }

    pub(crate) fn begin_scheduling(
        &mut self,
        ads: crate::intel_gpu_guc_sched::SchedulingAds,
        now: u64,
    ) -> Result<(), BootError> {
        if self.state != BootState::Ready || self.hwconfig.is_none() || self.scheduling.is_some() {
            return Err(BootError::State);
        }
        if self.submission_version.0 != 1 {
            return Err(BootError::Unsupported);
        }
        self.begin_stop(now)?;
        self.scheduling = Some(ads);
        self.reload = true;
        Ok(())
    }

    pub(crate) fn cancel_reload(&mut self) {
        self.reload = false;
    }

    pub(crate) fn invalidate_ggtt_before_ct(&self) -> Result<(), BootError> {
        self.awake()?;
        invalidate_guc_tlb(&self.mmio, self.platform);
        Ok(())
    }

    pub(crate) fn window(&self) -> &M {
        &self.mmio
    }

    pub(crate) fn hwconfig(&self) -> Option<&HardwareConfig> {
        self.hwconfig.as_deref()
    }

    pub(crate) fn hwconfig_for_device(&self, device_id: u16) -> Option<Arc<HardwareConfig>> {
        (self.config.device_id == device_id)
            .then(|| self.hwconfig.clone())
            .flatten()
    }

    pub(crate) fn prepare_hwconfig(&mut self, bytes: u32) -> Result<u32, BootError> {
        if self.state != BootState::Ready || self.resources.hwconfig.is_some() {
            return Err(BootError::State);
        }
        self.awake()?;
        crate::intel_gpu_hwconfig::validate_size(bytes).map_err(BootError::Hwconfig)?;
        let pages = bytes.div_ceil(PAGE);
        let r = &mut *self.resources;
        let backing = r.allocator.alloc(pages).map_err(BootError::Allocation)?;
        let base = backing.ggtt_offset();
        let checked = extent(&backing, pages).and_then(|()| {
            if [&r.image, &r.ads, &r.logs].iter().any(|old| {
                (base as u64) < old.ggtt_offset() as u64 + old.size_pages() as u64 * 4096
                    && (old.ggtt_offset() as u64) < base as u64 + pages as u64 * 4096
            }) {
                Err(BootError::Address)
            } else {
                Ok(())
            }
        });
        if let Err(error) = checked {
            r.allocator.free(backing);
            return Err(error);
        }
        backing.zero_fill();
        if let Err(error) = r.allocator.sync_for_device(&backing) {
            r.allocator.free(backing);
            return Err(error);
        }
        // The buffer stays with the bootstrap through timeout, cancellation
        // and unverified drop. A mailbox reply never owns its lifetime.
        r.hwconfig = Some(HwconfigDma { backing, bytes });
        invalidate_guc_tlb(&self.mmio, self.platform);
        Ok(base)
    }

    pub(crate) fn finish_hwconfig(&mut self) -> Result<(), BootError> {
        if self.state != BootState::Ready || self.hwconfig.is_some() {
            return Err(BootError::State);
        }
        self.awake()?;
        let r = &mut *self.resources;
        let output = r.hwconfig.as_ref().ok_or(BootError::State)?;
        r.allocator.sync_for_cpu(&output.backing)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(output.bytes as usize)
            .map_err(|_| BootError::Hwconfig(HwconfigError::Allocation))?;
        for offset in (0..u64::from(output.bytes)).step_by(4) {
            bytes.extend_from_slice(&output.backing.read32(offset).to_le_bytes());
        }
        self.hwconfig = Some(Arc::new(
            HardwareConfig::parse(bytes).map_err(BootError::Hwconfig)?,
        ));
        Ok(())
    }

    /// ADS/private/log memory remains owned for the entire GuC lifetime.
    /// Discrete CT requires coherent live cursors, beyond cache-cleaned upload.
    pub fn allocate_transport(&self) -> Result<XeLpgTransport<M, A>, BootError>
    where
        M: Clone,
        A: Clone,
    {
        if self.state != BootState::Ready {
            return Err(BootError::State);
        }
        self.awake()?;
        XeLpgTransport::allocate_for_platform(
            self.platform,
            self.mmio.clone(),
            self.resources.allocator.clone(),
        )
        .map_err(BootError::Transport)
    }

    fn awake(&self) -> Result<(), BootError> {
        let ack = self.mmio.read32(
            self.platform
                .guc_forcewake_ack()
                .ok_or(BootError::Unsupported)?,
        );
        if ack == u32::MAX {
            Err(BootError::Unavailable)
        } else if ack & 1 == 0 {
            Err(BootError::NotAwake)
        } else {
            Ok(())
        }
    }

    /// The sole GT owner holds GT forcewake/runtime-PM across every step and
    /// serializes reset, WOPCM and firmware DMA. VF/multi-tile admission is
    /// outside this physical-function, graphics-GT bootstrap.
    pub fn begin(&mut self, now: u64) -> Result<(), BootError> {
        if self.state != BootState::Staged {
            return Err(BootError::State);
        }
        self.awake()?;
        if self.mmio.read32(GDRST) != 0 || self.mmio.read32(DMA_CTRL) & 1 != 0 {
            return Err(BootError::Busy);
        }
        let ip = crate::intel_gpu_gt::GraphicsIp::read(&self.mmio, self.platform)
            .map_err(BootError::Graphics)?;
        let workarounds = GuCWorkarounds::for_rcs(self.platform, self.config.device_id, ip);
        if self.workarounds.is_some_and(|old| old != workarounds) {
            return Err(BootError::Device);
        }
        self.awake()?;
        self.workarounds = Some(workarounds);
        self.deadline = now.checked_add(5_000_000).ok_or(BootError::Timeout)?;
        self.state = BootState::Resetting;
        self.mmio.write32(GDRST, 8);
        let _ = self.mmio.read32(GDRST);
        Ok(())
    }

    fn layout(&self) -> Result<WopcmLayout, BootError> {
        let size = self.mmio.read32(0xc050);
        let offset = self.mmio.read32(0xc340);
        if size == u32::MAX || offset == u32::MAX {
            return Err(BootError::Unavailable);
        }
        if size & 1 != 0 || offset & 1 != 0 {
            if size & 1 == 0 || offset & 1 == 0 {
                return Err(BootError::Wopcm);
            }
            return WopcmLayout {
                base: offset & 0xffffc000,
                size: size & 0xfffff000,
            }
            .validate(0x800000, self.upload, self.config.huc_upload_bytes);
        }
        let layout = WopcmLayout::plan(self.upload, self.config.huc_upload_bytes)?;
        self.mmio.write32(0xc050, layout.size);
        if self.mmio.read32(0xc050) != layout.size | 1 {
            return Err(BootError::Wopcm);
        }
        let agent = if self.config.huc_upload_bytes != 0 {
            2
        } else {
            0
        };
        self.mmio.write32(0xc340, layout.base | agent);
        if self.mmio.read32(0xc340) != layout.base | agent | 1 {
            return Err(BootError::Wopcm);
        }
        Ok(layout)
    }

    fn upload(&mut self, now: u64) -> Result<(), BootError> {
        self.layout()?;
        let power_mask = self.mmio.read32(0xa168);
        if power_mask == u32::MAX {
            return Err(BootError::Unavailable);
        }
        let r = &mut *self.resources;
        let workarounds = self.workarounds.ok_or(BootError::State)?;
        // GuC is proven in reset. Publish bounded zero-length 16:16 KLVs,
        // the complete 64-bit ADS pointer and its byte count before DMA.
        for i in 0..PAGE / 4 {
            r.ads.write32(WA_KLVS + u64::from(i) * 4, 0);
        }
        for (i, word) in workarounds.klvs.iter().copied().enumerate() {
            r.ads.write32(WA_KLVS + i as u64 * 4, word);
        }
        r.ads.write32(0x11a4, r.ads.ggtt_offset() + WA_KLVS as u32);
        r.ads.write32(0x11a8, 0);
        r.ads.write32(0x11ac, workarounds.klvs.len() as u32 * 4);
        if !self.platform.is_discrete() {
            let doorbells = self.mmio.read32(0xd08);
            if doorbells == u32::MAX {
                return Err(BootError::Unavailable);
            }
            r.ads
                .write32(SYSINFO + 512 + 64 + 8, ((doorbells >> 16) & 0xff) + 1);
        }
        r.allocator.sync_for_device(&r.image)?;
        r.allocator.sync_for_device(&r.ads)?;
        r.allocator.sync_for_device(&r.logs)?;
        let mut params = [0u32; 14];
        params[0] = r.logs.ggtt_offset() | 0x3f5;
        params[1] = workarounds.flags;
        params[2] = if self.scheduling.is_some() {
            1 << 4
        } else {
            1 << 14
        };
        params[3] = 1 << 6; // verbose logging disabled
        params[4] = (r.ads.ggtt_offset() >> 12) << 1;
        params[5] = ((self.config.device_id as u32) << 16) | self.config.revision as u32;
        self.mmio.write32(0xc180, 0);
        for (i, word) in params.into_iter().enumerate() {
            self.mmio.write32(0xc184 + i as u64 * 4, word);
        }
        self.mmio.write32(
            0xc064,
            0x8602 | (u32::from(self.config.uncached_mocs.unwrap_or(0)) << 24),
        );
        self.mmio.write32(0x13816c, 1);
        self.mmio.write32(0xa168, power_mask & !(1 << 9));
        // Posted-read barrier for newly installed GGTT entries, then the
        // platform's GuC TLB invalidation path, as xe_ggtt/xe_guc_tlb_inval.
        let image = r.image.ggtt_offset();
        invalidate_guc_tlb(&self.mmio, self.platform);
        self.mmio.write32(0xc200, image + self.upload);
        self.mmio.write32(0xc300, image);
        self.mmio.write32(0xc304, 8 << 16);
        self.mmio.write32(0xc308, 0x2000);
        self.mmio.write32(0xc30c, 7 << 16);
        self.mmio.write32(0xc310, self.upload);
        self.deadline = now.checked_add(100_000_000).ok_or(BootError::Timeout)?;
        self.state = BootState::Dma;
        fence(Ordering::SeqCst);
        self.mmio.write32(DMA_CTRL, 0x00110011);
        let _ = self.mmio.read32(DMA_CTRL);
        Ok(())
    }

    pub fn begin_stop(&mut self, now: u64) -> Result<(), BootError> {
        if matches!(
            self.state,
            BootState::Staged | BootState::Stopped | BootState::Stopping
        ) {
            return Err(BootError::State);
        }
        self.awake()?;
        if self.mmio.read32(GDRST) != 0 {
            return Err(BootError::Busy);
        }
        self.deadline = now.checked_add(5_000_000).ok_or(BootError::Timeout)?;
        self.state = BootState::Stopping;
        self.mmio.write32(GDRST, 8);
        let _ = self.mmio.read32(GDRST);
        Ok(())
    }

    pub fn poll(&mut self, now: u64) -> Poll<Result<BootState, BootError>> {
        let result = self.poll_inner(now);
        if matches!(result, Poll::Ready(Err(_))) && self.state != BootState::Staged {
            self.state = BootState::Lost;
        }
        result
    }

    fn poll_inner(&mut self, now: u64) -> Poll<Result<BootState, BootError>> {
        if matches!(self.state, BootState::Ready | BootState::Stopped) {
            return Poll::Ready(Ok(self.state));
        }
        if self.state == BootState::Staged {
            return Poll::Ready(Err(BootError::State));
        }
        if self.state == BootState::Lost {
            return Poll::Ready(Err(BootError::Poisoned));
        }
        self.awake()?;
        if now >= self.deadline {
            return Poll::Ready(Err(BootError::Timeout));
        }
        match self.state {
            BootState::Resetting | BootState::Stopping => {
                let reset = self.mmio.read32(GDRST);
                if reset == u32::MAX {
                    return Poll::Ready(Err(BootError::Unavailable));
                }
                if reset & 8 != 0 {
                    return Poll::Pending;
                }
                let status = self.mmio.read32(STATUS);
                if status == u32::MAX {
                    return Poll::Ready(Err(BootError::Unavailable));
                }
                if status & 1 == 0 {
                    return Poll::Ready(Err(BootError::Reset));
                }
                if self.state == BootState::Stopping {
                    let dma = self.mmio.read32(DMA_CTRL);
                    if dma == u32::MAX {
                        return Poll::Ready(Err(BootError::Unavailable));
                    }
                    if dma & 1 != 0 {
                        return Poll::Pending;
                    }
                    fence(Ordering::Acquire);
                    if self.reload {
                        self.reload = false;
                        let config = self.scheduling.expect("scheduling reload");
                        let ads = &self.resources.ads;
                        let base = ads.ggtt_offset();
                        // Populate only while GuC is proven stopped: RCS0 and
                        // BCS0, each logical instance 0 of its GuC class.
                        // xe_guc_ads.c mapping/enable masks, golden LRCA with
                        // its post-register state size, and per-engine saves.
                        ads.write32(POLICIES + 76, 1); // no autonomous engine reset
                        for engine in crate::intel_gpu_engine::Engine::ALL {
                            let class = u64::from(engine.guc_class());
                            let state = config.engines[engine.index()];
                            let base_reg = engine.base();
                            let saves = 0x2000 + engine.index() as u64 * 48;
                            ads.write32(SYSINFO + class * 32, 0x20202000);
                            ads.write32(SYSINFO + 512 + class * 4, 1);
                            ads.write32(0x1014 + class * 4, state.golden);
                            ads.write32(0x1054 + class * 4, state.bytes - 4096 - 96 * 4);
                            ads.write32(class * 256, base + saves as u32);
                            ads.write32(class * 256 + 4, 3);
                            for (i, (reg, value, flags)) in [
                                (base_reg + 0x29c, 0, 1),
                                (base_reg + 0x80, state.hwsp, 0),
                                (base_reg + 0xa8, 0, 0),
                            ]
                            .into_iter()
                            .enumerate()
                            {
                                ads.write32(saves + i as u64 * 16, reg);
                                ads.write32(saves + i as u64 * 16 + 4, value);
                                ads.write32(saves + i as u64 * 16 + 8, flags);
                            }
                        }
                        self.state = BootState::Staged;
                        self.begin(now)?;
                        return Poll::Pending;
                    }
                    self.state = BootState::Stopped;
                    return Poll::Ready(Ok(self.state));
                }
                self.upload(now)?;
            }
            BootState::Dma => {
                let control = self.mmio.read32(DMA_CTRL);
                if control == u32::MAX {
                    return Poll::Ready(Err(BootError::Unavailable));
                }
                if control & 1 != 0 {
                    return Poll::Pending;
                }
                fence(Ordering::Acquire);
                self.mmio.write32(DMA_CTRL, 0x00100000);
                self.deadline = now.checked_add(10_000_000_000).ok_or(BootError::Timeout)?;
                self.state = BootState::Authenticating;
            }
            BootState::Authenticating => {
                let status = self.mmio.read32(STATUS);
                if status == u32::MAX {
                    return Poll::Ready(Err(BootError::Unavailable));
                }
                let rom = (status >> 1) & 0x7f;
                let kernel = (status >> 8) & 0xff;
                if status & 0xc0000000 == 0x40000000
                    || [0x13, 0x2b, 0x50, 0x73, 0x74, 0x75, 0x77, 0x79, 0x7a, 0x7e].contains(&rom)
                    || [0x02, 0x03, 0x04, 0x07, 0x60, 0x70, 0x71, 0x73, 0x74, 0x75]
                        .contains(&kernel)
                {
                    return Poll::Ready(Err(BootError::Firmware { status }));
                }
                if kernel == 0xf0 && status & 0xc0000001 == 0x80000000 {
                    fence(Ordering::Acquire);
                    self.state = BootState::Ready;
                    return Poll::Ready(Ok(self.state));
                }
            }
            _ => return Poll::Ready(Err(BootError::State)),
        }
        Poll::Pending
    }

    pub async fn wait(&mut self) -> Result<BootState, BootError> {
        loop {
            if let Poll::Ready(result) = self.poll(narf_time::monotonic_ns()) {
                return result;
            }
            narf_time::SleepUntil::new(narf_time::Deadline::after_us(50).as_instant()).await;
        }
    }

    fn free(&mut self) {
        if self.released {
            return;
        }
        self.released = true;
        // SAFETY: taken once, only before reset/publication, after verified
        // GuC stop plus DMA idle, or via the unsafe GT-reset proof below.
        unsafe { ManuallyDrop::take(&mut self.resources) }.free();
    }

    /// # Safety
    /// The GT owner proved every GuC/firmware-DMA agent stopped and invalidated
    /// stale firmware/ADS/log addresses. A timeout or unreadable BAR is no proof.
    pub unsafe fn release_after_gt_reset(mut self) {
        self.free();
    }
}

impl<M: MmioWindow, A: BootAllocator> Drop for GuCBoot<M, A> {
    fn drop(&mut self) {
        if matches!(self.state, BootState::Staged | BootState::Stopped) {
            self.free();
        }
    }
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use alloc::collections::{BTreeMap, BTreeSet};
    use alloc::rc::Rc;
    use core::cell::{Cell, RefCell};
    use narf_kernel_test::{kernel_test_in, TestResult};

    type Words = Rc<RefCell<Vec<u32>>>;
    #[derive(Default)]
    struct Device {
        regs: BTreeMap<u64, u32>,
        writes: Vec<(u64, u32)>,
        memory: BTreeMap<u32, Words>,
        synced: BTreeSet<u32>,
        next: u32,
        allocations: usize,
        fail_at: Option<usize>,
        fail_sync: bool,
        fail_cpu_sync: bool,
        cpu_ready: BTreeMap<u32, Rc<Cell<bool>>>,
        cpu_synced: BTreeSet<u32>,
        reject_wopcm: bool,
        coherent: bool,
        unstable_gmd: bool,
        gmd_reads: u32,
    }
    #[derive(Clone)]
    struct Window(Rc<RefCell<Device>>);
    impl MmioWindow for Window {
        fn read32(&self, offset: u64) -> u32 {
            if offset == 0xd8c {
                let mut device = self.0.borrow_mut();
                let value = *device.regs.get(&offset).unwrap_or(&0);
                device.gmd_reads += 1;
                return value ^ u32::from(device.unstable_gmd && device.gmd_reads % 2 == 0);
            }
            *self.0.borrow().regs.get(&offset).unwrap_or(&0)
        }
        fn write32(&self, offset: u64, value: u32) {
            let mut device = self.0.borrow_mut();
            device.writes.push((offset, value));
            let actual = match offset {
                0x190008 | 0x190010 => {
                    let old = *device.regs.get(&offset).unwrap_or(&0);
                    (old & !value & 0x7fffffff) | (value & 0x80000000)
                }
                0x190018 | 0x190060 => *device.regs.get(&offset).unwrap_or(&0) & !value,
                0x190070 => {
                    device.regs.insert(
                        0x190060,
                        match value {
                            1 => 0x80000001,
                            0x02000000 => 0x80048000,
                            _ => panic!("unowned interrupt selector"),
                        },
                    );
                    value
                }
                0xd8c => *device.regs.get(&offset).unwrap_or(&0), // read-only GMD_ID
                0xc050 | 0xc340 if !device.reject_wopcm => value | 1,
                0xc314 | 0xa188 | 0xa278 | 0x20ec | 0x83b4 | 0xe48c | 0xe18c | 0xe4f4 | 0xe5f0
                | 0xe420 | 0xe49c | 0xe4f0 | 0x20d4 | 0xe194 | 0xe4c4 | 0xe5f4 | 0x2050 => {
                    let mask = value >> 16;
                    let old = *device.regs.get(&offset).unwrap_or(&0);
                    if value == 0x00110011 {
                        // Hardware only learns the image/ADS/log addresses
                        // after their CPU cache contents have been published.
                        assert!(device.synced.len() >= 3);
                    }
                    (old & !mask) | (value & mask)
                }
                _ => value,
            };
            device.regs.insert(offset, actual);
        }
    }
    struct Backing {
        base: u32,
        words: Words,
        coherent: bool,
        cpu_ready: Rc<Cell<bool>>,
    }
    impl GpuBacking for Backing {
        fn ggtt_offset(&self) -> u32 {
            self.base
        }
        fn size_pages(&self) -> u32 {
            self.words.borrow().len() as u32 / 1024
        }
        fn read32(&self, at: u64) -> u32 {
            assert!(
                self.cpu_ready.get(),
                "CPU read before device-write synchronization"
            );
            self.words.borrow()[at as usize / 4]
        }
        fn write32(&self, at: u64, word: u32) {
            assert!(
                self.cpu_ready.get(),
                "CPU write during exclusive device DMA"
            );
            self.words.borrow_mut()[at as usize / 4] = word;
        }
        fn coherent_for_device(&self) -> bool {
            self.coherent
        }
    }
    #[derive(Clone)]
    struct Arena(Rc<RefCell<Device>>);
    impl GpuAllocator for Arena {
        type Backing = Backing;
        fn alloc(&mut self, pages: u32) -> Result<Backing, SubmitError> {
            let mut device = self.0.borrow_mut();
            device.allocations += 1;
            if device.fail_at == Some(device.allocations) {
                return Err(SubmitError::OutOfMemory);
            }
            let base = device.next;
            device.next += pages * 4096;
            let words = Rc::new(RefCell::new(alloc::vec![0;pages as usize*1024]));
            let cpu_ready = Rc::new(Cell::new(true));
            device.cpu_ready.insert(base, cpu_ready.clone());
            device.memory.insert(base, words.clone());
            Ok(Backing {
                base,
                words,
                coherent: device.coherent,
                cpu_ready,
            })
        }
        fn free(&mut self, backing: Backing) {
            let mut device = self.0.borrow_mut();
            device.memory.remove(&backing.base);
            device.cpu_ready.remove(&backing.base);
        }
        fn live_allocations(&self) -> usize {
            self.0.borrow().memory.len()
        }
        fn live_pages(&self) -> u32 {
            self.0
                .borrow()
                .memory
                .values()
                .map(|w| w.borrow().len() as u32 / 1024)
                .sum()
        }
    }
    impl BootAllocator for Arena {
        fn configure_cache(
            &mut self,
            _backing: &mut Backing,
            _policy: crate::intel_gpu_gt_hw::CachePolicy,
        ) -> Result<(), BootError> {
            if self.0.borrow().fail_sync {
                Err(BootError::Cache)
            } else {
                Ok(())
            }
        }
        fn sync_for_device(&mut self, backing: &Backing) -> Result<(), BootError> {
            let mut device = self.0.borrow_mut();
            if device.fail_sync {
                return Err(BootError::Cache);
            }
            device.synced.insert(backing.base);
            Ok(())
        }

        fn sync_for_cpu(&mut self, backing: &Backing) -> Result<(), BootError> {
            let mut device = self.0.borrow_mut();
            if device.fail_cpu_sync {
                return Err(BootError::Cache);
            }
            backing.cpu_ready.set(true);
            device.cpu_synced.insert(backing.base);
            Ok(())
        }
    }
    fn model() -> (Window, Arena) {
        let mut device = Device {
            next: 0x20000000,
            coherent: true,
            ..Device::default()
        };
        device.regs.insert(0x130044, 1);
        device.regs.insert(0xdfc, 1);
        let shared = Rc::new(RefCell::new(device));
        (Window(shared.clone()), Arena(shared))
    }
    fn image() -> Vec<u8> {
        let mut bytes = alloc::vec![0u8;528];
        for (at, value) in [
            (0, 6),
            (4, 225),
            (8, 0x10000),
            (16, 0x8086),
            (24, 229),
            (28, 96),
            (32, 96),
            (36, 1),
            (64, 0x00463600),
            (68, 0x00010000),
            (120, 4096),
        ] {
            crate::intel_gpu_uapi::put32(&mut bytes, at, value);
        }
        bytes[128..144].fill(0xa5);
        bytes[144..].fill(0x5a);
        bytes
    }
    fn stage(window: Window, arena: Arena, platform: GtPlatform) -> GuCBoot<Window, Arena> {
        window
            .0
            .borrow_mut()
            .regs
            .entry(0xd8c)
            .or_insert(if platform == GtPlatform::Battlemage {
                (20 << 22) | (1 << 14)
            } else {
                (12 << 22) | (70 << 14)
            });
        let device_id = match platform {
            GtPlatform::Alchemist => 0x56a0,
            GtPlatform::Battlemage => 0xe20b,
            _ => 0x7d55,
        };
        GuCBoot::stage_image(
            window,
            arena,
            platform,
            CssImage::parse(&image(), 70).unwrap(),
            BootConfig {
                device_id,
                revision: 3,
                huc_upload_bytes: 0,
                uncached_mocs: (platform == GtPlatform::Battlemage).then_some(2),
            },
        )
        .unwrap()
    }
    fn reset_done(window: &Window) {
        let mut device = window.0.borrow_mut();
        device.regs.insert(0x941c, 0);
        device.regs.insert(0xc000, 1);
        device.regs.insert(0xc314, 0);
    }
    fn ready(boot: &mut GuCBoot<Window, Arena>, window: &Window) {
        boot.begin(0).unwrap();
        reset_done(window);
        assert!(boot.poll(1).is_pending());
        window.0.borrow_mut().regs.insert(0xc314, 0x10);
        assert!(boot.poll(2).is_pending());
        window.0.borrow_mut().regs.insert(0xc000, 0x8000f000);
        assert_eq!(boot.poll(3), Poll::Ready(Ok(BootState::Ready)));
    }
    fn stop(boot: &mut GuCBoot<Window, Arena>, window: &Window) {
        boot.begin_stop(100).unwrap();
        reset_done(window);
        assert_eq!(boot.poll(101), Poll::Ready(Ok(BootState::Stopped)));
    }

    fn smoke_boot_workaround_wire_profiles() -> TestResult {
        let mtl = GtPlatform::Integrated(crate::intel_gpu::Generation::MeteorLake);
        let rows: &[(GtPlatform, u16, u32, u32, &[u32])] = &[
            (
                GtPlatform::Alchemist,
                0x56a0,
                0,
                0x424800,
                &[0x90020000, 0x900b0000],
            ),
            (
                GtPlatform::Alchemist,
                0x56a5,
                0,
                0x42c800,
                &[0x90020000, 0x900b0000],
            ),
            (
                GtPlatform::Alchemist,
                0x56a3,
                0,
                0x424800,
                &[0x90020000, 0x900b0000],
            ),
            (
                mtl,
                0x7d55,
                (12 << 22) | (70 << 14),
                0x420000,
                &[0x90020000, 0x900b0000],
            ),
            (
                mtl,
                0x7d55,
                (12 << 22) | (70 << 14) | 4,
                0x400000,
                &[0x90020000, 0x900b0000],
            ),
            (
                mtl,
                0x7d55,
                (12 << 22) | (71 << 14) | 3,
                0x420000,
                &[0x90020000, 0x900b0000],
            ),
            (
                mtl,
                0x7d55,
                (12 << 22) | (74 << 14),
                0x400000,
                &[0x90020000, 0x900b0000],
            ),
            (
                GtPlatform::Battlemage,
                0xe20b,
                (20 << 22) | (1 << 14),
                0,
                &[0x90050000, 0x90070000, 0x90090000, 0x900b0000],
            ),
            (
                GtPlatform::Battlemage,
                0xe20b,
                (20 << 22) | (2 << 14),
                0,
                &[0x90090000, 0x900b0000],
            ),
        ];
        for &(platform, device, gmd, flags, klvs) in rows {
            let (w, arena) = model();
            let mut boot = stage(w.clone(), arena.clone(), platform);
            boot.config.device_id = device;
            w.0.borrow_mut().regs.insert(0xd8c, gmd);
            ready(&mut boot, &w);
            {
                let d = w.0.borrow();
                assert_eq!(d.regs[&0xc188], flags);
                assert_eq!(d.regs[&0xc198] >> 16, u32::from(device));
                let ads = d.memory[&0x20001000].borrow();
                assert_eq!(
                    &ads[0x11a4 / 4..0x11b0 / 4],
                    &[0x20004000, 0, klvs.len() as u32 * 4]
                );
                assert_eq!(&ads[0x3000 / 4..0x3000 / 4 + klvs.len()], klvs);
                assert!(ads[0x3000 / 4 + klvs.len()..0x4000 / 4]
                    .iter()
                    .all(|v| *v == 0));
                assert!(ads[0x2000 / 4..0x3000 / 4].iter().all(|v| *v == 0));
            }
            stop(&mut boot, &w);
            drop(boot);
            assert_eq!(arena.live_allocations(), 0);
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_guc_boot",
        smoke_boot_workaround_wire_profiles
    );

    fn smoke_boot_workarounds_reject_bad_live_ip() -> TestResult {
        for (gmd, unstable, error) in [
            (
                u32::MAX,
                false,
                crate::intel_gpu_gt::GraphicsError::Unavailable,
            ),
            (
                (20 << 22) | (4 << 14),
                false,
                crate::intel_gpu_gt::GraphicsError::Unsupported,
            ),
            (
                (20 << 22) | (1 << 14),
                true,
                crate::intel_gpu_gt::GraphicsError::Unstable,
            ),
        ] {
            let (w, arena) = model();
            let mut boot = stage(w.clone(), arena.clone(), GtPlatform::Battlemage);
            w.0.borrow_mut().regs.insert(0xd8c, gmd);
            w.0.borrow_mut().unstable_gmd = unstable;
            assert_eq!(boot.begin(0), Err(BootError::Graphics(error)));
            assert_eq!(boot.state(), BootState::Staged);
            assert!(w.0.borrow().writes.is_empty());
            drop(boot);
            assert_eq!(arena.live_allocations(), 0);
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_guc_boot",
        smoke_boot_workarounds_reject_bad_live_ip
    );

    fn smoke_boot_dma_ads_and_transport() -> TestResult {
        for platform in [
            GtPlatform::Integrated(crate::intel_gpu::Generation::MeteorLake),
            GtPlatform::Alchemist,
            GtPlatform::Battlemage,
        ] {
            let (window, arena) = model();
            let mut boot = stage(window.clone(), arena.clone(), platform);
            if boot.allocate_transport().is_ok() {
                return TestResult::Fail("CT before authenticated boot");
            }
            ready(&mut boot, &window);
            {
                let device = window.0.borrow();
                // Source-defined literal wire values; DMA excludes RSA, whose
                // exact offset is supplied independently through scratch0.
                for pair in [
                    (0x941c, 8),
                    (0xc050, 0x3f3000),
                    (0xc340, 0x4000),
                    (0xc200, 0x20000090),
                    (0xc300, 0x20000000),
                    (0xc304, 0x80000),
                    (0xc308, 0x2000),
                    (0xc30c, 0x70000),
                    (0xc310, 144),
                    (0xc314, 0x00110011),
                ] {
                    if !device.writes.contains(&pair) {
                        return TestResult::Fail("GuC reset/WOPCM/DMA wire sequence");
                    }
                }
                let ads = device.memory.get(&0x20001000).unwrap().borrow();
                if ads[0x1004 / 4] != 0x200021dc
                    || ads[0x1008 / 4] != 0x2000223c
                    || ads[0x1094 / 4] != 0x20007000
                    || ads[0x121c / 4] != 500_000
                    || ads[0x1220 / 4] != 1
                    || ads[0x1224 / 4] != 15
                    || ads[0x123c / 4..0x143c / 4].iter().any(|v| *v != 0x20202020)
                    || ads[0x143c / 4..0x147c / 4].iter().any(|v| *v != 0)
                {
                    return TestResult::Fail(
                        "minimal ADS pointers, policies or invalid engine map",
                    );
                }
                if device.regs.get(&0xc18c) != Some(&0x4000) {
                    return TestResult::Fail("bootstrap must disable scheduler");
                }
                if platform == GtPlatform::Battlemage {
                    if !device.writes.contains(&(0xcf80, 64))
                        || !device.writes.contains(&(0xcf7c, 1))
                        || device.writes.iter().any(|(reg, _)| *reg == 0xcee8)
                        || device.regs.get(&0xc064) != Some(&0x02008602)
                    {
                        return TestResult::Fail("BMG MOCS/TLB profile");
                    }
                } else if !device.writes.contains(&(0xcee8, 1)) {
                    return TestResult::Fail("Gen12 GuC TLB path");
                }
            }
            let mut transport = boot.allocate_transport().unwrap();
            transport.begin_enable(4).unwrap();
            for i in 0..6 {
                window.0.borrow_mut().regs.insert(0x190240, 0xf0000001);
                assert!(transport.poll_transition(5 + i).is_pending());
            }
            window.0.borrow_mut().regs.insert(0x190240, 0xf0000000);
            assert_eq!(
                transport.poll_transition(12),
                Poll::Ready(Ok(crate::intel_gpu_guc_transport::TransportState::Enabled))
            );
            transport.begin_disable(13).unwrap();
            window.0.borrow_mut().regs.insert(0x190240, 0xf0000000);
            assert!(transport.poll_transition(14).is_ready());
            transport.release().unwrap();
            stop(&mut boot, &window);
            drop(boot);
            if arena.live_allocations() != 0 {
                return TestResult::Fail("stopped bootstrap leaked BOs");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_guc_boot",
        smoke_boot_dma_ads_and_transport
    );

    fn smoke_boot_failure_and_stop_proof() -> TestResult {
        for failure in 0..6 {
            let (window, arena) = model();
            let mut boot = stage(window.clone(), arena.clone(), GtPlatform::Alchemist);
            boot.begin(0).unwrap();
            reset_done(&window);
            if failure == 0 {
                window.0.borrow_mut().reject_wopcm = true;
            }
            if failure == 1 {
                window.0.borrow_mut().fail_sync = true;
            }
            let result = boot.poll(1);
            if failure > 1 {
                if failure == 2 {
                    assert_eq!(boot.poll(100000001), Poll::Ready(Err(BootError::Timeout)));
                } else {
                    window.0.borrow_mut().regs.insert(0xc314, 0x10);
                    assert!(boot.poll(2).is_pending());
                    let status = match failure {
                        3 => 0x400000a0,
                        4 => 0x00007100,
                        _ => u32::MAX,
                    };
                    window.0.borrow_mut().regs.insert(0xc000, status);
                    assert!(matches!(boot.poll(3), Poll::Ready(Err(_))));
                }
            } else if !matches!(result, Poll::Ready(Err(_))) {
                return TestResult::Fail("failed setup admitted DMA");
            }
            if boot.state() != BootState::Lost || arena.live_allocations() != 3 {
                return TestResult::Fail(
                    "boot error released DMA-visible resources or reported ready",
                );
            }
            boot.begin_stop(200000000).unwrap();
            // Reset bit clearing alone is insufficient: GuC must be in reset
            // and the independent firmware DMA engine must also be idle.
            reset_done(&window);
            window.0.borrow_mut().regs.insert(0xc314, 1);
            if !boot.poll(200000001).is_pending() || arena.live_allocations() != 3 {
                return TestResult::Fail("GuC reset released active firmware DMA");
            }
            window.0.borrow_mut().regs.insert(0xc314, 0);
            assert_eq!(boot.poll(200000002), Poll::Ready(Ok(BootState::Stopped)));
            drop(boot);
            if arena.live_allocations() != 0 {
                return TestResult::Fail("confirmed stop retained firmware resources");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_guc_boot",
        smoke_boot_failure_and_stop_proof
    );

    fn smoke_boot_prepublication_and_allocation_rollback() -> TestResult {
        for failure in 1..=3 {
            let (window, arena) = model();
            window.0.borrow_mut().fail_at = Some(failure);
            let result = GuCBoot::stage_image(
                window.clone(),
                arena.clone(),
                GtPlatform::Alchemist,
                CssImage::parse(&image(), 70).unwrap(),
                BootConfig {
                    device_id: 0x56a0,
                    revision: 0,
                    huc_upload_bytes: 0,
                    uncached_mocs: None,
                },
            );
            if !matches!(result, Err(BootError::Allocation(_)))
                || arena.live_allocations() != 0
                || !window.0.borrow().writes.is_empty()
            {
                return TestResult::Fail("failed staging leaked allocations or touched MMIO");
            }
        }
        let (window, arena) = model();
        let mut boot = stage(window.clone(), arena.clone(), GtPlatform::Alchemist);
        window.0.borrow_mut().regs.insert(0x130044, 0);
        if boot.begin(0) != Err(BootError::NotAwake) || !window.0.borrow().writes.is_empty() {
            return TestResult::Fail("GT access without forcewake");
        }
        drop(boot);
        if arena.live_allocations() != 0 {
            return TestResult::Fail("unpublished boot owner leaked");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_guc_boot",
        smoke_boot_prepublication_and_allocation_rollback
    );

    fn smoke_boot_locked_wopcm_and_address_bounds() -> TestResult {
        // An inherited layout must be complete, fit the maximum 8 MiB WOPCM
        // minus 36 KiB context reservation, and leave firmware/stack space.
        for (size, offset, valid) in [
            (0x3f3001, 0x4001, true),
            (0x3f3001, 0x4000, false),
            (0x3f3000, 0x4001, false),
            (0x7f4001, 0x4001, false),
            (0x5001, 0x4001, false),
        ] {
            let (window, arena) = model();
            let mut boot = stage(window.clone(), arena.clone(), GtPlatform::Alchemist);
            boot.begin(0).unwrap();
            reset_done(&window);
            window.0.borrow_mut().regs.insert(0xc050, size);
            window.0.borrow_mut().regs.insert(0xc340, offset);
            let result = boot.poll(1);
            let device = window.0.borrow();
            if device
                .writes
                .iter()
                .any(|(reg, _)| matches!(reg, 0xc050 | 0xc340))
                || (valid && !result.is_pending())
                || (!valid && result != Poll::Ready(Err(BootError::Wopcm)))
                || (!valid && device.writes.iter().any(|(reg, _)| *reg == DMA_CTRL))
            {
                return TestResult::Fail("inherited WOPCM rewritten or invalid layout uploaded");
            }
            drop(device);
            stop(&mut boot, &window);
            drop(boot);
            if arena.live_allocations() != 0 {
                return TestResult::Fail("inherited WOPCM stop leaked resources");
            }
        }
        // GuC low addresses bypass GGTT; high addresses exceed GUC_GGTT_TOP.
        for base in [0x7ff000, 0xfee00000] {
            let (window, arena) = model();
            window.0.borrow_mut().next = base;
            let result = GuCBoot::stage_image(
                window.clone(),
                arena.clone(),
                GtPlatform::Alchemist,
                CssImage::parse(&image(), 70).unwrap(),
                BootConfig {
                    device_id: 0x56a0,
                    revision: 0,
                    huc_upload_bytes: 0,
                    uncached_mocs: None,
                },
            );
            if !matches!(result, Err(BootError::Address)) || arena.live_allocations() != 0 {
                return TestResult::Fail("GuC GGTT boundary admitted or staging leaked");
            }
            window.0.borrow_mut().next = base;
            if !matches!(
                XeLpgTransport::allocate_for_platform(GtPlatform::Alchemist, window, arena.clone()),
                Err(TransportError::Address)
            ) || arena.live_allocations() != 0
            {
                return TestResult::Fail("CT GGTT boundary admitted or allocation leaked");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_guc_boot",
        smoke_boot_locked_wopcm_and_address_bounds
    );

    fn smoke_discrete_ct_needs_coherent_mapping() -> TestResult {
        let (window, arena) = model();
        window.0.borrow_mut().coherent = false;
        let mut boot = stage(window.clone(), arena.clone(), GtPlatform::Battlemage);
        ready(&mut boot, &window);
        if !matches!(
            boot.allocate_transport(),
            Err(BootError::Transport(TransportError::NonCoherent))
        ) || arena.live_allocations() != 3
        {
            return TestResult::Fail("ordinary WB BO admitted as coherent discrete CT or leaked");
        }
        stop(&mut boot, &window);
        drop(boot);
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_guc_boot",
        smoke_discrete_ct_needs_coherent_mapping
    );

    use crate::intel_gpu_guc_gt::{GtError, GtState, GuCGt};

    fn gt_model(platform: GtPlatform, ack: u64) -> (Window, Arena, GuCGt<Window, Arena>) {
        let (window, arena) = model();
        window.0.borrow_mut().regs.insert(ack, 0);
        // A separate hardware/user requestor must survive every masked write.
        window.0.borrow_mut().regs.insert(0xa188, 2);
        let boot = stage(window.clone(), arena.clone(), platform);
        (window, arena, GuCGt::from_staged(boot))
    }

    fn gt_ready(gt: &mut GuCGt<Window, Arena>, window: &Window, ack: u64) {
        gt.begin(0).unwrap();
        assert!(gt.poll(1).is_pending());
        assert!(!window
            .0
            .borrow()
            .writes
            .iter()
            .any(|(reg, _)| *reg == 0x941c));
        window.0.borrow_mut().regs.insert(ack, 1);
        assert!(gt.poll(2).is_pending());
        reset_done(window);
        assert!(gt.poll(3).is_pending());
        window.0.borrow_mut().regs.insert(0xc314, 0x10);
        assert!(gt.poll(4).is_pending());
        window.0.borrow_mut().regs.insert(0xc000, 0x8000f000);
        assert_eq!(gt.poll(5), Poll::Ready(Ok(GtState::Ready)));
    }

    fn gt_ct(gt: &mut GuCGt<Window, Arena>, window: &Window) {
        gt.begin_ct(6).unwrap();
        for i in 0..6 {
            window.0.borrow_mut().regs.insert(0x190240, 0xf0000001);
            assert!(gt.poll(7 + i).is_pending());
        }
        window.0.borrow_mut().regs.insert(0x190240, 0xf0000000);
        assert_eq!(gt.poll(13), Poll::Ready(Ok(GtState::CtReady)));
    }

    fn gt_stop(gt: &mut GuCGt<Window, Arena>, window: &Window, ack: u64) {
        gt.begin_stop(100).unwrap();
        assert!(gt.poll(101).is_pending());
        reset_done(window);
        assert!(gt.poll(102).is_pending());
        assert_eq!(gt.state(), GtState::Releasing);
        assert_eq!(window.0.borrow().regs.get(&0xa188), Some(&2));
        assert!(gt.poll(103).is_pending());
        window.0.borrow_mut().regs.insert(ack, 0);
        assert_eq!(gt.poll(104), Poll::Ready(Ok(GtState::Stopped)));
    }

    fn smoke_gt_boot_ct_and_verified_stop() -> TestResult {
        // xe_force_wake_init_gt selects MTL's 0xdfc for Gfx 12.70+;
        // DG2 uses 0x130044. The unselected ACK deliberately remains high.
        for (platform, ack) in [
            (
                GtPlatform::Integrated(crate::intel_gpu::Generation::MeteorLake),
                0xdfc,
            ),
            (GtPlatform::Alchemist, 0x130044),
            (GtPlatform::Battlemage, 0xdfc),
        ] {
            let (window, arena, mut gt) = gt_model(platform, ack);
            gt_ready(&mut gt, &window, ack);
            assert_eq!(window.0.borrow().regs.get(&0xa188), Some(&3));
            gt_ct(&mut gt, &window);
            assert_eq!(gt.begin_ct(14), Err(GtError::State));
            assert_eq!(arena.live_allocations(), 4);
            // Invalid messages and ordinary ring backpressure do not poison
            // the GT, unlike a broken firmware-owned descriptor.
            assert_eq!(
                gt.send(1, 0x1000, 0x1000, &[], true),
                Err(GtError::Transport(TransportError::Ct(
                    crate::intel_gpu_guc::GuCError::Message
                )))
            );
            for id in 1..=3 {
                gt.send(id, 0x1000, 0, &[0; 254], true).unwrap();
            }
            assert_eq!(
                gt.send(4, 0x1000, 0, &[0; 254], true),
                Err(GtError::Transport(TransportError::Ct(
                    crate::intel_gpu_guc::GuCError::Full
                )))
            );
            assert_eq!(gt.state(), GtState::CtReady);
            assert_eq!(gt.receive(), Ok(None));
            gt_stop(&mut gt, &window, ack);
            assert_eq!(arena.live_allocations(), 3); // CT released only after reset
            {
                let device = window.0.borrow();
                let reset = device
                    .writes
                    .iter()
                    .rposition(|pair| *pair == (0x941c, 8))
                    .unwrap();
                let release = device
                    .writes
                    .iter()
                    .rposition(|pair| *pair == (0xa188, 0x10000))
                    .unwrap();
                assert!(release > reset);
            }
            drop(gt);
            assert_eq!(arena.live_allocations(), 0);
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_guc_gt",
        smoke_gt_boot_ct_and_verified_stop
    );

    fn smoke_gt_wake_admission_and_timeouts() -> TestResult {
        for failure in 0..4 {
            let (window, arena, mut gt) = gt_model(GtPlatform::Battlemage, 0xdfc);
            let (reg, value, error) = match failure {
                0 => (0xa188, 3, GtError::Busy),
                1 => (0xdfc, 1, GtError::Busy),
                2 => (0xa188, u32::MAX, GtError::Unavailable),
                _ => (0xdfc, u32::MAX, GtError::Unavailable),
            };
            window.0.borrow_mut().regs.insert(reg, value);
            assert_eq!(gt.begin(0), Err(error));
            assert!(window.0.borrow().writes.is_empty());
            drop(gt);
            assert_eq!(arena.live_allocations(), 0);
        }
        let (window, arena, mut gt) = gt_model(GtPlatform::Battlemage, 0xdfc);
        gt.begin(0).unwrap();
        assert!(gt.poll(49_999_999).is_pending());
        assert_eq!(gt.poll(50_000_000), Poll::Ready(Err(GtError::WakeTimeout)));
        assert_eq!(arena.live_allocations(), 3);
        assert!(!window
            .0
            .borrow()
            .writes
            .iter()
            .any(|(reg, _)| *reg == 0x941c));
        gt.begin_stop(50_000_001).unwrap();
        assert_eq!(gt.poll(50_000_002), Poll::Ready(Ok(GtState::Stopped)));
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_guc_gt",
        smoke_gt_wake_admission_and_timeouts
    );

    fn smoke_gt_loss_recovery_retains_dma() -> TestResult {
        for failure in 0..5 {
            let (window, arena, mut gt) = gt_model(GtPlatform::Alchemist, 0x130044);
            gt_ready(&mut gt, &window, 0x130044);
            match failure {
                0 | 1 => {
                    window.0.borrow_mut().regs.insert(
                        if failure == 0 { 0x130044 } else { 0xa188 },
                        if failure == 0 { 0 } else { 2 },
                    );
                    assert_eq!(gt.poll(6), Poll::Ready(Err(GtError::WakeLost)));
                }
                2 => {
                    gt.begin_ct(6).unwrap();
                    assert_eq!(
                        gt.poll(10_000_006),
                        Poll::Ready(Err(GtError::Transport(TransportError::Timeout)))
                    );
                }
                3 => {
                    gt_ct(&mut gt, &window);
                    let memory = window.0.borrow().memory.last_key_value().unwrap().1.clone();
                    memory.borrow_mut()[0x808 / 4] = 1;
                    assert!(gt.receive().is_err());
                }
                _ => {
                    window.0.borrow_mut().regs.insert(0x130044, u32::MAX);
                    assert_eq!(gt.poll(6), Poll::Ready(Err(GtError::Unavailable)));
                    let writes = window.0.borrow().writes.len();
                    assert_eq!(gt.begin_stop(7), Err(GtError::Unavailable));
                    assert_eq!(window.0.borrow().writes.len(), writes);
                    window.0.borrow_mut().regs.insert(0x130044, 0);
                }
            }
            assert_eq!(gt.state(), GtState::Lost);
            let live = if failure == 2 || failure == 3 { 4 } else { 3 };
            assert_eq!(arena.live_allocations(), live);
            gt.begin_stop(100_000_000).unwrap();
            if gt.state() == GtState::Recovering {
                if failure == 0 || failure == 4 {
                    assert!(gt.poll(100_000_001).is_pending());
                    assert_eq!(arena.live_allocations(), live);
                }
                window.0.borrow_mut().regs.insert(0x130044, 1);
                assert!(gt.poll(100_000_002).is_pending());
            }
            assert_eq!(gt.state(), GtState::Stopping);
            assert_eq!(gt.begin_stop(100_000_003), Err(GtError::State));
            reset_done(&window);
            window.0.borrow_mut().regs.insert(0xc314, 1);
            assert!(gt.poll(100_000_004).is_pending());
            assert_eq!(window.0.borrow().regs.get(&0xa188), Some(&3));
            assert_eq!(arena.live_allocations(), live);
            window.0.borrow_mut().regs.insert(0xc314, 0);
            assert!(gt.poll(100_000_005).is_pending());
            assert_eq!(arena.live_allocations(), 3);
            window.0.borrow_mut().regs.insert(0x130044, 0);
            assert_eq!(gt.poll(100_000_006), Poll::Ready(Ok(GtState::Stopped)));
            drop(gt);
            assert_eq!(arena.live_allocations(), 0);
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_guc_gt",
        smoke_gt_loss_recovery_retains_dma
    );

    fn smoke_gt_wait_cancellation_and_drop() -> TestResult {
        use core::future::Future;
        use core::task::{Context, Waker};
        let (window, arena, mut gt) = gt_model(GtPlatform::Battlemage, 0xdfc);
        // The injected deadline stays distant even under TCG clock jumps.
        gt.begin(u64::MAX - 100_000_000).unwrap();
        {
            let mut waiting = core::pin::pin!(gt.wait());
            assert!(waiting
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending());
        }
        assert_eq!(gt.state(), GtState::Waking);
        assert_eq!(window.0.borrow().regs.get(&0xa188), Some(&3));
        assert_eq!(arena.live_allocations(), 3);
        gt.begin_stop(1).unwrap();
        assert_eq!(gt.poll(2), Poll::Ready(Ok(GtState::Stopped)));
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);

        let (window, arena, mut gt) = gt_model(GtPlatform::Alchemist, 0x130044);
        gt_ready(&mut gt, &window, 0x130044);
        gt_ct(&mut gt, &window);
        let weak = Rc::downgrade(&window.0);
        drop(window);
        drop(arena);
        drop(gt);
        // Even the last allocator/MMIO reference survives an unverified drop.
        let retained = weak.upgrade().expect("quarantined GT resource owner");
        assert_eq!(retained.borrow().memory.len(), 4);
        assert_eq!(retained.borrow().regs.get(&0xa188), Some(&3));
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_guc_gt",
        smoke_gt_wait_cancellation_and_drop
    );

    fn smoke_gt_platform_ack_and_discrete_coherence() -> TestResult {
        for (platform, ack) in [
            (
                GtPlatform::Integrated(crate::intel_gpu::Generation::MeteorLake),
                0xdfc,
            ),
            (GtPlatform::Alchemist, 0x130044),
            (GtPlatform::Battlemage, 0xdfc),
        ] {
            let (window, arena) = model();
            window.0.borrow_mut().regs.insert(ack, 0);
            let mut boot = stage(window.clone(), arena.clone(), platform);
            assert_eq!(boot.begin(0), Err(BootError::NotAwake));
            assert!(window.0.borrow().writes.is_empty());
            drop(boot);
            assert_eq!(arena.live_allocations(), 0);
        }
        let (window, arena, mut gt) = gt_model(GtPlatform::Battlemage, 0xdfc);
        window.0.borrow_mut().coherent = false;
        gt_ready(&mut gt, &window, 0xdfc);
        assert_eq!(
            gt.begin_ct(6),
            Err(GtError::Boot(BootError::Transport(
                TransportError::NonCoherent
            )))
        );
        assert_eq!(gt.state(), GtState::Ready);
        assert_eq!(arena.live_allocations(), 3);
        gt_stop(&mut gt, &window, 0xdfc);
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_guc_gt",
        smoke_gt_platform_ack_and_discrete_coherence
    );

    fn hwconfig_device_write(window: &Window, words: &[u32]) -> u32 {
        let device = window.0.borrow();
        let base = *device.regs.get(&0x190244).unwrap();
        assert!(device.synced.contains(&base));
        device.memory.get(&base).unwrap().borrow_mut()[..words.len()].copy_from_slice(words);
        device.cpu_ready.get(&base).unwrap().set(false);
        base
    }

    fn hwconfig_stop(gt: &mut GuCGt<Window, Arena>, window: &Window, ack: u64) {
        gt.begin_stop(20_000_000).unwrap();
        assert!(gt.poll(20_000_001).is_pending());
        reset_done(window);
        window.0.borrow_mut().regs.insert(0xc314, 1);
        assert!(gt.poll(20_000_002).is_pending());
        window.0.borrow_mut().regs.insert(0xc314, 0);
        assert!(gt.poll(20_000_003).is_pending());
        window.0.borrow_mut().regs.insert(ack, 0);
        assert_eq!(gt.poll(20_000_004), Poll::Ready(Ok(GtState::Stopped)));
    }

    fn smoke_hwconfig_snapshot_and_ct_handoff() -> TestResult {
        for (platform, ack) in [
            (
                GtPlatform::Integrated(crate::intel_gpu::Generation::MeteorLake),
                0xdfc,
            ),
            (GtPlatform::Alchemist, 0x130044),
            (GtPlatform::Battlemage, 0xdfc),
        ] {
            let (window, arena, mut gt) = gt_model(platform, ack);
            gt_ready(&mut gt, &window, ack);
            assert!(gt.hwconfig().is_none());
            gt.begin_hwconfig(6).unwrap();
            assert_eq!(gt.begin_ct(6), Err(GtError::State));
            {
                let d = window.0.borrow();
                for (reg, value) in [
                    (0x190240, 0x4100),
                    (0x190244, 0),
                    (0x190248, 0),
                    (0x19024c, 0),
                ] {
                    assert_eq!(d.regs.get(&reg), Some(&value));
                }
            }
            window.0.borrow_mut().regs.insert(0x190240, 0xf0000020);
            assert!(gt.poll(7).is_pending());
            assert_eq!(gt.state(), GtState::CopyingHwconfig);
            assert_eq!(arena.live_allocations(), 4);
            let base = hwconfig_device_write(
                &window,
                &[0x9000, 3, 0x00ffffff, 0xffffffff, 0xff000000, 7, 1, 8],
            );
            assert_eq!(base, 0x2011d000);
            {
                let d = window.0.borrow();
                let tlb_reg = if platform == GtPlatform::Battlemage {
                    0xcf7c
                } else {
                    0xcee8
                };
                assert_eq!(
                    d.writes
                        .iter()
                        .filter(|(reg, value)| *reg == tlb_reg && *value == 1)
                        .count(),
                    2
                );
                let invalidate = d
                    .writes
                    .iter()
                    .rposition(|(reg, _)| *reg == tlb_reg)
                    .unwrap();
                let notify = d
                    .writes
                    .iter()
                    .rposition(|pair| *pair == (0x1901f0, 1))
                    .unwrap();
                assert!(invalidate < notify);
            }
            assert_eq!(window.0.borrow().regs.get(&0x19024c), Some(&32));
            assert!(gt.hwconfig().is_none());
            assert!(!window.0.borrow().cpu_synced.contains(&base));
            // Linux accepts any nonnegative copy reply, not just zero.
            window.0.borrow_mut().regs.insert(0x190240, 0xf0000007);
            assert_eq!(gt.poll(8), Poll::Ready(Ok(GtState::Ready)));
            assert!(window.0.borrow().cpu_synced.contains(&base));
            let table = gt.hwconfig().unwrap();
            assert_eq!(table.as_bytes().len(), 32);
            assert_eq!(table.lookup_u32(7), Ok(Some(8)));
            assert_eq!(table.lookup_u32(0x9000), Err(HwconfigError::NotScalar));
            window.0.borrow().memory.get(&base).unwrap().borrow_mut()[7] = 99;
            assert_eq!(gt.hwconfig().unwrap().lookup_u32(7), Ok(Some(8)));
            assert_eq!(gt.begin_hwconfig(9), Err(GtError::State));
            gt.begin_ct(9).unwrap();
            for i in 0..6 {
                window.0.borrow_mut().regs.insert(0x190240, 0xf0000001);
                assert!(gt.poll(10 + i).is_pending());
            }
            window.0.borrow_mut().regs.insert(0x190240, 0xf0000000);
            assert_eq!(gt.poll(16), Poll::Ready(Ok(GtState::CtReady)));
            assert_eq!(gt.begin_hwconfig(17), Err(GtError::State));
            assert_eq!(arena.live_allocations(), 5);
            hwconfig_stop(&mut gt, &window, ack);
            assert_eq!(arena.live_allocations(), 4);
            assert_eq!(gt.hwconfig().unwrap().lookup_u32(7), Ok(Some(8)));
            drop(gt);
            assert_eq!(arena.live_allocations(), 0);
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_hwconfig",
        smoke_hwconfig_snapshot_and_ct_handoff
    );

    fn smoke_hwconfig_size_and_allocation_rollback() -> TestResult {
        for failure in 0..6 {
            let (window, arena, mut gt) = gt_model(GtPlatform::Alchemist, 0x130044);
            gt_ready(&mut gt, &window, 0x130044);
            gt.begin_hwconfig(6).unwrap();
            let size = match failure {
                0 => 0,
                1 => 14,
                2 => 0x100004,
                _ => 12,
            };
            {
                let mut d = window.0.borrow_mut();
                match failure {
                    3 => d.fail_at = Some(d.allocations + 1),
                    4 => d.fail_sync = true,
                    5 => d.next = 0x7ff000,
                    _ => {}
                }
                d.regs.insert(0x190240, 0xf0000000 | size);
            }
            assert!(matches!(gt.poll(7), Poll::Ready(Err(_))));
            assert_eq!(gt.state(), GtState::Lost);
            assert!(gt.hwconfig().is_none());
            assert_eq!(arena.live_allocations(), 3);
            // No failing destination was ever published to firmware.
            assert_eq!(window.0.borrow().regs.get(&0x190244), Some(&0));
            hwconfig_stop(&mut gt, &window, 0x130044);
            drop(gt);
            assert_eq!(arena.live_allocations(), 0);
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_hwconfig",
        smoke_hwconfig_size_and_allocation_rollback
    );

    fn smoke_hwconfig_copy_faults_retain_dma() -> TestResult {
        for failure in 0..6 {
            let (window, arena, mut gt) = gt_model(GtPlatform::Battlemage, 0xdfc);
            gt_ready(&mut gt, &window, 0xdfc);
            gt.begin_hwconfig(6).unwrap();
            window.0.borrow_mut().regs.insert(0x190240, 0xf000000c);
            assert!(gt.poll(7).is_pending());
            let words = if failure == 2 { [7, 2, 8] } else { [7, 1, 8] };
            let base = hwconfig_device_write(&window, &words);
            let response = match failure {
                1 => 0xe0000001,
                5 => u32::MAX,
                _ => 0xf0000000,
            };
            window.0.borrow_mut().regs.insert(0x190240, response);
            if failure == 3 {
                window.0.borrow_mut().fail_cpu_sync = true;
            }
            if failure == 4 {
                window.0.borrow_mut().regs.insert(0xdfc, 0);
            }
            let now = if failure == 0 { 10_000_007 } else { 8 };
            assert!(matches!(gt.poll(now), Poll::Ready(Err(_))));
            assert_eq!(gt.state(), GtState::Lost);
            assert!(gt.hwconfig().is_none());
            assert_eq!(arena.live_allocations(), 4);
            if failure != 2 {
                assert!(!window.0.borrow().cpu_synced.contains(&base));
            }
            window.0.borrow_mut().regs.insert(0xdfc, 1);
            window.0.borrow_mut().regs.insert(0x190240, 0xf0000000);
            assert_eq!(gt.poll(now + 1), Poll::Ready(Err(GtError::Poisoned)));
            hwconfig_stop(&mut gt, &window, 0xdfc);
            drop(gt);
            assert_eq!(arena.live_allocations(), 0);
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_hwconfig",
        smoke_hwconfig_copy_faults_retain_dma
    );

    fn smoke_hwconfig_cancelled_wait_and_last_owner() -> TestResult {
        use core::future::Future;
        use core::task::{Context, Waker};
        for copying in [false, true] {
            let (window, arena, mut gt) = gt_model(GtPlatform::Alchemist, 0x130044);
            gt_ready(&mut gt, &window, 0x130044);
            let now = u64::MAX - 100_000_000;
            gt.begin_hwconfig(now).unwrap();
            if copying {
                window.0.borrow_mut().regs.insert(0x190240, 0xf000000c);
                assert!(gt.poll(now + 1).is_pending());
            }
            let state = gt.state();
            {
                let mut waiting = core::pin::pin!(gt.wait());
                assert!(waiting
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending());
            }
            assert_eq!(gt.state(), state);
            assert!(gt.hwconfig().is_none());
            if copying {
                let weak = Rc::downgrade(&window.0);
                drop(window);
                drop(arena);
                drop(gt);
                let retained = weak.upgrade().expect("quarantined HWCONFIG destination");
                assert_eq!(retained.borrow().memory.len(), 4);
            } else {
                hwconfig_stop(&mut gt, &window, 0x130044);
                drop(gt);
                assert_eq!(arena.live_allocations(), 0);
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_hwconfig",
        smoke_hwconfig_cancelled_wait_and_last_owner
    );

    fn smoke_hwconfig_card_publication_and_gt_lifetime() -> TestResult {
        use crate::drm_devfs_bridge::IntelGpuCard;
        use crate::intel_gpu_render::{tests::check_card_hwconfig, DeviceInfo};
        use alloc::string::String;
        for (platform, ack, did, wrong_did) in [
            (
                GtPlatform::Integrated(crate::intel_gpu::Generation::MeteorLake),
                0xdfc,
                0x7d55,
                0x7d51,
            ),
            (GtPlatform::Alchemist, 0x130044, 0x56a0, 0x56a1),
            (GtPlatform::Battlemage, 0xdfc, 0xe20b, 0xe202),
        ] {
            let (window, arena, mut gt) = gt_model(platform, ack);
            let card = Arc::new(IntelGpuCard::new(String::new(), 0x8086, did, 0, 0));
            let index = crate::drm_registry::register_drm_card(card.clone());
            let other = Arc::new(IntelGpuCard::new(String::new(), 0x8086, did, 0, 0));
            let other_index = crate::drm_registry::register_drm_card(other.clone());
            let wrong = IntelGpuCard::new(String::new(), 0x8086, wrong_did, 0, 0);
            let before = DeviceInfo::for_card(index).unwrap();
            assert_eq!(card.publish_gt_hwconfig(&mut gt), Err(GtError::State));
            gt_ready(&mut gt, &window, ack);
            assert!(card.publish_gt_hwconfig(&mut gt).is_err());
            gt.begin_hwconfig(6).unwrap();
            assert_eq!(card.publish_gt_hwconfig(&mut gt), Err(GtError::State));
            window.0.borrow_mut().regs.insert(0x190240, 0xf0000020);
            assert!(gt.poll(7).is_pending());
            let words = [0x9000, 3, 0x00ffffff, 0xffffffff, 0xff000000, 7, 1, 8];
            let expected: Vec<u8> = words
                .iter()
                .flat_map(|word: &u32| word.to_le_bytes())
                .collect();
            let base = hwconfig_device_write(&window, &words);
            assert_eq!(card.publish_gt_hwconfig(&mut gt), Err(GtError::State));
            window.0.borrow_mut().regs.insert(0x190240, 0xf0000000);
            assert_eq!(gt.poll(8), Poll::Ready(Ok(GtState::Ready)));
            assert_eq!(
                wrong.publish_gt_hwconfig(&mut gt),
                Err(GtError::Boot(BootError::Device))
            );
            let wrong_vendor = IntelGpuCard::new(String::new(), 0x1002, did, 0, 0);
            assert_eq!(
                wrong_vendor.publish_gt_hwconfig(&mut gt),
                Err(GtError::Boot(BootError::Device))
            );
            card.publish_gt_hwconfig(&mut gt).unwrap();
            assert_eq!(card.publish_gt_hwconfig(&mut gt), Err(GtError::Busy));
            let after = DeviceInfo::for_card(index).unwrap();
            assert!(before.hwconfig.is_none());
            assert_eq!(after.hwconfig.as_ref().unwrap().as_bytes(), expected);
            window.0.borrow().memory.get(&base).unwrap().borrow_mut()[7] = 99;
            check_card_hwconfig(index, Some(&expected)).unwrap();
            // Two PCI functions with the same DID cannot share publication by
            // accident: the other card's slot remains absent.
            check_card_hwconfig(other_index, None).unwrap();
            hwconfig_stop(&mut gt, &window, ack);
            assert_eq!(other.publish_gt_hwconfig(&mut gt), Err(GtError::State));
            drop(gt);
            assert_eq!(arena.live_allocations(), 0);
            assert_eq!(after.hwconfig.as_ref().unwrap().as_bytes(), expected);
            check_card_hwconfig(index, Some(&expected)).unwrap();
            check_card_hwconfig(other_index, None).unwrap();
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_hwconfig",
        smoke_hwconfig_card_publication_and_gt_lifetime
    );

    fn smoke_hwconfig_card_refuses_wake_loss() -> TestResult {
        use crate::drm_devfs_bridge::IntelGpuCard;
        use crate::drm_registry::DrmCard;
        let (window, arena, mut gt) = gt_model(GtPlatform::Battlemage, 0xdfc);
        gt_ready(&mut gt, &window, 0xdfc);
        gt.begin_hwconfig(6).unwrap();
        window.0.borrow_mut().regs.insert(0x190240, 0xf000000c);
        assert!(gt.poll(7).is_pending());
        hwconfig_device_write(&window, &[7, 1, 8]);
        window.0.borrow_mut().regs.insert(0x190240, 0xf0000000);
        assert_eq!(gt.poll(8), Poll::Ready(Ok(GtState::Ready)));
        let card = IntelGpuCard::new(alloc::string::String::new(), 0x8086, 0xe20b, 0, 0);
        window.0.borrow_mut().regs.insert(0xdfc, 0);
        assert_eq!(card.publish_gt_hwconfig(&mut gt), Err(GtError::WakeLost));
        assert_eq!(gt.state(), GtState::Lost);
        assert!(card.intel_hwconfig().is_none());
        window.0.borrow_mut().regs.insert(0xdfc, 1);
        assert_eq!(card.publish_gt_hwconfig(&mut gt), Err(GtError::State));
        hwconfig_stop(&mut gt, &window, 0xdfc);
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_hwconfig",
        smoke_hwconfig_card_refuses_wake_loss
    );

    mod hardware_tests {
        use super::*;
        include!("intel_gpu_guc_hw_tests.rs");
    }
}
