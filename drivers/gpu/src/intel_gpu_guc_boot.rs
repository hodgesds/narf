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
use crate::intel_gpu_guc_transport::{MailboxRegisters, TransportError, XeLpgTransport};
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
    if platform.is_xe2() {
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
    HucDma,
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
    /// Physical LNL adapters require a fresh driver-FLR receipt before staging.
    fn lnl_takeover_ready(&self) -> bool {
        false
    }
    /// LNL seals and invalidates the whole arena before releasing media wake.
    /// Other profiles retain their existing per-backing retirement contract.
    fn retire_ggtt(&mut self) -> Result<(), BootError> {
        Err(BootError::Cache)
    }
    /// Register (`true`) or unregister the standalone media GuC as a second
    /// TLB of this allocator's shared GGTT. Allocators without one refuse.
    fn register_media_guc_tlb(&mut self, _live: bool) -> Result<(), BootError> {
        Err(BootError::Cache)
    }
    /// Select CT (`true`) or MMIO GGTT TLB invalidation for the registered
    /// media GuC once its submission is enabled or disabled again.
    fn media_guc_submission(&mut self, _enabled: bool) -> Result<(), BootError> {
        Err(BootError::Cache)
    }

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
    fn lnl_takeover_ready(&self) -> bool {
        crate::intel_gpu_rcs::SharedArena::lnl_takeover_ready(self)
    }
    fn retire_ggtt(&mut self) -> Result<(), BootError> {
        crate::intel_gpu_rcs::SharedArena::retire_ggtt(self).map_err(BootError::Allocation)
    }
    fn register_media_guc_tlb(&mut self, live: bool) -> Result<(), BootError> {
        self.set_media_guc_tlb(live).map_err(BootError::Allocation)
    }
    fn media_guc_submission(&mut self, enabled: bool) -> Result<(), BootError> {
        self.set_media_guc_submission(enabled)
            .map_err(BootError::Allocation)
    }

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
        // This proof covers concurrent CPU/device shared cache lines. Live
        // scheduler polling needs ordering, not repeated whole-LRC CLFLUSH.
        // Unconfigured/legacy/ARM mappings still use exclusive invalidation.
        if backing.coherent_for_device() {
            fence(Ordering::Acquire);
            return Ok(());
        }
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
        Self::plan_total(upload, huc, 0x400000)
    }

    fn plan_total(upload: u32, huc: u32, total: u32) -> Result<Self, BootError> {
        let base = huc.checked_add(0x7fff).ok_or(BootError::Wopcm)? & !0x3fff;
        let size = total
            .checked_sub(0x9000)
            .and_then(|top| top.checked_sub(base))
            .ok_or(BootError::Wopcm)?
            & !0xfff;
        Self { base, size }.validate(total, upload, huc)
    }
}

struct HwconfigDma<B: GpuBacking> {
    backing: B,
    bytes: u32,
}

struct HucDma<B: GpuBacking> {
    backing: B,
    upload: u32,
    version: (u8, u8, u8),
}

struct Resources<A: BootAllocator> {
    allocator: A,
    image: A::Backing,
    ads: A::Backing,
    logs: A::Backing,
    hwconfig: Option<HwconfigDma<A::Backing>>,
    huc: Option<HucDma<A::Backing>>,
}
impl<A: BootAllocator> Resources<A> {
    fn free(mut self) {
        self.allocator.free(self.image);
        self.allocator.free(self.ads);
        self.allocator.free(self.logs);
        if let Some(huc) = self.huc {
            self.allocator.free(huc.backing);
        }
        if let Some(output) = self.hwconfig {
            self.allocator.free(output.backing);
        }
    }
}

/// Which GuC of the tile this bootstrap owns. The media role is constructed
/// only over a `MediaGsi` window (see `GuCBoot::stage_media`), so its
/// GSI-translated GuC registers and its media mailbox cannot be mismatched.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum GuCRole {
    Primary,
    Media(crate::intel_gpu_gt::media::MediaIp),
}

pub struct GuCBoot<M: MmioWindow, A: BootAllocator> {
    mmio: M,
    resources: ManuallyDrop<Resources<A>>,
    platform: GtPlatform,
    role: GuCRole,
    config: BootConfig,
    huc_exposed: bool,
    huc_dma_done: bool,
    upload: u32,
    state: BootState,
    deadline: u64,
    released: bool,
    hwconfig: Option<Arc<HardwareConfig>>,
    scheduling: Option<crate::intel_gpu_guc_sched::SchedulingAds>,
    reload: bool,
    submission_version: (u8, u8, u8),
    firmware_version: (u8, u8, u8),
    incarnation: u64,
    workarounds: Option<GuCWorkarounds>,
}

pub(crate) struct LiveLog<'a, B> {
    pub backing: &'a B,
    pub firmware_version: (u8, u8, u8),
    pub incarnation: u64,
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

    pub(crate) fn live_log(&self) -> Option<LiveLog<'_, A::Backing>> {
        if self.released || self.state != BootState::Ready || self.incarnation == 0 {
            return None;
        }
        Some(LiveLog {
            backing: &self.resources.logs,
            firmware_version: self.firmware_version,
            incarnation: self.incarnation,
        })
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

    pub(crate) fn stage_with_huc(
        mmio: M,
        allocator: A,
        firmware: &GuCFirmware,
        huc: &crate::intel_gpu_huc::Firmware,
        mut config: BootConfig,
    ) -> Result<Self, BootError> {
        if firmware.platform() != crate::intel_gpu_huc::PLATFORM {
            return Err(BootError::Unsupported);
        }
        let huc = huc.image();
        config.huc_upload_bytes =
            u32::try_from(huc.upload.len()).map_err(|_| BootError::Address)?;
        Self::stage_images(
            mmio,
            allocator,
            firmware.platform(),
            firmware.image(),
            config,
            Some(huc),
        )
    }

    fn stage_image(
        mmio: M,
        allocator: A,
        platform: GtPlatform,
        image: CssImage<'_>,
        config: BootConfig,
    ) -> Result<Self, BootError> {
        Self::stage_images(mmio, allocator, platform, image, config, None)
    }

    fn stage_images(
        mmio: M,
        mut allocator: A,
        platform: GtPlatform,
        image: CssImage<'_>,
        config: BootConfig,
        huc: Option<crate::intel_gpu_huc::Image<'_>>,
    ) -> Result<Self, BootError> {
        if huc.as_ref().is_some_and(|h| {
            platform != crate::intel_gpu_huc::PLATFORM
                || usize::try_from(config.huc_upload_bytes).ok() != Some(h.upload.len())
        }) {
            return Err(BootError::Unsupported);
        }
        let profile = platform.guc().ok_or(BootError::Unsupported)?;
        if GtPlatform::from_pci(0x8086, config.device_id) != Some(platform)
            || image.version < profile.minimum_version
            || image.signature.len() != 384
        {
            return Err(BootError::Device);
        }
        if (platform.is_xe2() && config.uncached_mocs.is_none_or(|index| index > 15))
            || (!platform.is_xe2() && config.uncached_mocs.is_some())
        {
            return Err(BootError::Cache);
        }
        let upload = u32::try_from(image.upload.len()).map_err(|_| BootError::Address)?;
        if platform.is_gen12() || platform.is_headless_integrated() {
            WopcmLayout::plan_total(upload, config.huc_upload_bytes, 0x200000)?;
        } else {
            WopcmLayout::plan(upload, config.huc_upload_bytes)?;
        }
        let image_pages = (upload + 384).div_ceil(PAGE);
        let ads_pages = (ADS_PRIVATE + image.private_data_bytes).div_ceil(PAGE);
        let mut allocations: Vec<A::Backing> = Vec::new();
        allocations
            .try_reserve_exact(3 + usize::from(huc.is_some()))
            .map_err(|_| BootError::Allocation(SubmitError::OutOfMemory))?;
        let huc_pages = huc
            .as_ref()
            .map(|h| (h.upload.len() + h.signature.len()).div_ceil(PAGE as usize) as u32);
        for pages in [
            Some(image_pages),
            Some(ads_pages),
            Some(LOG_BYTES / PAGE),
            huc_pages,
        ]
        .into_iter()
        .flatten()
        {
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
        let huc = huc.map(|h| {
            let backing = allocations.pop().expect("HuC image");
            backing.zero_fill();
            for (i, word) in h
                .upload
                .chunks_exact(4)
                .chain(h.signature.chunks_exact(4))
                .enumerate()
            {
                backing.write32(
                    i as u64 * 4,
                    u32::from_le_bytes(word.try_into().expect("HuC dword")),
                );
            }
            HucDma {
                backing,
                upload: config.huc_upload_bytes,
                version: h.version,
            }
        });
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
                huc,
            }),
            platform,
            role: GuCRole::Primary,
            config,
            huc_exposed: false,
            huc_dma_done: false,
            upload,
            state: BootState::Staged,
            deadline: 0,
            released: false,
            hwconfig: None,
            scheduling: None,
            reload: false,
            submission_version: image.submission_version,
            firmware_version: image.version,
            incarnation: 0,
            workarounds: None,
        })
    }

    pub fn state(&self) -> BootState {
        self.state
    }

    pub(crate) fn platform(&self) -> GtPlatform {
        self.platform
    }

    pub(crate) fn role(&self) -> GuCRole {
        self.role
    }

    pub(crate) fn device_id(&self) -> u16 {
        self.config.device_id
    }

    pub(crate) fn revision(&self) -> u8 {
        self.config.revision
    }

    pub(crate) fn diagnostic_allocator(&self) -> A
    where
        A: Clone,
    {
        self.resources.allocator.clone()
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
        if let Some(huc) = &mut r.huc {
            r.allocator.configure_cache(&mut huc.backing, policy)?;
        }
        Ok(())
    }

    pub(crate) fn scheduler(
        &self,
        engines: crate::intel_gpu_engine::EngineSet,
    ) -> Result<crate::intel_gpu_guc_sched::GuCScheduler<A>, BootError>
    where
        A: Clone,
    {
        if self.state != BootState::Ready
            || (self.needs_hwconfig() && self.hwconfig.is_none())
            || self.submission_version.0 != 1
        {
            return Err(BootError::Unsupported);
        }
        let allocator = self.resources.allocator.clone();
        match self.role {
            GuCRole::Primary => crate::intel_gpu_guc_sched::GuCScheduler::allocate(
                allocator,
                self.platform,
                engines,
            ),
            // xe_hw_engine.c builds GT1's engines from the media fuses and
            // xe_guc_ads.c its ADS from that list; HWCONFIG is GT0-only.
            GuCRole::Media(_) => crate::intel_gpu_guc_sched::GuCScheduler::allocate_media(
                allocator,
                self.platform,
                engines,
            ),
        }
        .map_err(BootError::Scheduling)
    }

    /// xe_guc_hwconfig_init skips every non-GT0 GuC: only the primary GuC of
    /// a HWCONFIG platform must hold the table before scheduling.
    fn needs_hwconfig(&self) -> bool {
        self.role == GuCRole::Primary && self.platform.has_hwconfig()
    }

    pub(crate) fn begin_scheduling(
        &mut self,
        ads: crate::intel_gpu_guc_sched::SchedulingAds,
        now: u64,
    ) -> Result<(), BootError> {
        if self.state != BootState::Ready
            || (self.needs_hwconfig() && self.hwconfig.is_none())
            || self.scheduling.is_some()
        {
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
            if [&r.image, &r.ads, &r.logs]
                .into_iter()
                .chain(r.huc.as_ref().map(|h| &h.backing))
                .any(|old| {
                    (base as u64) < old.ggtt_offset() as u64 + old.size_pages() as u64 * 4096
                        && (old.ggtt_offset() as u64) < base as u64 + pages as u64 * 4096
                })
            {
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
        XeLpgTransport::allocate_with_mailbox(
            self.platform,
            match self.role {
                GuCRole::Primary => MailboxRegisters::PRIMARY,
                GuCRole::Media(_) => MailboxRegisters::MEDIA,
            },
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
        self.huc_dma_done = false;
        if self.mmio.read32(GDRST) != 0 || self.mmio.read32(DMA_CTRL) & 1 != 0 {
            return Err(BootError::Busy);
        }
        let workarounds = match self.role {
            GuCRole::Primary => {
                let ip = crate::intel_gpu_gt::GraphicsIp::read(&self.mmio, self.platform)
                    .map_err(BootError::Graphics)?;
                let mut workarounds =
                    GuCWorkarounds::for_rcs(self.platform, self.config.device_id, ip);
                if self.platform.is_headless_integrated() {
                    let fuse = self.mmio.read32(0x9114);
                    if fuse == u32::MAX || fuse != self.mmio.read32(0x9114) {
                        return Err(BootError::Unavailable);
                    }
                    if fuse & 0x000f0000 != 0 {
                        workarounds.flags |= 0x00400000;
                    }
                }
                workarounds
            }
            GuCRole::Media(ip) => {
                // The staged GT1 identity must still be current under media
                // wake. The GSI window reads GMD_ID at MEDIA_GT_GSI_OFFSET.
                let gmd = self.mmio.read32(0xd8c);
                if gmd == u32::MAX {
                    return Err(BootError::Unavailable);
                }
                if gmd != ip.gmd || self.mmio.read32(0xd8c) != gmd {
                    return Err(BootError::Device);
                }
                GuCWorkarounds::for_media(self.platform, ip).ok_or(BootError::Unsupported)?
            }
        };
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
            // Conservative ownership requirement for enabled TGL HuC: the
            // locked partition must select GuC as loading agent. Linux masks
            // this bit in its inherited-layout path; never rewrite its lock.
            if self.resources.huc.is_some() && offset & 2 == 0 {
                return Err(BootError::Wopcm);
            }
            if size & 1 == 0 || offset & 1 == 0 {
                return Err(BootError::Wopcm);
            }
            return WopcmLayout {
                base: offset & 0xffffc000,
                size: size & 0xfffff000,
            }
            .validate(0x800000, self.upload, self.config.huc_upload_bytes);
        }
        let layout = if self.platform.is_gen12() || self.platform.is_headless_integrated() {
            WopcmLayout::plan_total(self.upload, self.config.huc_upload_bytes, 0x200000)?
        } else {
            WopcmLayout::plan(self.upload, self.config.huc_upload_bytes)?
        };
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

    fn wa_offset(&self) -> u64 {
        if self.platform.is_gen12()
            && self.scheduling.is_some_and(|config| {
                config.engines.iter().enumerate().any(|(index, state)| {
                    state.is_some() && crate::intel_gpu_engine::Engine::ALL[index].is_media()
                })
            })
        {
            0x5000
        } else {
            WA_KLVS
        }
    }

    fn upload(&mut self, now: u64) -> Result<(), BootError> {
        let wa_offset = self.wa_offset();
        self.layout()?;
        if !self.huc_dma_done && self.resources.huc.is_some() {
            let status = self.mmio.read32(0xc1dc);
            if status == u32::MAX {
                return Err(BootError::Unavailable);
            }
            if status & 1 != 0 {
                return Err(BootError::Reset);
            }
            let r = &mut *self.resources;
            let huc = r.huc.as_ref().expect("owned HuC");
            r.allocator.sync_for_device(&huc.backing)?;
            invalidate_guc_tlb(&self.mmio, self.platform);
            self.huc_exposed = true; // sticky before the first hardware address publication
            self.mmio.write32(0xc300, huc.backing.ggtt_offset());
            self.mmio.write32(0xc304, 8 << 16);
            self.mmio.write32(0xc308, 0);
            self.mmio.write32(0xc30c, 7 << 16);
            self.mmio.write32(0xc310, huc.upload);
            self.deadline = now.checked_add(100_000_000).ok_or(BootError::Timeout)?;
            self.state = BootState::HucDma;
            // This lower-level boot owner cannot reclaim this graph on
            // GuC-only Stopped. The enclosing full Gen12 reset retires it.
            fence(Ordering::SeqCst);
            self.mmio.write32(DMA_CTRL, 0x02010201);
            let _ = self.mmio.read32(DMA_CTRL);
            return Ok(());
        }
        let power_mask = self.mmio.read32(0xa168);
        if power_mask == u32::MAX {
            return Err(BootError::Unavailable);
        }
        let r = &mut *self.resources;
        let workarounds = self.workarounds.ok_or(BootError::State)?;
        // Reset completion is independently verified before upload. No live
        // firmware writes this BO now; never relabel previous-incarnation log
        // bytes as output from the firmware about to start.
        r.logs.zero_fill();
        self.incarnation = crate::intel_gpu_guc_log::next_incarnation();
        if workarounds.klvs.len() > PAGE as usize / 4
            || wa_offset + u64::from(PAGE) > u64::from(ADS_PRIVATE)
        {
            return Err(BootError::Address);
        }
        // GuC is proven in reset. Publish bounded 16:16 KLVs including source length-one payloads,
        // the complete 64-bit ADS pointer and its byte count before DMA.
        for i in 0..PAGE / 4 {
            r.ads.write32(wa_offset + u64::from(i) * 4, 0);
        }
        for (i, word) in workarounds.klvs.iter().copied().enumerate() {
            r.ads.write32(wa_offset + i as u64 * 4, word);
        }
        r.ads
            .write32(0x11a4, r.ads.ggtt_offset() + wa_offset as u32);
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
        if crate::intel_gpu_guc_log::stream::enabled() {
            params[0] |= 1 << 1; // source half-full notifications; verbosity stays off
        }
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
                        let wa_offset = self.wa_offset();
                        let ads = &self.resources.ads;
                        let base = ads.ggtt_offset();
                        // Populate only while GuC is proven stopped. Mapping
                        // uses dense logical instances, enable masks and
                        // register-state headers use physical instances.
                        // xe_guc_ads.c mapping/enable masks, golden LRCA with
                        // its post-register state size, and per-engine saves.
                        let engines = crate::intel_gpu_engine::EngineSet::from_bits(
                            config
                                .engines
                                .iter()
                                .enumerate()
                                .fold(0, |bits, (i, state)| {
                                    bits | if state.is_some() { 1 << i } else { 0 }
                                }),
                        );
                        let policy = config.reset_policy.ok_or(BootError::State)?;
                        if !policy.matches(self.platform, engines)
                            || policy.device_id() != self.config.device_id
                        {
                            return Poll::Ready(Err(BootError::Device));
                        }
                        // Precompute and bound every engine's complete save
                        // list before changing any ADS header. The register
                        // page ends at the separate firmware-WA KLV page.
                        let mut regsets = Vec::new();
                        regsets
                            .try_reserve_exact(engines.iter().count())
                            .map_err(|_| BootError::Allocation(SubmitError::OutOfMemory))?;
                        let protected = [
                            Some(&self.resources.ads),
                            Some(&self.resources.image),
                            Some(&self.resources.logs),
                            self.resources.huc.as_ref().map(|h| &h.backing),
                        ]
                        .map(|backing| {
                            backing.map(|backing| {
                                let start = u64::from(backing.ggtt_offset());
                                (
                                    start,
                                    start + u64::from(backing.size_pages()) * u64::from(PAGE),
                                )
                            })
                        });
                        let mut state_ranges = Vec::new();
                        state_ranges
                            .try_reserve_exact(engines.iter().count() * 2)
                            .map_err(|_| BootError::Allocation(SubmitError::OutOfMemory))?;
                        let mut next_save = 0x2000u64;
                        for engine in engines.iter() {
                            let registers = policy.registers(engine).ok_or(BootError::State)?;
                            let end = next_save
                                .checked_add(registers.len() as u64 * 16)
                                .ok_or(BootError::Address)?;
                            let state = config.engines[engine.index()].ok_or(BootError::State)?;
                            if end > wa_offset
                                || wa_offset + u64::from(PAGE) > u64::from(ADS_PRIVATE)
                                || u64::from(ADS_PRIVATE)
                                    > u64::from(ads.size_pages()) * u64::from(PAGE)
                                || state.bytes != engine.lrc_pages(self.platform) * PAGE
                                || state.bytes < PAGE + 96 * 4
                                || state.golden % PAGE != 0
                                || state.hwsp % PAGE != 0
                                || state.golden.checked_add(state.bytes).is_none()
                            {
                                return Poll::Ready(Err(BootError::Address));
                            }
                            // Golden images and HWSPs remain separately owned
                            // DMA allocations, never ADS/private/KLV storage or
                            // another engine's writable state. Check every
                            // interval before publishing even the first header.
                            for (start, bytes) in [(state.golden, state.bytes), (state.hwsp, PAGE)]
                            {
                                let start = u64::from(start);
                                let end = start + u64::from(bytes);
                                if start < u64::from(GUC_GGTT_MIN)
                                    || end > 0xfee00000
                                    || protected
                                        .iter()
                                        .flatten()
                                        .chain(state_ranges.iter())
                                        .any(|&(other, limit)| start < limit && other < end)
                                {
                                    return Poll::Ready(Err(BootError::Address));
                                }
                                state_ranges.push((start, end));
                            }
                            regsets.push((engine, next_save, registers));
                            next_save = end;
                        }
                        // All class/physical headers and state pointers are now
                        // bounded. Saves end before the KLV page; that full page
                        // ends before firmware-private storage at 0x6000.
                        // guc_policies_init: allow firmware to reset an
                        // engine whose context fails to preempt in time.
                        ads.write32(POLICIES + 76, 0);
                        for (engine, saves, registers) in regsets {
                            let state = config.engines[engine.index()].ok_or(BootError::State)?;
                            let class = u64::from(engine.guc_class());
                            let base_reg = engine.base();
                            let logical = u64::from(
                                engines.logical_instance(engine).expect("published engine"),
                            );
                            let physical = engine.physical_instance();
                            let mapping = SYSINFO + class * 32 + logical / 4 * 4;
                            let shift = (logical % 4) * 8;
                            ads.write32(
                                mapping,
                                (ads.read32(mapping) & !(0xff << shift)) | physical << shift,
                            );
                            let enabled = SYSINFO + 512 + class * 4;
                            ads.write32(enabled, ads.read32(enabled) | 1 << physical);
                            // GuC's golden image is per class, not instance.
                            // COPY0's identical class state remains its source.
                            if logical == 0 {
                                ads.write32(0x1014 + class * 4, state.golden);
                                ads.write32(0x1054 + class * 4, state.bytes - 4096 - 96 * 4);
                            }
                            let header = class * 256 + u64::from(physical) * 8;
                            ads.write32(header, base + saves as u32);
                            ads.write32(header + 4, registers.len() as u32);
                            for (i, register) in registers.iter().enumerate() {
                                let entry = saves + i as u64 * 16;
                                ads.write32(entry, register.offset);
                                // The firmware owns value as save scratch;
                                // retain the initial HWS value for the ring.
                                ads.write32(
                                    entry + 4,
                                    if register.offset == base_reg + 0x80 {
                                        state.hwsp
                                    } else {
                                        0
                                    },
                                );
                                ads.write32(entry + 8, register.flags);
                                ads.write32(entry + 12, 0);
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
            BootState::HucDma => {
                let control = self.mmio.read32(DMA_CTRL);
                if control == u32::MAX {
                    return Poll::Ready(Err(BootError::Unavailable));
                }
                if control & 1 != 0 {
                    return Poll::Pending;
                }
                fence(Ordering::Acquire);
                self.mmio.write32(DMA_CTRL, 0x02000000);
                self.huc_dma_done = true;
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

    pub(crate) fn retire_ggtt(&mut self) -> Result<(), BootError> {
        if !matches!(self.state, BootState::Stopped | BootState::Staged) {
            return Err(BootError::State);
        }
        self.resources.allocator.retire_ggtt()
    }

    pub(crate) fn huc_upload(&self) -> Option<crate::intel_gpu_huc::Upload> {
        let h = self.resources.huc.as_ref()?;
        Some(crate::intel_gpu_huc::Upload {
            rsa: h.backing.ggtt_offset().checked_add(h.upload)?,
            version: h.version,
        })
    }

    /// Only the enclosing Gen12 owner calls this after full engine reset and
    /// release of every retained media wake ACK, never GuC-only reset.
    pub(crate) fn huc_full_reset_complete(&mut self) {
        self.huc_exposed = false;
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
    /// For HuC, the proof additionally covers full Gen12 engine reset and
    /// media-wake ACK retirement; GuC-only Stopped is insufficient.
    /// The GT owner proved every GuC/firmware-DMA agent stopped and invalidated
    /// stale firmware/ADS/log addresses. A timeout or unreadable BAR is no proof.
    pub unsafe fn release_after_gt_reset(mut self) {
        self.free();
    }
}

impl<W: MmioWindow, A: BootAllocator> GuCBoot<crate::intel_gpu_gt::media::MediaGsi<W>, A> {
    /// Stage the MTL/Arrow standalone media GuC with the same GuC firmware
    /// family as GT0 (xe_uc_fw.c: METEORLAKE GT_TYPE_ANY mtl_guc_70). WOPCM,
    /// reset, DMA, status and ADS registers go through the media GSI window;
    /// HWCONFIG is never queried (xe_guc_hwconfig_init: GT0 only) and no HuC
    /// image is reserved (MTL HuC is GSC-loaded).
    pub(crate) fn stage_media(
        mmio: crate::intel_gpu_gt::media::MediaGsi<W>,
        allocator: A,
        firmware: &GuCFirmware,
        config: BootConfig,
        ip: crate::intel_gpu_gt::media::MediaIp,
    ) -> Result<Self, BootError> {
        if !crate::intel_gpu_gt::media::profile_eligible(firmware.platform())
            || config.huc_upload_bytes != 0
            || GuCWorkarounds::for_media(firmware.platform(), ip).is_none()
        {
            return Err(BootError::Unsupported);
        }
        let mut boot = Self::stage_image(
            mmio,
            allocator,
            firmware.platform(),
            firmware.image(),
            config,
        )?;
        boot.role = GuCRole::Media(ip);
        Ok(boot)
    }
}

impl<M: MmioWindow, A: BootAllocator> Drop for GuCBoot<M, A> {
    fn drop(&mut self) {
        if !self.huc_exposed && matches!(self.state, BootState::Staged | BootState::Stopped) {
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
    #[derive(Clone)]
    struct ParallelContext {
        images: Vec<u32>,
        scratch: u32,
        enabled: bool,
    }
    #[derive(Default)]
    struct Device {
        // Opt-in independent whole-device model. Old fixture behavior is
        // unchanged unless a smallbar test explicitly enables these semantics.
        smallbar: bool,
        smallbar_flrs: usize,
        smallbar_guc_retired: bool,
        smallbar_engines_retired: bool,
        smallbar_reject: Option<u64>,
        smallbar_hold_flr: bool,
        slpc_dcc: Vec<(u32, u32)>,
        profile: Option<GtPlatform>,
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
        // Firmware-owned virtual-context routing, independent of the LRC's
        // class template. Tests can request a different logical placement
        // on the next restore, just as GuC may migrate a width-one context.
        virtual_contexts: BTreeMap<u32, (u32, u32)>,
        virtual_pick: Option<u32>,
        virtual_restores: Vec<(u32, u32)>,
        gen12_restores: Vec<(u32, u32, u32)>,
        nonrender_seeds: Vec<(u32, [u32; 4])>,
        parallel_contexts: BTreeMap<u32, ParallelContext>,
        parallel_lanes: Option<u8>,
        parallel_reply_child: bool,
        parallel_reply_lane: Option<u32>,
        parallel_starts: Vec<(u32, u32)>,
        parallel_join_hold: bool,
        parallel_join_stores: Vec<(u32, u64, u64)>,
        stream_controls: Vec<(u16, u16, u32)>,
        stream_fences: BTreeSet<u16>,
        stream_acks: usize,
        stream_enabled: bool,
        stream_drop: Option<(u16, u32)>,
        stream_overwrite: bool,
        mmio_reads: Cell<usize>,
        // Media GuC second-TLB registration and the write index at which
        // it was first registered (before any firmware address publication).
        media_tlb: Option<bool>,
        media_tlb_at: Option<usize>,
        // Media GuC GGTT invalidation mode: CT (submission enabled) or MMIO.
        media_ct: Option<bool>,
    }
    #[derive(Clone)]
    struct Window(Rc<RefCell<Device>>);
    impl MmioWindow for Window {
        fn read32(&self, offset: u64) -> u32 {
            {
                let d = self.0.borrow();
                d.mmio_reads.set(d.mmio_reads.get() + 1);
            }
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
            if device.smallbar && device.smallbar_reject == Some(offset) {
                return;
            }
            let media = [
                0x1c0000u64,
                0x1c4000,
                0x1d0000,
                0x1d4000,
                0x1e0000,
                0x1e4000,
                0x1f0000,
                0x1f4000,
                0x1c8000,
                0x1d8000,
                0x1e8000,
                0x1f8000,
            ]
            .into_iter()
            .find(|base| offset == base + 0x9c || offset == base + 0x29c || offset == base + 0xc4);
            let actual = match offset {
                0x101018 if device.smallbar => *device.regs.get(&offset).unwrap_or(&0) & !value,
                0x101010 if device.smallbar && value & 0x80000000 != 0 => {
                    assert_eq!(device.allocations, 0, "destructive FLR after arena DMA");
                    assert_eq!(device.regs[&0x101018] & 0x80000000, 0, "stale ACK");
                    device.smallbar_flrs += 1;
                    device.smallbar_guc_retired = false;
                    device.smallbar_engines_retired = false;
                    device.regs.extend([
                        (0xa188, 2),
                        (0xa278, 2),
                        (0xdfc, 0),
                        (0xd84, 0),
                        (0x38a188, 0),
                        (0x380dfc, 0),
                        (0x38941c, 0),
                        (0x38c000, 1),
                        (0x38c314, 0),
                    ]);
                    for reg in (0x4800..0x4880).step_by(4) {
                        device.regs.insert(reg, 0);
                    }
                    if device.smallbar_hold_flr {
                        value
                    } else {
                        device.regs.insert(0x101018, 0x80000000);
                        value & !0x80000000
                    }
                }
                0x38941c if device.smallbar => {
                    assert_eq!(device.smallbar_flrs, 1);
                    assert_eq!(device.regs[&0x38a188] & 1, 1);
                    assert_eq!(device.regs[&0x380dfc] & 1, 1);
                    match value {
                        8 => device.smallbar_guc_retired = true,
                        1 => {
                            assert!(device.smallbar_guc_retired);
                            device.smallbar_engines_retired = true;
                        }
                        _ => panic!("unqualified media reset"),
                    }
                    0
                }
                _ if device.profile.is_some_and(GtPlatform::is_gen12) && media.is_some() => {
                    let base = media.unwrap_or_default();
                    let old = *device.regs.get(&offset).unwrap_or(&0);
                    let mut next = (old & !(value >> 16)) | (value & (value >> 16));
                    if offset == base + 0x9c {
                        if next & 0x100 != 0 {
                            next |= 0x200;
                        } else {
                            next &= !0x200;
                        }
                    }
                    next
                }
                _ if device.profile.is_some_and(GtPlatform::is_gen12)
                    && ((0xa540..=0xa55c).contains(&offset)
                        || (0xa560..=0xa56c).contains(&offset)) =>
                {
                    let old = *device.regs.get(&offset).unwrap_or(&0);
                    (old & !(value >> 16)) | (value & (value >> 16))
                }
                0x209c | 0x2209c | 0x229c | 0x2229c
                    if device.profile.is_some_and(GtPlatform::is_gen12) =>
                {
                    let old = *device.regs.get(&offset).unwrap_or(&0);
                    let mut next = (old & !(value >> 16)) | (value & (value >> 16));
                    if matches!(offset, 0x209c | 0x2209c) {
                        // Stopping the otherwise idle modeled CS exposes its
                        // read-only MODE_IDLE bit in MI_MODE, not RING_MODE.
                        if next & 0x100 != 0 {
                            next |= 0x200;
                        } else {
                            next &= !0x200;
                        }
                    }
                    next
                }
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
                0xd8c | 0x380d8c => *device.regs.get(&offset).unwrap_or(&0), // read-only GMD_ID
                0xc050 | 0xc340 | 0x38c050 | 0x38c340 if !device.reject_wopcm => value | 1,
                0xc314 | 0x38c314 | 0xa188 | 0xa278 | 0x38a188 | 0x20ec | 0x83b4 | 0xe48c
                | 0xe18c | 0xe4f4 | 0xe5f0 | 0xe420 | 0xe49c | 0xe4f0 | 0x20d4 | 0xe194
                | 0xe4c4 | 0xe5f4 | 0x2050 | 0x220d4 | 0x22050 | 0x3ee0d4 | 0x3ee050 | 0x1a0d4
                | 0x1a050 | 0x1c0d4 | 0x1c050 | 0x1e0d4 | 0x1e050 | 0x260d4 | 0x26050 | 0x14800
                | 0x14804 | 0x20c4 | 0x220c4 | 0x3ee0c4 | 0x1a0c4 | 0x1c0c4 | 0x1e0c4 | 0x260c4 => {
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
            if device.smallbar && offset == 0x38a188 {
                device.regs.insert(0x380dfc, actual & 1);
            }
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
            if device.smallbar {
                assert_eq!(device.smallbar_flrs, 1, "first PTE before fresh FLR");
                assert!(
                    device.smallbar_guc_retired && device.smallbar_engines_retired,
                    "first PTE before independent media retirement"
                );
                assert_eq!(device.regs[&0x38a188] & 1, 1);
                assert_eq!(device.regs[&0x380dfc] & 1, 1);
            }
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
        fn retire_ggtt(&mut self) -> Result<(), BootError> {
            Ok(())
        } // model has no GGTT PTE window

        fn register_media_guc_tlb(&mut self, live: bool) -> Result<(), BootError> {
            let mut device = self.0.borrow_mut();
            if live && device.media_tlb_at.is_none() {
                device.media_tlb_at = Some(device.writes.len());
            }
            device.media_tlb = Some(live);
            device.media_ct = None;
            Ok(())
        }

        fn media_guc_submission(&mut self, enabled: bool) -> Result<(), BootError> {
            let mut device = self.0.borrow_mut();
            if device.media_tlb != Some(true) {
                return Err(BootError::Cache);
            }
            device.media_ct = Some(enabled);
            Ok(())
        }

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
        window.0.borrow_mut().profile = Some(platform);
        window
            .0
            .borrow_mut()
            .regs
            .entry(0xd8c)
            .or_insert(if platform.is_ptl() {
                30 << 22
            } else if platform.is_lnl() {
                (20 << 22) | (4 << 14)
            } else if platform == GtPlatform::Battlemage {
                (20 << 22) | (1 << 14)
            } else {
                (12 << 22) | (70 << 14)
            });
        let device_id = match platform {
            GtPlatform::Gen12(crate::intel_gpu_gt::Gen12Platform::TigerLake) => 0x9a49,
            GtPlatform::Gen12(crate::intel_gpu_gt::Gen12Platform::AlderLakeP) => 0x46a6,
            GtPlatform::Gen12(crate::intel_gpu_gt::Gen12Platform::AlderLakeS) => 0x4680,
            GtPlatform::Gen12(crate::intel_gpu_gt::Gen12Platform::AlderLakeN) => 0x46d1,
            GtPlatform::Alchemist => 0x56a0,
            GtPlatform::Battlemage => 0xe20b,
            _ if platform.is_ptl() => 0xb080,
            _ if platform.is_lnl() => 0x6420,
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
                uncached_mocs: platform.is_xe2().then_some(2),
            },
        )
        .unwrap()
    }
    fn reset_done(window: &Window) {
        let mut device = window.0.borrow_mut();
        if device.profile.is_some_and(GtPlatform::is_gen12) && device.regs.get(&0x941c) == Some(&1)
        {
            for base in [
                0x2000, 0x22000, 0x1c0000, 0x1c4000, 0x1d0000, 0x1d4000, 0x1e0000, 0x1e4000,
                0x1f0000, 0x1f4000, 0x1c8000, 0x1d8000, 0x1e8000, 0x1f8000,
            ] {
                for offset in [0x9c, 0x29c] {
                    device.regs.insert(base + offset, 0);
                }
            }
        }
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

    fn smoke_gen12_media_ads_rejects_state_alias_before_any_header_write() -> TestResult {
        use crate::intel_gpu_engine::{Engine, EngineSet};
        use crate::intel_gpu_guc_sched::{EngineAds, SchedulingAds};
        use crate::intel_gpu_reset_policy::ResetPolicy;
        let platform = GtPlatform::Gen12(crate::intel_gpu_gt::Gen12Platform::TigerLake);
        for failure in 0..4 {
            let (w, arena) = model();
            let mut boot = stage(w.clone(), arena.clone(), platform);
            ready(&mut boot, &w);
            let engines = EngineSet::of(&[Engine::Rcs0, Engine::Bcs0, Engine::Vcs1]);
            let mut config = SchedulingAds {
                engines: [None; Engine::COUNT],
                reset_policy: ResetPolicy::new(
                    platform, 0x9a49, 1200, 0, 0x40000000, 0, engines, false,
                ),
            };
            for (index, engine) in engines.iter().enumerate() {
                config.engines[engine.index()] = Some(EngineAds {
                    golden: 0x30000000 + index as u32 * 0x10000,
                    bytes: engine.lrc_pages(platform) * 4096,
                    hwsp: 0x31000000 + index as u32 * 4096,
                });
            }
            let ads = boot.resources.ads.ggtt_offset();
            let state = config.engines[Engine::Vcs1.index()].as_mut().unwrap();
            match failure {
                0 => state.golden = ads + 0x5000, // future KLV page
                1 => state.hwsp = ads + 0x6000,   // firmware-private page
                2 => state.golden = 0x30010000,   // existing BCS golden
                _ => state.bytes = 4096,          // under-sized class image
            }
            boot.begin_scheduling(config, 10).unwrap();
            assert_eq!(boot.wa_offset(), 0x5000);
            let before = w.0.borrow().memory[&ads].borrow().clone();
            reset_done(&w);
            assert_eq!(boot.poll(11), Poll::Ready(Err(BootError::Address)));
            assert_eq!(*w.0.borrow().memory[&ads].borrow(), before);
            assert!(boot.resources.ads.size_pages() >= 6);
            stop(&mut boot, &w);
            drop(boot);
            assert_eq!(arena.live_allocations(), 0);
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen12",
        smoke_gen12_media_ads_rejects_state_alias_before_any_header_write
    );

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

    const MTL: GtPlatform = GtPlatform::Integrated(crate::intel_gpu::Generation::MeteorLake);
    /// Media GMD_ID 13.00 step 2 behind the GSI base.
    const MEDIA_GMD: u32 = (13 << 22) | 2;

    fn media_model() -> (Window, Arena) {
        let (window, arena) = model();
        {
            let mut device = window.0.borrow_mut();
            device.profile = Some(MTL);
            // GT0 owns its own wake/GMD; the media GuC must never touch them.
            device.regs.insert(0xd8c, (12 << 22) | (70 << 14));
            device.regs.insert(0xa188, 1);
            device.regs.insert(0x380d8c, MEDIA_GMD);
            device.regs.insert(0x380dfc, 0);
            device.regs.insert(0x38a188, 0);
            device.regs.insert(0x1900e8, 0x8000_0000);
        }
        (window, arena)
    }

    fn media_config() -> BootConfig {
        BootConfig {
            device_id: 0x7d55,
            revision: 3,
            huc_upload_bytes: 0,
            uncached_mocs: None,
        }
    }

    fn media_policy() -> crate::intel_gpu_gt_hw::CachePolicy {
        crate::intel_gpu_gt_hw::CachePolicy {
            platform: MTL,
            ggtt_pat: 3,
            media: None,
        }
    }

    fn media_reset_done(window: &Window) {
        let mut device = window.0.borrow_mut();
        device.regs.insert(0x38941c, 0);
        device.regs.insert(0x38c000, 1);
        device.regs.insert(0x38c314, 0);
    }

    /// Offsets a media GuC owner may write: GSI-translated GT1 registers,
    /// the absolute media mailbox/doorbell, the shared GT_PM_CONFIG doorbell
    /// enable (xe_guc.c writes it through either GT's window) and the media
    /// half of GUC_SG_INTR_MASK.
    fn media_owned(offset: u64) -> bool {
        (0x380000..0x3c0000).contains(&offset)
            || (0x190304..=0x19031c).contains(&offset)
            || matches!(offset, 0x13816c | 0x1900e8)
    }

    type MediaWindow = crate::intel_gpu_gt::media::MediaGsi<Window>;

    fn media_ready(gt: &mut GuCGt<MediaWindow, Arena>, window: &Window) {
        gt.begin(0).unwrap();
        assert_eq!(window.0.borrow().regs[&0x38a188] & 1, 1);
        assert!(gt.poll(1).is_pending());
        window.0.borrow_mut().regs.insert(0x380dfc, 1);
        assert!(gt.poll(2).is_pending());
        media_reset_done(window);
        assert!(gt.poll(3).is_pending());
        window.0.borrow_mut().regs.insert(0x38c314, 0x10);
        assert!(gt.poll(4).is_pending());
        window.0.borrow_mut().regs.insert(0x38c000, 0x8000f000);
        assert_eq!(gt.poll(5), Poll::Ready(Ok(GtState::Ready)));
    }

    fn media_ct(gt: &mut GuCGt<MediaWindow, Arena>, window: &Window) {
        gt.begin_ct(6).unwrap();
        for i in 0..6 {
            window.0.borrow_mut().regs.insert(0x190310, 0xf0000001);
            assert!(gt.poll(7 + i).is_pending());
        }
        window.0.borrow_mut().regs.insert(0x190310, 0xf0000000);
        assert_eq!(gt.poll(13), Poll::Ready(Ok(GtState::CtReady)));
    }

    fn media_stop(gt: &mut GuCGt<MediaWindow, Arena>, window: &Window) {
        gt.begin_stop(100).unwrap();
        assert!(gt.poll(101).is_pending());
        media_reset_done(window);
        assert!(gt.poll(102).is_pending());
        assert_eq!(gt.state(), GtState::Releasing);
        assert_eq!(window.0.borrow().regs[&0x38a188] & 1, 0);
        assert!(gt.poll(103).is_pending());
        window.0.borrow_mut().regs.insert(0x380dfc, 0);
        assert_eq!(gt.poll(104), Poll::Ready(Ok(GtState::Stopped)));
    }

    fn smoke_media_guc_boot_ct_and_stop_touch_only_gt1_registers() -> TestResult {
        let (window, arena) = media_model();
        let firmware = GuCFirmware::from_fixture(MTL, &image()).unwrap();
        let ip = crate::intel_gpu_gt::media::MediaIp::decode(MEDIA_GMD);
        let mut gt = GuCGt::stage_media(
            crate::intel_gpu_gt::media::MediaGsi::new(window.clone()),
            arena.clone(),
            &firmware,
            media_config(),
            ip,
            media_policy(),
        )
        .unwrap();
        assert_eq!(gt.guc_role(), GuCRole::Media(ip));
        media_ready(&mut gt, &window);
        {
            let device = window.0.borrow();
            // Same firmware family and wire sequence as GT0, at the GSI base.
            for pair in [
                (0x38941c, 8),
                (0x38c050, 0x3f3000),
                (0x38c340, 0x4000),
                (0x38c300, 0x20000000),
                (0x38c310, 144),
                (0x38c314, 0x00110011),
                (0x38cee8, 1),
            ] {
                assert!(device.writes.contains(&pair), "media GuC wire sequence");
            }
            // Media 13.00 GuC flags and ADS WA KLVs (Wa_14018913170,
            // Wa_16021333562, Wa_16026508708), scheduling still disabled.
            assert_eq!(device.regs[&0x38c188], 0x0040_0000);
            assert_eq!(device.regs[&0x38c18c], 0x4000);
            assert_eq!(device.regs[&0x38c198] >> 16, 0x7d55);
            let ads = device.memory[&0x20001000].borrow();
            assert_eq!(&ads[0x11a4 / 4..0x11b0 / 4], &[0x20004000, 0, 8]);
            assert_eq!(&ads[0x3000 / 4..0x3000 / 4 + 2], &[0x90020000, 0x900b0000]);
            assert!(ads[0x3000 / 4 + 2..0x4000 / 4].iter().all(|v| *v == 0));
            // Minimal ADS: no engine is enabled before media scheduling.
            assert!(ads[0x123c / 4..0x143c / 4].iter().all(|v| *v == 0x20202020));
            assert!(ads[0x143c / 4..0x147c / 4].iter().all(|v| *v == 0));
            assert_eq!(device.gmd_reads, 0, "GT0 GMD_ID is not the media identity");
        }
        media_ct(&mut gt, &window);
        {
            let device = window.0.borrow();
            assert!(device.writes.iter().any(|(reg, _)| *reg == 0x190304));
            assert!(device.writes.iter().any(|(reg, _)| *reg == 0x190310));
        }
        media_stop(&mut gt, &window);
        drop(gt);
        let device = window.0.borrow();
        assert!(
            device.writes.iter().all(|(reg, _)| media_owned(*reg)),
            "a media GuC owner wrote a GT0 register"
        );
        assert_eq!(device.regs[&0xa188], 1, "GT0 wake untouched");
        drop(device);
        assert_eq!(arena.live_allocations(), 0);
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_media_gt",
        smoke_media_guc_boot_ct_and_stop_touch_only_gt1_registers
    );

    fn smoke_media_guc_staging_and_identity_refusals_publish_nothing() -> TestResult {
        let ip = crate::intel_gpu_gt::media::MediaIp::decode(MEDIA_GMD);
        // Media workaround profile is exact to MTL/Arrow Xe_LPM+ 13.00.
        let wa = GuCWorkarounds::for_media(MTL, ip).unwrap();
        assert_eq!(
            (wa.flags, wa.klvs),
            (0x0040_0000, &[0x90020000, 0x900b0000][..])
        );
        assert!(GuCWorkarounds::for_media(
            MTL,
            crate::intel_gpu_gt::media::MediaIp::decode((13 << 22) | (1 << 14))
        )
        .is_none());
        assert!(GuCWorkarounds::for_media(GtPlatform::Battlemage, ip).is_none());
        // Non-MTL firmware or another media IP: refused before allocation.
        for (platform, gmd) in [(GtPlatform::Battlemage, MEDIA_GMD), (MTL, 20 << 22)] {
            let (window, arena) = media_model();
            let firmware = GuCFirmware::from_fixture(platform, &image()).unwrap();
            let staged = GuCGt::stage_media(
                crate::intel_gpu_gt::media::MediaGsi::new(window.clone()),
                arena.clone(),
                &firmware,
                media_config(),
                crate::intel_gpu_gt::media::MediaIp::decode(gmd),
                media_policy(),
            );
            assert!(matches!(
                staged.err(),
                Some(GtError::Boot(BootError::Unsupported))
            ));
            assert_eq!(arena.live_allocations(), 0);
            assert!(window.0.borrow().writes.is_empty());
        }
        // The staged identity changed before GuC reset: no reset, no DMA.
        let (window, arena) = media_model();
        let firmware = GuCFirmware::from_fixture(MTL, &image()).unwrap();
        let mut gt = GuCGt::stage_media(
            crate::intel_gpu_gt::media::MediaGsi::new(window.clone()),
            arena.clone(),
            &firmware,
            media_config(),
            ip,
            media_policy(),
        )
        .unwrap();
        gt.begin(0).unwrap();
        window.0.borrow_mut().regs.insert(0x380dfc, 1);
        window.0.borrow_mut().regs.insert(0x380d8c, MEDIA_GMD + 1);
        assert_eq!(
            gt.poll(1),
            Poll::Ready(Err(GtError::Boot(BootError::Device)))
        );
        assert!(!window
            .0
            .borrow()
            .writes
            .iter()
            .any(|(reg, _)| matches!(reg, 0x38941c | 0x38c314 | 0x941c | 0xc314)));
        // The lost owner still proves its stop before releasing memory.
        gt.begin_stop(2).unwrap();
        assert!(gt.poll(3).is_pending());
        window.0.borrow_mut().regs.insert(0x380dfc, 0);
        assert_eq!(gt.poll(4), Poll::Ready(Ok(GtState::Stopped)));
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
        assert!(window
            .0
            .borrow()
            .writes
            .iter()
            .all(|(reg, _)| media_owned(*reg)));
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_media_gt",
        smoke_media_guc_staging_and_identity_refusals_publish_nothing
    );

    fn smoke_media_guc_owner_registers_tlb_masks_irq_and_retains_on_unproven_stop() -> TestResult {
        use crate::intel_gpu_gt::media::{MediaGt, MediaGuc, MediaGucError, MediaGucState};
        let firmware = GuCFirmware::from_fixture(MTL, &image()).unwrap();
        let media = MediaGt::initialized_for_test(MTL, MEDIA_GMD, 0x0001_0005);
        // An uninitialized media GT cannot start a GuC.
        let (window, arena) = media_model();
        let fresh = MediaGt::new(MTL, 1274);
        assert!(matches!(
            MediaGuc::start(
                window.clone(),
                arena.clone(),
                &firmware,
                media_config(),
                &fresh,
                0
            )
            .err(),
            Some(MediaGucError::State)
        ));
        assert!(window.0.borrow().writes.is_empty());
        assert_eq!(arena.live_allocations(), 0);
        // Positive start: interrupt half masked and TLB registered before
        // the media wake request, then boot and CT through the GT1 owner.
        let mut guc = MediaGuc::start(
            window.clone(),
            arena.clone(),
            &firmware,
            media_config(),
            &media,
            0,
        )
        .unwrap();
        {
            let device = window.0.borrow();
            assert_eq!(device.regs[&0x1900e8], 0x8000_8000, "GT0 half preserved");
            assert_eq!(device.media_tlb, Some(true));
            let wake = device
                .writes
                .iter()
                .position(|pair| *pair == (0x38a188, 0x0001_0001))
                .unwrap();
            assert!(device.media_tlb_at.unwrap() <= wake);
        }
        assert_eq!(guc.state(), MediaGucState::Starting);
        assert!(guc.poll(1, || true).is_pending());
        window.0.borrow_mut().regs.insert(0x380dfc, 1);
        assert!(guc.poll(2, || true).is_pending());
        media_reset_done(&window);
        assert!(guc.poll(3, || true).is_pending());
        window.0.borrow_mut().regs.insert(0x38c314, 0x10);
        assert!(guc.poll(4, || true).is_pending());
        window.0.borrow_mut().regs.insert(0x38c000, 0x8000f000);
        // Ready -> the fused VDBOX0 and VEBOX0 wells are requested for
        // media scheduling; no CT is enabled before the scheduling reload
        // and nothing is published while starting.
        assert!(guc.poll(5, || true).is_pending());
        {
            let device = window.0.borrow();
            assert_eq!(device.regs[&0x38a540], 0x0001_0001);
            assert_eq!(device.regs[&0x38a560], 0x0001_0001);
            assert!(!device.writes.iter().any(|(reg, _)| *reg == 0x190304));
        }
        assert_eq!(guc.state(), MediaGucState::Starting);
        assert_eq!(guc.publication(), None);
        // Current loss is a GT error; the owner then proves its stop.
        assert!(matches!(
            guc.poll(14, || false),
            Poll::Ready(Err(MediaGucError::Gt(GtError::Unavailable)))
        ));
        assert_eq!(guc.state(), MediaGucState::Stopping);
        assert!(guc.poll(15, || true).is_pending());
        media_reset_done(&window);
        assert!(guc.poll(16, || true).is_pending());
        window.0.borrow_mut().regs.insert(0x380dfc, 0);
        assert_eq!(
            guc.poll(17, || true),
            Poll::Ready(Ok(MediaGucState::Stopped))
        );
        assert!(guc.reclaimable());
        // Engine wells are released only after the proven GuC stop.
        {
            let device = window.0.borrow();
            assert_eq!(device.regs[&0x38a540], 0x0001_0000);
            assert_eq!(device.regs[&0x38a560], 0x0001_0000);
        }
        assert_eq!(window.0.borrow().media_tlb, Some(false));
        assert_eq!(guc.error(), Some(MediaGucError::Gt(GtError::Unavailable)));
        drop(guc);
        assert_eq!(arena.live_allocations(), 0);
        assert!(window
            .0
            .borrow()
            .writes
            .iter()
            .all(|(reg, _)| media_owned(*reg)));
        // A GuC reset that never completes cannot prove stop: the owner,
        // its firmware memory and the second-TLB registration stay retained.
        let (window, arena) = media_model();
        let mut guc = MediaGuc::start(
            window.clone(),
            arena.clone(),
            &firmware,
            media_config(),
            &media,
            0,
        )
        .unwrap();
        window.0.borrow_mut().regs.insert(0x380dfc, 1);
        assert!(guc.poll(1, || true).is_pending());
        media_reset_done(&window);
        assert!(guc.poll(2, || true).is_pending());
        // Firmware DMA is armed; the stop's GuC reset never self-clears.
        guc.begin_stop(3);
        assert_eq!(guc.state(), MediaGucState::Stopping);
        let mut outcome = Poll::Pending;
        for now in 4..64 {
            outcome = guc.poll(now * 1_000_000, || true);
            if outcome.is_ready() {
                break;
            }
        }
        assert_eq!(outcome, Poll::Ready(Err(MediaGucError::Retained)));
        assert_eq!(guc.state(), MediaGucState::Retained);
        assert!(!guc.reclaimable());
        assert_eq!(window.0.borrow().media_tlb, Some(true));
        assert!(arena.live_allocations() > 0);
        core::mem::forget(guc); // fixture: retained firmware memory is never freed
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_media_gt",
        smoke_media_guc_owner_registers_tlb_masks_irq_and_retains_on_unproven_stop
    );

    mod hardware_tests {
        use super::*;
        include!("intel_gpu_guc_hw_tests.rs");
    }
}
