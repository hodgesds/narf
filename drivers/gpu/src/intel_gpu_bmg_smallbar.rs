//! Opted-in fresh BMG whole-device incarnation; no CPU alias or migration.
//! MIT Linux b90c984d xe_device.c549–604, xe_gsc.c523–534, xe_vram.c63–173.
//! Early boot FLR is NARF policy, not Linux's probe sequence. The device-wide
//! reset retires inherited requests; no HECI status is called an idle ACK.
use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_gt::{lnl, GraphicsIp, GtPlatform};
use crate::intel_gpu_vram::{VramLayout, Xe2VramRegisters};
use alloc::sync::Arc;
use core::task::Poll;

pub(crate) fn requested(args: narf_boot::args::KernelCmdline<'_>) -> bool {
    let mut enabled = false;
    for token in args.tokens().take_while(|token| *token != "--") {
        if token == "narf.intel.bmg_smallbar" {
            return false;
        }
        if let Some(value) = token.strip_prefix("narf.intel.bmg_smallbar=") {
            if enabled || value != "1" {
                return false;
            }
            enabled = true;
        }
    }
    enabled
}

fn read(m: &impl MmioWindow, reg: u64) -> Result<u32, lnl::Error> {
    match m.read32(reg) {
        u32::MAX => Err(lnl::Error::Unavailable),
        value => Ok(value),
    }
}
fn dsm(m: &impl MmioWindow) -> Result<u64, lnl::Error> {
    let sample = || -> Result<u64, lnl::Error> {
        Ok((u64::from(read(m, 0x1080c4)?) << 32 | u64::from(read(m, 0x1080c0)?)) & !0xfffff)
    };
    let a = sample()?;
    if a == 0 || a != sample()? {
        return Err(lnl::Error::State);
    }
    Ok(a)
}

/// Same source Instance0 geometry read as RegisterInit, serialized by the
/// enclosing GT reset owner. No await/allocation escapes this MCR section.
/// A busy semaphore is a refusal, never a guessed current layout.
fn geometry(m: &impl MmioWindow) -> Result<Xe2VramRegisters, lnl::Error> {
    if read(m, 0xa188)? & 1 == 0
        || read(m, 0xdfc)? & 1 == 0
        || read(m, 0xa278)? & 1 == 0
        || read(m, 0xd84)? & 1 == 0
    {
        return Err(lnl::Error::State);
    }
    if read(m, 0xfd0)? & 1 == 0 {
        return Err(lnl::Error::Busy);
    }
    let saved = read(m, 0xfd4);
    let result = (|| {
        let _ = saved?;
        m.write32(0xfd4, 0x80000000);
        if read(m, 0xfd4)? != 0x80000000 {
            return Err(lnl::Error::State);
        }
        let sample = || -> Result<Xe2VramRegisters, lnl::Error> {
            Ok(Xe2VramRegisters {
                tile_range: read(m, 0x1083a0)?,
                ccs_lower: read(m, 0x8800)?,
                ccs_upper: read(m, 0x8804)?,
                fuse3: read(m, 0x9118)?,
                gsm_base: u64::from(read(m, 0x108104)?) << 32 | u64::from(read(m, 0x108100)?),
            })
        };
        let a = sample()?;
        if a != sample()? {
            return Err(lnl::Error::State);
        }
        Ok(a)
    })();
    // Restore/release even when an intermediate read/write was refused.
    // Every physical raw operation invokes current authority independently.
    let restored = if let Ok(saved) = saved {
        m.write32(0xfd4, saved);
        read(m, 0xfd4).is_ok_and(|value| value == saved)
    } else {
        false
    };
    m.write32(0xfd0, 1);
    if !restored || read(m, 0x1901f8)? & 1 != 0 {
        return Err(lnl::Error::State);
    }
    result
}

/// One-way state retained by the physical owner, before even an arena exists.
/// Failure is sticky. Dropping a waiter cannot start a second destructive reset.
#[derive(Debug)]
pub(crate) struct Takeover {
    device: narf_bus::BusDevice,
    bar: narf_bus::MmioRegion,
    local: narf_bus::MmioRegion,
    flr: Option<lnl::DriverFlr>,
    receipt: Option<Arc<lnl::Receipt>>,
    media: lnl::MediaQuiesce,
    ready: Option<Arc<Authority>>,
    failed: bool,
}
impl Takeover {
    pub(crate) fn new(
        device: narf_bus::BusDevice,
        bar: narf_bus::MmioRegion,
        local: narf_bus::MmioRegion,
        now: u64,
    ) -> Result<Self, lnl::Error> {
        if GtPlatform::from_pci(device.id.vendor, device.id.device) != Some(GtPlatform::Battlemage)
            || local.phys.raw() == 0
            || local.len == 0
            || local.len & 4095 != 0
            || !matches!(local.kind, narf_bus::BarKind::Mmio64 { prefetchable: true })
        {
            return Err(lnl::Error::Unsupported);
        }
        Ok(Self {
            device,
            bar,
            local,
            flr: Some(lnl::DriverFlr::new_bmg(device, bar, now)?),
            receipt: None,
            media: lnl::MediaQuiesce::for_bmg(),
            ready: None,
            failed: false,
        })
    }
    /// `current` renews permanent boot/client exclusion and physical PCI
    /// authority. The MmioWindow independently invokes current authority for
    /// every raw operation. No IRQ lock or executor bridge spans these polls.
    pub(crate) fn poll(
        &mut self,
        m: &impl MmioWindow,
        now: u64,
        mut current: impl FnMut() -> bool,
    ) -> Poll<Result<Arc<Authority>, lnl::Error>> {
        let result = self.poll_inner(m, now, &mut current);
        if matches!(result, Poll::Ready(Err(_))) {
            self.failed = true;
        }
        result
    }
    fn poll_inner(
        &mut self,
        m: &impl MmioWindow,
        now: u64,
        current: &mut impl FnMut() -> bool,
    ) -> Poll<Result<Arc<Authority>, lnl::Error>> {
        if self.failed || !current() {
            return Poll::Ready(Err(lnl::Error::Unavailable));
        }
        if let Some(ready) = &self.ready {
            ready.current(m)?;
            return Poll::Ready(Ok(ready.clone()));
        }
        if self.receipt.is_none() {
            // GMD_ID is source early-probe identity, before GT initialization.
            // Re-read after reset as part of the fresh HardwareInit; this
            // pre-trigger qualification is never a retained wake/cache proof.
            GraphicsIp::read(m, GtPlatform::Battlemage).map_err(|_| lnl::Error::Unsupported)?;
            if read(m, 0x10100c)? & (1 << 9) != 0 {
                let display = read(m, 0x510a0)?;
                if display != read(m, 0x510a0)?
                    || (display >> 22) * 100 + ((display >> 14) & 255) != 1401
                {
                    return Poll::Ready(Err(lnl::Error::Unsupported));
                }
            }
            match self
                .flr
                .as_mut()
                .ok_or(lnl::Error::State)?
                .poll(m, now, &mut *current)
            {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(result) => self.receipt = Some(Arc::new(result?)),
            }
            self.flr = None;
        }
        if !current() {
            return Poll::Ready(Err(lnl::Error::Unavailable));
        }
        let media = match self.media.poll(m, now) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(result) => result?,
        };
        let authority = Arc::new(Authority {
            device: self.device,
            bar: self.bar,
            local: self.local,
            receipt: self.receipt.as_ref().ok_or(lnl::Error::State)?.clone(),
            media,
        });
        authority.current(m)?;
        self.ready = Some(authority.clone());
        Poll::Ready(Ok(authority))
    }
}

/// Retained full-device-reset incarnation. The constructor is private and
/// requires the actual acknowledged FLR plus independently held media reset.
/// This is never reconstructed from a BAR grant or an initialized boolean.
#[derive(Debug)]
pub(crate) struct Authority {
    device: narf_bus::BusDevice,
    bar: narf_bus::MmioRegion,
    local: narf_bus::MmioRegion,
    receipt: Arc<lnl::Receipt>,
    media: lnl::MediaProof,
}
impl Authority {
    pub(crate) fn current(&self, m: &impl MmioWindow) -> Result<(), lnl::Error> {
        if !self.receipt.matches(self.device, self.bar, m) {
            return Err(lnl::Error::State);
        }
        self.media.current(m)
    }
    pub(crate) fn matches(&self, bar: narf_bus::MmioRegion, local: narf_bus::MmioRegion) -> bool {
        self.bar.phys == bar.phys
            && self.bar.len == bar.len
            && self.local.phys == local.phys
            && self.local.len == local.len
            && self.local.kind == local.kind
    }
    pub(crate) fn matches_window(
        &self,
        m: &crate::intel_gpu_gt_hw::AuthorizedWindow,
        bar: narf_bus::MmioRegion,
    ) -> bool {
        self.matches(bar, self.local) && m.matches_bmg_source(self.device, self.bar, self.local)
    }
    pub(crate) fn derive(
        self: &Arc<Self>,
        m: &impl MmioWindow,
        layout: VramLayout,
    ) -> Result<Arc<DpaGrant>, lnl::Error> {
        self.current(m)?;
        GraphicsIp::read(m, GtPlatform::Battlemage).map_err(|_| lnl::Error::Unsupported)?;
        let gmd = read(m, 0xd8c)?;
        let reserved = dsm(m)?;
        let geometry = geometry(m)?;
        if VramLayout::xe2(geometry).ok() != Some(layout)
            || layout.tile_offset != 0
            || layout.usable == 0
            || layout.usable > reserved
            || layout.usable > layout.tile_size
            || reserved > layout.tile_size
            || layout.tile_size > 1 << 46
            || self.local.len >= layout.usable
        {
            return Err(lnl::Error::Unsupported);
        }
        self.current(m)?;
        Ok(Arc::new(DpaGrant {
            authority: self.clone(),
            layout,
            gmd,
            dsm: reserved,
            geometry,
        }))
    }
}

/// Derived ordinary usable-DPA grant, after fresh source layout, wake and
/// cache initialization. It excludes DSM/GSM/CCS and is bound to this PF/BAR.
#[derive(Debug)]
pub(crate) struct DpaGrant {
    authority: Arc<Authority>,
    pub(crate) layout: VramLayout,
    gmd: u32,
    dsm: u64,
    geometry: Xe2VramRegisters,
}
impl DpaGrant {
    pub(crate) fn matches(&self, local: narf_bus::MmioRegion, layout: VramLayout) -> bool {
        self.layout == layout
            && self.authority.local.phys == local.phys
            && self.authority.local.len == local.len
            && self.authority.local.kind == local.kind
    }
    pub(crate) fn same_owner(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.authority, &other.authority)
            && self.layout == other.layout
            && self.gmd == other.gmd
            && self.dsm == other.dsm
            && self.geometry == other.geometry
    }
    pub(crate) fn current(&self, m: &impl MmioWindow) -> Result<(), lnl::Error> {
        self.authority.current(m)?;
        if read(m, 0xd8c)? != self.gmd || dsm(m)? != self.dsm || geometry(m)? != self.geometry {
            return Err(lnl::Error::State);
        }
        self.authority.current(m)
    }
}
