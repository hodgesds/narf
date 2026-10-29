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
}
impl AuthorizedWindow {
    pub(crate) fn new(
        bar: narf_bus::bar::MmioRegion,
        cap: Cap<narf_bus::BusDeviceCap, Write>,
    ) -> Self {
        Self { bar, cap }
    }
}
struct Register {
    bar: narf_bus::bar::MmioRegion,
    offset: u64,
    write: Option<u32>,
}
impl CapOp<narf_bus::BusDeviceCap, Write> for Register {
    type Output = u32;
    fn execute(
        self,
        _cap: &Cap<narf_bus::BusDeviceCap, Write>,
    ) -> Result<u32, narf_capabilities::CapError> {
        if self.offset % 4 != 0
            || self
                .offset
                .checked_add(4)
                .is_none_or(|end| end > self.bar.len)
        {
            return Ok(u32::MAX);
        }
        // SAFETY: the PCI probe owns this permanent mapping; the invocation
        // validated current authority and the aligned offset is inside BAR0.
        Ok(unsafe {
            if let Some(value) = self.write {
                self.bar.write32(self.offset, value);
                0
            } else {
                self.bar.read32(self.offset)
            }
        })
    }
}
impl MmioWindow for AuthorizedWindow {
    fn read32(&self, offset: u64) -> u32 {
        self.cap
            .invoke(Register {
                bar: self.bar,
                offset,
                write: None,
            })
            .unwrap_or(u32::MAX)
    }
    fn write32(&self, offset: u64, value: u32) {
        let _ = self.cap.invoke(Register {
            bar: self.bar,
            offset,
            write: Some(value),
        });
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
}

impl HardwareInit {
    pub(crate) fn ready(&self) -> bool {
        self.ready
    }
    pub(crate) fn recover(
        &mut self,
        mmio: &impl MmioWindow,
        now: u64,
    ) -> Result<(), HardwareError> {
        self.deadline = now.checked_add(50_000_000).ok_or(HardwareError::Timeout)?;
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
        if !self.requested || request & 1 == 0 || ack & 1 == 0 {
            return Err(HardwareError::WakeLost);
        }
        Ok(())
    }

    pub(crate) fn poll(
        &mut self,
        mmio: &impl MmioWindow,
        now: u64,
    ) -> Poll<Result<CachePolicy, HardwareError>> {
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
                mmio.write32(0x941c, 1);
                self.quiesce = 2;
                self.deadline = now.checked_add(5_000_000).ok_or(HardwareError::Timeout)?;
                return Poll::Pending;
            }
            self.quiesce = 3;
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
            GtPlatform::Integrated(_) => {
                // Xe-LPG PAT3: WB L4, one-way coherent. PAT0, used by the
                // inherited display, is deliberately not redefined.
                mmio.write32(0x480c, 2);
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
            GtPlatform::Battlemage => {
                mmio.write32(0x4808, 0xf); // Xe2 default WB PAT2: L3 WB, L4 UC, two-way coherent
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
        }))
    }

    pub(crate) fn begin_release(
        &mut self,
        mmio: &impl MmioWindow,
        now: u64,
    ) -> Result<(), HardwareError> {
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
