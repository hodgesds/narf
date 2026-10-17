//! Bind DCN's physical aperture and flat VMID0 root to the retained GMC owner.
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DisplayContext {
    pub fb_base: u64,
    pub fb_top: u64,
    pub fb_offset: u64,
    /// Physical VRAM PDE including VALID, not a GPU FB or CPU BAR address.
    pub root: u64,
    pub start: u64,
    pub end: u64,
}
impl<I: Io> Engine<I> {
    pub(super) fn display_context(&mut self) -> Result<DisplayContext, Error> {
        if self.state != State::Ready {
            return Err(Error::Busy);
        }
        let g = self.geometry.ok_or(Error::Busy)?;
        let context = DisplayContext {
            fb_base: g.fb,
            fb_top: g.end - 1,
            fb_offset: g.offset,
            root: g.physical(self.memory.address()) | 1,
            start: g.aperture.start,
            end: g.aperture.start + g.aperture.size - 1,
        };
        let l = self.layout;
        self.access(|io| {
            // Fresh geometry and VMID0 checks in both hubs, against the saved
            // owned configuration. Never adopt firmware's replacement root.
            for ((base, r), offset) in l.bases.into_iter().zip([GFX, MM]).zip([0x15a7, 0x4c7]) {
                for (reg, mask, want) in [
                    (r.fb_base, 0xffffff, (g.fb >> 24) as u32),
                    (r.fb_top, 0xffffff, ((g.end - 1) >> 24) as u32),
                    (offset, 0xffffff, (g.offset >> 24) as u32),
                    // The retained fault monitor may arm/mask these IRQ bits
                    // independently. Translation/default/retry fields stay fixed.
                    (r.ctx, !0x555400, 0xaaa801),
                    (r.agp_base, 0xffffff, 0),
                    (r.agp_bot, 0xffffff, 0xffffff),
                    (r.agp_top, 0xffffff, 0),
                    (r.sys_low, 0x3fffffff, (g.fb >> 18) as u32),
                    (r.sys_high, 0x3fffffff, ((g.end - 1) >> 18) as u32),
                ] {
                    if checked(io.read(base + u64::from(reg) * 4))? & mask != want {
                        return Err(Error::Busy);
                    }
                }
                for (reg, want) in [
                    (r.pt_base, context.root),
                    (r.pt_start, context.start >> 12),
                    (r.pt_end, context.end >> 12),
                ] {
                    let lo = checked(io.read(base + u64::from(reg) * 4))?;
                    let hi = checked(io.read(base + u64::from(reg + 1) * 4))?;
                    if u64::from(lo) | u64::from(hi) << 32 != want {
                        return Err(Error::Busy);
                    }
                }
            }
            Ok(context)
        })
    }
}
impl Gmc {
    pub(crate) fn display_context(&mut self, regs: MmioRegion) -> Result<DisplayContext, Error> {
        let own = self.engine.io.0;
        if own.phys != regs.phys || own.virt != regs.virt || own.len != regs.len {
            return Err(Error::Invalid);
        }
        self.engine.display_context()
    }
}
