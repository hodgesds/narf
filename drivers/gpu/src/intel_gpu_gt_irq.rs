//! Main GuC/render/copy/compute and qualified Gen12 media IRQ delivery.
//! MIT Linux xe_irq.c and xe_guc.c, b90c984d615e8ce2af96f5b1411a962d83fed2ad.
//! The hard handler only masks the tile master. Identity waits and GuC work
//! run in task context; IRQ notification never proves DMA retirement.

use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_engine::{Engine, EngineSet};
use alloc::sync::Arc;
use narf_lib::sync::IrqSafeSpinLock;

const TILE: u64 = 0x190008;
const MASTER: u64 = 0x190010;
const DW: u64 = 0x190018;
const IDENTITY: u64 = 0x190060;
const SELECTOR: u64 = 0x190070;
const RENDER_ENABLE: u64 = 0x190030;
const RCS_MASK: u64 = 0x190090;
const BCS_MASK: u64 = 0x1900a0;
const GUC_ENABLE: u64 = 0x190038;
const GUC_MASK: u64 = 0x1900e8;
const RING_MASK: u64 = 0x20a8;
const BCS_RING_MASK: u64 = 0x220a8;
const BCS8_MASK: u64 = 0x19011c; // BCS7 ENGINE1, BCS8 ENGINE0
const BCS8_RING_MASK: u64 = 0x3ee0a8;
const ENABLE: u32 = 1 << 31;
const RCS: u32 = 0x11; // MI_USER_INTERRUPT and FLUSH_COMPLETE
const RCS_EVENTS: u32 = RCS << 16;
// RENDER_COPY_INTR_ENABLE: render in ENGINE1 (high), copy in ENGINE0 (low).
// BCS_RSVD_INTR_MASK carries BCS0 in its ENGINE1 half, like RCS0_RSVD.
const ENGINE_EVENTS: u32 = RCS_EVENTS | RCS;
const GUC: u32 = 1 << 31; // primary GuC GUC2HOST (bit 15 in engine 1)
const RCS0: u32 = 1;
const BCS0: u32 = 1 << 15; // INTR_BCS(0)
const BCS8: u32 = 1 << 23;
const GUC_BIT: u32 = 1 << 25;
const OWNED: u32 = RCS0 | BCS0 | GUC_BIT; // bank zero
                                          // CCS0 pairs with CCS1: ENGINE1 (high) halves of CCS_RSVD_INTR_ENABLE and
                                          // CCS0_CCS1_INTR_MASK, bank-zero INTR_CCS(0), identity class COMPUTE (5).
const CCS_ENABLE: u64 = 0x190048;
const CCS_MASK: u64 = 0x190100;
const CCS_MASKS: [u64; 2] = [CCS_MASK, 0x190104];
const CCS_BASES: [u64; 4] = [0x1a000, 0x1c000, 0x1e000, 0x26000];
const MEDIA_ENABLE: u64 = 0x190034;
const MEDIA_MASKS: [u64; 6] = [0x1900a8, 0x1900ac, 0x1900b0, 0x1900b4, 0x1900d0, 0x1900d4];
const MEDIA: [Engine; 12] = [
    Engine::Vcs0,
    Engine::Vcs1,
    Engine::Vcs2,
    Engine::Vcs3,
    Engine::Vcs4,
    Engine::Vcs5,
    Engine::Vcs6,
    Engine::Vcs7,
    Engine::Vecs0,
    Engine::Vecs1,
    Engine::Vecs2,
    Engine::Vecs3,
];
fn media_pair_mask(engines: EngineSet, pair: usize) -> u32 {
    (if engines.contains(MEDIA[pair * 2]) {
        RCS_EVENTS
    } else {
        0
    }) | if engines.contains(MEDIA[pair * 2 + 1]) {
        RCS
    } else {
        0
    }
}
fn media_enable(engines: EngineSet) -> u32 {
    (if engines.iter().any(|e| e.is_decode()) {
        RCS_EVENTS
    } else {
        0
    }) | if engines.iter().any(|e| e.xe_class() == 3) {
        RCS
    } else {
        0
    }
}
fn media_bits(engines: EngineSet) -> u32 {
    engines.iter().fold(0, |bits, e| {
        bits | (1
            << if e.is_decode() {
                e.physical_instance()
            } else {
                31 - e.physical_instance()
            })
    })
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum IrqError {
    Unavailable,
    Conflict,
    Identity,
    Timeout,
    Route,
}

#[derive(Copy, Clone)]
struct Saved {
    master: u32,
    render: u32,
    rcs: u32,
    bcs: u32,
    guc_enable: u32,
    guc_mask: u32,
    ring: u32,
    bcs_ring: u32,
    bcs8: u32,
    bcs8_ring: u32,
    ccs_enable: u32,
    ccs: [u32; 2],
    ccs_ring: [u32; 4],
    media_enable: u32,
    media_masks: [u32; 6],
    media_ring: [u32; 12],
}

struct State<M> {
    mmio: M,
    saved: Saved,
    /// CCS0 is a published engine and owns its sources.
    compute: u8,
    copy8: bool,
    media: EngineSet,
    /// The media sources are enabled. On a tiled (MTL/Arrow) controller the
    /// standalone media GT's engines join `media` when routed and stay owned
    /// for identity decoding after unrouting, so a late pending identity is
    /// still acknowledged rather than read as a foreign cause.
    media_routed: bool,
    tiled: bool,
    active: bool,
    pending: bool,
    bits: [u32; 2],
    bank: usize,
    selected: u32,
    deadline: u64,
}

pub(crate) struct Controller<M>(IrqSafeSpinLock<State<M>>);

fn read(mmio: &impl MmioWindow, offset: u64) -> Result<u32, IrqError> {
    let value = mmio.read32(offset);
    (value != u32::MAX)
        .then_some(value)
        .ok_or(IrqError::Unavailable)
}

fn restore_bits(mmio: &impl MmioWindow, offset: u64, mask: u32, saved: u32) {
    // All-ones is a valid mask value, unlike master/identity registers.
    // Availability is checked through the master around these updates.
    let current = mmio.read32(offset);
    mmio.write32(offset, (current & !mask) | (saved & mask));
}

fn ccs_pair_mask(compute: u8, pair: usize) -> u32 {
    (if compute & (1 << (pair * 2)) != 0 {
        RCS_EVENTS
    } else {
        0
    }) | if compute & (1 << (pair * 2 + 1)) != 0 {
        RCS
    } else {
        0
    }
}

impl<M: MmioWindow> Controller<M> {
    #[cfg(feature = "kernel-test")]
    pub(crate) fn new(mmio: M, compute: bool) -> Result<Self, IrqError> {
        let engines = if compute {
            EngineSet::of(&[Engine::Rcs0, Engine::Bcs0, Engine::Ccs0])
        } else {
            EngineSet::of(&[Engine::Rcs0, Engine::Bcs0])
        };
        Self::with_engines(mmio, engines)
    }

    #[cfg(feature = "kernel-test")]
    pub(crate) fn with_engines(mmio: M, engines: EngineSet) -> Result<Self, IrqError> {
        Self::with_hierarchy(mmio, engines, true)
    }

    fn with_hierarchy(mmio: M, engines: EngineSet, tiled: bool) -> Result<Self, IrqError> {
        let compute = engines
            .compute()
            .fold(0u8, |mask, engine| mask | 1 << engine.physical_instance());
        let copy8 = engines.contains(Engine::Bcs8);
        let media = EngineSet::of(&MEDIA).bits() & engines.bits();
        let media = EngineSet::from_bits(media);
        // No other owner may have delivery enabled. Never commandeer firmware
        // MSI or enable a master with an unhandled display/media indication.
        if !tiled && (compute != 0 || copy8) {
            return Err(IrqError::Identity);
        }
        let tile = if tiled { read(&mmio, TILE)? } else { 0 };
        let master = read(&mmio, MASTER)?;
        if tile & ENABLE != 0
            || tile & !(ENABLE | 1) != 0
            || master & !(ENABLE | 1 | if media_enable(media) != 0 { 2 } else { 0 }) != 0
            || (!tiled && master & ENABLE != 0)
        {
            return Err(IrqError::Conflict);
        }
        let saved = Saved {
            master: master & ENABLE,
            render: read(&mmio, RENDER_ENABLE)?,
            rcs: mmio.read32(RCS_MASK),
            bcs: mmio.read32(BCS_MASK),
            guc_enable: read(&mmio, GUC_ENABLE)?,
            guc_mask: mmio.read32(GUC_MASK),
            ring: mmio.read32(RING_MASK),
            bcs_ring: mmio.read32(BCS_RING_MASK),
            bcs8: if copy8 { mmio.read32(BCS8_MASK) } else { 0 },
            bcs8_ring: if copy8 {
                mmio.read32(BCS8_RING_MASK)
            } else {
                0
            },
            ccs_enable: if compute != 0 {
                read(&mmio, CCS_ENABLE)?
            } else {
                0
            },
            ccs: core::array::from_fn(|pair| {
                if ccs_pair_mask(compute, pair) != 0 {
                    mmio.read32(CCS_MASKS[pair])
                } else {
                    0
                }
            }),
            media_enable: if media_enable(media) != 0 {
                read(&mmio, MEDIA_ENABLE)?
            } else {
                0
            },
            media_masks: core::array::from_fn(|pair| {
                if media_pair_mask(media, pair) != 0 {
                    mmio.read32(MEDIA_MASKS[pair])
                } else {
                    0
                }
            }),
            media_ring: core::array::from_fn(|index| {
                if media.contains(MEDIA[index]) {
                    mmio.read32(u64::from(MEDIA[index].base()) + 0xa8)
                } else {
                    0
                }
            }),
            ccs_ring: core::array::from_fn(|i| {
                if compute & (1 << i) != 0 {
                    mmio.read32(CCS_BASES[i] + 0xa8)
                } else {
                    0
                }
            }),
        };
        Ok(Self(IrqSafeSpinLock::new(State {
            mmio,
            saved,
            compute,
            copy8,
            media,
            media_routed: media.bits() != 0,
            tiled,
            active: false,
            pending: true, // drain pre-existing owned status before enabling
            bits: [0; 2],
            bank: 0,
            selected: 0,
            deadline: 0,
        })))
    }

    pub(crate) fn activate(&self) -> Result<(), IrqError> {
        let mut s = self.0.lock();
        read(&s.mmio, MASTER)?;
        s.active = true;
        let mut routes = alloc::vec![
            (RENDER_ENABLE, ENGINE_EVENTS, ENGINE_EVENTS),
            (RCS_MASK, RCS_EVENTS, 0),
            (BCS_MASK, RCS_EVENTS, 0),
            (GUC_ENABLE, GUC, GUC),
            (GUC_MASK, GUC, 0),
            (RING_MASK, RCS, 0),
            (BCS_RING_MASK, RCS, 0),
        ];
        if s.compute != 0 {
            routes.push((CCS_ENABLE, RCS_EVENTS, RCS_EVENTS));
            for (pair, reg) in CCS_MASKS.into_iter().enumerate() {
                let mask = ccs_pair_mask(s.compute, pair);
                if mask != 0 {
                    routes.push((reg, mask, 0));
                }
            }
            for (i, base) in CCS_BASES.into_iter().enumerate() {
                if s.compute & (1 << i) != 0 {
                    routes.push((base + 0xa8, RCS, 0));
                }
            }
        }
        if media_enable(s.media) != 0 {
            let enabled = media_enable(s.media);
            routes.push((MEDIA_ENABLE, enabled, enabled));
            for (pair, reg) in MEDIA_MASKS.into_iter().enumerate() {
                let mask = media_pair_mask(s.media, pair);
                if mask != 0 {
                    routes.push((reg, mask, 0));
                }
            }
            for engine in s.media.iter() {
                routes.push((u64::from(engine.base()) + 0xa8, RCS, 0));
            }
        }
        if s.copy8 {
            routes.extend_from_slice(&[(BCS8_MASK, RCS, 0), (BCS8_RING_MASK, RCS, 0)]);
        }
        for &(offset, mask, value) in &routes {
            restore_bits(&s.mmio, offset, mask, value);
        }
        for (offset, mask, expected) in routes {
            if s.mmio.read32(offset) & mask != expected {
                return Err(IrqError::Route);
            }
        }
        // service() drains stale causes before opening the tile master.
        read(&s.mmio, MASTER).map(|_| ())
    }

    /// Route the MTL/Arrow standalone media GT's published VCS/VECS onto this
    /// tile's shared banks, as xe_irq.c::xe_irq_enable_hwe does for a media
    /// GT: VCS (ENGINE1) and VECS (ENGINE0) halves of VCS_VECS_INTR_ENABLE,
    /// the per-pair VCSn/VECSn mask halves and each engine's RING_IMR, all
    /// for MI_USER_INTERRUPT | FLUSH_COMPLETE. GT0's bank-0 sources, the
    /// GuC halves and every other bit keep their values. Bank-1 identities
    /// decode as VIDEO_DECODE/VIDEO_ENHANCE (pick_engine_gt -> media GT) and
    /// only wake the polled media owner; they never prove DMA retirement.
    pub(crate) fn route_media(&self, engines: EngineSet) -> Result<(), IrqError> {
        let mut s = self.0.lock();
        if !s.active
            || !s.tiled
            || s.media_routed
            || engines.bits() == 0
            || engines.bits() & !EngineSet::of(&MEDIA).bits() != 0
            || (s.media.bits() != 0 && s.media != engines)
        {
            return Err(IrqError::Identity);
        }
        let enabled = media_enable(engines);
        let saved_enable = read(&s.mmio, MEDIA_ENABLE)?;
        let saved_masks: [u32; 6] = core::array::from_fn(|pair| {
            if media_pair_mask(engines, pair) != 0 {
                s.mmio.read32(MEDIA_MASKS[pair])
            } else {
                0
            }
        });
        let saved_ring: [u32; 12] = core::array::from_fn(|index| {
            if engines.contains(MEDIA[index]) {
                s.mmio.read32(u64::from(MEDIA[index].base()) + 0xa8)
            } else {
                0
            }
        });
        s.saved.media_enable = saved_enable;
        s.saved.media_masks = saved_masks;
        s.saved.media_ring = saved_ring;
        s.media = engines;
        s.media_routed = true;
        let mut routes = alloc::vec![(MEDIA_ENABLE, enabled, enabled)];
        for (pair, reg) in MEDIA_MASKS.into_iter().enumerate() {
            let mask = media_pair_mask(engines, pair);
            if mask != 0 {
                routes.push((reg, mask, 0));
            }
        }
        for engine in engines.iter() {
            routes.push((u64::from(engine.base()) + 0xa8, RCS, 0));
        }
        for &(offset, mask, value) in &routes {
            restore_bits(&s.mmio, offset, mask, value);
        }
        for (offset, mask, expected) in routes {
            if s.mmio.read32(offset) & mask != expected {
                return Err(IrqError::Route);
            }
        }
        Ok(())
    }

    /// Mask the media sources again before the media GuC stops: restore the
    /// saved halves of exactly the bits `route_media` owned. The engines stay
    /// owned for decoding, so an identity already latched is acknowledged.
    pub(crate) fn unroute_media(&self) {
        let mut s = self.0.lock();
        if !s.tiled || !s.media_routed {
            return;
        }
        s.media_routed = false;
        for (index, engine) in MEDIA.into_iter().enumerate() {
            if s.media.contains(engine) {
                restore_bits(
                    &s.mmio,
                    u64::from(engine.base()) + 0xa8,
                    RCS,
                    s.saved.media_ring[index],
                );
            }
        }
        for (pair, reg) in MEDIA_MASKS.into_iter().enumerate() {
            let mask = media_pair_mask(s.media, pair);
            if mask != 0 {
                restore_bits(&s.mmio, reg, mask, s.saved.media_masks[pair]);
            }
        }
        restore_bits(
            &s.mmio,
            MEDIA_ENABLE,
            media_enable(s.media),
            s.saved.media_enable,
        );
    }

    pub(crate) fn hard_irq(&self) -> narf_interrupts::dispatch::IrqStatus {
        let mut s = self.0.lock();
        if !s.active {
            return narf_interrupts::dispatch::IrqStatus::None;
        }
        let outer = if s.tiled { TILE } else { MASTER };
        s.mmio.write32(outer, 0);
        let _ = s.mmio.read32(outer); // posted mask before EOI
        s.pending = true;
        narf_interrupts::dispatch::IrqStatus::Handled
    }

    /// One bounded decoder step. An identity may take time to become valid;
    /// callers sleep between steps, with the tile master still masked.
    /// Ok(true) requests a short timer retry; Ok(false) is fully rearmed.
    pub(crate) fn service(&self, now: u64) -> Result<bool, IrqError> {
        let mut s = self.0.lock();
        if !s.active {
            return Ok(false);
        }
        if !s.pending {
            // The watchdog also drains a lost MSI edge. Mask before inspecting
            // the hierarchy, exactly as the hard handler would have done.
            let outer = if s.tiled { TILE } else { MASTER };
            s.mmio.write32(outer, 0);
            let _ = read(&s.mmio, outer)?;
            s.pending = true;
        }
        if s.selected != 0 {
            let identity = read(&s.mmio, IDENTITY + s.bank as u64 * 4)?;
            if identity & ENABLE == 0 {
                return if now >= s.deadline {
                    Err(IrqError::Timeout)
                } else {
                    Ok(true)
                };
            }
            let (expected, class, instance) = if s.bank == 1 {
                let bit = s.selected.trailing_zeros();
                if bit < 8 {
                    (RCS, 1, bit)
                } else {
                    (RCS, 2, 31 - bit)
                }
            } else {
                match s.selected {
                    RCS0 => (RCS, 0, 0),
                    BCS0 => (RCS, 3, 0),
                    BCS8 => (RCS, 3, 8),
                    bit if bit & 0xf0 != 0 => (RCS, 5, bit.trailing_zeros() - 4),
                    _ => (0x8000, 4, 0),
                }
            };
            if (identity >> 20) & 0x3f != instance
                || (identity >> 16) & 7 != class
                || identity & 0xffff == 0
                || identity & 0xffff & !expected != 0
            {
                return Err(IrqError::Identity);
            }
            // Identity acknowledgement must precede the bank acknowledgement.
            s.mmio.write32(IDENTITY + s.bank as u64 * 4, identity);
            s.mmio.write32(DW + s.bank as u64 * 4, s.selected);
            let bank = s.bank;
            let selected = s.selected;
            s.bits[bank] &= !selected;
            s.selected = 0;
        }
        if s.bits == [0; 2] {
            let tile = if s.tiled { read(&s.mmio, TILE)? } else { 0 };
            let master = read(&s.mmio, MASTER)?;
            let banks = 1 | if media_enable(s.media) != 0 { 2 } else { 0 };
            if tile & !(ENABLE | 1) != 0 || master & !(ENABLE | banks) != 0 {
                return Err(IrqError::Conflict);
            }
            if tile & 1 != 0 {
                s.mmio.write32(TILE, 1);
            }
            for bank in 0..2 {
                if master & (1 << bank) != 0 {
                    let bits = read(&s.mmio, DW + bank as u64 * 4)?;
                    let owned = if bank == 0 {
                        OWNED | (u32::from(s.compute) << 4) | if s.copy8 { BCS8 } else { 0 }
                    } else {
                        media_bits(s.media)
                    };
                    if bits & !owned != 0 {
                        return Err(IrqError::Conflict);
                    }
                    s.bits[bank] = bits;
                }
            }
            if master & banks != 0 {
                // On Gen12 there is no outer tile mask. Keep the master
                // disabled while identities in either bank are outstanding.
                s.mmio.write32(
                    MASTER,
                    (if s.tiled { ENABLE } else { 0 }) | (master & banks),
                );
            }
        }
        if let Some(bank) = s.bits.iter().position(|bits| *bits != 0) {
            s.bank = bank;
            s.selected = 1 << s.bits[bank].trailing_zeros();
            s.deadline = now.checked_add(100_000).ok_or(IrqError::Timeout)?;
            s.mmio.write32(SELECTOR + bank as u64 * 4, s.selected);
            return Ok(true);
        }
        // Lower status is quiet; enabling the master generates a fresh edge
        // for any cause arriving between the final read and this write.
        s.mmio.write32(MASTER, ENABLE);
        if s.tiled {
            s.mmio.write32(TILE, ENABLE);
        }
        if (s.tiled && read(&s.mmio, TILE)? & ENABLE == 0) || read(&s.mmio, MASTER)? & ENABLE == 0 {
            return Err(IrqError::Route);
        }
        s.pending = false;
        Ok(false)
    }

    pub(crate) fn quiesce(&self) -> bool {
        let mut s = self.0.lock();
        if !s.active {
            return true;
        }
        let outer = if s.tiled { TILE } else { MASTER };
        s.mmio.write32(outer, 0);
        let quiet = read(&s.mmio, outer).is_ok_and(|value| value & ENABLE == 0);
        s.active = false;
        // Restore only our source bits. The media GuC shares ENABLE but owns
        // its separate mask half; all unrelated masks/status stay untouched.
        for (offset, mask, saved) in [
            (RING_MASK, RCS, s.saved.ring),
            (BCS_RING_MASK, RCS, s.saved.bcs_ring),
            (RCS_MASK, RCS_EVENTS, s.saved.rcs),
            (BCS_MASK, RCS_EVENTS, s.saved.bcs),
            (RENDER_ENABLE, ENGINE_EVENTS, s.saved.render),
            (GUC_MASK, GUC, s.saved.guc_mask),
        ] {
            restore_bits(&s.mmio, offset, mask, saved);
        }
        if s.compute != 0 {
            for (i, base) in CCS_BASES.into_iter().enumerate() {
                if s.compute & (1 << i) != 0 {
                    restore_bits(&s.mmio, base + 0xa8, RCS, s.saved.ccs_ring[i]);
                }
            }
            for (pair, reg) in CCS_MASKS.into_iter().enumerate() {
                let mask = ccs_pair_mask(s.compute, pair);
                if mask != 0 {
                    restore_bits(&s.mmio, reg, mask, s.saved.ccs[pair]);
                }
            }
            restore_bits(&s.mmio, CCS_ENABLE, RCS_EVENTS, s.saved.ccs_enable);
        }
        if s.media_routed && media_enable(s.media) != 0 {
            s.media_routed = false;
            for (index, engine) in MEDIA.into_iter().enumerate() {
                if s.media.contains(engine) {
                    restore_bits(
                        &s.mmio,
                        u64::from(engine.base()) + 0xa8,
                        RCS,
                        s.saved.media_ring[index],
                    );
                }
            }
            for (pair, reg) in MEDIA_MASKS.into_iter().enumerate() {
                let mask = media_pair_mask(s.media, pair);
                if mask != 0 {
                    restore_bits(&s.mmio, reg, mask, s.saved.media_masks[pair]);
                }
            }
            restore_bits(
                &s.mmio,
                MEDIA_ENABLE,
                media_enable(s.media),
                s.saved.media_enable,
            );
        }
        if s.copy8 {
            restore_bits(&s.mmio, BCS8_RING_MASK, RCS, s.saved.bcs8_ring);
            restore_bits(&s.mmio, BCS8_MASK, RCS, s.saved.bcs8);
        }
        // The primary/media GuCs share this enable bit. An independently
        // unmasked media GuC still needs it, even if it was clear at takeover.
        if s.mmio.read32(GUC_MASK) & (1 << 15) != 0 {
            restore_bits(&s.mmio, GUC_ENABLE, GUC, s.saved.guc_enable);
        }
        s.mmio.write32(MASTER, s.saved.master);
        let _ = s.mmio.read32(MASTER);
        quiet
    }
}

pub(crate) trait MessageRoute {
    fn program(&mut self, vector: u8) -> Result<(), IrqError>;
    fn enable(&mut self) -> Result<(), IrqError>;
    fn disable(&mut self) -> bool;
}

/// Owns handler lifetime and routing together. All failure paths mask device
/// causes, disable PCI delivery, synchronize, and only then release the cookie.
pub(crate) struct Delivery<M: MmioWindow + Send + 'static, R: MessageRoute> {
    controller: Arc<Controller<M>>,
    route: Option<R>,
    vector: u8,
}

fn handler<M: MmioWindow + Send + 'static>(cookie: u64) -> narf_interrupts::dispatch::IrqStatus {
    // SAFETY: Delivery retains the Arc until after remove + synchronize_irq.
    unsafe { &*(cookie as *const Controller<M>) }.hard_irq()
}

impl<M: MmioWindow + Send + 'static, R: MessageRoute> Delivery<M, R> {
    #[cfg(feature = "kernel-test")]
    fn install(mmio: M, route: R) -> Result<Self, IrqError> {
        Self::install_with(mmio, route, EngineSet::of(&[Engine::Rcs0, Engine::Bcs0]))
    }

    #[cfg(feature = "kernel-test")]
    fn install_with(mmio: M, route: R, engines: EngineSet) -> Result<Self, IrqError> {
        Self::install_hierarchy(mmio, route, engines, true)
    }

    fn install_hierarchy(
        mmio: M,
        mut route: R,
        engines: EngineSet,
        tiled: bool,
    ) -> Result<Self, IrqError> {
        let controller = Arc::new(Controller::with_hierarchy(mmio, engines, tiled)?);
        let vector = narf_interrupts::vector::alloc().map_err(|_| IrqError::Route)?;
        if let Err(error) = route.program(vector) {
            if route.disable() {
                let _ = narf_interrupts::vector::free(vector);
            } else {
                core::mem::forget(route); // uncertain PCI delivery keeps its vector
            }
            return Err(error);
        }
        narf_interrupts::dispatch::install_handler_named(
            vector,
            "intel-gt",
            Arc::as_ptr(&controller) as u64,
            handler::<M>,
        );
        let delivery = Self {
            controller,
            route: Some(route),
            vector,
        };
        let mut delivery = delivery;
        delivery.route.as_mut().expect("owned route").enable()?;
        delivery.controller.activate()?;
        Ok(delivery)
    }

    pub(crate) fn vector(&self) -> u8 {
        self.vector
    }

    pub(crate) fn service(&self, now: u64) -> Result<bool, IrqError> {
        self.controller.service(now)
    }

    /// See `Controller::route_media`.
    pub(crate) fn route_media(&self, engines: EngineSet) -> Result<(), IrqError> {
        self.controller.route_media(engines)
    }

    /// See `Controller::unroute_media`.
    pub(crate) fn unroute_media(&self) {
        self.controller.unroute_media()
    }

    /// Whether media sources are currently enabled on this delivery graph.
    pub(crate) fn media_routed(&self) -> bool {
        self.controller.0.lock().media_routed
    }
}

impl<M: MmioWindow + Send + 'static, R: MessageRoute> Drop for Delivery<M, R> {
    fn drop(&mut self) {
        let device_quiet = self.controller.quiesce();
        let route_quiet = self.route.as_mut().expect("owned route").disable();
        narf_interrupts::dispatch::disable_irq(self.vector);
        if !device_quiet || !route_quiet {
            // Revocation/removal can make it impossible to prove MSI stopped.
            // Keep the vector, cookie, BAR authority and route together. A
            // later device message must never reach another driver's vector.
            core::mem::forget(self.controller.clone());
            core::mem::forget(self.route.take());
            return;
        }
        narf_interrupts::dispatch::remove_handler(
            self.vector,
            "intel-gt",
            Arc::as_ptr(&self.controller) as u64,
        );
        narf_interrupts::dispatch::synchronize_irq(self.vector);
        let _ = narf_interrupts::vector::free(self.vector);
    }
}

pub(crate) type GtIrq = Delivery<crate::intel_gpu_gt_hw::AuthorizedWindow, PciMsi>;

pub(crate) struct PciMsi {
    cap: narf_capabilities::Cap<narf_bus::BusDeviceCap, narf_capabilities::Write>,
    device: narf_bus::BusDevice,
    config: narf_bus::msi::MsiConfig,
    mask: Option<(u16, u32)>,
    control: (u16, u32),
    programmed: bool,
}

struct PciAction<F>(F);
impl<T, F> narf_capabilities::CapOp<narf_bus::BusDeviceCap, narf_capabilities::Write>
    for PciAction<F>
where
    F: FnOnce() -> T,
{
    type Output = T;
    fn execute(
        self,
        _: &narf_capabilities::Cap<narf_bus::BusDeviceCap, narf_capabilities::Write>,
    ) -> Result<T, narf_capabilities::CapError> {
        Ok((self.0)())
    }
}

impl PciMsi {
    fn new(
        cap: narf_capabilities::Cap<narf_bus::BusDeviceCap, narf_capabilities::Write>,
        device: narf_bus::BusDevice,
    ) -> Result<Self, IrqError> {
        cap.invoke(PciAction(|| {
            if narf_bus::vmd_domain::domain_for_device(&device).is_some() {
                return Err(IrqError::Conflict); // requires the VMD shared-route owner
            }
            let mut control = None;
            for id in [narf_bus::pci_cap::id::MSI, narf_bus::pci_cap::id::MSI_X] {
                // SAFETY: exclusive live physical PCI function, inside invoke.
                if let Some(offset) = unsafe { narf_bus::pci_cap::find_cap(&device, id) }
                    .map_err(|_| IrqError::Route)?
                {
                    let word = narf_bus::pci::read_config32(&cap, &device, offset as u16)
                        .map_err(|_| IrqError::Route)?;
                    let enabled = if id == narf_bus::pci_cap::id::MSI {
                        1 << 16
                    } else {
                        1 << 31
                    };
                    if word == u32::MAX || word & enabled != 0 {
                        return Err(IrqError::Conflict);
                    }
                    if id == narf_bus::pci_cap::id::MSI {
                        control = Some((offset as u16, word));
                    }
                }
            }
            let control = control.ok_or(IrqError::Route)?;
            let config =
                narf_bus::msi::enable_msi(&cap, &device, 1).map_err(|_| IrqError::Route)?;
            let end = control.0
                + if config.is_64bit() { 16 } else { 12 }
                + if config.per_vector_mask() { 8 } else { 0 };
            if end > 0x100 {
                return Err(IrqError::Route);
            }
            let mask = if config.per_vector_mask() {
                let offset = control.0 + if config.is_64bit() { 16 } else { 12 };
                let value = narf_bus::pci::read_config32(&cap, &device, offset)
                    .map_err(|_| IrqError::Route)?;
                Some((offset, value))
            } else {
                None
            };
            Ok(Self {
                cap,
                device,
                config,
                mask,
                control,
                programmed: false,
            })
        }))
        .map_err(|_| IrqError::Unavailable)?
    }
}

impl MessageRoute for PciMsi {
    fn program(&mut self, vector: u8) -> Result<(), IrqError> {
        self.cap
            .invoke(PciAction(|| {
                self.programmed = true;
                if let Some((offset, value)) = self.mask {
                    narf_bus::pci::write_config32(&self.cap, &self.device, offset, value | 1)
                        .map_err(|_| IrqError::Route)?;
                }
                // SAFETY: Late task, APIC initialized; target this online CPU.
                #[cfg(target_arch = "x86_64")]
                let target = unsafe { narf_interrupts::x86_64::apic::apic_id() };
                #[cfg(not(target_arch = "x86_64"))]
                let target = 0;
                if target > 255 {
                    return Err(IrqError::Route); // basic MSI cannot encode x2APIC IDs >255
                }
                // SAFETY: exclusive PCI owner, disabled MSI, current authority.
                unsafe { narf_bus::msi::program_msi(&mut self.config, target, vector) }
                    .map_err(|_| IrqError::Route)?;
                Ok(())
            }))
            .map_err(|_| IrqError::Unavailable)?
    }
    fn enable(&mut self) -> Result<(), IrqError> {
        self.cap
            .invoke(PciAction(|| {
                // SAFETY: programmed vector + handler retained by Delivery.
                unsafe { narf_bus::msi::enable(&self.config) }.map_err(|_| IrqError::Route)?;
                if let Some((offset, value)) = self.mask {
                    narf_bus::pci::write_config32(&self.cap, &self.device, offset, value & !1)
                        .map_err(|_| IrqError::Route)?;
                    if narf_bus::pci::read_config32(&self.cap, &self.device, offset)
                        .map_err(|_| IrqError::Route)?
                        & 1
                        != 0
                    {
                        return Err(IrqError::Route);
                    }
                }
                let control = narf_bus::pci::read_config32(&self.cap, &self.device, self.control.0)
                    .map_err(|_| IrqError::Route)?;
                if control == u32::MAX || control & 0x00710000 != 0x00010000 {
                    return Err(IrqError::Route);
                }
                Ok(())
            }))
            .map_err(|_| IrqError::Unavailable)?
    }
    fn disable(&mut self) -> bool {
        if !self.programmed {
            return true;
        }
        self.cap
            .invoke(PciAction(|| {
                // SAFETY: device sources masked; vector and handler still retained.
                let _ = unsafe { narf_bus::msi::disable(&self.config) };
                if !narf_bus::pci::read_config32(&self.cap, &self.device, self.control.0)
                    .is_ok_and(|value| value != u32::MAX && value & (1 << 16) == 0)
                {
                    return false;
                }
                if let Some((offset, value)) = self.mask {
                    let _ = narf_bus::pci::write_config32(&self.cap, &self.device, offset, value);
                }
                let _ = narf_bus::pci::write_config32(
                    &self.cap,
                    &self.device,
                    self.control.0,
                    self.control.1,
                );
                true
            }))
            .unwrap_or(false)
    }
}

impl GtIrq {
    pub(crate) fn for_device(
        mmio: crate::intel_gpu_gt_hw::AuthorizedWindow,
        cap: narf_capabilities::Cap<narf_bus::BusDeviceCap, narf_capabilities::Write>,
        device: narf_bus::BusDevice,
        engines: EngineSet,
    ) -> Result<Self, IrqError> {
        // The GT's production DMA path currently admits coherent x86 only.
        // Do not program ARM MSI without an ITS DeviceID/event owner.
        if !cfg!(target_arch = "x86_64") {
            return Err(IrqError::Route);
        }
        let platform =
            crate::intel_gpu_gt::GtPlatform::from_pci(device.id.vendor, device.id.device)
                .filter(|platform| platform.guc().is_some())
                .ok_or(IrqError::Identity)?;
        Self::install_hierarchy(
            mmio,
            PciMsi::new(cap, device)?,
            engines,
            !platform.is_gen12(),
        )
    }
}

#[cfg(feature = "kernel-test")]
#[path = "intel_gpu_gt_irq_tests.rs"]
mod tests;
