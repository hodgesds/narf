//! NVIDIA interrupt handling — MSI routing + the PMC top-half (G4).
//!
//! ## Delivery decision (MSI, single vector — Nouveau's choice)
//!
//! Nouveau enables **plain MSI, never MSI-X**, on every chip including
//! Pascal/GP107: `nvkm/subdev/pci/base.c::nvkm_pci_new_` sets
//! `pci->msi = true` by default (except chipset `0xaa` and big-endian)
//! and then `pci->msi = pci_enable_msi(pdev) == 0`. No MSI-X attempt
//! exists anywhere in Nouveau. This lane follows that exactly: one
//! MSI vector via `narf_bus::msi`, no MSI-X attempt (NARF's MSI-X path
//! is proven on Intel/AMD parts only, and no Nvidia part is known to
//! need it), no INTx handler. If MSI cannot be programmed the card
//! still binds and the mode degrades to [`IrqMode::Polling`] — the same
//! degradation the AMDGPU Navi22 IH uses (`amdgpu_ih_navi22.rs::route`
//! returns `Delivery::Polling` when routing fails). `INTX_DISABLE`
//! stays set in the PCI command word (see `pci::probe`): MSI delivery
//! does not use the INTx line.
//!
//! The routing shape mirrors `amdgpu_ih_navi22.rs::route`: allocate a
//! kernel vector, install the hard handler, program the MSI message,
//! enable delivery; unwind (remove handler, sync, free vector) if any
//! step fails. x86_64 only, like Navi22 — aarch64 stays [`IrqMode::Polling`]
//! (the bus MSI layer needs ITS `MAPD`/`MAPTI` the caller must do first).
//!
//! ## Top-half / bottom-half split (Nouveau `nvkm_pci_intr` shape)
//!
//! The hard handler ([`nvidia_irq_handler`], cookie = card index) is
//! the `nvkm_pci_intr` analogue: read `PMC_INTR_0`, walk the asserted
//! sources, mask each consumed source at the top level, record the
//! cookies. It allocates nothing — the walk is the pure
//! [`IrqState::observe`] step over a raw status word plus per-engine
//! status reads, following `mc::walk_intr0`'s hermetic-walker precedent
//! (the allocating `mc::read_live_intr0` is reserved for the bottom
//! half, where allocation is fine).
//!
//! The bottom half is a spawned task that waits on the vector with
//! `narf_interrupts::wait_for_irq` and drains the pending mask via
//! [`IrqState::drain_pending`], which re-samples with
//! `mc::read_live_intr0` and re-arms (unmasks) the consumed sources.
//! The wait is constructed *before* each drain so an IRQ landing
//! between the drain and the park cannot be missed (the
//! `wait_for_irq` baseline is taken at construction).
//!
//! ## G11 seam
//!
//! Flip completion + vblank (G11) plugs in here, not in the top half:
//! the drain returns the mask of sources it re-armed, and
//! [`IrqState::take_pending`] exposes the raw pending mask. G11's
//! consumer will take the `Display` bit from the drained mask and call
//! `FlipQueue::on_vblank` with the head frame counter. Until then the
//! handler only counts `Display` firings (`IrqState::count`).
//!
//! ## Open items (not guessed here)
//!
//! - Per-engine **ack** (the write that clears a PMC bit) is
//!   per-engine and unverified for Pascal; the drain re-arms the
//!   top-level enable without acking the engine. A source whose engine
//!   status is never acked will not produce a new MSI edge until the
//!   engine status is cleared — G11 (or the per-engine lanes) own the
//!   ack. See `drain_pending`.
//! - `gp100_mc_intr_update` programs the enable via the `0x160`/`0x180`
//!   SET/CLEAR registers, while `mc::mask/unmask_intr_source` RMWs
//!   `PMC_INTR_EN_0` (`0x140`, the `nv04`/`gf100` shape). Whether the
//!   `0x140` RMW is still the live enable on Pascal is a G13 remainder;
//!   this lane uses the crate's existing mask/unmask and does not
//!   re-derive the enable register.
//! - `NVKM_SUBDEV_FAULT` (`0x200`, bit 9 in `gp100_mc_intr[]`) has no
//!   `IntrSource` variant yet; an asserted FAULT bit is counted as
//!   unrecognized, never masked. G13 remainder.

#![allow(dead_code)]

use core::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};

use narf_driver_runtime::{BusDevice, BusDeviceCap, Cap, MmioRegion, Write};

use crate::mc::{self, IntrSource};
use crate::pci::NvidiaDevice;

/// How this card's interrupts reach the CPU.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IrqMode {
    /// No vector: MSI could not be programmed (or this arch has no
    /// routing yet). The card binds; interrupt-driven delivery is off.
    Polling,
    /// Single-vector MSI, Nouveau's delivery mode. Holds the kernel
    /// vector the MSI message targets.
    Msi { vector: u8 },
}

/// Per-source slot in the `counts` / `last_engine_status` tables,
/// in `IntrSource::all()` order.
fn index_of(source: IntrSource) -> usize {
    match source {
        IntrSource::Display => 0,
        IntrSource::Fifo => 1,
        IntrSource::Graphics => 2,
        IntrSource::CopyEngine0 => 3,
        IntrSource::CopyEngine1 => 4,
        IntrSource::CopyEngine2 => 5,
        IntrSource::Sec => 6,
        IntrSource::Pmu => 7,
        IntrSource::Gsp => 8,
    }
}

/// Per-card interrupt state. All atomics: the hard top half runs with
/// only `&NvidiaDevice`, the drain task runs concurrently, and both
/// must observe the same counters without a lock in IRQ context.
#[derive(Debug)]
pub struct IrqState {
    /// `0` = [`IrqMode::Polling`], `1` = [`IrqMode::Msi`].
    mode: AtomicU8,
    /// Kernel vector for MSI mode; `u8::MAX` when none.
    vector: AtomicU8,
    /// Top-half entries (every hard-IRQ delivery on our vector).
    fired: AtomicU64,
    /// Top-half entries that consumed at least one known source.
    handled: AtomicU64,
    /// Top-half entries with `PMC_INTR_0 == 0` (not our device).
    spurious: AtomicU64,
    /// Top-half entries with a nonzero status word but no known
    /// source bit (e.g. the FAULT bit, which has no variant yet).
    unrecognized: AtomicU64,
    /// Sources re-armed by the drain (cumulative count).
    rearmed: AtomicU64,
    /// Last raw `PMC_INTR_0` sample the top half observed.
    last_intr0: AtomicU32,
    /// Sources consumed by the top half and awaiting the drain.
    /// Bitmask over `IntrSource::intr0_bit`; the G11 seam.
    pending: AtomicU32,
    /// Per-source firing counts, `IntrSource::all()` order.
    counts: [AtomicU32; 9],
    /// Last per-engine status value observed per source,
    /// `IntrSource::all()` order.
    last_engine_status: [AtomicU32; 9],
}

impl Default for IrqState {
    fn default() -> Self {
        Self::new()
    }
}

impl IrqState {
    /// Fresh state: polling mode, no vector, all counters zero.
    pub fn new() -> Self {
        Self {
            mode: AtomicU8::new(0),
            vector: AtomicU8::new(u8::MAX),
            fired: AtomicU64::new(0),
            handled: AtomicU64::new(0),
            spurious: AtomicU64::new(0),
            unrecognized: AtomicU64::new(0),
            rearmed: AtomicU64::new(0),
            last_intr0: AtomicU32::new(0),
            pending: AtomicU32::new(0),
            counts: core::array::from_fn(|_| AtomicU32::new(0)),
            last_engine_status: core::array::from_fn(|_| AtomicU32::new(0)),
        }
    }

    /// Current delivery mode.
    pub fn mode(&self) -> IrqMode {
        if self.mode.load(Ordering::Acquire) == 1 {
            IrqMode::Msi {
                vector: self.vector.load(Ordering::Acquire),
            }
        } else {
            IrqMode::Polling
        }
    }

    /// Kernel vector in MSI mode; `None` in polling mode.
    pub fn vector(&self) -> Option<u8> {
        match self.mode() {
            IrqMode::Msi { vector } => Some(vector),
            IrqMode::Polling => None,
        }
    }

    /// Top-half entries so far.
    pub fn fired(&self) -> u64 {
        self.fired.load(Ordering::Acquire)
    }

    /// Top-half entries that consumed a known source.
    pub fn handled(&self) -> u64 {
        self.handled.load(Ordering::Acquire)
    }

    /// Top-half entries with a zero status word.
    pub fn spurious(&self) -> u64 {
        self.spurious.load(Ordering::Acquire)
    }

    /// Top-half entries with nonzero status but no known source bit.
    pub fn unrecognized(&self) -> u64 {
        self.unrecognized.load(Ordering::Acquire)
    }

    /// Sources re-armed by the drain, cumulative.
    pub fn rearmed(&self) -> u64 {
        self.rearmed.load(Ordering::Acquire)
    }

    /// Last raw `PMC_INTR_0` sample.
    pub fn last_intr0(&self) -> u32 {
        self.last_intr0.load(Ordering::Acquire)
    }

    /// Pending mask (sources consumed, awaiting the drain).
    pub fn pending_bits(&self) -> u32 {
        self.pending.load(Ordering::Acquire)
    }

    /// Firing count for one source.
    pub fn count(&self, source: IntrSource) -> u32 {
        self.counts[index_of(source)].load(Ordering::Acquire)
    }

    /// Last per-engine status value observed for one source.
    pub fn last_engine_status(&self, source: IntrSource) -> u32 {
        self.last_engine_status[index_of(source)].load(Ordering::Acquire)
    }

    /// Pure consume step. Allocation-free and MMIO-free, so the hard
    /// top half can call it: given a raw `PMC_INTR_0` sample plus a
    /// per-engine status reader, record one cookie per asserted known
    /// source and return the bitmask of sources the caller must mask
    /// at the top level (the consume). Returns `0` when nothing known
    /// asserted — `top == 0` (spurious) or only unknown bits set.
    ///
    /// Sources with no top-level bit (`Sec`, `Gsp` — see
    /// `IntrSource::intr0_bit`) can never assert here; their
    /// `engine_status` reader is never called.
    pub fn observe(&self, top: u32, engine_status: impl Fn(IntrSource) -> u32) -> u32 {
        self.fired.fetch_add(1, Ordering::Relaxed);
        if top == 0 {
            self.spurious.fetch_add(1, Ordering::Relaxed);
            return 0;
        }
        self.last_intr0.store(top, Ordering::Relaxed);
        let mut mask = 0u32;
        for src in IntrSource::all().iter().copied() {
            let bit = src.intr0_bit();
            if bit == 0 || top & bit == 0 {
                continue;
            }
            let idx = index_of(src);
            self.counts[idx].fetch_add(1, Ordering::Relaxed);
            self.last_engine_status[idx].store(engine_status(src), Ordering::Relaxed);
            self.pending.fetch_or(bit, Ordering::Relaxed);
            mask |= bit;
        }
        if mask != 0 {
            self.handled.fetch_add(1, Ordering::Relaxed);
        } else {
            self.unrecognized.fetch_add(1, Ordering::Relaxed);
        }
        mask
    }

    /// Take the pending mask for the bottom half. Clears it; the
    /// drain owns re-arming exactly the sources it takes. G11 seam:
    /// the consumer reads the `Display` bit from the returned mask.
    pub fn take_pending(&self) -> u32 {
        self.pending.swap(0, Ordering::AcqRel)
    }

    /// Hard-IRQ top half over live MMIO. Reads `PMC_INTR_0`,
    /// consumes the asserted sources via [`IrqState::observe`], and
    /// masks each consumed source so it cannot re-fire until the
    /// drain re-arms it. Returns `true` iff a known source was
    /// consumed (the handler claims the IRQ).
    ///
    /// # Safety
    /// `bar0` is the kernel-mapped BAR0 view of this card, owned by
    /// the card for its lifetime. Called from the hard handler with
    /// interrupts disabled on this CPU; only PMC registers are
    /// touched.
    pub unsafe fn handle_top_half(&self, bar0: &MmioRegion) -> bool {
        // SAFETY: per this fn's `# Safety`, `bar0` is the card's BAR0
        // window; `read_intr0_status` is a single 32-bit MMIO read.
        let top = unsafe { mc::read_intr0_status(bar0) };
        let mask = self.observe(top, |src| {
            match src.engine_status_offset() {
                // SAFETY: same as above; `off` is the per-engine status
                // register offset for `src`, a fixed valid 32-bit
                // register within BAR0.
                // SAFETY: Valid MMIO bounds or trusted driver environment
                Some(off) => unsafe { bar0.read32(off) },
                None => 0,
            }
        });
        for src in IntrSource::all().iter().copied() {
            let bit = src.intr0_bit();
            if bit != 0 && mask & bit != 0 {
                // SAFETY: same as above; the caller holds exclusive
                // access to the intr-enable register in IRQ context.
                unsafe { mc::mask_intr_source(bar0, src) };
            }
        }
        mask != 0
    }

    /// Bottom half over live MMIO. Re-arms every source the top half
    /// consumed: takes the pending mask, re-samples the live cookies
    /// with `mc::read_live_intr0` (task context — allocation is
    /// fine), unmasks the sources that are still asserted, then
    /// unmasks any remaining pending sources that cleared before the
    /// re-sample. Returns the mask of sources re-armed.
    ///
    /// The re-sample also refreshes `last_engine_status` for
    /// still-asserted sources, so the drain can tell a source that is
    /// still asserting (needs a per-engine ack — G11 / engine lanes)
    /// from one that cleared on its own.
    ///
    /// # Safety
    /// `bar0` is the kernel-mapped BAR0 view of this card, owned by
    /// the card for its lifetime. Called from the drain task only,
    /// never from IRQ context.
    pub unsafe fn drain_pending(&self, bar0: &MmioRegion) -> u32 {
        let pending = self.take_pending();
        if pending == 0 {
            return 0;
        }
        // SAFETY: per this fn's `# Safety`, `bar0` is the card's BAR0
        // window and this runs in task context.
        let cookies = unsafe { mc::read_live_intr0(bar0) };
        let mut drained = 0u32;
        for cookie in &cookies {
            if pending & cookie.intr0_bit != 0 {
                let idx = index_of(cookie.source);
                self.last_engine_status[idx].store(cookie.engine_status, Ordering::Relaxed);
                // SAFETY: same as above.
                unsafe { mc::unmask_intr_source(bar0, cookie.source) };
                drained |= cookie.intr0_bit;
            }
        }
        for src in IntrSource::all().iter().copied() {
            let bit = src.intr0_bit();
            if bit != 0 && pending & bit != 0 && drained & bit == 0 {
                // SAFETY: same as above.
                unsafe { mc::unmask_intr_source(bar0, src) };
                drained |= bit;
            }
        }
        self.rearmed
            .fetch_add(drained.count_ones() as u64, Ordering::Relaxed);
        drained
    }
}

/// Hard-IRQ handler installed by [`route_irq`]. Cookie is the card
/// index (`NvidiaDevice::card_index`); the card is found in the
/// global controller list, which outlives every delivery.
fn nvidia_irq_handler(cookie: u64) -> narf_interrupts::IrqStatus {
    let handled = crate::pci::with_card(cookie as u32, |card| {
        // SAFETY: `card.regs` is the BAR0 window owned by the card for
        // its lifetime; the top half only reads/masks PMC registers.
        unsafe { card.irq.handle_top_half(&card.regs) }
    })
    .unwrap_or(false);
    if handled {
        narf_interrupts::IrqStatus::Handled
    } else {
        narf_interrupts::IrqStatus::None
    }
}

/// Route one MSI vector for `card` and install the hard handler.
/// Best-effort: on any failure the card stays in polling mode and
/// probe still succeeds — the card binds, only interrupt delivery is
/// off. On success the drain task is spawned (it owns no card state,
/// only the card index, and looks the card up per wake).
///
/// # Safety
/// Caller owns the PCI function's config space (`cap`) and BARs, and
/// APIC initialization precedes device initcalls (same contract as
/// `amdgpu_ih_navi22.rs::route`). The card is already in the global
/// controller list, so the handler can find it from the first
/// delivery on. The MSI config is not retained: there is no unbind
/// path in this driver yet, so no teardown disables delivery.
pub unsafe fn route_irq(card: &NvidiaDevice, device: &BusDevice, cap: &Cap<BusDeviceCap, Write>) {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: forwarded exclusive PCI function ownership.
    unsafe {
        route_irq_x86_64(card, device, cap)
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (card, device, cap);
        // Polling mode: no MSI routing on this arch yet.
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn route_irq_x86_64(
    card: &NvidiaDevice,
    device: &BusDevice,
    cap: &Cap<BusDeviceCap, Write>,
) {
    use narf_interrupts::{dispatch, vector};
    let cookie = card.card_index as u64;
    // SAFETY: APIC initialization precedes device initcalls.
    let target = unsafe { narf_interrupts::current_cpu_target_id() };
    if target > 255 {
        return;
    }
    let Ok(vector) = vector::alloc() else {
        return;
    };
    dispatch::install_handler_named(vector, "nvidia-ih", cookie, nvidia_irq_handler);
    // Single-vector MSI, Nouveau's delivery mode — no MSI-X attempt
    // (see the module docs). `enable_msi` only discovers the cap;
    // delivery starts at `msi::enable`.
    let routed = match narf_bus::msi::enable_msi(cap, device, 1) {
        Ok(mut cfg) => {
            // SAFETY: owned config space; vector and handler installed.
            unsafe { narf_bus::msi::program_msi(&mut cfg, target, vector) }.is_ok()
                // SAFETY: same owned config space.
                && unsafe { narf_bus::msi::enable(&cfg) }.is_ok()
        }
        Err(_) => false,
    };
    if !routed {
        dispatch::remove_handler(vector, "nvidia-ih", cookie);
        dispatch::synchronize_irq(vector);
        let _ = vector::free(vector);
        return;
    }
    card.irq.mode.store(1, Ordering::Release);
    card.irq.vector.store(vector, Ordering::Release);
    let card_index = card.card_index;
    narf_scheduler::spawn(async move {
        loop {
            // Construct the wait BEFORE draining: its baseline is
            // taken at construction, so an IRQ landing between the
            // drain and the park still resolves this wait instead of
            // being missed until the next delivery.
            let wait = narf_interrupts::wait_for_irq(vector);
            crate::pci::with_card(card_index, |card| {
                // SAFETY: `card.regs` is the BAR0 window owned by the
                // card for its lifetime; the drain runs in task
                // context, never IRQ context.
                unsafe { card.irq.drain_pending(&card.regs) };
            });
            wait.await;
        }
    });
}
