//! The AHB HIF: [`CeHif`] over [`AhbIo`] with interrupts from per-line
//! GIC SPIs ([`AhbIrq`]).
//!
//! Linux `ahb.c`:
//!
//! | NARF | Linux |
//! |---|---|
//! | [`ahb_lines`] | `ath11k_ahb_config_irq` (CE lines) + `ath11k_ahb_config_ext_irq` (DP group lines); hybrid bus: `ath11k_pcic_config_irq` over the DT MSI vectors |
//! | [`AhbIrq::bind_gic`] | the `request_irq(.., IRQF_TRIGGER_RISING, ..)` calls, through [`GicSpi`] |
//! | [`AhbIrq::line_fired`] | `ath11k_ahb_ce_interrupt_handler` / `ath11k_ahb_ext_interrupt_handler` (and the `pcic` ones) |
//! | [`CeIrq::take_pending`] / [`DpIrq::take_dp_pending`] | the CE tasklet / NAPI poll taking the work, then `enable_irq` |
//! | [`CeIrq::hif_start`] / [`CeIrq::hif_stop`] | `ath11k_ahb_start` / `_stop` → `ath11k_ahb_ce_irqs_{enable,disable}` (`CE_HOST_IE_*`) |
//! | [`ahb_ce_hif`] | `ath11k_hal_srng_init` + `ath11k_ce_alloc_pipes` in `ath11k_ahb_probe` |
//!
//! The hard-IRQ handler touches only atomics and the distributor: it
//! masks the line(s) (`disable_irq_nosync`; Linux masks the CE at the
//! `CE_HOST_IE` register instead, which needs register access the
//! handler does not have) and records the pending CE / ext-group bits in
//! the same state the PCI MSI handlers feed ([`super::ce::raise_ce`],
//! [`super::runtime::raise_dp`]), so the runtime's service pass
//! ([`super::runtime`]) is bus-agnostic. Taking the pending bits unmasks
//! the lines before the service pass runs (Linux unmasks after it): an
//! edge raised during the pass stays pending in the distributor and
//! starts another pass instead of being coalesced into this one.
//!
//! Everything goes through [`GicSpi`] / [`spi_set_enabled`], so the GIC
//! backend underneath (GICv3 today; the IPQ SoCs are GICv2) can change
//! without touching this module.

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::Future;
use core::sync::atomic::{AtomicU64, Ordering};

use narf_drivers_qcom_soc::io::RegIo;
use narf_drivers_qcom_soc::irq::{spi_set_enabled, GicSpi, IrqBindError};
use narf_lib::sync::IrqSafeSpinLock;

use super::ahb::{ce_irqs, ce_irqs_set, ext_irq_groups, AhbHwParams, AhbIo, AhbResources};
use super::ce::{self, Ce, CeIrq, CeMsi, MsiCeIrq};
use super::core::CeHif;
use super::hal::TransportError;
use super::hw::ATH11K_EXT_IRQ_GRP_NUM_MAX;
use super::power::ChipIo;
use super::runtime::{dp_vector_cookie, DpIrq};

/// What one interrupt line signals: a bitmask of CEs or of ext groups.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AhbLineKind {
    Ce(u32),
    Dp(u32),
}

/// One device interrupt line: its GIC INTID and what it signals.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct AhbLine {
    pub intid: u32,
    pub kind: AhbLineKind,
}

/// The CE and DP lines `ath11k_ahb_config_irq` requests. Non-hybrid:
/// one line per interrupt-enabled CE (`ATH11K_IRQ_CE0_OFFSET + ce`)
/// and one per ring interrupt of each ext group
/// (`ath11k_ahb_config_ext_irq`). Hybrid (WCN6750): the DT MSI vectors,
/// assigned as `ath11k_pcic_config_irq` does (the "CE" and "DP" MSI
/// users). Lines missing from `res` are skipped (the probe already
/// refused a node that lacks one).
pub fn ahb_lines(res: &AhbResources) -> Vec<AhbLine> {
    let p = &res.params;
    let mut out = Vec::new();
    if let (Some(msi), Some(cfg)) = (&res.msi, p.msi) {
        for (i, &intid) in msi.irqs.iter().enumerate() {
            if let Some(m) = ce::ce_vector_cookie(p.host_ce_config, cfg, i as u32) {
                out.push(AhbLine {
                    intid,
                    kind: AhbLineKind::Ce(m as u32),
                });
            }
            if let Some(m) = dp_vector_cookie(p.ring_mask, cfg, i as u32) {
                out.push(AhbLine {
                    intid,
                    kind: AhbLineKind::Dp(m as u32),
                });
            }
        }
        return out;
    }
    let hw = |idx: usize| res.irqs.iter().find(|(i, _)| *i == idx).map(|(_, h)| *h);
    for (ce, idx) in ce_irqs(p) {
        if let Some(intid) = hw(idx) {
            out.push(AhbLine {
                intid,
                kind: AhbLineKind::Ce(1 << ce),
            });
        }
    }
    for (grp, idxs) in ext_irq_groups(p).iter().enumerate() {
        for &idx in idxs {
            if let Some(intid) = hw(idx as usize) {
                out.push(AhbLine {
                    intid,
                    kind: AhbLineKind::Dp(1 << grp),
                });
            }
        }
    }
    out
}

/// Masks / unmasks one line (`enable_irq` / `disable_irq_nosync`).
/// [`spi_set_enabled`] on hardware; fixtures record.
pub type LineCtl = fn(intid: u32, on: bool);

struct Shared {
    lines: Vec<AhbLine>,
    params: AhbHwParams,
    ctl: LineCtl,
    /// Bit `i`: line `i` is masked by its handler.
    masked: AtomicU64,
    /// Bound GIC lines (released on [`AhbIrq::release`]).
    gic: Vec<GicSpi>,
    /// `(vector, cookie)` of every chained handler.
    cookies: IrqSafeSpinLock<Vec<(u8, u64)>>,
    fires: AtomicU64,
}

/// The AHB interrupt source: [`CeIrq`] + [`DpIrq`] over the device's
/// lines.
#[derive(Clone)]
pub struct AhbIrq(Arc<Shared>);

impl core::fmt::Debug for AhbIrq {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AhbIrq")
            .field("lines", &self.0.lines.len())
            .field("masked", &self.masked())
            .finish()
    }
}

/// `ATH11K_EXT_IRQ_GRP_NUM_MAX` fits the 32-bit group mask.
const _: () = assert!(ATH11K_EXT_IRQ_GRP_NUM_MAX <= 32);

/// Handler cookie: a leaked `(state, line)` pair.
struct LineCookie {
    irq: AhbIrq,
    line: usize,
}

const HANDLER: &str = "ath11k-ahb";

fn ahb_line_irq(cookie: u64) -> narf_interrupts::IrqStatus {
    if cookie == 0 {
        return narf_interrupts::IrqStatus::None;
    }
    // SAFETY: non-zero cookies come only from `bind_gic`, which leaks
    // the box until `release` removes the handler.
    let c = unsafe { &*(cookie as *const LineCookie) };
    c.irq.line_fired(c.line);
    narf_interrupts::IrqStatus::Handled
}

impl AhbIrq {
    /// The source over `lines` (64 at most), masked through `ctl`.
    pub fn new(lines: Vec<AhbLine>, params: AhbHwParams, ctl: LineCtl) -> Self {
        Self::with_gic(lines, params, ctl, Vec::new())
    }

    fn with_gic(lines: Vec<AhbLine>, params: AhbHwParams, ctl: LineCtl, gic: Vec<GicSpi>) -> Self {
        AhbIrq(Arc::new(Shared {
            lines,
            params,
            ctl,
            masked: AtomicU64::new(0),
            gic,
            cookies: IrqSafeSpinLock::new(Vec::new()),
            fires: AtomicU64::new(0),
        }))
    }

    /// Bind every line as an edge-triggered SPI (`IRQF_TRIGGER_RISING`)
    /// and chain the handler; a line shared by a CE and a DP user (hybrid
    /// bus) is bound once with both. On failure every line bound so far
    /// is released.
    pub fn bind_gic(lines: Vec<AhbLine>, params: AhbHwParams) -> Result<Self, IrqBindError> {
        let mut gic: Vec<GicSpi> = Vec::new();
        for l in &lines {
            if gic.iter().any(|g| g.intid() == l.intid) {
                continue;
            }
            match GicSpi::bind(l.intid, true) {
                Ok(g) => gic.push(g),
                Err(e) => {
                    for g in gic {
                        g.release(HANDLER, 0);
                    }
                    return Err(e);
                }
            }
        }
        let irq = Self::with_gic(lines, params, spi_set_enabled, gic);
        for (i, l) in irq.0.lines.iter().enumerate() {
            if let Some(g) = irq.0.gic.iter().find(|g| g.intid() == l.intid) {
                let c = Box::into_raw(Box::new(LineCookie {
                    irq: irq.clone(),
                    line: i,
                })) as u64;
                irq.0.cookies.lock().push((g.vector(), c));
                g.install(HANDLER, c, ahb_line_irq);
            }
        }
        Ok(irq)
    }

    /// `ath11k_ahb_free_irq`: unchain every handler, then mask and
    /// release every bound line. The cookies stay leaked (the state they
    /// point at is reference-counted and never called again).
    pub fn release(&self) {
        let cookies = core::mem::take(&mut *self.0.cookies.lock());
        for (v, c) in cookies {
            narf_interrupts::remove_handler(v, HANDLER, c);
        }
        for g in &self.0.gic {
            g.release(HANDLER, 0);
        }
    }

    pub fn lines(&self) -> &[AhbLine] {
        &self.0.lines
    }

    /// Lines currently masked by their handler.
    pub fn masked(&self) -> u64 {
        self.0.masked.load(Ordering::Acquire)
    }

    /// Hard-IRQ deliveries seen.
    pub fn fires(&self) -> u64 {
        self.0.fires.load(Ordering::Relaxed)
    }

    fn set_lines(&self, pick: impl Fn(&AhbLineKind) -> bool, on: bool) {
        for (i, l) in self.0.lines.iter().enumerate() {
            if !pick(&l.kind) {
                continue;
            }
            let bit = 1u64 << i;
            let was = if on {
                self.0.masked.fetch_and(!bit, Ordering::AcqRel)
            } else {
                self.0.masked.fetch_or(bit, Ordering::AcqRel)
            };
            if (was & bit != 0) == on {
                (self.0.ctl)(l.intid, on);
            }
        }
    }

    /// The hard-IRQ body for line `i`: CE — mask the line, note the CE
    /// (`ath11k_ahb_ce_interrupt_handler`); DP — mask every line of the
    /// group (`ath11k_ahb_ext_grp_disable`), note the group
    /// (`napi_schedule`). Ignored (line left unmasked) while that side's
    /// interrupts are disabled. Atomics + distributor writes only.
    pub fn line_fired(&self, i: usize) {
        let Some(l) = self.0.lines.get(i) else {
            return;
        };
        self.0.fires.fetch_add(1, Ordering::Relaxed);
        match l.kind {
            AhbLineKind::Ce(m) => {
                if ce::raise_ce(m) {
                    self.set_lines(|k| matches!(k, AhbLineKind::Ce(x) if x & m != 0), false);
                }
            }
            AhbLineKind::Dp(m) => {
                if super::runtime::raise_dp(m) {
                    self.set_lines(|k| matches!(k, AhbLineKind::Dp(x) if x & m != 0), false);
                }
            }
        }
    }
}

impl CeIrq for AhbIrq {
    fn take_pending(&self) -> u32 {
        let p = MsiCeIrq.take_pending();
        if p != 0 {
            self.set_lines(|k| matches!(k, AhbLineKind::Ce(x) if x & p != 0), true);
        }
        p
    }
    fn wait(&self, ms: u32) -> impl Future<Output = ()> + Send {
        MsiCeIrq.wait(ms)
    }
    fn hif_start(&self, io: &impl ChipIo) {
        if !self.0.params.hybrid_bus_type {
            ce_irqs_set(io, &self.0.params, self.0.params.ce_offset(), true);
        }
    }
    fn hif_stop(&self, io: &impl ChipIo, crash_flush: bool) {
        if !self.0.params.hybrid_bus_type && !crash_flush {
            ce_irqs_set(io, &self.0.params, self.0.params.ce_offset(), false);
        }
    }
}

impl DpIrq for AhbIrq {
    fn take_dp_pending(&self) -> u32 {
        let p = MsiCeIrq.take_dp_pending();
        if p != 0 {
            self.set_lines(|k| matches!(k, AhbLineKind::Dp(x) if x & p != 0), true);
        }
        p
    }
}

/// The CE half of `ath11k_ahb_probe` (`ath11k_hal_srng_init`,
/// `ath11k_ce_alloc_pipes`) and the HIF over it. IPQ parts get no ring
/// MSI ([`super::hw::MSI_CONFIG_NONE`]); WCN6750 gets the DT MSI
/// doorbell (`ath11k_ahb_setup_msi_resources`).
pub fn ahb_ce_hif<R: RegIo>(
    res: &AhbResources,
    io: AhbIo<R>,
    irq: AhbIrq,
    clock: fn() -> u64,
) -> Result<CeHif<AhbIo<R>, AhbIrq>, TransportError> {
    let hw = res.params.hw_params(res.chip.hw_rev());
    let msi = CeMsi {
        addr: res.msi.as_ref().map_or(0, |m| m.addr),
        ep_base_data: res.msi.as_ref().map_or(0, |m| m.ep_base_data),
        config: hw.msi,
    };
    let ce = Ce::alloc(&hw, msi, clock)?;
    Ok(CeHif {
        ce,
        io,
        irq,
        on_start: || {},
        clock,
    })
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "ahb_hif_tests.rs"]
mod tests;
