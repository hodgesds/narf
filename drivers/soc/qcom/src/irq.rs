//! Interrupt delivery for Qualcomm DT devices.
//!
//! Linux wires three kinds of interrupt into the remoteproc / WiFi
//! drivers, and each lands here:
//!
//! - **GIC SPIs** (`interrupts = <GIC_SPI n type>`; [`IrqSource::Gic`]
//!   carries INTID `n + 32`): [`GicSpi::bind`] reserves the dispatch
//!   slot (`intid & 0xFF`, what the aarch64 trap passes to `on_irq`),
//!   configures trigger/route/enable at the distributor
//!   (`narf_interrupts::aarch64::gic::configure_spi`) and exposes the
//!   line as an [`IrqLine`] (`wait_for_irq` with a deadline) or as a
//!   synchronous handler.
//! - **SMP2P virtual interrupts** (`interrupts-extended = <&wcss_smp2p_in
//!   bit 0>`): the edge's own GIC/IPCC interrupt runs
//!   `qcom_smp2p_intr` → [`Smp2p::handle_interrupt`], which needs SMEM
//!   access and allocates, so it is a threaded handler here too:
//!   [`smp2p_dispatch`] is one pass, [`service_smp2p`] the loop an async
//!   task runs on the edge's [`IrqLine`].
//! - **IPCC** (`qcom,ipcc`, SC7280 / WCN6750): the controller's own SPI
//!   is demultiplexed by [`ipcc_pending`] (`qcom_ipcc_irq_fn`: read
//!   `RECV_ID` until `IPCC_NO_PENDING_IRQ`, clearing each).
//!
//! [`Q6Irqs`] maps a resolved [`Q6Platform`]'s interrupts onto
//! [`Q6v5::signal`]: GIC lines through [`q6v5_gic_handler`] (atomics
//! only, safe in hard-IRQ context), SMP2P bits through
//! [`Q6Irqs::route_smp2p`]. Linux: `qcom_q6v5_init` (the five
//! `devm_request_threaded_irq` calls), `smp2p.c` irq domain,
//! `qcom-ipcc.c`.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::future::Future;

use crate::io::RegIo;
use crate::ipc::Kick;
use crate::platform::{IrqSource, Q6Platform};
use crate::q6v5::{Q6Event, Q6v5};
use crate::smem::Smem;
use crate::smp2p::{InHandle, Smp2p, Smp2pIrq};

/// An interrupt line a task can wait on.
pub trait IrqLine {
    /// Wait up to `ms`; `true` if the line fired.
    fn wait(&self, ms: u32) -> impl Future<Output = bool> + Send;
}

/// Why a DT interrupt could not be bound.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IrqBindError {
    /// Not an SPI, or past the distributor's `ITLinesNumber`.
    OutOfRange(u32),
    /// The dispatch slot `intid & 0xFF` is already taken.
    SlotTaken(u8),
    /// No GICv3 on this architecture.
    NotSupported,
}

/// DT `IRQ_TYPE_EDGE_RISING` (1) / `IRQ_TYPE_EDGE_BOTH` (3) in the
/// third GIC cell select edge; level otherwise.
pub const fn dt_flags_edge(flags: u32) -> bool {
    flags & 0x3 != 0
}

/// A bound GIC SPI.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct GicSpi {
    intid: u32,
    vector: u8,
}

impl GicSpi {
    /// `request_irq` for INTID `intid` (= DT SPI + 32).
    pub fn bind(intid: u32, edge: bool) -> Result<Self, IrqBindError> {
        #[cfg(target_arch = "aarch64")]
        {
            use narf_interrupts::aarch64::gic;
            if !(gic::SPI_BASE..gic::spi_limit()).contains(&intid) {
                return Err(IrqBindError::OutOfRange(intid));
            }
            let vector = gic::spi_vector(intid);
            narf_interrupts::vector::reserve(vector)
                .map_err(|_| IrqBindError::SlotTaken(vector))?;
            let trig = if edge {
                gic::SpiTrigger::Edge
            } else {
                gic::SpiTrigger::Level
            };
            if gic::configure_spi(intid, trig).is_err() {
                let _ = narf_interrupts::vector::free(vector);
                return Err(IrqBindError::OutOfRange(intid));
            }
            Ok(Self { intid, vector })
        }
        #[cfg(not(target_arch = "aarch64"))]
        {
            let _ = (intid, edge);
            Err(IrqBindError::NotSupported)
        }
    }

    pub fn intid(&self) -> u32 {
        self.intid
    }
    /// The `narf_interrupts` dispatch slot.
    pub fn vector(&self) -> u8 {
        self.vector
    }

    /// Chain a synchronous (hard-IRQ) handler on the line.
    pub fn install(&self, name: &'static str, cookie: u64, handler: narf_interrupts::SyncHandler) {
        narf_interrupts::install_handler_named(self.vector, name, cookie, handler);
    }

    /// `free_irq`: mask at the distributor, drop the handler, release
    /// the slot.
    pub fn release(self, name: &str, cookie: u64) {
        #[cfg(target_arch = "aarch64")]
        {
            let _ = narf_interrupts::aarch64::gic::mask_spi(self.intid);
        }
        narf_interrupts::remove_handler(self.vector, name, cookie);
        let _ = narf_interrupts::vector::free(self.vector);
    }
}

impl IrqLine for GicSpi {
    fn wait(&self, ms: u32) -> impl Future<Output = bool> + Send {
        let deadline = narf_time::Deadline::after_ms(ms as u64);
        let w = narf_interrupts::wait_for_irq_until(self.vector, deadline);
        async move { w.await.is_ok() }
    }
}

/// One Q6 interrupt routed to [`Q6v5::signal`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Q6Route {
    /// GIC INTID.
    Gic { intid: u32, event: Q6Event },
    /// SMP2P inbound `entry` bit `bit` on edge `edge`.
    Smp2p {
        edge: String,
        entry: String,
        bit: u32,
        event: Q6Event,
    },
}

/// The interrupt map `qcom_q6v5_init` builds: `wdog`, `fatal`, `ready`,
/// `handover`, `stop-ack`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Q6Irqs {
    pub routes: Vec<Q6Route>,
}

impl Q6Irqs {
    pub fn from_platform(p: &Q6Platform) -> Self {
        let routes = p
            .irqs
            .iter()
            .map(|(event, src)| match src {
                IrqSource::Gic(intid) => Q6Route::Gic {
                    intid: *intid,
                    event: *event,
                },
                IrqSource::Smp2p { edge, entry, bit } => Q6Route::Smp2p {
                    edge: edge.clone(),
                    entry: entry.clone(),
                    bit: *bit,
                    event: *event,
                },
            })
            .collect();
        Self { routes }
    }

    /// GIC INTIDs to bind, with their events.
    pub fn gic_lines(&self) -> Vec<(u32, Q6Event)> {
        self.routes
            .iter()
            .filter_map(|r| match r {
                Q6Route::Gic { intid, event } => Some((*intid, *event)),
                _ => None,
            })
            .collect()
    }

    /// Register this remote's inbound SMP2P entries on `edge` and enable
    /// each routed bit for rising edges (`IRQ_TYPE_EDGE_RISING`, the
    /// trigger every Q6 binding uses). Returns (handle, entry name).
    pub fn attach_smp2p<K: Kick>(
        &self,
        edge: &str,
        smp2p: &mut Smp2p<K>,
    ) -> Result<Vec<(InHandle, String)>, crate::smp2p::Smp2pError> {
        let mut handles: Vec<(InHandle, String)> = Vec::new();
        for r in &self.routes {
            let Q6Route::Smp2p {
                edge: e,
                entry,
                bit,
                ..
            } = r
            else {
                continue;
            };
            if e != edge {
                continue;
            }
            let h = match handles.iter().find(|(_, n)| n == entry) {
                Some((h, _)) => *h,
                None => {
                    let h = smp2p.add_inbound(entry)?;
                    handles.push((h, entry.clone()));
                    h
                }
            };
            smp2p.enable_irq(h, *bit, true, false)?;
        }
        Ok(handles)
    }

    /// Deliver what one `qcom_smp2p_intr` pass reported on `edge`: each
    /// rising edge of a routed (entry, bit) signals its event. Returns
    /// how many events were signalled.
    pub fn route_smp2p(
        &self,
        edge: &str,
        handles: &[(InHandle, String)],
        fired: &[Smp2pIrq],
        q6: &Q6v5,
    ) -> usize {
        let mut n = 0;
        for irq in fired.iter().filter(|i| i.high) {
            let Some((_, name)) = handles.iter().find(|(h, _)| *h == irq.entry) else {
                continue;
            };
            for r in &self.routes {
                if let Q6Route::Smp2p {
                    edge: e,
                    entry,
                    bit,
                    event,
                } = r
                {
                    if e == edge && entry == name && *bit == irq.bit {
                        q6.signal(*event);
                        n += 1;
                    }
                }
            }
        }
        n
    }

    /// Bind every GIC route and chain [`q6v5_gic_handler`] on it. The
    /// cookies are leaked (the remoteproc lives as long as the kernel).
    pub fn bind_gic(&self, q6: &'static Q6v5) -> Result<Vec<GicSpi>, IrqBindError> {
        let mut out = Vec::new();
        for (intid, event) in self.gic_lines() {
            // Q6 interrupts are IRQF_TRIGGER_RISING in qcom_q6v5_init.
            let line = match GicSpi::bind(intid, true) {
                Ok(l) => l,
                Err(e) => {
                    for l in out.drain(..) {
                        GicSpi::release(l, "q6v5", 0);
                    }
                    return Err(e);
                }
            };
            line.install("q6v5", q6v5_cookie(q6, event), q6v5_gic_handler);
            out.push(line);
        }
        Ok(out)
    }
}

struct Q6Cookie {
    q6: &'static Q6v5,
    event: Q6Event,
}

/// Cookie for [`q6v5_gic_handler`]: a leaked `(q6, event)` pair.
pub fn q6v5_cookie(q6: &'static Q6v5, event: Q6Event) -> u64 {
    Box::into_raw(Box::new(Q6Cookie { q6, event })) as u64
}

/// Hard-IRQ handler for a Q6 GIC line: `q6v5_{wdog,fatal,ready,
/// handover,stop}_interrupt` all reduce to [`Q6v5::signal`] (atomics).
pub fn q6v5_gic_handler(cookie: u64) -> narf_interrupts::IrqStatus {
    if cookie == 0 {
        return narf_interrupts::IrqStatus::None;
    }
    // SAFETY: non-zero cookies come only from `q6v5_cookie`, which leaks
    // the box for the life of the kernel.
    let c = unsafe { &*(cookie as *const Q6Cookie) };
    c.q6.signal(c.event);
    narf_interrupts::IrqStatus::Handled
}

/// One `qcom_smp2p_intr` pass routed into the Q6: returns the events
/// signalled.
pub fn smp2p_dispatch<K: Kick, R: RegIo>(
    smp2p: &mut Smp2p<K>,
    smem: &Smem<R>,
    edge: &str,
    handles: &[(InHandle, String)],
    routes: &Q6Irqs,
    q6: &Q6v5,
) -> usize {
    let fired = smp2p.handle_interrupt(smem);
    routes.route_smp2p(edge, handles, &fired, q6)
}

/// The threaded SMP2P handler as a task body: wait on the edge's line
/// (`poll_ms` at a time, so `keep_going` is checked even when quiet)
/// and dispatch each wake. Runs until `keep_going` returns false.
#[allow(clippy::too_many_arguments)]
pub async fn service_smp2p<K: Kick, R: RegIo, L: IrqLine>(
    smp2p: &mut Smp2p<K>,
    smem: &Smem<R>,
    line: &L,
    edge: &str,
    handles: &[(InHandle, String)],
    routes: &Q6Irqs,
    q6: &Q6v5,
    poll_ms: u32,
    keep_going: &mut dyn FnMut() -> bool,
) {
    while keep_going() {
        if line.wait(poll_ms).await {
            smp2p_dispatch(smp2p, smem, edge, handles, routes, q6);
        }
    }
}

pub const IPCC_REG_RECV_ID: u32 = 0x10;
pub const IPCC_REG_RECV_SIGNAL_ENABLE: u32 = 0x14;
pub const IPCC_REG_RECV_SIGNAL_DISABLE: u32 = 0x18;
pub const IPCC_REG_RECV_SIGNAL_CLEAR: u32 = 0x1c;
pub const IPCC_NO_PENDING_IRQ: u32 = u32::MAX;

/// `qcom_ipcc_irq_fn`: drain pending (client, signal) pairs, clearing
/// each. Bounded by `max` (a stuck `RECV_ID` cannot wedge the caller).
pub fn ipcc_pending<R: RegIo + ?Sized>(regs: &R, max: usize) -> Vec<(u16, u16)> {
    let mut out = Vec::new();
    for _ in 0..max {
        let id = regs.read32(IPCC_REG_RECV_ID);
        if id == IPCC_NO_PENDING_IRQ {
            break;
        }
        regs.write32(IPCC_REG_RECV_SIGNAL_CLEAR, id);
        out.push(((id >> 16) as u16, id as u16));
    }
    out
}

/// `qcom_ipcc_irq_unmask` / `_mask` for one (client, signal).
pub fn ipcc_set_enabled<R: RegIo + ?Sized>(regs: &R, client: u16, signal: u16, on: bool) {
    let id = ((client as u32) << 16) | signal as u32;
    let reg = if on {
        IPCC_REG_RECV_SIGNAL_ENABLE
    } else {
        IPCC_REG_RECV_SIGNAL_DISABLE
    };
    regs.write32(reg, id);
}
