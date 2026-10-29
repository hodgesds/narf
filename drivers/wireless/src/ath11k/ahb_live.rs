//! The production [`AhbBringUp`]: `ath11k_ahb_probe` → `ath11k_core_init`
//! → `rproc_boot` → QMI → `ath11k_core_qmi_firmware_ready` on a live SoC.
//!
//! [`LiveAhb`] runs every step of [`bring_up`] against the Qualcomm SoC
//! layer:
//!
//! | step | NARF | Linux |
//! |---|---|---|
//! | `hal_ce_alloc` | map `reg[0]` (+ the IPQ5018 CE remap) into [`AhbIo`], [`ahb_ce_hif`]; WCN6750 allocates the CE pipes only (its registers are the DEVICE_INFO BAR) | `ath11k_ahb_setup_resources`, `_ce_remap`, `ath11k_hal_srng_init`, `ath11k_ce_alloc_pipes` |
//! | `qmi_init_service` | [`WlfwConfig::ahb`] (the client runs once QRTR exists) | `ath11k_qmi_init_service` |
//! | `rproc_irqs` | SMEM + TCSR mutex, one [`Smp2p`] per edge with the Q6 inbound bits and the `stop` / `wlan-smp2p-out` outbound entries, the remoteproc object, its Q6 GIC lines | `qcom_smp2p_probe`, `qcom_q6v5_init` |
//! | `rproc_boot` | the MDT from the firmware registry into the `memory-region` carve-out, [`Q6Wcss::start`] (IPQ) or [`PasRproc::start`] (WCN6750) | `rproc_boot` → `q6v5_wcss_load` / `_start`, `adsp_load` / `adsp_start` |
//! | `glink_start` | [`GlinkSmem::register`] + [`Glink`] + [`GlinkQrtr`] on the `glink-edge` | `qcom_glink_smem_register`, `qcom_smd_qrtr_probe` |
//! | `config_irq` | [`AhbEnv::bind_lines`] (hardware: [`AhbIrq::bind_gic`]) | `ath11k_ahb_config_irq` |
//! | `qmi_ready` | [`Wlfw::run_to_fw_ready`]; WCN6750 maps the DEVICE_INFO BAR into [`AhbIo`] (static windows); [`Ath11kCore::qmi_firmware_ready`] with [`DpHooks`] | `ath11k_qmi_event_server_arrive` … `ath11k_qmi_request_device_info`, `ath11k_core_qmi_firmware_ready` → `ath11k_core_start` |
//!
//! SMP2P is a threaded interrupt in Linux; here every remoteproc wait
//! iteration (which sleeps between iterations through
//! [`narf_drivers_qcom_soc::io::Delay`]) runs one `qcom_smp2p_intr` pass
//! per edge and routes rising Q6 bits into [`Q6v5::signal`], so the
//! edge's interrupt parent (GIC or IPCC) does not matter during start /
//! stop. The GLINK edge interrupt is [`AhbEnv::glink_bus`]: a GIC SPI on
//! IPQ, the IPCC (client, signal) behind the IPCC block's SPI on WCN6750
//! ([`AhbGlinkBus`]).
//!
//! Everything platform-specific (mapping, carve-outs, firmware, SCM,
//! interrupt binding) comes from [`AhbEnv`]: [`NarfAhbEnv`] on hardware,
//! RAM fixtures in the smokes. Nothing here has run on Qualcomm silicon.

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_drivers_qcom_soc::gcc::Gcc;
use narf_drivers_qcom_soc::glink::{Glink, GlinkSmem, GLINK_FEATURE_INTENT_REUSE};
use narf_drivers_qcom_soc::hwlock::TcsrMutex;
use narf_drivers_qcom_soc::io::{Delay, RegIo};
use narf_drivers_qcom_soc::ipc::{ApcsIpc, DtKick, Ipcc};
use narf_drivers_qcom_soc::irq::Q6Irqs;
use narf_drivers_qcom_soc::mdt::SegmentSource;
use narf_drivers_qcom_soc::pas::PasRproc;
use narf_drivers_qcom_soc::platform::{self, GlinkEdgeDt, KickDt, RprocKind};
use narf_drivers_qcom_soc::q6v5::Q6v5;
use narf_drivers_qcom_soc::rproc::{Carveout, RprocError, StopState};
use narf_drivers_qcom_soc::scm::{Scm, ScmAlloc, SmcConduit};
use narf_drivers_qcom_soc::smem::Smem;
use narf_drivers_qcom_soc::smp2p::{InHandle, OutHandle, Smp2p};
use narf_drivers_qcom_soc::wcss::{Q6Wcss, WcssRegs, WcssResets};
use narf_lib::sync::IrqSafeSpinLock;

use super::ahb::{AhbError, AhbIo};
use super::ahb_hif::{ahb_ce_hif, AhbIrq, AhbLine};
use super::ahb_probe::{bring_up, AhbBringUp, AhbPlatform};
use super::ce::{Ce, CeMsi};
use super::core::{Ath11kCore, CeHif, CoreConfig};
use super::dp_ring::{Dp, DpHwParams, DpRingSizes};
use super::hal::TransportError;
use super::qrtr_glink::{GlinkBus, GlinkQrtr};
use super::runtime::DpHooks;
use super::wlfw::{DmaAllocator, FirmwareLoader, Wlfw, WlfwConfig};

const EINVAL: i32 = 22;
const ENOENT: i32 = 2;
const ENOMEM: i32 = 12;
const ENODEV: i32 = 19;
const EIO: i32 = 5;
const EBUSY: i32 = 16;
const ETIMEDOUT: i32 = 110;

/// The platform services [`LiveAhb`] needs. Mappings and carve-outs are
/// `'static`: the device owns them for the kernel's lifetime (Linux
/// `devm_ioremap` on a never-unbound platform device).
pub trait AhbEnv: Send + Sync + 'static {
    type Regs: RegIo + Send + Sync + 'static;
    type Delay: Delay + Send + Sync + 'static;
    type Smc: SmcConduit + Send + 'static;
    type ScmAlloc: ScmAlloc + Send + 'static;
    type Fw: FirmwareLoader + Send + 'static;
    type Dma: DmaAllocator + Send + 'static;
    type Bus: GlinkBus + Send + Sync + 'static;

    /// `devm_ioremap(phys, len)` (Device memory).
    fn map(&mut self, phys: u64, len: u64) -> Result<&'static Self::Regs, AhbError>;
    /// The remoteproc `memory-region` carve-out, mapped for loading.
    fn carveout(&mut self, phys: u64, len: u64) -> Result<&'static mut [u8], AhbError>;
    fn delay(&self) -> &'static Self::Delay;
    /// A firmware loader (`request_firmware`); `None` = no authority.
    fn firmware(&mut self) -> Option<Self::Fw>;
    /// The SCM conduit and its coherent allocator (PAS).
    fn scm(&mut self) -> (Self::Smc, Self::ScmAlloc);
    fn dma(&mut self) -> Self::Dma;
    /// `ath11k_ahb_config_irq`: bind the CE / DP lines.
    fn bind_lines(
        &mut self,
        lines: Vec<AhbLine>,
        params: super::ahb::AhbHwParams,
    ) -> Result<AhbIrq, AhbError>;
    /// `qcom_q6v5_init`'s GIC lines (the `wdog` SPI on every supported
    /// SoC), chained to `q6`.
    fn bind_q6_gic(&mut self, irqs: &Q6Irqs, q6: &'static Q6v5) -> Result<(), AhbError>;
    /// The `glink-edge` interrupt (`qcom_glink_smem_intr`).
    fn glink_bus(&mut self, blob: &[u8], edge: &GlinkEdgeDt) -> Result<Self::Bus, AhbError>;
    /// Monotonic milliseconds.
    fn clock(&self) -> fn() -> u64;
    /// Called on every remoteproc wait iteration before the SMP2P
    /// edges are serviced. Hardware: nothing; fixtures play the remote.
    fn remote_tick(&self) {}
}

/// The QRTR endpoint over the remoteproc's GLINK edge.
pub type AhbQrtr<E> = GlinkQrtr<
    GlinkSmem<&'static <E as AhbEnv>::Regs, DtKick<&'static <E as AhbEnv>::Regs>>,
    <E as AhbEnv>::Bus,
>;
/// The TCSR hardware mutex over the SMEM lock window.
type AhbLock<E> = TcsrMutex<&'static <E as AhbEnv>::Regs, &'static <E as AhbEnv>::Delay>;

/// The QMI session type over the GLINK QRTR endpoint.
pub type AhbWlfw<E> = Wlfw<
    GlinkQrtr<
        GlinkSmem<&'static <E as AhbEnv>::Regs, DtKick<&'static <E as AhbEnv>::Regs>>,
        <E as AhbEnv>::Bus,
    >,
    <E as AhbEnv>::Fw,
    <E as AhbEnv>::Dma,
>;
/// The ready core over the AHB HIF.
pub type AhbCore<E> = Ath11kCore<CeHif<AhbIo<&'static <E as AhbEnv>::Regs>, AhbIrq>, AhbWlfw<E>>;

/// One SMP2P edge the bring-up services.
struct LiveEdge<R: RegIo + 'static> {
    path: String,
    smp2p: Smp2p<DtKick<&'static R>>,
    /// The Q6's inbound entries on this edge.
    handles: Vec<(InHandle, String)>,
    /// The remoteproc `stop` state: (outbound entry, bit).
    stop: Option<(OutHandle, u32)>,
    /// `wlan-smp2p-out` (`smp2p_wow_exit`): (outbound entry, bit).
    wlan: Option<(OutHandle, u32)>,
}

enum Rproc<E: AhbEnv> {
    Wcss {
        w: Q6Wcss<&'static E::Regs>,
        /// aon, wcss, q6: (GCC, reset index).
        resets: [(Gcc<&'static E::Regs>, u32); 3],
    },
    Pas {
        p: PasRproc,
        scm: Scm<E::Smc>,
        alloc: E::ScmAlloc,
    },
}

/// The outbound `stop` bit over the edge lock.
struct EdgeStop<'a, R: RegIo + 'static> {
    edges: &'a IrqSafeSpinLock<Vec<LiveEdge<R>>>,
    smem: &'a Smem<&'static R>,
}

impl<R: RegIo + 'static> StopState for EdgeStop<'_, R> {
    fn set_stop(&self, on: bool) {
        let g = self.edges.lock();
        for e in g.iter() {
            if let Some((h, bit)) = e.stop {
                let b = 1 << bit;
                let _ = e.smp2p.update_bits(self.smem, h, b, if on { b } else { 0 });
            }
        }
    }
}

/// [`SegmentSource`] over a [`FirmwareLoader`] (`request_firmware` per
/// split segment).
struct FwSegments<'a, F: FirmwareLoader>(&'a IrqSafeSpinLock<F>);

impl<F: FirmwareLoader> SegmentSource for FwSegments<'_, F> {
    fn read_into(&self, name: &str, dst: &mut [u8]) -> Option<usize> {
        let b = self.0.lock().request(name).ok()?;
        let b = b.as_ref();
        let n = b.len().min(dst.len());
        dst[..n].copy_from_slice(&b[..n]);
        Some(n)
    }
}

/// What the bring-up ended with.
#[allow(missing_debug_implementations)]
pub enum LiveOutcome<E: AhbEnv> {
    /// `ath11k_core_qmi_firmware_ready` succeeded: the core and DP for
    /// the runtime.
    Ready(Box<AhbCore<E>>, Box<Dp>),
    /// The core failed after firmware got memory / rings: kept, never
    /// freed (as the PCI path does).
    Stranded(Box<AhbCore<E>>, Option<Box<Dp>>),
}

/// The live [`AhbBringUp`].
#[allow(missing_debug_implementations)]
pub struct LiveAhb<E: AhbEnv> {
    pub env: E,
    blob: &'static [u8],
    io: Option<AhbIo<&'static E::Regs>>,
    /// WCN6750: the CE pipes before the DEVICE_INFO BAR is known.
    ce: Option<Ce>,
    hif: Option<CeHif<AhbIo<&'static E::Regs>, AhbIrq>>,
    cfg: Option<WlfwConfig>,
    smem: Option<Smem<&'static E::Regs>>,
    lock: Option<AhbLock<E>>,
    edges: IrqSafeSpinLock<Vec<LiveEdge<E::Regs>>>,
    rproc: Option<Rproc<E>>,
    qrtr: Option<AhbQrtr<E>>,
    irq: Option<AhbIrq>,
    pub outcome: Option<LiveOutcome<E>>,
    /// The last core / WLFW failure, for the bring-up log.
    pub failure: Option<TransportError>,
}

fn failed(errno: i32) -> AhbError {
    AhbError::Failed(-errno.abs())
}

fn rproc_errno(e: &RprocError) -> AhbError {
    failed(match e {
        RprocError::NoFirmware => ENOENT,
        RprocError::Firmware(_) | RprocError::BadState(_) => EINVAL,
        RprocError::Handshake(_) => ETIMEDOUT,
        _ => EIO,
    })
}

impl<E: AhbEnv> LiveAhb<E> {
    pub fn new(env: E, blob: &'static [u8]) -> Self {
        Self {
            env,
            blob,
            io: None,
            ce: None,
            hif: None,
            cfg: None,
            smem: None,
            lock: None,
            edges: IrqSafeSpinLock::new(Vec::new()),
            rproc: None,
            qrtr: None,
            irq: None,
            outcome: None,
            failure: None,
        }
    }

    /// The HIF assembled so far (IPQ: after `hal_ce_alloc`; WCN6750:
    /// after `qmi_ready` mapped the DEVICE_INFO BAR).
    pub fn hif(&self) -> Option<&CeHif<AhbIo<&'static E::Regs>, AhbIrq>> {
        self.hif.as_ref()
    }
    pub fn is_booted(&self) -> bool {
        matches!(
            &self.rproc,
            Some(Rproc::Wcss { w, .. }) if w.state() == narf_drivers_qcom_soc::rproc::RprocState::Running
        ) || matches!(
            &self.rproc,
            Some(Rproc::Pas { p, .. }) if p.state() == narf_drivers_qcom_soc::rproc::RprocState::Running
        )
    }
    pub fn rproc_state(&self) -> Option<narf_drivers_qcom_soc::rproc::RprocState> {
        match &self.rproc {
            Some(Rproc::Wcss { w, .. }) => Some(w.state()),
            Some(Rproc::Pas { p, .. }) => Some(p.state()),
            None => None,
        }
    }
    pub fn qrtr_open(&self) -> bool {
        self.qrtr.as_ref().is_some_and(|q| q.lcid().is_some())
    }
    pub fn glink_negotiated(&self) -> bool {
        self.qrtr.as_ref().is_some_and(|q| q.glink.negotiated())
    }
    /// The `wlan-smp2p-out` value (`ath11k_ahb_hif_{suspend,resume}`
    /// writes it): `None` without that state.
    pub fn set_wlan_smp2p(&self, value: u32) -> Option<()> {
        let smem = self.smem.as_ref()?;
        let g = self.edges.lock();
        let e = g.iter().find(|e| e.wlan.is_some())?;
        let (h, _) = e.wlan?;
        e.smp2p.update_bits(smem, h, u32::MAX, value).ok()
    }

    fn kick(&mut self, k: &KickDt) -> Result<DtKick<&'static E::Regs>, AhbError> {
        Ok(match *k {
            KickDt::Apcs {
                base,
                offset,
                channel,
            } => DtKick::Apcs(ApcsIpc::new(self.env.map(base.0, base.1)?, offset, channel)),
            KickDt::Ipcc {
                base,
                client,
                signal,
            } => DtKick::Ipcc(Ipcc::new(self.env.map(base.0, base.1)?, client, signal)),
        })
    }

    fn smem_lock(
        &mut self,
        p: &AhbPlatform,
    ) -> Result<(Smem<&'static E::Regs>, AhbLock<E>), AhbError> {
        let s = p.remote.platform.smem.clone().ok_or(failed(ENODEV))?;
        let mem = self.env.map(s.region.0, s.region.1)?;
        let smem = Smem::probe(mem, s.region.1 as u32).map_err(|_| failed(ENODEV))?;
        let lregs = self.env.map(s.hwlock_base.0, s.hwlock_base.1)?;
        let lock =
            TcsrMutex::new(lregs, self.env.delay(), s.hwlock_id).map_err(|_| failed(EINVAL))?;
        Ok((smem, lock))
    }

    /// The core half of `ath11k_core_qmi_firmware_ready` once WLFW
    /// reported FW_READY.
    async fn core_ready(&mut self, p: &AhbPlatform, w: AhbWlfw<E>) -> Result<(), AhbError> {
        let res = &p.res;
        let hw = res.params.hw_params(res.chip.hw_rev());
        if res.params.hybrid_bus_type && self.hif.is_none() {
            // ath11k_qmi_request_device_info: ab->mem = the BAR.
            let (addr, size) = w.device_bar().ok_or(failed(ENODEV))?;
            let mem = self.env.map(addr, size as u64)?;
            let io = AhbIo {
                mem,
                ce: None,
                window: Some(res.params.regs),
            };
            let ce = self.ce.take().ok_or(failed(EINVAL))?;
            let irq = self.irq.clone().ok_or(failed(EINVAL))?;
            self.hif = Some(CeHif {
                ce,
                io,
                irq,
                on_start: || {},
                clock: self.env.clock(),
            });
        }
        let hif = self.hif.take().ok_or(failed(EINVAL))?;
        let Some(cfg) = CoreConfig::for_hw(&hw) else {
            return Err(failed(EINVAL));
        };
        let mut core = match Ath11kCore::new(hif, w, cfg) {
            Ok(c) => c,
            Err((e, hif, _w)) => {
                self.hif = Some(hif);
                self.failure = Some(e);
                return Err(failed(e.errno));
            }
        };
        let msi = res.msi.as_ref().map(|m| CeMsi {
            addr: m.addr,
            ep_base_data: m.ep_base_data,
            config: hw.msi,
        });
        let mut hooks = DpHooks::new(
            DpHwParams::for_rev(hw.hw_rev),
            hw.hw_rev as u32,
            DpRingSizes::LINUX,
            msi,
        );
        let r = core.qmi_firmware_ready(&mut hooks).await;
        let dp = hooks.dp.take().map(Box::new);
        match (r, dp) {
            (Ok(()), Some(dp)) => {
                self.outcome = Some(LiveOutcome::Ready(Box::new(core), dp));
                Ok(())
            }
            (r, dp) => {
                let e = r.err().unwrap_or(TransportError::new(0, 0, ENODEV));
                self.failure = Some(e);
                self.outcome = Some(LiveOutcome::Stranded(Box::new(core), dp));
                Err(failed(e.errno))
            }
        }
    }
}

impl<E: AhbEnv> AhbBringUp for LiveAhb<E> {
    fn hal_ce_alloc(&mut self, p: &AhbPlatform) -> Result<(), AhbError> {
        let res = &p.res;
        let hw = res.params.hw_params(res.chip.hw_rev());
        if res.params.hybrid_bus_type {
            // WCN6750: no register window until DEVICE_INFO.
            let msi = res.msi.as_ref().ok_or(failed(EINVAL))?;
            let ce = Ce::alloc(
                &hw,
                CeMsi {
                    addr: msi.addr,
                    ep_base_data: msi.ep_base_data,
                    config: hw.msi,
                },
                self.env.clock(),
            )
            .map_err(|e| failed(e.errno))?;
            self.ce = Some(ce);
            return Ok(());
        }
        let (base, len) = res.mem.ok_or(failed(EINVAL))?;
        let mem = self.env.map(base, len)?;
        let ce = match res.params.ce_remap {
            Some(r) => Some(self.env.map(r.base as u64, r.size as u64)?),
            None => None,
        };
        let io = AhbIo {
            mem,
            ce,
            window: None,
        };
        // Interrupt lines are bound in config_irq; until then the HIF
        // carries an unbound source.
        let irq = AhbIrq::new(Vec::new(), res.params, |_, _| {});
        let hif = ahb_ce_hif(res, io, irq, self.env.clock()).map_err(|e| failed(e.errno))?;
        self.hif = Some(hif);
        Ok(())
    }

    fn qmi_init_service(&mut self, p: &AhbPlatform) -> Result<(), AhbError> {
        let res = &p.res;
        // dev_name(): "<unit-address>.<node name>", e.g. c000000.wifi.
        let seg = res.node.path.rsplit('/').next().unwrap_or("wifi");
        let dev_name = match seg.split_once('@') {
            Some((name, unit)) => alloc::format!("{}.{}", unit, name),
            None => String::from(seg),
        };
        let host_ddr = res.node.memory_region(0).ok();
        self.cfg = Some(WlfwConfig::ahb(res.chip, dev_name, host_ddr));
        Ok(())
    }

    async fn rproc_irqs(&mut self, p: &AhbPlatform) -> Result<(), AhbError> {
        let (smem, lock) = self.smem_lock(p)?;
        let mut edges = Vec::new();
        for path in p.smp2p_edges() {
            let dt = match p.remote.platform.edge(&path) {
                Some(d) => d.clone(),
                None => platform::smp2p_edge(self.blob, &path)?,
            };
            let kick = self.kick(&dt.kick)?;
            let mut smp2p = Smp2p::new(&smem, &lock, dt.cfg, kick)
                .await
                .map_err(|_| failed(EIO))?;
            let handles = p
                .q6_irqs
                .attach_smp2p(&path, &mut smp2p)
                .map_err(|_| failed(EINVAL))?;
            let stop = match &p.remote.platform.stop {
                Some((e, entry, bit)) if *e == path => Some((
                    smp2p
                        .add_outbound(&smem, entry)
                        .map_err(|_| failed(EINVAL))?,
                    *bit,
                )),
                _ => None,
            };
            let wlan = match &p.res.wlan_smp2p_out {
                Some((e, entry, bit)) if *e == path => {
                    let h = match &p.remote.platform.stop {
                        Some((se, sentry, _)) if *se == path && sentry == entry => {
                            stop.map(|s| s.0)
                        }
                        _ => None,
                    };
                    let h = match h {
                        Some(h) => h,
                        None => smp2p
                            .add_outbound(&smem, entry)
                            .map_err(|_| failed(EINVAL))?,
                    };
                    Some((h, *bit))
                }
                _ => None,
            };
            edges.push(LiveEdge {
                path,
                smp2p,
                handles,
                stop,
                wlan,
            });
        }
        *self.edges.lock() = edges;
        self.smem = Some(smem);
        self.lock = Some(lock);
        let plat = &p.remote.platform;
        let rproc = match plat.kind {
            RprocKind::Wcss => {
                let halt = plat.halt.clone().ok_or(failed(ENODEV))?;
                let rmb = plat.rmb.ok_or(failed(ENODEV))?;
                let regs = WcssRegs {
                    qdsp6: self.env.map(plat.qdsp6.0, plat.qdsp6.1)?,
                    rmb: self.env.map(rmb.0, rmb.1)?,
                    tcsr: self.env.map(halt.tcsr.0, halt.tcsr.1)?,
                    halt_q6: halt.q6,
                    halt_wcss: halt.wcss,
                    halt_nc: halt.nc,
                };
                let mut line = |name: &str| -> Result<(Gcc<&'static E::Regs>, u32), AhbError> {
                    let r = plat.reset(name).ok_or(failed(ENODEV))?;
                    let g = Gcc::new(self.env.map(r.gcc_base.0, r.gcc_base.1)?, r.gcc);
                    Ok((g, r.index))
                };
                let resets = [
                    line("wcss_aon_reset")?,
                    line("wcss_reset")?,
                    line("wcss_q6_reset")?,
                ];
                Rproc::Wcss {
                    w: Q6Wcss::new(regs),
                    resets,
                }
            }
            RprocKind::Pas { pas_id } => {
                let (smc, alloc) = self.env.scm();
                Rproc::Pas {
                    p: PasRproc::new(pas_id),
                    scm: Scm::new(smc),
                    alloc,
                }
            }
        };
        let q6 = match &rproc {
            Rproc::Wcss { w, .. } => w.q6,
            Rproc::Pas { p, .. } => p.q6,
        };
        self.env.bind_q6_gic(&p.q6_irqs, q6)?;
        self.rproc = Some(rproc);
        Ok(())
    }

    async fn rproc_boot(&mut self, p: &AhbPlatform) -> Result<(), AhbError> {
        let plat = &p.remote.platform;
        let fw = self.env.firmware().ok_or(failed(ENOENT))?;
        let fw = IrqSafeSpinLock::new(fw);
        let mdt = fw.lock().request(plat.firmware).map_err(failed)?;
        let mdt: Vec<u8> = Vec::from(mdt.as_ref());
        let mem = self.env.carveout(plat.carveout.0, plat.carveout.1)?;
        let mut co = Carveout {
            phys: plat.carveout.0,
            mem,
        };
        let segs = FwSegments(&fw);
        let delay = self.env.delay();
        let Self {
            env,
            edges,
            smem,
            rproc,
            ..
        } = self;
        let (env, edges) = (&*env, &*edges);
        let smem = smem.as_ref().ok_or(failed(EINVAL))?;
        let routes = &p.q6_irqs;
        let mut pump = |q6: &Q6v5| {
            env.remote_tick();
            for e in edges.lock().iter_mut() {
                let fired = e.smp2p.handle_interrupt(smem);
                routes.route_smp2p(&e.path, &e.handles, &fired, q6);
            }
        };
        let r = match rproc.as_mut().ok_or(failed(EINVAL))? {
            Rproc::Wcss { w, resets } => {
                w.load(plat.firmware, &mdt, &segs, &mut co)
                    .map_err(|e| rproc_errno(&e))?;
                let aon = resets[0]
                    .0
                    .reset_line(resets[0].1)
                    .map_err(|_| failed(EINVAL))?;
                let wr = resets[1]
                    .0
                    .reset_line(resets[1].1)
                    .map_err(|_| failed(EINVAL))?;
                let q6r = resets[2]
                    .0
                    .reset_line(resets[2].1)
                    .map_err(|_| failed(EINVAL))?;
                let rs = WcssResets {
                    aon: &aon,
                    wcss: &wr,
                    q6: &q6r,
                };
                w.start(rs, delay, &mut pump).await
            }
            Rproc::Pas { p: pas, scm, alloc } => {
                pas.start(
                    scm,
                    alloc,
                    plat.firmware,
                    &mdt,
                    &segs,
                    &mut co,
                    delay,
                    &mut pump,
                )
                .await
            }
        };
        r.map_err(|e| rproc_errno(&e))
    }

    async fn glink_start(&mut self, p: &AhbPlatform) -> Result<(), AhbError> {
        let (smem, _) = self.smem_lock(p)?;
        let kick = self.kick(&p.glink.kick)?;
        let lock = self.lock.as_ref().ok_or(failed(EINVAL))?;
        let pipe = GlinkSmem::register(smem, lock, p.glink.remote_pid, kick)
            .await
            .map_err(|_| failed(ENOMEM))?;
        let bus = self.env.glink_bus(self.blob, &p.glink)?;
        let glink = Glink::new(pipe, GLINK_FEATURE_INTENT_REUSE);
        self.qrtr = Some(GlinkQrtr::new(glink, bus));
        Ok(())
    }

    fn config_irq(&mut self, p: &AhbPlatform) -> Result<(), AhbError> {
        let irq = self.env.bind_lines(p.lines.clone(), p.res.params)?;
        if let Some(h) = self.hif.as_mut() {
            h.irq = irq.clone();
        }
        self.irq = Some(irq);
        Ok(())
    }

    async fn qmi_ready(&mut self, p: &AhbPlatform) -> Result<(), AhbError> {
        let qrtr = self.qrtr.take().ok_or(failed(EINVAL))?;
        let cfg = self.cfg.take().ok_or(failed(EINVAL))?;
        let fw = self.env.firmware().ok_or(failed(ENOENT))?;
        let dma = self.env.dma();
        let mut w = Wlfw::new(qrtr, fw, dma, cfg).map_err(|e| {
            self.failure = Some(TransportError::new(e.step, e.detail, e.errno));
            failed(e.errno)
        })?;
        if let Err(e) = w.run_to_fw_ready().await {
            self.failure = Some(TransportError::new(e.step, e.detail, e.errno));
            return Err(failed(e.errno));
        }
        self.core_ready(p, w).await
    }

    async fn rproc_shutdown(&mut self, p: &AhbPlatform) {
        let delay = self.env.delay();
        let Self {
            env,
            edges,
            smem,
            rproc,
            ..
        } = self;
        let (env, edges) = (&*env, &*edges);
        let (Some(smem), Some(rproc)) = (smem.as_ref(), rproc.as_mut()) else {
            return;
        };
        let stop = EdgeStop { edges, smem };
        let routes = &p.q6_irqs;
        let mut pump = |q6: &Q6v5| {
            env.remote_tick();
            for e in edges.lock().iter_mut() {
                let fired = e.smp2p.handle_interrupt(smem);
                routes.route_smp2p(&e.path, &e.handles, &fired, q6);
            }
        };
        // `rproc_shutdown` → `q6v5_wcss_stop` / `adsp_stop`; a failed
        // stop leaves the remoteproc for recovery, as Linux does.
        match rproc {
            Rproc::Wcss { w, resets } => {
                let (Ok(aon), Ok(wr), Ok(q6r)) = (
                    resets[0].0.reset_line(resets[0].1),
                    resets[1].0.reset_line(resets[1].1),
                    resets[2].0.reset_line(resets[2].1),
                ) else {
                    return;
                };
                let rs = WcssResets {
                    aon: &aon,
                    wcss: &wr,
                    q6: &q6r,
                };
                let _ = w.stop(rs, &stop, delay, &mut pump).await;
            }
            Rproc::Pas { p: pas, scm, .. } => {
                let _ = pas.stop(scm, &stop, delay, &mut pump).await;
            }
        }
    }
}

// ── hardware environment ───────────────────────────────────────────

/// The `glink-edge` interrupt on hardware: a GIC SPI (IPQ: `GIC_SPI n
/// IRQ_TYPE_EDGE_RISING`), or an IPCC (client, signal) behind the IPCC
/// block's own SPI (WCN6750: `<&ipcc IPCC_CLIENT_WPSS
/// IPCC_MPROC_SIGNAL_GLINK_QMP IRQ_TYPE_EDGE_RISING>`), whose pending
/// signals each wake drains and clears (`qcom_ipcc_irq_fn`).
#[allow(missing_debug_implementations)]
pub enum AhbGlinkBus {
    Gic(narf_drivers_qcom_soc::irq::GicSpi),
    Ipcc {
        line: narf_drivers_qcom_soc::irq::GicSpi,
        regs: &'static narf_drivers_qcom_soc::io::MmioRegs,
    },
}

impl GlinkBus for AhbGlinkBus {
    fn wait_irq(&self, ms: u32) -> impl core::future::Future<Output = ()> + Send {
        use narf_drivers_qcom_soc::irq::IrqLine;
        let (w, ipcc) = match self {
            AhbGlinkBus::Gic(l) => (l.wait(ms), None),
            AhbGlinkBus::Ipcc { line, regs } => (line.wait(ms), Some(*regs)),
        };
        async move {
            if w.await {
                if let Some(r) = ipcc {
                    let _ = narf_drivers_qcom_soc::irq::ipcc_pending(r, 32);
                }
            }
        }
    }
    fn now_ms(&self) -> u64 {
        super::ce::monotonic_ms()
    }
}

/// [`AhbEnv`] on a Qualcomm SoC: `ioremap` windows (cached per
/// resource), write-combined carve-outs, the firmware registry, SMCCC,
/// 32-bit coherent DMA and GIC lines.
#[derive(Debug, Default)]
pub struct NarfAhbEnv {
    maps: BTreeMap<(u64, u64), &'static narf_drivers_qcom_soc::io::MmioRegs>,
}

static NARF_DELAY: narf_drivers_qcom_soc::io::NarfDelay = narf_drivers_qcom_soc::io::NarfDelay;

impl AhbEnv for NarfAhbEnv {
    type Regs = narf_drivers_qcom_soc::io::MmioRegs;
    type Delay = narf_drivers_qcom_soc::io::NarfDelay;
    type Smc = narf_drivers_qcom_soc::scm::ArchSmc;
    type ScmAlloc = narf_drivers_qcom_soc::scm::CoherentAlloc;
    type Fw = super::wlfw::NarfFirmware;
    type Dma = super::wlfw::Dma32;
    type Bus = AhbGlinkBus;

    fn map(&mut self, phys: u64, len: u64) -> Result<&'static Self::Regs, AhbError> {
        if let Some(r) = self.maps.get(&(phys, len)) {
            return Ok(r);
        }
        let r = narf_drivers_qcom_soc::io::MmioRegs::map(phys, len).map_err(|_| failed(ENOMEM))?;
        let r: &'static _ = Box::leak(Box::new(r));
        self.maps.insert((phys, len), r);
        Ok(r)
    }
    fn carveout(&mut self, phys: u64, len: u64) -> Result<&'static mut [u8], AhbError> {
        let n = usize::try_from(len).map_err(|_| failed(EINVAL))?;
        // SAFETY: `phys..phys+len` is the remoteproc's DT `memory-region`
        // (reserved RAM no other owner uses); ioremap installs a fresh
        // write-combined mapping that is never torn down, so the slice
        // never dangles and nothing else aliases it.
        let m = unsafe {
            narf_memory::ioremap::ioremap(
                phys,
                len,
                narf_memory::ioremap::MmioAttrs::WriteCombining,
            )
        }
        .map_err(|_| failed(ENOMEM))?;
        // SAFETY: see above; `n` bytes are mapped at `m.va()`.
        Ok(unsafe { core::slice::from_raw_parts_mut(m.va() as *mut u8, n) })
    }
    fn delay(&self) -> &'static Self::Delay {
        &NARF_DELAY
    }
    fn firmware(&mut self) -> Option<Self::Fw> {
        super::wlfw::NarfFirmware::new()
    }
    fn scm(&mut self) -> (Self::Smc, Self::ScmAlloc) {
        (
            narf_drivers_qcom_soc::scm::ArchSmc,
            narf_drivers_qcom_soc::scm::CoherentAlloc,
        )
    }
    fn dma(&mut self) -> Self::Dma {
        super::wlfw::Dma32
    }
    fn bind_lines(
        &mut self,
        lines: Vec<AhbLine>,
        params: super::ahb::AhbHwParams,
    ) -> Result<AhbIrq, AhbError> {
        AhbIrq::bind_gic(lines, params).map_err(|_| failed(EBUSY))
    }
    fn bind_q6_gic(&mut self, irqs: &Q6Irqs, q6: &'static Q6v5) -> Result<(), AhbError> {
        // The lines stay bound for the remoteproc's lifetime.
        let lines = irqs.bind_gic(q6).map_err(|_| failed(EBUSY))?;
        core::mem::forget(lines);
        Ok(())
    }
    fn glink_bus(&mut self, blob: &[u8], edge: &GlinkEdgeDt) -> Result<Self::Bus, AhbError> {
        use narf_drivers_qcom_soc::irq::{dt_flags_edge, ipcc_set_enabled, GicSpi};
        let parent = narf_drivers_qcom_soc::dt::find_phandle(blob, edge.irq.parent).ok();
        let ipcc = parent
            .as_ref()
            .filter(|n| n.compatible.iter().any(|c| c == "qcom,ipcc"));
        match ipcc {
            Some(n) => {
                let (base, len) = n.reg(0)?;
                let regs = self.map(base, len)?;
                let spec = n.irqs.first().ok_or(AhbError::MissingIrq("ipcc"))?;
                let hw = spec.gic_hwirq().ok_or(AhbError::MissingIrq("ipcc"))?;
                let edge_trig = spec.cells.get(2).is_some_and(|f| dt_flags_edge(*f));
                let line = GicSpi::bind(hw, edge_trig).map_err(|_| failed(EBUSY))?;
                let (client, signal) = match edge.irq.cells.as_slice() {
                    [c, s, ..] => (*c as u16, *s as u16),
                    _ => return Err(AhbError::MissingIrq("glink ipcc")),
                };
                ipcc_set_enabled(regs, client, signal, true);
                Ok(AhbGlinkBus::Ipcc { line, regs })
            }
            None => {
                let hw = edge
                    .irq
                    .gic_hwirq()
                    .ok_or(AhbError::MissingIrq("glink-edge"))?;
                let edge_trig = edge.irq.cells.get(2).is_some_and(|f| dt_flags_edge(*f));
                let line = GicSpi::bind(hw, edge_trig).map_err(|_| failed(EBUSY))?;
                Ok(AhbGlinkBus::Gic(line))
            }
        }
    }
    fn clock(&self) -> fn() -> u64 {
        super::ce::monotonic_ms
    }
}

/// The hardware runtime of an AHB part.
pub type NarfAhbShared = super::runtime::Shared<
    AhbIo<&'static narf_drivers_qcom_soc::io::MmioRegs>,
    AhbIrq,
    AhbWlfw<NarfAhbEnv>,
>;

/// Runtimes handed over by finished bring-ups.
static AHB_RUNTIME: IrqSafeSpinLock<Vec<Arc<NarfAhbShared>>> = IrqSafeSpinLock::new(Vec::new());
/// Bring-ups that failed after the firmware was given memory (kept).
static AHB_STRANDED: IrqSafeSpinLock<Vec<Box<LiveAhb<NarfAhbEnv>>>> =
    IrqSafeSpinLock::new(Vec::new());

/// The runtimes AHB bring-ups produced.
pub fn ahb_runtimes() -> Vec<Arc<NarfAhbShared>> {
    AHB_RUNTIME.lock().clone()
}

fn log(args: core::fmt::Arguments<'_>) {
    use core::fmt::Write as _;
    let _ = writeln!(narf_console::Writer, "  ath11k_ahb: {}", args);
}

/// The WLFW task: [`bring_up`] over [`LiveAhb`], then the ready core
/// to the runtime ([`super::runtime::start_ahb`]).
pub async fn bring_up_task(blob: &'static [u8], p: AhbPlatform) {
    let mut live = Box::new(LiveAhb::new(NarfAhbEnv::default(), blob));
    let r = bring_up(&p, &mut *live).await;
    match (r, live.outcome.take()) {
        (Ok(()), Some(LiveOutcome::Ready(core, dp))) => {
            let (shared, r) = super::runtime::start_ahb(*core, *dp);
            match r {
                Ok(m) => log(format_args!(
                    "{}: runtime up, MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    p.res.node.path, m[0], m[1], m[2], m[3], m[4], m[5]
                )),
                Err(e) => e.report("ath11k_ahb mac register"),
            }
            AHB_RUNTIME.lock().push(shared);
        }
        (r, outcome) => {
            if let Err((step, e)) = r {
                log(format_args!(
                    "{}: {:?} failed: {:?}",
                    p.res.node.path, step, e
                ));
            }
            if let Some(f) = live.failure {
                f.report("ath11k_ahb");
            }
            live.outcome = outcome;
            AHB_STRANDED.lock().push(live);
        }
    }
}

/// Spawn [`bring_up_task`] for a probed node.
pub fn spawn_bring_up(blob: &'static [u8], p: AhbPlatform) {
    narf_scheduler::spawn(bring_up_task(blob, p));
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "ahb_live_tests.rs"]
mod tests;
