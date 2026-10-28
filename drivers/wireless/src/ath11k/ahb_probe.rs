//! The AHB device bring-up, in Linux order.
//!
//! [`AhbPlatform::probe`] is every devicetree read the bring-up needs:
//! `ath11k_ahb_probe`'s resources ([`probe_resources`]), the
//! `qcom,rproc` remoteproc ([`AhbRemote`]) with its Q6 interrupt map
//! (`qcom_q6v5_init`: [`Q6Irqs`]), its SMP2P edges, its `glink-edge`
//! subnode ([`GlinkEdgeDt`], `qcom_add_glink_subdev`) and the WiFi
//! block's CE / DP lines ([`ahb_lines`]).
//!
//! [`bring_up`] runs the steps over an [`AhbBringUp`] implementation in
//! the order Linux does them:
//!
//! | step | Linux |
//! |---|---|
//! | [`BringUpStep::HalCeAlloc`] | `ath11k_ahb_probe`: `ath11k_hal_srng_init`, `ath11k_ce_alloc_pipes` ([`super::ahb_hif::ahb_ce_hif`]) |
//! | [`BringUpStep::QmiInit`] | `ath11k_core_init` → `ath11k_core_soc_create` → `ath11k_qmi_init_service` (the WLFW client waits for its server on QRTR) |
//! | [`BringUpStep::RprocIrqs`] | the remoteproc's probe: `qcom_q6v5_init` (Q6 GIC lines, SMP2P edges and their threaded handler) |
//! | [`BringUpStep::RprocBoot`] | `ath11k_hif_power_up` → `ath11k_ahb_power_up` → `rproc_boot` (load, start, wait for `ready`) |
//! | [`BringUpStep::GlinkStart`] | `rproc_start_subdevices` → the glink subdev: `qcom_glink_smem_register` on the edge, QRTR over it |
//! | [`BringUpStep::ConfigIrq`] | `ath11k_ahb_config_irq` (after `ath11k_core_init` returns) |
//! | [`BringUpStep::QmiReady`] | WLFW server arrival → `ath11k_qmi_event_server_arrive` … `ath11k_core_qmi_firmware_ready` |
//!
//! A failure after the remoteproc booted shuts it down
//! (`ath11k_core_deinit` → `ath11k_hif_power_down` → `rproc_shutdown`)
//! before the error is returned.

use alloc::string::String;
use alloc::vec::Vec;
use core::future::Future;

use narf_drivers_qcom_soc::dt::PlatformDevice;
use narf_drivers_qcom_soc::irq::Q6Irqs;
use narf_drivers_qcom_soc::platform::{self, GlinkEdgeDt, IrqSource};

use super::ahb::{probe_resources, AhbError, AhbRemote, AhbResources};
use super::ahb_hif::{ahb_lines, AhbLine};

/// Everything the bring-up reads from the devicetree.
#[derive(Clone, Debug)]
pub struct AhbPlatform {
    pub res: AhbResources,
    pub remote: AhbRemote,
    pub q6_irqs: Q6Irqs,
    pub glink: GlinkEdgeDt,
    pub lines: Vec<AhbLine>,
}

impl AhbPlatform {
    /// Resolve `node` (an `ath11k_ahb_of_match` device) and its
    /// remoteproc. Refuses a remoteproc whose loader does not match the
    /// chip (IPQ: host-reset WCSS; WCN6750: PAS) and a remoteproc
    /// without a `glink-edge` (QMI has no transport without it).
    pub fn probe(blob: &[u8], node: &PlatformDevice) -> Result<Self, AhbError> {
        let res = probe_resources(blob, node)?;
        let remote = AhbRemote::resolve(blob, &res)?;
        if !remote.loader_matches(res.chip) {
            return Err(AhbError::LoaderMismatch);
        }
        let q6_irqs = Q6Irqs::from_platform(&remote.platform);
        let glink = platform::glink_edge(blob, &remote.platform.node.path)?;
        let lines = ahb_lines(&res);
        Ok(Self {
            res,
            remote,
            q6_irqs,
            glink,
            lines,
        })
    }

    /// The SMP2P edges (DT paths) the bring-up services: those the Q6
    /// interrupts and the `stop` state use, plus `wlan-smp2p-out`'s.
    pub fn smp2p_edges(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        let mut add = |e: &str| {
            if !out.iter().any(|x| x == e) {
                out.push(String::from(e));
            }
        };
        for (_, src) in &self.remote.platform.irqs {
            if let IrqSource::Smp2p { edge, .. } = src {
                add(edge);
            }
        }
        if let Some((edge, _, _)) = &self.remote.platform.stop {
            add(edge);
        }
        if let Some((edge, _, _)) = &self.res.wlan_smp2p_out {
            add(edge);
        }
        out
    }
}

/// One bring-up step ([`bring_up`] order).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BringUpStep {
    HalCeAlloc,
    QmiInit,
    RprocIrqs,
    RprocBoot,
    GlinkStart,
    ConfigIrq,
    QmiReady,
}

/// The actions [`bring_up`] sequences. Production binds GIC lines through
/// `narf_drivers_qcom_soc::irq`, boots through `Q6Wcss` / `PasRproc` and
/// runs QRTR over `GlinkQrtr`; fixtures record.
pub trait AhbBringUp {
    fn hal_ce_alloc(&mut self, p: &AhbPlatform) -> Result<(), AhbError>;
    fn qmi_init_service(&mut self, p: &AhbPlatform) -> Result<(), AhbError>;
    fn rproc_irqs(&mut self, p: &AhbPlatform) -> Result<(), AhbError>;
    fn rproc_boot(&mut self, p: &AhbPlatform) -> impl Future<Output = Result<(), AhbError>>;
    fn glink_start(&mut self, p: &AhbPlatform) -> impl Future<Output = Result<(), AhbError>>;
    fn config_irq(&mut self, p: &AhbPlatform) -> Result<(), AhbError>;
    fn qmi_ready(&mut self, p: &AhbPlatform) -> impl Future<Output = Result<(), AhbError>>;
    /// `rproc_shutdown` (unwind after a booted remoteproc).
    fn rproc_shutdown(&mut self, p: &AhbPlatform) -> impl Future<Output = ()>;
}

/// `ath11k_ahb_probe` → `ath11k_core_init` → `rproc_boot` → QMI.
pub async fn bring_up<B: AhbBringUp>(
    p: &AhbPlatform,
    b: &mut B,
) -> Result<(), (BringUpStep, AhbError)> {
    use BringUpStep::*;
    b.hal_ce_alloc(p).map_err(|e| (HalCeAlloc, e))?;
    b.qmi_init_service(p).map_err(|e| (QmiInit, e))?;
    b.rproc_irqs(p).map_err(|e| (RprocIrqs, e))?;
    b.rproc_boot(p).await.map_err(|e| (RprocBoot, e))?;
    let r = async {
        b.glink_start(p).await.map_err(|e| (GlinkStart, e))?;
        b.config_irq(p).map_err(|e| (ConfigIrq, e))?;
        b.qmi_ready(p).await.map_err(|e| (QmiReady, e))
    }
    .await;
    if r.is_err() {
        b.rproc_shutdown(p).await;
    }
    r
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "ahb_probe_tests.rs"]
mod tests;
