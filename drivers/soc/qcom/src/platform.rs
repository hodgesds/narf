//! Devicetree → remoteproc resource resolution.
//!
//! Resolves everything a Q6 remoteproc node references into plain
//! physical addresses and indices, the way Linux probe code does with
//! `platform_get_resource_byname`, `syscon_node_to_regmap`,
//! `devm_reset_control_get`, `qcom_smem_state_get` and the SMP2P/SMEM
//! drivers' own probes:
//!
//! - the remoteproc node (`qcom,ipq6018-wcss-pil` / `qcom,ipq8074-wcss-pil`
//!   / `qcom,ipq5018-wcss-pil` → [`RprocKind::Wcss`];
//!   `qcom,sc7280-wpss-pas` → [`RprocKind::Pas`]);
//! - its `memory-region` carve-out, `qdsp6`/`rmb` windows and
//!   `qcom,halt-regs` TCSR syscon;
//! - `resets` against the GCC tables in [`crate::gcc`];
//! - each interrupt as a GIC SPI or an SMP2P inbound bit, and the
//!   `stop` state as an SMP2P outbound entry + bit;
//! - the SMP2P edge (`qcom,smem`, pids, kick mailbox, its IPC interrupt);
//! - the SMEM region and its TCSR-mutex hwlock;
//! - for PAS, the proxy power resources (`power-domains` on the RPMh
//!   RSC, the `xo` RPMh clock, `qcom,cmd-db`, `qcom,qmp`).

use alloc::string::String;
use alloc::vec::Vec;

use crate::dt::{self, DtError, IrqSpec, PlatformDevice};
use crate::gcc::{self, GccDesc};
use crate::q6v5::Q6Event;
use crate::smp2p::Smp2pConfig;

/// Which loader drives the node.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RprocKind {
    /// `qcom_q6v5_wcss.c` host-driven reset (no PAS).
    Wcss,
    /// `qcom_q6v5_pas.c` TrustZone authenticated boot.
    Pas { pas_id: u32 },
}

/// Supported remoteproc compatibles → (kind, firmware, crash-reason item).
pub const RPROC_MATCH: &[(&str, RprocKind, &str, u32)] = &[
    (
        "qcom,ipq8074-wcss-pil",
        RprocKind::Wcss,
        crate::wcss::IPQ8074_FIRMWARE,
        crate::wcss::WCSS_CRASH_REASON,
    ),
    // ipq6018.dtsi binds the same IPQ8074 ops; Linux v6.12's match table
    // lacks the string, NARF accepts it with the IPQ8074 data.
    (
        "qcom,ipq6018-wcss-pil",
        RprocKind::Wcss,
        crate::wcss::IPQ8074_FIRMWARE,
        crate::wcss::WCSS_CRASH_REASON,
    ),
    (
        "qcom,sc7280-wpss-pas",
        RprocKind::Pas {
            pas_id: crate::pas::WPSS_PAS_ID,
        },
        crate::pas::WPSS_FIRMWARE,
        crate::pas::WPSS_CRASH_REASON,
    ),
];

/// A mailbox kick target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KickDt {
    /// APCS global IPC register: window, register offset, channel bit.
    Apcs {
        base: (u64, u64),
        offset: u32,
        channel: u32,
    },
    /// IPCC: window, client, signal.
    Ipcc {
        base: (u64, u64),
        client: u16,
        signal: u16,
    },
}

/// One SMP2P edge node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Smp2pDt {
    pub path: String,
    pub cfg: Smp2pConfig,
    pub kick: KickDt,
    /// The edge's incoming IPC interrupt.
    pub irq: IrqSpec,
}

/// Where a remoteproc interrupt comes from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IrqSource {
    /// A GIC interrupt (`hwirq` = SPI + 32).
    Gic(u32),
    /// SMP2P inbound entry `entry` on edge `edge`, bit `bit`.
    Smp2p {
        edge: String,
        entry: String,
        bit: u32,
    },
}

/// A resolved reset line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResetDt {
    pub name: String,
    pub gcc_base: (u64, u64),
    pub gcc: &'static GccDesc,
    pub index: u32,
}

/// SMEM region + hwlock.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmemDt {
    pub region: (u64, u64),
    pub hwlock_base: (u64, u64),
    pub hwlock_id: u32,
}

/// The `qcom,halt-regs` syscon.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HaltRegsDt {
    pub tcsr: (u64, u64),
    pub q6: u32,
    pub wcss: u32,
    pub nc: u32,
}

/// One RPMh RSC DRV (`rpmh-rsc.c` `rpmh_rsc_probe` +
/// `rpmh_probe_tcs_config`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RscDt {
    /// The `drv-<qcom,drv-id>` register window.
    pub drv: (u64, u64),
    pub drv_id: u32,
    /// `qcom,tcs-offset`.
    pub tcs_offset: u32,
    /// The first ACTIVE TCS: the `qcom,tcs-config` counts of the
    /// non-CONTROL groups listed before ACTIVE (groups are numbered in
    /// DT order; CONTROL takes no TCS index).
    pub active_tcs: u32,
}

/// The AOSS QMP channel (`qcom_aoss.c` `qmp_probe`): message RAM and
/// its outgoing mailbox.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QmpDt {
    pub msgram: (u64, u64),
    pub kick: KickDt,
}

/// The proxy resources `qcom_q6v5_pas.c` votes around a PAS start.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PasPowerDt {
    pub rsc: RscDt,
    /// The `qcom,cmd-db` reserved-memory region (`cmd_db_dev_probe`).
    pub cmd_db: (u64, u64),
    /// `power-domain-names` resolved to rpmhpd rails (`cx`, `mx`).
    pub rails: Vec<&'static str>,
    /// `qcom,qmp` (`None`: Linux skips the load-state message).
    pub qmp: Option<QmpDt>,
}

/// `rpmhpd.c` `sc7280_rpmhpds[]` index → rail (`res_name` minus
/// `.lvl`), for the indices a PAS proxy domain names. Only the SC7280
/// table is transcribed.
fn rpmhpd_rail(compat: &[String], index: u32) -> Option<&'static str> {
    if !compat.iter().any(|c| c == "qcom,sc7280-rpmhpd") {
        return None;
    }
    // SC7280_CX 0, SC7280_CX_AO 1, SC7280_EBI 2, SC7280_GFX 3,
    // SC7280_MX 4, SC7280_MX_AO 5, SC7280_LCX 6, SC7280_LMX 7,
    // SC7280_MSS 8 (dt-bindings `qcom,rpmhpd.h`).
    match index {
        0 => Some("cx"),
        4 => Some("mx"),
        _ => None,
    }
}

/// `qcom,tcs-config` group types (dt-bindings `qcom,rpmh-rsc.h`).
const ACTIVE_TCS: u32 = 2;
const CONTROL_TCS: u32 = 3;
const TCS_TYPE_NR: usize = 4;
const DRV_NAMES: [&str; 8] = [
    "drv-0", "drv-1", "drv-2", "drv-3", "drv-4", "drv-5", "drv-6", "drv-7",
];

fn rsc(node: &PlatformDevice) -> Result<RscDt, DtError> {
    let drv_id = node
        .prop_u32("qcom,drv-id")
        .ok_or(DtError::MissingResource("qcom,drv-id"))?;
    let name = DRV_NAMES
        .get(drv_id as usize)
        .ok_or(DtError::Malformed("qcom,drv-id"))?;
    let drv = node.reg_by_name(name)?;
    let tcs_offset = node
        .prop_u32("qcom,tcs-offset")
        .ok_or(DtError::MissingResource("qcom,tcs-offset"))?;
    let cfg = node
        .prop_u32s("qcom,tcs-config")
        .filter(|v| v.len() == 2 * TCS_TYPE_NR)
        .ok_or(DtError::Malformed("qcom,tcs-config"))?;
    let mut st = 0;
    let mut active = None;
    for pair in cfg.chunks(2) {
        let (ty, n) = (pair[0], pair[1]);
        if ty as usize >= TCS_TYPE_NR {
            return Err(DtError::Malformed("qcom,tcs-config"));
        }
        if n == 0 || ty == CONTROL_TCS {
            continue;
        }
        if ty == ACTIVE_TCS {
            active = Some(st);
        }
        st += n;
    }
    // Linux falls back to a WAKE TCS when no ACTIVE TCS exists; that
    // path is not implemented here, so such a DRV is refused.
    let active_tcs = active.ok_or(DtError::Malformed("no ACTIVE TCS"))?;
    Ok(RscDt {
        drv,
        drv_id,
        tcs_offset,
        active_tcs,
    })
}

/// Resolve the PAS proxy resources of the remoteproc `node`:
/// `power-domains` + `power-domain-names` (rpmhpd rails under one
/// `qcom,rpmh-rsc`), `clocks` `xo` (the RPMh `RPMH_CXO_CLK` under the
/// same RSC), the `qcom,cmd-db` reserved memory and the optional
/// `qcom,qmp` AOSS channel. `qcom_q6v5_pas.c` fails probe without the
/// proxy domains or the `xo` clock, so their absence is an error.
pub fn pas_power(blob: &[u8], node: &PlatformDevice) -> Result<PasPowerDt, DtError> {
    let names = node.prop_strings("power-domain-names");
    let pds = node.phandle_args(blob, "power-domains", "#power-domain-cells")?;
    if pds.is_empty() || pds.len() != names.len() {
        return Err(DtError::MissingResource("power-domains"));
    }
    let mut rsc_path = None;
    let mut rails = Vec::new();
    for (pd, name) in pds.iter().zip(names.iter()) {
        let ctl = dt::find_phandle(blob, pd.phandle)?;
        let index = *pd.args.first().ok_or(DtError::Malformed("power-domains"))?;
        let rail = rpmhpd_rail(&ctl.compatible, index)
            .ok_or(DtError::Malformed("unsupported power domain"))?;
        if rail != name.as_str() {
            return Err(DtError::Malformed("power-domain-names"));
        }
        let parent = String::from(parent_path(&ctl.path));
        if rsc_path.get_or_insert_with(|| parent.clone()) != &parent {
            return Err(DtError::Malformed("power domains on different RSCs"));
        }
        rails.push(rail);
    }
    let rsc_path = rsc_path.ok_or(DtError::MissingResource("power-domains"))?;
    let rsc_node = dt::find_compatible(blob, "qcom,rpmh-rsc")
        .into_iter()
        .find(|n| n.path == rsc_path)
        .ok_or(DtError::Malformed("rpmhpd parent is not an RSC"))?;
    let xo = node.phandle_args_by_name(blob, "clocks", "#clock-cells", "clock-names", "xo")?;
    let clk = dt::find_phandle(blob, xo.phandle)?;
    // RPMH_CXO_CLK = 0 (dt-bindings `qcom,rpmh.h`) on a `clk-rpmh`
    // provider under the same RSC: the `xo.lvl` ARC vote.
    if !clk.compatible.iter().any(|c| c.ends_with("-rpmh-clk"))
        || parent_path(&clk.path) != rsc_path
        || xo.args.as_slice() != [0]
    {
        return Err(DtError::Malformed("xo is not the RPMh CXO clock"));
    }
    let cmd_db = dt::find_compatible(blob, "qcom,cmd-db")
        .into_iter()
        .next()
        .ok_or(DtError::MissingResource("qcom,cmd-db"))?
        .reg(0)?;
    let qmp = match node.prop_u32("qcom,qmp") {
        Some(ph) => {
            let n = dt::find_phandle(blob, ph)?;
            if !n.is_compatible("qcom,aoss-qmp") {
                return Err(DtError::Malformed("qcom,qmp"));
            }
            Some(QmpDt {
                msgram: n.reg(0)?,
                kick: mbox_kick(blob, &n)?,
            })
        }
        None => None,
    };
    Ok(PasPowerDt {
        rsc: rsc(&rsc_node)?,
        cmd_db,
        rails,
        qmp,
    })
}

/// Everything a Q6 remoteproc needs, resolved.
#[derive(Clone, Debug)]
pub struct Q6Platform {
    pub node: PlatformDevice,
    pub kind: RprocKind,
    pub firmware: &'static str,
    pub crash_reason_item: u32,
    pub carveout: (u64, u64),
    /// `qdsp6` (WCSS) or `reg[0]` (PAS).
    pub qdsp6: (u64, u64),
    pub rmb: Option<(u64, u64)>,
    pub halt: Option<HaltRegsDt>,
    pub resets: Vec<ResetDt>,
    pub irqs: Vec<(Q6Event, IrqSource)>,
    /// Outbound `stop`: (edge path, entry name, bit).
    pub stop: Option<(String, String, u32)>,
    pub edges: Vec<Smp2pDt>,
    pub smem: Option<SmemDt>,
    /// PAS proxy power ([`pas_power`]); `None` for WCSS.
    pub power: Option<PasPowerDt>,
}

impl Q6Platform {
    pub fn reset(&self, name: &str) -> Option<&ResetDt> {
        self.resets.iter().find(|r| r.name == name)
    }
    pub fn irq(&self, ev: Q6Event) -> Option<&IrqSource> {
        self.irqs.iter().find(|(e, _)| *e == ev).map(|(_, s)| s)
    }
    pub fn edge(&self, path: &str) -> Option<&Smp2pDt> {
        self.edges.iter().find(|e| e.path == path)
    }
}

fn parent_path(path: &str) -> &str {
    match path.rfind('/') {
        Some(0) | None => "/",
        Some(i) => &path[..i],
    }
}

/// Resolve the SMP2P edge node at `path`.
pub fn smp2p_edge(blob: &[u8], path: &str) -> Result<Smp2pDt, DtError> {
    let node = dt::find_compatible(blob, "qcom,smp2p")
        .into_iter()
        .find(|n| n.path == path)
        .ok_or(DtError::NotFound)?;
    let smem = node
        .prop_u32s("qcom,smem")
        .filter(|v| v.len() == 2)
        .ok_or(DtError::MissingResource("qcom,smem"))?;
    let local = node
        .prop_u32("qcom,local-pid")
        .ok_or(DtError::MissingResource("qcom,local-pid"))?;
    let remote = node
        .prop_u32("qcom,remote-pid")
        .ok_or(DtError::MissingResource("qcom,remote-pid"))?;
    let irq = node
        .irqs
        .first()
        .cloned()
        .ok_or(DtError::MissingResource("interrupts"))?;
    let kick = mbox_kick(blob, &node)?;
    Ok(Smp2pDt {
        path: node.path.clone(),
        cfg: Smp2pConfig {
            smem_in: smem[0],
            smem_out: smem[1],
            local_pid: local as u16,
            remote_pid: remote as u16,
        },
        kick,
        irq,
    })
}

/// The first `mboxes` entry of `node` as an outgoing kick (APCS global
/// IPC or IPCC).
fn mbox_kick(blob: &[u8], node: &PlatformDevice) -> Result<KickDt, DtError> {
    let mbox = node
        .phandle_args(blob, "mboxes", "#mbox-cells")?
        .into_iter()
        .next()
        .ok_or(DtError::MissingResource("mboxes"))?;
    let ctl = dt::find_phandle(blob, mbox.phandle)?;
    let base = ctl.reg(0)?;
    let kick = if ctl.is_compatible("qcom,ipcc") {
        match mbox.args.as_slice() {
            [client, signal] => KickDt::Ipcc {
                base,
                client: *client as u16,
                signal: *signal as u16,
            },
            _ => return Err(DtError::Malformed("ipcc mboxes")),
        }
    } else if ctl
        .compatible
        .iter()
        .any(|c| c.ends_with("-apcs-apps-global"))
    {
        match mbox.args.as_slice() {
            [ch] => KickDt::Apcs {
                base,
                offset: crate::ipc::APCS_IPQ_IPC_OFFSET,
                channel: *ch,
            },
            _ => return Err(DtError::Malformed("apcs mboxes")),
        }
    } else {
        return Err(DtError::Malformed("unsupported mailbox"));
    };
    Ok(kick)
}

/// A remoteproc's `glink-edge` subnode (`qcom_add_glink_subdev`,
/// `qcom,glink-edge.yaml`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GlinkEdgeDt {
    pub path: String,
    /// `label` (`rtr`, `wpss`, ...).
    pub label: String,
    /// `qcom,remote-pid` (the SMEM host of the FIFO items).
    pub remote_pid: u16,
    /// The edge's incoming interrupt (GIC SPI or IPCC signal).
    pub irq: IrqSpec,
    /// `mboxes`: the outgoing kick.
    pub kick: KickDt,
    /// Every child's `qcom,glink-channels` (e.g. `IPCRTR`).
    pub channels: Vec<String>,
}

/// The `glink-edge` child of the remoteproc at `rproc_path`.
pub fn glink_edge(blob: &[u8], rproc_path: &str) -> Result<GlinkEdgeDt, DtError> {
    let node = dt::children(blob, rproc_path)
        .into_iter()
        .find(|n| n.path.rsplit('/').next() == Some("glink-edge"))
        .ok_or(DtError::NotFound)?;
    let remote_pid = node
        .prop_u32("qcom,remote-pid")
        .ok_or(DtError::MissingResource("qcom,remote-pid"))?;
    let irq = node
        .irqs
        .first()
        .cloned()
        .ok_or(DtError::MissingResource("interrupts"))?;
    let kick = mbox_kick(blob, &node)?;
    let channels = dt::children(blob, &node.path)
        .iter()
        .flat_map(|c| c.prop_strings("qcom,glink-channels"))
        .collect();
    Ok(GlinkEdgeDt {
        path: node.path.clone(),
        label: node
            .prop_strings("label")
            .into_iter()
            .next()
            .unwrap_or_default(),
        remote_pid: remote_pid as u16,
        irq,
        kick,
        channels,
    })
}

/// An SMP2P entry node (`master-kernel`, `slave-kernel`, `wlan-*`) by
/// phandle → (edge path, `qcom,entry-name`), or `None` if the phandle is
/// not an SMP2P entry.
pub fn smp2p_entry(blob: &[u8], phandle: u32) -> Option<(String, String)> {
    let n = dt::find_phandle(blob, phandle).ok()?;
    let name = n.prop_strings("qcom,entry-name").into_iter().next()?;
    let edge = parent_path(&n.path);
    let is_edge = dt::find_compatible(blob, "qcom,smp2p")
        .iter()
        .any(|e| e.path == edge);
    is_edge.then(|| (String::from(edge), name))
}

/// The `qcom,smem` node.
pub fn smem(blob: &[u8]) -> Result<SmemDt, DtError> {
    let n = dt::find_compatible(blob, "qcom,smem")
        .into_iter()
        .next()
        .ok_or(DtError::NotFound)?;
    // Either a memory-region (IPQ6018/SC7280) or a direct reg (IPQ8074).
    let region = n.memory_region(0).or_else(|_| n.reg(0))?;
    let lock = n
        .phandle_args(blob, "hwlocks", "#hwlock-cells")?
        .into_iter()
        .next()
        .ok_or(DtError::MissingResource("hwlocks"))?;
    let ctl = dt::find_phandle(blob, lock.phandle)?;
    Ok(SmemDt {
        region,
        hwlock_base: ctl.reg(0)?,
        hwlock_id: *lock.args.first().ok_or(DtError::Malformed("hwlocks"))?,
    })
}

/// Resolve the remoteproc node `phandle` (ath11k `qcom,rproc`).
pub fn q6_platform(blob: &[u8], phandle: u32) -> Result<Q6Platform, DtError> {
    let node = dt::find_phandle(blob, phandle)?;
    let (_, kind, firmware, crash) = RPROC_MATCH
        .iter()
        .copied()
        .find(|(c, ..)| node.is_compatible(c))
        .ok_or(DtError::Malformed("unsupported remoteproc compatible"))?;
    let carveout = node.memory_region(0)?;
    let (qdsp6, rmb, halt) = match kind {
        RprocKind::Wcss => {
            let h = node
                .prop_u32s("qcom,halt-regs")
                .filter(|v| v.len() == 4)
                .ok_or(DtError::MissingResource("qcom,halt-regs"))?;
            let tcsr = dt::find_phandle(blob, h[0])?.reg(0)?;
            (
                node.reg_by_name("qdsp6")?,
                Some(node.reg_by_name("rmb")?),
                Some(HaltRegsDt {
                    tcsr,
                    q6: h[1],
                    wcss: h[2],
                    nc: h[3],
                }),
            )
        }
        RprocKind::Pas { .. } => (node.reg(0)?, None, None),
    };
    let mut resets = Vec::new();
    let names = node.prop_strings("reset-names");
    for (i, r) in node
        .phandle_args(blob, "resets", "#reset-cells")?
        .into_iter()
        .enumerate()
    {
        let ctl = dt::find_phandle(blob, r.phandle)?;
        let gcc = gcc::desc_for(&ctl.compatible)
            .ok_or(DtError::Malformed("unsupported reset controller"))?;
        let index = *r.args.first().ok_or(DtError::Malformed("resets"))?;
        if !gcc.resets.iter().any(|e| e.index == index) {
            return Err(DtError::Malformed("reset index not in GCC table"));
        }
        resets.push(ResetDt {
            name: names.get(i).cloned().unwrap_or_default(),
            gcc_base: ctl.reg(0)?,
            gcc,
            index,
        });
    }
    let mut irqs = Vec::new();
    let mut edges: Vec<Smp2pDt> = Vec::new();
    for (i, spec) in node.irqs.iter().enumerate() {
        let Some(ev) = node
            .irq_names
            .get(i)
            .and_then(|n| Q6Event::from_irq_name(n))
        else {
            continue;
        };
        let src = match smp2p_entry(blob, spec.parent) {
            Some((edge, entry)) => {
                if !edges.iter().any(|e| e.path == edge) {
                    edges.push(smp2p_edge(blob, &edge)?);
                }
                IrqSource::Smp2p {
                    edge,
                    entry,
                    bit: *spec.cells.first().ok_or(DtError::Malformed("smp2p irq"))?,
                }
            }
            None => IrqSource::Gic(spec.gic_hwirq().ok_or(DtError::Malformed("gic irq"))?),
        };
        irqs.push((ev, src));
    }
    let stop = match node.phandle_args_by_name(
        blob,
        "qcom,smem-states",
        "#qcom,smem-state-cells",
        "qcom,smem-state-names",
        "stop",
    ) {
        Ok(s) => {
            let (edge, entry) =
                smp2p_entry(blob, s.phandle).ok_or(DtError::Malformed("stop state"))?;
            if !edges.iter().any(|e| e.path == edge) {
                edges.push(smp2p_edge(blob, &edge)?);
            }
            Some((
                edge,
                entry,
                *s.args.first().ok_or(DtError::Malformed("stop state"))?,
            ))
        }
        Err(DtError::MissingResource(_)) => None,
        Err(e) => return Err(e),
    };
    let smem = if edges.is_empty() {
        None
    } else {
        Some(smem(blob)?)
    };
    let power = match kind {
        RprocKind::Pas { .. } => Some(pas_power(blob, &node)?),
        RprocKind::Wcss => None,
    };
    Ok(Q6Platform {
        node,
        kind,
        firmware,
        crash_reason_item: crash,
        carveout,
        qdsp6,
        rmb,
        halt,
        resets,
        irqs,
        stop,
        edges,
        smem,
        power,
    })
}
