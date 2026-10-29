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
//! - the SMEM region and its TCSR-mutex hwlock.

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
    })
}
