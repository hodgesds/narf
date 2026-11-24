//! Strix Point (GC 11.5.0) cold boot: the sixteen-stage graphics bring-up
//! in Linux order, mirroring [`crate::amdgpu_phoenix_boot`] but with the
//! Strix owners (`gfx_v11_0.c::gfx_v11_0_hw_init` +
//! `mes_v11_0.c::mes_v11_0_hw_init`).
//!
//! Stages: Smu → MemoryHubs → Gart → Interrupts → GoldenSettings → SdmaTest
//! → InterruptTest → Doorbells → GfxSetup → Kiq → ComputeQueues → GfxRing →
//! SdmaQueues → IbTests → FenceInterrupts → ReadTopology. Media (VCN 4.0.5)
//! is NOT one of the sixteen: there is no VCN 4.0 owner yet, so the media
//! stage is a flagged remainder and `media` is always `None`.
//!
//! This is a skeleton: only the Smu stage executes. The other fifteen
//! fail closed with [`Error::NotReady`], naming the missing owner and the
//! lane that must land before the stage can execute — no stage is skipped,
//! and `run` never reports success it did not earn. What is grounded so
//! far, per stage:
//!
//!   * Smu — LIVE: [`crate::amdgpu_smu_strix`] (SMU 14.0.1, v14_0_0
//!     message table, C2PMSG_66/82/90 on MP1 window 1; driver-IF exactly
//!     0x6). The stage runs `smu.start()` then disallows GFXOFF.
//!   * MemoryHubs — needs a GMC 11.5 arm: `Gfx11Die::of` DID-gates Strix
//!     out (`amdgpu_gmc_navi31.rs:132`), and the GC 11.5.0 bank layout is
//!     ungrounded. GMC lane.
//!   * Interrupts — needs a Strix IH: `amdgpu_ih_phoenix.rs:163`
//!     DID-gates Strix out ("its own IH"). IH lane.
//!   * GoldenSettings — the table is grounded: Linux applies
//!     `golden_settings_gc_11_0` (1 entry: GC 0, regTCP_CNTL, mask and
//!     value 0x20000000) to ALL GC 11.x, and `golden_settings_gc_11_0_1`
//!     only to 11.0.1/11.0.4, so Strix gets the base table only. The
//!     stage itself waits on MemoryHubs (it writes through the GC banks).
//!   * SdmaTest / SdmaQueues — SDMA 6.1.0 is driven by Linux's
//!     `sdma_v6_0.c` (IP_VERSION(6,1,0)-(6,1,3) arms at :1365-1377); the
//!     6.1.0-vs-6.0.1 delta in that switch is unpinned. SDMA lane.
//!   * GfxSetup / Kiq / ComputeQueues / GfxRing — GFX 11.5.0 setup and the
//!     MES-KIQ topology: `PHOENIX_TOPOLOGY` is the only topology const
//!     (`amdgpu_mes_hw.rs:513`); there is no `read_strix` topology reader
//!     (`amdgpu_gfx11_topology.rs:370` has only `read_phoenix`). GFX/MES
//!     lane.
//!   * ReadTopology — needs the `read_strix` reader (CU info for GC
//!     11.5.0). Topology lane.
//!   * Gart, InterruptTest, Doorbells, IbTests, FenceInterrupts — follow
//!     their owners (GMC, IH, doorbells, SDMA, queues) and fail closed
//!     until those land.
//!
//! The platform wiring (`graphics_boot_strix` in `amdgpu_platform`) is
//! unreachable until a Strix firmware-set opener (`Firmware::open_strix` +
//! `Loader::set_graphics` Strix arm) lands — there is none in tree, and
//! Phoenix itself has no firmware-set opener either.
//!
//! Fixture-validated (stage order, DID gate, SMU protocol); silicon
//! untested. No Strix test hardware is known.

use crate::amdgpu::AmdGpu;
use crate::amdgpu_discovery as ip;
use crate::amdgpu_smu_strix::{self as smu, Smu};
use crate::amdgpu_vram::Pool;
use narf_bus::{BusDevice, BusDeviceCap};
use narf_capabilities::{Cap, Write};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    Invalid,
    Busy,
    Allocation,
    Revoked,
    DeviceGone,
    Smu(smu::Error),
    /// A stage whose owner does not exist yet. `missing` names the
    /// owner/lane that must land before the stage can execute; the stage
    /// is never skipped, so `run` fails closed here.
    NotReady {
        stage: Stage,
        missing: &'static str,
    },
}

/// The sixteen stages, in Linux bring-up order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    Smu,
    MemoryHubs,
    Gart,
    Interrupts,
    GoldenSettings,
    SdmaTest,
    InterruptTest,
    Doorbells,
    GfxSetup,
    Kiq,
    ComputeQueues,
    GfxRing,
    SdmaQueues,
    IbTests,
    FenceInterrupts,
    ReadTopology,
}
const STAGES: [Stage; 16] = [
    Stage::Smu,
    Stage::MemoryHubs,
    Stage::Gart,
    Stage::Interrupts,
    Stage::GoldenSettings,
    Stage::SdmaTest,
    Stage::InterruptTest,
    Stage::Doorbells,
    Stage::GfxSetup,
    Stage::Kiq,
    Stage::ComputeQueues,
    Stage::GfxRing,
    Stage::SdmaQueues,
    Stage::IbTests,
    Stage::FenceInterrupts,
    Stage::ReadTopology,
];

/// What a completed run proved. Today only the SMU versions are known;
/// the remaining fields arrive with their stage lanes (aperture with the
/// GMC lane, proofs with the SDMA/queue/MES lanes, topology with the
/// topology lane).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Report {
    pub smu: smu::Versions,
    /// How many of the sixteen stages completed.
    pub stages_completed: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Prepared,
    Running(Stage),
    Ready(Report),
    Failed { stage: Stage, error: Error },
}

/// Every Strix graphics owner so far, retained through success and failure
/// so no published memory is released while an engine may still reach it.
/// The SMU is the only owner that exists today; the rest arrive as their
/// lanes land and take their fields here.
#[derive(Debug)]
pub struct StrixColdBoot {
    /// Retained for the GMC lane (step_memory_hubs) and the
    /// golden-settings lane, which write through its banks.
    #[allow(dead_code, reason = "read by the GMC lane (step_memory_hubs)")]
    gpu: AmdGpu,
    /// Retained for the GMC/IH lanes' direct-MMIO access.
    #[allow(dead_code, reason = "read by the GMC and IH lanes")]
    authority: Cap<BusDeviceCap, Write>,
    /// Retained for the GMC lane (client VRAM).
    #[allow(dead_code, reason = "read by the GMC lane (client VRAM)")]
    pool: Pool,
    smu: Smu,
    /// Per-pipe MES program-counter entry points (`uc_start_addr`), from
    /// the firmware-load lane; read by the Kiq lane.
    #[allow(dead_code, reason = "read by the Kiq lane (MES entry points)")]
    mes_start: [u64; 2],
    versions: Option<smu::Versions>,
    /// How many stages the current run completed.
    stages_completed: u8,
    state: State,
}

fn is_strix_did(vid: u16, did: u16) -> bool {
    // Strix shares Family::Phoenix today but is RDNA3.5 with its own
    // bring-up; the Strix owners DID-gate on this one DID until the
    // parallel bringup lane adds Family::Strix.
    matches!(
        (vid, did),
        (crate::amdgpu::AMD_VENDOR, crate::amdgpu::STRIX_POINT)
    )
}

/// The blocks whose Strix versions this port infers rather than knows:
/// no Strix discovery table has been read. Each is accepted at every
/// version Linux drives with the same functions.
const INFERRED: [(&str, u16); 6] = [
    ("NBIF", ip::HW_ID_NBIF),
    ("MMHUB", ip::HW_ID_MMHUB),
    ("ATHUB", ip::HW_ID_ATHUB),
    ("OSSSYS", ip::HW_ID_OSSSYS),
    ("HDP", ip::HW_ID_HDP),
    ("SMUIO", ip::HW_ID_SMUIO),
];
/// One boot line with the discovered versions of [`INFERRED`]'s blocks
/// (instance 0; `-` where discovery lists none), so the first boot on the
/// hardware confirms or refutes them.
fn discovery_line(blocks: &[ip::IpBlock]) -> alloc::string::String {
    use core::fmt::Write as _;
    let mut line = alloc::string::String::from("amdgpu: strix discovery:");
    for (name, id) in INFERRED {
        let _ = match ip::find_ip(blocks, id, 0) {
            Some(b) => write!(line, " {name} {}.{}.{}", b.major, b.minor, b.revision),
            None => write!(line, " {name} -"),
        };
    }
    line
}

fn snapshot(gpu: &AmdGpu) -> Result<AmdGpu, Error> {
    let mut blocks = alloc::vec::Vec::new();
    blocks
        .try_reserve_exact(gpu.ip_blocks.len())
        .map_err(|_| Error::Allocation)?;
    blocks.extend_from_slice(&gpu.ip_blocks);
    Ok(AmdGpu {
        fb_bar: gpu.fb_bar,
        regs: gpu.regs,
        chip: gpu.chip,
        vram: gpu.vram,
        ip_blocks: blocks,
        gc_info: gpu.gc_info,
        vbios: None,
        mode: None,
        backlight_percent: None,
        fw_loaded: false,
    })
}

impl StrixColdBoot {
    /// # Safety
    /// Own this physical GPU, permanent mappings, the inventory-derived free
    /// VRAM pool, all GFX/SDMA/MES/IP sources/indexing/reset/PM, and its PCI
    /// interrupt route. The retained coordinator must outlive any published
    /// address, including errors. Preparation validates layouts, reserves
    /// memory and maps BAR2, but never writes a register.
    ///
    /// `mes_start` is `[sched, kiq]`: the two MES program-counter entry
    /// points from the MES firmware header; the firmware-load lane supplies
    /// them. `device` is retained for the Doorbells lane
    /// (`Doorbells::map_strix`); the SMU gate reads `gpu.chip`.
    pub(crate) unsafe fn new(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        pool: &Pool,
        device: &BusDevice,
        mes_start: [u64; 2],
    ) -> Result<Self, Error> {
        // `device` is unused until the Doorbells lane adds
        // `Doorbells::map_strix`; the parameter stays so the platform
        // wiring matches Phoenix's shape.
        let _ = device;
        if !is_strix_did(gpu.chip.vid, gpu.chip.did) {
            return Err(Error::Unsupported);
        }
        {
            use core::fmt::Write as _;
            let _ = writeln!(narf_console::Writer, "{}", discovery_line(&gpu.ip_blocks));
        }
        let gpu = snapshot(gpu)?;
        // SAFETY: forwarded exclusive ownership; the constructor below only
        // validates layouts.
        unsafe {
            let smu = Smu::new(&gpu, authority).map_err(Error::Smu)?;
            Ok(Self {
                gpu,
                authority,
                pool: pool.clone(),
                smu,
                mes_start,
                versions: None,
                stages_completed: 0,
                state: State::Prepared,
            })
        }
    }

    pub fn state(&self) -> State {
        self.state
    }
    /// A completed run: every kernel queue passed its ring and IB tests.
    /// Unreachable until all sixteen stages land.
    pub fn queues_verified(&self) -> bool {
        matches!(self.state, State::Ready(_))
    }

    /// # Safety
    /// The owner is new, this display owner holds the whole GPU, and the
    /// RLC autoload has completed — the same contract as Raphael's `run`.
    pub(crate) async unsafe fn run(&mut self) -> Result<&Report, Error> {
        if !matches!(self.state, State::Prepared) {
            return Err(Error::Busy);
        }
        for stage in STAGES {
            self.state = State::Running(stage);
            progress(stage, None);
            let result = self.step(stage).await;
            progress(stage, Some(result));
            if let Err(error) = result {
                self.state = State::Failed { stage, error };
                return Err(error);
            }
            self.stages_completed += 1;
        }
        let report = Report {
            smu: self.versions.ok_or(Error::Invalid)?,
            stages_completed: self.stages_completed,
        };
        self.state = State::Ready(report);
        Ok(match &self.state {
            State::Ready(report) => report,
            _ => unreachable!(),
        })
    }

    async fn step(&mut self, stage: Stage) -> Result<(), Error> {
        match stage {
            Stage::Smu => self.step_smu().await,
            Stage::MemoryHubs => Err(not_ready(
                Stage::MemoryHubs,
                "GMC 11.5 arm (Gfx11Die::of DID-gates Strix out; GC 11.5.0 bank layout ungrounded)",
            )),
            Stage::Gart => Err(not_ready(
                Stage::Gart,
                "GMC 11.5 arm (GART is ready once the GMC's client contexts are prepared)",
            )),
            Stage::Interrupts => Err(not_ready(
                Stage::Interrupts,
                "Strix IH (amdgpu_ih_phoenix DID-gates Strix out)",
            )),
            Stage::GoldenSettings => Err(not_ready(
                Stage::GoldenSettings,
                "GC banks via the GMC lane (table grounded: base gc_11_0 only, 1 entry)",
            )),
            Stage::SdmaTest => Err(not_ready(
                Stage::SdmaTest,
                "SDMA 6.1.0 owner (6.1.0-vs-6.0.1 delta in sdma_v6_0.c unpinned)",
            )),
            Stage::InterruptTest => Err(not_ready(
                Stage::InterruptTest,
                "Strix IH (interrupt trap follows the IH lane)",
            )),
            Stage::Doorbells => Err(not_ready(
                Stage::Doorbells,
                "Doorbells::map_strix (doorbell assignment for Strix)",
            )),
            Stage::GfxSetup => Err(not_ready(
                Stage::GfxSetup,
                "GFX 11.5.0 setup (no Strix GFX owner yet)",
            )),
            Stage::Kiq => Err(not_ready(
                Stage::Kiq,
                "MES-KIQ Strix topology (no Strix topology const; PHOENIX_TOPOLOGY only)",
            )),
            Stage::ComputeQueues => Err(not_ready(
                Stage::ComputeQueues,
                "GFX 11.5.0 setup (compute queues follow the GFX lane)",
            )),
            Stage::GfxRing => Err(not_ready(
                Stage::GfxRing,
                "GFX 11.5.0 setup (GFX ring follows the GFX lane)",
            )),
            Stage::SdmaQueues => Err(not_ready(
                Stage::SdmaQueues,
                "SDMA 6.1.0 owner (SDMA queues follow the SDMA lane)",
            )),
            Stage::IbTests => Err(not_ready(
                Stage::IbTests,
                "SDMA 6.1.0 + GFX 11.5.0 owners (IB tests follow the queue lanes)",
            )),
            Stage::FenceInterrupts => Err(not_ready(
                Stage::FenceInterrupts,
                "Strix IH + queue owners (fence interrupts follow the IH lane)",
            )),
            Stage::ReadTopology => Err(not_ready(
                Stage::ReadTopology,
                "read_strix topology reader (GC 11.5.0 CU info)",
            )),
        }
    }

    async fn step_smu(&mut self) -> Result<(), Error> {
        // Unlike Phoenix there is no known newer driver-IF to accept: the
        // engine refuses anything but exactly 0x6, so no mismatch-continue
        // logic applies here.
        let versions = self.smu.start().await.map_err(Error::Smu)?;
        self.smu.set_gfxoff(false).await.map_err(Error::Smu)?;
        self.versions = Some(versions);
        Ok(())
    }
}

/// A stage whose owner does not exist yet: fail closed, naming what must
/// land first.
fn not_ready(stage: Stage, missing: &'static str) -> Error {
    Error::NotReady { stage, missing }
}

/// Boot-only checkpoints, never a poll-loop trace.
fn progress(stage: Stage, result: Option<Result<(), Error>>) {
    use core::fmt::Write as _;
    let _ = match result {
        None => writeln!(narf_console::Writer, "amdgpu: strix {stage:?}: start"),
        Some(Ok(())) => writeln!(narf_console::Writer, "amdgpu: strix {stage:?}: complete"),
        Some(Err(error)) => writeln!(
            narf_console::Writer,
            "amdgpu: strix {stage:?}: failed {error:?}"
        ),
    };
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_strix_boot_tests.rs"]
mod tests;
