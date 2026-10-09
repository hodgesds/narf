//! The GFX11 bring-up order, as a value.
//!
//! Every register sequence and packet `gfx_v11_0_cp_resume` issues now exists
//! somewhere in this driver. What did not exist is the **order**, and order is
//! the part that cannot be checked by reading any one module: the MES must be
//! executing before a packet is submitted to it, `SET_HW_RSRC` must precede
//! any `ADD_QUEUE`, a descriptor must be written before the queue it describes
//! is mapped, and the clear-state preamble must go onto a ring the engine is
//! already reading.
//!
//! So the plan is a table. It is the inventory of what bring-up consists of,
//! it records which builder in this tree implements each step, and the steps
//! that nothing implements are [`Implemented::Missing`] rather than absent —
//! a gap you can enumerate instead of discover.
//!
//! This module plans; it does not execute. Executing needs an `AmdGpu` that
//! owns the contexts, which it does not yet.
//!
//! ## The fork
//!
//! `gfx_v11_0_cp_resume` branches on the `amdgpu_async_gfx_ring` module
//! parameter. [`CP_RESUME_ASYNC`] is the arm Linux takes by default and the
//! one this driver targets; see [`crate::amdgpu_gfx::build_gfx11_ring_init`]
//! for what the other arm does and why the two must not be interleaved.

/// What implements a step.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Implemented {
    /// A builder or helper in this tree. The string names it so the plan can
    /// be read as a map into the code.
    By(&'static str),
    /// Nothing implements this step. The string says what it needs.
    Missing(&'static str),
}

/// One step of bring-up.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct BringupStep {
    /// Short name, used by the ordering assertions.
    pub name: &'static str,
    /// The Linux function this step is.
    pub linux_fn: &'static str,
    pub implemented: Implemented,
}

const fn step(name: &'static str, linux_fn: &'static str, implemented: Implemented) -> BringupStep {
    BringupStep {
        name,
        linux_fn,
        implemented,
    }
}

/// `gfx_v11_0_cp_resume` on a PSP-loading, RS64, MES-KIQ part with
/// `amdgpu_async_gfx_ring = 1` — which is Phoenix with stock parameters.
///
/// Read against `gfx_v11_0_cp_resume`, `mes_v11_0_kiq_hw_init`,
/// `mes_v11_0_hw_init`, `gfx_v11_0_kcq_resume` and
/// `gfx_v11_0_cp_async_gfx_ring_resume`.
///
/// The firmware load is not here: on this part the PSP does it before any of
/// this runs, which is `AmdGpu::initialize`.
pub const CP_RESUME_ASYNC: &[BringupStep] = &[
    step(
        "doorbell_range",
        "gfx_v11_0_cp_set_doorbell_range",
        Implemented::By("amdgpu_gfx::build_cp_set_doorbell_range"),
    ),
    step(
        "compute_enable",
        "gfx_v11_0_cp_compute_enable",
        Implemented::By("amdgpu_gfx::cp_compute_enable_value"),
    ),
    step(
        "gfx_enable",
        "gfx_v11_0_cp_gfx_enable",
        Implemented::By("amdgpu_cp_fw::cp_enable"),
    ),
    // ── amdgpu_mes_kiq_hw_init -> mes_v11_0_kiq_hw_init ──
    step(
        "mes_enable",
        "mes_v11_0_enable",
        Implemented::By("amdgpu_mes_hw::build_mes_enable"),
    ),
    step(
        "mes_fw_version",
        "mes_v11_0_get_fw_version",
        // The selector values and the register are named; the read itself is
        // a read-modify-read a sequence cannot carry, and nothing performs it.
        // It decides `enable_legacy_queue_map`, i.e. which of the two
        // queue-mapping paths the two `map_queue` steps below take.
        Implemented::Missing("a two-step MMIO read; selector in fw_version_select"),
    ),
    step(
        "kiq_setting",
        "mes_v11_0_kiq_setting",
        Implemented::By("amdgpu_mes_hw::rlc_cp_schedulers_value"),
    ),
    step(
        "kiq_pipe_mqd",
        "mes_v11_0_queue_init(KIQ_PIPE)",
        Implemented::By("MesQueue::write_mqd + queue_init_sequence"),
    ),
    // ── mes_v11_0_hw_init ──
    step(
        "sched_pipe_mqd",
        "mes_v11_0_queue_init(SCHED_PIPE)",
        Implemented::By("MesQueue::write_mqd + queue_init_sequence"),
    ),
    step(
        "set_hw_resources",
        "mes_v11_0_set_hw_resources",
        Implemented::By("MesQueue::hw_resources + build_set_hw_resources"),
    ),
    step(
        "query_sched_status",
        "mes_v11_0_query_sched_status",
        Implemented::By("amdgpu_mes::build_query_mes_status"),
    ),
    // ── gfx_v11_0_kcq_resume ──
    step(
        "kcq_mqd",
        "gfx_v11_0_kcq_init_queue",
        Implemented::By("ComputeContext::write_mqd"),
    ),
    step(
        "kcq_map",
        "amdgpu_gfx_enable_kcq",
        Implemented::By("ComputeContext::map_legacy_args + MesQueue::map_legacy_queue"),
    ),
    // ── gfx_v11_0_cp_async_gfx_ring_resume ──
    step(
        "kgq_mqd",
        "gfx_v11_0_kgq_init_queue",
        Implemented::By("GfxContext::write_mqd"),
    ),
    step(
        "kgq_map",
        "amdgpu_gfx_enable_kgq",
        Implemented::By("GfxContext::map_legacy_args + MesQueue::map_legacy_queue"),
    ),
    step(
        "clear_state",
        "gfx_v11_0_cp_gfx_start",
        Implemented::By("amdgpu_clearstate::build_preamble"),
    ),
    // ── the ring tests cp_resume ends with ──
    step(
        "gfx_ring_test",
        "amdgpu_ring_test_helper(gfx_ring)",
        Implemented::By("amdgpu_gfx::build_ring_test_packet"),
    ),
    step(
        "compute_ring_test",
        "amdgpu_ring_test_helper(compute_ring)",
        Implemented::By("amdgpu_gfx::build_ring_test_packet"),
    ),
];

/// Index of `name` in `plan`, or `None`.
pub fn position(plan: &[BringupStep], name: &str) -> Option<usize> {
    plan.iter().position(|s| s.name == name)
}

/// The steps nothing implements yet.
pub fn missing(plan: &[BringupStep]) -> impl Iterator<Item = &BringupStep> {
    plan.iter()
        .filter(|s| matches!(s.implemented, Implemented::Missing(_)))
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
mod smoke_tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// The ordering constraints, each one a thing that is silent when wrong.
    fn smoke_bringup_order_invariants() -> TestResult {
        let plan = CP_RESUME_ASYNC;
        let at = |n: &str| position(plan, n);

        // Every name resolves, and no name is duplicated.
        for s in plan {
            if at(s.name).is_none() {
                return TestResult::Fail("a step's name does not resolve");
            }
        }
        for (i, s) in plan.iter().enumerate() {
            if plan.iter().skip(i + 1).any(|o| o.name == s.name) {
                return TestResult::Fail("two steps share a name");
            }
        }

        let (
            Some(doorbell),
            Some(compute_en),
            Some(gfx_en),
            Some(mes_en),
            Some(kiq_set),
            Some(kiq_mqd),
            Some(sched_mqd),
            Some(hw_rsrc),
            Some(query),
            Some(kcq_mqd),
            Some(kcq_map),
            Some(kgq_mqd),
            Some(kgq_map),
            Some(clear),
            Some(gfx_test),
        ) = (
            at("doorbell_range"),
            at("compute_enable"),
            at("gfx_enable"),
            at("mes_enable"),
            at("kiq_setting"),
            at("kiq_pipe_mqd"),
            at("sched_pipe_mqd"),
            at("set_hw_resources"),
            at("query_sched_status"),
            at("kcq_mqd"),
            at("kcq_map"),
            at("kgq_mqd"),
            at("kgq_map"),
            at("clear_state"),
            at("gfx_ring_test"),
        )
        else {
            return TestResult::Fail("a required step is missing from the plan");
        };

        // The doorbell windows are opened before any engine is unhalted: an
        // engine running with the window closed drops doorbell rings.
        if doorbell > compute_en || doorbell > gfx_en {
            return TestResult::Fail("the doorbell ranges are set before the engines start");
        }
        // The MES is executing before anything is asked of it. Every step
        // after this one submits a packet.
        if mes_en > kiq_set || mes_en > kiq_mqd || mes_en > hw_rsrc {
            return TestResult::Fail("the MES must be enabled before any packet");
        }
        // `SET_HW_RSRC` tells the scheduler which pipes and VMIDs exist. An
        // ADD_QUEUE before it names resources the scheduler does not know
        // about.
        if hw_rsrc > kcq_map || hw_rsrc > kgq_map {
            return TestResult::Fail("SET_HW_RSRC must precede any queue mapping");
        }
        // And the scheduler is confirmed alive before the driver trusts it
        // with a queue.
        if query > kcq_map || query > kgq_map {
            return TestResult::Fail("the scheduler is queried before queues are mapped");
        }
        // A descriptor is written before the queue it describes is mapped —
        // the firmware reads the descriptor when the map arrives.
        if kcq_mqd > kcq_map {
            return TestResult::Fail("the compute descriptor precedes its mapping");
        }
        if kgq_mqd > kgq_map {
            return TestResult::Fail("the graphics descriptor precedes its mapping");
        }
        // The clear-state preamble goes onto a ring the engine is already
        // reading, so it follows the map.
        if kgq_map > clear {
            return TestResult::Fail("the clear-state preamble follows the queue mapping");
        }
        // And the ring test is last: it is the evidence, so everything it is
        // evidence of comes first.
        if clear > gfx_test {
            return TestResult::Fail("the ring test comes after the preamble");
        }
        if gfx_test != plan.len() - 2 {
            return TestResult::Fail("the two ring tests end the plan");
        }
        // Linux's own order inside the MES block: the KIQ pipe is brought up
        // in `mes_v11_0_kiq_hw_init` and the scheduler pipe in
        // `mes_v11_0_hw_init`, which it calls afterwards.
        if kiq_mqd > sched_mqd {
            return TestResult::Fail("the KIQ pipe is initialised before the scheduler pipe");
        }
        // kcq_resume runs before the graphics ring comes up.
        if kcq_map > kgq_mqd {
            return TestResult::Fail("kcq_resume precedes cp_async_gfx_ring_resume");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/amdgpu/bringup", smoke_bringup_order_invariants);

    /// The plan doubles as the gap inventory, so the gaps are declared.
    ///
    /// A step that quietly becomes unimplemented, or a new unimplemented step
    /// appearing, fails here rather than being found by booting.
    fn smoke_bringup_declared_gaps() -> TestResult {
        let gaps: alloc::vec::Vec<&str> = missing(CP_RESUME_ASYNC).map(|s| s.name).collect();
        // Exactly one step has no implementation: the firmware-version read
        // that decides which queue-mapping path applies.
        if gaps != ["mes_fw_version"] {
            return TestResult::Fail("the set of unimplemented bring-up steps has changed");
        }
        // Everything else names a builder, and the name is not empty.
        for s in CP_RESUME_ASYNC {
            match s.implemented {
                Implemented::By(b) if !b.is_empty() => {}
                Implemented::By(_) => return TestResult::Fail("a step names an empty builder"),
                Implemented::Missing(why) if !why.is_empty() => {}
                Implemented::Missing(_) => {
                    return TestResult::Fail("a missing step does not say what it needs")
                }
            }
            if s.linux_fn.is_empty() {
                return TestResult::Fail("a step does not name its Linux function");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/amdgpu/bringup", smoke_bringup_declared_gaps);
}
