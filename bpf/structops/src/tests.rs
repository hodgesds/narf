//! In-kernel smokes for contract-bound atomic struct-ops.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use narf_bpf::prog::{BpfProg, BpfProgLoad, LoadError, LoadMetadata, LoadRequest};
use narf_bpf_isa::encode::encode;
use narf_bpf_isa::{AluOp, CallTarget, Decoded, Insn, Reg, Size, Source};
use narf_bpf_verifier::kfunc::Context;
use narf_capabilities::{Cap, CapKind, CapType, Grant};
use narf_kernel_test::{kernel_test_in, TestResult};

fn load_cap() -> &'static Cap<BpfProgLoad, Grant> {
    use narf_lib::sync::IrqSafeSpinLock;
    static SLOT: IrqSafeSpinLock<Option<&'static Cap<BpfProgLoad, Grant>>> =
        IrqSafeSpinLock::new(None);
    let mut slot = SLOT.lock();
    if slot.is_none() {
        *slot = Some(Box::leak(Box::new(Cap::bootstrap())));
    }
    slot.expect("just installed")
}

fn r(number: u8) -> Reg {
    Reg::new(number).expect("register in range")
}

fn asm(items: &[Decoded]) -> Vec<Insn> {
    let mut out = Vec::new();
    for item in items {
        out.extend_from_slice(encode(*item).slots());
    }
    out
}

fn mov_imm(dst: u8, value: i32) -> Decoded {
    Decoded::Mov {
        wide: true,
        dst: r(dst),
        src: Source::Imm(value),
        sign_extend: None,
    }
}

fn ldx(dst: u8, src: u8, off: i16) -> Decoded {
    Decoded::Load {
        size: Size::Dw,
        sign_extend: false,
        dst: r(dst),
        src: r(src),
        off,
    }
}

fn alu_reg(op: AluOp, dst: u8, src: u8) -> Decoded {
    Decoded::Alu {
        wide: true,
        op,
        dst: r(dst),
        src: Source::Reg(r(src)),
    }
}

const EXIT: Decoded = Decoded::Exit;

fn request(name: &str, insns: Vec<Insn>, context: Context) -> LoadRequest {
    LoadRequest {
        name: String::from(name),
        insns,
        context,
        maps: Vec::new(),
        map_indices: Vec::new(),
        load_references: Vec::new(),
    }
}

fn fallback_select(_expected_idle_ns: u64) -> u32 {
    11
}

fn validate_select(raw: u64) -> Option<u32> {
    u32::try_from(raw).ok()
}

fn fallback_init() -> i32 {
    -7
}

fn validate_init(raw: u64) -> Option<i32> {
    i32::try_from(raw).ok()
}

crate::struct_ops! {
    /// Test target covering typed construction, lifecycle, and fallback.
    #[target("narf.test.DemoGovernor")]
    #[version(1)]
    #[cap(IdleGovernor)]
    #[install(install_bpf_demo_governor)]
    #[desc(DEMO_GOVERNOR_OPS)]
    #[adapter(BpfDemoGovernor)]
    #[builder(BpfDemoGovernorPrograms)]
    #[commit(commit_demo_governor)]
    #[detach(detach_demo_governor)]
    #[optional(init)]
    pub trait DemoGovernor {
        /// Pick an idle state.
        #[fallback(fallback_select)]
        #[validate(validate_select)]
        #[fuel(32)]
        #[kfuncs()]
        fn select_state(&self, expected_idle_ns: u64) -> u32;

        /// Optional setup operation.
        #[fallback(fallback_init)]
        #[validate(validate_init)]
        #[fuel(16)]
        #[kfuncs()]
        fn init(&self) -> i32;
    }
}

struct NativeDemoGovernor;

impl DemoGovernor for NativeDemoGovernor {
    fn select_state(&self, expected_idle_ns: u64) -> u32 {
        if expected_idle_ns > 1_000_000 {
            2
        } else {
            0
        }
    }

    fn init(&self) -> i32 {
        0
    }
}

struct LiveEntry {
    generation: u64,
    governor: Arc<dyn DemoGovernor>,
}

static LIVE_GOVERNOR: narf_lib::sync::IrqSafeSpinLock<Option<LiveEntry>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

fn commit_demo_governor<M: CapType>(
    cap: &Cap<M, Grant>,
    generation: u64,
    governor: Arc<BpfDemoGovernor>,
) -> Result<(), crate::structops::StructOpsError> {
    cap.check_live()?;
    let next = LiveEntry {
        generation,
        governor,
    };
    let old = {
        let mut slot = LIVE_GOVERNOR.lock();
        slot.replace(next)
    };
    drop(old);
    Ok(())
}

fn detach_demo_governor(generation: u64) -> bool {
    let old = {
        let mut slot = LIVE_GOVERNOR.lock();
        if slot
            .as_ref()
            .is_some_and(|entry| entry.generation == generation)
        {
            slot.take()
        } else {
            return false;
        }
    };
    drop(old);
    true
}

fn live_select(expected_idle_ns: u64) -> Option<u32> {
    let governor = LIVE_GOVERNOR
        .lock()
        .as_ref()
        .map(|entry| entry.governor.clone());
    governor.map(|governor| governor.select_state(expected_idle_ns))
}

struct LockObservingGovernor {
    dropped_outside_lock: Arc<AtomicBool>,
}

impl DemoGovernor for LockObservingGovernor {
    fn select_state(&self, _expected_idle_ns: u64) -> u32 {
        if LIVE_GOVERNOR.try_lock().is_some() {
            77
        } else {
            0
        }
    }

    fn init(&self) -> i32 {
        0
    }
}

impl Drop for LockObservingGovernor {
    fn drop(&mut self) {
        self.dropped_outside_lock
            .store(LIVE_GOVERNOR.try_lock().is_some(), Ordering::Release);
    }
}

#[derive(Copy, Clone, Debug)]
struct IdleGovInstall;

impl CapType for IdleGovInstall {
    const KIND: CapKind = CapKind::IdleGovernor;
}

fn smoke_bpf_structops_native_impl_still_works() -> TestResult {
    let governor = NativeDemoGovernor;
    if governor.select_state(10) != 0
        || governor.select_state(2_000_000) != 2
        || governor.init() != 0
    {
        return TestResult::Fail("native impl of a struct_ops trait misbehaved");
    }
    TestResult::Pass
}
kernel_test_in!("bpf/structops", smoke_bpf_structops_native_impl_still_works);

fn smoke_bpf_structops_descriptor_is_complete() -> TestResult {
    let Some(desc) = crate::structops::descriptors()
        .iter()
        .find(|desc| desc.target == "narf.test.DemoGovernor")
    else {
        return TestResult::Fail("descriptor was not linked");
    };
    if desc.version != 1 || desc.cap != CapKind::IdleGovernor || desc.methods.len() != 2 {
        return TestResult::Fail("target metadata is incomplete");
    }
    let method = &desc.methods[0];
    if method.ctx.len() != 1
        || !method.allowed_kfuncs.is_empty()
        || method.context != Context::Atomic
        || method.fuel != 32
        || method.fallback != "fallback_select"
        || method.optional
        || !desc.methods[1].optional
    {
        return TestResult::Fail("method contract metadata is incomplete");
    }
    TestResult::Pass
}
kernel_test_in!("bpf/structops", smoke_bpf_structops_descriptor_is_complete);

fn smoke_bpf_structops_builder_and_link_lifetime() -> TestResult {
    let cap = Cap::<IdleGovInstall, Grant>::bootstrap();
    let programs = match BpfDemoGovernorPrograms::new().select_state(
        load_cap(),
        request(
            "demo_double",
            asm(&[ldx(0, 1, 0), alu_reg(AluOp::Add, 0, 0), EXIT]),
            Context::Atomic,
        ),
    ) {
        Ok(programs) => programs,
        Err(_) => return TestResult::Fail("method-specific load was rejected"),
    };
    let link = match install_bpf_demo_governor(&cap, programs) {
        Ok(link) => link,
        Err(_) => return TestResult::Fail("complete typed builder was rejected"),
    };
    if live_select(21) != Some(42) || !crate::structops::is_installed("DemoGovernor") {
        return TestResult::Fail("installed program did not reach the live slot");
    }
    link.close();
    if live_select(21).is_some() || crate::structops::is_installed("DemoGovernor") {
        return TestResult::Fail("dropping the owning link did not detach");
    }
    TestResult::Pass
}
kernel_test_in!(
    "bpf/structops",
    smoke_bpf_structops_builder_and_link_lifetime
);

fn smoke_bpf_structops_generation_prevents_stale_detach() -> TestResult {
    let cap = Cap::<IdleGovInstall, Grant>::bootstrap();
    let first = BpfDemoGovernorPrograms::new()
        .select_state(
            load_cap(),
            request("demo_one", asm(&[mov_imm(0, 1), EXIT]), Context::Atomic),
        )
        .and_then(|programs| {
            install_bpf_demo_governor(&cap, programs).map_err(|_| LoadError::BadStructOpsContract)
        });
    let Ok(first) = first else {
        return TestResult::Fail("first generation failed to install");
    };
    let second_programs = match BpfDemoGovernorPrograms::new().select_state(
        load_cap(),
        request("demo_two", asm(&[mov_imm(0, 2), EXIT]), Context::Atomic),
    ) {
        Ok(programs) => programs,
        Err(_) => return TestResult::Fail("second generation failed to load"),
    };
    let second = match install_bpf_demo_governor(&cap, second_programs) {
        Ok(link) => link,
        Err(_) => return TestResult::Fail("second generation failed to install"),
    };
    drop(first);
    if live_select(0) != Some(2) {
        return TestResult::Fail("stale link detached its replacement");
    }
    drop(second);
    TestResult::Pass
}
kernel_test_in!(
    "bpf/structops",
    smoke_bpf_structops_generation_prevents_stale_detach
);

fn smoke_bpf_structops_live_slot_releases_lock() -> TestResult {
    let dropped_outside_lock = Arc::new(AtomicBool::new(false));
    let entry = LiveEntry {
        generation: u64::MAX,
        governor: Arc::new(LockObservingGovernor {
            dropped_outside_lock: dropped_outside_lock.clone(),
        }),
    };
    let previous = LIVE_GOVERNOR.lock().replace(entry);
    drop(previous);
    if live_select(0) != Some(77) {
        return TestResult::Fail("callback ran while the live-slot lock was held");
    }
    let removed = LIVE_GOVERNOR.lock().take();
    drop(removed);
    if !dropped_outside_lock.load(Ordering::Acquire) {
        return TestResult::Fail("displaced adapter was destroyed under the live-slot lock");
    }
    TestResult::Pass
}
kernel_test_in!("bpf/structops", smoke_bpf_structops_live_slot_releases_lock);

fn smoke_bpf_structops_rejects_wrong_cap_and_missing_method() -> TestResult {
    let right = Cap::<IdleGovInstall, Grant>::bootstrap();
    match install_bpf_demo_governor(&right, BpfDemoGovernorPrograms::new()) {
        Err(crate::structops::StructOpsError::MissingMethod("select_state")) => {}
        _ => return TestResult::Fail("missing required method was accepted"),
    }

    let programs = match BpfDemoGovernorPrograms::new().select_state(
        load_cap(),
        request("demo_cap", asm(&[mov_imm(0, 1), EXIT]), Context::Atomic),
    ) {
        Ok(programs) => programs,
        Err(_) => return TestResult::Fail("valid program failed to load"),
    };
    let wrong = Cap::<BpfProgLoad, Grant>::bootstrap();
    match install_bpf_demo_governor(&wrong, programs) {
        Err(crate::structops::StructOpsError::WrongCapability { .. }) => {}
        _ => return TestResult::Fail("wrong capability kind was accepted"),
    }
    if live_select(0).is_some() {
        return TestResult::Fail("rejected install touched the live slot");
    }
    TestResult::Pass
}
kernel_test_in!(
    "bpf/structops",
    smoke_bpf_structops_rejects_wrong_cap_and_missing_method
);

fn smoke_bpf_structops_rejects_generic_and_sleepable_programs() -> TestResult {
    let generic = match BpfProg::load(
        load_cap(),
        request("generic", asm(&[mov_imm(0, 1), EXIT]), Context::Atomic),
    ) {
        Ok(program) => program,
        Err(_) => return TestResult::Fail("generic control program failed to load"),
    };
    let method = &DEMO_GOVERNOR_OPS.methods[0];
    let mut set = crate::structops::ProgSet::default();
    set.bind(method.id, generic);
    let cap = Cap::<IdleGovInstall, Grant>::bootstrap();
    match crate::structops::validate(&DEMO_GOVERNOR_OPS, &cap, &set) {
        Err(crate::structops::StructOpsError::WrongProgram("select_state")) => {}
        _ => return TestResult::Fail("generic program matched a method contract"),
    }

    let xdp = match BpfProg::load_for_xdp(
        load_cap(),
        request("xdp", asm(&[mov_imm(0, 1), EXIT]), Context::Atomic),
    ) {
        Ok(program) => program,
        Err(_) => return TestResult::Fail("XDP control program failed to load"),
    };
    let mut set = crate::structops::ProgSet::default();
    set.bind(method.id, xdp);
    if !matches!(
        crate::structops::validate(&DEMO_GOVERNOR_OPS, &cap, &set),
        Err(crate::structops::StructOpsError::WrongProgram(
            "select_state"
        ))
    ) {
        return TestResult::Fail("XDP program matched a method contract");
    }

    let tracing = match BpfProg::load_with_metadata(
        load_cap(),
        request("tracing", asm(&[mov_imm(0, 1), EXIT]), Context::Atomic),
        LoadMetadata {
            linux_prog_type: Some(17),
            ..LoadMetadata::default()
        },
    ) {
        Ok(program) => program,
        Err(_) => return TestResult::Fail("tracing control program failed to load"),
    };
    let mut set = crate::structops::ProgSet::default();
    set.bind(method.id, tracing);
    if !matches!(
        crate::structops::validate(&DEMO_GOVERNOR_OPS, &cap, &set),
        Err(crate::structops::StructOpsError::WrongProgram(
            "select_state"
        ))
    ) {
        return TestResult::Fail("tracing program matched a method contract");
    }

    let init = &DEMO_GOVERNOR_OPS.methods[1];
    let wrong_method = match BpfProg::load_for_struct_ops(
        load_cap(),
        request("wrong_method", asm(&[mov_imm(0, 1), EXIT]), Context::Atomic),
        init.contract(DEMO_GOVERNOR_OPS.target_id),
    ) {
        Ok(program) => program,
        Err(_) => return TestResult::Fail("second method contract failed to load"),
    };
    let mut set = crate::structops::ProgSet::default();
    set.bind(method.id, wrong_method);
    if !matches!(
        crate::structops::validate(&DEMO_GOVERNOR_OPS, &cap, &set),
        Err(crate::structops::StructOpsError::WrongProgram(
            "select_state"
        ))
    ) {
        return TestResult::Fail("program loaded for another method was accepted");
    }

    match BpfDemoGovernorPrograms::new().select_state(
        load_cap(),
        request("sleepable", asm(&[mov_imm(0, 1), EXIT]), Context::Sleepable),
    ) {
        Err(LoadError::StructOpsRequiresAtomic) => {}
        _ => return TestResult::Fail("sleepable program loaded for an atomic target"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "bpf/structops",
    smoke_bpf_structops_rejects_generic_and_sleepable_programs
);

fn smoke_bpf_structops_kfunc_allowlist_is_closed() -> TestResult {
    let call = Decoded::Call(CallTarget::Kfunc(narf_bpf::kfunc::id_for(
        "narf_counter_add",
    )));
    if BpfDemoGovernorPrograms::new()
        .select_state(
            load_cap(),
            request("forbidden_call", asm(&[call, EXIT]), Context::Atomic),
        )
        .is_ok()
    {
        return TestResult::Fail("method loaded a kfunc outside its allowlist");
    }
    TestResult::Pass
}
kernel_test_in!(
    "bpf/structops",
    smoke_bpf_structops_kfunc_allowlist_is_closed
);

fn smoke_bpf_structops_invalid_result_and_fuel_use_fallback() -> TestResult {
    let cap = Cap::<IdleGovInstall, Grant>::bootstrap();
    let invalid = match BpfDemoGovernorPrograms::new().select_state(
        load_cap(),
        request(
            "invalid_result",
            asm(&[mov_imm(0, -1), EXIT]),
            Context::Atomic,
        ),
    ) {
        Ok(programs) => programs,
        Err(_) => return TestResult::Fail("invalid-result program failed to load"),
    };
    let invalid_link = match install_bpf_demo_governor(&cap, invalid) {
        Ok(link) => link,
        Err(_) => return TestResult::Fail("invalid-result program failed to install"),
    };
    if live_select(1) != Some(11) {
        return TestResult::Fail("invalid raw result did not use the fallback");
    }
    drop(invalid_link);

    let mut long = Vec::new();
    for value in 0..40 {
        long.push(mov_imm(0, value));
    }
    long.push(EXIT);
    let fuel = match BpfDemoGovernorPrograms::new()
        .select_state(load_cap(), request("fuel", asm(&long), Context::Atomic))
    {
        Ok(programs) => programs,
        Err(_) => return TestResult::Fail("fuel test program failed to load"),
    };
    let fuel_link = match install_bpf_demo_governor(&cap, fuel) {
        Ok(link) => link,
        Err(_) => return TestResult::Fail("fuel test program failed to install"),
    };
    if live_select(1) != Some(11) {
        return TestResult::Fail("fuel exhaustion did not use the fallback");
    }
    drop(fuel_link);
    TestResult::Pass
}
kernel_test_in!(
    "bpf/structops",
    smoke_bpf_structops_invalid_result_and_fuel_use_fallback
);

fn smoke_bpf_structops_optional_method_uses_declared_fallback() -> TestResult {
    let cap = Cap::<IdleGovInstall, Grant>::bootstrap();
    let programs = match BpfDemoGovernorPrograms::new().select_state(
        load_cap(),
        request("optional", asm(&[mov_imm(0, 3), EXIT]), Context::Atomic),
    ) {
        Ok(programs) => programs,
        Err(_) => return TestResult::Fail("program failed to load"),
    };
    let link = match install_bpf_demo_governor(&cap, programs) {
        Ok(link) => link,
        Err(_) => return TestResult::Fail("program failed to install"),
    };
    let governor = LIVE_GOVERNOR
        .lock()
        .as_ref()
        .map(|entry| entry.governor.clone());
    if governor.as_ref().map(|governor| governor.init()) != Some(-7) {
        return TestResult::Fail("optional method did not use its declared fallback");
    }
    drop(link);
    TestResult::Pass
}
kernel_test_in!(
    "bpf/structops",
    smoke_bpf_structops_optional_method_uses_declared_fallback
);
