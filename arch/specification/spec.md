# arch — Specification

> Status: **v1.0** (Stage 2 design lock). v0.2 split DomainPrimitive
> into a backend-aware trait; v1.0 locks the MSR/system-register
> access policy, the crate layout, the canonical idle primitive
> (`idle_halt_then_disable`), the per-arch MMIO discipline, and
> the SDK ABI versioning policy.

## 1. Purpose & scope

**Owns:** The Rust trait surface that abstracts CPU, MMU, interrupt
controller, timer, and cache operations. Per-arch crates (`arch-x86_64`,
`arch-aarch64`) implement the traits.

**Does NOT own:** Policy (who gets which domain, which IRQ goes where).
That lives in `frame/`, `memory/`, `interrupts/`.

## 2. Assumptions

- Boot environment hands control to the kernel with MMU either off or in
  a known identity-mapped state (see `boot/`).
- Exactly one arch backend is linked at build time; `#[cfg(target_arch)]`
  selects it.

## 3. Public interface

`access_user_u64_guarded(address, write)` performs one aligned atomic user
qword access: `None` loads with acquire ordering, `Some(value)` stores with
release ordering and returns that value. The unsafe caller validates the
entire user range and owns the active syscall address space. Racing unmaps
and unrecoverable page faults return `Err`; misalignment is rejected before
access. The helper uses the existing per-CPU probe and IRQ restoration
contract, including re-resolving the CPU after a healed x86 page fault.
It never substitutes byte copies or a modifying operation for a load.

Sketched shape:

```rust
pub trait Cpu {
    fn halt() -> !;
    fn current_cpu() -> CpuId;
    unsafe fn enable_interrupts();
    unsafe fn disable_interrupts();
    fn feature_flags() -> FeatureFlags; // PKS, PKU, UIPI, MTE, PAC, ...
}

pub trait Mmu { /* map, unmap, tlb ops; base + huge page sizes */ }
pub trait IntCtrl { /* configure, mask, send_ipi, eoi */ }
pub trait Timer { /* read_counter, set_oneshot_ns */ }

/// Domain-rights primitive. The backends are NOT interchangeable —
/// see §4 and §5. Callers MUST use `DomainPrimitive::BACKEND` to
/// decide whether a single-instruction rights flip is available.
pub trait DomainPrimitive {
    const BACKEND: DomainBackend;     // Pks | Mte
    type SavedState: Copy;

    /// Read the live domain-rights state on this CPU into `out`.
    unsafe fn save() -> Self::SavedState;

    /// Restore `s` to the live domain-rights state on this CPU.
    /// Must serialise with respect to subsequent loads / stores.
    unsafe fn restore(s: Self::SavedState);

    /// Rights-flip helper. On PKS this is a single `WRMSR IA32_PKRS`.
    /// On MTE there is no equivalent — the function reconfigures
    /// `SCTLR_EL1.TCF` and relies on pointer-tag discipline for the
    /// actual access check. Callers must not treat the two as
    /// performance-equivalent.
    unsafe fn set_rights(domain: u8, rights: Self::Rights);

    unsafe fn enter_domain(frame: u8, target: u8) -> Self::SavedState;
    unsafe fn exit_domain(saved: Self::SavedState);
}

pub enum DomainBackend { Pks, Mte }

/// Architecture-owned trap ABI. `frame` materialises this exact layout in
/// assembly and the executor receives only a typed reference when deciding
/// whether to preempt. Neither crate keeps a mirror definition.
#[cfg(target_arch = "x86_64")]
pub struct x86_64::trap_frame::TrapFrame { /* domain prefix, GPRs, return frame */ }
#[cfg(target_arch = "aarch64")]
pub struct aarch64::trap_frame::TrapFrame { /* MTE prefix, GPRs, SP_EL0, ELR/SPSR, FP/SIMD image */ }

/// Architecture-owned continuation state used only by the executor core.
/// Domain state is an opaque tail saved/restored by `kernel_switch`, before
/// any outgoing-context store and after the last incoming-context load.
/// Policy crates never receive this type or the switch entry point.
#[cfg(target_arch = "x86_64")]
pub struct x86_64::kernel_ctx::KernelContext {
    /* callee-saved GPRs, RSP, RIP, RFLAGS, opaque PKRS-or-CR3 state */
}
#[cfg(target_arch = "aarch64")]
pub struct aarch64::kernel_ctx::KernelContext {
    /* x19-x29, SP, PC, DAIF, opaque SCTLR/GCR state */
}
#[cfg(target_arch = "x86_64")]
pub unsafe extern "C" fn x86_64::kernel_ctx::kernel_switch(
    out: *mut x86_64::kernel_ctx::KernelContext,
    incoming: *const x86_64::kernel_ctx::KernelContext,
);
#[cfg(target_arch = "aarch64")]
pub unsafe extern "C" fn aarch64::kernel_ctx::kernel_switch(
    out: *mut aarch64::kernel_ctx::KernelContext,
    incoming: *const aarch64::kernel_ctx::KernelContext,
);

/// True only while the executing CPU owns a guarded kernel-user copy probe.
/// Trap handlers use this to forbid reclaim parking until fixup/disarm.
#[cfg(target_arch = "x86_64")]
pub fn x86_64::smap::guarded_copy_armed() -> bool;
#[cfg(target_arch = "aarch64")]
pub fn aarch64::uaccess::guarded_copy_armed() -> bool;

/// AArch64 EL0 FP/SIMD image: Q0-Q31 followed by FPCR and FPSR.
#[cfg(target_arch = "aarch64")]
pub struct aarch64::UserFpState { /* 528 bytes, 16-byte aligned */ }
#[cfg(target_arch = "aarch64")]
pub unsafe fn aarch64::save_user_fp_state(state: *mut u8);
#[cfg(target_arch = "aarch64")]
pub unsafe fn aarch64::restore_user_fp_state(state: *const u8);
/// GIC CPU-interface intrinsics used by `interrupts::aarch64`. GICv3:
/// `ICC_*_EL1` system registers (valid only when
/// `Features::gicv3_sysreg`). GICv2: memory-mapped `GICC`, through the
/// fenced MMIO accessors. All of them are bracketed by
/// `compiler_fence(SeqCst)` (§4).
#[cfg(target_arch = "aarch64")]
pub struct aarch64::Features { pub gicv3_sysreg: bool, /* ... */ }
#[cfg(target_arch = "aarch64")]
pub unsafe fn aarch64::sysreg::{read_icc_iar1_el1, write_icc_eoir1_el1,
    write_icc_sre_el1, write_icc_pmr_el1, write_icc_igrpen1_el1,
    write_icc_sgi1r_el1};
#[cfg(target_arch = "aarch64")]
pub unsafe fn aarch64::mmio::{read_u32, write_u32, read_u8, write_u8};
#[cfg(target_arch = "aarch64")]
pub unsafe fn aarch64::sysreg::read_ttbr0_el1() -> u64;
#[cfg(target_arch = "aarch64")]
pub unsafe fn aarch64::sysreg::write_ttbr0_el1(value: u64);

/// Full-register SMCCC conduit (DEN0028E §2.6) for SiP firmware services
/// that use more than `x0..x3` (Qualcomm SCM: `x1` arginfo, `x2..x5`
/// values, `x6` session word returned on a retried call). `regs` carries
/// `x0..x7` in and out; `x8..x17` are clobbered; the asm is not `nomem`
/// and is bracketed by `compiler_fence(SeqCst)` (§4). `psci::smc`/`hvc`
/// remain the 4-register PSCI helpers.
#[cfg(target_arch = "aarch64")]
pub mod aarch64::smccc {
    pub const FAST_CALL: u32;   // x0 bit 31
    pub const SMC64: u32;       // x0 bit 30
    pub const OWNER_SHIFT: u32; // 24
    pub const OWNER_CPU: u32;
    pub const OWNER_SIP: u32;
    pub const OWNER_STANDARD: u32;
    pub const fn call_val(fast: bool, smc64: bool, owner: u32, function: u32) -> u32;
    pub unsafe fn smc_call(regs: &mut [u64; 8]);
    pub unsafe fn hvc_call(regs: &mut [u64; 8]);
}

/// FSGSBASE is enabled independently on every supporting CPU before EL0 runs.
/// The accessors use RDFSBASE/WRFSBASE only when the current CPU's CR4 cache
/// confirms the enable bit and otherwise use the architectural MSR fallback.
#[cfg(target_arch = "x86_64")]
pub fn x86_64::user_mode::fsgsbase_supported() -> bool;
#[cfg(target_arch = "x86_64")]
pub unsafe fn x86_64::user_mode::enable_fsgsbase();
#[cfg(target_arch = "x86_64")]
pub unsafe fn x86_64::user_mode::user_fs_base() -> u64;
#[cfg(target_arch = "x86_64")]
pub unsafe fn x86_64::user_mode::user_fs_base_for_cpu(cpu: usize) -> u64;
// `cpu` must identify the executing CPU; this form reuses a pinned caller's id.
#[cfg(target_arch = "x86_64")]
pub unsafe fn x86_64::user_mode::set_user_fs_base(fs_base: u64);

/// User protection keys are enabled only on CPUs that advertise CPUID.PKU.
/// The PKRU register is task state, distinct from supervisor PKRS domain state.
#[cfg(target_arch = "x86_64")]
pub fn x86_64::pku::supported() -> bool;
#[cfg(target_arch = "x86_64")]
pub fn x86_64::pku::enabled() -> bool;
#[cfg(target_arch = "x86_64")]
pub unsafe fn x86_64::pku::enable_current_cpu() -> bool;
#[cfg(target_arch = "x86_64")]
pub unsafe fn x86_64::pku::read() -> u32;
#[cfg(target_arch = "x86_64")]
pub unsafe fn x86_64::pku::write(value: u32);

/// Process PCIDs are independent of the PKS/PCID domain backend. Boot calls
/// `enable_pcide` on every CPU, then closes the global gate after SMP discovery.
#[cfg(target_arch = "x86_64")]
pub unsafe fn x86_64::pcid::enable_pcide();
#[cfg(target_arch = "x86_64")]
pub fn x86_64::pcid::finalize_process_pcid(online_cpu_mask: u64);
#[cfg(target_arch = "x86_64")]
pub fn x86_64::pcid::process_pcid_ready() -> bool;
#[cfg(target_arch = "x86_64")]
pub fn x86_64::pcid::process_pcid_cpu_count() -> u64;

/// EL0 entry/resume variants that first abandon the current EL1 frames and
/// reset SP_EL1 to the supplied per-task kernel-stack top.
#[cfg(target_arch = "aarch64")]
pub unsafe extern "C" fn aarch64::enter_user_mode_at_top(
    pc: u64, user_sp: u64, kernel_stack_top: u64,
) -> !;
#[cfg(target_arch = "aarch64")]
pub unsafe extern "C" fn aarch64::enter_user_mode_with_arg_at_top(
    pc: u64, user_sp: u64, arg: u64, kernel_stack_top: u64,
) -> !;
#[cfg(target_arch = "aarch64")]
pub unsafe extern "C" fn aarch64::enter_user_mode_resume_at_top(
    state: *const aarch64::UserState, kernel_stack_top: u64,
) -> !;

/// Current-CPU speculative-execution policy. Remote changes require an
/// IPI/rendezvous that executes this function on the target CPU.
pub enum speculation::Policy { Disabled, Protected }
pub enum speculation::State {
    Unconfigured, Disabled, Protected, Unsupported, Failed,
}
pub unsafe fn speculation::configure_current_cpu(
    policy: speculation::Policy,
) -> speculation::State;
pub fn speculation::state(cpu: usize) -> speculation::State;

#[cfg(target_arch = "x86_64")]
pub unsafe fn pmu::alloc_counter_filtered(
    event: pmu::PmuEvent,
    os: bool,
    usr: bool,
) -> Result<pmu::PmuCounter, pmu::PmuError>;
#[cfg(target_arch = "x86_64")]
pub unsafe fn pmu::arm_sampling(
    counter: &pmu::PmuCounter,
    period: u64,
) -> Result<(), pmu::PmuError>;
pub unsafe fn pmu::arm_sampling_with_reload(
    counter: &pmu::PmuCounter,
    initial_period: u64,
    reload_period: u64,
) -> Result<(), pmu::PmuError>;
pub unsafe fn pmu::sampling_period_left(
    counter: &pmu::PmuCounter,
) -> Result<u64, pmu::PmuError>;
#[cfg(target_arch = "x86_64")]
pub unsafe fn pmu::handle_sampling_overflow() -> u8;
#[cfg(target_arch = "x86_64")]
pub unsafe fn pmu::pause_sampling(
    counter: &pmu::PmuCounter,
) -> Result<(), pmu::PmuError>;
#[cfg(target_arch = "x86_64")]
pub fn pmu::update_sampling_period(counter: &pmu::PmuCounter, period: u64);
#[cfg(target_arch = "x86_64")]
pub fn pmu::last_overflow_period(cpu: usize, counter: usize) -> u64;
#[cfg(target_arch = "x86_64")]
pub unsafe fn pmi::program_current_lvt_pc(vector: u8, masked: bool);

#[cfg(target_arch = "aarch64")]
pub unsafe fn pmu::alloc_cycle_counter() -> Result<pmu::CycleCounter, pmu::PmuError>;
#[cfg(target_arch = "aarch64")]
pub unsafe fn pmu::alloc_cycle_counter_filtered(
    kernel: bool,
    user: bool,
) -> Result<pmu::CycleCounter, pmu::PmuError>;
#[cfg(target_arch = "aarch64")]
pub unsafe fn pmu::alloc_programmable_filtered(
    event: u16,
    kernel: bool,
    user: bool,
) -> Result<pmu::ProgrammableCounter, pmu::PmuError>;
#[cfg(target_arch = "aarch64")]
pub unsafe fn pmu::start(
    counter: &pmu::CycleCounter,
) -> Result<(), pmu::PmuError>;
#[cfg(target_arch = "aarch64")]
pub unsafe fn pmu::arm_sampling(
    counter: &pmu::CycleCounter,
    period: u64,
) -> Result<(), pmu::PmuError>;
pub unsafe fn pmu::arm_sampling_with_reload(
    counter: &pmu::CycleCounter,
    initial_period: u64,
    reload_period: u64,
) -> Result<(), pmu::PmuError>;
#[cfg(target_arch = "aarch64")]
pub unsafe fn pmu::sampling_period_left(
    counter: &pmu::CycleCounter,
) -> Result<u64, pmu::PmuError>;
#[cfg(target_arch = "aarch64")]
pub unsafe fn pmu::handle_sampling_overflow() -> bool;
#[cfg(target_arch = "aarch64")]
pub fn pmu::update_sampling_period(counter: &pmu::CycleCounter, period: u64);
#[cfg(target_arch = "aarch64")]
pub fn pmu::last_overflow_period(cpu: usize) -> u64;
#[cfg(target_arch = "aarch64")]
pub unsafe fn pmu::pause_sampling(
    counter: &pmu::CycleCounter,
) -> Result<(), pmu::PmuError>;
#[cfg(target_arch = "aarch64")]
pub const fn pmu::minimum_sample_period() -> u64;
#[cfg(target_arch = "aarch64")]
pub fn pmu::programmable_counter_count() -> u8;
#[cfg(target_arch = "aarch64")]
pub fn pmu::event_supported(event: u16) -> bool;
#[cfg(target_arch = "aarch64")]
pub unsafe fn pmu::alloc_programmable(
    event: u16,
) -> Result<pmu::ProgrammableCounter, pmu::PmuError>;
#[cfg(target_arch = "aarch64")]
pub unsafe fn pmu::read_programmable(
    counter: &pmu::ProgrammableCounter,
) -> Result<u64, pmu::PmuError>;
#[cfg(target_arch = "aarch64")]
pub unsafe fn pmu::start_programmable(
    counter: &pmu::ProgrammableCounter,
) -> Result<(), pmu::PmuError>;
#[cfg(target_arch = "aarch64")]
pub unsafe fn pmu::arm_programmable(
    counter: &pmu::ProgrammableCounter,
    period: u64,
) -> Result<(), pmu::PmuError>;
#[cfg(target_arch = "aarch64")]
pub unsafe fn pmu::arm_programmable_with_reload(
    counter: &pmu::ProgrammableCounter,
    initial_period: u64,
    reload_period: u64,
) -> Result<(), pmu::PmuError>;
#[cfg(target_arch = "aarch64")]
pub unsafe fn pmu::programmable_period_left(
    counter: &pmu::ProgrammableCounter,
) -> Result<u64, pmu::PmuError>;
#[cfg(target_arch = "aarch64")]
pub unsafe fn pmu::handle_programmable_overflows() -> u32;
#[cfg(target_arch = "aarch64")]
pub fn pmu::update_programmable_period(
    counter: &pmu::ProgrammableCounter,
    period: u64,
);
#[cfg(target_arch = "aarch64")]
pub fn pmu::programmable_period(cpu: usize, counter: usize) -> u64;
#[cfg(target_arch = "aarch64")]
pub unsafe fn pmu::pause_programmable(
    counter: &pmu::ProgrammableCounter,
) -> Result<(), pmu::PmuError>;
#[cfg(target_arch = "aarch64")]
pub unsafe fn pmu::release_programmable(
    counter: pmu::ProgrammableCounter,
) -> Result<(), pmu::PmuError>;

#[cfg(target_arch = "x86_64")]
pub mod amd_pstate {
    pub const MSR_AMD_CPPC_CAP1: u32 = 0xC001_02B0;
    pub const MSR_AMD_CPPC_ENABLE: u32 = 0xC001_02B1;
    pub const MSR_AMD_CPPC_CAP2: u32 = 0xC001_02B2;
    pub const MSR_AMD_CPPC_REQ: u32 = 0xC001_02B3;
    pub const MSR_AMD_CPPC_STATUS: u32 = 0xC001_02B4;

    pub fn read_caps() -> Option<Result<CppcCaps, MsrFault>>;
    pub fn read_status() -> Option<Result<u8, MsrFault>>;
pub fn amd_pstate_request(
        min_perf: u8,
        max_perf: u8,
        desired_perf: u8,
        epp: u8,
    ) -> Option<Result<(), MsrFault>>;
}

#[cfg(target_arch = "x86_64")]
pub mod cr {
    pub const CR0_TS: u64;
    pub const CR0_NW: u64;
    pub const CR0_CD: u64;
    pub const CR4_PGE: u64;
    pub unsafe fn read_cr0() -> u64;
    pub unsafe fn write_cr0(value: u64);
    pub unsafe fn set_task_switched();
    pub unsafe fn clear_task_switched();
}

/// Page Attribute Table, mirroring Linux `pat_bp_init` / `pat_cpu_init` /
/// `init_cache_modes` and the `cache_disable` / `cache_enable` sequence.
#[cfg(target_arch = "x86_64")]
pub mod pat {
    pub const MSR_IA32_PAT: u32 = 0x277;
    /// Linux full layout PAT_VALUE(WB, WC, UC_MINUS, UC, WB, WP, UC_MINUS, WT).
    pub const NARF_PAT: u64 = 0x0407_0506_0007_0106;
    /// Pentium Pro..M / Pentium 4 errata layout (PAT bit unused).
    pub const NARF_PAT_ERRATA: u64 = 0x0007_0106_0007_0106;
    /// Emulated table while PAT is disabled (WB, WT, UC-, UC).
    pub const PAT_DISABLED_EMULATION: u64 = 0x0007_0406_0007_0406;
    pub const PTE_PWT: u64; pub const PTE_PCD: u64;
    pub const PTE_PAT_4K: u64;    // bit 7
    pub const PTE_PAT_LARGE: u64; // bit 12
    pub enum CacheMode { Wb, Wc, UcMinus, Uc, Wt, Wp }
    pub enum PatError { Disabled, UnsupportedOnThisCpu, WriteFaulted, ReadbackMismatch }
    pub fn supported() -> bool;
    pub fn enabled() -> bool;
    pub fn programmed_value() -> u64;
    pub fn read() -> u64;
    /// Boot CPU, before APs: choose the layout, fill the cache-mode table,
    /// program this CPU. `Err(Disabled)` leaves WC degrading to UC-.
    pub unsafe fn bp_init() -> Result<(), PatError>;
    /// Every CPU (each AP at bring-up, the BSP again after S3): write the
    /// chosen value under CR0.CD=1 + WBINVD (unless self-snoop) + PGE-clear
    /// TLB flush, IRQs masked, then flush all TLB entries and require matching
    /// IA32_PAT readback. No-op if disabled.
    pub unsafe fn cpu_init() -> Result<(), PatError>;
    /// IA32_PAT read back on `cpu` after its last `cpu_init` (0 = never).
    pub fn recorded_cpu_value(cpu: usize) -> u64;
    /// Linux `cachemode2protval` for a 4 KiB leaf under the programmed
    /// layout; missing modes degrade to UC-. WB is always 0.
    pub fn cachemode2pte(mode: CacheMode) -> u64;
    pub const fn pte_bits_for(pat: u64, mode: CacheMode) -> u64;
    pub const fn protval_4k_2_large(bits: u64) -> u64;
    pub const fn protval_large_2_4k(bits: u64) -> u64;
    pub const fn encode(pa: [u8; 8]) -> u64;
    pub const fn slot_type(pat: u64, index: u32) -> u8;
}

/// MAIR_EL1 layout programmed by frame boot.S (BSP) and smp_entry.S (APs).
#[cfg(target_arch = "aarch64")]
pub mod mair {
    pub const MAIR_ATTR_NORMAL: u64 = 0xFF;
    pub const MAIR_ATTR_DEVICE_NGNRE: u64 = 0x04;
    pub const MAIR_ATTR_NORMAL_TAGGED: u64 = 0xF0;
    pub const MAIR_ATTR_NORMAL_NC: u64 = 0x44;
    pub const MAIR_ATTR_DEVICE_NGNRNE: u64 = 0x00;
    pub const ATTR_IDX_NORMAL: u64 = 0;
    pub const ATTR_IDX_DEVICE_NGNRE: u64 = 1;
    pub const ATTR_IDX_NORMAL_TAGGED: u64 = 2;
    pub const ATTR_IDX_NORMAL_NC: u64 = 3;
    pub const ATTR_IDX_DEVICE_NGNRNE: u64 = 4;
    pub const MAIR_EL1_VALUE: u64 = 0x44F0_04FF;
    pub const fn attridx(attr: u64, idx: u64) -> u64;
    pub const fn attr_at(mair: u64, idx: u64) -> u64;
}
#[cfg(target_arch = "aarch64")]
pub unsafe fn aarch64::sysreg::read_mair_el1() -> u64;

#[cfg(target_arch = "x86_64")]
pub mod xsave {
    /// Selects x87/SSE/AVX/AVX-512/PKRU dependencies as complete groups;
    /// deliberately excludes opt-in AMX state.
    pub const fn default_xcr0_mask(supported: u64) -> u64;

    /// Standard-format bytes required by exactly `mask`, derived from
    /// CPUID.(0Dh,n) component offsets rather than the all-supported size.
    pub fn area_size_for_mask(mask: u64) -> usize;

    /// Select the fixed-size per-task save mask and standard-format save
    /// instruction once at boot. XSAVEOPT is selected only when advertised;
    /// otherwise task images use XSAVE, with FXSAVE as the no-XSAVE fallback.
    pub unsafe fn init_task_fpu();
    pub unsafe fn fpu_save(buf: *mut u8);
    pub unsafe fn fpu_restore(buf: *const u8);
}
```

## 4. Invariants & safety properties

- All trait methods marked `unsafe` require the caller to hold the
  equivalent capability in `capabilities/` once Stage 3 is in place.
- Feature-flag queries are monotonic: a flag that is absent at boot is
  absent forever.
- The HAL never allocates; callers pass in storage.
- **`DomainPrimitive::BACKEND` is part of the type-level contract.**
  Code that depends on a single-instruction rights flip (e.g.
  `scheduler/` direct context transfer) must either pin to
  `BACKEND == Pks` via `#[cfg(target_arch = "x86_64")]` or provide a
  fallback that accepts the MTE discipline cost. Treating the two as
  symmetric is a bug, not a simplification.
- **Speculation policy is current-CPU scoped.** A transition masks and
  restores ordinary IRQ delivery, rejects nested transitions, updates only
  the executing CPU's hardware state, and publishes observable state only
  after write/read-back completion. Callers must pin/non-preempt the CPU;
  remote policy changes require a rendezvous. NMI/SError handlers must be
  correct under either the old or new policy. Disabling additionally requires
  policy authorisation and quiescence from protected-boundary entry. On x86,
  Protected prefers verified AMD Automatic IBRS and clears legacy IBRS only
  after AIBRSE is active; rejected AIBRSE writes retain legacy IBRS. Failed
  multi-MSR transitions attempt to restore the complete entry policy before
  publishing `Failed`.
- **All domain / TLB / cache / MSR intrinsics are wrapped with
  `compiler_fence(SeqCst)` before and after the `asm!`.** Under fat
  LTO (see `build/` §4) the `"memory"` clobber alone is not enough
  to prevent reordering of loads/stores around a privileged write.
  The `DomainPrimitive` impls, `Mmu::invlpg`, `Mmu::tlb_flush`, and
  cache-maintenance helpers are the only supported paths to the
  underlying instructions; they all carry the double-fence discipline.
- **FSGSBASE is a per-CPU enable.** The BSP and every AP set
  `CR4.FSGSBASE` only after CPUID advertises it and before that CPU can run
  untrusted EL0. Every later CR4 mutation goes through the architecture helper
  and preserves the bit. FS-base reads/writes test the executing CPU's cached
  CR4 value and retain the fenced MSR fallback for unsupported CPUs.
- **XSAVEOPT never changes the task-image format or component mask.** Boot
  selects it only from CPUID.(0Dh,1):EAX[0], publishes that selection before
  the release-published XCR0 mask, and restores the resulting standard-format
  image with the same XRSTOR path as XSAVE.
  Callers must not reach around the HAL to raw `asm!`.
- **CR0.TS transitions are fenced architecture operations.** `read_cr0`, the
  read-modify-write that sets TS, and `clts` carry the same compiler-fence
  discipline as other privileged state transitions. Callers may cache the
  scheduler-owned TS state only while execution is pinned to that CPU and must
  clear TS before XSAVE/XRSTOR or explicit kernel FP/SIMD use.
- **Guarded-copy recovery slots are CPU-isolated.** Each x86_64 CPU's probe
  descriptor occupies a complete cache line. Installing or clearing the
  recovery RIP for a user copy therefore cannot contend with, partially share,
  or perturb another CPU's fault-recovery publication; the existing
  per-CPU-only access rule and compiler fences remain unchanged.
- **Required features fail boot, optional features degrade.** Boot
  panics if any of these are absent: PKS (x86_64) or MTE (aarch64),
  invariant TSC / Generic Timer, x2APIC / GICv3. Optional features
  (UIPI, CET, MTE2, PAC) degrade to software fallbacks where feasible.
  The `build/` subsystem emits the required CPU-feature flags at
  compile time so LLVM can emit the right intrinsics (PKRS manipulation,
  MTE tag-set instructions); missing the flag is a build-time error,
  not a runtime check.

## 5. Architecture notes

### x86_64

- Boot mode: long mode, provided by `boot/` via Limine or multiboot2.
- Feature detection via `CPUID`: PKS (leaf 7), PKU, UIPI.
- IntCtrl: x2APIC preferred; fall back to xAPIC.
- Timer: TSC deadline preferred; fall back to LAPIC timer.
- `DomainPrimitive::BACKEND = Pks`. `save` / `restore` are single
  MSR accesses (`RDMSR` / `WRMSR IA32_PKRS`). `assign` edits PTE PK
  bits and invalidates the TLB entry (typically via per-page INVLPG,
  batched where possible). `set_rights` is one `WRMSR`.
- The private `kernel_switch` reads boot-stable PKS/PCIDE enablement from the
  architecture-maintained CR4 cache. An outgoing context already in the exact
  neutral FRAME state (`PKRS == 0`, or the FRAME root with FRAME PCID) is
  represented by inactive opaque domain state and does not rewrite the same
  privileged register. Non-neutral state still enters FRAME before the first
  outgoing-context store and is restored after the last incoming-context load.
- Rust PCID domain primitives consult a CPU-local CR4 snapshot maintained after
  every fenced `write_cr4`, rather than executing `MOV from CR4` in the hot
  path. A CPU whose PCIDE enable was skipped retains a zero/disabled snapshot,
  so the cache cannot authorize PCID-tagged CR3 or INVPCID operations on that
  CPU. The live control register remains the enforcement mechanism; the cache
  only avoids a read-side virtualization exit.
- Process-PCID readiness is a global post-SMP decision over a boot-only per-CPU
  capability bitmap. A CPU enters that bitmap only after CR4.PCIDE is live and
  CPUID advertises INVPCID, which is required to retire an inactive lifetime
  tag before reuse. The address-space allocator issues no nonzero process PCID
  unless every online CPU is present; the PCID value itself remains per-address-
  space and identical on every CPU. A later CPU re-entry must support both
  features and performs a local all-context invalidation before publishing
  itself online, covering process-tag retirements missed while it was offline.

### aarch64

- Boot mode: EL1, MMU off, little-endian.
- Feature detection via `ID_AA64*_EL1` registers: MTE (`ID_AA64PFR1_EL1.MTE`),
  PAC (`ID_AA64ISAR1_EL1.APA/API`).
- IntCtrl: GICv3 (with ITS where present) or GICv2. `Features::gicv3_sysreg`
  (`ID_AA64PFR0_EL1.GIC != 0`) says only whether the `ICC_*_EL1` system
  registers exist; the controller version is discovered from the devicetree
  by `interrupts::aarch64::gic::probe`. The `sysreg::*_icc_*` accessors are
  UNDEFINED without that interface and must only run on the GICv3 backend;
  the GICv2 CPU interface (`GICC_IAR` / `GICC_EOIR`) is reached through
  `aarch64::mmio::{read_u32, write_u32, write_u8}`, which carry
  `compiler_fence(SeqCst)` before and after the access (§4), exactly like
  the `ICC_*` accessors.
- Timer: generic timer (`CNTPCT_EL0`, `CNTP_CVAL_EL0`).
- `DomainPrimitive::BACKEND = Mte`. `save` / `restore` snapshot
  `SCTLR_EL1.TCF` and `TCR_EL1` MTE bits. `assign` writes tag storage
  for every 16-B granule in `region` via `STG` / `STGM`. `set_rights`
  has **no direct analogue to `WRMSR`** — it reconfigures `TCF` mode
  (sync / async / off) and relies on the pointer-tagging discipline in
  `memory/` §5 and `ipc/` §4 for the actual per-access check. A caller
  expecting PKS-style O(1) rights flip will be surprised on aarch64.

## 6. Dependencies

- **Consumes:** `boot/` (entry state), nothing from other subsystems.
- **Provides to:** every other subsystem. This spec is a fan-out root.

## 7. Stage assignment

Stage 1 (minimal trait + per-arch stubs sufficient to boot & print), Stage 2
(full surface: PKS/MTE, UIPI/GICv3 ITS, cache ops).

## 8. Resolved decisions

### 8.1 Raw MSR/system-register access (resolved)

**Decision (was open):** **typed helpers only** for the public
surface; raw MSR/MRS access is `pub(crate)` inside `arch/` and
gated behind specific Cap kinds for any escapee path.

The typed-helper layer wraps every privileged register the
kernel actually uses (PKRS, IA32_APIC_*, IA32_UINTR_*,
SCTLR_EL1, TCR_EL1, TTBR0/1_EL1, GICR_*, etc.). Adding a new
register goes through:

1. Add a typed accessor in `arch/x86_64/msr.rs` or
   `arch/aarch64/sysreg.rs`.
2. If a driver needs it, expose via SDK at `@v0`.
3. If it's TCB-only (e.g. PKRS), keep `pub(crate)` and let
   `frame/` and `interrupts/` consume it.

Raw `WRMSR` / `MSR` from outside `arch/` is a build-time error
(rejected by the `xtask check-driver-isolation` SDK gate).

### 8.2 Crate layout (resolved)

**Decision (was open):** **single `narf-arch` crate with
`#[cfg(target_arch = "...")]` modules**, not separate per-arch
crates.

Rationale: the trait surface is shared; per-arch modules
implement it. Two crates would require either (a) a third
`narf-arch-trait` crate with no implementation (extra
indirection, slower compile), or (b) duplicated trait
definitions (maintenance burden). The `#[cfg]` approach has
been working; promote to permanent.

The internal layout (already in code as of `arch/src/`):

```text
arch/
  src/
    lib.rs              # public API + re-exports
    mmio.rs             # arch-portable MMIO accessors
    percpu.rs           # arch-portable per-CPU primitives
    x86_64/
      mod.rs
      asm.rs            # halt_until_irq, idle_halt_then_disable, sti/cli
      msr.rs            # typed MSR accessors
      io_port.rs        # in/out instructions
      cr.rs             # CR0..4 access
      ...
    aarch64/
      mod.rs
      asm.rs            # halt_until_irq, idle_halt_then_disable, wfi
      sysreg.rs         # typed system-register accessors
      ...
```

### 8.3 The canonical idle primitive

**Decision:** `arch::idle_halt_then_disable()` is the spec's
mandated way to wait-for-condition. The previously-existing
`halt_until_irq()` has the documented check-halt race for
condition-loop use; new code uses `idle_halt_then_disable`
in the canonical pattern:

```text
cli;
while !condition() {
    idle_halt_then_disable();   // sti;hlt;cli (atomic)
}
sti;
```

Mirrors Linux's `default_idle` (`raw_safe_halt` then
`raw_local_irq_disable`). On x86_64: `sti;hlt;cli`. On
aarch64: `msr DAIFClr,#2; wfi; msr DAIFSet,#2`.

`halt_until_irq()` is retained for opportunistic-idle paths
(scheduler runs out of work) where a missed wake just means
the next condition check spins; it's documented as racy and
must not be used in correctness-critical condition loops.

### 8.4 MMIO accessor discipline

**Decision:** all driver-side MMIO goes through
`arch::mmio::{read8,16,32, write8,16,32}` which:

- Are `unsafe fn` (caller asserts the address is mapped).
- Use `core::ptr::read_volatile` / `write_volatile`.
- On x86_64: emit a `compiler_fence(SeqCst)` before and after.
- On aarch64: emit `dmb ishld` after a load, `dmb ishst`
  before / `dsb st` after a store — the equivalent of x86's
  TSO ordering for MMIO.

Drivers do not write inline `read_volatile` / `write_volatile`
calls; the driver-isolation gate rejects such calls in driver
crates. (See `drivers/spec` §3 for the gate.)

## 9. ABI versioning

`narf-arch` re-exports through `narf-driver-sdk` at `@v0`:

- `mmio::read8/16/32`, `mmio::write8/16/32`
- `idle_halt_then_disable`
- `halt_until_irq`
- `interrupts_enabled`
- `enable_interrupts` / `disable_interrupts` (slow-path
  drivers' explicit IRQ control; most drivers shouldn't touch
  these directly)

`ARCH_ABI_MAJOR = 1`, `ARCH_ABI_MINOR = 0`. Adding a new MMIO
width (`read64`/`write64`) is a minor bump. Removing or
changing existing semantics is a major bump.

## 10. Open questions

(none — all v0.2 questions resolved in §8)
