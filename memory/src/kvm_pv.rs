//! KVM paravirtual guest features: `PV_SEND_IPI` and `PV_TLB_FLUSH`.
//!
//! Under KVM every x2APIC ICR write is a vmexit, so a fixed-IPI broadcast to
//! N peers costs N exits. `KVM_HC_SEND_IPI` (CPUID 0x40000001 EAX bit 11,
//! `KVM_FEATURE_PV_SEND_IPI`) delivers the same set in ONE hypercall — the
//! apic layer consults [`pv_send_ipi`] before falling back to ICR writes.
//!
//! `PV_TLB_FLUSH` (bit 9, requires `KVM_FEATURE_STEAL_TIME` bit 5) removes
//! preempted vCPUs from TLB-shootdown fan-outs entirely: each vCPU registers
//! a 64-byte `struct kvm_steal_time` via `MSR_KVM_STEAL_TIME`; while the host
//! has a vCPU scheduled out it sets `KVM_VCPU_PREEMPTED` in that vCPU's
//! `preempted` byte. A shootdown sender that finds the bit set CAS-es
//! `KVM_VCPU_FLUSH_TLB` into the same byte instead of sending an IPI — KVM
//! then flushes that vCPU's entire guest TLB (all PCIDs) before it executes
//! its next instruction, which is strictly stronger than any ranged request
//! the IPI would have carried, and a vCPU that is not executing cannot touch
//! a stale translation in the meantime. This is exactly Linux's
//! `kvm_flush_tlb_multi` contract (arch/x86/kernel/kvm.c); the CAS mirrors
//! its `try_cmpxchg` — losing the race to the host's sched-in path means the
//! vCPU is (about to be) running again and must be IPI'd normally.
//!
//! Detection is BSP-only ([`detect`]); each CPU — BSP and APs — then calls
//! [`register_steal_time_current_cpu`] during its own bring-up. The
//! hypercall instruction is vendor-specific (`vmmcall` on AMD, `vmcall` on
//! Intel); using the wrong one raises #UD, so [`detect`] records the vendor.

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};

const MAX_CPUS: usize = narf_lib::percpu::MAX_CPUS;

/// CPUID leaves (KVM_CPUID_SIGNATURE / KVM_CPUID_FEATURES).
const KVM_CPUID_SIGNATURE: u32 = 0x4000_0000;
const KVM_CPUID_FEATURES: u32 = 0x4000_0001;
/// "KVMKVMKVM\0\0\0" split across ebx/ecx/edx.
const KVM_SIG_EBX: u32 = u32::from_le_bytes(*b"KVMK");
const KVM_SIG_ECX: u32 = u32::from_le_bytes(*b"VMKV");
const KVM_SIG_EDX: u32 = u32::from_le_bytes(*b"M\0\0\0");

const KVM_FEATURE_STEAL_TIME: u32 = 1 << 5;
const KVM_FEATURE_PV_TLB_FLUSH: u32 = 1 << 9;
const KVM_FEATURE_PV_SEND_IPI: u32 = 1 << 11;

const MSR_KVM_STEAL_TIME: u32 = 0x4b56_4d03;
const KVM_MSR_ENABLED: u64 = 1;

const KVM_HC_SEND_IPI: u64 = 10;

/// `struct kvm_steal_time` field offsets (uapi/asm/kvm_para.h): steal u64,
/// version u32, flags u32, preempted u8 at offset 16.
const STEAL_TIME_PREEMPTED_OFFSET: usize = 16;
const KVM_VCPU_PREEMPTED: u8 = 1 << 0;
const KVM_VCPU_FLUSH_TLB: u8 = 1 << 1;

static SEND_IPI_ACTIVE: AtomicBool = AtomicBool::new(false);
static TLB_FLUSH_FEATURE: AtomicBool = AtomicBool::new(false);
static STEAL_TIME_FEATURE: AtomicBool = AtomicBool::new(false);
/// `vmmcall` (AMD) vs `vmcall` (Intel) — the wrong one is #UD.
static USE_VMMCALL: AtomicBool = AtomicBool::new(false);

/// Per-CPU steal-time area: direct-map VA of the registered frame, 0 when
/// this CPU has not (yet) registered. The frame outlives the boot (never
/// freed), so a reader holding a stale non-zero VA is always safe.
static STEAL_TIME_VA: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];

/// One KVM hypercall, Linux `kvm_hypercall4` ABI: nr in rax, args in
/// rbx/rcx/rdx/rsi, result in rax (negative = -errno).
///
/// # Safety
/// Only meaningful under a KVM host that advertised the relevant feature;
/// the caller must have checked the [`detect`]-published flags (that also
/// pins the correct vendor instruction, so no #UD).
unsafe fn hypercall4(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64) -> i64 {
    // rbx is LLVM-reserved for inline asm, so stage the first argument
    // through a scratch register around the call.
    let ret: i64;
    if USE_VMMCALL.load(Ordering::Relaxed) {
        // SAFETY: caller contract — KVM host, AMD vendor. rbx is saved and
        // restored around the hypercall.
        unsafe {
            core::arch::asm!(
                "push rbx",
                "mov rbx, {a0}",
                "vmmcall",
                "pop rbx",
                a0 = in(reg) a0,
                inlateout("rax") nr => ret,
                in("rcx") a1, in("rdx") a2, in("rsi") a3,
            );
        }
    } else {
        // SAFETY: caller contract — KVM host, Intel vendor. rbx is saved
        // and restored around the hypercall.
        unsafe {
            core::arch::asm!(
                "push rbx",
                "mov rbx, {a0}",
                "vmcall",
                "pop rbx",
                a0 = in(reg) a0,
                inlateout("rax") nr => ret,
                in("rcx") a1, in("rdx") a2, in("rsi") a3,
            );
        }
    }
    ret
}

/// BSP-only feature detection. Returns `(send_ipi, tlb_flush_possible)` for
/// the boot banner; both stay false when not running under KVM (bare metal,
/// TCG, other hypervisors — the signature check covers them all).
pub fn detect() -> (bool, bool) {
    // SAFETY: CPUID is unprivileged and always available on x86_64.
    let sig = unsafe { core::arch::x86_64::__cpuid(KVM_CPUID_SIGNATURE) };
    if sig.ebx != KVM_SIG_EBX
        || sig.ecx != KVM_SIG_ECX
        || sig.edx != KVM_SIG_EDX
        || sig.eax < KVM_CPUID_FEATURES
    {
        return (false, false);
    }
    // SAFETY: as above; the signature leaf guaranteed this leaf exists.
    let features = unsafe { core::arch::x86_64::__cpuid(KVM_CPUID_FEATURES) }.eax;
    // SAFETY: leaf 0 is architectural.
    let vendor = unsafe { core::arch::x86_64::__cpuid(0) };
    // "AuthenticAMD" → ebx = "Auth". (Hygon "HygonGenuine" also takes
    // vmmcall; its ebx is "Hygo" — treat any non-Intel as AMD-style, since
    // under the KVM signature the only vmcall vendor is GenuineIntel.)
    let intel = vendor.ebx == u32::from_le_bytes(*b"Genu");
    USE_VMMCALL.store(!intel, Ordering::Relaxed);

    let send_ipi = features & KVM_FEATURE_PV_SEND_IPI != 0;
    let steal = features & KVM_FEATURE_STEAL_TIME != 0;
    let tlb = features & KVM_FEATURE_PV_TLB_FLUSH != 0;
    SEND_IPI_ACTIVE.store(send_ipi, Ordering::Release);
    STEAL_TIME_FEATURE.store(steal, Ordering::Release);
    TLB_FLUSH_FEATURE.store(tlb && steal, Ordering::Release);
    (send_ipi, tlb && steal)
}

/// Register this CPU's steal-time area with the host. Called once per CPU
/// during bring-up (BSP after [`detect`], each AP from `_ap_start_rust`),
/// after the frame allocator is live. No-op without the feature.
pub fn register_steal_time_current_cpu() {
    if !STEAL_TIME_FEATURE.load(Ordering::Acquire) {
        return;
    }
    let cpu = narf_lib::percpu::current_cpu().min(MAX_CPUS - 1);
    if STEAL_TIME_VA[cpu].load(Ordering::Acquire) != 0 {
        return;
    }
    // A whole 4 KiB frame per CPU for a 64-byte struct is deliberate: the
    // host writes it via a pinned gfn, so it must never be handed back to
    // the buddy, and frame granularity keeps it out of any cache line the
    // kernel heap could share with unrelated data.
    let Ok(frame) = crate::frame::alloc_frame() else {
        return;
    };
    let phys = frame.start_address();
    let va = phys.kernel_mut_ptr::<u8>();
    // SAFETY: freshly allocated, exclusively owned frame in the direct map.
    unsafe { core::ptr::write_bytes(va, 0, 4096) };
    STEAL_TIME_VA[cpu].store(va as u64, Ordering::Release);
    // Publish to the host. `wrmsr_or_gp`: a host that lied about the
    // feature (or a nested setup filtering the MSR) faults recoverably and
    // we simply leave PV TLB off for this CPU.
    if narf_arch::x86_64::msr::wrmsr_or_gp(MSR_KVM_STEAL_TIME, phys.raw() | KVM_MSR_ENABLED)
        .is_err()
    {
        STEAL_TIME_VA[cpu].store(0, Ordering::Release);
    }
}

/// Deliver a fixed-vector IPI to `cpu_mask` with one `KVM_HC_SEND_IPI`
/// hypercall. Returns false (caller must fall back to ICR writes) when the
/// feature is absent, a target sits outside the single 64-bit bitmap window,
/// or the host rejects the call. APIC IDs equal logical CPU ids on every
/// topology NARF boots today (QEMU `-smp`, MADT identity), matching the
/// `min = 0` window base.
pub fn pv_send_ipi(cpu_mask: u64, vector: u8) -> bool {
    if cpu_mask == 0 {
        return true;
    }
    if !SEND_IPI_ACTIVE.load(Ordering::Acquire) {
        return false;
    }
    // icr low word: vector, fixed delivery (APIC_DM_FIXED = 0).
    // SAFETY: feature checked; vendor instruction pinned by detect().
    let ret = unsafe { hypercall4(KVM_HC_SEND_IPI, cpu_mask, 0, 0, vector as u64) };
    ret >= 0
}

/// If `cpu` is currently preempted by the host, arrange for KVM to flush its
/// whole guest TLB before it runs again and return true — the caller may
/// then drop that CPU from an invalidation fan-out AND its ack wait. False
/// means the CPU must be IPI'd normally.
pub fn try_flush_preempted(cpu: usize) -> bool {
    if !TLB_FLUSH_FEATURE.load(Ordering::Acquire) || cpu >= MAX_CPUS {
        return false;
    }
    let va = STEAL_TIME_VA[cpu].load(Ordering::Acquire);
    if va == 0 {
        return false;
    }
    // SAFETY: `va` is the direct-map address of a never-freed, 64-byte-
    // aligned steal-time frame; `preempted` is a single byte the host
    // updates atomically. AtomicU8 gives the guest-side atomicity the CAS
    // contract needs.
    let preempted = unsafe { &*((va as usize + STEAL_TIME_PREEMPTED_OFFSET) as *const AtomicU8) };
    let mut state = preempted.load(Ordering::Acquire);
    loop {
        if state & KVM_VCPU_PREEMPTED == 0 {
            return false;
        }
        match preempted.compare_exchange_weak(
            state,
            state | KVM_VCPU_FLUSH_TLB,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return true,
            Err(actual) => state = actual,
        }
    }
}
