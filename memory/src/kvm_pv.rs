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
//! The same registered area's `steal` counter (offset 0) backs steal-time
//! accounting: [`steal_time_ns`] snapshots it under the struct's version
//! protocol so the scheduler can charge host-stolen time to the `steal`
//! column of `/proc/stat` instead of to busy time (issue #660).
//!
//! Detection is BSP-only ([`detect`]); each CPU — BSP and APs — then calls
//! [`register_steal_time_current_cpu`] during its own bring-up. The
//! hypercall instruction is vendor-specific (`vmmcall` on AMD, `vmcall` on
//! Intel); using the wrong one raises #UD, so [`detect`] records the vendor.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};

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
const STEAL_TIME_STEAL_OFFSET: usize = 0;
const STEAL_TIME_VERSION_OFFSET: usize = 8;
const STEAL_TIME_PREEMPTED_OFFSET: usize = 16;
const KVM_VCPU_PREEMPTED: u8 = 1 << 0;
const KVM_VCPU_FLUSH_TLB: u8 = 1 << 1;

static SEND_IPI_ACTIVE: AtomicBool = AtomicBool::new(false);
/// Host advertised KVM_FEATURE_PV_SEND_IPI (whether or not we use it).
static SEND_IPI_SUPPORTED: AtomicBool = AtomicBool::new(false);
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

    let send_ipi_supported = features & KVM_FEATURE_PV_SEND_IPI != 0;
    let steal = features & KVM_FEATURE_STEAL_TIME != 0;
    let tlb = features & KVM_FEATURE_PV_TLB_FLUSH != 0;
    // PV_SEND_IPI stays OFF even when advertised. KVM advertises the bit
    // unconditionally, including on hosts whose hardware virtualises guest
    // ICR writes (AMD AVIC / Intel APICv+IPI-virt) — there a native fixed
    // IPI to a RUNNING vCPU costs no vmexit at all, and the hypercall
    // replaces that free write with a mandatory exit. Measured on the AMD
    // AVIC bench host (16 vCPUs, stress-ng, 10 s, 2 workers): sock 2291 ->
    // 1069 bogo-ops/s and shm 111 -> 55 with the hypercall path on; fork
    // unchanged. The guest cannot see whether the host runs APIC
    // virtualisation, so the safe default is the native path; a non-APICv
    // deployment can opt in with [`enable_send_ipi`]. (Preempted targets
    // are already covered: PV_TLB_FLUSH elides them from shootdowns, and a
    // fixed IPI to a preempted vCPU is delivered on its next resume either
    // way.)
    SEND_IPI_SUPPORTED.store(send_ipi_supported, Ordering::Release);
    STEAL_TIME_FEATURE.store(steal, Ordering::Release);
    TLB_FLUSH_FEATURE.store(tlb && steal, Ordering::Release);
    (send_ipi_supported, tlb && steal)
}

/// Opt in to `KVM_HC_SEND_IPI` broadcasts. Only sensible on hosts WITHOUT
/// hardware APIC virtualisation (see the [`detect`] rationale); no-op when
/// the host never advertised the feature.
pub fn enable_send_ipi() {
    if SEND_IPI_SUPPORTED.load(Ordering::Acquire) {
        SEND_IPI_ACTIVE.store(true, Ordering::Release);
    }
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

/// Validate one steal-counter snapshot against the version word read
/// around it (the KVM steal-time ABI, Documentation/virt/kvm/msr.rst):
/// the host bumps `version` to an odd value before updating the struct
/// and to the next even value after, so a snapshot is usable only when
/// the bracketing versions are equal and even. Pure — host-testable
/// without a hypervisor.
pub fn validate_steal_snapshot(
    version_before: u32,
    steal_ns: u64,
    version_after: u32,
) -> Option<u64> {
    if version_before & 1 != 0 || version_before != version_after {
        return None;
    }
    Some(steal_ns)
}

/// Delta between two reads of the cumulative steal counter. The counter
/// is nanoseconds since the area was registered and monotonic in
/// practice (a u64 ns counter wraps after ~585 years); a read that goes
/// backwards means the host reset the counter (area re-registration,
/// migration quirk), so the interval is unmeasurable — report 0 and let
/// the caller resync its last-sample to the new value rather than
/// fabricating a near-2^64 delta.
pub fn steal_counter_delta(last_ns: u64, now_ns: u64) -> u64 {
    now_ns.saturating_sub(last_ns)
}

/// Cumulative stolen nanoseconds for `cpu` since its steal-time area was
/// registered, or `None` when steal time is unavailable for that CPU
/// (feature not advertised — bare metal / TCG / other hypervisor — or the
/// area not registered yet, or no stable snapshot within the retry
/// bound). The counter itself is cumulative, so callers derive deltas
/// with [`steal_counter_delta`] and never lose time between samples.
pub fn steal_time_ns(cpu: usize) -> Option<u64> {
    if !STEAL_TIME_FEATURE.load(Ordering::Acquire) || cpu >= MAX_CPUS {
        return None;
    }
    let va = STEAL_TIME_VA[cpu].load(Ordering::Acquire);
    if va == 0 {
        return None;
    }
    // SAFETY: `va` is the direct-map address of a never-freed frame
    // holding this CPU's 64-byte steal-time struct; the field is read
    // through an atomic of its ABI width, and the version protocol in
    // `validate_steal_snapshot` rejects any snapshot torn by a host
    // update in progress.
    let steal = unsafe { &*((va as usize + STEAL_TIME_STEAL_OFFSET) as *const AtomicU64) };
    // SAFETY: same frame and argument as the `steal` read above; the
    // version word is read through an atomic of its ABI width.
    let version = unsafe { &*((va as usize + STEAL_TIME_VERSION_OFFSET) as *const AtomicU32) };
    // Bounded retry: a host update is a handful of stores, so a stable
    // even version appears almost immediately; the bound only guards
    // against a host that updates pathologically (or a torn mapping),
    // where reporting "unavailable" beats spinning in a stats reader.
    for _ in 0..128 {
        let version_before = version.load(Ordering::Acquire);
        if version_before & 1 != 0 {
            core::hint::spin_loop();
            continue;
        }
        let raw = steal.load(Ordering::Relaxed);
        core::sync::atomic::fence(Ordering::SeqCst);
        let version_after = version.load(Ordering::Acquire);
        if let Some(ns) = validate_steal_snapshot(version_before, raw, version_after) {
            return Some(ns);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{steal_counter_delta, validate_steal_snapshot};

    #[test]
    fn snapshot_stable_even_version_is_valid() {
        assert_eq!(validate_steal_snapshot(4, 123_456, 4), Some(123_456));
        assert_eq!(validate_steal_snapshot(0, 0, 0), Some(0));
    }

    #[test]
    fn snapshot_odd_version_is_invalid() {
        // Host update in progress at first read: reject even if the
        // second read lands on the same odd value.
        assert_eq!(validate_steal_snapshot(5, 123, 5), None);
        assert_eq!(validate_steal_snapshot(5, 123, 6), None);
    }

    #[test]
    fn snapshot_version_change_is_invalid() {
        // Update completed (or another began) mid-read: torn sample.
        assert_eq!(validate_steal_snapshot(4, 123, 6), None);
        assert_eq!(validate_steal_snapshot(4, 123, 5), None);
    }

    #[test]
    fn delta_counts_forward_progress() {
        assert_eq!(steal_counter_delta(1_000, 1_750), 750);
        assert_eq!(steal_counter_delta(0, u64::MAX), u64::MAX);
    }

    #[test]
    fn delta_no_progress_is_zero() {
        assert_eq!(steal_counter_delta(42, 42), 0);
    }

    #[test]
    fn delta_backwards_or_wrapped_is_zero_not_huge() {
        // Counter reset / re-registration: resync, don't fabricate.
        assert_eq!(steal_counter_delta(1_000_000, 17), 0);
        assert_eq!(steal_counter_delta(u64::MAX - 5, 10), 0);
    }
}
