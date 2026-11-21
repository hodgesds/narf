//! x86_64 GDT + TSS with IST stacks.
//!
//! Stage 1 Wave 2 per `frame/` spec §3–§5 and STAGE1.md Wave 2 item #7:
//! every fault that could share a stack with a victim of the very fault
//! it's handling (NMI, #DF, #MC, #VC) gets its own IST-backed stack.
//!
//! Every CPU's GDT has Linux's 64-bit layout (`arch/x86/include/asm/
//! segment.h`, 16 descriptors) for every user-visible selector; the
//! authoritative table and the constants live in
//! `narf_arch::x86_64::segments`:
//!
//! | index | selector | kind |
//! |-------|----------|------|
//! | 0     | 0x00     | null |
//! | 1     | 0x08     | kernel code — long mode, DPL 0 |
//! | 2     | 0x10     | kernel data — present, writable (cosmetic) |
//! | 4     | 0x23     | `__USER32_CS` — 32-bit user code, DPL 3 |
//! | 5     | 0x2b     | `__USER_DS` — user data, DPL 3 |
//! | 6     | 0x33     | `__USER_CS` — long-mode user code, DPL 3 |
//! | 8–9   | 0x40     | TSS (16-byte system descriptor) |
//! | 12–14 | 0x63/0x6b/0x73 | TLS, the running task's (`set_thread_area`) |
//!
//! Slots 3, 7, 10–11 (LDT) and 15 stay empty. The kernel-code selector
//! (0x08) is at the same offset as the one boot.S bootstrapped, so reloading
//! CS isn't necessary — the current CS selector still points at a valid
//! descriptor after LGDT.

use core::arch::asm;
use core::sync::atomic::{compiler_fence, Ordering};

use narf_arch::x86_64::segments::{
    self, DESC_KERNEL_CS, DESC_KERNEL_DS, DESC_USER32_CS, DESC_USER_CS, DESC_USER_DS, GDT_ENTRIES,
};

/// Kernel-code selector — byte offset into the GDT.
pub const KCODE_SEL: u16 = segments::KERNEL_CS;
/// Kernel-data selector.
pub const KDATA_SEL: u16 = segments::KERNEL_DS;
/// TSS selector (`GDT_ENTRY_TSS`, index 8).
const TSS_SEL: u16 = segments::TSS_SELECTOR;
/// User-data selector (`__USER_DS`, index 5, RPL 3 → 0x2B).
pub const UDATA_SEL: u16 = segments::USER_DS;
/// User-code selector (`__USER_CS`, index 6, RPL 3 → 0x33) — long-mode code
/// at DPL=3.
pub const UCODE_SEL: u16 = segments::USER_CS;

/// `LGDT` limit of every CPU's table.
const GDT_LIMIT: u16 = (GDT_ENTRIES * 8 - 1) as u16;

/// Fill `gdt` (`GDT_ENTRIES` descriptors) with the layout above, its TSS
/// descriptor naming the TSS at `tss_base`. The TLS slots start empty; the
/// scheduler writes the running task's on every switch-in.
///
/// # Safety
/// `gdt` must be writable for `GDT_ENTRIES` u64s and not yet loaded by any
/// CPU.
unsafe fn write_gdt(gdt: *mut u64, tss_base: u64) {
    // TSS descriptor (system; 16 bytes):
    //   low:  type=0x9 (available 64-bit TSS), P=1, limit=sizeof(TSS)-1,
    //         base[31:0] stitched in.
    //   high: base[63:32] in the low 32 bits.
    let tss_limit = (core::mem::size_of::<Tss>() - 1) as u64;
    let tss_lo: u64 = (tss_limit & 0xFFFF)
        | ((tss_base & 0x00FF_FFFF) << 16)
        | (0x9 << 40)                     // type: available 64-bit TSS
        | (1 << 47)                       // P
        | (((tss_limit >> 16) & 0xF) << 48)
        | (((tss_base >> 24) & 0xFF) << 56);
    let tss_hi: u64 = tss_base >> 32;
    // SAFETY: the caller owns `GDT_ENTRIES` writable descriptors at `gdt`;
    // every index below is less than `GDT_ENTRIES`.
    unsafe {
        core::ptr::write_bytes(gdt, 0, GDT_ENTRIES);
        gdt.add(1).write(DESC_KERNEL_CS); // kernel code   (0x08)
        gdt.add(2).write(DESC_KERNEL_DS); // kernel data   (0x10)
        gdt.add(4).write(DESC_USER32_CS); // __USER32_CS   (0x23)
        gdt.add(5).write(DESC_USER_DS); // __USER_DS     (0x2B)
        gdt.add(6).write(DESC_USER_CS); // __USER_CS     (0x33)
        gdt.add(8).write(tss_lo); // TSS lo        (0x40)
        gdt.add(9).write(tss_hi); // TSS hi
    }
}

// The literal indices above are Linux's (`arch/x86/include/asm/segment.h`).
const _: () = {
    assert!(segments::GDT_ENTRY_DEFAULT_USER32_CS == 4);
    assert!(segments::GDT_ENTRY_DEFAULT_USER_DS == 5);
    assert!(segments::GDT_ENTRY_DEFAULT_USER_CS == 6);
    assert!(segments::GDT_ENTRY_TSS == 8);
    assert!(TSS_SEL == 0x40);
    assert!(UDATA_SEL == 0x2B && UCODE_SEL == 0x33);
};

/// IST slot assignments, STAGE1.md Wave 2 #7.
pub const IST_NMI: u8 = 1;
pub const IST_DF: u8 = 2;
pub const IST_MC: u8 = 3;
pub const IST_VC: u8 = 4;

/// Long-mode TSS (Intel SDM Vol 3 §7.7). Reserved / unused fields kept
/// at the documented offsets. 104 bytes.
#[repr(C, packed)]
#[derive(Copy, Clone)]
struct Tss {
    _reserved0: u32,
    rsp0: u64,
    rsp1: u64,
    rsp2: u64,
    _reserved1: u64,
    ist: [u64; 7], // ist[0] = IST1, ist[6] = IST7
    _reserved2: u64,
    _reserved3: u16,
    io_map_base: u16,
}

impl core::fmt::Debug for Tss {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Tss").finish_non_exhaustive()
    }
}

/// 16-byte IST stack size. Small enough to place in `.bss`, big enough
/// that a NMI/#DF handler can print a trap frame without overflowing.
const IST_STACK_BYTES: usize = 16 * 1024;

#[repr(C, align(16))]
struct IstStack([u8; IST_STACK_BYTES]);

static mut IST_STACKS: [IstStack; 4] = [
    IstStack([0; IST_STACK_BYTES]),
    IstStack([0; IST_STACK_BYTES]),
    IstStack([0; IST_STACK_BYTES]),
    IstStack([0; IST_STACK_BYTES]),
];

/// Kernel stack used by `TSS.rsp0`. On a user→kernel trap (CPL=3 →
/// CPL=0) the CPU reads `TSS.rsp0` and atomically switches to it
/// before pushing the trap frame. Without this, user-mode traps
/// would push onto a user-controlled RSP — classic CPL-confusion.
///
/// 16 KiB matches the IST slot size; big enough for the trap frame
/// plus one level of Rust call without overflow.
///
/// Per-task kernel stacks (once we have multi-process support) will
/// relocate via `set_kernel_rsp0` when the scheduler switches tasks.
const KERNEL_RSP0_BYTES: usize = 16 * 1024;

#[repr(C, align(16))]
struct KernelRsp0Stack([u8; KERNEL_RSP0_BYTES]);

static mut KERNEL_RSP0_STACK: KernelRsp0Stack = KernelRsp0Stack([0; KERNEL_RSP0_BYTES]);

/// Dedicated per-CPU **hardirq stack** (Linux model). A device interrupt's
/// dispatch body (`on_irq` + EOI, which contains the timer-wheel drain and all
/// device handlers) is switched onto this stack so it never consumes the
/// interrupted task's own kernel stack. 16 KiB matches Linux's `IRQ_STACK_SIZE`.
/// This is the BSP instance; each AP gets its own inside `ApCpuBlock`.
const IRQ_STACK_BYTES: usize = 16 * 1024;

#[repr(C, align(16))]
struct IrqStack([u8; IRQ_STACK_BYTES]);

static mut BSP_IRQ_STACK: IrqStack = IrqStack([0; IRQ_STACK_BYTES]);

/// Top (highest address) of the BSP's hardirq stack. `percpu::init_bsp`
/// publishes `top - 8` into `gs:[24]`.
pub fn bsp_irq_stack_top() -> u64 {
    // SAFETY: address-of a static; no deref.
    unsafe {
        core::ptr::addr_of!(BSP_IRQ_STACK)
            .cast::<u8>()
            .add(IRQ_STACK_BYTES) as u64
    }
}

static mut TSS: Tss = Tss {
    _reserved0: 0,
    rsp0: 0,
    rsp1: 0,
    rsp2: 0,
    _reserved1: 0,
    ist: [0; 7],
    _reserved2: 0,
    _reserved3: 0,
    io_map_base: 0,
};

/// The BSP's GDT: `GDT_ENTRIES` (16) × 8 bytes in Linux's layout (see the
/// module docs). Each AP builds its own copy in its `ApCpuBlock`.
static mut GDT: [u64; GDT_ENTRIES] = [0; GDT_ENTRIES];

/// Per-CPU pointer to the TSS the CPU's TR is loaded with — the static `TSS`
/// for the BSP (CPU 0), each AP's leaked `ApCpuBlock.tss` otherwise. Lets
/// `set_kernel_rsp0` retarget the CURRENT CPU's `rsp0` at runtime (per-task
/// kernel stacks under SMP). Filled by `init` (BSP) / `init_ap`; a null entry
/// falls back to the static `TSS` (pre-init / BSP).
static TSS_PTRS: [core::sync::atomic::AtomicPtr<Tss>; narf_lib::percpu::MAX_CPUS] =
    [const { core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()) };
        narf_lib::percpu::MAX_CPUS];

/// Per-CPU baseline kernel-entry stack top (the boot-time `rsp0` stack),
/// captured lazily on the first per-task retarget so `set_task_kernel_stack(0)`
/// can restore it. 0 = uncaptured.
static KERNEL_STACK_BASELINE: [core::sync::atomic::AtomicU64; narf_lib::percpu::MAX_CPUS] =
    [const { core::sync::atomic::AtomicU64::new(0) }; narf_lib::percpu::MAX_CPUS];

#[repr(C, packed)]
#[derive(Copy, Clone)]
struct Pseudo {
    limit: u16,
    base: u64,
}
impl core::fmt::Debug for Pseudo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Pseudo").finish_non_exhaustive()
    }
}

/// Install the GDT + TSS. Called from `init_traps` before the IDT so
/// the IDT can reference `KCODE_SEL` and set IST slots correctly.
///
/// # Safety
/// Must run on the BSP, exactly once.
pub unsafe fn init() {
    // ── populate TSS with IST stack pointers (top of each stack) ──
    // SAFETY: Stage 1 boot is single-threaded; writing the static TSS and
    // the static IST_STACKS from the BSP cannot race.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        let stacks_base = core::ptr::addr_of!(IST_STACKS) as *const u8;
        for i in 0..4 {
            let top = stacks_base.add((i + 1) * IST_STACK_BYTES) as u64;
            core::ptr::addr_of_mut!(TSS)
                .cast::<u8>()
                .add(36 /* offset of ist[] within Tss */ + i * 8)
                .cast::<u64>()
                .write_unaligned(top);
        }
    }

    // Record the BSP's TSS pointer so `set_kernel_rsp0` retargets the right
    // TSS (CPU 0) once the scheduler does per-task kernel-stack updates.
    TSS_PTRS[0].store(
        core::ptr::addr_of_mut!(TSS),
        core::sync::atomic::Ordering::Release,
    );

    // ── TSS.rsp0 — kernel stack for user→kernel trap entry ──
    // SAFETY: single-threaded boot, no observer for the static yet.
    unsafe {
        let top = core::ptr::addr_of!(KERNEL_RSP0_STACK)
            .cast::<u8>()
            .add(KERNEL_RSP0_BYTES) as u64;
        set_kernel_rsp0(top);
    }

    // ── build GDT descriptors (Linux layout, see the module docs) ──
    let tss_base = core::ptr::addr_of!(TSS) as u64;
    // SAFETY: single-threaded boot path; the static GDT has GDT_ENTRIES
    // descriptors and no CPU has loaded it yet.
    unsafe {
        write_gdt(core::ptr::addr_of_mut!(GDT).cast::<u64>(), tss_base);
    }

    // ── LGDT ──
    let ptr = Pseudo {
        limit: GDT_LIMIT,
        base: core::ptr::addr_of!(GDT) as u64,
    };
    compiler_fence(Ordering::SeqCst);
    // SAFETY: LGDT with a valid 10-byte pseudo-descriptor.
    unsafe {
        asm!("lgdt [{p}]", p = in(reg) &ptr, options(readonly, nostack, preserves_flags));
    }
    compiler_fence(Ordering::SeqCst);

    // Reload data segment registers so they reference the new kernel-data
    // descriptor (0x10). In long mode the CPU *treats* most segment-
    // register loads as ignored for access checks, but the selectors
    // themselves still have to be valid (SS with DPL != CPL on IRET is
    // the famous way this bites you). SS+DS+ES+FS+GS → 0x10.
    // SAFETY: 0x10 is a present writable data descriptor in the GDT we
    // just installed.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        asm!(
            "mov ax, 0x10",
            "mov ds, ax",
            "mov es, ax",
            "mov ss, ax",
            "mov fs, ax",
            "mov gs, ax",
            out("ax") _,
            options(nostack, preserves_flags),
        );
    }

    // ── LTR ──
    compiler_fence(Ordering::SeqCst);
    // SAFETY: TSS selector 0x40 references the descriptor we just wrote.
    unsafe {
        asm!("ltr {s:x}", s = in(reg) TSS_SEL,
             options(nomem, nostack, preserves_flags));
    }
    compiler_fence(Ordering::SeqCst);

    // Publish the BSP's table so the scheduler can load each task's TLS
    // descriptors into its slots 12..=14 on switch-in.
    // SAFETY: the static GDT has GDT_ENTRIES descriptors, is the BSP's live
    // table (LGDT above) and lives for the life of the system.
    unsafe {
        segments::register_cpu_gdt(0, core::ptr::addr_of_mut!(GDT).cast::<u64>());
    }
}

/// Write `top` into `TSS.rsp0`. The scheduler calls this when it
/// picks a user task so a subsequent user→kernel trap lands on that
/// task's kernel stack instead of the previous task's.
///
/// `top` is the *top* of the stack (highest address + 1); the CPU
/// uses it directly as the new RSP on trap-from-user-mode.
///
/// # Safety
/// `top` must point at the high end of a writable, 16-byte-aligned
/// kernel stack with at least enough slack for a trap frame +
/// Rust-side dispatch frames before the trap returns. 16 KiB is
/// plenty; per-task stacks smaller than 4 KiB risk overflow.
pub unsafe fn set_kernel_rsp0(top: u64) {
    use core::sync::atomic::{compiler_fence, Ordering};
    compiler_fence(Ordering::SeqCst);
    // Write THIS CPU's TSS.rsp0. Per-CPU under SMP: the BSP uses the static
    // `TSS`, each AP its own leaked `ApCpuBlock.tss` (looked up via TSS_PTRS).
    // Before the table is filled (early BSP boot) fall back to the static TSS.
    // (The previous version always wrote the static BSP `TSS`, so a per-task
    // retarget on an AP was silently a no-op — a latent SMP bug.)
    let cpu = narf_arch::x86_64::cpu::current_cpu() as usize;
    let mut tss = TSS_PTRS
        .get(cpu)
        .map(|p| p.load(Ordering::Acquire))
        .unwrap_or_default();
    if tss.is_null() {
        tss = core::ptr::addr_of_mut!(TSS);
    }
    // SAFETY: `tss` points at this CPU's live TSS; rsp0 is at byte offset 4
    // (after `_reserved0`). Unaligned write matches the `#[repr(packed)]` Tss;
    // the CPU reads rsp0 atomically on trap entry.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        tss.cast::<u8>()
            .add(4 /* offset of rsp0 */)
            .cast::<u64>()
            .write_unaligned(top);
    }
    compiler_fence(Ordering::SeqCst);
}

/// Top of the running CPU's #DF IST stack. The #PF path switches onto it to
/// report a kernel-stack overflow with room to print (Linux `page_fault_oops`
/// does `call_on_stack(__this_cpu_ist_top_va(DF), handle_stack_overflow)`).
pub fn df_ist_top() -> u64 {
    use core::sync::atomic::Ordering;
    let cpu = narf_arch::x86_64::cpu::current_cpu() as usize;
    let mut tss = TSS_PTRS
        .get(cpu)
        .map(|p| p.load(Ordering::Acquire))
        .unwrap_or_default();
    if tss.is_null() {
        tss = core::ptr::addr_of_mut!(TSS);
    }
    // SAFETY: `tss` is this CPU's live TSS (or the BSP static); `ist[IST_DF-1]`
    // is at byte offset 36 + 8 * (IST_DF - 1), read unaligned as `Tss` is packed.
    unsafe {
        tss.cast::<u8>()
            .add(36 + (IST_DF as usize - 1) * 8)
            .cast::<u64>()
            .read_unaligned()
    }
}

/// Move this CPU's four IST stacks (NMI, #DF, #MC, #VC) onto guarded
/// `KernelStack`s (Linux keeps them in `cpu_entry_area` with guard pages), so
/// an IST handler that overflows faults instead of running into the next
/// stack of the per-CPU block. The boot-time stacks stay in force until this
/// runs: the kernel-stack slot is reserved after the GDT/TSS are up.
///
/// Each TSS slot is one aligned 8-byte store, so an IST exception taken while
/// this runs uses either the old or the new stack, both valid; the old stacks
/// are static / leaked and never freed.
pub fn guard_ist_stacks() {
    use core::sync::atomic::Ordering;
    let cpu = narf_arch::x86_64::cpu::current_cpu() as usize;
    let mut tss = TSS_PTRS
        .get(cpu)
        .map(|p| p.load(Ordering::Acquire))
        .unwrap_or_default();
    if tss.is_null() {
        tss = core::ptr::addr_of_mut!(TSS);
    }
    for i in 0..4 {
        let Ok(stack) = narf_memory::kstack::KernelStack::alloc(IST_STACK_BYTES) else {
            return; // keep the remaining boot-time stacks
        };
        let top = stack.top() & !0xF;
        core::mem::forget(stack); // per-CPU, lives as long as the CPU
                                  // SAFETY: `tss` is this CPU's live TSS; `ist[i]` is at byte offset
                                  // 36 + 8 i (packed, so unaligned write), read by the CPU on IST entry.
        unsafe {
            tss.cast::<u8>()
                .add(36 + i * 8)
                .cast::<u64>()
                .write_unaligned(top);
        }
    }
}

/// Retarget the running CPU's kernel-entry stack (TSS.rsp0 + the SYSCALL
/// `gs:[8]` kernel_stack_top) to `top`, or restore the per-CPU boot baseline
/// when `top == 0`. Installed into the scheduler via `set_kernel_stack_hook`
/// so a trap/syscall from the running user task lands on THAT task's own
/// kernel stack (Linux `update_task_stack` model). Per-CPU; runs on the CPU
/// that owns the stacks, at CPL=0 with kernel GS (every scheduler path).
///
/// DORMANT in Stage 1: installed but not yet called by the scheduler.
pub fn set_task_kernel_stack(top: u64) {
    use core::sync::atomic::Ordering;
    let cpu = narf_arch::x86_64::cpu::current_cpu() as usize;
    // Lazily capture the boot-time baseline (current gs:[8]) before the first
    // retarget on this CPU, so `top == 0` can restore it.
    if let Some(b) = KERNEL_STACK_BASELINE.get(cpu) {
        if b.load(Ordering::Acquire) == 0 {
            b.store(super::percpu::kernel_stack_top(), Ordering::Release);
        }
    }
    let target = if top == 0 {
        KERNEL_STACK_BASELINE
            .get(cpu)
            .map(|b| b.load(Ordering::Acquire))
            .unwrap_or(0)
    } else {
        top
    };
    if target == 0 {
        return; // no baseline captured and no explicit top — nothing to do
    }
    // SAFETY: CPL=0 with kernel GS (scheduler context); per-CPU writes only.
    unsafe {
        set_kernel_rsp0(target);
        super::percpu::set_kernel_stack_top(target);
    }
}

/// Per-AP GDT + TSS + trap stacks, heap-allocated and leaked for the
/// lifetime of the system. Each AP that will run user tasks needs its
/// *own* TSS so a user→kernel trap (page fault, timer preemption,
/// IST fault) lands on this CPU's kernel stack rather than the shared
/// BSP `TSS.rsp0` — two CPUs trapping onto one stack would corrupt
/// each other. The GDT is a per-CPU copy because the TSS descriptor
/// encodes the (per-CPU) TSS base address.
#[repr(C, align(16))]
struct ApCpuBlock {
    gdt: [u64; GDT_ENTRIES],
    tss: Tss,
    rsp0_stack: [u8; KERNEL_RSP0_BYTES],
    /// This AP's dedicated hardirq stack — genuinely per-CPU (lives in the
    /// per-AP leaked block, never shared with another CPU). See the
    /// shared-TSS/IST corruption lesson that motivated per-CPU AP stacks.
    irq_stack: [u8; IRQ_STACK_BYTES],
    ist_stacks: [[u8; IST_STACK_BYTES]; 4],
}

/// Install a per-AP GDT + TSS on the calling CPU. Allocates this AP's
/// own `ApCpuBlock` (leaked — lives forever), points `TSS.rsp0` and
/// the four IST entries at this CPU's stacks, then `LGDT` + reloads
/// the data segments + `LTR`. Returns the top of this CPU's `rsp0`
/// stack so the caller can mirror it into `PerCpu.kernel_stack_top`
/// for the SYSCALL entry path (which reads `gs:8`, not `TSS.rsp0`).
/// Also returns the top of this CPU's dedicated hardirq stack (for
/// `PerCpu.irq_stack_top` at `gs:24`), as the tuple `(rsp0_top, irq_top)`.
///
/// Mirrors [`init`] but writes a freshly-allocated per-CPU block
/// instead of the BSP statics. Loading `gs` to the kernel-data
/// selector here zeroes `GS.base`; the caller must run
/// `percpu::init_ap` afterwards to program this CPU's per-CPU pointer
/// into `IA32_GS_BASE`.
///
/// # Safety
/// Must run once per AP, in kernel mode with IRQs masked, after the
/// global allocator is up. The returned stack top stays valid for the
/// lifetime of the system (the block is leaked).
pub unsafe fn init_ap() -> (u64, u64) {
    use alloc::alloc::{alloc_zeroed, Layout};

    let layout = Layout::new::<ApCpuBlock>();
    // SAFETY: non-zero-size layout; global allocator is up by AP
    // bring-up (heap promoted to slab before start_aps).
    let block = unsafe { alloc_zeroed(layout) } as *mut ApCpuBlock;
    assert!(!block.is_null(), "AP per-CPU block allocation failed");

    // SAFETY: `block` is a fresh, uniquely-owned, zeroed allocation
    // sized for `ApCpuBlock`; all field writes below stay in bounds.
    unsafe {
        let tss_ptr = core::ptr::addr_of_mut!((*block).tss).cast::<u8>();

        // IST stack tops (highest address of each 16 KiB stack).
        let ist_base = core::ptr::addr_of_mut!((*block).ist_stacks).cast::<u8>();
        for i in 0..4 {
            let top = ist_base.add((i + 1) * IST_STACK_BYTES) as u64;
            tss_ptr
                .add(36 /* offset of ist[] within Tss */ + i * 8)
                .cast::<u64>()
                .write_unaligned(top);
        }

        // TSS.rsp0 — kernel stack for user→kernel trap entry on this AP.
        let rsp0_top = core::ptr::addr_of_mut!((*block).rsp0_stack)
            .cast::<u8>()
            .add(KERNEL_RSP0_BYTES) as u64;
        tss_ptr
            .add(4 /* offset of rsp0 */)
            .cast::<u64>()
            .write_unaligned(rsp0_top);

        // This AP's dedicated hardirq stack top (for `gs:[24]`).
        let irq_top = core::ptr::addr_of_mut!((*block).irq_stack)
            .cast::<u8>()
            .add(IRQ_STACK_BYTES) as u64;

        // Record THIS AP's TSS pointer (keyed by logical id, set in TSC_AUX by
        // `_ap_start_rust` before this call) so `set_kernel_rsp0` retargets the
        // AP's own TSS, not the static BSP one, on per-task kernel-stack updates.
        let cpu = narf_arch::x86_64::cpu::current_cpu() as usize;
        if let Some(slot) = TSS_PTRS.get(cpu) {
            slot.store(
                core::ptr::addr_of_mut!((*block).tss),
                core::sync::atomic::Ordering::Release,
            );
        }

        // Build GDT descriptors — identical kernel/user code+data to
        // the BSP GDT (so the live CS / reloaded SS stay valid), with
        // a TSS descriptor pointing at *this AP's* TSS.
        let tss_base = core::ptr::addr_of!((*block).tss) as u64;
        let gdt = core::ptr::addr_of_mut!((*block).gdt).cast::<u64>();
        write_gdt(gdt, tss_base);

        // LGDT this AP's table.
        let ptr = Pseudo {
            limit: GDT_LIMIT,
            base: gdt as u64,
        };
        compiler_fence(Ordering::SeqCst);
        asm!("lgdt [{p}]", p = in(reg) &ptr, options(readonly, nostack, preserves_flags));
        compiler_fence(Ordering::SeqCst);

        // Reload data segment registers against the new kernel-data
        // descriptor (0x10). Loading `gs` here zeroes GS.base — the
        // caller restores it via `percpu::init_ap`.
        asm!(
            "mov ax, 0x10",
            "mov ds, ax",
            "mov es, ax",
            "mov ss, ax",
            "mov fs, ax",
            "mov gs, ax",
            out("ax") _,
            options(nostack, preserves_flags),
        );

        // LTR — load this AP's TSS so user→kernel traps and IST faults
        // switch to this CPU's stacks.
        compiler_fence(Ordering::SeqCst);
        asm!("ltr {s:x}", s = in(reg) TSS_SEL,
             options(nomem, nostack, preserves_flags));
        compiler_fence(Ordering::SeqCst);

        // Publish this AP's live table for the scheduler's TLS-slot loads
        // (the block is leaked, so the pointer stays valid).
        segments::register_cpu_gdt(cpu, gdt);

        (rsp0_top, irq_top)
    }
}

/// Linear address of the BSP-built GDT. AP bring-up reads this to
/// patch the AP trampoline's GDT-pointer parameter so the AP loads
/// the same GDT the BSP uses.
pub fn gdt_base() -> u64 {
    core::ptr::addr_of!(GDT) as u64
}

/// Limit of the BSP-built GDT (size − 1). Used alongside `gdt_base`.
pub fn gdt_limit() -> u16 {
    GDT_LIMIT
}

/// Read the currently-installed `TSS.rsp0`. Diagnostic helper —
/// scheduler tests use it to confirm the setter took effect.
pub fn kernel_rsp0() -> u64 {
    // SAFETY: aligned (well, packed) read of a u64; single reader
    // convention + the atomic-write contract on the setter keep
    // tearing at bay.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        core::ptr::addr_of!(TSS)
            .cast::<u8>()
            .add(4)
            .cast::<u64>()
            .read_unaligned()
    }
}

// ── Linux GDT layout (IA-32 emulation) ─────────────────────────────
//
// `arch/x86/include/asm/segment.h` (64-bit): 16 descriptors, the 32-bit user
// code segment `__USER32_CS` at index 4 (0x23), `__USER_DS` at 5 (0x2b),
// `__USER_CS` at 6 (0x33), the TSS at 8–9 (`GDT_ENTRY_TSS`) and the three
// TLS slots `set_thread_area` hands out at 12–14 (selectors 0x63/0x6b/0x73).
// NARF keeps its own kernel selectors (0x08 code, 0x10 data; the IDT and
// `IA32_STAR` name them) — they are not user-visible.
use narf_kernel_test::{kernel_test_in, TestResult};

/// The live GDTR (`SGDT`): `(limit, base)`.
fn live_gdtr() -> (u16, u64) {
    let mut image = [0u8; 10];
    compiler_fence(Ordering::SeqCst);
    // SAFETY: SGDT stores the 10-byte GDTR image into `image`, which is
    // writable for 10 bytes; CPL0, no other side effect.
    unsafe {
        asm!("sgdt [{p}]", p = in(reg) image.as_mut_ptr(), options(nostack, preserves_flags));
    }
    compiler_fence(Ordering::SeqCst);
    let mut base = [0u8; 8];
    base.copy_from_slice(&image[2..10]);
    (
        u16::from_le_bytes([image[0], image[1]]),
        u64::from_le_bytes(base),
    )
}

/// The live task-register selector (`STR`).
fn live_tr() -> u16 {
    let tr: u16;
    // SAFETY: STR copies the task-register selector into a register; it has
    // no memory operand and no side effect.
    unsafe {
        asm!("str {t:x}", t = out(reg) tr, options(nomem, nostack, preserves_flags));
    }
    tr
}

/// The running CPU's GDT matches Linux's index layout: 16 entries, the TSS
/// in TR at 0x40, `__USER32_CS` a flat DPL-3 32-bit code segment at index
/// 4, user data and 64-bit user code at 5 and 6, and the unused slots empty.
fn smoke_ia32_gdt_matches_linux_layout() -> TestResult {
    // The CPU sets a code/data descriptor's accessed bit when it loads it.
    const ACCESSED: u64 = 1 << 40;
    let (limit, base) = live_gdtr();
    if usize::from(limit) + 1 != 16 * 8 {
        return TestResult::Fail("GDT limit is not 16 descriptors (Linux GDT_ENTRIES)");
    }
    if live_tr() != 0x40 {
        return TestResult::Fail("TR is not the GDT_ENTRY_TSS selector 0x40");
    }
    let gdt = base as *const u64;
    let desc = |i: usize| -> u64 {
        // SAFETY: SGDT returned the live table and its limit covers 16
        // descriptors (checked above); `i` is below 16 at every call.
        unsafe { core::ptr::read_volatile(gdt.add(i)) }
    };
    if desc(1) & !ACCESSED != 0x00af_9a00_0000_ffff {
        return TestResult::Fail("kernel code (0x08) is not a long-mode DPL-0 code segment");
    }
    if desc(2) & !ACCESSED != 0x00cf_9200_0000_ffff {
        return TestResult::Fail("kernel data (0x10) is not a DPL-0 data segment");
    }
    if desc(4) & !ACCESSED != 0x00cf_fa00_0000_ffff {
        return TestResult::Fail("__USER32_CS (0x23) is not a flat DPL-3 32-bit code segment");
    }
    if desc(5) & !ACCESSED != 0x00cf_f200_0000_ffff {
        return TestResult::Fail("__USER_DS (0x2b) is not a flat DPL-3 data segment");
    }
    if desc(6) & !ACCESSED != 0x00af_fa00_0000_ffff {
        return TestResult::Fail("__USER_CS (0x33) is not a long-mode DPL-3 code segment");
    }
    // Index 8: a present, busy 64-bit TSS (LTR marks it busy, type 0xB).
    let tss_lo = desc(8);
    if (tss_lo >> 40) & 0xF != 0xB || tss_lo & (1 << 47) == 0 {
        return TestResult::Fail("GDT entry 8 is not the loaded 64-bit TSS");
    }
    for unused in [3usize, 7, 10, 11, 15] {
        if desc(unused) != 0 {
            return TestResult::Fail("an unused GDT slot (3, 7, 10, 11, 15) is not empty");
        }
    }
    TestResult::Pass
}
kernel_test_in!("frame/ia32-gdt", smoke_ia32_gdt_matches_linux_layout);
