//! x86_64 Interrupt Descriptor Table.
//!
//! Long-mode IDT entries are 16 bytes each. 32 CPU-exception vectors are
//! installed with interrupt gates pointing at `int_N` stubs from
//! `trap_entry.S`. Vectors 32..=255 remain "not present" — external
//! IRQs / IPIs land with the `interrupts/` crate in Stage 2.

use core::arch::asm;
use core::sync::atomic::{compiler_fence, Ordering};

/// 64-bit IDT gate layout (Intel SDM Vol 3 §6.14).
#[repr(C, packed)]
#[derive(Copy, Clone)]
struct IdtEntry {
    offset_low:  u16,
    selector:    u16,
    ist:         u8,      // low 3 bits; 0 = use current stack
    type_attr:   u8,      // P | DPL(2) | 0 | Type(4)
    offset_mid:  u16,
    offset_high: u32,
    _zero:       u32,
}

impl IdtEntry {
    const NULL: Self = Self {
        offset_low: 0, selector: 0, ist: 0, type_attr: 0,
        offset_mid: 0, offset_high: 0, _zero: 0,
    };

    const fn new(handler: u64, selector: u16, ist: u8, type_attr: u8) -> Self {
        Self {
            offset_low:  (handler        & 0xFFFF) as u16,
            selector,
            ist,
            type_attr,
            offset_mid:  ((handler >> 16) & 0xFFFF) as u16,
            offset_high: ((handler >> 32) & 0xFFFF_FFFF) as u32,
            _zero: 0,
        }
    }
}

// SAFETY: `IdtEntry` is `#[repr(C, packed)]` POD; manual Debug elided because
// `missing_debug_implementations` is deny-by-default but we don't expose
// IdtEntry outside this module.
impl core::fmt::Debug for IdtEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IdtEntry").finish_non_exhaustive()
    }
}

/// 10-byte LIDT pseudo-descriptor.
#[repr(C, packed)]
#[derive(Copy, Clone)]
struct IdtPointer {
    limit: u16,
    base:  u64,
}

impl core::fmt::Debug for IdtPointer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IdtPointer").finish_non_exhaustive()
    }
}

const IDT_ENTRIES: usize = 256;

/// Interrupt-gate, present, DPL=0: 0x8E.
const GATE_INT_KERNEL: u8 = 0x8E;

use super::gdt::{KCODE_SEL, IST_NMI, IST_DF, IST_MC, IST_VC};

/// The IDT itself — 4 KiB.
static mut IDT: [IdtEntry; IDT_ENTRIES] = [IdtEntry::NULL; IDT_ENTRIES];

// Declared by `trap_entry.S` — one symbol per vector.
extern "C" {
    fn int_0();   fn int_1();   fn int_2();   fn int_3();
    fn int_4();   fn int_5();   fn int_6();   fn int_7();
    fn int_8();   fn int_9();   fn int_10();  fn int_11();
    fn int_12();  fn int_13();  fn int_14();  fn int_15();
    fn int_16();  fn int_17();  fn int_18();  fn int_19();
    fn int_20();  fn int_21();  fn int_22();  fn int_23();
    fn int_24();  fn int_25();  fn int_26();  fn int_27();
    fn int_28();  fn int_29();  fn int_30();  fn int_31();

    // External IRQ stubs (32..=47) + spurious (255).
    fn int_32();  fn int_33();  fn int_34();  fn int_35();
    fn int_36();  fn int_37();  fn int_38();  fn int_39();
    fn int_40();  fn int_41();  fn int_42();  fn int_43();
    fn int_44();  fn int_45();  fn int_46();  fn int_47();
    fn int_255();
}

fn install(vec: usize, handler: unsafe extern "C" fn()) {
    install_with_ist(vec, handler, 0);
}

fn install_with_ist(vec: usize, handler: unsafe extern "C" fn(), ist: u8) {
    let entry = IdtEntry::new(handler as u64, KCODE_SEL, ist, GATE_INT_KERNEL);
    // SAFETY: IDT is accessed only on the BSP during Stage-1 bring-up, before
    // any other CPU or interrupt handler can observe it. The write happens
    // before `lidt`, and the entry layout matches the hardware spec.
    unsafe { core::ptr::addr_of_mut!(IDT).cast::<IdtEntry>().add(vec).write(entry); }
}

/// Build and load the IDT. Called from `init_traps`.
///
/// # Safety
/// Must be called exactly once, on the BSP, before anything that could
/// generate a CPU exception we want to survive.
pub unsafe fn init() {
    // Fill the 32 CPU-exception slots. The rest stay zero/NULL;
    // unhandled external IRQs would cause a triple-fault, but Stage 1
    // leaves interrupts masked until `interrupts/` lands.
    install(0,  int_0);  install(1,  int_1);
    install_with_ist(2, int_2, IST_NMI);         // NMI runs on its own stack
    install(3,  int_3);
    install(4,  int_4);  install(5,  int_5);  install(6,  int_6);  install(7,  int_7);
    install_with_ist(8, int_8, IST_DF);          // #DF must not re-double-fault
    install(9,  int_9);  install(10, int_10); install(11, int_11);
    install(12, int_12); install(13, int_13); install(14, int_14); install(15, int_15);
    install(16, int_16); install(17, int_17);
    install_with_ist(18, int_18, IST_MC);        // #MC is asynchronous, own stack
    install(19, int_19); install(20, int_20); install(21, int_21);
    install(22, int_22); install(23, int_23); install(24, int_24); install(25, int_25);
    install(26, int_26); install(27, int_27); install(28, int_28);
    install_with_ist(29, int_29, IST_VC);        // #VC (SEV-ES) own stack
    install(30, int_30); install(31, int_31);

    // External IRQs 32..=47 + spurious 255.
    install(32, int_32);
    install(33, int_33); install(34, int_34); install(35, int_35);
    install(36, int_36); install(37, int_37); install(38, int_38); install(39, int_39);
    install(40, int_40); install(41, int_41); install(42, int_42); install(43, int_43);
    install(44, int_44); install(45, int_45); install(46, int_46); install(47, int_47);
    install(255, int_255);

    // Build the LIDT descriptor and load it.
    let ptr = IdtPointer {
        limit: (IDT_ENTRIES * core::mem::size_of::<IdtEntry>() - 1) as u16,
        base:  core::ptr::addr_of!(IDT) as u64,
    };

    compiler_fence(Ordering::SeqCst);
    // SAFETY: `lidt` with a valid 10-byte pseudo-descriptor installs the
    // IDT. The compiler_fence pair follows arch/ §4.
    unsafe {
        asm!("lidt [{p}]", p = in(reg) &ptr, options(readonly, nostack, preserves_flags));
    }
    compiler_fence(Ordering::SeqCst);
}
