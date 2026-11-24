//! x86_64 GOT slots for `R_X86_64_GOTPCREL` and its relaxable forms.
//!
//! The kernel target builds with `-Z plt=no`, so LLVM reaches a symbol it
//! does not know to be local through the GOT: `call *memcpy@GOTPCREL(%rip)`,
//! `mov sym@GOTPCREL(%rip), %rax`. The instruction *loads a pointer* from the
//! GOT slot; it does not address the symbol. A static link resolves that by
//! building a `.got` (or relaxing the instruction); `ld -r` does neither, so
//! a `.ko` arrives with the relocations still pending and the loader must
//! supply the slot. Patching the displacement straight at the symbol, as if
//! it were `R_X86_64_PC32`, makes the CPU dereference the first eight bytes
//! of the callee's *code* — a module that calls `memcpy` jumps into the
//! weeds.
//!
//! The arena is a run of 8-byte slots at the end of the module's read-only
//! data region, so every slot sits inside the ±2 GiB a 32-bit displacement
//! reaches from any instruction in the image (the whole image is far smaller)
//! and is sealed read-only with the rest of `.rodata` — the same property
//! RELRO gives a userspace GOT. Each slot holds the symbol's resolved
//! address; repeated references share one.
//!
//! aarch64 has no counterpart: its code model materialises addresses with
//! ADRP/ADD or MOVZ/MOVK, and its long branches go through `crate::plt`.
//!
//! Linux ref: Linux kernel modules are built without `-fno-plt` and never
//! carry GOTPCREL (`arch/x86/kernel/module.c` rejects it); the slot shape
//! follows the psABI's definition, `G + GOT + A - P`.

use alloc::vec::Vec;

/// Bytes per GOT slot.
pub const SLOT_BYTES: usize = 8;

/// A module's GOT — slots reserved by the loader's layout pass.
#[derive(Debug)]
pub struct Got {
    /// VA of the first slot, inside the module image.
    base: u64,
    /// Slots reserved by the layout pass.
    capacity: usize,
    /// `(symbol value, slot VA)` for each slot written so far. Linear: a
    /// module has a handful of GOT-referenced symbols and this runs once per
    /// relocation at load time.
    entries: Vec<(u64, u64)>,
}

impl Got {
    /// An arena of `capacity` slots starting at `base` (8-byte aligned).
    pub fn new(base: u64, capacity: usize) -> Self {
        Self {
            base,
            capacity,
            entries: Vec::new(),
        }
    }

    /// Slots written so far.
    pub fn used(&self) -> usize {
        self.entries.len()
    }

    /// Address of the slot holding `value`, writing one on the first
    /// reference. `None` once the reserved capacity is spent — which the
    /// layout's upper-bound count makes impossible for a well-formed image,
    /// and which must fail the load rather than patch a wrong displacement.
    ///
    /// # Safety
    /// The image must still be mapped writable at the arena: this runs during
    /// relocation, before `module_text::protect` seals the read-only region.
    pub unsafe fn slot_for(&mut self, value: u64) -> Option<u64> {
        if let Some(&(_, va)) = self.entries.iter().find(|(v, _)| *v == value) {
            return Some(va);
        }
        if self.entries.len() >= self.capacity {
            return None;
        }
        let va = self.base + (self.entries.len() * SLOT_BYTES) as u64;
        // SAFETY: `va` is an 8-byte-aligned slot inside the arena the layout
        // pass reserved, and the caller guarantees it is still writable.
        unsafe { (va as *mut u64).write(value) };
        self.entries.push((value, va));
        Some(va)
    }
}

// ── In-kernel smokes ───────────────────────────────────────────────────

use narf_kernel_test::{kernel_test_in, TestResult};

/// Slots hold the symbol value, dedupe by value, and stop at capacity.
fn smoke_got_slots_dedup_and_respect_capacity() -> TestResult {
    let mut arena = alloc::vec![0u64; 2];
    let base = arena.as_mut_ptr() as u64;
    let mut got = Got::new(base, 2);
    // SAFETY: `arena` is a live, writable, 8-byte-aligned two-slot buffer.
    let (a, a_again, b, c) = unsafe {
        (
            got.slot_for(0x1111),
            got.slot_for(0x1111),
            got.slot_for(0x2222),
            got.slot_for(0x3333),
        )
    };
    if a != Some(base) || a_again != Some(base) || b != Some(base + 8) {
        return TestResult::Fail("GOT slots were not deduplicated in order");
    }
    if c.is_some() {
        return TestResult::Fail("GOT wrote past its reserved capacity");
    }
    if arena != [0x1111, 0x2222] || got.used() != 2 {
        return TestResult::Fail("GOT slots do not hold the symbol values");
    }
    TestResult::Pass
}
kernel_test_in!("modules/got", smoke_got_slots_dedup_and_respect_capacity);

/// End to end through real code: a `call *slot(%rip)` encoded the way LLVM
/// emits `call *memcpy@GOTPCREL(%rip)`, relocated against a GOT slot in the
/// same module-text page, must reach the target once sealed. Executes on
/// x86_64 only.
#[cfg(target_arch = "x86_64")]
fn smoke_got_indirect_call_reaches_target() -> TestResult {
    use narf_memory::module_text::{self, Prot};

    extern "C" fn got_target() -> u32 {
        0x607C_A110
    }
    // `ff 15 <rel32>` = call *rel32(%rip), then `c3` = ret. The rel32 field
    // starts at offset 2 and is relative to the next instruction (offset 6),
    // which is the psABI's addend of -4 from the field.
    const CODE: [u8; 7] = [0xff, 0x15, 0, 0, 0, 0, 0xc3];
    const SLOT_OFFSET: u64 = 64;

    let mut img = match module_text::alloc(1, narf_lib::id::DomainId::SCRATCH) {
        Ok(i) => i,
        Err(_) => return TestResult::Fail("module_text::alloc(1) failed"),
    };
    // SAFETY: the image is freshly allocated and still mapped Rw.
    unsafe { core::ptr::copy_nonoverlapping(CODE.as_ptr(), img.base as *mut u8, CODE.len()) };
    let mut got = Got::new(img.base + SLOT_OFFSET, 1);
    // SAFETY: as above; the slot lies inside the same writable page.
    let Some(slot) = (unsafe { got.slot_for(got_target as usize as u64) }) else {
        // SAFETY: never executed.
        unsafe { module_text::free(img) };
        return TestResult::Fail("slot_for failed with capacity available");
    };
    // SAFETY: the page is still writable; `CODE.len()` bytes were written.
    let text = unsafe { core::slice::from_raw_parts_mut(img.base as *mut u8, CODE.len()) };
    let patched = crate::elf::apply_x86_64(
        text,
        2,
        img.base,
        slot,
        -4,
        crate::elf::reloc::R_X86_64_GOTPCREL,
    );
    if patched.is_err() || module_text::protect(&mut img, 0, 1, Prot::Rx).is_err() {
        // SAFETY: never executed.
        unsafe { module_text::free(img) };
        return TestResult::Fail("GOTPCREL patch or RX seal failed");
    }

    // SAFETY: the sealed page holds `call *slot(%rip); ret`, and the slot
    // holds a real `extern "C" fn() -> u32`.
    let f: extern "C" fn() -> u32 = unsafe { core::mem::transmute(img.base as *const ()) };
    let value = f();

    // SAFETY: `f` has returned.
    unsafe { module_text::free(img) };
    if value == 0x607C_A110 {
        TestResult::Pass
    } else {
        TestResult::Fail("call through the GOT slot did not reach its target")
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("modules/got", smoke_got_indirect_call_reaches_target);
