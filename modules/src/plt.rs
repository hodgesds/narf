//! aarch64 PLT veneers.
//!
//! `R_AARCH64_CALL26` and `R_AARCH64_JUMP26` carry a 26-bit signed
//! word-displacement — ±128 MiB. NARF's module window is 1 GiB from the
//! kernel image (`narf_memory::module_text` explains why it cannot be
//! closer: the intervening space *is* the linear map), so a module calling
//! any exported kernel symbol overflows that field and, before this, failed
//! to load with `RelocError::Overflow`.
//!
//! The fix is the standard one: emit a trampoline inside the module's own
//! text, within branch range of the call site, that performs the long jump.
//!
//! ```text
//!     adrp x16, dst              // page of the target, ±4 GiB
//!     add  x16, x16, #dst & 0xFFF
//!     br   x16
//! ```
//!
//! x16 (IP0) is free to clobber: AAPCS64 requires a conforming program to
//! assume a veneer altering IP0/IP1 may be inserted at any branch exposed to
//! a long-branch relocation, which is exactly this situation. Linux states
//! the same justification verbatim at `arch/arm64/include/asm/module.h:33`.
//!
//! ADRP itself reaches ±4 GiB, so with the window 1 GiB out it always
//! resolves and no second-order veneer is needed. Linux additionally carries
//! `module_emit_veneer_for_adrp` for kernels where that is not true; if the
//! module window ever moves further out, that is the piece to add.
//!
//! x86_64 needs none of this. Its module window sits immediately above the
//! kernel image, inside the ±2 GiB that `R_X86_64_PLT32` reaches, so calls
//! resolve directly — which is the entire reason for that placement.
//!
//! Linux ref: `arch/arm64/kernel/module-plts.c`.

use alloc::vec::Vec;

/// Bytes per veneer: three A64 instructions.
pub const VENEER_BYTES: usize = 12;

/// Encode a veneer at `pc` branching to `dst`.
///
/// Returns `None` if the target is beyond ADRP's ±4 GiB page reach, which
/// with the current window placement cannot happen — but is checked rather
/// than assumed, because silently emitting a truncated displacement would
/// produce a branch to the wrong address instead of a load failure.
pub fn encode_veneer(dst: u64, pc: u64) -> Option<[u8; VENEER_BYTES]> {
    // ADRP x16, page(dst) — bits 30:29 hold immlo, bits 23:5 immhi.
    let page_diff = ((dst & !0xFFF) as i64).wrapping_sub((pc & !0xFFF) as i64) >> 12;
    if !(-(1 << 20)..(1 << 20)).contains(&page_diff) {
        return None;
    }
    let imm = page_diff as u32;
    let adrp = 0x9000_0000u32 | ((imm & 0x3) << 29) | (((imm >> 2) & 0x7FFFF) << 5) | 16;

    // ADD x16, x16, #(dst & 0xFFF) — 64-bit variant, no shift.
    let add = 0x9100_0000u32 | (((dst & 0xFFF) as u32) << 10) | (16 << 5) | 16;

    // BR x16.
    let br = 0xD61F_0000u32 | (16 << 5);

    let mut out = [0u8; VENEER_BYTES];
    out[0..4].copy_from_slice(&adrp.to_le_bytes());
    out[4..8].copy_from_slice(&add.to_le_bytes());
    out[8..12].copy_from_slice(&br.to_le_bytes());
    Some(out)
}

/// A module's veneer arena — a run of [`VENEER_BYTES`] slots reserved at the
/// end of the module's text region, so veneers are executable and within
/// branch range of every call site in the module.
#[derive(Debug)]
pub struct Plt {
    /// VA of the first slot, inside the module image.
    base: u64,
    /// Slots reserved by the layout pass.
    capacity: usize,
    /// `(target, veneer_va)` for every slot emitted so far. Linear lookup:
    /// a module has tens of distinct call targets, not thousands, and this
    /// runs once per relocation at load time.
    entries: Vec<(u64, u64)>,
}

impl Plt {
    /// An arena of `capacity` slots starting at `base`.
    pub fn new(base: u64, capacity: usize) -> Self {
        Self {
            base,
            capacity,
            entries: Vec::new(),
        }
    }

    /// Slots emitted so far.
    pub fn used(&self) -> usize {
        self.entries.len()
    }

    /// Address of a veneer branching to `target`, emitting one if this is the
    /// first reference. Repeated calls for the same target share a slot,
    /// which is why the layout's count is an upper bound rather than exact.
    ///
    /// # Safety
    /// The module image must still be mapped writable at the arena — i.e.
    /// this runs during relocation, before `module_text::protect` seals the
    /// text region.
    pub unsafe fn veneer_for(&mut self, target: u64) -> Option<u64> {
        if let Some(&(_, va)) = self.entries.iter().find(|(t, _)| *t == target) {
            return Some(va);
        }
        if self.entries.len() >= self.capacity {
            return None;
        }
        let va = self.base + (self.entries.len() * VENEER_BYTES) as u64;
        let bytes = encode_veneer(target, va)?;
        // SAFETY: `va` is inside the text region the layout pass reserved for
        // the arena, and the caller guarantees the image is still writable.
        unsafe {
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), va as *mut u8, VENEER_BYTES);
        }
        self.entries.push((target, va));
        Some(va)
    }
}

// ── In-kernel smokes ───────────────────────────────────────────────────

use narf_kernel_test::{kernel_test_in, TestResult};

/// Decode a veneer back to the address it branches to. Mirrors the encoder,
/// so a sign-extension or field-offset error in either shows up as a
/// mismatch rather than as a wild branch at run time.
fn decode_veneer(bytes: &[u8; VENEER_BYTES], pc: u64) -> u64 {
    let adrp = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let add = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);

    let immlo = (adrp >> 29) & 0x3;
    let immhi = (adrp >> 5) & 0x7FFFF;
    let imm21 = ((immhi << 2) | immlo) as i64;
    // Sign-extend the 21-bit page displacement.
    let imm21 = (imm21 << 43) >> 43;
    let page = ((pc & !0xFFF) as i64).wrapping_add(imm21 << 12) as u64;

    page + (((add >> 10) & 0xFFF) as u64)
}

/// The encoder must round-trip, including across a page boundary and for a
/// negative (backwards) displacement — the two cases where an ADRP
/// sign-extension bug hides.
fn smoke_plt_veneer_encoding_round_trips() -> TestResult {
    // Chosen to exercise: forward, backward, page-crossing, and a target
    // whose low 12 bits are non-zero.
    let pc = 0xFFFF_FF80_8000_1000u64;
    for dst in [
        0xFFFF_FF80_8000_1000u64, // same page
        0xFFFF_FF80_8000_1ABCu64, // same page, non-zero offset
        0xFFFF_FF80_C000_0123u64, // far forward
        0xFFFF_FF80_4008_0456u64, // backward, into the kernel image
    ] {
        let Some(v) = encode_veneer(dst, pc) else {
            return TestResult::Fail("encode_veneer refused an in-range target");
        };
        if decode_veneer(&v, pc) != dst {
            return TestResult::Fail("veneer does not decode back to its target");
        }
        // Third word must be `br x16`.
        let br = u32::from_le_bytes([v[8], v[9], v[10], v[11]]);
        if br != 0xD61F_0200 {
            return TestResult::Fail("veneer does not end in `br x16`");
        }
    }
    TestResult::Pass
}
kernel_test_in!("modules/plt", smoke_plt_veneer_encoding_round_trips);

/// Targets beyond ADRP's ±4 GiB page reach must be refused, not silently
/// truncated — a truncated displacement is a branch to the wrong address.
fn smoke_plt_veneer_rejects_out_of_adrp_range() -> TestResult {
    let pc = 0x0000_0000_1000_0000u64;
    if encode_veneer(0x0000_0100_0000_0000u64, pc).is_some() {
        return TestResult::Fail("encode_veneer accepted a target beyond ADRP range");
    }
    TestResult::Pass
}
kernel_test_in!("modules/plt", smoke_plt_veneer_rejects_out_of_adrp_range);

/// Repeated references to one symbol must share a slot — the arena is sized
/// from a per-relocation over-count, so without folding a module with many
/// calls to the same function would exhaust it.
fn smoke_plt_veneer_dedups_by_target() -> TestResult {
    // Back the arena with a real image: `veneer_for` writes through the VA.
    let img = match narf_memory::module_text::alloc(1) {
        Ok(i) => i,
        Err(_) => return TestResult::Fail("module_text::alloc(1) failed"),
    };
    let mut plt = Plt::new(img.base, 4);

    // SAFETY: the image is freshly allocated and still Rw.
    let a1 = unsafe { plt.veneer_for(img.base + 0x1000) };
    // SAFETY: as above.
    let a2 = unsafe { plt.veneer_for(img.base + 0x1000) };
    // SAFETY: as above.
    let b = unsafe { plt.veneer_for(img.base + 0x2000) };
    let used = plt.used();

    // SAFETY: nothing was ever executed from this image.
    unsafe { narf_memory::module_text::free(img) };

    match (a1, a2, b) {
        (Some(x), Some(y), Some(z)) if x == y && z != x && used == 2 => TestResult::Pass,
        (Some(_), Some(_), Some(_)) => TestResult::Fail("veneer dedup did not fold by target"),
        _ => TestResult::Fail("veneer_for returned None with capacity available"),
    }
}
kernel_test_in!("modules/plt", smoke_plt_veneer_dedups_by_target);

/// A veneer must be exhausted rather than overrun: the slot after the last
/// one belongs to whatever the layout put next.
fn smoke_plt_veneer_respects_capacity() -> TestResult {
    let img = match narf_memory::module_text::alloc(1) {
        Ok(i) => i,
        Err(_) => return TestResult::Fail("module_text::alloc(1) failed"),
    };
    let mut plt = Plt::new(img.base, 1);
    // SAFETY: freshly allocated, still Rw.
    let first = unsafe { plt.veneer_for(img.base + 0x1000) };
    // SAFETY: as above.
    let second = unsafe { plt.veneer_for(img.base + 0x2000) };
    // SAFETY: never executed.
    unsafe { narf_memory::module_text::free(img) };

    match (first, second) {
        (Some(_), None) => TestResult::Pass,
        (Some(_), Some(_)) => TestResult::Fail("veneer arena overran its capacity"),
        _ => TestResult::Fail("first veneer failed with capacity available"),
    }
}
kernel_test_in!("modules/plt", smoke_plt_veneer_respects_capacity);

/// The claim that matters: a veneer emitted into module text, sealed RX, and
/// branched to actually reaches its target. Encoding round-trips prove the
/// arithmetic; only this proves the instructions.
#[cfg(target_arch = "aarch64")]
fn smoke_plt_veneer_executes() -> TestResult {
    use narf_memory::module_text::{self, Prot};

    /// Branch target. `extern "C"` so the veneer's `br x16` lands on a real
    /// function entry with the ABI the caller expects.
    extern "C" fn veneer_target() -> u32 {
        0xA64
    }

    let mut img = match module_text::alloc(1) {
        Ok(i) => i,
        Err(_) => return TestResult::Fail("module_text::alloc(1) failed"),
    };
    let mut plt = Plt::new(img.base, 1);
    // SAFETY: the image is freshly allocated and still mapped Rw.
    let Some(va) = (unsafe { plt.veneer_for(veneer_target as usize as u64) }) else {
        // SAFETY: never executed.
        unsafe { module_text::free(img) };
        return TestResult::Fail("veneer_for failed for an in-range target");
    };
    if module_text::protect(&mut img, 0, 1, Prot::Rx).is_err() {
        // SAFETY: never executed.
        unsafe { module_text::free(img) };
        return TestResult::Fail("protect(.., Rx) failed");
    }

    // SAFETY: `va` is a sealed-RX veneer that clobbers only x16 (AAPCS64
    // permits this at any long-branch site) and tail-calls a real
    // `extern "C" fn() -> u32`.
    let f: extern "C" fn() -> u32 = unsafe { core::mem::transmute(va as *const ()) };
    let got = f();

    // SAFETY: `f` has returned.
    unsafe { module_text::free(img) };
    if got == 0xA64 {
        TestResult::Pass
    } else {
        TestResult::Fail("call through veneer returned the wrong value")
    }
}
#[cfg(target_arch = "aarch64")]
kernel_test_in!("modules/plt", smoke_plt_veneer_executes);
