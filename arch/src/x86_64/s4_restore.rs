//! x86_64 hibernation restore (S4): Linux's `restore_image` and
//! `core_restore_code` (`arch/x86/power/hibernate_asm_64.S`).
//!
//! The boot kernel has loaded every image page into a frame the image
//! does not use, and listed the (copy, original) pairs in pages of their
//! own, a chain of [`PbPage`]s (Linux's `restore_pblist`). It has copied
//! [`copy_loop`] into another such page and built a temporary page table
//! that identity-maps all RAM, executable, and keeps the kernel half of
//! the current table. [`jump`] switches to that table and enters the
//! relocated loop at its identity address. The loop:
//! - copies every page to its original frame, using no stack, since the
//!   boot kernel's own stack may be one of the destinations;
//! - copies the image's kernel half (PML4 slots 256..512, now restored)
//!   over the temporary table's, reloads it, and flushes the TLB including
//!   global entries (a CR4.PGE toggle), so no boot-kernel translation
//!   survives;
//! - jumps to the image kernel's [`super::s3_resume::s3_wake_entry`] at
//!   its *virtual* address, as Linux enters `restore_registers`.
//!
//! The wake entry is S3's. It reads the image's own saved context (EFER,
//! CR3, the bases, RSP, GDT, IDT, CR0, CR4, RFLAGS) through its virtual
//! address (`set_resume_context_virt`), loads the image's page table,
//! which maps that address too, and long-jumps back to where the image
//! kernel took its snapshot. The image's table need not identity-map
//! anything.

/// Pairs one restore-list page holds: 16 bytes of header and 255 pairs.
pub const PB_PAIRS: usize = 255;

/// One page of the restore list. `next` is the next page's physical
/// address (0 ends the chain); `pairs[..count]` are (copy, original)
/// physical frame addresses.
#[repr(C)]
pub struct PbPage {
    pub next: u64,
    pub count: u64,
    pub pairs: [[u64; 2]; PB_PAIRS],
}

const _: () = assert!(core::mem::size_of::<PbPage>() == 4096);

impl core::fmt::Debug for PbPage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PbPage")
            .field("next", &self.next)
            .field("count", &self.count)
            .finish_non_exhaustive()
    }
}

// The copy loop. Position-independent: relative jumps only, no data. It is
// entered under the identity map with rdi = the first PbPage (physical),
// rdx = the image's wake entry (virtual), r12 = the temporary PML4 and
// r13 = the image's PML4 (physical).
core::arch::global_asm!(
    ".pushsection .text.narf_s4_restore,\"ax\"",
    ".global narf_s4_copy_loop",
    "narf_s4_copy_loop:",
    "2:",
    "test rdi, rdi",
    "jz 6f",
    "mov rsi, [rdi + 8]",
    "lea r10, [rdi + 16]",
    "3:",
    "test rsi, rsi",
    "jz 5f",
    "mov rcx, [r10]",
    "mov r8, [r10 + 8]",
    "mov r9d, 512",
    "4:",
    "mov rax, [rcx]",
    "mov [r8], rax",
    "add rcx, 8",
    "add r8, 8",
    "dec r9",
    "jnz 4b",
    "add r10, 16",
    "dec rsi",
    "jmp 3b",
    "5:",
    "mov rdi, [rdi]",
    "jmp 2b",
    "6:",
    // The image's kernel half replaces the boot kernel's.
    "mov ecx, 256",
    "7:",
    "mov rax, [r13 + rcx * 8]",
    "mov [r12 + rcx * 8], rax",
    "inc ecx",
    "cmp ecx, 512",
    "jne 7b",
    "mov cr3, r12",
    // Flush every TLB entry, globals included: toggle CR4.PGE (bit 7).
    "mov rax, cr4",
    "mov rcx, rax",
    "and rcx, -129",
    "mov cr4, rcx",
    "mov cr4, rax",
    "jmp rdx",
    ".global narf_s4_copy_loop_end",
    "narf_s4_copy_loop_end:",
    ".popsection",
);

unsafe extern "C" {
    static narf_s4_copy_loop: u8;
    static narf_s4_copy_loop_end: u8;
}

/// The copy loop's code, to be copied into a safe page.
pub fn copy_loop() -> &'static [u8] {
    // SAFETY: both symbols bound the loop in one text section; the bytes
    // between them are immutable code.
    unsafe {
        let start = &raw const narf_s4_copy_loop;
        let end = &raw const narf_s4_copy_loop_end;
        core::slice::from_raw_parts(start, end as usize - start as usize)
    }
}

/// Switch to `temp_cr3` and run the relocated copy loop at `loop_phys`
/// over the restore list at `first_page_phys`, ending in the image's wake
/// entry at `entry_virt`, after installing the kernel half of the image's
/// PML4 at `image_pml4_phys`.
///
/// # Safety
/// Interrupts are off and this is the only CPU running. `temp_cr3`
/// identity-maps all RAM executable and keeps the current kernel half,
/// so the instruction after the CR3 write still fetches. `loop_phys`
/// holds [`copy_loop`]. The restore list, the loop and the table are in
/// frames no pair writes. Every original frame belongs to an image whose
/// saved context the wake entry resumes. Nothing returns.
pub unsafe fn jump(
    temp_cr3: u64,
    loop_phys: u64,
    first_page_phys: u64,
    entry_virt: u64,
    image_pml4_phys: u64,
) -> ! {
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    // SAFETY: the caller's contract.
    unsafe {
        core::arch::asm!(
            "mov cr3, {cr3}",
            "jmp {entry}",
            cr3 = in(reg) temp_cr3,
            entry = in(reg) loop_phys,
            in("rdi") first_page_phys,
            in("rdx") entry_virt,
            in("r12") temp_cr3,
            in("r13") image_pml4_phys,
            options(noreturn),
        )
    }
}

/// Reload the task register from the live GDT's TSS at `selector`, as
/// Linux's `fix_processor_context` does after a restore. The descriptor is
/// marked busy (the image kernel had loaded it), and `ltr` faults on a busy
/// TSS, so its type goes back to available first. Without the reload, TR
/// still caches the boot kernel's TSS, and the first interrupt that needs
/// `rsp0` or an IST stack reads them from memory the image overwrote.
///
/// # Safety
/// CPL0 with interrupts off; the live GDT holds a 64-bit TSS descriptor at
/// `selector`.
pub unsafe fn reload_task_register(selector: u16) {
    let mut gdtr = [0u8; 10];
    // SAFETY: CPL0; `sgdt` writes ten bytes to the buffer.
    unsafe { core::arch::asm!("sgdt [{}]", in(reg) gdtr.as_mut_ptr(), options(nostack)) };
    let base = u64::from_le_bytes(gdtr[2..10].try_into().unwrap());
    let access = (base + u64::from(selector & !7) + 5) as *mut u8;
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    // SAFETY: the caller's contract; bit 1 of the access byte is the busy
    // bit of a TSS type (0xB busy, 0x9 available).
    unsafe {
        access.write_volatile(access.read_volatile() & !0b10);
        core::arch::asm!("ltr {0:x}", in(reg) selector, options(nostack, preserves_flags));
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}
