/*
 * NARF kernel linker script — x86_64.
 */

ENTRY(_start)

/* 16 MiB. Modern UEFI firmware on x86_64 (OVMF on QEMU, real-world
 * EDK2 builds, Lenovo / Dell / HP firmware) typically reserves the
 * 0–16 MiB range for its own code, ACPI tables, and BootServices
 * data. Loading the kernel above that line keeps the .data + .bss
 * LOAD segment (~38 MiB once the 32-MiB static heap arena is
 * accounted for) inside contiguous EfiConventionalMemory. The PVH
 * direct-boot path (QEMU `-kernel`) honours the same ELF p_paddr,
 * so this works for both protocols. */
KERNEL_LOAD_BASE = 0x1000000;
KERNEL_VIRT_BASE = 0xFFFFFFFF80000000;

/* VA span reserved for the kernel image. The module text window begins
 * exactly where this ends, which is how Linux places its own:
 * `MODULES_VADDR = __START_KERNEL_map + KERNEL_IMAGE_SIZE`
 * (arch/x86/include/asm/pgtable_64_types.h). `module_text.rs` derives
 * `MODULE_VA_BASE` from the same relationship rather than repeating the
 * address, so the two cannot drift.
 *
 * Also the bound on how far the image may slide: the ASSERT at the end of
 * this file ties `KASLR_SLIDE_MASK` to it and to `__kernel_end`, so a mask
 * that would push the image into the module window fails the build instead
 * of corrupting module text at run time. */
KERNEL_IMAGE_SIZE = 0x40000000;   /* 1 GiB. LLD takes K/M, not G. */

/* Space reserved for the KASLR relocation table. A debug build currently
 * needs ~1.6 MiB (399k sites x 4 bytes + header); 4 MiB leaves room to grow
 * before the reservation has to be revisited. `xtask relocs` errors out if a
 * table does not fit rather than writing a short one. */
KASLR_RELOC_RESERVE = 4M;

/* Largest slide the kernel window may take, as a mask of the low bits.
 *
 * The module text window begins 1 GiB above the link base, so the image plus
 * its slide has to stay below that. 256 MiB leaves the ~78 MiB image well
 * clear of it with room to grow, and is a single mask the 32-bit entry can
 * apply with one AND. `KERNEL_RANDOM_BITS = 30` in kaslr.rs describes the
 * 1 GiB kernel slot, NOT how far the image may move inside it. */

/* Debug: pin the slide to a fixed value instead of drawing entropy, so a
 * slide-dependent failure is reproducible and bisectable. The random path
 * gives every boot a different slide, which makes a failure look like it
 * moves between unrelated tests. Still masked and 2 MiB aligned by the same
 * code as the random value, so an out-of-range value here cannot widen the
 * window. 0 = draw entropy as normal. */
KASLR_SLIDE_FIXED = 0x00000000;

/* Physical relocation: how far the boot stub copies the image before running
 * it. The slide randomizes where the image APPEARS; this randomizes where it
 * IS, which a VA slide cannot do because the loader places the image.
 *
 * Pinned for now, and 0 disables relocation entirely. A real value must be
 *   - 2 MiB aligned, so the kernel window's 2 MiB pages still describe it;
 *   - at least the image size, so the copy cannot overlap its own source
 *     (the stub copies forward);
 *   - inside RAM the identity map covers (PDPT[0..3] = the low 4 GiB) and
 *     clear of anything the loader marked reserved — which is why choosing it
 *     needs the memory map, and why this is pinned until the stub can parse
 *     one. */
/* Master switch for physical relocation. The target is chosen from the
 * bootloader's memory map at boot (see `.Lphys_pick` in boot.S); only the Xen
 * PVH handoff is parsed, so a multiboot2 boot simply does not relocate. */
KASLR_PHYS_ENABLE = 1;

/* Pin the delta to a specific value for reproducing a layout. Unvalidated, like
 * KASLR_SLIDE_FIXED. 0 = choose one from the memory map. */
KASLR_PHYS_FIXED = 0;

PHDRS
{
    boot   PT_LOAD FLAGS(5); /* R-X */
    text   PT_LOAD FLAGS(5); /* R-X */
    rodata PT_LOAD FLAGS(4); /* R-- */
    data   PT_LOAD FLAGS(6); /* RW- */
    note   PT_NOTE FLAGS(4); /* R-- : PVH / Xen entry note (see boot.S) */
}

SECTIONS
{
    . = KERNEL_LOAD_BASE;

    __kernel_start = .;

    .boot : ALIGN(4K) {
        __boot_start = .;
        /* Multiboot2 header must live in the first 32 KiB of the
         * file; placing it at the head of the first PT_LOAD section
         * keeps it well inside that window. */
        KEEP(*(.multiboot2_header))
        KEEP(*(.boot .boot.*))
        __boot_end = .;
    } :boot

    .boot.data : ALIGN(4K) {
        __boot_data_start = .;
        *(.boot.data)
        __boot_data_end = .;
    } :boot

    .note.Xen : ALIGN(4) {
        KEEP(*(.note.Xen))
    } :note

    . += KERNEL_VIRT_BASE;

    .text : AT(ADDR(.text) - KERNEL_VIRT_BASE) ALIGN(4K) {
        __text_start = .;
        *(.text .text.*)
        __text_end = .;
    } :text

    /* KASLR relocation table.
     *
     * Reserved here, filled after linking by `xtask relocs --patch`: the
     * table's contents are computed FROM the linked image, so its size has to
     * be fixed before the link or every address it records would move. The
     * build fails rather than truncating if the table outgrows the window.
     *
     * It lives in the kernel half so the boot-time apply pass can find it by
     * the same slid addressing it is patching, and it is PROGBITS (not .bss)
     * because a NOBITS section has no file bytes to write into.
     *
     * Linux keeps its table appended after the compressed payload instead;
     * that is not available here because the multiboot2/PVH loader maps only
     * PT_LOAD segments, so anything outside one never reaches memory. */
    .kaslr_relocs : AT(ADDR(.kaslr_relocs) - KERNEL_VIRT_BASE) ALIGN(4K) {
        __kaslr_relocs_start = .;
        QUAD(0);
        . = __kaslr_relocs_start + KASLR_RELOC_RESERVE;
        __kaslr_relocs_end = .;
    } :rodata

    /* Physical alias of the table, for the 32-bit apply pass in boot.S.
     * Before paging there is no kernel-half addressing, and a 32-bit absolute
     * cannot hold the high VA, so the pass needs the low address as a
     * link-time constant. */
    __kaslr_relocs_phys = __kaslr_relocs_start - KERNEL_VIRT_BASE;

    /* Physical alias of `kaslr::KERNEL_SLIDE`, so the 32-bit pass can record
     * the slide it applied for the Rust conversions to read later. */
    __kernel_slide_phys = KERNEL_SLIDE - KERNEL_VIRT_BASE;

    /* Physical alias of `kaslr::IMAGE_PHYS_DELTA`, so the 32-bit stub can
     * record how far it moved the image. Link-time address; the stub adds the
     * delta to reach the copy's. */
    __image_phys_delta_phys = IMAGE_PHYS_DELTA - KERNEL_VIRT_BASE;

    /* `_start_rust`'s offset within the image, as a link-time constant.
     *
     * The stub calls it by ABSOLUTE address (`KERNEL_VIRT_BASE + slide + this`)
     * rather than with the `call rel32` that used to be there. A rel32 reaches
     * +/-2 GiB from the instruction, and the stub executes at whatever physical
     * address the image was relocated to while the target is in the kernel half
     * -- so the call only reached while the physical target happened to be below
     * the slide. Above it, the displacement overflowed and the 32-bit truncation
     * jumped into nothing: a boot that hangs for one random pair of a slide and
     * a delta and works for the next.
     *
     * It has to be an absolute linker symbol, not `_start_rust - KERNEL_VIRT_BASE`
     * written in the asm: that expression leaves a relocation whose symbol value
     * IS in the image, so `xtask relocs` would classify it as moving and add the
     * slide a second time. This symbol's value is a small offset, so the
     * classifier leaves it alone -- which is the whole point. */
    __start_rust_off = _start_rust - KERNEL_VIRT_BASE;

    .rodata : AT(ADDR(.rodata) - KERNEL_VIRT_BASE) ALIGN(4K) {
        __rodata_start = .;
        *(.rodata .rodata.*)
        . = ALIGN(4);
        __build_id_note_start = .;
        KEEP(*(.note.gnu.build-id))
        __build_id_note_end = .;
        . = ALIGN(8);
        __narf_probes_start = .;
        KEEP(*(.note.narf.probes))
        __narf_probes_end   = .;
        . = ALIGN(8);
        __narf_tests_start = .;
        KEEP(*(narf.tests))
        __narf_tests_end   = .;
        . = ALIGN(8);
        __narf_kfuncs_start = .;
        KEEP(*(narf.kfuncs))
        __narf_kfuncs_end   = .;
        . = ALIGN(8);
        __narf_structops_start = .;
        KEEP(*(narf.structops))
        __narf_structops_end   = .;
        __rodata_end = .;
    } :rodata

    .data : AT(ADDR(.data) - KERNEL_VIRT_BASE) ALIGN(4K) {
        __data_start = .;
        *(.data .data.*)
        __data_end = .;
    } :data

    .bss : AT(ADDR(.bss) - KERNEL_VIRT_BASE) ALIGN(4K) {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        __bss_end = .;
    } :data


    /* Physical bounds of the loaded image, as VALUES in a high-half word.
     *
     * `__kernel_start` / `__kernel_end` are physical addresses, because `.boot`
     * is linked at `KERNEL_LOAD_BASE` rather than in the kernel half. Kernel
     * code must not reference them directly: `addr_of!(sym)` compiles to a
     * PC-relative page reference (ADRP+ADD on aarch64, a 32-bit signed
     * absolute on x86_64), and the distance from kernel-half code to a low
     * symbol is ~512 GiB — beyond ADRP's +/-4 GiB. That is what pins aarch64
     * to `code-model=large`, and the large model materialises every absolute
     * address as four MOVZ/MOVK immediates, which a slide cannot patch without
     * carrying the full target value for ~967k sites.
     *
     * Linux has the same split and the same answer: the value lives in a
     * runtime word (`kimage_voffset`, stored by `head.S`), and `__pa_symbol()`
     * reads it. Populating the word at link time gets there without the store.
     *
     * The values are physical, so they are below `KERNEL_VIRT_BASE` and the
     * KASLR pass leaves them alone — `relocs.rs` matches on whether the
     * encoded VALUE moves, not just the field.
     */
    .kernel_bounds : AT(ADDR(.kernel_bounds) - KERNEL_VIRT_BASE) ALIGN(8) {
        __kernel_phys_bounds = .;
        QUAD(__kernel_start);
        QUAD(__kernel_end);
    } :data
    /*
     * The GOT holds runtime-resolved function pointers (e.g. the
     * compiler-builtins `memcpy`/`memset` reached via `call *GOT(%rip)`).
     * LLD synthesizes `.got` and places it AFTER .bss regardless of where
     * an explicit section is written, so it MUST be declared here — after
     * .bss but BEFORE __kernel_end — and __kernel_end taken past it. Left
     * implicit, the GOT lands past __kernel_end: the frame allocator (which
     * reserves only [__kernel_start, __kernel_end)) then hands out the frame
     * holding live GOT entries and zeroes it on allocation, nulling the
     * memcpy pointer. The next `call *GOT` from FifoScheduler::pick_next
     * jumps to 0x0 — the weston/SMP #UD heisenbug (rip=0x3, etc.).
     */
    .got : AT(ADDR(.got) - KERNEL_VIRT_BASE) ALIGN(8) {
        __got_start = .;
        *(.got)
        *(.got.plt)
        *(.data.rel.ro .data.rel.ro.*)
        __got_end = .;
    } :data

    /* Physical aliases of the GOT, for the 32-bit slide pass.
     *
     * The GOT needs fixing up and carries NO relocation records: LLD resolves
     * each slot at link time to an absolute kernel-half address, so
     * `--emit-relocs` has nothing to report and the table cannot see them. An
     * unslid GOT is an immediate instruction-fetch fault on the first indirect
     * call through it. Linux fixes its own GOT explicitly in head_64.S for the
     * same reason. */
    __got_phys_start = __got_start - KERNEL_VIRT_BASE;
    __got_phys_end   = __got_end   - KERNEL_VIRT_BASE;

    . = ALIGN(4K);
    __kernel_end = . - KERNEL_VIRT_BASE;

    /DISCARD/ : {
        *(.eh_frame*)
        *(.comment)
        *(.dynamic)
        *(.interp)
        *(.gcc_except_table*)
    }
}

/* ── KASLR slide bound ────────────────────────────────────────────────────
 *
 * Derived from the image, not hand-picked. This was 0x0FE00000 (254 MiB) with
 * a comment admitting it was a guess that had to be revisited as the image
 * grew; the real constraint is that the image plus its slide stays below the
 * module text window at `KERNEL_IMAGE_SIZE`.
 *
 * Masks are contiguous and 2 MiB aligned, `m(k) = 2^k - 2 MiB`, because the
 * slide is chosen with a single AND: `entropy & MASK`. That yields a submask
 * of MASK, so a NON-contiguous mask would silently cost entropy — the gaps
 * are bits the slide can never set. Deriving `align_down(slack, 2 MiB)`
 * directly is the obvious approach and is exactly that mistake: for today's
 * image it gives 0x3A000000, whose four set bits allow 16 positions where a
 * contiguous mask allows 256.
 *
 * Picking the largest `m(k) <= slack` needs no log2 and no ternary (LLD has
 * neither): since `m(k) - m(k-1) == 2^(k-1)`, summing `2^(k-1)` over every
 * `m(k)` that fits telescopes to the largest one that does.
 *
 * `KASLR_ENABLE = 0` turns the slide off wholesale — the mask reaching 0 is
 * how `smoke_kaslr_kernel_image_is_slid` decides to Skip rather than Pass. */
KASLR_ENABLE = 1;
KASLR_SLIDE_SLACK = KERNEL_IMAGE_SIZE - __kernel_end;
KASLR_SLIDE_MASK = KASLR_ENABLE * (
      (KASLR_SLIDE_SLACK >= 0x3FE00000) * 0x20000000
    + (KASLR_SLIDE_SLACK >= 0x1FE00000) * 0x10000000
    + (KASLR_SLIDE_SLACK >= 0x0FE00000) * 0x08000000
    + (KASLR_SLIDE_SLACK >= 0x07E00000) * 0x04000000
    + (KASLR_SLIDE_SLACK >= 0x03E00000) * 0x02000000
    + (KASLR_SLIDE_SLACK >= 0x01E00000) * 0x01000000
    + (KASLR_SLIDE_SLACK >= 0x00E00000) * 0x00800000
    + (KASLR_SLIDE_SLACK >= 0x00600000) * 0x00400000
    + (KASLR_SLIDE_SLACK >= 0x00200000) * 0x00200000);

ASSERT(__boot_end <= __text_start - KERNEL_VIRT_BASE,
       "linker: .boot section must come before .text — see build/ §4")

/* The image plus the widest slide the mask allows must stay clear of the
 * module text window. `__kernel_end` is the image's physical end, and the
 * image occupies VA [KERNEL_VIRT_BASE + slide, + __kernel_end), so this is
 * the real constraint that 0x0FE00000 was hand-picked to satisfy. Deriving
 * it keeps the bound honest as the image grows. */
ASSERT(__kernel_end + KASLR_SLIDE_MASK <= KERNEL_IMAGE_SIZE,
       "linker: image + KASLR_SLIDE_MASK reaches the module text window — lower KASLR_SLIDE_MASK or raise KERNEL_IMAGE_SIZE (and MODULE_VA_BASE with it)")
