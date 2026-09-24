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
/* Currently 0: the slide is implemented end to end and boots, but enabling it
 * regresses `drivers/storage/nvme-e2e`, so it stays off until that is
 * diagnosed. Set to 0x0FE00000 (254 MiB, already 2 MiB aligned) to enable.
 *
 * That value is a hand-picked bound, not a derived one. The real constraint is
 * that the image plus its slide must stay clear of the module text window one
 * GiB above the link base; deriving it from `__kernel_end` would keep it
 * honest as the image grows. */
/* Enabled. A nonzero slide used to fail in one of two ways, both traced to
 * one defect in the relocation-table builder: it slid every absolute field in
 * a kernel-half section, including the few encoding `__kernel_start` /
 * `__kernel_end`, which are PHYSICAL. See `relocs.rs` and
 * `smoke_kaslr_image_bounds_stay_physical`. Verified at slides of 2, 8, 32,
 * 128 and 254 MiB and on the random path. */
KASLR_SLIDE_MASK = 0x0FE00000;

/* Debug: pin the slide to a fixed value instead of drawing entropy, so a
 * slide-dependent failure is reproducible and bisectable. The random path
 * gives every boot a different slide, which makes a failure look like it
 * moves between unrelated tests. Still masked and 2 MiB aligned by the same
 * code as the random value, so an out-of-range value here cannot widen the
 * window. 0 = draw entropy as normal. */
KASLR_SLIDE_FIXED = 0x00000000;

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

ASSERT(__boot_end <= __text_start - KERNEL_VIRT_BASE,
       "linker: .boot section must come before .text — see build/ §4")
