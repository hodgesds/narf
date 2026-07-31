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
        *(.got)
        *(.got.plt)
        *(.data.rel.ro .data.rel.ro.*)
    } :data

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
