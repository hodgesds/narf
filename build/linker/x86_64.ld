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
        . = ALIGN(8);
        __narf_probes_start = .;
        KEEP(*(.note.narf.probes))
        __narf_probes_end   = .;
        . = ALIGN(8);
        __narf_tests_start = .;
        KEEP(*(narf.tests))
        __narf_tests_end   = .;
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

    __kernel_end = . - KERNEL_VIRT_BASE;

    /DISCARD/ : {
        *(.eh_frame*)
        *(.note.gnu.build-id)
        *(.comment)
        *(.dynamic)
        *(.interp)
        *(.gcc_except_table*)
    }
}

ASSERT(__boot_end <= __text_start - KERNEL_VIRT_BASE,
       "linker: .boot section must come before .text — see build/ §4")
