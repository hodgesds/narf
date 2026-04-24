/*
 * NARF kernel linker script — x86_64.
 */

ENTRY(_start)

KERNEL_LOAD_BASE = 0x100000;
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
        *(.note.narf.probes)
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
