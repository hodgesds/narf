/*
 * NARF kernel linker script — aarch64.
 *
 * Spec: build/specification/spec.md §5 (QEMU virt at 0x4008_0000),
 *       boot/specification/spec.md §3–§5 (U-Boot/EFI + FDT handoff).
 *
 * Invariant (STAGE1.md Wave 0 #2): the `.boot` section comes before `.text`.
 */

ENTRY(_start)

/* QEMU's aarch64 `virt` machine puts RAM at 0x4000_0000. Kernel loads at
 * 0x4008_0000 (matching the Linux Image convention on virt). Stage 2
 * runs low-half identity: VMA == LMA == 0x4008_0000. Higher-half
 * relocation at 0xFFFF_8000_4008_0000 (conventional aarch64 kernel
 * space) lands with the aarch64 MMU bring-up in `memory::mmu`.
 */
KERNEL_LOAD_BASE = 0x40080000;

PHDRS
{
    boot   PT_LOAD FLAGS(5); /* R-X */
    text   PT_LOAD FLAGS(5); /* R-X */
    rodata PT_LOAD FLAGS(4); /* R-- */
    data   PT_LOAD FLAGS(6); /* RW- */
}

SECTIONS
{
    . = KERNEL_LOAD_BASE;

    __kernel_start = .;

    .boot : ALIGN(4K) {
        __boot_start = .;
        KEEP(*(.boot.header))
        KEEP(*(.boot .boot.*))
        __boot_end = .;
    } :boot

    .text : ALIGN(4K) {
        __text_start = .;
        *(.text .text.*)
        __text_end = .;
    } :text

    .rodata : ALIGN(4K) {
        __rodata_start = .;
        *(.rodata .rodata.*)
        *(.note.narf.probes)   /* USDT probe markers; tracing/ §3.3 */

        . = ALIGN(8);
        __narf_tests_start = .;
        KEEP(*(narf.tests))
        __narf_tests_end   = .;

        __rodata_end = .;
    } :rodata

    .data : ALIGN(4K) {
        __data_start = .;
        *(.data .data.*)
        __data_end = .;
    } :data

    .bss : ALIGN(4K) {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        __bss_end = .;
    } :data

    __kernel_end = .;

    /DISCARD/ : {
        *(.eh_frame*)
        *(.note.gnu.build-id)
        *(.comment)
    }
}

ASSERT(__boot_end <= __text_start,
       "linker: .boot section must come before .text — see build/ §4")
