/*
 * NARF kernel linker script — aarch64.
 *
 * Spec: build/specification/spec.md §5 (QEMU virt at 0x4008_0000),
 *       boot/specification/spec.md §3–§5 (U-Boot/EFI + FDT handoff).
 *
 * Invariant (STAGE1.md Wave 0 #2): the `.boot` section comes before `.text`.
 */

ENTRY(_start)

/* QEMU's aarch64 `virt` machine puts RAM at 0x4000_0000. Kernel convention
 * on NARF: kernel at 0x4008_0000 (512 KiB above base, matching the Linux
 * Image convention on virt). High-half mapping is established by the early
 * MMU bring-up in `memory/` once `console::remap_to_virtual` hands off.
 */
KERNEL_PHYS_BASE = 0x40080000;
KERNEL_VIRT_BASE = 0xFFFF800000000000;   /* kernel half on 48-bit VA */

PHDRS
{
    boot   PT_LOAD FLAGS(5); /* R-X */
    text   PT_LOAD FLAGS(5); /* R-X */
    rodata PT_LOAD FLAGS(4); /* R-- */
    data   PT_LOAD FLAGS(6); /* RW- */
}

SECTIONS
{
    /* Initial PC is physical (EL1 entry from U-Boot / EFI stub);
     * the `.boot` stub runs at KERNEL_PHYS_BASE before MMU enable.
     */
    . = KERNEL_VIRT_BASE + KERNEL_PHYS_BASE;

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
