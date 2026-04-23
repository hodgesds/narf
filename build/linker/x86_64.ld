/*
 * NARF kernel linker script — x86_64.
 *
 * Spec: build/specification/spec.md §5 (kernel at -2GiB high half),
 *       boot/specification/spec.md §3–§5 (Limine handoff).
 *
 * Invariant (STAGE1.md Wave 0 #2): the `.boot` section comes before `.text`.
 * `boot/` code must be reachable at the early physical-map address the
 * bootloader hands us, then control transfers into `.text` once the virtual
 * mapping is up. ASSERT() below catches any accidental reorder.
 */

ENTRY(_start)

/* Kernel linked to run at -2GiB (standard kernel high half on x86_64).
 * The bootloader identity-maps the first few MiB of the kernel image so the
 * `.boot` stub can execute at its physical address before paging is on.
 */
KERNEL_VIRT_BASE = 0xFFFFFFFF80000000;
KERNEL_PHYS_BASE = 0x0000000000100000;  /* 1 MiB — Limine default load addr */

PHDRS
{
    boot   PT_LOAD FLAGS(5); /* R-X */
    text   PT_LOAD FLAGS(5); /* R-X */
    rodata PT_LOAD FLAGS(4); /* R-- */
    data   PT_LOAD FLAGS(6); /* RW- */
}

SECTIONS
{
    . = KERNEL_VIRT_BASE + KERNEL_PHYS_BASE;

    __kernel_start = .;

    /* `.boot` lives before `.text`. The bootloader enters through a symbol
     * in `.boot` before the MMU is fully programmed to the kernel's view.
     * See STAGE1.md Wave 1 / console+memory MMU handoff protocol.
     */
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
        *(.dynamic)
        *(.interp)
    }
}

/* The load-bearing assertion from STAGE1.md Wave 0 #2:
 * `.boot` MUST be before `.text` in the file layout; otherwise the bootloader
 * hands control to code that assumes paging is already on, and we silently
 * triple-fault at MMU enable.
 */
ASSERT(__boot_end <= __text_start,
       "linker: .boot section must come before .text — see build/ §4")
