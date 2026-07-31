/*
 * NARF kernel linker script — aarch64.
 */

ENTRY(_start)

KERNEL_LOAD_BASE = 0x40080000;
KERNEL_VIRT_BASE = 0xFFFFFF8000000000;

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
        KEEP(*(.boot .boot.*))
        __boot_end = .;
    } :boot

    .boot.data : ALIGN(4K) {
        __boot_data_start = .;
        *(.boot.data)
        __boot_data_end = .;
    } :boot

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

    __kernel_end = . - KERNEL_VIRT_BASE;

    /* Physical end of `.text`. `boot.S` builds its L2 tables before the
     * MMU is on, so it can only compare *physical* addresses; doing the
     * `- KERNEL_VIRT_BASE` here keeps a 64-bit constant and a subtraction
     * out of the assembly. Everything at or past this address — .rodata,
     * .data, .bss, .got, and every frame the buddy later hands out — is
     * mapped PXN|UXN in both the TTBR0 identity map and the TTBR1 kernel
     * window, so it has no executable alias. */
    __text_end_phys = __text_end - KERNEL_VIRT_BASE;

    /* Aliased high-VA view of the boot stack. The boot stack
     * itself lives in `.boot.data` at low-VA so boot.S's
     * pre-MMU `adrp` + `:lo12:` setup keeps working (adrp can't
     * reach high-VA from a pre-MMU low PC). Once the MMU is on
     * and `_start_rust_entry` has branched to high-VA, any code
     * that swaps TTBR0 (e.g. `AddressSpace::activate()`) must
     * not be running on a low-VA stack — the low-half mapping
     * disappears with the swap. We expose `stack_top_virt` so
     * `_start_rust_entry` can install a high-VA SP that lives
     * inside TTBR1's mapping of the same physical bytes.
     *
     * `stack_top` is a LOW-VA absolute address (the linker
     * placed `.boot.data` at PA 0x40081000+). OR-ing in
     * `KERNEL_VIRT_BASE` produces the matching VA in TTBR1's
     * 1 GiB block at L0[511]/L1[1]. */
    PROVIDE(stack_top_virt = stack_top + KERNEL_VIRT_BASE);

    /DISCARD/ : {
        *(.eh_frame*)
        *(.comment)
    }
}

ASSERT(__boot_end <= __text_start - KERNEL_VIRT_BASE,
       "linker: .boot section must come before .text — see build/ §4")
