/*
 * NARF kernel linker script — x86_64.
 *
 * Spec: build/specification/spec.md §5, boot/specification/spec.md §3–§5.
 *
 * Stage 1 layout: link + load both at physical 0x100000 (the Multiboot
 * standard load address). Higher-half relocation is deferred until `memory/`
 * brings the MMU up with the final kernel-virtual mapping and
 * `console::remap_to_virtual` executes — that's the earliest we can jump
 * from low-half into -2 GiB without unmapped-address faults. See
 * STAGE1.md Wave 1 for the critical-path reasoning.
 *
 * Invariant (STAGE1.md Wave 0 #2): `.boot` precedes `.text`. The ASSERT
 * at the end of this file is the static guard.
 */

ENTRY(_start)

KERNEL_LOAD_BASE = 0x100000;    /* Multiboot low-1-MiB load address */

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

    /*
     * `.boot` is where `_start` lives. It runs in 32-bit protected mode
     * directly after multiboot2 hands control over, transitions to long
     * mode, and then calls into `.text` (`_start_rust`). The multiboot2
     * header must be within the first 32 KiB of the ELF and 8-byte
     * aligned — we place it as the first section of `.boot`.
     */
    .boot : ALIGN(4K) {
        __boot_start = .;
        KEEP(*(.boot .boot.*))
        __boot_end = .;
    } :boot

    /* PT_NOTE only — the note is read by the loader at boot time, not
     * mapped into guest memory at runtime. Assigning it to :rodata too
     * makes the rodata PT_LOAD span everything through .text, which
     * trips QEMU's "overlapping ROM regions" check. */
    .note.Xen : ALIGN(4) {
        KEEP(*(.note.Xen))
    } :note

    .text : ALIGN(4K) {
        __text_start = .;
        *(.text .text.*)
        __text_end = .;
    } :text

    .rodata : ALIGN(4K) {
        __rodata_start = .;
        *(.rodata .rodata.*)
        *(.note.narf.probes)        /* USDT probe markers; tracing/ §3.3 */
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
        *(.gcc_except_table*)
    }
}

ASSERT(__boot_end <= __text_start,
       "linker: .boot section must come before .text — see build/ §4")
