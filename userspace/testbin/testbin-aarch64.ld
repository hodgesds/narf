/* Linker script for narf-testbin on aarch64.
 *
 * Place the program at user vaddr 0x0000_0080_0000_1000 — same
 * region the x86_64 variant uses so verification's hand-built ELF
 * comparisons match across arches. Single R+X PT_LOAD so the
 * loader's per-segment model sees a clean contiguous page.
 */

ENTRY(_start)

PHDRS {
    image PT_LOAD FLAGS(5);   /* R + X */
}

SECTIONS {
    . = 0x0000008000001000;

    .text : ALIGN(4096) {
        *(.text._start)
        *(.text .text.*)
        *(.rodata .rodata.*)
        *(.data .data.*)
        *(.bss .bss.*)
    } :image

    /DISCARD/ : {
        *(.eh_frame)
        *(.eh_frame_hdr)
        *(.comment)
        *(.note.*)
        *(.gnu.hash)
        *(.dynamic)
        *(.dynsym)
        *(.dynstr)
        *(.ARM.exidx*)
        *(.ARM.extab*)
    }
}
