/* Linker script for narf-testbin.
 *
 * Place the program at user vaddr 0x0000_0080_0000_1000. This
 * matches `narf_verification`'s hand-built ELFs and sits inside
 * PML4[1] (comfortably outside the kernel's low-4 GiB identity
 * map via huge pages). All code + rodata land in a single PT_LOAD
 * so the Stage-4 one-segment loader suffices.
 */

ENTRY(_start)

/* Everything gets collapsed into a single R+X PT_LOAD so the
 * Stage-4 one-segment-per-PT_LOAD loader sees a clean contiguous
 * page. Split R/X vs R-only segments would overlap the same page
 * and trip `AddressSpaceError::Overlap` on the second map_region.
 * When the loader grows sub-page segment coalescing, revisit.
 */
PHDRS {
    image PT_LOAD FLAGS(5);   /* R + X */
}

SECTIONS {
    . = 0x0000008000001000;

    .text : ALIGN(4096) {
        *(.text._start)
        *(.text .text.*)
        *(.ltext .ltext.*)
        *(.rodata .rodata.*)
        *(.lrodata .lrodata.*)
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
    }
}
