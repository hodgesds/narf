/* Linker script for narf-testbin.
 *
 * Place the program at user vaddr 0x0000_0080_0000_1000. This
 * matches `narf_verification`'s hand-built ELFs and sits inside
 * PML4[1] (comfortably outside the kernel's low-4 GiB identity
 * map via huge pages). All code + rodata land in a single PT_LOAD
 * so the Stage-4 one-segment loader suffices.
 */

ENTRY(_start)

/* Everything gets collapsed into a single R+W+X PT_LOAD so the
 * Stage-4 one-segment-per-PT_LOAD loader sees a clean contiguous
 * page AND .data / .bss writes (libc errno, malloc state, the
 * shell's own line buffer when it spills off-stack) don't fault.
 * Split R/X / R / RW segments would overlap the same page and
 * trip `AddressSpaceError::Overlap` on the second map_region.
 * When the loader grows sub-page segment coalescing, revisit
 * splitting back into R+X for code, R for rodata, RW for data.
 */
PHDRS {
    image PT_LOAD FLAGS(7);   /* R + W + X */
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
