/* Linker script for narf-libc-validate.
 *
 * Place the program at user vaddr 0x0000_0080_0001_0000 — distinct
 * from narf-testbin's 0x0000_0080_0000_1000 so both binaries can
 * coexist in the same kernel test run without colliding on a
 * mapped region.
 *
 * Layout:
 *   - PT_LOAD R+X carrying .text + .rodata + (collapsed) .data/.bss.
 *     Single-segment for the same Stage-4 loader reasons described
 *     in testbin.ld: split R/X vs R-only segments overlap the same
 *     page and trip AddressSpaceError::Overlap.
 *   - PT_LOAD R+W carrying a 16-byte .tdata image. The TLS stager
 *     reads PT_TLS off this segment to size the per-thread block.
 *   - PT_TLS overlapping the .tdata bytes — the kernel's loader
 *     uses the PT_TLS phdr to know which bytes form the TLS image
 *     and how big the per-thread block must be.
 *
 * The .tdata image carries 16 bytes: 12 padding bytes + a 4-byte
 * `errno` slot at the very end. Per the SysV-AMD64 initial-exec
 * model, fs_base = TCB_self_pointer = end of the TLS template, so
 * the last 4 bytes of the image sit at fs_base - 4. The narf-libc
 * errno helpers read at fs_base - 8 (8-byte slot to keep the field
 * naturally aligned), which is the last 8 bytes of the image.
 */

ENTRY(_start)

PHDRS {
    image PT_LOAD FLAGS(5);   /* R + X */
    tdata PT_LOAD FLAGS(6);   /* R + W */
    tls   PT_TLS  FLAGS(4);   /* R     */
}

SECTIONS {
    . = 0x0000008000010000;

    .text : ALIGN(4096) {
        *(.text._start)
        *(.text .text.*)
        *(.ltext .ltext.*)
        *(.rodata .rodata.*)
        *(.lrodata .lrodata.*)
        *(.data .data.*)
        *(.bss .bss.*)
    } :image

    . = ALIGN(4096);
    /* Hand-rolled 16-byte TLS template. We do NOT pull from
     * `*(.tdata)` here because Rust's `#[link_section = ".tdata"]`
     * marks the static as TLS GLOBAL with vaddr 0 — codegen then
     * emits a literal `(0)` load, which faults. Instead we BYTE()
     * the template directly into the linker script so the bytes
     * exist purely as image data the kernel's PT_TLS staging
     * picks up. The narf-libc errno helpers read fs_base - 8,
     * which lands inside this hand-rolled image once the kernel
     * has staged it.
     */
    .tdata : {
        BYTE(0x00); BYTE(0x00); BYTE(0x00); BYTE(0x00);
        BYTE(0x00); BYTE(0x00); BYTE(0x00); BYTE(0x00);
        BYTE(0x00); BYTE(0x00); BYTE(0x00); BYTE(0x00);
        BYTE(0x00); BYTE(0x00); BYTE(0x00); BYTE(0x00);
    } :tdata :tls

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
