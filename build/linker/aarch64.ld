/*
 * NARF kernel linker script — aarch64.
 */

ENTRY(_start)

KERNEL_LOAD_BASE = 0x40080000;
KERNEL_VIRT_BASE = 0xFFFFFF8000000000;

/* Virtual offset of the kernel IMAGE, distinct from the linear map above.
 *
 * `KERNEL_VIRT_BASE` is the linear map: `PhysAddr::kernel_ptr` resolves every
 * physical address to `phys | KERNEL_VIRT_BASE`, so that whole range is the
 * image of RAM and nothing else may live in it. The kernel image used to live
 * there too — image VA was `KERNEL_VIRT_BASE + phys` — which made the two
 * inseparable: sliding the image inside the linear map's own L2 would
 * overwrite entries for unrelated physical addresses.
 *
 * So the image gets its own offset. `phys = va - KIMAGE_VOFFSET` for anything
 * in the image, exactly as `phys = va - KERNEL_VIRT_BASE` is on x86_64, and
 * `kaslr::KERNEL_LINK_BASE` is this value. Linux draws the same line:
 * `KIMAGE_VADDR` for the image, `PAGE_OFFSET` for the linear map, with
 * `kimage_voffset` between them and `__pa_symbol()` using it.
 *
 * Placed in L0[510], the slot the module window already occupies, so the image
 * and the module veneers stay within ADRP's +/-4 GiB of each other:
 *
 *   image        0xffffff7fc0080000  L0[510] L1[511] L2[0..36]
 *   modules      0xffffff7ff8000000  L0[510] L1[511] L2[448..]
 *
 * Disjoint L2 ranges in one L1 slot, leaving ~824 MiB for the image to slide
 * into. 1 GiB aligned so a 2 MiB block mapping can place the image exactly:
 * VA and phys then share 2 MiB alignment. */
KIMAGE_VOFFSET = 0xFFFFFF7F80000000;

/* Start of the region reserved for the module window — the mirror of
 * `memory::module_text::MODULE_VA_BASE`, which is the region base, not the
 * window's live address.
 *
 * The window is 128 MiB and the region is 384 MiB, so the window's base is
 * drawn from the remaining 256 MiB (128 positions at 2 MiB). It is the region,
 * not the window, that bounds the image's slide: the image must not slide into
 * any address the window might later occupy.
 *
 * Taking 384 MiB costs the image nothing. The slide mask is quantised to
 * `2^k - 2 MiB`, and the remaining slack (569 MiB) still admits the same
 * 510 MiB mask the full slot did — only at 512 MiB would the region force the
 * mask down to 254 MiB. */
MODULE_VA_BASE_LD = 0xFFFFFF7FE8000000;

/* Bytes reserved in-image for the KASLR relocation table. `xtask` fills it
 * after the link; the header magic is what the apply pass keys on, so an
 * unfilled reserve is a skipped slide rather than a slide by garbage.
 *
 * aarch64 needs far less than x86_64's 4M: under `code-model=small` the only
 * class a slide touches is R_AARCH64_ABS64 (~86k sites, 4 bytes each), because
 * every other absolute reference is a PC-relative ADRP+ADD pair. x86_64 must
 * additionally carry ~150k R_X86_64_32S sites. 1M leaves better than 2x
 * headroom; `xtask` fails the build if the table outgrows it. */
KASLR_RELOC_RESERVE = 1M;



/* Debug: pin the slide instead of drawing entropy, so a slide-dependent
 * failure is reproducible. Masked and aligned by the same code as a drawn
 * value, so it cannot widen the window. 0 = draw entropy. */
KASLR_SLIDE_FIXED = 0x00000000;

/* Physical relocation: copy the image this many bytes up from where the loader
 * put it and run from the copy. The VA slide randomizes where the image
 * APPEARS; this randomizes where it IS.
 *
 * Unlike x86_64 this is still a pin rather than a value chosen at boot. The
 * memory map arrives in the DTB — big-endian, nested, string-keyed — so walking
 * it to /memory and /chosen is a much larger job in assembly than the flat
 * PVH array the x86_64 stub reads, and picking a target without it would be
 * guessing at where RAM and the initrd are.
 *
 * Constraints a value here must satisfy, unchecked because nothing parses the
 * map yet:
 *   - target + image size stays inside RAM (QEMU virt: 0x4000_0000 up);
 *   - target stays below 2 GiB, which is all the TTBR0 identity map covers
 *     (lo_L1[0..1], two 1 GiB blocks) and `.boot` executes there post-MMU;
 *   - at least the image's size, so the forward copy cannot eat its source;
 *   - clear of the DTB and the initrd the loader placed.
 * 0 = run where the loader put us.
 *
 * 0x1000_0000 puts the copy at 0x5008_0000..0x541e_6db0. QEMU's virt machine
 * places the kernel, the initrd and the DTB all inside the first 256 MiB of RAM
 * (the DTB lands at 0x4f00_0000, just under the 0x5000_0000 mark), so starting
 * above that clears every one of them; it also still fits inside boot-smoke's
 * 512 MiB, not just the suite's 1 GiB. */
KASLR_PHYS_FIXED = 0x10000000;

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

    . += KIMAGE_VOFFSET;

    .text : AT(ADDR(.text) - KIMAGE_VOFFSET) ALIGN(4K) {
        __text_start = .;
        *(.text .text.*)
        __text_end = .;
    } :text

    /* KASLR relocation table. Reserved here at link time and filled by
     * `xtask` after the link, because the site list is only knowable once
     * addresses are final.
     *
     * In-image and PROGBITS on purpose: `.bss` has no file bytes for `xtask`
     * to write into, and anything outside a PT_LOAD segment never reaches
     * memory. The leading QUAD(0) is the header magic slot — `boot.S` checks
     * it and skips the slide entirely if the table was never filled, so a
     * forgotten patch step disables KASLR instead of sliding by garbage.
     *
     * Linux arm64 does not need an equivalent: it links `-shared -Bsymbolic`
     * and consumes the `.rela.dyn` R_AARCH64_RELATIVE entries directly
     * (arch/arm64/kernel/pi/relocate.c). NARF reuses its own table format on
     * both arches so there is one encoder and one apply pass to reason about. */
    .kaslr_relocs : AT(ADDR(.kaslr_relocs) - KIMAGE_VOFFSET) ALIGN(4K) {
        __kaslr_relocs_start = .;
        QUAD(0);
        . = __kaslr_relocs_start + KASLR_RELOC_RESERVE;
        __kaslr_relocs_end = .;
    } :rodata

    /* Physical aliases for the apply pass. It runs in `.boot`, before the MMU,
     * where there is no kernel-half addressing at all. */
    __kaslr_relocs_phys = __kaslr_relocs_start - KIMAGE_VOFFSET;

    /* Physical alias of `kaslr::KERNEL_SLIDE`, so the pass can record the
     * slide it applied for the Rust conversions to read later. */
    __kernel_slide_phys = KERNEL_SLIDE - KIMAGE_VOFFSET;

    /* Physical alias of `kaslr::IMAGE_PHYS_DELTA`, so the stub can record how
     * far it moved the image. A link-time address: the stub adds the delta
     * itself to reach the copy's word. */
    __image_phys_delta_phys = IMAGE_PHYS_DELTA - KIMAGE_VOFFSET;

    .rodata : AT(ADDR(.rodata) - KIMAGE_VOFFSET) ALIGN(4K) {
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

    .data : AT(ADDR(.data) - KIMAGE_VOFFSET) ALIGN(4K) {
        __data_start = .;
        *(.data .data.*)
        __data_end = .;
    } :data

    .bss : AT(ADDR(.bss) - KIMAGE_VOFFSET) ALIGN(4K) {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        __bss_end = .;
    } :data

    /* Physical bounds of the loaded image, as VALUES in a high-half word.
     *
     * `__kernel_start` / `__kernel_end` are physical addresses, because `.boot`
     * is linked at `KERNEL_LOAD_BASE` rather than in the kernel half. Kernel
     * code must not reference them directly: `addr_of!(sym)` compiles to a
     * PC-relative page reference (ADRP+ADD on aarch64, a 32-bit signed
     * absolute on x86_64), and the distance from kernel-half code to a low
     * symbol is ~512 GiB — beyond ADRP's +/-4 GiB. That is what pins aarch64
     * to `code-model=large`, and the large model materialises every absolute
     * address as four MOVZ/MOVK immediates, which a slide cannot patch without
     * carrying the full target value for ~967k sites.
     *
     * Linux has the same split and the same answer: the value lives in a
     * runtime word (`kimage_voffset`, stored by `head.S`), and `__pa_symbol()`
     * reads it. Populating the word at link time gets there without the store.
     *
     * The values are physical, so they are below `KERNEL_VIRT_BASE` and the
     * KASLR pass leaves them alone — `relocs.rs` matches on whether the
     * encoded VALUE moves, not just the field.
     */
    .kernel_bounds : AT(ADDR(.kernel_bounds) - KIMAGE_VOFFSET) ALIGN(8) {
        __kernel_phys_bounds = .;
        QUAD(__kernel_start);
        QUAD(__kernel_end);
    } :data

    /* Physical addresses of the AP trampoline entry and its stack table.
     *
     * Both live in `.boot` / `.boot.data`, which is linked low so an AP can
     * execute it before the MMU is on. `smp.rs` needs the entry address to
     * hand to PSCI CPU_ON and needs to write the stack table, and it runs in
     * the kernel half — so it faces the same +/-4 GiB ADRP limit as the image
     * bounds above and gets the same treatment: read the VALUE here rather
     * than take the address of a low symbol.
     *
     * Linux does the same thing at the same place: `psci.c` boots a secondary
     * with `__pa_symbol(secondary_entry)` rather than referencing a physical
     * symbol. The low identity map is still live during bring-up, so the
     * address is directly usable as a pointer.
     */
    .ap_boot_syms : AT(ADDR(.ap_boot_syms) - KIMAGE_VOFFSET) ALIGN(8) {
        __ap_boot_syms = .;
        QUAD(_ap_start);
        QUAD(AP_STACKS);
    } :data


    __kernel_end = . - KIMAGE_VOFFSET;

    /* Physical end of `.text`. `boot.S` builds its L2 tables before the
     * MMU is on, so it can only compare *physical* addresses; doing the
     * `- KIMAGE_VOFFSET` here keeps a 64-bit constant and a subtraction
     * out of the assembly. Everything at or past this address — .rodata,
     * .data, .bss, .got, and every frame the buddy later hands out — is
     * mapped PXN|UXN in both the TTBR0 identity map and the TTBR1 kernel
     * window, so it has no executable alias. */
    __text_end_phys = __text_end - KIMAGE_VOFFSET;

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

/* KASLR slide bound, derived from the image the way x86_64's is.
 *
 * The image now has its own VA offset (`KIMAGE_VOFFSET`), so it can slide
 * without touching the linear map. What bounds it is the module window above
 * it in the same L1 slot: image top plus the widest slide must stay below
 * `MODULE_VA_BASE`, or a slid image would land on module text.
 *
 * Masks are contiguous and 2 MiB aligned, `m(k) = 2^k - 2 MiB`, because the
 * slide is `entropy & MASK` and a gap in the mask is a bit the slide can never
 * set. Largest fitting `m(k)` without log2 or a ternary: since
 * `m(k) - m(k-1) == 2^(k-1)`, summing `2^(k-1)` over every `m(k)` that fits
 * telescopes to the largest. Same construction as the x86_64 script.
 *
 * `KASLR_ENABLE = 0` turns it off wholesale; the mask reaching 0 is what
 * `smoke_kaslr_kernel_image_is_slid` keys on to Skip rather than Pass. */
KASLR_ENABLE = 1;
KASLR_SLIDE_SLACK = MODULE_VA_BASE_LD - (KIMAGE_VOFFSET + __kernel_end);
KASLR_SLIDE_MASK = KASLR_ENABLE * (
      (KASLR_SLIDE_SLACK >= 0x3FE00000) * 0x20000000
    + (KASLR_SLIDE_SLACK >= 0x1FE00000) * 0x10000000
    + (KASLR_SLIDE_SLACK >= 0x0FE00000) * 0x08000000
    + (KASLR_SLIDE_SLACK >= 0x07E00000) * 0x04000000
    + (KASLR_SLIDE_SLACK >= 0x03E00000) * 0x02000000
    + (KASLR_SLIDE_SLACK >= 0x01E00000) * 0x01000000
    + (KASLR_SLIDE_SLACK >= 0x00E00000) * 0x00800000
    + (KASLR_SLIDE_SLACK >= 0x00600000) * 0x00400000
    + (KASLR_SLIDE_SLACK >= 0x00200000) * 0x00200000);

ASSERT(__boot_end <= __text_start - KIMAGE_VOFFSET,
       "linker: .boot section must come before .text — see build/ §4")

/* The image plus the widest slide the mask allows must stay clear of the
 * module window in the same L1 slot. Same guard the x86_64 script has against
 * its module text window, and the reason the mask is derived rather than
 * hand-picked. */
ASSERT(KIMAGE_VOFFSET + __kernel_end + KASLR_SLIDE_MASK <= MODULE_VA_BASE_LD,
       "linker: image + KASLR_SLIDE_MASK reaches the module window — lower the mask \
or move MODULE_VA_BASE (and module_text::MODULE_VA_BASE with it)")
