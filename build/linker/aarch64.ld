/*
 * NARF kernel linker script — aarch64.
 */

ENTRY(_start)

KERNEL_LOAD_BASE = 0x40080000;
KERNEL_VIRT_BASE = 0xFFFFFF8000000000;

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
    .kaslr_relocs : AT(ADDR(.kaslr_relocs) - KERNEL_VIRT_BASE) ALIGN(4K) {
        __kaslr_relocs_start = .;
        QUAD(0);
        . = __kaslr_relocs_start + KASLR_RELOC_RESERVE;
        __kaslr_relocs_end = .;
    } :rodata

    /* Physical aliases for the apply pass. It runs in `.boot`, before the MMU,
     * where there is no kernel-half addressing at all. */
    __kaslr_relocs_phys = __kaslr_relocs_start - KERNEL_VIRT_BASE;

    /* Physical alias of `kaslr::KERNEL_SLIDE`, so the pass can record the
     * slide it applied for the Rust conversions to read later. */
    __kernel_slide_phys = KERNEL_SLIDE - KERNEL_VIRT_BASE;

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
    .kernel_bounds : AT(ADDR(.kernel_bounds) - KERNEL_VIRT_BASE) ALIGN(8) {
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
    .ap_boot_syms : AT(ADDR(.ap_boot_syms) - KERNEL_VIRT_BASE) ALIGN(8) {
        __ap_boot_syms = .;
        QUAD(_ap_start);
        QUAD(AP_STACKS);
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
