# kallsyms references

- Local Linux tree `~/git/linux`, inspected for this crate:
  - `scripts/kallsyms.c` — symbol selection (`is_ignored_symbol`,
    `symbol_valid`), address order and alias tie-breaks (`compare_symbols`,
    `may_be_linker_script_provide_symbol`), the best-pair token compression
    (`optimize_token_table`, `compress_symbols`, `find_best_token`), the
    ULEB128 length prefix and the 256-symbol markers. The encoder reproduces
    the token algorithm exactly; `tests.rs` checks it against a verbatim
    port. `KSYM_NAME_LEN` = 512 (`include/linux/kallsyms.h`).
  - `scripts/mksysmap` — the name filters (`$` mapping symbols, `.L` locals,
    `__crc_`, `__kstrtab_`, …) the cargo narf extractor applies.
  - `scripts/link-vmlinux.sh` — the two/three-pass link that makes the
    table's own size stop moving symbols. NARF reaches the same fixed point in
    one link by filling a fixed-size reservation (as `.kaslr_relocs` does).
  - `kernel/kallsyms.c` — `kallsyms_expand_symbol`, `get_symbol_pos` (the
    `lookup` alias rule), `kallsyms_sym_address` (offset + relative base),
    `s_show` (`%px %c %s`), `kallsyms_open` (`show_value` cached from
    `file->f_cred`).
  - `kernel/ksyms_common.c` — `kallsyms_show_value`.
  - `tools/lib/symbol/kallsyms.c` — perf's parser: reads the name to end of
    line into a `KSYM_NAME_LEN + 1` buffer (so names over 511 bytes must be
    cut, and names may contain spaces).
  - `tools/perf/util/machine.c` — `ref_reloc_sym_names = {"_text", "_stext"}`,
    `_edata`/`_etext` as the kernel map end, `/proc/modules` handling.
  - `tools/perf/util/symbol.c` — `symbol__read_kptr_restrict`,
    `demangle_kernel = false` (why the table stores demangled names).
- `rustc-demangle` (crates.io) — the demangler the cargo narf uses; `{:#}` is the
  hash-free form binutils' `nm -C` prints for legacy and v0 Rust symbols.
