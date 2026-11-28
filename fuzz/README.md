# narf-fuzz — libFuzzer targets for untrusted-input parsers

Implements `verification/specification/spec.md` §7: `cargo-fuzz`
(libFuzzer) on host, corpus in-tree under `fuzz/corpus/`, crash
reports become regression unit tests. The nightly gate is
`.github/workflows/fuzz-nightly.yml` (the Fuzz row of the §3
taxonomy: host, nightly).

This package is its own Cargo workspace (note the `[workspace]`
table in `Cargo.toml`) so the kernel workspace — which builds for
`*-unknown-none` through `cargo narf` — never absorbs host
libFuzzer binaries.

## Targets

| Target | Surface under fuzz | Invariant |
| --- | --- | --- |
| `elf_loader` | `narf_userspace::elf::parse` (execve's ELF64 parser) | No panic / no OOB on any bytes; on success every segment's file range lies inside the input and `mem_size >= file_size`. |
| `fat_image` | FAT mount + bounded dir walk + reads over a RAM disk | No panic / no harness hang / no OOB; `FsError` is a fine outcome. |
| `minix_image` | MINIX mount + the same walk | Same. |
| `btf_parse` | `narf_bpf_btf::Btf::parse` + per-type size/modifier/string walks | No panic / no OOB; `BtfError` is a fine outcome. The crate docs already promise "never panics, for any input" — this target holds it to that. |
| `acpi_table` | The 45 `__test_parse_*_body` table decoders in `narf_acpi` (PPTT, IORT, DMAR, IVRS, HEST, SPCR, ...), dispatched on the table signature; SRAT entries via `__parse_srat_body_for_test` | No panic / no OOB on any bytes; short tables are rejected by each decoder's length checks. The RSDP/XSDT chain walkers are out of scope — they dereference physical addresses, which has no host meaning. |
| `aml_method` | `narf_aml::__parse_body_for_test` — the AML namespace build over a raw byte stream (no SDT header) | No panic / no OOB; `AmlError` is a fine outcome, partial namespace is documented behaviour. Nesting is capped by `MAX_NAMESPACE_DEPTH` / `MAX_EVAL_NESTING`; the harness resets the global namespace before every input. |
| `fdt_blob` | `narf_firmware_fdt::parse_header` + `walk_with_cells` + `reg` decode + `chosen_bootargs` / `chosen_initrd_range` + reservation / memory-range copies + `compatible` matchers | No panic / no OOB; `None` / `0` is a fine outcome. The walker is iterative with a fixed path-depth cap. |
| `edid_block` | `narf_edid::Block::parse` over the first 128 bytes, then extension blocks by tag: `0x02` → `cta861::CtaExtension::parse`, `0x70` → `displayid::Section::parse` | No panic / no OOB; `EdidError` / `DisplayIdError` is a fine outcome. Every parse is over a fixed 128-byte slice. |

§7's other initial targets — cap-table slot decoder, Narf-Ring
message parser, virtio descriptor validator — are follow-ups on
issue #758 now that the harness and the nightly exist.

## Running locally

Requires the repo's pinned nightly (cargo-fuzz needs nightly) and
`cargo install cargo-fuzz`:

```sh
cd fuzz
cargo fuzz run elf_loader            # until Ctrl-C
cargo fuzz run fat_image -- -max_total_time=300
cargo fuzz build                       # build all targets only
```

The filesystem targets initialise the kernel services they need
once per process (`narf_fuzz::host`, modelled on
`verification/btrfs-host`'s host harness: a 1 GiB identity-mapped
arena for the frame allocator plus `narf_scheduler::init()`).

## Corpus and seeds

`corpus/<target>/` is checked in, per spec. The starting seeds are
**binary files derived from in-tree test fixtures** — flagged here
explicitly for repo hygiene:

| Seed | Derivation |
| --- | --- |
| `corpus/elf_loader/minimal-et-dyn` | Hand-built minimal ELF64 `ET_DYN` with one `PT_LOAD`, laid out against the acceptance checks in `userspace/src/elf.rs::parse`. |
| `corpus/fat_image/fat12-narf-txt` | Byte-for-byte the image the FAT kernel tests build in code (`build_fat12_image_fat_sectors` in `drivers/fs/fat/src/tests.rs`): FAT12, one root file `NARF.TXT`. |
| `corpus/minix_image/minix3-hi-txt` | Byte-for-byte the image from `build_minix3_image` in `drivers/fs/minix/src/tests.rs`: MINIX3, root dir with `hi.txt`. |
| `corpus/btf_parse/minimal-int` | The minimal blob from `narf-bpf-btf`'s host tests: header + one `int` type + string section. |
| `corpus/acpi_table/pptt-cpu-cache` | The PPTT table from `smoke_acpi_pptt_synthetic_decode` in `acpi/src/tests.rs`: SDT header + Type-0 Processor (leaf, UID 0x42) + Type-1 Cache (64 B line, 8-way, 32 KiB). `pptt-truncated` is its first 40 bytes. |
| `corpus/acpi_table/srat-lapic`, `srat-memory` | The SRAT entries from `smoke_acpi_srat_synthetic_lapic_entry` / `smoke_acpi_srat_synthetic_memory_entry`: one Type-0 LAPIC entry (APIC 7, node 3) / one Type-1 memory entry, each after the 36-byte header + 12 reserved bytes. `srat-bad-length` is the LAPIC seed with the entry length byte set to 0xFF. |
| `corpus/acpi_table/iort-its-smmuv3` | The IORT table from `smoke_acpi_iort_synthetic_decode`: ITS group (ID 0xCAFE) + SMMUv3 node (base 0xDEAD0000, flags 0xA5). |
| `corpus/acpi_table/spcr-pl011` | The SPCR table from `smoke_acpi_spcr_synthetic_decode`: ARM PL011 at 0x9000000, GSI 33, 115200 baud. |
| `corpus/acpi_table/hest-mce-ghes` | The HEST table from `smoke_acpi_hest_synthetic_decode`: Type-0 MCE (source 0xABCD) + Type-9 GHES (source 0x1234). |
| `corpus/aml_method/scope-name` | The Scope(`\X`) { Name(`_HID`, DWord) } body from `smoke_aml_synthetic_scope_and_name` in `aml/src/tests.rs`. `scope-name-truncated` is its first 8 bytes; `scope-name-bad-pkglen` has the PkgLength byte set to 2. |
| `corpus/aml_method/method-return-one` | The Method(`\Y`, 0) { Return(One) } body from `smoke_aml_synthetic_method_skipped`. |
| `corpus/aml_method/processor-cpu7` | The Processor(`\CPU7`, 42) body from `processor_identity_retained`. |
| `corpus/fdt_blob/minimal-memory-node` | `build_blob` from `firmware/fdt/src/tests.rs` with one `memory@0` node (`device_type = "memory"`), as in `smoke_fdt_walk_minimal`. `header-only` is its first 40 bytes; `bad-magic` has the magic zeroed. |
| `corpus/fdt_blob/chosen-bootargs` | `build_blob` with a `chosen` node carrying `bootargs = "console=ttyAMA0"`, as in `smoke_fdt_chosen_bootargs`. |
| `corpus/fdt_blob/memory-ranges` | `build_blob` with a `memory@40000000` node carrying a `reg` (0x40000000 + 0x10000000), as in `smoke_fdt_memory_ranges`. |
| `corpus/fdt_blob/reserved-memory` | `build_blob` with one memory reservation (0x80000000 + 0x10000). |
| `corpus/edid_block/valid-1080p` | `make_block` from `edid/src/tests.rs` with the 1920×1080 @ 60 Hz DTD from `smoke_edid_detailed_timing_decodes_1080p_60`. `valid-1080p-name` swaps the DTD for the "narf monitor" name descriptor from `smoke_edid_monitor_name_descriptor`. |
| `corpus/edid_block/valid-1080p-cta` | The 1080p base block with `extension_count = 1` plus a CTA-861 block (`make_cta_block`, revision 3, empty data-block collection) from `smoke_cta_caps_decode`. |
| `corpus/edid_block/bad-checksum` | The 1080p block with the checksum byte tampered (+1). `truncated-64` is its first 64 bytes. |

Per spec §7 the corpus is minimised weekly; in practice, minimise
when adding a crash-derived entry (`cargo fuzz cmin <target>`).

## When a target crashes

1. The nightly job uploads the reproducing input as the
   `fuzz-crash-<target>` artifact.
2. File the crash on the owning subsystem's tracker with the input
   attached and the target name.
3. Fix the parser, add the input as a **regression unit test** in
   the owning crate (spec §7), and only then add it to
   `corpus/<target>/` so the fuzzer keeps it as a seed.
