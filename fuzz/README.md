# narf-fuzz — libFuzzer targets for untrusted-input parsers

Implements `verification/specification/spec.md` §7: `cargo-fuzz`
(libFuzzer) on host, corpus in-tree under `fuzz/corpus/`, crash
reports become regression unit tests. The nightly gate is
`.github/workflows/fuzz-nightly.yml` (the Fuzz row of the §3
taxonomy: host, nightly).

This package is its own Cargo workspace (note the `[workspace]`
table in `Cargo.toml`) so the kernel workspace — which builds for
`*-unknown-none` through `cargo xtask` — never absorbs host
libFuzzer binaries.

## Targets

| Target | Surface under fuzz | Invariant |
| --- | --- | --- |
| `elf_loader` | `narf_userspace::elf::parse` (execve's ELF64 parser) | No panic / no OOB on any bytes; on success every segment's file range lies inside the input and `mem_size >= file_size`. |
| `fat_image` | FAT mount + bounded dir walk + reads over a RAM disk | No panic / no harness hang / no OOB; `FsError` is a fine outcome. |
| `minix_image` | MINIX mount + the same walk | Same. |
| `btf_parse` | `narf_bpf_btf::Btf::parse` + per-type size/modifier/string walks | No panic / no OOB; `BtfError` is a fine outcome. The crate docs already promise "never panics, for any input" — this target holds it to that. |

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
