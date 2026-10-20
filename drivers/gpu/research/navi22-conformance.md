# Navi22 conformance harness

Host-side checks that compare the Navi22 (RX 6750 XT, `navy_flounder`) driver
against Linux itself rather than against NARF's own register models. They exist
because the first conformance review found boot blockers (DCN 3.0 FB-location
offset 0x475 instead of 0x493, PSP KM ring type `1 << 16` instead of `2 << 16`)
that every model test accepted: the fakes encoded the same wrong values.

```
drivers/gpu/tools/navi22-conformance.sh            # runs everything, nonzero on any mismatch
LINUX_SRC=~/git/linux FW_DIR=target/firmware/amdgpu drivers/gpu/tools/navi22-conformance.sh
```

Requirements: python3, a C compiler, rustc (any recent stable/nightly), a Linux
tree (`LINUX_SRC`, default `~/git/linux`) and the imported firmware
(`cargo xtask import-firmware`; default `target/firmware/amdgpu`). With
`/lib/firmware/amdgpu/navy_flounder_*.bin[.zst]` present the imported payloads
are also compared byte-for-byte with the distribution blobs.

## 1. Constant checker (`tools/navi22_conformance/check_constants.py`)

Scans every Navi22-path module (`amdgpu_*navi22*.rs`, `amdgpu_dcn30_*.rs`,
`amdgpu_dcn_*.rs`, `amdgpu_dml30.rs`, `amdgpu_psp*.rs`, `amdgpu_vram_boot.rs`,
and the GFX/SMC/DMCUB firmware parsers; `*_tests.rs` excluded) and evaluates
each annotated constant against the Linux headers of the exact IP version this
card's Linux path compiles against:

| set      | Linux source                                                   | discovery IP |
| -------- | -------------------------------------------------------------- | ------------ |
| `gc`     | `gc_10_3_0_{offset,sh_mask}.h` + `gfx_v10_0.c` locals          | GC 10.3.2    |
| `gc101`  | `gc_10_1_0_*` + `gfx_v10_0.c` locals (what gfx_v10_0.c includes) | GC         |
| `dcn`    | `dcn_3_0_0_*`                                                  | DMU 3.0.0    |
| `mmhub`  | `mmhub_2_0_0_*` + `mmhub_v2_0.c` locals (MMHUB 2.1.0)          | MMHUB        |
| `oss`    | `osssys_5_0_0_*` + `navi10_ih.c` locals (OSSSYS 5.0.3)         | OSSSYS       |
| `nbio`   | `nbio_2_3_*` + `nbio_v2_3.c` locals                            | NBIF         |
| `hdp`    | `hdp_5_0_0_*`                                                  | HDP 5.0.3    |
| `mp`     | `mp_11_0_*` (MP0/MP1 11.0.11)                                  | MP0          |
| `psp11`  | `psp_v11_0.c` locals                                           | GC           |
| `smuio`  | `smuio_11_0_6_*`; `smuio0` = `smuio_11_0_0_*` (gfx_v10_0.c)    | SMUIO        |
| `thm`    | `thm_11_0_2_*` (smu_v11_0.c, THM 11.0.5)                       | THM          |
| `vcn`    | `vcn_3_0_0_*` + `vcn_v3_0.c`/`jpeg_v3_0.c` locals              | (no base)    |
| `athub`  | `athub_2_1_0_*`; `df` = `df_3_6_*`                             | ATHUB / DF   |
| `psp`    | `psp_gfx_if.h`, `amdgpu_psp.h`                                 |              |
| `ppsmc`  | `smu_v11_0_7_ppsmc.h`, `smu11_driver_if_sienna_cichlid.h`, `smu_v11_0.h`, `smu_v11_0.c`, `sienna_cichlid_ppt.c` | |
| `pm4`    | `nvd.h`; `soc15d.h`; `sdma` = `navi10_sdma_pkt_open.h`         |              |
| `ih`     | `soc15_ih_clientid.h` + the ivsrcid headers sdma_v5_2/gfx_v10_0/gmc_v10_0/vcn_v3_0 include | |
| `dmub`   | `dmub_cmd.h`, `dmub_srv.h`, `dmub_dcn30/20.{c,h}`              |              |
| `amdgpu` | core amdgpu headers + `gmc_v10_0.c`, `gfxhub_v2_1.c`, `sdma_v5_2.c`, `nv.c`, `amdgpu_vcn.c`, `amdgpu_psp.c`, `amdgpu_ucode.c`, `v10_structs.h` | |
| `atom`, `uapi`, `dc` | `atomfirmware.h`/`atombios.h`; `amdgpu_drm.h`/`drm_fourcc.h`; DC/DRM display headers | |

When a symbol exists in several sets with different values the first set in
the table wins (`--notes` lists every such case); pin with `SYM@set`.

### Annotation convention

Comment-only; applies to the code line it trails, or (standalone) to the next
code line:

```rust
pub const RB_CNTL: u32 = 0x80; // linux: mmIH_RB_CNTL
// linux: mmCP_MEC_CNTL_Sienna_Cichlid
pub const CP_MEC_CNTL: Reg = Reg(0, 0x0f55);             // idx checked vs _BASE_IDX
(Reg(1, 0x224e), Reg(0, 0x0fc3)), // linux: mmVGT_TF_RING_SIZE_UMD@gc101; mmVGT_TF_RING_SIZE_Sienna_Cichlid
const DPP_STRIDE: u64 = 0x16b; // linux: mmDPP_TOP1_DPP_CONTROL - mmDPP_TOP0_DPP_CONTROL
const DIG_MODE: u32 = 0x0007_0000; // linux: DIG0_DIG_BE_CNTL__DIG_MODE_MASK
const IH_RB_CNTL_ABS: u64 = 0x1120; // linux: abs(mmIH_RB_CNTL)        (discovery base + offset, dwords)
const C2PMSG_64: u64 = 0x58200; // linux: bytes(mmMP0_SMN_C2PMSG_64)   (BAR5 byte address)
const HDR: usize = 244; // linux: sizeof(struct rlc_firmware_header_v2_4)
const TIMEOUT_US: u32 = 100_000; // linux: n/a (NARF policy)
// linux-lit: 22=GFX_FW_TYPE_RLC_RESTORE_LIST_SRM_CNTL; 0x21=GFX_CMD_ID_AUTOLOAD_RLC
if matches!(kind, 22 | 20) { submit(command(0x21, &[])); }
// linux-ctx: hdr=oss seg=0     (restrict lookup; assert the code applies segment 0)
// linux-ctx: reset
```

* `// linux: E1; E2` — each `E` is a C expression (macros, function-like
  macros, enum constants, `offsetof`/`sizeof` via a compiled C probe) matching
  one value item of the line in order; `Reg(idx, off)` is one item and its idx
  is checked against `<sym>_BASE_IDX`.
* Masks compare at the Rust type width; register items additionally resolve to
  an absolute BAR5 address with this card's discovery bases (`--regs`), are
  rejected when BASE_IDX exceeds the IP's segment list, and warn when they land
  outside the 1 MiB BAR5 window (indirect/SMN access required).
* Unannotated integer constants are auto-matched (`mmNAME`, `regNAME`,
  `PPSMC_MSG_NAME`, `PACKET3_NAME`, `GFX_FW_TYPE_NAME`,
  `SOC15_IH_CLIENTID_NAME`); an auto-mismatch fails until the constant is
  annotated with the symbol it really mirrors (or `n/a`). Everything else is
  reported as unmapped (`--unmapped`), which is informational.

`--selftest` checks `selftest_fixture.rs`, which carries both review boot
blockers; it must flag exactly those lines.

## 2. Firmware parsers against the real blobs (`tools/navi22_conformance/fw/`)

* `linux_ucode.c` mirrors Linux's header handling for the same files using the
  Linux structs from `amdgpu_ucode.h` (`psp_init_sos_microcode` /
  `psp_init_sos_base_fw` for SOS v1.x, `amdgpu_ucode_init_single_fw` and
  `psp_load_non_psp_fw` for the PSP-loaded GFX/SDMA/RLC/VCN/DMCUB uploads,
  `smu_v11_0_init_microcode` for SMC, `dm_dmub_sw_init` /
  `dmub_srv_get_fw_meta_info` for the DMCUB inst-const/BSS split and
  metadata).
* `narf_ucode.rs` compiles NARF's own parsers (`amdgpu_psp_firmware.rs`,
  `amdgpu_smc_firmware.rs`, `amdgpu_gfx_firmware.rs`, `amdgpu_dmub_firmware.rs`)
  on the host via `#[path]` and prints the same record format.
* Both strip the NARF trailer (`firmware/src/signature.rs`: payload, Ed25519
  signature, signer, metadata, length, `NRFW`) and the outputs must be
  identical: versions, every upload's PSP firmware type, file offset and size,
  in upload order.

## Annotating under rustfmt

`cargo fmt` moves comments, so after annotating run `cargo fmt -p
narf-drivers-gpu` and then the checker again:

* A trailing comment after `{` is moved into the block and then applies to
  the block's first line. Put that annotation on the line above.
* A standalone `//` comment directly after a line with a trailing comment is
  re-indented as a continuation. Use `/// linux:` on items, or move it.
* Consecutive trailing comments in match arms or argument lists are aligned.
  That is harmless.

A `linux-lit` literal that no longer appears on its line, or an item count
that no longer matches, fails the run. A moved annotation is never accepted
silently.

## Coverage (first run, 2026-10)

59 modules: 2483 values checked against Linux (including 641 registers,
568 of them resolved to BAR5 addresses; VCN has no discovery base here), 656
marked `n/a` with a reason, 0 unmapped. Mismatches found: `ENUM_ID_MASK` and
`OBJECT_TYPE_MASK` in `amdgpu_dcn_inventory.rs` (0x0f00/0xf000, but
`ObjectID.h` has 0x0700/0x7000; fixed). The firmware diff matched all 69
records, and all twelve imported payloads are byte-identical to
`/lib/firmware`.
`navy_flounder_dmcub.bin` is a symlink to `beige_goby_dmcub.bin` there.
Since linux-firmware 20260916, `navy_flounder_ta.bin` and `_vcn.bin` are also
aliases of the `beige_goby` blobs, and `_sdma.bin` changed (0x50 -> 0x54).
`xtask import-firmware` now follows symlinks that resolve to regular files
(as Linux `request_firmware` does), importing each alias under its own name;
it used to skip them, which left a stale earlier import in place (or no file
after `--clean`). Re-import after a linux-firmware upgrade before running the
byte-identity check.
