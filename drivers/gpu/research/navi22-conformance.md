# Navi22 register and firmware source notes

The Navi22 (`navy_flounder`) Rust implementation retains source annotations for
register offsets, masks, firmware layouts and IP selection. Those annotations
are review provenance, not an executable validation language. The former host
compiler/comparison pipeline has been removed.

Past source review identified a DCN3 framebuffer-location offset (`0x493`) and
PSP kernel ring type (`2 << 16`) that permissive models had missed. That history
illustrates the limit of internal tests: matching a model does not independently
establish the external hardware contract. Review exact IP versions and bank
selection against the primary documentation/source and require physical
acceptance before promoting support.

The source sets below document the reference families used for Navi22. NARF's
Rust tests exercise actual parser, identity, bounds and register-owner paths;
they make no claim that the current external sources are byte-for-byte equal.

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


Firmware parsing remains production Rust. Signed asset authority, bounds,
version checks, upload ownership and verified reset are separate from a file's
source provenance or a model result. Existing fixtures and upstream notices are
retained. External Linux/Mesa compatibility and physical firmware execution
remain acceptance work.

## Captured RX 6750 XT preflight coverage

`amdgpu_navi22_board_tests.rs` carries the discovery metadata from the MSI
`1462:3985`, PCI revision `c0`, with its actual GC/DCN/NBIO/HDP/OSSSYS banks,
distinct `SDMA0:0` and `SDMA1:0` engines, 12272 MiB usable VRAM, 16 GiB BAR0,
and high MC addresses. Its inert, revoked-authority constructors check the
later HDMI/DP display paths and GMC/GART/CP/SDMA reservations without touching
hardware. Those checks complement the stage-order and register models; they
do not establish that a hardware checkpoint completes.

This board's VBIOS `113-MSITV398MH.310` has no command entries 4
(`digxencodercontrol`), 12 (`setpixelclock`) or 76
(`dig1transmittercontrol`). The board case in `amdgpu_navi22_bios_tests.rs`
therefore verifies that display setup sends DMUB commands and uses the v1.7
transmitter fallback without requiring those tables. Without a running DMUB,
the missing pixel-clock table remains an error. Its data tables report a
100 MHz DCHUB reference and twelve 16-bit VRAM channels; do not substitute
the reference clock or memory geometry of another fixture.
