# GFX12 native rectangle reference

This offline harness builds the pinned Mesa26.2.4 RADV/ACO/Addrlib3 sources
and libdrm2.4.134. It calls the real META `CmdClearAttachments` graphics path
for a partial rectangle on one RGBA8 linear color attachment. It does not run
GPU instructions or prove physical rendering.

```
MESA_ARCHIVE=/path/mesa-26.2.4.tar.xz \
LIBDRM_ARCHIVE=/path/libdrm-2.4.134.tar.xz \
PATH=/path/glslang/bin:/path/llvm22/bin:$PATH \
sh drivers/gpu/tests/gfx12_render/generate.sh target/gfx12-render-reference
```

`generate.sh` verifies both archive SHA256s before extraction, changes only
linkage/prototypes to expose existing META/queue constructors, builds with
`-j2 --wrap-mode=nodownload`, and compares all generated shader/config,
Addrlib3 surface, ring descriptor and PM4 words against the Rust fixture.
It never downloads dependencies or changes a supplied reference checkout.
Pass `--write` after the build-directory argument to regenerate the Rust
fixture and format it. The build directory contains JSON outputs, hashes and
LLVM disassembly for audit. `SOURCE.sha256` records the archive pins.

Host prerequisites: C/C++ compiler, Meson, Ninja, pkg-config, Python3 with
Mako/PyYAML, glslangValidator>=12.2, and LLVM22+ AMDGPU tools (`LLVM_MC`,
`LLVM_OBJDUMP`, `LLVM_OBJCOPY` may override PATH). The implementation was
checked with GCC15.3, Meson1.12.1, Ninja1.13.2, Mako1.3.10,
MarkupSafe3.0.3, PyYAML6.0.3, glslang16.0.0 and LLVM22. Native kernel
models do not require this optional host compiler toolchain. The harness is
not named `check.sh` so Linux-only reference discovery stays unchanged.

The exact Mesa archive pin is
`bce5f7fbebb934373b86c999a064d52fb5065878dc57f287f95346648ec832e9`;
libdrm is
`ac5e74d157830eb8bee44c6a6bf3ad49774ef0dd2a72bdad74a8f20308b52a95`.
The generated shader/command data derives from Mesa's MIT-licensed AMD
common/RADV implementation (AMD, Intel and other Mesa contributors);
`MESA_LICENSE.txt` preserves the upstream license text.

Mesa26.2.4 removed `AMD_FORCE_FAMILY`. Its tests use the AMDGPU DRM shim,
whose pristine device table contains a recorded gfx1201 profile. This adapter
explicitly varies `CHIP_GFX1200`/`CHIP_GFX1201`, physical SE count2/4,
address32_hi=0 and PFP versions2630/2680 before device/pipeline construction;
these are compiler/constructor test inputs, not a recorded gfx1200 board.
ACO keys executable generation on GFX12 capabilities and uses the family for
disassembly. Both target ISAs independently disassemble/reassemble with LLVM;
only disabled EXP channel selectors are canonicalized (ACO uses0x80, LLVM
uses0). All active selectors and every other instruction bit must match.
The native owner checks the discovered physical SE count and retained PFP
version before selecting a fixture. Actual harvesting remains hardware
masked, as in the upstream default SPI CU mask.

`RADV_DEBUG=nobinning` and the full HiZ workaround make this fixed no-depth
proof independent of optional primitive binning/HiZ behavior. Addrlib3
produces LINEAR/swizzle0,64x64RGBA8,256-byte row pitch,16KiB image;
the harness also checks all4096 pixel addresses through the actual
`ac_surface_addr_from_coord`/Addr3 entry point. Its linear-address calculation
does not use pipe XOR or tiled addressing.
GE storage follows Mesa's1408KiB attribute/SE and position/primitive
max-SE-squared sizing:4MiB on2SE,10.5MiB on4SE. Every BO/shader VA
is provided as an explicit owned-aperture input before constructors emit PM4;
no unknown shim allocation address is replayed. Code prefetch uses the
upstream DST_NOWHERE encoding, allowing native code mappings to remain R|X.
Mesa allocates these GE rings without ZERO_VRAM or CPU initialization
(`radv_queue.c`'s `needs->ge_rings` path), so the native proof initializes
their interiors with a deterministic pattern and checks only their bounds
after execution. Task/mesh rings are not used by this draw.

Primary constructors: `radv_meta_nir_build_clear_color_shaders`,
`get_color_pipeline`, `radv_CmdClearAttachments`, `radv_emit_graphics`,
`ac_init_graphics_preamble_state`, `radv_fill_shader_rings`,
`radv_emit_ge_rings`, `ac_emit_cp_gfx11_ge_rings`,
`radv_emit_graphics_shader_pointers`, `radv_CreateImage`/Addrlib3,
`radv_gfx12_emit_fb_color_state`, `radv_emit_hw_ngg`,
`radv_emit_fragment_shader`, and the normal draw/cache-barrier paths.
The final BOTTOM_OF_PIPE PWS pair establishes pixel completion before the
outer native job fence; a compute fence alone cannot prove rendered pixels.
