# GFX12 rectangle fixture provenance

`src/amdgpu_gfx12_draw_data.rs` retains reviewed fixed shader, descriptor and
PM4 words originating from Mesa26.2.4 RADV/ACO/Addrlib3's META
`CmdClearAttachments` path. This is data used by the Rust diagnostic, not a
Mesa runtime or an in-tree C implementation. The compiler/shim regeneration
pipeline has been removed. The stored words and native Rust ownership tests do
not establish physical rendering or Mesa API conformance.

The Mesa archive SHA256 was
`bce5f7fbebb934373b86c999a064d52fb5065878dc57f287f95346648ec832e9`;
libdrm2.4.134 was
`ac5e74d157830eb8bee44c6a6bf3ad49774ef0dd2a72bdad74a8f20308b52a95`.
`MESA_LICENSE.txt` preserves the upstream MIT notice. Keep these provenance
records when reviewing changes to the retained data.

Fixtures describe GFX1200/GFX1201 with explicit SE counts 2/4 and PFP
versions 2630/2680. They are constructor inputs, not captured board profiles.
The native owner checks discovered SE count and retained PFP version before
selecting a fixture; harvesting remains hardware masked. LINEAR/swizzle0,
64x64RGBA8 uses 256-byte row pitch and 16KiB image storage. GE sizing is 4MiB
for 2SE and 10.5MiB for 4SE. Every address belongs to the diagnostic's retained
aperture. Prefetch uses DST_NOWHERE, preserving code R|X mappings.

Native Rust tests check command/admission and resource retention. Real GPU
completion must verify rendered and untouched pixels, guards and fresh fences;
external application acceptance must exercise the actual userspace boundary.
