# Intel HDA — Stage-0 PCH controller coverage

Date: 2026-05-25. Companion to `audio/src/hda.rs`.

## What landed

The HDA controller driver's PCI match table now binds every modern
Intel PCH HDA controller and the Tiger Lake iGPU display-audio
function in addition to the existing AMD Phoenix / Radeon and Intel
ICH6 / ICH7 / ICH9 lines. The HDA programming model is identical
across vendors (Intel "High Definition Audio Specification" rev 1.0a)
so every entry routes through the same `probe` — bring-up reset,
CORB / RIRB allocation, STATESTS codec walk, Get-Parameter
vendor / revision / function-group descriptor.

Match table is now a static `HDA_PCI_IDS: &[(&str, u16, u16)]` table
that `register_pci_driver` iterates — easier to extend, easier to
audit.

## Intel device IDs added (all vendor 0x8086)

PCH HDA controller:
- `0x9D70`, `0x9D71` — Sunrise Point-LP (Skylake / Kaby Lake PCH-LP)
- `0xA348` — Cannon Lake PCH
- `0xA171`, `0x43C8` — Comet Lake variants
- `0xA0C8`, `0xA0C9` — Tiger Lake PCH-LP
- `0x7AD0`, `0x51C8`, `0x51CD` — Alder Lake-P / Alder Lake-S
- `0x7E28` — Meteor Lake

iGPU display-audio (graphics PCI function, HDMI / DP audio path):
- `0x4F90`, `0x4F92` — Tiger Lake-H graphics audio
- `0x9A09`, `0x9A0C` — Tiger Lake-LP graphics audio

Reference: Linux `sound/pci/hda/hda_intel.c` `azx_ids[]` + `pci.ids`.

## Codec layer

`audio/src/hda_codec.rs` is transport-neutral: enumerate() works
against any `verb -> response` resolver. Verb encoding follows HDA
§7.3, no vendor-specific opcodes. Realtek / Conexant / IDT codecs on
Intel platforms are reached through the same Get-Parameter walk
that already works on AMD.

## Smokes

- `smoke_hda_match_amd_phoenix_ids` — unchanged (AMD + ICH9).
- `smoke_hda_match_intel_pch_ids` — new; asserts every Intel PCH +
  TGL graphics device id is in the match table.

## Out of scope (Stage-1+)

- SoundWire (`drivers/audio/sdw/` — separate bus / cap-list ID).
- Intel SST DSP firmware loading (Skylake+ Audio DSP / `cAVS`,
  `IPC` doorbell, ADSP topology blobs).
- HDMI / DP audio ELD parsing (graphics-side codec quirk).
- Per-codec quirk patches (Realtek ALC subsystem-ID overrides,
  Conexant pin-fixups).
- Per-PCH timing quirks (TGL+ codec-reset hold-off,
  `azx_skip_init_dsp_*` flags from Linux).

## References

- Intel "High Definition Audio Specification" rev 1.0a, §3.3 / §7.3
- Linux `sound/pci/hda/hda_intel.c` (`azx_ids[]`, `azx_probe`)
- Linux `sound/pci/hda/hda_controller.c` (controller bring-up)
