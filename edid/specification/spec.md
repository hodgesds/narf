# narf-edid — VESA Enhanced EDID parser

Clean-room parser for VESA E-EDID 1.4 (and backwards-compatible
1.3 / 1.2) blocks read from a display's DDC channel.

## References (public-only)

All parser code is derived strictly from the references below.
**No GPL Linux `drivers/gpu/drm/drm_edid.c` or any non-public
document was consulted.**

- **VESA Enhanced Extended Display Identification Data Standard,
  Release A, Revision 2** (E-EDID 1.4) — VESA, Sep 2006.
  Public document; sections referenced inline.
- **VESA Display Identification Data (DDC) Standard, Version 1.0**
  — VESA. Public document covering the I²C transport.
- **PNP ID list** — Microsoft's published manufacturer ID
  registry (the 3-character compressed-ASCII codes the
  Manufacturer Name field uses).

## Scope

### Stage-1 (landed)

- 128-byte block parser (`Block::parse`):
  - Header magic check (`00 FF FF FF FF FF FF 00`).
  - Manufacturer 3-char PNP ID + Product Code + Serial Number.
  - Manufacture week / year.
  - EDID version + revision.
  - Basic display parameters (digital input flag, max H/V size,
    gamma, supported features bitmap).
  - Established Timings I + II bitmap.
  - Standard Timings (8 entries, 2 bytes each).
  - Detailed Timing Descriptors (4 entries, 18 bytes each):
    pixel-clock, H/V active, blanking, sync offsets/widths,
    image size, border, sync polarity, interlaced flag.
  - Monitor Descriptors (Range Limits, Name, Serial, Unspecified).
  - Extension count + checksum.

### Out of scope (deferred)

- CTA-861 Extension blocks (audio, video, vendor-specific data).
  Every modern HDMI display ships at least one CTA-861 block; we
  expose `extension_count` so a future module can chain-decode.
- DisplayID extension blocks.

## Cap surface

EDID parsing has no security implications past trusting the
display's bytes — it's a pure parse / no I/O. Callers that read
EDID over DDC (I²C) hold the I²C bus cap separately.
