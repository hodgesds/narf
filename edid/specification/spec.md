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
- **CTA-861-G** "A DTV Profile for Uncompressed High Speed Digital
  Interfaces" — Consumer Technology Association, 2016. Public
  document. §7.3 (CEA Extension Block layout), §7.5 (Data Block
  Collection: Audio / Video / Vendor / Speaker / Extended-tag).
- **HDMI Specification 1.4b** — HDMI Forum. §8.3.2 references the
  HDMI Licensing IEEE OUI 0x000C03 carried inside a CTA Vendor
  Specific Data Block, plus the byte layout for the CEC Source
  Physical Address that follows it.

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

### Stage-2 (landed)

- CTA-861-G extension block parser (`cta861::CtaExtension::parse`):
  - Tag check (0x02), revision, capabilities byte (underscan,
    basic-audio, YCbCr 4:4:4 / 4:2:2), native-DTD count.
  - Data Block Collection iterator, decoding:
    - Audio Data Block → Short Audio Descriptors (format / channels
      / sample-rates bitmap / format-dependent byte).
    - Video Data Block → Short Video Descriptors (VIC + native flag).
    - Vendor Specific Data Block → IEEE OUI + raw payload, with
      HDMI Licensing OUI (0x000C03) and HDMI Forum OUI (0xC45DD8)
      detection.
    - Speaker Allocation Data Block → channel-pair bitmap.
    - Extended Tag Code Data Block → ext-tag + payload (HDR Static
      Metadata, Colorimetry, etc., kept opaque pending follow-on).
  - Detailed Timing Descriptor list after the DBC up to byte 126.
  - HDMI VSDB convenience parse → CEC Source Physical Address.

### Out of scope (deferred)

- DisplayID 1.3 / 2.0 extension blocks.

## Cap surface

EDID parsing has no security implications past trusting the
display's bytes — it's a pure parse / no I/O. Callers that read
EDID over DDC (I²C) hold the I²C bus cap separately.
