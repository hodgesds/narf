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
- **HDMI Specification 1.4b, Supplement 1 — Consumer Electronics
  Control (CEC)** — HDMI Forum. §CEC 6 (signal form / framing),
  §CEC 7 (logical / physical addresses), §CEC 9 (message
  descriptions and encodings, opcode tables 8..14).
- **CEC v1.3a** — public Annex covering operand encodings (Power
  Status, Vendor Command With ID, Set OSD Name, Routing Change,
  Active Source).
- **VESA DisplayID Standard, Version 2.0, Errata B** (Aug 2017) —
  VESA. §2 Section structure, §3.4 Data Block header, §4.4 Type
  VII Detailed Timing Data Block (20-byte timings), Annex A
  (data-block tag codes).

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

### Stage-3 (landed)

- DisplayID 2.0 section parser (`displayid::Section::parse`):
  section header (version/revision, payload size, primary use case),
  Data Block Collection iterator with Type VII Detailed Timing
  decoder (20-byte timings — pixel clock kHz, H/V active/blanking/
  porch/sync widths, sync polarity, interlaced flag, refresh in
  millihertz). Section-checksum verification.
- HDMI CEC line protocol (`cec`): logical address enum, opcode
  constants (Image View On, Standby, Active Source, Routing Change,
  Set OSD Name, Vendor Command With ID, Report Physical Address,
  Report Power Status, Feature Abort, …), header-byte packing,
  frame encode/decode (header-only polling messages + full
  header+opcode+operand frames, capped at the spec 16-byte CEC
  message size). Builders for the most common messages.

### Out of scope (deferred)

- DisplayID 1.3 extension blocks (older tablet/laptop panels).
- DisplayID Type I/II/III/V/VIII/IX timings — Type VII is the
  modern path; older types land if a legacy panel demands it.
- CEC line-encoding (start/EOM/ACK bit timing) — handled by the
  CEC PHY (typically Realtek / Synopsys IP). The codec here is the
  bytestream CEC controllers feed to / receive from MMIO TX/RX
  registers.

## Cap surface

EDID parsing has no security implications past trusting the
display's bytes — it's a pure parse / no I/O. Callers that read
EDID over DDC (I²C) hold the I²C bus cap separately.
