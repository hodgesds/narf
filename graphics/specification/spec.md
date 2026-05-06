# narf-graphics — display primitives

## Sources (public only)

All code is derived strictly from the references below.
**No GPL Linux source consulted.**

### Framebuffer / pixel primitives

- VESA Bochs Display Interface (BGA) and ramfb conventions for
  XRGB8888 layout — public.

### EDID

See `edid/specification/spec.md` — this crate's `edid.rs` is a thin
adapter that calls into the dedicated EDID parser.

### DisplayPort AUX channel + DPCD

- **VESA DisplayPort Standard, Version 1.4a** — VESA. Public document.
  §2.9 (AUX channel transactions, command byte layout), §2.9.7
  (Native AUX Read/Write framing), §2.9.7.1.5 (I²C-over-AUX),
  §3.2 (Link Training state machine), §3.6 (DPCD register map:
  receiver capability field at 0x00000.., link configuration
  field at 0x00100.., sink status at 0x00200..).
- **VESA DisplayPort Standard, Version 2.0** — VESA. Public.
  Referenced for forward-compatibility constants (UHBR rates).

## Scope

### Landed
- 32-bit XRGB8888 framebuffer + drawing primitives (rect fill,
  blit, font rendering).
- Cursor compositor + boot splash.
- EDID adapter (delegates to `narf-edid`).
- DisplayPort AUX bytestream codec (`dp_aux`): Native AUX Read /
  Write request builders, I²C-over-AUX request builder (with the
  Middle-Of-Transaction flag used during EDID readback over DP),
  reply-byte decoder. DPCD register-address constants for receiver
  capability (REV / MAX_LINK_RATE / MAX_LANE_COUNT), link
  configuration (LINK_BW_SET / LANE_COUNT_SET / TRAINING_PATTERN_SET
  / TRAINING_LANE0..3_SET), sink status (SINK_COUNT /
  LANE0_1_STATUS / LANE2_3_STATUS / LANE_ALIGN_STATUS_UPDATED), and
  power management (SET_POWER). Link-rate constants for RBR / HBR /
  HBR2 / HBR3, training-pattern values (TPS1..TPS4), and lane-status
  bit helpers.

### Out of scope (deferred)
- The AUX line encoder (Manchester encoding at 1 Mb/s) — handled by
  the SoC's DP PHY/AUX IP (Intel SBI, AMD DCN). Our codec produces
  the bytestream those blocks expect.
- DSC (Display Stream Compression) bitstream encoder — landed only
  if a target panel demands it.
