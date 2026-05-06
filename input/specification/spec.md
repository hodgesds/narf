# narf-input — input event types + RMI4 codec

## Sources (public only)

All code is derived strictly from the references below.
**No GPL Linux source consulted.**

### Event ring + key/pointer/scroll types

- `evdev` user-space ABI — Linux's stable user-facing input event
  numbering and key-code conventions (the public ABI documented in
  `linux/input.h`'s comments / userspace-facing portion only — this
  is the *kernel-facing API*, not the kernel's GPL implementation).
  Used as a structural reference for the per-driver translation
  table shape.

### Goodix GT911 (touchscreen)

- **GT911 Programming Guide, Version 0.1** (March 2014) — Goodix
  Technology. Public document distributed by panel integrators
  (Hantick, Waveshare, Adafruit). I²C address pair (0x5D / 0x14)
  determined by INT pin state at reset, 16-bit register addressing.
- **GT911 Datasheet, Revision 0.9** — Goodix. Public.
  §3.5 (I²C protocol). §4.4 (Coordinate Reporting Layout — 5-touch
  data block at 0x814E with 1-byte status + N×8-byte point
  records). §6 (Configuration register block 0x8047..0x80FF with
  the 8-bit checksum at 0x80FF and the 1-byte "config-fresh"
  trigger at 0x8100).

### Synaptics RMI4 (touchpad)

- **Synaptics PS/2 ↔ SMBus + RMI4 Application Note** — Synaptics,
  public PDF (document number "511-000405-01"). Describes the RMI4
  transport layer that ClickPad / Force touchpads expose over
  SMBus. §4.4 Page Description Table walk. §4.5 F$01 Device Control
  control + status registers. §4.6 F$11 2D Touchpad finger
  position packing (12-bit X/Y across two bytes + a shared low-
  nibble byte). §4.10 F$34 Flash Reflash command codes.
- **Synaptics SMBus Touchpad Communication Application Note** —
  rev D, 2008. Public PDF. Covers the SMBus bring-up sequence
  modern Lenovo / Dell / HP laptop touchpads use to switch out of
  PS/2 mode into RMI4.

## Scope

### Landed
- `KeyEvent` / `PointerEvent` / `ScrollEvent` types + `EventRing`
  with the `narf-capabilities`-gated subscriber handle.
- `goodix`: clean-room GT911 codec. I²C address constants,
  status-byte decoder (buffer-ready / large-detect / have-key /
  4-bit touch count), TouchPoint parser (track-id + LE 16-bit
  X/Y/size), CoordReport multi-finger decoder, command-register
  values (read coord / soft reset / baseline update /
  calibration / screen off), config-block 8-bit checksum builder
  + verifier.
- `rmi4`: Page Description Table entry decoder, Function-Number
  constants for F$01 / F$11 / F$12 / F$30 / F$34 / F$54, F$01
  Device Control byte builder + Device Status decoder, F$11 finger
  parser (12-bit X/Y packing, touch widths) and multi-finger
  Touchpad Report decoder. F$34 command-code constants.

### Out of scope (deferred)
- F$12 next-generation touchpad function (extends F$11 with
  "Sensor Report Format" descriptor — lands when a target Force
  Touch surface needs it).
- Force Touch / haptic-feedback path (Synaptics F$54 self-test +
  F$30 GPIO/LED wiring). Surface kept but not exercised end-to-end.
