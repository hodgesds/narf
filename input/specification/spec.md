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
