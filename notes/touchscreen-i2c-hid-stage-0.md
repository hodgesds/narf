# Touchscreen Stage 0 — HID-over-I2C touch event surface

## Scope

Drop touchscreens into the existing i2c-hid pump pipeline
beside the PTP (touchpad) path. Reuses the parsed
`ReportDescriptor` to spot a Touch Screen Application
Collection (Digitizer page 0x0D, usage 0x04) and decodes
per-finger reports into the shared `TouchEvent` ring.

## What landed

1. `hid/src/touchscreen.rs` — clean-room profile probe +
   `decode_input` modeled on the Microsoft "Touch Screen
   Sample Report Descriptors" reference (HID Usage Tables 1.4
   §16). Identifies per-finger Tip Switch / Contact ID / X /
   Y / Tip Pressure / In Range / Width / Height fields plus
   the top-level Contact Count.
2. `input/src/lib.rs` — `TouchState { Down, Move, Up }` plus
   `TouchEvent::{id, state, normalise_axis, normalise_xy}`.
   Coordinates remap to `0..=65535`. **Hard cutover**:
   virtio-input's protocol-B path now fills `state` / `id`
   from per-slot `was_active`.
3. `drivers/input/src/i2c_hid_touch.rs` — `TouchPumpState`
   slot allocator (max 10) keyed on Contact Identifier;
   `pump_report` allocates / frees on Down / Up transitions
   and pushes via `narf_input::push_global`.
4. `drivers/input/src/i2c_hid_bind.rs` — pump task detects
   both PTP and touchscreen profiles, dispatches per-report
   by `input_report_id`. Emits
   `touch: $path digitizer, $N contacts max, x=[...] y=[...]`.

## Smokes

- `hid/touchscreen`: descriptor parse + detect + decode
  (positive, Touch Pad rejection, wrong-report-id reject).
- `drivers/input/i2c-hid`: Down→Move→Up lifecycle, two-finger
  slot distinctness, normalisation, slot-reuse-after-Up,
  ring routing, phantom-release safety.

## Out of scope (Stage 1+)

- Stylus / pen tilt / barrel pressure.
- Width / Height bounding-box decode (constants reserved).
- Finger-rejection / palm-detection (userspace).
- Per-device coordinate rotation.

## Real-HW exposure

Phoenix HawkPoint1 panels declare `_HID` = `ELANxxxx` /
`GDIXxxxx` / `WCOMxxxx` with `_CID = "PNP0C50"` /
`"ACPI0C50"`. The bind layer's vendor-prefix whitelist
catches these; the new touchscreen detect just fires
alongside PTP on the same descriptor.
