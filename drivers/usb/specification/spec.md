# narf-drivers-usb — USB host controllers and class drivers

## Sources (public only)

All driver code is derived strictly from the references below.
**No GPL Linux source consulted.**

### xHCI host controller

- **eXtensible Host Controller Interface for Universal Serial Bus
  (xHCI), Revision 1.2** — Intel. Public document.

### USB Mass Storage (BOT)

- **Universal Serial Bus Mass Storage Class Bulk-Only Transport,
  Revision 1.0** (Sep 1999) — USB-IF. Public.
- **SCSI Block Commands - 3 (SBC-3)** — for the embedded SCSI
  command opcodes (`READ(10)` / `WRITE(10)` / `INQUIRY` /
  `READ CAPACITY(10)`).

### USB HID

- **Device Class Definition for Human Interface Devices (HID),
  Version 1.11** — USB-IF. Public.
- **HID Usage Tables, Version 1.5** — USB-IF.

### USB Audio Class 1.0

- **Universal Serial Bus Device Class Definition for Audio Devices,
  Release 1.0** (March 18, 1998) — USB-IF. Public document.
  §4.3.2 (AC interface header + topology unit descriptors), §4.5.2
  (AS interface descriptors), §A.5/A.6 (subtype tables), §A.7
  (terminal type codes).
- **Universal Serial Bus Device Class Definition for Audio Data
  Formats, Release 1.0** (March 18, 1998) — USB-IF. Public.
  §A.1.1 (format tags), §A.2 (format type codes), §2.2.5 (Type-I
  PCM format descriptor layout).

## Scope

### Landed
- **xHCI** (`xhci`): MMIO bring-up, BAR mapping, command/event ring
  setup, device enumeration.
- **HID** (`hid`): Boot keyboard report decoder, modifier+keycode
  state tracking, usage-table mapping for alphanumeric input.
- **MSC** (`msc`): Bulk-Only Transport CBW/CSW codec, INQUIRY,
  READ_CAPACITY(10), READ(10), WRITE(10) for single-block transfers.
- **Hub** (`hub`): basic hub class enumeration so devices behind
  a hub are visible.
- **UAC1** (`uac`): USB Audio Class 1.0 descriptor parser. AC
  HEADER, INPUT_TERMINAL, OUTPUT_TERMINAL, FEATURE_UNIT (per-channel
  control bitmaps), AS_GENERAL, Type-I FORMAT_TYPE (discrete sample-
  rate list and continuous-range form). Class triple constants for
  bus probing. Pure descriptor decode — pairs with a future
  isochronous-endpoint scheduler in `xhci` to ship audio data.

### Out of scope (deferred)
- UAC2 / UAC3 (newer protocol byte; descriptor layouts differ).
- Isochronous endpoint scheduling on xHCI (lands when an audio data
  path is exercised end-to-end).
- USB Video Class (UVC) — webcam support.
