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

### USB Video Class 1.5

- **Universal Serial Bus Device Class Definition for Video Devices,
  Revision 1.5** (March 16, 2012) — USB-IF. Public.
  §3.1 (class triple), §3.7 (VC class-specific descriptors:
  HEADER, INPUT_TERMINAL camera, OUTPUT_TERMINAL, PROCESSING_UNIT,
  EXTENSION_UNIT), §3.9.2.1 (VS INPUT_HEADER), Annex A (terminal
  type codes).
- **Universal Serial Bus Device Class Definition for Video Devices:
  Uncompressed Payload, Revision 1.5** — USB-IF. Public. §3.1.1
  (FORMAT_UNCOMPRESSED + Format-GUID byte order), §3.1.2
  (FRAME_UNCOMPRESSED).
- **Universal Serial Bus Device Class Definition for Video Devices:
  Frame-Based Payload, Revision 1.5** — USB-IF. Public.

### UVC payload header (1.5 §2.4.3.3)

- **UVC 1.5 §2.4.3.3** "Video and Still Image Payload Headers" —
  USB-IF. Public. Bit Field Header layout (FID toggle, EOF, PTS
  flag, SCR flag, SI flag, Error, EOH).
- **UVC 1.5 §2.4.3.4** "Source Clock Reference and Presentation
  Time Stamp" — USB-IF. Public. PTS = LE 32-bit; SCR = LE 32-bit
  SOF tick + 11-bit clock counter packed across 6 bytes.

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
- **UVC stream** (`uvc_stream`): clean-room payload-header
  encoder + decoder for the per-isoch-transaction UVC header
  (bHeaderLength + Bit Field Header), with optional PTS (LE u32)
  and SCR (LE u32 SOF tick + 11-bit clock counter) fields. A
  `FrameReassembler` turns FID toggles into "new frame started" /
  "end of frame" / "error" steps the host driver feeds into the
  buffer manager.
- **UVC 1.5** (`uvc`): UVC descriptor parser. VC HEADER (bcdUVC,
  clock frequency, controlled VS interfaces), INPUT_TERMINAL with
  the camera-specific extension (objective focal length range,
  controls bitmap), OUTPUT_TERMINAL, PROCESSING_UNIT, VS
  INPUT_HEADER (with the per-format control bitmap list), VS
  FORMAT_UNCOMPRESSED with 16-byte Format-GUIDs (YUY2, NV12), VS
  FRAME_UNCOMPRESSED with both discrete and continuous frame-
  interval forms, VS FORMAT_MJPEG. Pure descriptor decode — pairs
  with a future isochronous/bulk video data path.
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
