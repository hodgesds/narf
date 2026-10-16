# Navi48 native display acceptance

No RX 9070 XT physical display run has been recorded for this branch. QEMU
register/protocol models and Linux differential vectors do not fill the physical
columns below. Milestone 4 remains open until every advertised connector, mode
and property has evidence for boot, hotplug, modeset and disable, with advanced
features either implemented or explicitly scoped out by the project owner.

## Board and route inventory

Create one board ID per PCB/VBIOS combination. Keep the raw artifacts alongside
the run log and record their hashes; do not infer a route from a retail GPU name.

| Board ID | PCI/subsystem IDs, PCB revision | VBIOS version/hash | ATOM routes and physical connector labels | Route evidence |
| --- | --- | --- | --- | --- |
| Pending | Not supplied | Not supplied | Not supplied | No board capture |

The inventory must map each physical port to its ATOM connector/transmitter,
AUX/DDC and HPD selectors and speed records. Record retimer/repeater routing,
lane reversal and spread-spectrum policy from board data and corroborating
captures. eDP panel/backlight and USB-C/ACPI PHY interlocks are **undetermined**;
mark either not applicable only when this board's inventory supports that claim.
Keep an unsupported or unknown route distinct from an absent route.

## Run manifest

Each physical run needs a stable ID and these artifacts:

- Exact NARF commit and local diff, architecture, build profile, bootloader and
  full kernel arguments, including native-display, FRL and maximum-bpc policy.
- Board ID, monitor/repeater/retimer models and firmware, cable/adapter labels,
  physical port map and complete EDID/DPCD or SCDC capability captures.
- Firmware image versions/hashes, boot-stage serial log, admitted timing/link
  settings, clock limits/floors, pipe assignment and payload/DSC configuration.
- KMS connector/mode/property inventory before and after every transition,
  native state/error diagnostics, framebuffer/flip evidence and allocation
  accounting before retirement and after re-enable.
- Observed image, refresh/depth/range and audio channel results. Record exact
  failure points and attempts; absence of a panic is not proof of a correct image.

Retain a full serial log throughout. Record serial/input responsiveness while
the displayed test pattern changes. Do not include credentials or protected keys
in captures. Device-register snapshots must use the existing owner/diagnostic
interfaces without racing active hardware producers.

## Physical run matrix

Use separate rows for connector/mode/property combinations and simultaneous
configurations. Reference the manifest and raw evidence for every Pass or Fail.
An unrun case stays Not run; a policy-disabled feature stays Unsupported or
Disabled, without becoming a physical pass.

| Run ID / board | Port, cable, sink / topology | Timing, transport, depth / properties | Boot + changing pattern | Hotplug / replug | Mode change / disable / re-enable | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Pending | No physical setup supplied | None | Not run | Not run | Not run | None |

For each advertised combination, exercise cold boot and firmware handoff;
front/back updates and flips; accepted mode/range/depth requests; disable and
re-enable; physical removal while running and while disabled; replug and monitor
replacement. Check that stale EDIDs, modes, CRTC bindings and requests do not
move to another connector. Record repetitions and failures. Verify CPU writers
drain before release and repeated transitions do not accumulate parked VRAM.

For multiple displays, include different refresh rates/resolutions, removal of
one display and reconfiguration while siblings remain connected. For MST,
include all-off/empty branches, downstream replug, stable connector slots,
shared-link loss and bandwidth changes affecting a common upstream hop. Check
that the fresh path budget bounds all active and dark-connector modes.

Audio acceptance includes capability/ELD changes, channel routing, continuity,
clock synchronization, display disable, retraining and physical unplug. A
successful codec bind or packet-register model does not prove audible output.

## Feature coverage ledger

This is an acceptance inventory, not a declaration that all rows are supported.
The GPU specification is authoritative for the current exposed interfaces.

| Feature family | Current software evidence / remaining work | Physical evidence |
| --- | --- | --- |
| Legacy DP SST / FEC / LTTPR | Native sequencing and protocol models; transition/reset recovery incomplete | None |
| HDMI TMDS / SCDC / RGB depth and range / 8-bpc 4:2:0 | Native register and capability models; pre-link sink cleanup implemented | None |
| UHBR / FRL | Startup, training, scanout, shutdown and live FRL status models; FRL 8/10/12-bpc 4:2:0 up to 4096 pixels; firmware-made mux/clock assumptions need confirmation; FRL opt-in | None |
| Legacy DP DSC | PPS/DML differential vectors and native models; HPO/FRL DSC, larger ODM layouts and other input formats remain open | None |
| Legacy MST | Topology, payload, notification, path-budget and fixed-output models; mixed MST/SST, UHBR MST and audio/DSC remain open | None |
| Joint display configuration | Joint DML/clock/CRB models, four fixed pipes; ODM, broader routing and seamless shared-clock changes remain open | None |
| Scaling / composition / tiling / color management / HDR / VRR | Additional native programming and exposure gates remain open | None |
| Audio | TMDS/FRL HDMI and legacy/UHBR DP LPCM models; AFMT/APG/ACR, bandwidth filtering, DTO/endpoint ownership and DP DSC shared PPS covered; compressed passthrough, channel maps and MST audio remain open | None |
| Board-specific panel / USB-C routes | Inventory required before applicability or implementation decisions | None |
| Protected output | [Separate requirements](navi48-protected-output.md); unsupported, unadvertised | None |

Software validation logs are recorded in the local branch work log. A future
physical run should cite the tested commit rather than inheriting a pass from a
different board, mode, firmware version or model-only result.
