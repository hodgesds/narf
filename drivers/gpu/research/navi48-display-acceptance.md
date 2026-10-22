# RX 9000 native hardware acceptance

No Navi48 or Navi44 physical display run has been recorded for this branch. QEMU
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
| Legacy DP SST / FEC / LTTPR | Native link, owned retraining and teardown/recovery models; physical transitions remain unverified | None |
| HDMI TMDS / SCDC / output formats and depth | Native RGB, YCbCr420/422/444, deep-color admission, AVI/FMT/OPTC/MPC and sink-cleanup models | None |
| UHBR / FRL | Native startup, training, scanout, shutdown and live-status models; firmware mux/clock and sink behavior need confirmation; FRL remains opt-in | None |
| DSC / ODM | Native legacy DP, UHBR and FRL programming with PPS/DML comparisons, split-pipe allocation and retirement models | None |
| MST / converter workarounds | Legacy/UHBR topology, DSC, concurrent SST/MST, multiple branches, PCON constraints and Synaptics FIFO/decoder ownership models | None |
| Joint display configuration | Harvest-aware pipes and joint DML/clock/CRB/DET/ODM admission and reconfiguration models | None |
| Scaling / composition / tiling / color / HDR / VRR | Native plane/tiling/scaling, color/HDR and FreeSync metadata/LFC/MCCS models; board/sink acceptance required | None |
| Audio | TMDS/FRL HDMI and legacy/UHBR DP SST/MST; endpoint/DTO/packet ownership, payload transitions, compressed/HBR and channel-map models | None |
| Rendering / compute | Kernel and client-context compute proofs; graphics draw/render-target proof under implementation; actual Mesa/API/compositor acceptance open | None |
| Media | AVC/JPEG paths; HEVC Main8/Main10, VP9 Profile0/2 and AV1 Main8/Main10 decoder and HEVC Main8/AV1 Main8 encoder-roundtrip integration; additional codec rows remain gated | None |
| Board-specific panel / USB-C routes | Inventory required before applicability or implementation decisions | None |
| Protected output | [Separate requirements](navi48-protected-output.md); unsupported, unadvertised | None |

Software validation logs are recorded in the local branch work log. A future
physical run should cite the tested commit rather than inheriting a pass from a
different board, mode, firmware version or model-only result.

## Rendering, media and lifecycle acceptance

Run the matrix separately on gfx1200/Navi44 and gfx1201/Navi48, including
harvested/OEM boards and small CPU-visible BAR apertures. Record actual firmware,
VRAM/BAR sizes, retained owner allocations, client heap and refusal/recovery
behavior under pressure. A nominal GPU family or successful initialization does
not establish these device-specific results.
The complete requested media proof set currently retains156069888bytes before
firmware, displays and other owners. Clean S3/BACO resume reclaims the stopped
old proof owner; fault recovery conservatively retains the old whole owner.
On a256MiB aperture, a replacement full request can therefore refuse and leave
the device lost. Record this availability limit and the actual refusal rather
than assuming the initial admission result guarantees fault recovery.

For graphics and compute, retain native proof readbacks and submitted command
traces, then run the selected Mesa/libdrm stack with real application contexts.
Record renderer/device strings and verify that output came from this GPU; a
software fallback cannot fill an acceptance row. Exercise multiple clients,
resource/synchronization reuse, fault isolation and rendering-to-scanout ordering.
Keep API/ring/version claims gated until their acceptance requirements hold.

For each advertised codec/profile/direction, retain source and decoded pixel
checks, encode/decode roundtrips, supported geometry/precision limits, malformed
input and concurrent graphics/media teardown. A single intra/keyframe proof is
not inter-frame, profile-range or application acceptance. In particular, the
HEVC encoder proof uses the selected Mesa minimum of384x128 and AV1 uses320x128;
these bounded proof shapes do not define the complete advertised limits.

Exercise repeated cold/warm boots, inherited active display, runtime power,
reset/recovery, suspend/resume, shutdown and device removal with active clients.
For system suspend, validate global SMP park/restart as well as GPU-local state;
the device model alone does not prove that platform sequence.
