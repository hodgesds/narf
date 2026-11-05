# audio — Specification

> Status: Stage 5 native HDA and Phoenix ACP 6.3 PDM implementation.
> Hardware validation on the target Lenovo laptop remains pending.

## 1. Purpose & scope

Owns the kernel playback/capture API, native HDA controller and codec
routing, Phoenix ACP 6.3 digital-microphone capture, and backend selection.
The sound-card registry, PCM lifecycle, mixer and file bridge live in
[drivers/sound](../../drivers/sound/specification/spec.md).
Mixing, resampling and policy belong to a future userspace audio service.

The implemented native profile is analog HDA, LPCM HDMI/DisplayPort audio
(stereo to 7.1) on AMD GPU HD-Audio, ACP PDM, and SoundWire codecs on the
ACP 6.3 SDW manager (generic codec conversation, §3.2). Compressed
(non-PCM/HBR) HDMI passthrough, user channel maps, vendor smart-amplifier
fixups and DSP firmware execution are outside this profile. PCI identity
alone does not establish which codec or amplifier a laptop contains.

## 2. Assumptions

- PCI enumeration, coherent DMA allocation, timekeeping and the scheduler
  are initialized before controller use.
- A successful probe owns the function and its register/DMA engines.
- Probe brings PCI D1/D2/D3hot into D0 before command/BAR setup; platform
  D3cold power resources must already be available.
- HDA pin defaults and connection lists describe usable analog routes,
  except where a verified codec quirk overrides them (§3.2).
- ACP is 1022:15e2, revision 0x63, multimedia class 0x048000. The ACPI
  companion has a child with _ADR=2 and standard device-properties _DSD
  `acp-audio-device-type=2`; _WOV, when present, must be nonzero.
  The ACP pin configuration must include PDM. Revision, ACPI and pin mux
  checks all matter; 1022:15e3 is the separate HDA function.
- Native controllers use the existing DMA/address-mapping infrastructure;
  this implementation does not establish a new IOMMU isolation proof.

## 3. Public interface

### 3.1 Kernel PCM API

`AudioWriter::open(Cap<AudioStreamCap, Write>, AudioFormat)` selects an active
playback backend. VirtIO retains precedence when available; native HDA
supports S16LE, stereo, 48 kHz through this convenience API.
`submit(&[u8]) -> Result<u64, AudioWriteError>` validates current authority,
copies complete frames into owned DMA with backpressure, waits for completion,
and stops the native output stream. Its result is frames in this submission,
not a cumulative position. HDA accepts submissions longer than its cyclic
buffer. Native HDA `submit_shmem` returns UnsupportedFormat until pinned
shared-memory lifetime management is implemented.

`AudioReader::open(Cap<AudioStreamCap, Read>)` explicitly starts capture,
preferring ACP PDM over HDA analog input. `format()` reports the selected
format: ACP S32LE stereo 48 kHz; HDA S16LE stereo 48 kHz.
`read(&mut [u8]) -> Result<usize, AudioReadError>` returns completed bytes,
checks capability validity on every polling attempt, and waits at most 500 ms
for the first samples. Buffers must contain whole nonzero frames. Revocation
observed during read stops capture and returns StreamClosed. Revocation does
not schedule an independent stop while a reader is idle. `stop()` and Drop
quiesce DMA. Errors are NoActiveStream, UnsupportedFormat, StreamClosed, Timeout.

`SampleFormat::S32Le` represents signed little-endian 32-bit PCM alongside
the existing S16Le and F32Le variants. Backend support remains explicit.

### 3.2 Native cards and codecs

The unused standalone `acp6`, `codec`, `hda_tests`, `i2s`, `realtek_alc`
and `wm8960` model modules are retired. Native HDA and ACP controller paths
continue to register through the sound-card surface below. Preserved Realtek
identification and quirk tables live in `hda::quirks`. The rescued
pin-quirk table is staged data only and is never consulted by the
live path: none of its keys verified as a codec subsystem ID
(#1496). The live path applies only the re-derived
`VERIFIED_QUIRK_TABLE`, keyed on codec subsystem IDs Linux matches
on `HDA_CODEC_QUIRK`, and the verified per-chip init coef tables
(`CoefOp`: plain writes and masked read-modify-write updates,
Linux `alc_write_coef_idx` / `alc_update_coef_idx`). A quirk
applies only when the subsystem ID and the chip both match. Its
coef sequence runs before enumeration; its pin, connection-list
and preferred-DAC overrides patch the decoded graph after
enumeration (Linux's driver-side caches — no verbs are issued for
them), so the connection-select index a path later sends is the
index into the overridden list. Coef state is volatile across
controller reset, so reinit re-applies the init table and the
quirk sequence; the graph-side overrides survive in the retained
graph.

HDA registers one sound card per usable controller with at most one exclusive
playback lease and one exclusive capture lease. Both directions support
S16LE/S32LE stereo 48 kHz when codec capabilities allow it. Buffers contain
2–256 periods, each a multiple of 128 bytes, with total size 4–256 KiB.
The generic route enables BIOS-described speakers, line output and headphones;
capture walks from an ADC through selectors/mixers to a microphone/line pin.
Headphone presence disables speaker pins. Mixer controls expose master volume
when the routed converters have output amplifiers, output enable/mute through
pin controls, and headphone presence where supported. Gain never exceeds the
codec's advertised 0 dB offset. Per-route playback controls (Headphone/Speaker
Volume and Switch) apply to their route's converters only; the effective
converter gain is master × route / 87 and the path is muted when either mute
is set, so untouched routes behave exactly like the master-only path. Capture
controls follow the selected input path: Capture Volume drives the ADC's
input amp at the selected input (attenuation from its 0 dB offset), Mic Boost
drives a mic source pin's input amp (from its 0 dB offset up to its maximum
step). The capture source is re-selected from jack state on every 100 ms
jack tick: a plugged presence-capable pin beats an unplugged one, ties break
by class preference (Mic > Line > AUX) then discovery order, and a sense
failure keeps the current selection; the new source takes effect at the next
capture configure, never mid-stream. ACP 3.x and 6.3 PDM cards expose a
software Capture Volume (left/right, 0..87, 87 = unity): their PDM blocks
have no hardware gain stage in-tree, so the card scales the copied S32LE
samples in the read path instead of programming an ungrounded register.

AMD GPU HD-Audio functions (Linux's ATI HDMI NS IDs, `HDA_ATI_HDMI_NS_DEVICES`,
through 0xab40) run without snoop as Linux's `AZX_DCAPS_SNOOP_OFF`: narf DMA
memory is write-back, so the CPU-zeroed CORB/RIRB are written back before the
controller owns them, CORB entries after queueing, RIRB entries invalidated
before reading, and PCM rings write back their BDL/data at reset and after
each playback write or retired-byte clear and invalidate before capture reads
(`DmaBuffer::sync`). Their ATI HDMI codec (0x1002aa01) contributes every
connected digital output pin as an output path; Linux's converter capability
override (any rate, S16/S32, eight channels) replaces the PCM capability
query. Setting up a playback stream follows atihdmi and Linux's generic HDMI
prepare, at hw_params and again at prepare (so the IEC958 non-audio bit is
taken at prepare, as Linux does): zero downmix, per-channel remap mode
(revision 3+), the CEA channel allocation (a user channel map's
`hdmi_manual_channel_allocation` for PCM, otherwise
`hdmi_channel_allocation_spk_alloc_blk` for the channel count and the sink's
ELD speaker allocation), converter channel count, the slot map (the user
map's, stream order for non-PCM, else `hdmi_std_setup_channel_mapping`)
written through the ATI slot verbs (pairs with FC/LFE swapped before
revision 3), `SET_CHANNEL_ALLOCATION` (the hardware's Audio InfoFrame
source), ramp rate 180 for PCM and 0 for non-PCM (revision 3+), HBR enabled
exactly for eight-channel non-PCM (refused on a port without HBR
capability), the converter's DIG1/DIG2 from the IEC958 state, then the
stream format and tag. Non-PCM sets the TYPE bit in both the converter and
the controller's SDnFMT (`snd_hdac_spdif_stream_format`). Playback offers
stereo, 4, 6 and 8 channels up to the smallest channel ceiling among attached
sinks, S32_LE only while every attached sink advertises 20/24-bit LPCM, and
the 44.1–192 kHz rates every attached sink's SADs share
(`snd_hdmi_eld_update_pcm_info`; 48 kHz if they share none, no 32 kHz); with
no sink the converter's own limits apply. Analog codecs stay at 48 kHz.

GPU codecs expose Linux's digital-output controls for the one playback PCM:
`IEC958 Playback Con Mask`/`Pro Mask` (read-only), `IEC958 Playback Default`
(`convert_from_spdif_status` into DIG1/DIG2 on every port's converter;
setting AES0 non-audio selects IEC 61937 passthrough at the next prepare) and
`IEC958 Playback Switch` (DIGEN). The state starts from the first converter's
GET_DIGI_CONVERT_1 with DIGEN set, since no userspace hook is required to
play. `Playback Channel Map` follows `hdmi_chmap_ctl_put`: ignored with no
open stream, accepted while open, set up or prepared (applied at once to
every routed port when prepared), EBUSY once running, EINVAL for positions
past `SNDRV_CHMAP_LAST`, for maps no CA carries and (before revision 3) for
maps that split a slot pair. Closing the stream clears it; after a prepare it
reports the standard layout's map (`hdmi_setup_fake_chmap`). Its TLV lists the
CAs the primary port's speakers cover (CHMAP_VAR, or CHMAP_PAIRED with N/A
fillers before revision 3, where an odd layout is ENODEV as in Linux). The
primary port is the first one with a valid ELD, the same port the ELD control
reports; mirrored ports may differ in speaker allocation and CA. The ATI codec has no ELD buffer: narf rebuilds one as `get_eld_ati`
does from the speaker allocation, sink info (revision 3+), audio descriptor
and A/V delay verbs, and parses it as `snd_parse_eld`. Pin sense (presence
and ELD-valid) is polled every 100 ms with the other jacks; the ELD is
re-read only when the sense changes or the last read was unusable. A playback
PCM routes to every port whose monitor has a valid ELD (mirroring, since a
native card has one playback PCM), detaching the converters of the others; with
none it routes to every port as Linux's static PCM mapping keeps pins
attached. A port that gains a valid ELD while a stream is configured is set
up again, as Linux update_eld does. The card exposes "HDMI/DP,pcm=0 Jack"
(CARD interface) and "ELD" (PCM interface, volatile read-only bytes) and
notifies subscribers when either changes. The display side (DCN Azalia
endpoint, ACR, AFMT) is programmed by the amdgpu modeset.

`hda::probe`, `register_pci_driver`, `controller`, `capture_card`,
`play_buffer`, and the legacy codec/period helpers share this runtime.
CORB/RIRB command submission is serialized; unsolicited responses have their
own completion indices. Both polled and async commands have a 100 ms timeout.
A cancelled or timed-out in-flight command poisons the transport until reset,
preventing a late response being mistaken for another command.

`acp63::probe`, `register_pci_driver`, `is_probed`, `capture_card`
publish one capture-only card. It uses S32LE stereo 48 kHz, four periods of
4096–8192 bytes, and at most 32 KiB. PDM DMA addresses a fixed ACP window
translated through 4 KiB scratch-RAM PTEs. It needs no DSP firmware.
`pin_config_has_pdm` recognizes Linux's PDM-capable mux configurations.

The shared ACP PCI id (1022:15e2) dispatches on PCI revision in
`acp63::probe`: 0x63 selects the ACP 6.3 map above; 0x01 selects
`acp3x::probe` (Renoir / Lucienne / Cezanne ACP 3.x), which publishes the
same capture-only contract — S32LE stereo 48 kHz, four periods of
4096–8192 bytes, the same fixed ATU DMA window and scratch-PTE scheme —
with the 3.x generation's PGFSM power-on handshake, CLKMUX select,
external-interrupt block and SRAM PTE base. Any other revision stays
unbound. `acp3x::is_probed`, `acp3x::capture_card` mirror the 6.3 entry
points, and `AudioReader` capture selection falls back 6.3 → 3.x → HDA.
The Renoir APU's HDA display-audio function (1002:1637) binds through
`HDA_ATI_HDMI_NS_DEVICES`, receiving the ATI HDMI preset's no-snoop
treatment (`ati_hdmi_noncoherent`) like the other ATI HDMI functions.

`acp6::probe/register_pci_driver` are compatibility aliases for ACP 6.3.
The previous generic I2S/RI-upload scaffold is unbound; its direct bring-up
and firmware methods return UnsupportedDevice without touching hardware.

`soundwire` is the MIPI SoundWire bus layer, transport-abstract (one
command frame out, one classified ACK/ignored/timeout response back):
`Bus::enumerate` reads the six DevID registers at the enumeration address,
assigns device numbers 1..=11 through `SCP_DEVNUMBER` and verifies each
assignment, ending cleanly when a DevID read goes unanswered and failing
closed on any other transport error; `read_reg`/`write_reg` carry
peripheral register access (broadcast writes permitted); the stream
surface programs a data port's transport parameters (`DPn_BLOCKCTRL1`
word length, `DPn_SAMPLECTRL1/2` sample interval), writes `DPn_PREPARE`
and polls its NotFinished bits under a bounded wait, then sets
`DPn_CHANNELEN` to enable and clears it to disable, clearing
`DPN_PREPARE` on deprepare. Streams are configured while stopped;
glitchless bank switching mid-stream is out of scope.

`acp63_sdw::probe`, `register_pci_driver`, `is_probed`, `capture_card`
bind the ACP 6.3 function's SDW0 manager for pin configurations without
PDM (the PDM probe declines those, and this driver is the next candidate
for the function under the candidate-walking dispatcher, PR #852, which
is on main). Configurations where PDM and SoundWire coexist compose
through the PDM probe instead: after claiming the function it calls
`acp63_sdw::bind_composed`, which runs the manager init + enumeration
on the already-powered block and publishes any codecs found alongside
the PDM capture card (#871); SDW presence on a PDM wiring is
enumeration, not a pin bit, and a failed composition just means
PDM-only. Probe powers the ACP up, initialises the manager (enable,
bus reset, 50×10 frame shape, interrupt masks), enumerates, and
publishes one sound card per enumerated codec through the registry,
using the generic codec profile (DP1 sink + DP1 source, stereo S16LE
48 kHz). A bus with no answering codec publishes nothing. The card
implements the PCM lifecycle against the bus (configure/prepare/enable/
disable/deprepare) and moves PCM payload through the ACP SDW DMA engine
(`acp63_sdw_dma::SdwDma`, installed on each card at probe): one ring
per lease, ATU/window programming at prepare mirroring the PDM path,
counter/pointer accounting in frames, wrap/xrun discipline, and
failed-stop retention. A full stop invalidates prepare on both layers
(restart needs a fresh prepare); pause/resume preserves queued samples
and position. One DMA channel serves the whole function, so a second
stream's start fails `DeviceBusy` while the first runs — concurrent
bidirectional streaming is out of scope. Cards without an engine
(generic transports) still report `BadState` for payload reads/writes.
UNVERIFIED HARDWARE ASSUMPTION: the engine programs the ACP DMA
channel block the PDM path uses, on the premise that the SDW binding
owns the function exclusively when it binds. Linux's `ps-sdw-dma.c`
register map was not verified from source in the #870 lane (no
`sound/` tree on the build machine; the patch text was unreachable),
so the channel programming must be validated on silicon before it is
treated as proven; a correction belongs in `AcpDmaRegs` alone.

Intel SoundWire links are not bound here: in the tree's platform model
they are owned by the audio DSP (SOF), whose in-tree surface is a
register-level stub with no link enumeration or firmware path. Binding
them is a follow-up to #780, not a gap in the bus layer, which is
controller-agnostic.

### 3.3 Registration and service

The registered `PcmDevice::capabilities` supplies ALSA negotiation constraints.
HDA exposes S16LE/S32LE, 48 kHz stereo, 128-byte period alignment and a
4–256 KiB buffer. ACP 6.3 exposes its implemented S32LE, 48 kHz stereo,
512–1024 frame periods, four periods and 16–32 KiB buffer. Refine queries
are side-effect-free; actual configuration still validates in the engine.

Subsystem initcalls register PCI probes; late init publishes native cards
through the sound file bridge. Capture is never started by enumeration.
HDA and ACP register their actual bus address with the sound registry, so
their sysfs card parent resolves to the same PCI device as bus enumeration.
VirtIO sound also registers through that registry from its probe; its
implemented playback stream is accessible through `/dev/snd` as well as the
kernel convenience API. An exclusive file PCM lease prevents concurrent
kernel convenience submissions from changing that stream's configuration.
Owned MSI-X/MSI routing is used for HDA when available. ACP uses firmware
INTx. A direct _PRT GSI can join an existing compatible shared vector;
named interrupt-link routes fall back to polling. A 2 ms service timer
handles DMA accounting even without IRQ routing; jack refresh runs at 100 ms.

ALSA stream hooks preserve DMA position and storage across pause/resume. HDA
supports rewriting queued cyclic slots and delegates stop-threshold/silence
policy to ALSA in free-running mode; raw native clients retain underrun checks.
ACP restarts its physical counter baseline while retaining logical position.
RESET discards application ownership without stopping the controller.
Platform power callers use `suspend_hardware_card` before powering down and
must restore controller programming before ALSA RESUME.

## 4. Invariants

- Every stream owns coherent DMA and its hardware lease. Buffers are freed
  only after STOP acknowledges, or after controller reset establishes
  quiescence. Failed stop/reset retains storage rather than exposing freed
  memory to DMA.
- Playback writes only reclaimed/free slots; capture reads only completed
  slots. Capture validates against the pre-copy consumer position again
  after copying to detect overwrite races.
- Underrun/overrun stops the stream and requires stop/prepare recovery.
  HDA rejects a position sample gap long enough to hide a whole ring wrap.
- No IRQ-safe lock crosses an await. Synchronous register waits use the
  scheduler's bounded responsive polling; timer waits release all guards.
- IRQ handlers acknowledge their device sources and report unhandled shared
  interrupts correctly. Teardown masks sources, removes and synchronizes
  the handler before releasing its cookie or vector. A vector still used by
  another shared-line handler is retained.
- Codec amp capabilities inherit from the AFG unless overridden. Malformed
  or cyclic connection graphs are bounded and cannot cause unbounded walks.

## 5. Architecture notes

x86_64 uses MSI-X, MSI or firmware-routed IOAPIC INTx. AMD HDA enables the
Linux AMD-SB PCI snooping bits. ECAM and BAR access use mapped addresses.

aarch64 compiles the same native DMA/codec implementation and runs fake-device
tests. MSI-X uses the bus ITS mapping; ordinary MSI and INTx fall back to
polling. Physical Phoenix is an x86_64 target.

## 6. Dependencies and references

Consumes bus, capabilities, IO/DMA, scheduler, time, interrupts, ACPI/AML and
drivers/sound. Supplies kernel clients and the sound file bridge.

Implementation checked against local /usr/src/linux:
- sound/hda/controllers/intel.c (AMD IDs and snooping);
- sound/hda/core/controller.c and stream.c (command/stream engines);
- sound/hda/codecs/generic.c (routing, amps and jack handling);
- sound/soc/amd/ps/pci-ps.c, ps-common.c, ps-pdm-dma.c, acp63.h;
- include/sound/acp63_chip_offset_byte.h.
The SDW DMA channel programming mirrors the in-tree PDM path; Linux
`sound/soc/amd/ps/ps-sdw-dma.c` was not available to the #870 lane
(no `sound/` tree on the build machine, patch text unreachable), so
the channel-block reuse is an explicitly flagged assumption (§3.2),
not a checked reference.

## 7. Stage assignment and verification

Stage 5 native analog output/input and digital-microphone foundations.
Targeted tests cover full fake-HDA initialization and command/PCM paths,
unsolicited replies interleaved with commands, selector cycles, capture,
ACP address translation/counter rollover/overrun and failed-stop retention,
and ACP SDW DMA ring layout, counter/pointer accounting, capture wrap,
failed-stop retention, single-channel arbitration, and lease-level
playback/capture movement through the engine.
QEMU intel-hda with hda-duplex exercises playback across ring wrap, capture
DMA progress and capture-capability revocation. These are software/emulator
proofs, not evidence of audible playback or microphone quality on Lenovo 50ee.

## 8. Open questions

Physical validation must establish the actual HDA codec, BIOS route quality,
jack behavior and whether speaker amplifiers need a model-specific quirk.
HDMI/DP and system power-transition reinitialization remain separate
implementation work. SoundWire follow-ups to #780 remain: Intel
DSP/SOF-owned SoundWire links, and vendor codec profiles (jack/amp
sequences) beyond the generic conversation. The ACP SDW DMA payload
engine has landed (#870), but its channel programming still needs
validation on silicon against the Linux `ps-sdw-dma.c` register map
(see §3.2). PCM pause/resume preserves DMA buffers and position.
The shared sound bridge supplies Linux ALSA ioctl/mmap/poll for the registered
native endpoints, subject to its documented feature limits.
