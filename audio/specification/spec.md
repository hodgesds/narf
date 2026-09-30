# audio — Specification

> Status: Stage 5 native HDA and Phoenix ACP 6.3 PDM implementation.
> Hardware validation on the target Lenovo laptop remains pending.

## 1. Purpose & scope

Owns the kernel playback/capture API, native HDA controller and codec
routing, Phoenix ACP 6.3 digital-microphone capture, and backend selection.
The sound-card registry, PCM lifecycle, mixer and file bridge live in
[drivers/sound](../../drivers/sound/specification/spec.md).
Mixing, resampling and policy belong to a future userspace audio service.

The implemented native profile is analog HDA plus ACP PDM. HDMI/DisplayPort
audio, SoundWire codecs, vendor smart-amplifier fixups and DSP firmware
execution are outside this profile. PCI identity alone does not establish
which codec or amplifier a laptop contains.

## 2. Assumptions

- PCI enumeration, coherent DMA allocation, timekeeping and the scheduler
  are initialized before controller use.
- A successful probe owns the function and its register/DMA engines.
- Probe brings PCI D1/D2/D3hot into D0 before command/BAR setup; platform
  D3cold power resources must already be available.
- HDA pin defaults and connection lists describe usable analog routes.
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

HDA registers one sound card per usable controller with at most one exclusive
playback lease and one exclusive capture lease. Both directions support
S16LE/S32LE stereo 48 kHz when codec capabilities allow it. Buffers contain
2–256 periods, each a multiple of 128 bytes, with total size 4–256 KiB.
The generic route enables BIOS-described speakers, line output and headphones;
capture walks from an ADC through selectors/mixers to a microphone/line pin.
Headphone presence disables speaker pins. Mixer controls expose master volume
when the routed converters have output amplifiers, output enable/mute through
pin controls, and headphone presence where supported. Gain never exceeds the
codec's advertised 0 dB offset.

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

`acp6::probe/register_pci_driver` are compatibility aliases for ACP 6.3.
The previous generic I2S/RI-upload scaffold is unbound; its direct bring-up
and firmware methods return UnsupportedDevice without touching hardware.

### 3.3 Registration and service

Subsystem initcalls register PCI probes; late init publishes native cards
through the sound file bridge. Capture is never started by enumeration.
Owned MSI-X/MSI routing is used for HDA when available. ACP uses firmware
INTx. A direct _PRT GSI can join an existing compatible shared vector;
named interrupt-link routes fall back to polling. A 2 ms service timer
handles DMA accounting even without IRQ routing; jack refresh runs at 100 ms.

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

## 7. Stage assignment and verification

Stage 5 native analog output/input and digital-microphone foundations.
Targeted tests cover full fake-HDA initialization and command/PCM paths,
unsolicited replies interleaved with commands, selector cycles, capture,
ACP address translation/counter rollover/overrun and failed-stop retention.
QEMU intel-hda with hda-duplex exercises playback across ring wrap, capture
DMA progress and capture-capability revocation. These are software/emulator
proofs, not evidence of audible playback or microphone quality on Lenovo 50ee.

## 8. Open questions

Physical validation must establish the actual HDA codec, BIOS route quality,
jack behavior and whether speaker amplifiers need a model-specific quirk.
SoundWire, HDMI/DP, suspend/resume and a Linux ALSA ioctl/mmap ABI remain
separate implementation work. The current file bridge is NARF's PCM protocol.
