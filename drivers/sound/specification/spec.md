# sound — Specification

## 1. Purpose & scope

Owns the sound-card registry, PCM lifecycle, mixer and file bridge. Native
HDA and ACP hardware engines register from `narf-audio`, and VirtIO playback
registers from `drivers/virtio`; the older controller,
codec and software PCM models remain available for existing tests.

## 2. Assumptions

Callers hold the authority needed to access a card or its filesystem node.
One hardware lease owns a direction/device pair. Registry locks are released
before invoking a backend; an Arc keeps it alive during the operation.

## 3. Public interface

`register_hardware_card(CardInfo, Arc<dyn hardware::PcmDevice>) -> u32`
assigns a card index. `unregister_hardware_card(index)` prevents new opens
without invalidating outstanding stream leases. `default_hw_params(card,
capture)` returns a backend's supported starting configuration.
`register_hardware_card_at(info, backend, Option<BusAddr>)` associates a card
with its physical bus parent. HDA, ACP and VirtIO use this entry point; the
parentless entry point remains available for virtual cards. The static ALSA
device-number layout supports at most eight PCM devices per direction per
card; registration asserts this driver-supplied bound. Control minors are
`card * 32`, playback minors `card * 32 + 16 + device`, and capture minors
`card * 32 + 24 + device` (major 116).

After `sound_fs_initcall`, registration publishes sysfs and procfs immediately;
unregistration removes their card subtree and discovery links. Publication,
teardown and bridge initialization are serialized independently of the registry
lock. Canonical sysfs nodes live under the physical PCI parent's `sound/cardN`
directory, or `/sys/devices/virtual/sound/cardN` for parentless cards.
`/sys/class/sound/*` and `/sys/dev/char/116:*` link to those same nodes.
Cards expose `id`, `number`, `longname`, `subsystem`, and writable `uevent`;
physical cards also expose `device`. Control/PCM nodes expose `dev`, `device`
(the card), `subsystem`, and writable `uevent` with MAJOR/MINOR/DEVNAME.
PCM nodes also expose `pcm_class`. Complete publication emits ADD events
followed by a card CHANGE event, which lets udev mark the card initialized;
teardown emits REMOVE events. Repeated bridge initialization is idempotent.

`PcmDevice: Send + Sync + Debug` provides `open(capture, device)`,
`default_params(capture)`, and mixer `controls/get_control/set_control`.
`PcmHardware: Send + Debug` is an exclusive lease with `configure(HwParams)`,
`prepare`, `start`, `stop`, `pointer` (cumulative frames), `write`, `read`
(byte counts), and `drain`. Its Drop must stop DMA or retain its storage.

`open_playback/open_capture` return the existing PlaybackStream/CaptureStream
wrappers, delegating hw_params/prepare/start/stop/pointer/read/write/drain to
the native lease. A full output ring or empty input ring returns zero bytes;
the caller waits and retries. Invalid format/geometry returns InvalidParams;
an occupied endpoint returns DeviceBusy; failed devices and xruns return
BadState. Recovery is stop then prepare before restarting. Unsupported mixer
controls return NoSuchControl, and invalid values return OutOfRange.
Software-only registered cards retain their synthetic test behavior.

`mixer(card)` delegates control enumeration, reads and writes to the hardware
backend when one exists. It must not report synthetic controls for native cards.

`sound_fs_initcall` publishes `/dev/snd`, sysfs and procfs card information.
Each successful PCM open acquires its own exclusive lease after access checks;
lookup/stat do not acquire a hardware lease. Files retain that lease across
calls and release it with the open file object. Per-file async mutexes serialize
operations without disabling interrupts during device waits. Close flush and
fsync drain playback; subsequent writes can start a new prepared stream.
Open prepares backend defaults without starting DMA. Playback writes copy
available samples and start DMA; they return partial byte counts under
backpressure. An underrun is recovered with stop/prepare on the next write.
Capture starts on the first explicit read. Direct kernel callers of a lookup
node retain lazy default initialization on first I/O. Timer waits are
outside IRQ-safe locks and bounded to 1 s for playback progress and 500 ms
for capture progress.

The bridge uses its existing NARF protocol, not the Linux ALSA ioctl ABI.
A 20-byte little-endian record written to a playback or capture PCM file at
`HW_PARAMS_MAGIC_OFFSET` configures format, rate, channels, period frames
and period count. Mixer files use textual control records. Writing parameters
to a control file only validates them on a temporary stream and does not
configure another file's PCM lease. Capture uses backend defaults unless its
own file is configured, and configuration does not start capture.
Unimplemented ALSA timer/sequencer devices are absent from devfs and sysfs;
the former write-discarding placeholder nodes are not published.
Linux applications needing ALSA ioctl/mmap need additional ABI work.

## 4. Invariants

- Native streams use backend-owned coherent DMA, never a Vec address as a
  device DMA address. A Vec/BDL model is only used for synthetic cards.
- Direction, format and state errors are checked before hardware access.
- Stream teardown must not free memory reachable by a running engine.
- No registry/file IRQ-safe guard spans an await.

## 5. Architecture notes

The registry and protocol are architecture-neutral. Register layouts, cache
coherency and interrupt routing are the hardware backend's responsibility.

## 6. Dependencies

Bus, IO, capabilities, scheduler/time, filesystem and hardware implementations.
See [audio](../../../audio/specification/spec.md) for native engine contracts.

## 7. Stage assignment

Stage 5 connects the existing card/PCM/mixer surfaces to native HDA and ACP.
Targeted software PCM, file bridge, format, card and native DMA tests apply.

## 8. Open questions

Linux ALSA ioctl/mmap/poll compatibility, userspace audio-service policy and
multiclient mixing remain outside this card-backend implementation.
