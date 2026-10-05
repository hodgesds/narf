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
`default_params(capture)`, side-effect-free `capabilities(capture)`, and mixer
`controls/control_info/get_control/set_control`. `PcmCapabilities` describes
finite format/rate/channel sets, period-frame and period-count bounds, buffer
byte bounds and period-byte alignment. The default restricts negotiation to
the backend's default configuration; native backends override it.
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

The legacy NARF protocol remains available until a file receives an ALSA ioctl.
A 20-byte little-endian record written to a playback or capture PCM file at
`HW_PARAMS_MAGIC_OFFSET` configures format, rate, channels, period frames
and period count. Mixer files use textual control records. Writing parameters
to a control file only validates them on a temporary stream and does not
configure another file's PCM lease. Capture uses backend defaults unless its
own file is configured, and configuration does not start capture.
Unimplemented ALSA timer/sequencer devices are absent from devfs and sysfs;
the former write-discarding placeholder nodes are not published.

### 3.1 Linux ALSA PCM and control ABI

The bridge implements the 64-bit `sound/asound.h` layouts shared by x86_64
and aarch64. Requests dispatch through `FileOps::ioctl_user`; every user pointer,
including nested buffers and channel-pointer arrays, goes through the syscall's
guarded `IoctlContext`. Unknown or malformed request words return ENOTTY without
reading the argument. `pcm_native.c`, `pcm_lib.c` and `control.c` in the local
Linux source are the errno and validation-order references.

PCM exposes protocol/info, HW_REFINE/HW_PARAMS/HW_FREE, SW_PARAMS, STATUS/EXT,
DELAY/HWSYNC/SYNC_PTR, CHANNEL_INFO, PREPARE/RESET/START/DROP/DRAIN/XRUN,
FORWARD/REWIND and interleaved/planar transfer requests. HW_REFINE intersects
backend constraints without configuring hardware. HW_PARAMS leaves SETUP;
PREPARE resets pointers and enters PREPARED. Transfers use bounded staging
storage, report partial progress, and support null playback buffers as silence.
O_NONBLOCK returns EAGAIN when no progress is possible. Xruns require PREPARE
and return EPIPE without SIGPIPE; invalid state returns EBADFD (77).

MMAP_INTERLEAVED uses dedicated zeroed page-backed sample storage serviced into
the hardware lease. Mappings retain the exact allocation; HW_PARAMS/HW_FREE
reject live sample mappings with EBADFD. Invalid data offsets/lengths or RW
access mode return EINVAL. SYNC_APPLPTR is advertised: control-page mmap returns
ENXIO and commits use SYNC_PTR. On x86_64, clients declaring protocol >= 2.0.14
may map the status page read-only; mprotect cannot add write permission.
Aarch64 uses SYNC_PTR for status as well. MMAP commits never implicitly start
the stream. A scheduler sleep pump updates position and readiness; PCM poll
also supplies a 1 ms deadline, and reports IN/RDNORM or OUT/WRNORM according to
avail_min, with ERR for invalid states and xruns.

Control files expose card info/components, element list/info/read/write,
element locks, subscriptions and 72-byte coalesced events, plus PCM device
enumeration/info and power-state queries. Control values and ranges come from
the backend. An unowned unlock is EINVAL, another file's lock is EPERM, and a
duplicate lock is EBUSY. Unknown controls return ENOENT. Native controls without
TLV metadata return ENXIO for TLV requests.

ELEM_ADD/REPLACE/REMOVE support Boolean, integer, integer64, enumerated, bytes
and IEC958 user controls, including multiple indexed elements and nested enum
names. Controls persist until removed or the card is unregistered; closing an
open description releases its locks. INFO reports lock ownership and PID.
Values, names and TLV storage share an 8 MiB per-card budget. TLV_WRITE returns
1 on change and 0 when unchanged; TLV_READ reports ENOSPC for short buffers.
Subscriptions coalesce VALUE/INFO/ADD/TLV masks and carry REMOVE notifications.

PAUSE preserves queued data and position; RESUME restores the state saved by
`suspend_hardware_card(card)`. Platform drivers call that async hook before
quiescing a card for power management and restore the controller before users
resume. Suspended transfers/HWSYNC return ESTRPIPE (86), and poll reports ERR.
The PAUSE and RESUME capabilities are advertised after parameter negotiation.
An unconfigured PAUSE returns ENOSYS; invalid configured states return EBADFD.
System power-transition orchestration and device reinitialization remain owned
by the native driver and platform power subsystem.

LINK uses the calling process's descriptor table through `IoctlContext::file`.
Linked PREPARE/RESET/START/DROP/DRAIN/PAUSE/RESUME/XRUN validate every member before
triggering any hardware. RW automatic starts include linked peers. A failed
hardware action quiesces the group and publishes XRUN; closing a member stops
survivors. UNLINK detaches a member, returning EALREADY when already unlinked.
Groups retain weak memberships and serialize changes without IRQ-safe guards.
Software grouping does not advertise hardware-synchronous SYNC_START.

SW_PARAMS supports bounded automatic silence and the boundary silence mode.
The PCM layer mirrors changed samples into queued native DMA and fills retired
regions without advancing appl_ptr. A stop threshold at or beyond boundary
permits cyclic playback without application commits; availability can exceed
buffer_size and playback delay can be negative. Ordinary stop thresholds still
produce XRUN. REWIND reports zero frames with NO_REWINDS advertised.

`PcmHardware` supplies `pause`, `reset`, `free_running` and `overwrite` hooks.
Pause retains position and queued data; reset discards application ownership
without changing DMA state; free_running delegates underrun policy to ALSA;
overwrite refreshes cyclic playback slots at an absolute frame offset. HDA,
ACP capture and VirtIO implement the applicable hooks. `PcmSubstream::Paused`
is a distinct state and permits queued transfers while DMA is stopped.

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

The remaining ALSA features listed in §3.1, userspace audio-service policy and
multiclient mixing require further implementation and hardware validation.
