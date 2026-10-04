# audio — PCM Audio Subsystem Core

`narf-audio` is NARF's audio core: the kernel-side PCM playback and
capture surface, together with the native hardware engines that drive
real sound controllers. It is backend-agnostic — a stream is a stream
whether it is backed by VirtIO sound in a VM or by a physical HDA
controller on a laptop — and it is the layer the rest of the system
talks to when it wants to make or record sound. Mixing, resampling, and
audio policy are left to a future userspace audio service; this crate
provides the mechanism, not the policy.

Audio is expressed as PCM streams negotiated at open time: a format
triple of sample format (S16/F32/S32 little-endian), channel layout
(mono or stereo for now), and sample rate. Each backend advertises which
formats it supports, and a picker selects the best available output.
Streams carry per-stream buffer pools and a submit / wait / close
lifecycle for moving PCM buffers to and from hardware. The surface is
capability-gated: playback and capture are distinct authorities keyed on
the stream capability's direction, so merely enumerating devices never
starts recording — a design that keeps microphone access explicit.

Beyond the abstract surface, the crate carries the native hardware
engines. These include an Intel/AMD HDA (High Definition Audio)
controller and codec path — CORB/RIRB command rings, stream descriptors,
the codec widget graph, and Realtek ALC codec routing — and the AMD
Phoenix ACP 6.3 audio co-processor path for digital-microphone (PDM)
capture, with its buffer-descriptor, codec-link, and PCM submodules.
Supporting codec logic (generic AFG bring-up, Realtek ALC, WM8960, I2S)
and the SBC/mSBC Bluetooth audio codecs also live here. Native PCM and
mixer endpoints are published through `narf-drivers-sound`'s card and
file bridge; VirtIO retains precedence as a backend when present.

The crate depends broadly across the kernel — capabilities, memory and
shared memory, PCI/bus enumeration, ACPI/AML (to confirm ACP identity
and pin configuration), interrupts, firmware loading, the scheduler and
timekeeping, plus `drivers/virtio` and `drivers/sound`. The implemented
native profile is analog HDA plus ACP PDM; HDMI/DisplayPort audio,
SoundWire, vendor smart-amplifier fixups, and DSP firmware execution are
out of this profile. The crate is `no_std`.

- Spec: [`specification/spec.md`](./specification/spec.md)
