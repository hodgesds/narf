# drivers/sound — HDA Sound Drivers and ALSA-Style Surface

`narf-drivers-sound` holds NARF's sound-hardware drivers and the
card-oriented, ALSA-equivalent surface that sits in front of them.
Where `narf-audio` owns the abstract PCM stream API and the active
native engines, this crate owns the sound-card registry, the PCM
substream lifecycle, the mixer control surface, and the filesystem
bridges that make audio visible to userspace. Without a working driver
here the machine's speakers, microphone, and headphone jack are silent.

Its primary target is the Intel/AMD High Definition Audio (HDA)
controller family — specifically the AMD HDA controllers on Zen2 Renoir
and Phoenix HawkPoint laptops with Realtek ALC-family codecs — and it
also probes Intel PCH HDA, whose programming model is identical. The HDA
layering mirrors Linux's `sound/hda/`: PCI probe and the GCAP/GCTL/INTCTL
reset sequence, the CORB and RIRB command/response rings, stream
descriptors with buffer-descriptor lists, and codec widget-graph walking.
Codec support spans a vendor-agnostic generic AFG bring-up path (power,
unmute, default routing for any compliant codec), the large Realtek ALC
init-verb sequences across many ALC part numbers, and per-laptop-model
widget-connection quirk tables (Lenovo, Dell, HP, ASUS, MSI). Additional
controller/codec stubs (Intel8x0, SOF, MAX98357A, RT5645) are present at
varying depth.

On top of the hardware, the crate provides the ALSA-style plumbing:
sample-format and rate handling, a PCM substream model
(open/hw_params/prepare/trigger/pointer/close) with error and xrun
recovery semantics, and a mixer surface for volume, mute, and
jack-sense. A sound-card registry assigns card indices and keeps a card
alive while a stream lease is outstanding; one hardware lease owns a
direction/device pair. Three bridges publish this to the filesystem —
`/dev/snd` via devfs, plus sysfs and procfs card information — through an
init call. These are ALSA-style interfaces; binary Linux ALSA ioctl/mmap
compatibility and USB Audio Class are separate work.

Native HDA and ACP engines live in `narf-audio` and register their
hardware PCM/mixer backends here; this crate's older software
controller/codec/PCM models remain for compatibility and tests. It
depends on capabilities, memory, I/O, bus, interrupts, scheduler, time,
the driver framework, and the filesystem, and is `no_std`.

- Spec: [`specification/spec.md`](./specification/spec.md)
