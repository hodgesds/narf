# drivers/sound — HDA Sound Drivers and ALSA-Style Surface

`narf-drivers-sound` holds NARF's sound-hardware drivers and the
card-oriented, ALSA-equivalent surface that sits in front of them.
Where `narf-audio` owns the abstract PCM stream API and the active
native engines, this crate owns the sound-card registry, the PCM
substream lifecycle, the mixer control surface, and the filesystem
bridges that make audio visible to userspace. Without a working driver
here the machine's speakers, microphone, and headphone jack are silent.

The cards registered here are driven by the native engines in
`narf-audio` — the Intel/AMD HDA controller family (the AMD HDA
controllers on Zen2 Renoir and Phoenix HawkPoint laptops with Realtek
ALC-family codecs, and Intel PCH HDA) and the ACP 6.3 co-processor.
This crate keeps only the HDA stream-descriptor and buffer-descriptor
list types (`hda::streams`) that its PCM substream model is built on.
It formerly carried its own software HDA controller/codec models and
stub drivers (Intel8x0, SOF, MAX98357A, RT5645); none had a caller,
and they were excised in #783. The Realtek ALC init sequences and
per-laptop-model quirk tables they held were rescued into
`narf_audio::hda::quirks`.

On top of the hardware, the crate provides the ALSA-style plumbing:
sample-format and rate handling, a PCM substream model
(open/hw_params/prepare/trigger/pointer/close) with error and xrun
recovery semantics, and a mixer surface for volume, mute, and
jack-sense. A sound-card registry assigns card indices and keeps a card
alive while a stream lease is outstanding; one hardware lease owns a
direction/device pair. Three bridges publish this to the filesystem —
`/dev/snd` via devfs, plus sysfs and procfs card information — through an
init call. The file bridge implements Linux ALSA PCM/control ioctls, shared
sample mappings, pointer synchronization and poll readiness. See the
[specification](specification/spec.md#31-linux-alsa-pcm-and-control-abi) for
supported requests and hardware capability limits. USB Audio Class is
separate work.

Native HDA and ACP engines live in `narf-audio` and register their
hardware PCM/mixer backends here. It depends on capabilities, memory,
I/O, bus, interrupts, scheduler, time, the driver framework, and the
filesystem, and is `no_std`.

- Spec: [`specification/spec.md`](./specification/spec.md)
