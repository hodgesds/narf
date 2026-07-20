# Extending NARF: Sound / Audio Drivers

Prereq: [drivers.md](drivers.md). This covers the audio-stream seam a sound
card / codec driver publishes into.

Source: `audio/src/lib.rs`. Reference drivers: Intel HDA (`audio/src/hda.rs`)
and virtio-sound (`drivers/virtio` via `narf_drivers_virtio::snd_pci`).

The trait is out-of-tree-implementable; the **active-stream picker is
hard-coded** (same shape as the graphics scanout picker — see the gotcha).

---

## 1. The `AudioStream` trait — implement this

`AudioStream` (`audio/src/lib.rs:118`) is the backend-agnostic stream interface.
All four methods required; `Send + Sync + Debug`:

```rust
pub trait AudioStream: Send + Sync + core::fmt::Debug {   // audio/src/lib.rs:118
    fn current_format(&self) -> Option<AudioFormat>;       // :121  None until opened
    fn supports(&self, fmt: AudioFormat) -> bool;          // :124  format negotiation
    fn name(&self) -> &'static str;                        // :127  "hda", "virtio-sound", "ac97"
    fn is_playback(&self) -> bool;                         // :130  true = playback, false = capture
}
```

`AudioFormat` (`audio/src/lib.rs`) is the triple `(sample_rate_hz, SampleFormat,
ChannelLayout)`; `SampleFormat` is `S16Le`/`F32Le`, `ChannelLayout` is
`Mono`/`Stereo`. The Stage-3 baseline every driver should support is **48 kHz /
S16LE / stereo**; advertise anything extra via `supports()`.

Implementations are typically zero-sized wrappers over the driver's stream
state, exposed as a `static` (`static HDA_PLAYBACK: IntelHdaPlayback`,
`audio/src/lib.rs:199`).

---

## 2. How a driver is wired

A sound driver has two independent registrations:

1. **The PCI driver** (bus binding) — ordinary
   `narf_bus::register_pci_driver`, at `Stage::Subsys`. This is what brings the
   controller up.
2. **The `AudioStream` backend** — a `static` your crate owns, which the audio
   crate's picker consults.

### 2.1 PCI registration (HDA reference)

`register_pci_driver` (`audio/src/hda.rs:1851`) — note it loops over a whole ID
table under one probe:

```rust
pub fn register_pci_driver() {
    for &(name, vendor, device) in HDA_PCI_IDS {           // 41 AMD+Intel HDA IDs
        narf_bus::register_pci_driver(narf_bus::PciMatch {
            name,
            kind: narf_bus::MatchKind::VendorDevice { vendor, device },
            probe,                                          // audio/src/hda.rs:1705
        });
    }
}
```

Probe signature is the standard
`fn(BusDevice, Cap<BusDeviceCap, Write>) -> Result<(), ProbeError>`
(`audio/src/hda.rs:1705`). Wired at `Stage::Subsys` (`audio/src/lib.rs:440`):

```rust
narf_init::register(Stage::Subsys, "hda-pci", || {
    hda::register_pci_driver();
    InitResult::Ok
});
```

### 2.2 The playback picker

`select_active_playback()` (`audio/src/lib.rs:204`) returns the first backend
whose `current_format()` is `Some` (i.e. actually probed + opened):

```rust
pub fn select_active_playback() -> Option<&'static dyn AudioStream> {  // audio/src/lib.rs:204
    if PLAYBACK.current_format().is_some() { return Some(&PLAYBACK); }        // virtio-sound
    if HDA_PLAYBACK.current_format().is_some() { return Some(&HDA_PLAYBACK); } // Intel HDA
    None
}
```

A `Stage::Late` initcall (`audio/src/lib.rs:452`, `audio-playback-picker`)
resolves the active stream once at boot.

---

## 3. Gotcha: the active-stream picker is hard-coded

Like the framebuffer scanout picker, `select_active_playback`
(`audio/src/lib.rs:204`) references a **fixed set of `static` backends**
(`PLAYBACK` = virtio-sound `audio/src/lib.rs:166`, `HDA_PLAYBACK` = Intel HDA
`audio/src/lib.rs:199`), both living in the `audio` crate. **A new out-of-tree
audio backend can bring its hardware up and implement `AudioStream`, but it will
not be selected as the active playback stream without editing
`audio/src/lib.rs`.**

So today the clean out-of-tree part is: register your PCI driver, bring the
codec up, and drive PCM through your own controller path. Being picked up by the
generic `narf_audio` write path (`audio/src/lib.rs:241` routes through
`select_active_playback`) requires a small core edit to add your `static` to the
picker. Flagged as a gap — parallel to graphics §4.

Other notes:

- **`no_std`/`alloc`.** Standard driver constraints (see [drivers.md](drivers.md)
  §4). DMA the PCM ring from coherent buffers.
- **One probe, many IDs** is a good pattern (HDA's 41-entry table under one
  probe) — the probe inspects the device to pick the codec path.
- **`/dev/snd` directory.** The sound char-device directory uses the same
  directory-delegate devfs pattern as `/dev/dri`
  (`narf_filesystem::devfs::register_snd_dir`, see [chardev.md](chardev.md)).
