# drivers/audio/hda — HD Audio controller + codec

Native driver for Intel, AMD and ATI/AMD-GPU HD Audio controllers and their
HDA codecs. `hda.rs` + `hda/` cover the controller (CORB/RIRB, stream
descriptors, IRQ/service, HDMI/DP audio, codec quirks); `hda_codec.rs` the
transport-neutral widget walk, verbs and pin configuration. `ids.rs` is the
PCI match table, compiled in both builds. `narf-audio` re-exports `hda` and
`hda_codec`. Sequencing follows Linux `sound/hda/{core,controllers}`.

Dual-build: the built-in build compiles the real driver; the `.ko` build
registers every id in `ids.rs` through the `narf_register_pci_driver`
KSYMTAB export and is registration-only until the device datapath ABI covers
a PCM device.

```
cargo xtask build-module --package narf-drivers-audio-hda \
  --no-default-features --features module
```

- Spec: [audio specification](../../../audio/specification/spec.md) §3.2–§3.3
