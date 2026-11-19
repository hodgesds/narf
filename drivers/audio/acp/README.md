# drivers/audio/acp — AMD Audio Co-Processor

Native drivers for the AMD ACP: ACP 3.x (Renoir) and 6.3 (Phoenix) PDM DMIC
capture (`acp3x.rs`, `acp63.rs`, the `acp6.rs` compatibility surface) and the
ACP 6.3 SoundWire manager (`acp63_sdw.rs`, `acp63_sdw_dma.rs`) with its bus
core (`soundwire.rs`) and Realtek RT711 / RT1316 codecs. All share PCI id
1022:15E2; the revision selects the register map at probe. `narf-audio`
re-exports every module. Programming follows Linux `sound/soc/amd/ps/`.

Dual-build: the built-in build compiles the real drivers; the `.ko` build
registers 1022:15E2 through the `narf_register_pci_driver` KSYMTAB export and
is registration-only until the device datapath ABI covers a PCM device.

```
cargo xtask build-module --package narf-drivers-audio-acp \
  --no-default-features --features module
```

- Spec: [audio specification](../../../audio/specification/spec.md) §3.2–§3.3
