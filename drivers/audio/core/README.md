# drivers/audio/core — shared native-audio helpers

PCI power-on (`native_pci`), MSI-X/MSI/INTx/poll IRQ routing (`native_irq`),
the PCM DMA ring (`native_pcm::Ring`) and ACPI/AML firmware queries
(`native_firmware`) shared by `narf-drivers-audio-hda` and
`narf-drivers-audio-acp`. Always built-in; never linked into a `.ko`.

- Spec: [audio specification](../../../audio/specification/spec.md) §3.3
