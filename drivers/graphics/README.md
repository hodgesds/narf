# drivers/graphics — Display Hardware Drivers

`narf-graphics-driver` holds the concrete display drivers that bind a
scanout device and present its linear framebuffer to the rest of the
kernel. Where `graphics` defines the neutral framebuffer and
display-interface primitives, this crate contains the per-device glue
that maps a device's BARs, programs its display registers, and exposes
the result as a framebuffer the console and compositor can draw into.

The current surface is small and targets the paravirtual platforms
used for bring-up. The primary driver is bochs-display — QEMU's
`-device bochs-display` on an x86_64 q35 machine — which is registered
as a PCI driver during the `Stage::Subsys` initcall phase so the bus
scan finds and binds it. A generic path consumes a linear framebuffer
whose parameters were handed over by the bootloader (UEFI GOP, VBE,
and similar firmware framebuffers), for the case where firmware has
already set a usable mode and the kernel only needs to adopt it. The
companion driver families named as future work — virtio-gpu
(cross-architecture) and ramfb (minimal paravirtual) — fit the same
registration shape.

A deliberate layering note: the generic framebuffer's `FbScanout`
implementation deliberately lives in the `fb` crate rather than here,
to avoid a circular dependency between the scanout abstraction and the
driver that produces it. This crate supplies the device discovery and
register programming; `fb` owns the active-scanout selection and the
bounds-checked draw surface.

The crate is `no_std` with `alloc`, and depends on `narf-graphics` for
the framebuffer primitives, `narf-bus` and `narf-drivers` for the
device model, `narf-memory` for BAR mapping, `narf-capabilities` for
gating access to the scanout, and `narf-init` for initcall
registration.
