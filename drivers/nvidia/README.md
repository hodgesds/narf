# drivers/nvidia — NVIDIA GPU Driver

`narf-drivers-nvidia` is the NVIDIA GPU driver scaffold. It targets the
discrete and mobile GeForce parts from Maxwell forward — GTX through
RTX, up to Ada Lovelace — and deliberately excludes Tegra. Its
authoritative reference is Linux's Nouveau driver, cited as a
first-class source under NARF's GPL-2.0-or-later license; the module
layout mirrors Nouveau's split between the `nvkm` core, the engines,
and the display block.

A full GPU driver is many subsystems, and the crate is organized along
the same lines. The device foundation covers PCI attach and PCIe error
recovery, the Master Controller, the BAR windows, the GPU MMU, the
frame-buffer/VRAM subsystem, and VBIOS table parsing — plus a
per-ASIC dispatch table keyed on chip family (Fermi through Ada), so
one driver can specialize per generation. The Falcon microcontroller
framework underpins the signed microcontrollers the GPU boots: the PMU
(power management), SEC2, the GSP runtime, and the firmware front-ends
of the graphics, NVDEC, and NVENC engines. The engine side exposes the
host FIFO and channel/pushbuffer machinery, the graphics engine, the
copy engine, and fences for command completion, with NVDEC and NVENC
present for video decode and encode.

The display side is a DRM/KMS-like modeset stack for Maxwell-and-later
(the `nv50`-class display): a kernel-mode-setting layer over CRTC and
SOR output resources, DisplayPort link handling with AUX, EDID read
over AUX, hotplug detection, MST (multi-stream transport for daisy-
chained DP), HDCP, and page-flip/present submission. Pre-Maxwell
display hardware is explicitly not a target.

The crate is a clean-room scaffold: it establishes the subsystem
structure and register/command vocabulary with Nouveau as the
reference, rather than a fully functional driver. It registers during
the `Stage::Subsys` initcall phase so the PCI bus scan can bind it.

The crate is `no_std` with `alloc`. It depends on the driver runtime
and `narf-bus`/`narf-drivers` for the device model,
`narf-capabilities` and `narf-memory`-adjacent plumbing for resource
access, `narf-edid` and `narf-graphics` for mode and scanout support,
and `narf-firmware` and `narf-crypto` for loading and verifying the
signed GPU microcode. A `kernel-test` feature gates its in-kernel
smoke tests.
