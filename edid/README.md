# edid — EDID Display Descriptor Parser

`narf-edid` is a clean-room parser for the display-descriptor blocks a
monitor reports to the host. Every DDC-capable display exposes an EDID
(Extended Display Identification Data) structure — read over the
I2C-based VESA DDC transport — describing who made the panel, its
supported timings, color characteristics, and physical size. This
crate decodes that structure so a display driver can discover a
panel's capabilities and pick a mode without hard-coded assumptions.
It is derived strictly from public VESA standards and the Microsoft
PNP manufacturer-ID registry; no GPL Linux source was consulted.

The core is the VESA Enhanced EDID (E-EDID) 1.4 base block: the
128-byte structure with its header magic, compressed three-character
manufacturer code, product and serial numbers, manufacture date, input
definition, gamma and feature bitmap, chromaticity coordinates,
established and standard timing lists, the four detailed-timing /
display-descriptor slots, the extension-block count, and the trailing
checksum. On top of the base block the crate parses the extension
blocks that modern displays append: CTA-861 (the CEA extension
carrying HDMI/consumer video data blocks and additional timings),
VESA DisplayID, and CEC-related descriptors. Together these cover the
descriptor set a real HDMI or DisplayPort sink presents.

The crate stays narrowly a parser: it turns descriptor bytes into
structured data and validates checksums, and leaves transport (the
actual DDC/AUX read) and mode selection to its callers. The `graphics`
crate wraps it through a thin adapter, and the GPU driver in
`drivers/nvidia` pulls EDID over its DisplayPort AUX path and feeds the
bytes here to learn a sink's timings.

The crate is `no_std` and dependency-light, needing only the kernel
test harness. A `kernel-test` feature gates its in-kernel smoke tests.

- Spec: [`specification/spec.md`](./specification/spec.md)
