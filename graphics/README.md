# graphics — Graphics & Display Core

`narf-graphics` is the display-side core: framebuffer, pixel, drawing,
and display-interface primitives shared by every display driver and by
the kernel's framebuffer console. It stays neutral on which device
backs the framebuffer — bochs-display, virtio-gpu, ramfb, or a real
GPU scanout — by letting a driver construct a framebuffer view over
the device's linear buffer, after which the compositor, console, or
driver writes through the primitives defined here. The canonical pixel
format is 32-bit XRGB8888, the layout most QEMU framebuffers expose by
default, with the high byte held at 0xFF.

Above the raw pixel surface the crate provides the pieces a kernel
needs to put something legible on screen before any userspace display
server exists: a framebuffer-backed text console with an 8×8 glyph
font and a cursor grid, a mouse-cursor sprite with position tracking,
and an end-of-boot splash composer that paints a "kernel up" status
panel. These make the framebuffer usable as a boot console and status
display directly from kernel space.

The crate also carries clean-room codecs for the modern display
interface standards a display pipeline encounters, all derived from
public VESA and MIPI specifications with no GPL Linux source
consulted. These include a DisplayPort AUX channel and DPCD register
set (VESA DisplayPort 1.4a), Panel Self-Refresh and Adaptive-Sync
DPCD registers, VESA Display Stream Compression (DSC) picture-parameter
set encoding, and MIPI DSI and CSI-2 host packet codecs. A thin EDID
adapter delegates to the dedicated parser in the `edid` crate rather
than duplicating it. These codecs are the shared building blocks a
real modeset driver assembles into a link-training and mode-set
sequence.

The crate is `no_std` with `alloc`, and depends on `narf-lib` and
`narf-drivers`. It is consumed by the display drivers in
`drivers/graphics`, the GPU driver in `drivers/nvidia`, and the
framebuffer abstraction in `fb`, all of which build their
device-specific scanout and modeset logic on these primitives.

- Spec: [`specification/spec.md`](./specification/spec.md)
