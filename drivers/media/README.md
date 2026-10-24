# drivers/media — Media Capture and Broadcast Drivers

The media subsystem: drivers for devices that capture or receive audio/video
and related signals, rather than storing or displaying them. It covers four
broad domains — Software Defined Radio (SDR), Digital Video Broadcasting
(DVB), HDMI Consumer Electronics Control (CEC), and video/TV capture — modeled
after the organization of Linux's `drivers/media` tree. These are the drivers
behind webcams, TV tuners, HDMI capture bridges, and RF receivers.

Each device is a self-contained module. `rtl2832` drives the Realtek RTL2832U
USB receiver, the chip at the heart of the ubiquitous RTL-SDR dongles, usable
both as a DVB-T demodulator and as a raw SDR front end. `tc358743` drives the
Toshiba TC358743 HDMI-to-MIPI-CSI-2 bridge found in common HDMI capture
adapters. `cec_gpio` implements HDMI CEC by bit-banging the protocol on a single
GPIO pin, giving the kernel a way to exchange CEC control messages without
dedicated CEC hardware.

This crate has **no UVC driver and no software camera**. It previously carried
log-only `uvcvideo` and `vivid` placeholder modules that announced themselves
as registered while doing nothing; both were deleted under #810 (2026-10-24)
so they cannot be mistaken for a working path. The live USB Video Class
implementation is `drivers/usb/src/uvc.rs` (bind/negotiate/pump) together with
the codec library and V4L2 surface in `drivers/video` (`uvc/`, `v4l2_ioctl.rs`,
`devfs_bridge.rs`). A real vivid-style software camera — the natural fixture
base for the V4L2 pipeline — is scoped to the #812 end-to-end fixture lane,
not to this crate.

The crate depends on the USB stack (`drivers/usb`) for the USB-attached
devices and on the bus and console facilities for enumeration and logging; it
exposes a single initcall-registration entry point that wires each driver's
own initcalls into the kernel's staged boot. It is `#![no_std]`, forbids
implicit unsafe in unsafe functions, and denies missing `Debug`
implementations. Device availability is inherently hardware- and
bus-dependent; this crate currently offers no hardware-free test device.
