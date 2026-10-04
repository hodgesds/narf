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
adapters. `uvcvideo` supports USB Video Class webcams and capture devices,
driving any camera that conforms to the UVC specification rather than a single
part. `cec_gpio` implements HDMI CEC by bit-banging the protocol on a single
GPIO pin, giving the kernel a way to exchange CEC control messages without
dedicated CEC hardware. `vivid` is the Virtual Video Test Driver — a
software-only, hardware-free video source used to exercise the capture
pipeline in tests and smokes where no physical device is attached.

The crate depends on the USB stack (`drivers/usb`) for the USB-attached
devices and on the bus and console facilities for enumeration and logging; it
exposes a single initcall-registration entry point that wires each driver's
own initcalls into the kernel's staged boot. It is `#![no_std]`, forbids
implicit unsafe in unsafe functions, and denies missing `Debug`
implementations. Device availability is inherently hardware- and
bus-dependent; `vivid` is the exception that always works and anchors
pipeline testing.
