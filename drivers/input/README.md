# drivers/input — Input Hardware Drivers

`narf-input-driver` holds the concrete hardware drivers for input
devices. Where `input` defines the neutral event vocabulary and `hid`
defines the protocol codecs, this crate contains the per-controller
and per-device glue that talks to real silicon, translates its wire
format, and pushes canonical key, pointer, and scroll events into the
event ring.

The drivers span the input transports a modern laptop or tablet
actually uses. On x86_64 there is the legacy i8042 PS/2 path — a
keyboard driver and a mouse driver (including a PS/2-protocol
`psmouse`) — gated to x86_64 because no PS/2 controller exists outside
legacy PC platforms. Cross-architecture, the dominant class is
i2c-HID: devices that advertise `PNP0C50` and speak HID over an I2C
controller (such as an AMD FCH), which is the common case on ARM
laptops and modern thin-and-light x86 machines. On top of the i2c-HID
transport sit specialized HID bindings — keyboard, touch, multitouch
(with multitouch feature handling), Elan panels, HID-over-RMI, and HID
sensors. There are also direct-protocol drivers: a Goodix touchscreen
driver, a Synaptics RMI4 touchpad core, a Wacom digitizer, and a
Windows-Precision-style device path.

Each driver's role is narrow: claim its device, decode its reports or
raw packets, and emit events upstream. The reusable decoding logic —
HID report parsing, the RMI4 and Goodix codecs — comes from `hid` and
`input`; this crate supplies the binding, IRQ wiring, and
device-model registration. On the x86_64 i8042 path that means routing
each channel's interrupt handler through the IOAPIC at its ISA-default
GSI (1 for keyboard, 12 for mouse), honoring any ACPI MADT Interrupt
Source Override. Drivers register as `Stage::Device` initcalls so the
bus scan binds them during bring-up.

The crate is `no_std` and depends broadly on the kernel's device
plumbing: `narf-input` and `narf-hid` for the event and protocol
layers, `narf-drivers-i2c` and `narf-drivers-gpio` for the i2c-HID
transport, `narf-interrupts`/`narf-arch` for IRQ routing,
`narf-acpi`/`narf-aml` for device enumeration, and
`narf-init`/`narf-scheduler` for registration and async bind flows.
