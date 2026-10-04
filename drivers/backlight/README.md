# drivers/backlight — Backlight and Brightness-Key Subsystem

`narf-drivers-backlight` is NARF's subsystem for display and keyboard
brightness: it is the single registry point for panel backlights, drives the
keyboard-backlight LED, and turns the hardware brightness keys into input
events. Its role is to unify the several very different ways a laptop or
desktop actually controls screen brightness behind one device contract, and to
publish that contract where userspace expects it — the Linux-compatible
`/sys/class/backlight/*` hierarchy.

A backlight device is modeled by its name, its maximum brightness step, its
current level, a setter, and an interface kind. The interface kind mirrors the
Linux `backlight_type` distinction between Raw control (direct hardware PWM or
MMIO register writes), Firmware control (brightness mediated by platform
firmware such as ACPI or WMI), and Platform control (a vendor
embedded-controller register). That distinction matters because it tells
userspace and the kernel which device to prefer when several claim the same
panel. Registration is into a global, allocation-backed registry guarded by an
IRQ-safe spinlock, with name-based lookup and idempotent replacement.

The crate implements the real brightness control paths found on PC hardware.
The ACPI video path drives the `_BCL`/`_BCM`/`_BQC` methods — the firmware
brightness-level table, set, and query. The AMD GPU path bridges to the
`amdgpu` PWM backlight register. An Intel backlight scaffold is present for the
Intel PWM frequency/duty registers. Keyboard backlight is driven through vendor
WMI and registered as a PWM-backed LED in the LED class. The brightness-key
handler subscribes to ACPI Notify events and, on the standard
brightness-up/brightness-down notifications (0x86/0x87), steps the active ACPI
video device and emits the corresponding brightness key event into the input
layer.

Because the keyboard backlight is an LED, this crate builds on `drivers/leds`:
it imports that crate's LED class and registers its keyboard-backlight channel
there, so brightness and LED concerns share one registry rather than
duplicating it. The ACPI/WMI work rests on `narf-aml`; brightness keys feed
`narf-input`; devices are brought up as `Stage::Device` initcalls and exposed
through `narf-filesystem` via the sysfs bridge. The crate also pulls in
`narf-console`, `narf-scheduler`, `narf-time`, `narf-memory`, and the driver
runtime.

`narf-drivers-backlight` is `no_std` and `alloc`-backed, with strict lints. Its
`kernel-test` feature compiles the in-kernel smokes (and cascades the LED
crate's test feature), covering the registry, the ACPI video path, and the
brightness-key handler.
