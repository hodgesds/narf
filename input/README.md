# input — Input Event Core

`narf-input` is the input-event core: the neutral contract that sits
between input drivers and the consumers that react to user activity. A
PS/2 keyboard controller, a virtio-input device, or a future USB HID
endpoint all speak different wire formats, but each translates its
hardware-specific bytes into the small set of event shapes defined
here — key, pointer, and scroll events — and pushes them through a
per-device event ring. Consumers (the eventual TTY, a windowing layer,
or the kernel test harness) pop from that ring through a
capability-gated subscriber handle, so only authorized readers observe
the stream.

The deliberate design point is that this crate stays neutral on
hardware specifics. It owns the *shape* of an input event and the
*plumbing* that moves events from one producer to many subscribers; it
does not own any scancode table, evdev code map, or panel protocol.
Those wire-level translation tables live in the drivers. The event and
code vocabulary is modeled structurally on Linux's stable `evdev`
user-facing ABI (the documented userspace numbering in `input.h`, not
the GPL kernel implementation), which gives the event codes, button
namespaces, and absolute-axis conventions a familiar and durable
layout.

Alongside the core ring, the crate carries a handful of device codecs
derived from public vendor documentation: a Goodix GT911 touchscreen
codec, a Synaptics RMI4 touchpad codec, and evdev/uinput-flavored
helpers for turning decoded device state into the canonical event
shapes. These are the parts generic enough to be reused across the
concrete drivers in `drivers/input`, rather than per-board glue.

The crate is `no_std` and allocation-aware (it uses `alloc` for the
ring's backing queue and subscriber bookkeeping). It builds on
`narf-lib` for IRQ-safe locking, on `narf-scheduler` and `narf-time`
for waking blocked subscribers and timestamping events, and on
`narf-init`/`narf-drivers` for registration into the kernel's
initcall and device model. The hardware drivers in `drivers/input` and
the HID profile decoders in `hid` are its principal producers.

- Spec: [`specification/spec.md`](./specification/spec.md)
