# drivers/leds — LED Class Registry and Drivers

`narf-drivers-leds` is NARF's LED subsystem: the single registry for every LED
device in the machine and the drivers that back them. It plays the role of
Linux's LED class, presenting a uniform brightness-and-trigger model over the
very different ways an LED is actually wired — a GPIO pin, a PWM channel, or a
keyboard indicator reached over HID — and publishing them under the
Linux-compatible `/sys/class/leds/*` hierarchy so existing tooling works.

Every LED registers through a common device contract into a global registry
guarded by an IRQ-safe spinlock, with name-based lookup. On top of that sit the
concrete drivers: GPIO-backed LEDs (with the active-low inversion real boards
need), PWM-backed dimmable LEDs (built on `narf-pwm`), and the keyboard
indicator LEDs — Caps Lock, Num Lock, Scroll Lock — bridged from HID output
reports. A multicolor module adds RGB LEDs with their own registry and color
model.

Two mechanisms make LEDs do more than hold a fixed level. The trigger engine
implements the familiar LED behaviors — Heartbeat, Timer blink, and OneShot —
advancing them at 100 ms resolution each time it is ticked. The engine worker
is a background task, started as a late-stage initcall once the scheduler is
up, that both ticks the trigger engine (so timed and heartbeat blinking
actually animate) and drains a command mailbox. That mailbox is the key to
atomic-context callers: a producer can enqueue a brightness, blink, off, or
color command without allocating or blocking, and the worker resolves the
device and performs the slow work (a registry snapshot, hardware color writes)
where sleeping is allowed. This is precisely the path `bpf-leds` uses to let a
BPF program drive an LED.

The crate is the home of the LED device contract itself, which is why the
backlight subsystem imports it rather than defining its own: the keyboard
backlight is registered here as a PWM LED. LEDs come up as `Stage::Device`
initcalls (the class and the sysfs bridge) with the worker deferred to
`Stage::Late`.

`narf-drivers-leds` is `no_std` and `alloc`-backed. It depends on `narf-lib`,
`narf-drivers-gpio`, `narf-pwm`, `narf-init`, `narf-scheduler`, `narf-time`,
and `narf-filesystem` (for the sysfs class), and uses `async-trait`. The
`kernel-test` feature compiles the in-kernel smoke suite over the class,
drivers, triggers, and worker.
