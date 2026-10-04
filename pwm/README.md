# pwm — Pulse-Width Modulation Subsystem

`narf-pwm` is NARF's clean-room pulse-width modulation subsystem. PWM is the
technique of encoding an analog level as the ratio of on-time to off-time of a
square wave; it is the hardware primitive behind fan speed control, LED
dimming, backlight brightness, piezo tone generation, and the step/direction
timing of motor controllers. A PWM controller exposes one or more independent
output channels, and this crate provides the kernel's hardware-agnostic model
of such a controller.

The control model is intentionally small and precise. A channel's behavior is
captured by three parameters — frequency, duty cycle (expressed as a
nanosecond on-time so the resolution does not depend on frequency), and output
polarity (normal or inverted) — together with the per-channel enable/disable
state and the channel count a controller reports. A concrete PWM controller
driver implements the device contract; higher-level drivers (fans, LEDs,
motors) consume it rather than reimplementing waveform generation. Because PWM
parameters are real-time constraints, configuration is meant to be applied
atomically so that changing a setting does not glitch the output mid-cycle.
Channel operations are asynchronous (built on `async-trait`, driven by
`narf-scheduler`) since programming a controller may cross a slow peripheral
bus.

Access is capability-gated under PWM's own capability kind (`CapKind::Pwm`).
This is a deliberate isolation property: a PWM channel is a typed capability,
so one subsystem cannot interfere with another's channel on the same
controller without holding the relevant capability. The security posture is
that raw PWM authority is dangerous — a bad duty cycle can overdrive hardware —
so safety-critical consumers are expected to hold the raw capability and
re-export a narrowed, checked interface to their own clients.

`narf-pwm` is `no_std` and `alloc`-backed, depending on `narf-lib`,
`narf-capabilities`, and `narf-scheduler`. It serves the LED, backlight, and
fan/motor driver layers; `drivers/leds` in particular builds its PWM-dimmable
LED driver on top of it. The `kernel-test` feature compiles in-kernel smokes
that drive a mock controller through configure/enable/disable, verify
channel-bounds rejection, and check the config, polarity, and error shapes.

- Spec: [`specification/spec.md`](./specification/spec.md)
