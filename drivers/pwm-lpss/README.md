# drivers/pwm-lpss — Intel LPSS PWM Controller Driver

This crate is NARF's first production PWM controller driver
(issue #1699): the Intel Low Power Subsystem (LPSS) PWM block on
Bay Trail, Braswell, Broxton and Tangier SoCs, enumerated over PCI.

It implements the `PwmDevice` trait from `narf-pwm` — channel
`set_config` (period/duty programming), `enable` / `disable`, and
`channel_count` — over the LPSS control register block (one 32-bit
register per channel at `channel * 0x400`). All register offsets,
bit positions and programming formulas are transcribed from Linux
`drivers/pwm/pwm-lpss.c`, `pwm-lpss.h` and `pwm-lpss-pci.c`
(torvalds/linux master); the crate's `specification/spec.md` names
the source for every constant.

The LPSS block has no polarity bit, so `Polarity::Inversed` is
emulated in software by complementing the duty cycle (the technique
Linux `pwm-meson.c` uses for hardware without polarity control).
Enable sequencing follows Linux exactly: non-bypass parts set
ENABLE before waiting for `SW_UPDATE` to clear; Broxton (bypass)
waits first, then sets ENABLE.

Until the `narf_pwm` controller registry lands with open draft PR
#1700, `probe()` stashes bound controllers in a module static
(`probed_controllers()`); the one-line `register_controller` wiring
is a marked rebase remainder, not re-implemented here.

Fixtures: a fake BAR0 window (leaked heap backing, backlight-test
pattern) plus a hardware-model task that clears `SW_UPDATE` the way
the block does at the next cycle start, asserting exact control
values (BYT 1 kHz/50% → `0x380`; BXT 25 kHz/25% → `0x1555C0`;
inversed → `0x15553F`), channel stride, enable/disable, both
enable orderings, input validation, stuck-`SW_UPDATE` errors, and
the 9-ID Linux PCI table.
