# pmbus — PMBus Power Telemetry

`narf-pmbus` is NARF's interface to PMBus (the Power Management Bus), the
SMBus/I²C-layered command protocol that intelligent power supplies and
voltage regulators speak. Its role in the kernel is narrow and deliberate:
expose real-time power telemetry — input and output voltage, current, output
and input power, and temperature — from an ATX 3.x power supply or a PMBus
regulator, without pulling the rest of the kernel into the details of the bus
transaction or the on-wire data encoding.

PMBus carries measurements in two standard numeric encodings: the Direct
format (a 16-bit signed value scaled by per-device coefficients) and the
Linear format (an 11-bit mantissa with a 5-bit exponent). The telemetry
commands the subsystem is concerned with are the standard `READ_*` opcodes —
input/output voltage and current, input/output power, and temperature
sensor 1. The crate's job is to model those readings as a single normalized
snapshot (millivolts, milliamps, milliwatts, millidegrees Celsius) so
consumers never touch raw PMBus words.

Architecturally the crate is a thin, transport-neutral abstraction layer: it
defines a monitor contract that a concrete bus driver implements, plus a
static device-information record (manufacturer, model, revision). Telemetry
reads are asynchronous — a PMBus transaction crosses a real bus and should
not block the caller — so the monitor contract is built on `async-trait` and
driven by `narf-scheduler`.

Access is mediated by NARF's capability system rather than by ambient
authority. PMBus is its own capability kind (`CapKind::PmBus`), and the crate
distinguishes read-only telemetry authority from configuration authority
(thresholds and limits) and from administrative authority (calibration,
inventory). A task that may observe power draw need not be trusted to
reconfigure the supply.

`narf-pmbus` is `no_std` and `alloc`-backed. It depends on `narf-lib`,
`narf-capabilities`, and `narf-scheduler`. The `kernel-test` feature compiles
in-kernel smoke tests that exercise the telemetry read cycle, the capability
kind, and the error and reading data shapes against a mock monitor.

- Spec: [`specification/spec.md`](./specification/spec.md)
