# USB-C port drivers — specification

## 1. Purpose & scope

Provide firmware-owned UCSI connectors and host-owned Type-C port controller
(TCPC) drivers. UCSI/firmware owns PD policy and the mux on ACPI laptops;
raw TCPC drivers supply the physical transport to `narf_usbpd::tcpc`.

## 2. Assumptions

UCSI requires an enabled ACPI `PNP0CA0`, a valid shared-memory `_CRS`, and
revision-1 `_DSM` read/write functions. PCI NHI enumeration alone does not
establish UCSI availability. Raw TCPC probing is suppressed when a PNP0CA0
exists to avoid competing with firmware for the same controller.

## 3. Public interface

- `ucsi::Transport` supplies bounded version, CCI, control and message accesses.
- `ucsi::Ppm<T>` owns and serializes async reset, initialization, polling and
  mode selection. Known UCSI versions 1.0/1.1/1.2/2.0/2.1/3.0 are accepted.
- `ucsi::connectors()` returns `Connector` snapshots keyed by `(ppm, number)`.
  `available` distinguishes a working PPM from transport failure. Snapshots
  expose connection/data/power state, firmware CAM/SVID/VDO, and orientation
  only when the UCSI version reports it. UCSI numbers are never GPU indices.
- `ucsi::register_observer(Arc<dyn ConnectorObserver>)` delivers the current
  snapshot and changes in task context, with no registry lock held.
- `Ppm::set_mode` requires firmware's alternate-mode override feature,
  validates PPM/connector identity and refreshes connection/mode support.
  Its mode-specific configuration is a Configure VDO, not a lane count.
- UCSI publishes `extcon::typec::FirmwareState` without programming a host mux.
- Existing TCPC drivers register `Arc<dyn Tcpc>`; production I2C drivers retain
  their granted `Cap<I2cBus, Write>` and use capability-checked operations.

## 4. Invariants

A single task owns each PPM. Command completion and acknowledgement complete
before another command starts; command errors still receive an ACK. Connector
changes are preserved independently. Transport/ACK failure or cancelled
commands poison the PPM until reset. Shared-memory accesses and all firmware
lengths/connector indices are checked. Failed workers publish unavailable
state, retry reset at bounded intervals, and stop after three failures.

PM gates prevent AML/shared-memory access during suspend; in-flight commands
return Busy to the system suspend caller. Resume requests a PPM reinitialization.
No hardware polling holds a spinlock or runs a custom busy-spin loop.

## 5. Architecture notes

The ACPI transport maps firmware RAM write-back, uses volatile little-endian
accesses and fences, and polls `_DSM` every 100 ms as a Notify fallback.
The protocol and fake-device tests run on x86_64 and aarch64.

## 6. Dependencies and references

`aml`, `memory`, `scheduler`, `time`, `power`, `drivers/extcon`, `drivers/i2c`,
`usbpd`, `capabilities`. UCSI register layouts/handshakes were checked against
`/usr/src/linux/drivers/usb/typec/ucsi/{ucsi.h,ucsi.c,ucsi_acpi.c,displayport.c}`.
The existing TPS65987 driver references TI SLVUBH2A/SLVSEX0F; FUSB302 references
ON Semiconductor FUSB302B/D and USB Type-C/PD specifications.

## 7. Stage assignment

Stage 5 laptop connector integration. Fake transports test status versions,
command/ACK sequencing, event preservation and failure poisoning. Physical
Lenovo firmware has not been exercised by this change.

## 8. Open work

ACPI Notify-driven wakeups, broader platform quirks and role-swap interfaces.
GPU source modesetting and native USB4 tunneling are separate subsystems.
