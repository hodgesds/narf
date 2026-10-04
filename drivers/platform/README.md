# drivers/platform — Platform & Chipset Peripheral Drivers

`narf-drivers-platform` is the home for drivers that talk to the
platform and chipset peripherals glued to a machine's board rather
than to the general expansion buses — the embedded controller, the
SMBus/SMBus-over-PCI host, the TPM, thermal and fan control, laptop
lid/battery/button telemetry, vendor hotkey and WMI dispatch, and a
range of Intel/AMD chipset features such as the management engine
host interface, VSEC/PMT telemetry capabilities, processor thermal
tuning, and AMD modern-standby D-state control. Each device is a
clean-room implementation against a public specification (the ACPI
and TPM 2.0 specs, Intel ICH SMBus, and documented vendor
interfaces), and each lives in its own module.

Conceptually this crate sits above the kernel's driver and bus
layers and leans heavily on firmware services. Many of its drivers
are driven by ACPI: they walk the AML namespace, respond to SCI
events routed through the embedded controller's event registry, and
consume SMBIOS data to identify the OEM. A vendor registry probes the
SMBIOS Type-1 manufacturer string and routes to the matching per-
vendor laptop driver — ThinkPad, IdeaPad, Dell, HP, ASUS, Samsung,
Surface, System76 — so that only the driver appropriate to the
running hardware activates. The rest (SMBus, TPM, thermal, fan,
backlight, IPMI, watchdog, and the Intel/AMD chipset features)
register independently.

All of these are wired into the kernel through the staged initcall
registry: the crate exposes a single entry point that registers its
drivers at the subsystem stage, and ordering among them is deliberate
where it matters — the EC's event handler must be installed before
the hotkey bridge that depends on it, and the vendor WMI and laptop-
vendor dispatch must run after the ACPI/AML namespace walk has
enumerated the WMI GUIDs. Registration is uniformly best-effort: on
hardware that lacks a given device the initcall simply reports the
device absent and the kernel continues.

Much of the crate is inherently x86-specific. The embedded
controller reaches its registers through x86 I/O ports, the Intel
management-engine and chipset features only appear on Intel PCHs, and
the laptop/vendor paths assume PC firmware; those modules are gated to
x86_64. The aarch64 equivalents (SoC-specific PMIC and MMIO embedded-
controller paths) are not yet ported, so the board-telemetry drivers
compile only on x86_64, while a smaller architecture-neutral core
(SMBus, TPM, thermal, fan) builds everywhere. A `kernel-test` feature
gates in-tree test support. The crate is `no_std`.
