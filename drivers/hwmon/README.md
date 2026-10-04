# drivers/hwmon — Hardware Monitoring Drivers

`narf-drivers-hwmon` is NARF's hardware-monitoring subsystem: the drivers that
read a machine's temperature sensors, fan tachometers, and voltage rails, and —
where the hardware allows — set fan speeds. This is the kernel's equivalent of
Linux's hwmon class, and it follows the same conventions so that userspace sees
a familiar surface: temperatures in millidegrees Celsius, fan speeds in RPM,
voltages in millivolts.

All drivers register behind a single shared device contract that exposes the
chip's name, enumerates its sensor labels (driver-defined strings such as
`"Tdie"`, `"fan1"`, `"in0"`), reads a sensor by label, and optionally drives a
fan PWM output. A measurement class a given chip does not support simply reads
back as absent. A small registry collects the probed devices, and a
`sysfs_bridge` publishes them under the Linux-compatible `/sys/class/hwmon/*`
layout so existing monitoring tools work unmodified.

The crate ships concrete drivers spanning the common sensor sources on real
x86 hardware. `k10temp` reads AMD Family 17h/19h (Zen 2 through Zen 4) CPU
temperature and voltage; `coretemp` reads Intel per-core thermal status through
the thermal-status MSRs. `nct6775` and `it87` drive Nuvoton and ITE Super-I/O
"environment controller" chips found on desktop motherboards — the chips that
carry most board-level fan and voltage sensing. `dell_smm` speaks the Dell
System Management Mode interface over the i8042 path for fan and temperature
control on Dell laptops. `applesmc` reaches the Apple System Management
Controller, and `jc42` handles JC-42.4 temperature sensors on memory modules.

The drivers probe through NARF's driver and bus machinery rather than appearing
by magic: hwmon registers its probes as `Stage::Subsys` initcalls (PCI for
k10temp, ISA/Super-I/O port probes for nct6775 and it87, MSR and SMM paths for
the x86-only CPU and platform drivers), and the sysfs bridge runs as a later
stage once every driver has had its chance to probe. Several drivers are
compiled only for `x86_64`, matching where the hardware exists. Firmware
discovery leans on SMBIOS and AML (ACPI) to identify platform-specific
controllers.

`narf-drivers-hwmon` is `no_std` and `alloc`-backed. It depends broadly on the
kernel's plumbing — `narf-lib`, `narf-bus`, `narf-arch`, `narf-capabilities`,
`narf-console`, `narf-filesystem` (for the sysfs class), `narf-init` (for
initcall staging), `narf-firmware-smbios`, and `narf-aml`. The `kernel-test`
feature compiles the in-kernel smoke suite over the drivers and the sysfs
bridge.
