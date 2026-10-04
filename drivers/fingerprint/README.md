# drivers/fingerprint — Fingerprint Reader Chip-Class Scaffold

`narf-drivers-fingerprint` is a chip-class scaffold for the USB
fingerprint readers found in business laptops. It recognizes the four
vendor families that dominate the installed base — Synaptics
(Prometheus / VFS9500 / Match-In-Sensor, VID `0x06CB`), Goodix (GF318
/ GF512 series, VID `0x27C6`), Validity / older Synaptics (VID
`0x138A`), and Elan (VID `0x04F3`) — by vendor ID, and provides a
probe-and-log entry point for devices it matches.

The crate is deliberately thin, and the reason is architectural. The
enrollment and matching protocols on every one of these chips are
vendor-proprietary, frequently signed, and intentionally undocumented;
some keep the biometric template entirely on-chip (Match-In-Sensor),
others stream images for host-side matching (Match-on-Host). The
right place for that protocol logic is userspace, mirroring Linux's
`libfprint` model: the kernel claims the USB device and exposes a
capability-gated surface that ferries raw USB transfers to a userspace
daemon, and userspace owns every byte of the vendor protocol. Keeping
the proprietary, security-sensitive code out of the kernel keeps the
trusted computing base small.

This is Stage-0 of that arc: a VID/PID match table plus probe
logging. The deferred stages — not present here — are interface-claim
against the USB stack's post-address dispatch so matched readers land
in a registry instead of falling through as an unknown class, a
cap-gated syscall/ioctl surface for the userspace daemon to issue raw
transfers, and power-management hooks for the suspend/resume state
machines (notably the Synaptics parts, which lock up without the
correct suspend-detect and resume-arm sequence). As of this stage the
crate speaks no vendor protocol, claims no interfaces, and exposes no
userspace surface.

The crate is `no_std` and minimal in its dependencies — `narf-lib`,
`narf-console` for probe logging, and `narf-init` for registration.
A `kernel-test` feature gates its in-kernel smoke tests. The device
tables are grounded in the public, BSD-licensed `libfprint`
supported-devices list; no GPL source was consulted.
