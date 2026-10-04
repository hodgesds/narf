# drivers/video — Camera & ISP Drivers

`narf-drivers-video` is the camera-capture driver crate: drivers for
the image signal processors (ISPs) and camera sensors found in modern
laptops, plus the V4L-like userspace surface through which captured
video is exposed. It plays the role Linux's media subsystem does —
binding the ISP, wiring up the MIPI-CSI receiver and the attached
sensor, and presenting a Video4Linux-compatible capture device — and
its device tables and structure are referenced against the GPL Linux
media drivers (consulted after the 2026-05-20 relicense).

The crate targets the integrated camera ISPs that appear on current
x86 laptops: Intel IPU3 (Skylake-era pixel visual core), Intel IPU6
across its Tiger Lake through Meteor Lake variants (each with its own
firmware blob name), and the AMD MP2 ISP. Each is matched by PCI ID
and carries its firmware-name constants. Alongside the ISPs are
drivers for the MIPI-CSI camera sensors those pipelines drive — Sony
IMX219 and several OmniVision parts (OV01A1S, OV02C10, OV05C10) —
behind a common CSI-2 sensor-driver interface, plus a USB Video Class
(UVC) driver for ordinary USB webcams (descriptor parsing, format and
probe negotiation, streaming, and payload/transfer handling).

The userspace-facing side is a V4L2-equivalent surface: a pixel-format
classification, V4L2-compatible buffer-queue types, and a devfs/sysfs
bridge that registers each capture device under the familiar
`/sys/class/video4linux/video<N>/` path so standard tooling recognizes
it.

This is an early-stage scaffold. Stage 0 established the crate skeleton
— PCI ID tables, firmware-name constants, buffer-queue and
pixel-format types, and the sensor trait — and Stage 1 added PCI probe
registration, BAR mapping, firmware-name resolution, and the
bound-driver record. The heavier work is deferred: firmware load over
the PSP/CSE paths, MIPI-CSI receiver bring-up, per-sensor I2C
configuration, the DMA scatter-gather ring, and the full V4L2 buffer
dequeue path.

The crate is `no_std`. It depends on the driver runtime and
`narf-bus`/`narf-drivers` for the device model, `narf-drivers-i2c` for
sensor configuration, `narf-filesystem` for the sysfs/devfs
registration, and `narf-init`/`narf-scheduler` for registration and
async work. The `kernel-test` feature compiles the sysfs registration
into the test build so smoke tests can assert it against a synthetic
device.
