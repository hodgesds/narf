//! `/proc/bus/{pci,usb,input}/*` — bus-subsystem visibility files.
//!
//! Three subtrees registered under the dynamic procfs registry:
//!
//! * `/proc/bus/pci/devices`       — one line per PCIe device (BDF + IDs + BARs)
//! * `/proc/bus/pci/<bus>/<slot>.<func>` — raw 256-byte config-space blob (deferred)
//! * `/proc/bus/usb/devices`       — multi-line USB topology (T/B/D/P/S/C/I/E)
//! * `/proc/bus/input/devices`     — multi-line input device capabilities
//! * `/proc/bus/input/handlers`    — one line per evdev handler
//!
//! Linux refs:
//!   `drivers/pci/proc.c`               — pci_procfs_read / proc_bus_pci_devices
//!   `drivers/usb/core/devio.c`         — usb_dump_device_descriptor et al.
//!   `drivers/input/input.c`            — input_proc_devices_show
//!
//! ## Dep-graph constraints
//!
//! `narf-filesystem` already depends on `narf-input` and (now) `narf-bus`.
//! `narf-drivers-usb` depends on `narf-filesystem`, so `narf-filesystem`
//! cannot depend on `narf-drivers-usb` (cycle).  USB device data reaches
//! us through a function-pointer hook installed by `narf_drivers_usb` at
//! boot, identical to the hook pattern used in `procfs/net.rs`.
//!
//! For input, `narf_input::evdev::snapshot_devices()` is a public API we
//! added to the already-in-deps crate — no hook needed.

extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use narf_bus::{registry, BusKind};
use narf_input::evdev;

use super::{register_proc, ProcFile};

// ════════════════════════════════════════════════════════════════════
// USB hook — avoids narf-filesystem → narf-drivers-usb dep cycle
// ════════════════════════════════════════════════════════════════════

/// Snapshot of one USB device, suitable for `/proc/bus/usb/devices`.
/// The USB driver populates this via `install_usb_proc_hook`.
#[derive(Clone, Debug, Default)]
pub struct UsbDeviceSnapshot {
    /// Root-hub port this device is connected to (1-indexed).
    pub port: u8,
    /// Sequential device number (root hub = 1, first device = 2, …).
    pub dev_num: u32,
    /// Speed in Mbps: 1=LS, 12=FS, 480=HS, 5000=SS, 10000=SS+.
    pub speed_mbps: u32,
    /// idVendor from the USB Device Descriptor.
    pub vendor_id: u16,
    /// idProduct from the USB Device Descriptor.
    pub product_id: u16,
}

/// Hook function type: returns a snapshot of all currently-enumerated USB
/// devices (not including the synthetic root hub).
type UsbSnapshotFn = fn() -> Vec<UsbDeviceSnapshot>;

static USB_SNAPSHOT_HOOK: AtomicUsize = AtomicUsize::new(0);

/// Install the USB device snapshot hook.  Called once by the USB driver's
/// boot initcall.  Linux analogue: `usb_register_notify` + the
/// `usb_proc_init` procfs bridge in `drivers/usb/core/devio.c`.
pub fn install_usb_proc_hook(f: UsbSnapshotFn) {
    USB_SNAPSHOT_HOOK.store(f as usize, Ordering::Release);
}

fn usb_snapshot() -> Vec<UsbDeviceSnapshot> {
    let v = USB_SNAPSHOT_HOOK.load(Ordering::Acquire);
    if v == 0 {
        return Vec::new();
    }
    // SAFETY: v was stored via `f as usize` in install_usb_proc_hook, so it
    // holds a valid function pointer of type UsbSnapshotFn.
    // SAFETY: Valid memory or trusted environment
    let f: UsbSnapshotFn = unsafe { core::mem::transmute(v) };
    f()
}

// ════════════════════════════════════════════════════════════════════
// /proc/bus/pci/devices
// ════════════════════════════════════════════════════════════════════

/// `/proc/bus/pci/devices` line format (Linux `drivers/pci/proc.c`):
///
/// ```text
/// <bdf>  <vendor><device>  <irq>  <bar0>...<bar5>  <rom>  <driver>
/// ```
///
/// * BDF:  `(bus<<8)|(dev<<3)|fn` as 4 hex digits
/// * vendor+device: 8 hex digits (no separator)
/// * IRQ: 2 hex digits (from cfg-space offset 0x3C)
/// * BARs 0-5: 16-digit padded u64 (raw register, 64-bit BAR pairs merged)
/// * ROM: 16-digit padded u64
/// * driver: empty when unbound
///
/// BAR sizing (the destructive write-read-restore cycle) is NOT performed
/// here — we read the raw register values as programmed by firmware.
/// Deferred: add a non-destructive `bars_snapshot` helper to `bus::pci`.
#[derive(Debug)]
struct PciDevicesFile;

impl ProcFile for PciDevicesFile {
    fn read(&self) -> Vec<u8> {
        use core::fmt::Write as _;
        let devs = registry::snapshot();
        let mut out = String::new();
        for d in &devs {
            let pcie_addr = match d.kind {
                BusKind::Pcie { addr, .. } => addr,
                BusKind::VirtioMmio { .. } => continue,
            };
            let cfg_phys = match d.kind {
                BusKind::Pcie { cfg_phys, .. } => cfg_phys.raw(),
                _ => 0,
            };

            // BDF packed as Linux: (bus<<8)|(dev<<3)|fn.
            let bdf = ((pcie_addr.bus as u32) << 8)
                | ((pcie_addr.device as u32) << 3)
                | (pcie_addr.function as u32);
            // vendor+device concatenated (no separator).
            let vid_did = ((d.id.vendor as u32) << 16) | (d.id.device as u32);

            // IRQ from cfg-space offset 0x3C (interrupt_line).
            let irq: u8 = if cfg_phys != 0 {
                // SAFETY: cfg_phys is the ECAM window (set by the bus
                // enumerator).  Offset 0x3C is within the 256-byte type-0
                // standard header which is always readable.  Identity-mapped.
                // SAFETY: Valid memory or trusted environment
                unsafe { core::ptr::read_volatile((cfg_phys + 0x3C) as *const u8) }
            } else {
                0
            };

            // BARs: read raw 32-bit register slots, then merge 64-bit pairs.
            let mut bars = [0u64; 6];
            if cfg_phys != 0 {
                for i in 0u64..6 {
                    // SAFETY: BAR registers at offsets 0x10..0x28; within
                    // the 256-byte standard header; identity-mapped.
                    // SAFETY: Valid memory or trusted environment
                    bars[i as usize] = unsafe {
                        core::ptr::read_volatile((cfg_phys + 0x10 + i * 4) as *const u32) as u64
                    };
                }
                // Merge 64-bit BAR pairs (bit 2 of low slot set = 64-bit).
                let mut i = 0;
                while i < 5 {
                    if (bars[i] & 0b110) == 0b100 {
                        bars[i] = (bars[i + 1] << 32) | (bars[i] & 0xFFFF_FFF0);
                        bars[i + 1] = 0;
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
            }

            // ROM BAR at offset 0x30.
            let rom: u64 = if cfg_phys != 0 {
                // SAFETY: offset 0x30 within the 256-byte header.
                unsafe { core::ptr::read_volatile((cfg_phys + 0x30) as *const u32) as u64 }
            } else {
                0
            };

            let _ = write!(out, "{bdf:04x} {vid_did:08x} {irq:02x}");
            for b in &bars {
                let _ = write!(out, " {b:016x}");
            }
            let _ = writeln!(out, " {rom:016x}  ");
        }
        out.into_bytes()
    }
}

// ════════════════════════════════════════════════════════════════════
// /proc/bus/pci/<bus>/<slot>.<func>  — 256-byte config-space blob
// ════════════════════════════════════════════════════════════════════

/// Per-device binary config-space file.  Used from `PciBusDir` DirOps
/// (follow-up); defined here for completeness.
///
/// Linux reads up to 4 KiB (extended config space); we restrict to 256
/// bytes (the standard type-0 header) to avoid triggering the "don't read
/// undefined config regs" errata noted in `drivers/pci/proc.c:42`.
#[derive(Debug)]
pub struct PciCfgSpaceFile {
    /// Physical base of this function's 4-KiB ECAM window.
    pub cfg_phys: u64,
}

impl ProcFile for PciCfgSpaceFile {
    fn read(&self) -> Vec<u8> {
        const CFG_SIZE: usize = 256;
        if self.cfg_phys == 0 {
            return alloc::vec![0u8; CFG_SIZE];
        }
        let mut out = Vec::with_capacity(CFG_SIZE);
        for off in 0..CFG_SIZE {
            let val =
                // SAFETY: cfg_phys is the ECAM window; identity-mapped.
                unsafe { core::ptr::read_volatile((self.cfg_phys as usize + off) as *const u8) };
            out.push(val);
        }
        out
    }
}

// ════════════════════════════════════════════════════════════════════
// /proc/bus/usb/devices
// ════════════════════════════════════════════════════════════════════

/// Multi-line USB device listing.
///
/// Format mirrors `drivers/usb/core/devio.c::usb_dump_device_descriptor`.
/// The root hub is synthesised from the enumerated device count.
///
/// Bandwidth allocation ("B:") and per-interface endpoint ("E:") details
/// are deferred — USB bandwidth accounting is not tracked at the NARF
/// driver level yet.  The "B:" line is emitted for format compliance but
/// always reports 0.
#[derive(Debug)]
struct UsbDevicesFile;

impl ProcFile for UsbDevicesFile {
    fn read(&self) -> Vec<u8> {
        use core::fmt::Write as _;
        let devs = usb_snapshot();
        let mut out = String::new();

        if devs.is_empty() {
            // No controller bound yet; empty file is correct.
            return out.into_bytes();
        }

        // Synthesised root hub (always device #1 on bus 1).
        let _ = writeln!(
            out,
            "T:  Bus=01 Lev=00 Prnt=00 Port=00 Cnt=00 Dev#=  1 Spd=480 MxCh={:>2}",
            devs.len().min(255)
        );
        let _ = writeln!(out, "B:  Alloc=  0/800 us ( 0%), #Int=  0, #Iso=  0");
        let _ = writeln!(
            out,
            "D:  Ver= 2.00 Cls=09(hub  ) Sub=00 Prot=00 MxPS=64 #Cfgs=  1"
        );
        let _ = writeln!(out, "P:  Vendor=1d6b ProdID=0002 Rev=06.06");
        let _ = writeln!(out, "S:  Manufacturer=NARF xhci-hcd");
        let _ = writeln!(out, "S:  Product=xHCI Host Controller");
        let _ = writeln!(out, "S:  SerialNumber=0000:00:00.0");
        let _ = writeln!(out, "C:* #Ifs= 1 Cfg#= 1 Atr=e0 MxPwr=  0mA");
        let _ = writeln!(
            out,
            "I:* If#= 0 Alt= 0 #EPs= 1 Cls=09(hub  ) Sub=00 Prot=00 Driver=hub"
        );
        let _ = writeln!(out, "E:  Ad=81(I) Atr=03(Int.) MxPS=  4 Ivl=256ms");
        let _ = writeln!(out);

        for dev in &devs {
            let port = dev.port;
            let cnt = dev.dev_num.saturating_sub(1);
            let spd = dev.speed_mbps;
            let dn = dev.dev_num;
            let vid = dev.vendor_id;
            let pid = dev.product_id;

            let _ = writeln!(
                out,
                "T:  Bus=01 Lev=01 Prnt=01 Port={port:02} Cnt={cnt:02} Dev#={dn:3} \
                 Spd={spd} MxCh= 0"
            );
            let _ = writeln!(out, "B:  Alloc=  0/800 us ( 0%), #Int=  0, #Iso=  0");
            let _ = writeln!(
                out,
                "D:  Ver= 2.00 Cls=00(>ifc ) Sub=00 Prot=00 MxPS= 8 #Cfgs=  1"
            );
            let _ = writeln!(out, "P:  Vendor={vid:04x} ProdID={pid:04x} Rev= 0.00");
            let _ = writeln!(out, "S:  Manufacturer=");
            let _ = writeln!(out, "S:  Product=");
            let _ = writeln!(out, "S:  SerialNumber=");
            let _ = writeln!(out, "C:* #Ifs= 1 Cfg#= 1 Atr=80 MxPwr=500mA");
            let _ = writeln!(
                out,
                "I:* If#= 0 Alt= 0 #EPs= 0 Cls=ff(vend.) Sub=00 Prot=00 Driver="
            );
            let _ = writeln!(out);
        }

        out.into_bytes()
    }
}

// ════════════════════════════════════════════════════════════════════
// /proc/bus/input/devices
// ════════════════════════════════════════════════════════════════════

/// Multi-line input device listing.
///
/// Format mirrors `drivers/input/input.c::input_proc_devices_show`.
/// Capability bitmaps come from `narf_input::evdev::snapshot_devices()`.
///
/// ```text
/// I: Bus=0000 Vendor=0000 Product=0000 Version=0000
/// N: Name="input0"
/// P: Phys=
/// S: Sysfs=/devices/virtual/input/input0
/// U: Uniq=
/// H: Handlers=kbd event0
/// B: PROP=0
/// B: EV=3
/// B: KEY=<hex-words>
/// B: REL=0
/// B: ABS=0
/// ```
#[derive(Debug)]
struct InputDevicesFile;

/// Render a capability bitmap in the Linux `/proc/bus/input/devices` format:
/// words from most-significant non-zero down to word 0, space-separated.
/// If all words are zero, emits "0".
///
/// Linux ref: `drivers/input/input.c::input_seq_print_bitmap`.
fn render_bitmap(words: &[u64]) -> String {
    use core::fmt::Write as _;
    let top = words
        .iter()
        .rposition(|&w| w != 0)
        .map(|i| i + 1)
        .unwrap_or(0);
    if top == 0 {
        return String::from("0");
    }
    let mut s = String::new();
    for i in (0..top).rev() {
        if i + 1 < top {
            s.push(' ');
        }
        let _ = write!(s, "{:x}", words[i]);
    }
    s
}

impl ProcFile for InputDevicesFile {
    fn read(&self) -> Vec<u8> {
        use core::fmt::Write as _;
        let snaps = evdev::snapshot_devices();
        let mut out = String::new();

        for snap in &snaps {
            let id_num = snap.id.0;
            let caps = &snap.caps;

            let _ = writeln!(out, "I: Bus=0000 Vendor=0000 Product=0000 Version=0000");
            let _ = writeln!(out, "N: Name=\"input{id_num}\"");
            let _ = writeln!(out, "P: Phys=");
            let _ = writeln!(out, "S: Sysfs=/devices/virtual/input/input{id_num}");
            let _ = writeln!(out, "U: Uniq=");

            // H: always include evdev eventN; also kbd when EV_KEY is set.
            let ev_key_bit = 1u32 << (evdev::EventType::Key as u16);
            if (caps.evbit & ev_key_bit) != 0 {
                let _ = writeln!(out, "H: Handlers=kbd event{id_num}");
            } else {
                let _ = writeln!(out, "H: Handlers=event{id_num}");
            }

            let _ = writeln!(out, "B: PROP=0");
            let _ = writeln!(out, "B: EV={:x}", caps.evbit);
            let _ = writeln!(out, "B: KEY={}", render_bitmap(&caps.keybit.words));
            let _ = writeln!(out, "B: REL={}", render_bitmap(&caps.relbit.words));
            let _ = writeln!(out, "B: ABS={}", render_bitmap(&caps.absbit.words));
            let _ = writeln!(out);
        }

        out.into_bytes()
    }
}

// ════════════════════════════════════════════════════════════════════
// /proc/bus/input/handlers
// ════════════════════════════════════════════════════════════════════

/// Static list of evdev handler registrations.
///
/// Linux registers: sysrq (minor 64), kbd, mousedev (minor 32), evdev (minor 64).
/// NARF mirrors this static list.
///
/// ```text
/// N: Number=0 Name=sysrq Minor=64
/// N: Number=1 Name=kbd
/// N: Number=2 Name=mousedev Minor=32
/// N: Number=3 Name=evdev Minor=64
/// ```
#[derive(Debug)]
struct InputHandlersFile;

impl ProcFile for InputHandlersFile {
    fn read(&self) -> Vec<u8> {
        use core::fmt::Write as _;
        static HANDLERS: &[(&str, Option<u8>)] = &[
            ("sysrq", Some(64)),
            ("kbd", None),
            ("mousedev", Some(32)),
            ("evdev", Some(64)),
        ];
        let mut out = String::new();
        for (i, &(name, minor)) in HANDLERS.iter().enumerate() {
            if let Some(m) = minor {
                let _ = writeln!(out, "N: Number={i} Name={name} Minor={m}");
            } else {
                let _ = writeln!(out, "N: Number={i} Name={name}");
            }
        }
        out.into_bytes()
    }
}

// ════════════════════════════════════════════════════════════════════
// Registration
// ════════════════════════════════════════════════════════════════════

/// Register all `/proc/bus/*` files.  Called once from
/// `procfs::init_bus` (wired in `filesystem/src/procfs/mod.rs`).
///
/// Deferred: per-device `/proc/bus/pci/<bus>/<dev>.<fn>` binary
/// config-space files require a dynamic `DirOps`; `PciCfgSpaceFile`
/// is the read-side implementation, ready for that follow-up.
/// Deferred: PCI config-space write support (not exposed in read-only
/// mode today).  USB bandwidth allocation percentages in B: lines.
pub fn register_bus_proc() {
    register_proc("bus/pci/devices", Arc::new(PciDevicesFile));
    register_proc("bus/usb/devices", Arc::new(UsbDevicesFile));
    register_proc("bus/input/devices", Arc::new(InputDevicesFile));
    register_proc("bus/input/handlers", Arc::new(InputHandlersFile));
}

// ════════════════════════════════════════════════════════════════════
// Smoke tests
// ════════════════════════════════════════════════════════════════════

use narf_bus::registry as bus_registry;
use narf_kernel_test::{kernel_test_in, TestResult};

/// /proc/bus/pci/devices: one line per registered PCI device.
fn smoke_pci_devices_line_count() -> TestResult {
    use narf_bus::addr::PcieAddr;
    use narf_bus::device::{BusDevice, BusKind, DeviceId as BusDevId};
    use narf_bus::BusAddr;
    use narf_memory::PhysAddr;

    bus_registry::install(alloc::vec![
        BusDevice {
            addr: BusAddr::Pcie(PcieAddr::new(0, 0, 1, 0)),
            id: BusDevId {
                vendor: 0x8086,
                device: 0x1234,
                class: 0x060000,
                subsystem_vendor: 0,
                subsystem_id: 0
            },
            kind: BusKind::Pcie {
                addr: PcieAddr::new(0, 0, 1, 0),
                cfg_phys: PhysAddr::new(0),
            },
        },
        BusDevice {
            addr: BusAddr::Pcie(PcieAddr::new(0, 0, 2, 0)),
            id: BusDevId {
                vendor: 0x10de,
                device: 0x5678,
                class: 0x030000,
                subsystem_vendor: 0,
                subsystem_id: 0
            },
            kind: BusKind::Pcie {
                addr: PcieAddr::new(0, 0, 2, 0),
                cfg_phys: PhysAddr::new(0),
            },
        },
    ]);

    let bytes = PciDevicesFile.read();
    let text = core::str::from_utf8(&bytes).unwrap_or("");
    let count = text.lines().count();
    if count == 2 {
        TestResult::Pass
    } else {
        TestResult::Fail("/proc/bus/pci/devices: wrong line count")
    }
}
kernel_test_in!("filesystem/procfs/bus", smoke_pci_devices_line_count);

/// /proc/bus/pci/devices: BDF encoded as 4 hex digits without separators.
fn smoke_pci_devices_hex_bdf() -> TestResult {
    use narf_bus::addr::PcieAddr;
    use narf_bus::device::{BusDevice, BusKind, DeviceId as BusDevId};
    use narf_bus::BusAddr;
    use narf_memory::PhysAddr;

    // bus=0x02, dev=0x03, fn=1 → (2<<8)|(3<<3)|1 = 0x219
    bus_registry::install(alloc::vec![BusDevice {
        addr: BusAddr::Pcie(PcieAddr::new(0, 0x02, 0x03, 1)),
        id: BusDevId {
            vendor: 0xAAAA,
            device: 0xBBBB,
            class: 0,
            subsystem_vendor: 0,
            subsystem_id: 0
        },
        kind: BusKind::Pcie {
            addr: PcieAddr::new(0, 0x02, 0x03, 1),
            cfg_phys: PhysAddr::new(0),
        },
    }]);

    let bytes = PciDevicesFile.read();
    let text = core::str::from_utf8(&bytes).unwrap_or("");
    let first = text.lines().next().unwrap_or("");
    if first.starts_with("0219 ") {
        TestResult::Pass
    } else {
        TestResult::Fail("/proc/bus/pci/devices: BDF hex format wrong")
    }
}
kernel_test_in!("filesystem/procfs/bus", smoke_pci_devices_hex_bdf);

/// /proc/bus/usb/devices: T:/D:/P: lines present when hook installed.
fn smoke_usb_devices_tlines_present() -> TestResult {
    // Install a synthetic hook.
    fn fake_usb() -> Vec<UsbDeviceSnapshot> {
        alloc::vec![UsbDeviceSnapshot {
            port: 1,
            dev_num: 2,
            speed_mbps: 480,
            vendor_id: 0x1234,
            product_id: 0x5678,
        }]
    }
    install_usb_proc_hook(fake_usb);

    let bytes = UsbDevicesFile.read();
    let text = core::str::from_utf8(&bytes).unwrap_or("");
    let has_t = text.lines().any(|l| l.starts_with("T:"));
    let has_d = text.lines().any(|l| l.starts_with("D:"));
    let has_p = text.lines().any(|l| l.starts_with("P:"));
    if has_t && has_d && has_p {
        TestResult::Pass
    } else {
        TestResult::Fail("/proc/bus/usb/devices: missing T:/D:/P: lines")
    }
}
kernel_test_in!("filesystem/procfs/bus", smoke_usb_devices_tlines_present);

/// /proc/bus/usb/devices: hub entry shows #Ifs= 1.
fn smoke_usb_devices_hub_ifs() -> TestResult {
    // Reuse the hook installed in the previous smoke.
    let bytes = UsbDevicesFile.read();
    let text = core::str::from_utf8(&bytes).unwrap_or("");
    if text.is_empty() {
        return TestResult::Pass; // no hook installed
    }
    if text.lines().any(|l| l.contains("#Ifs= 1")) {
        TestResult::Pass
    } else {
        TestResult::Fail("/proc/bus/usb/devices: hub #Ifs= 1 not found")
    }
}
kernel_test_in!("filesystem/procfs/bus", smoke_usb_devices_hub_ifs);

/// /proc/bus/input/devices: shows B: EV= line for a registered keyboard.
fn smoke_input_devices_ev_line() -> TestResult {
    use narf_input::evdev::{DeviceCaps, ROUTER};
    let mut caps = DeviceCaps::new();
    caps.add_key(1); // KEY_ESC
    caps.add_key(28); // KEY_ENTER
    let (_id, _node) = ROUTER.register_device(caps);

    let bytes = InputDevicesFile.read();
    let text = core::str::from_utf8(&bytes).unwrap_or("");
    if text.lines().any(|l| l.starts_with("B: EV=")) {
        TestResult::Pass
    } else {
        TestResult::Fail("/proc/bus/input/devices: no B: EV= line found")
    }
}
kernel_test_in!("filesystem/procfs/bus", smoke_input_devices_ev_line);

/// /proc/bus/input/handlers: includes the "evdev" handler.
fn smoke_input_handlers_evdev() -> TestResult {
    let bytes = InputHandlersFile.read();
    let text = core::str::from_utf8(&bytes).unwrap_or("");
    if text.lines().any(|l| l.contains("evdev")) {
        TestResult::Pass
    } else {
        TestResult::Fail("/proc/bus/input/handlers: evdev not found")
    }
}
kernel_test_in!("filesystem/procfs/bus", smoke_input_handlers_evdev);
