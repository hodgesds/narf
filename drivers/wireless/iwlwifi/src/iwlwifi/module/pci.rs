//! The module build's PCI binding (`iwlwifi.ko`).
//!
//! Probe is the built-in `iwlwifi::probe` + `bootstrap` sequence for the Sc
//! profile, over the KABI:
//!
//! 1. `narf_pci_identity`; the driver's own chip table and subsystem
//!    qualification ([`super::super::chip_config_for_pci_id`],
//!    [`super::super::pci_subsystem_claimed`]); only the Sc MAC is claimed.
//! 2. Firmware-owned DMA is retained on teardown from the start.
//! 3. `narf_pci_prepare_probe` parks inherited decode/mastering; BAR0 is
//!    mapped and memory decode enabled with bus mastering off (`mmio::map`).
//! 4. The Sc MAC/RF identity is read from CSR and selects the firmware
//!    ladder ([`super::super::firmware_identity::Sc`]), never installed-file
//!    order. A refused identity refuses the probe.
//! 5. The 1 ms poller and the startup task are spawned; probe returns.
//!
//! The startup task resolves the executable and PNVM through
//! `narf_firmware_open` (retrying while the files are not staged yet, like
//! the built-in `drive_scheduled`), parses the TLVs, re-checks the identity
//! and hands the device to the driver's own transport,
//! [`super::super::runtime::Hardware`]: owned boot DMA, MSI-X, context info
//! and IML, ALIVE, PNVM and PHY configuration. Then the MLD station profile
//! check and the configuration commands ([`super::super::mld_start`]), and the
//! radio is published ([`super::netdev`]).

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use super::super::{
    chip_config_for_pci_id, firmware_identity, mld_start, mmio, parse_ucode, pci_subsystem_claimed,
    runtime::Hardware, rx_rfh::CompletionFormat, ChipConfig, IwlMmioImpl, MacFamily, INTEL_VENDOR,
    PCI_DIDS,
};
use super::firmware_asset::Asset;
use super::kernel::narf_bus::{BusAddr, BusDevice, BusDeviceCap, DeviceId, MmioRegion};
use super::kernel::narf_capabilities::{Cap, Write};
use super::kernel::narf_console::Writer;
use super::kernel::narf_lib::sync::IrqSafeSpinLock;
use super::kernel::narf_time;

/// KABI exports the PCI binding calls.
mod ffi {
    unsafe extern "C" {
        pub fn narf_register_pci_driver(
            name: *const u8,
            len: usize,
            vendor: u16,
            device: u16,
            probe: usize,
        ) -> i32;
        pub fn narf_pci_identity(dev: u64, out: *mut u8, len: usize) -> i32;
        pub fn narf_spawn_poller(dev: u64, callback: usize, cookie: u64) -> i32;
        pub fn narf_dma_retain_on_teardown(dev: u64, retain: u32) -> i32;
        pub fn narf_random_bytes(buf: *mut u8, len: usize) -> i32;
        pub fn narf_firmware_open(
            name: *const u8,
            name_len: usize,
            out_handle: *mut u64,
            out_size: *mut usize,
        ) -> i32;
        pub fn narf_firmware_read(
            handle: u64,
            offset: u64,
            buf: *mut u8,
            len: usize,
            out_read: *mut usize,
        ) -> i32;
        pub fn narf_firmware_close(handle: u64) -> i32;
    }
}

const ENOENT: i32 = -2;
const EIO: i32 = -5;
const EBUSY: i32 = -16;
const ENODEV: i32 = -19;

/// Largest executable or PNVM the transport accepts (the built-in limit).
const FIRMWARE_MAX: usize = 16 * 1024 * 1024;
/// Startup retries while the firmware is not staged yet, and their spacing
/// (the built-in `bootstrap::schedule`: 120 x 500 ms).
const STARTUP_ATTEMPTS: usize = 120;
const STARTUP_RETRY_MS: u64 = 500;

/// One bound function per module: the probe token and every module static
/// (DMA pools, the interrupt owner) belong to it.
static BOUND: IrqSafeSpinLock<bool> = IrqSafeSpinLock::new(false);

fn log(args: core::fmt::Arguments<'_>) {
    let _ = writeln!(Writer, "  iwlwifi.ko: {}", args);
}

/// The PCI device ids `iwlwifi.ko` claims: the built-in table's Sc entries.
pub(crate) fn module_device_ids() -> impl Iterator<Item = u16> {
    PCI_DIDS.iter().map(|&(did, _)| did).filter(|&did| {
        chip_config_for_pci_id(INTEL_VENDOR, did).is_some_and(|chip| chip.mac == MacFamily::ScA0)
    })
}

/// Register the Sc PCI ids; the kernel calls [`probe_c`] for a match.
pub(crate) fn register_pci_driver() {
    const NAME: &[u8] = b"iwlwifi";
    for did in module_device_ids() {
        // SAFETY: `NAME` is 'static and `probe_c` is a valid extern "C" fn; the
        // loader unregisters every match before this image is unmapped.
        let rc = unsafe {
            ffi::narf_register_pci_driver(
                NAME.as_ptr(),
                NAME.len(),
                INTEL_VENDOR,
                did,
                probe_c as usize,
            )
        };
        if rc != 0 {
            log(format_args!(
                "PCI registration of 8086:{did:04x} failed ({rc})"
            ));
        }
    }
}

/// The kernel's DRBG, installed as the entropy source the kernel-free
/// `narf-crypto` draws from.
pub(crate) fn install_entropy() {
    fn kernel_random(out: &mut [u8]) -> bool {
        out.chunks_mut(4096).all(|chunk| {
            // SAFETY: `chunk` names `chunk.len()` (<= 4096) writable bytes.
            unsafe { ffi::narf_random_bytes(chunk.as_mut_ptr(), chunk.len()) == 0 }
        })
    }
    narf_crypto::install_entropy_source(kernel_random);
}

/// The function's identity (`narf_pci_identity`, 16-byte record).
fn identity(dev: u64) -> Option<BusDevice> {
    let mut record = [0u8; 16];
    // SAFETY: `record` names 16 writable bytes.
    if unsafe { ffi::narf_pci_identity(dev, record.as_mut_ptr(), record.len()) } != 0 {
        return None;
    }
    let u16_at = |i: usize| u16::from_le_bytes([record[i], record[i + 1]]);
    let devfn = record[15];
    Some(BusDevice {
        addr: BusAddr {
            segment: u16_at(12),
            bus: record[14],
            slot: devfn >> 3,
            function: devfn & 7,
        },
        id: DeviceId {
            vendor: u16_at(0),
            device: u16_at(2),
            class: u32::from_le_bytes([record[9], record[10], record[11], 0]),
            subsystem_vendor: u16_at(4),
            subsystem_id: u16_at(6),
        },
    })
}

/// The device poller: the executor's heartbeat (every 1 ms).
extern "C" fn poll(_cookie: u64) -> i32 {
    let _ = super::EXEC.run();
    0
}

/// Probe thunk the kernel's PCI match calls (task context, module domain).
extern "C" fn probe_c(dev: u64, _reserved: u64) -> i32 {
    // Every device export after this point takes the bound token: a second
    // function must not replace it.
    if *BOUND.lock() {
        return EBUSY;
    }
    let rc = probe_device(dev);
    if rc != 0 {
        super::set_device(0);
    }
    rc
}

fn probe_device(dev: u64) -> i32 {
    super::set_device(dev);
    let Some(device) = identity(dev) else {
        return ENODEV;
    };
    let Some(chip) = chip_config_for_pci_id(device.id.vendor, device.id.device).filter(|chip| {
        chip.mac == MacFamily::ScA0
            && pci_subsystem_claimed(device.id.device, device.id.subsystem_id)
    }) else {
        return ENODEV;
    };
    // Firmware owns the boot context, rings and buffers from ALIVE on; a
    // teardown that cannot prove the device stopped must not free them.
    // SAFETY: argument-only call on our probe token.
    let _ = unsafe { ffi::narf_dma_retain_on_teardown(dev, 1) };
    let cap = Cap::<BusDeviceCap, Write>::device();
    let region = match mmio::map(&device, &cap) {
        Ok(region) => region,
        Err(reason) => {
            log(format_args!("{}: {reason}", chip.display_name));
            return EIO;
        }
    };
    // Identity-only discovery: memory decode on, bus mastering off.
    let identity = match firmware_identity::Sc::read(&mut IwlMmioImpl::new(region, cap)) {
        Ok(identity) => identity,
        Err(reason) => {
            log(format_args!("{}: {reason}", chip.display_name));
            return ENODEV;
        }
    };
    let ladder = match identity.ladder(&chip) {
        Ok(ladder) => ladder,
        Err(reason) => {
            log(format_args!("{}: {reason}", chip.display_name));
            return ENODEV;
        }
    };
    *BOUND.lock() = true;
    log(format_args!(
        "probed {} ({:04x}:{:04x} subsys {:04x}:{:04x}, MAC={}), firmware {}",
        chip.display_name,
        device.id.vendor,
        device.id.device,
        device.id.subsystem_vendor,
        device.id.subsystem_id,
        chip.mac.prefix(),
        ladder.first().map_or("?", String::as_str),
    ));
    // SAFETY: `poll` is a valid extern "C" fn in this image; the kernel
    // retires the poller before unmapping it.
    if unsafe { ffi::narf_spawn_poller(dev, poll as usize, 0) } != 0 {
        return EIO;
    }
    // The WIFI session first: the regulatory queries need it, and the netif
    // bridge names a netdev `wlan%d` only on a device with a session.
    let Some(session) = super::netdev::open_session() else {
        return EIO;
    };
    let startup = Startup {
        device,
        cap,
        region,
        chip,
        identity,
        ladder,
        session,
    };
    let _ = super::EXEC.spawn(startup.run());
    let _ = super::EXEC.run();
    0
}

/// What probe hands the startup task.
struct Startup {
    device: BusDevice,
    cap: Cap<BusDeviceCap, Write>,
    region: MmioRegion,
    chip: ChipConfig,
    identity: firmware_identity::Sc,
    ladder: Vec<String>,
    /// The device's `WIFI` session.
    session: u64,
}

/// A startup step's failure: retried only before the transport is touched.
enum Failure {
    NotStaged,
    Fatal(&'static str),
}

impl From<&'static str> for Failure {
    fn from(reason: &'static str) -> Self {
        Failure::Fatal(reason)
    }
}

/// The selected executable and its PNVM (`bootstrap::Inputs`).
struct Inputs {
    firmware: Asset,
    pnvm: Option<Asset>,
}

impl Startup {
    async fn run(self) {
        for attempt in 0..STARTUP_ATTEMPTS {
            if attempt > 0 {
                narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(
                    STARTUP_RETRY_MS * 1_000_000,
                ))
                .await;
            }
            match self.start().await {
                Ok(()) => return,
                Err(Failure::NotStaged) => continue,
                Err(Failure::Fatal(reason)) => {
                    log(format_args!(
                        "{} startup failed: {reason}",
                        self.chip.display_name
                    ));
                    return;
                }
            }
        }
        log(format_args!(
            "{}: firmware not staged ({} tried); device left parked",
            self.chip.display_name,
            self.ladder.join(", ")
        ));
    }

    /// `bootstrap::Owner::start` for the Sc profile, then
    /// `device::Device::initialize`'s firmware half and the publication.
    async fn start(&self) -> Result<(), Failure> {
        let input = resolve(&self.ladder)?;
        let mut parsed =
            parse_ucode(&input.firmware.bytes).map_err(|_| "invalid Intel firmware")?;
        if parsed.api.pnvm.is_none() {
            parsed.api.pnvm = input.pnvm.as_ref().map(|asset| asset.bytes.as_slice());
        }
        // Policy absence still permits firmware/receive setup (as built in);
        // station TX and active scan retry the authenticated policy later
        // and fail shut without it.
        let _ = super::regulatory::ensure_snapshot();
        let format = CompletionFormat::for_mac(self.chip.mac)
            .ok_or("unsupported native completion profile")?;
        self.identity
            .check(&mut IwlMmioImpl::new(self.region, self.cap))?;
        let mut hardware = Hardware::new(
            self.device,
            self.cap,
            self.region,
            &parsed,
            format,
            Some(self.identity),
        )?;
        hardware.bind_sources(&input.firmware, input.pnvm.as_ref())?;
        hardware.prepare_station_profile(&parsed)?;
        mld_start::validate_station_profile(&hardware)?;
        let mac = hardware.start(&parsed).await?;
        let nvm = mld_start::configure(&mut hardware, mac).await?;
        log(format_args!(
            "{} firmware up: MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, {} legacy + {} 6 GHz \
             channels, chains tx {:#x} rx {:#x}, HT {} VHT {} HE {} EHT {}",
            self.chip.display_name,
            mac[0],
            mac[1],
            mac[2],
            mac[3],
            mac[4],
            mac[5],
            nvm.channels.len(),
            nvm.six_channels.len(),
            nvm.tx_chains,
            nvm.rx_chains,
            nvm.phy.ht,
            nvm.phy.vht,
            nvm.phy.he,
            nvm.phy.eht,
        ));
        // The PNVM actually booted (embedded or external), as the built-in
        // `Device` retains it for `recover`.
        let pnvm = parsed.api.pnvm.map(<[u8]>::to_vec);
        let firmware = super::netdev::Firmware {
            executable: input.firmware.bytes,
            pnvm,
        };
        super::netdev::publish(self.session, hardware, mac, nvm, firmware);
        Ok(())
    }
}

/// `bootstrap::resolve`: the first staged executable of the ladder and, when
/// its TLVs carry no PNVM, the matching `.pnvm` file.
fn resolve(candidates: &[String]) -> Result<Inputs, Failure> {
    for name in candidates {
        let firmware = match load(name) {
            Ok(bytes) => Asset { bytes },
            Err(ENOENT) => continue,
            Err(_) => {
                return Err(Failure::Fatal(
                    "Intel firmware source authority/extent failed",
                ))
            }
        };
        let parsed = parse_ucode(&firmware.bytes).map_err(|_| "invalid Intel firmware")?;
        let pnvm = if parsed.api.pnvm.is_none() {
            match name.rsplit_once('-') {
                Some((prefix, _)) => match load(&alloc::format!("{prefix}.pnvm")) {
                    Ok(bytes) => Some(Asset { bytes }),
                    Err(ENOENT) => None,
                    Err(_) => {
                        return Err(Failure::Fatal("Intel PNVM source authority/extent failed"))
                    }
                },
                None => None,
            }
        } else {
            None
        };
        return Ok(Inputs { firmware, pnvm });
    }
    Err(Failure::NotStaged)
}

/// The whole firmware file through `narf_firmware_open` / `_read`. `-ENOENT`
/// for a file that is not staged (yet); any other error is terminal.
fn load(name: &str) -> Result<Vec<u8>, i32> {
    /// The KABI reads at most this much per call.
    const CHUNK: usize = 64 * 1024;
    let (mut handle, mut size) = (0u64, 0usize);
    // SAFETY: `name` is a live `&str`; both outputs are live locals.
    let rc = unsafe { ffi::narf_firmware_open(name.as_ptr(), name.len(), &mut handle, &mut size) };
    if rc != 0 {
        return Err(if rc == ENOENT { ENOENT } else { EIO });
    }
    let result = (|| {
        if size == 0 || size > FIRMWARE_MAX {
            return Err(EIO);
        }
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(size).map_err(|_| EIO)?;
        bytes.resize(size, 0);
        let mut at = 0usize;
        while at < size {
            let want = (size - at).min(CHUNK);
            let mut got = 0usize;
            // SAFETY: `bytes[at..at + want]` is writable and in bounds.
            let rc = unsafe {
                ffi::narf_firmware_read(handle, at as u64, bytes[at..].as_mut_ptr(), want, &mut got)
            };
            if rc != 0 || got == 0 {
                return Err(EIO);
            }
            at += got;
        }
        Ok(bytes)
    })();
    // SAFETY: closing our own open handle once.
    let _ = unsafe { ffi::narf_firmware_close(handle) };
    result
}
