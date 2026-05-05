//! Subsystem smokes for `narf-firmware-smbios`.

use alloc::vec::Vec;
use narf_kernel_test::{kernel_test_in, TestResult};

use crate::{
    self as smbios, SmbiosAdditionalInfo, SmbiosBaseboard, SmbiosBattery,
    SmbiosBios, SmbiosBiosLanguage, SmbiosBis, SmbiosBootInfo, SmbiosCache,
    SmbiosChassis, SmbiosCoolingDevice, SmbiosCurrentProbe, SmbiosEventLog,
    SmbiosFirmwareInventory, SmbiosGroupAssoc, SmbiosHwSecurity,
    SmbiosIpmiDevice, SmbiosMemoryArrayAddr, SmbiosMemoryChannel,
    SmbiosMemoryDevice, SmbiosMemoryDeviceAddr, SmbiosMemoryError32,
    SmbiosMemoryError64, SmbiosMgmtCtrlHci, SmbiosMgmtDevice,
    SmbiosMgmtDeviceComponent, SmbiosMgmtDeviceThreshold, SmbiosOemStrings,
    SmbiosOnboardExt, SmbiosPhysicalMemoryArray, SmbiosPointingDevice,
    SmbiosPortConnector, SmbiosPowerSupply, SmbiosProcessor,
    SmbiosProcessorAdditional, SmbiosRemoteAccess, SmbiosStringProperty,
    SmbiosSystem, SmbiosSystemConfig, SmbiosSystemPowerControls,
    SmbiosSystemReset, SmbiosSystemSlot, SmbiosTemperatureProbe,
    SmbiosTpmDevice, SmbiosVoltageProbe,
};

fn smoke_smbios_bios_record() -> TestResult {
    let fixed_len: u8 = 18;
    let mut buf: Vec<u8> = Vec::new();
    buf.push(0); buf.push(fixed_len);
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.push(1);                                          // vendor str
    buf.push(2);                                          // version str
    buf.extend_from_slice(&0xE000u16.to_le_bytes());      // start seg
    buf.push(3);                                          // release date str
    buf.push(0x0F);                                       // rom size
    while buf.len() < fixed_len as usize { buf.push(0); }
    buf.extend_from_slice(b"NARFCorp\0");
    buf.extend_from_slice(b"v1.0\0");
    buf.extend_from_slice(b"2026-05-05\0");
    buf.push(0);

    buf.push(127); buf.push(4); buf.extend_from_slice(&0u16.to_le_bytes());
    buf.push(0); buf.push(0);

    let n = smbios::parse_stream(&buf);
    if n < 1 { return TestResult::Fail("expected ≥ 1 SMBIOS structure"); }
    let mut out = [SmbiosBios::ZERO; 2];
    let nb = smbios::copy_bios(&mut out);
    if nb != 1 { return TestResult::Fail("expected 1 BIOS record"); }
    if &out[0].vendor[..8] != b"NARFCorp" {
        return TestResult::Fail("vendor string mismatch");
    }
    if &out[0].version[..4] != b"v1.0" {
        return TestResult::Fail("version string mismatch");
    }
    if &out[0].release_date[..10] != b"2026-05-05" {
        return TestResult::Fail("release date mismatch");
    }
    if out[0].rom_size != 0x0F {
        return TestResult::Fail("rom size mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("firmware/smbios", smoke_smbios_bios_record);

fn smoke_smbios_system_record() -> TestResult {
    let fixed_len: u8 = 25;
    let mut buf: Vec<u8> = Vec::new();
    buf.push(1); buf.push(fixed_len);
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.push(1); buf.push(2); buf.push(3); buf.push(4);
    let uuid: [u8; 16] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                           0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00];
    buf.extend_from_slice(&uuid);
    buf.push(0x06);
    buf.extend_from_slice(b"Acme\0");
    buf.extend_from_slice(b"Frame\0");
    buf.extend_from_slice(b"v0\0");
    buf.extend_from_slice(b"SN-001\0");
    buf.push(0);

    buf.push(127); buf.push(4); buf.extend_from_slice(&0u16.to_le_bytes());
    buf.push(0); buf.push(0);

    smbios::parse_stream(&buf);
    let mut out = [SmbiosSystem::ZERO; 1];
    let n = smbios::copy_system(&mut out);
    if n != 1 { return TestResult::Fail("expected 1 System record"); }
    if &out[0].manufacturer[..4] != b"Acme"
        || &out[0].product_name[..5] != b"Frame"
        || &out[0].version[..2] != b"v0"
        || &out[0].serial_number[..6] != b"SN-001"
        || out[0].uuid != uuid
        || out[0].wake_up_type != 0x06
    {
        return TestResult::Fail("System decode mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("firmware/smbios", smoke_smbios_system_record);

fn smoke_smbios_baseboard_record() -> TestResult {
    let fixed_len: u8 = 9;
    let mut buf: Vec<u8> = Vec::new();
    buf.push(2); buf.push(fixed_len);
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.push(1); buf.push(2); buf.push(3); buf.push(4); buf.push(0);

    buf.extend_from_slice(b"Mfr\0");
    buf.extend_from_slice(b"Prod\0");
    buf.extend_from_slice(b"V\0");
    buf.extend_from_slice(b"Sn\0");
    buf.push(0);

    buf.push(127); buf.push(4); buf.extend_from_slice(&0u16.to_le_bytes());
    buf.push(0); buf.push(0);

    smbios::parse_stream(&buf);
    let mut out = [SmbiosBaseboard::ZERO; 1];
    let n = smbios::copy_baseboard(&mut out);
    if n != 1 || &out[0].manufacturer[..3] != b"Mfr"
        || &out[0].product[..4] != b"Prod"
        || &out[0].version[..1] != b"V"
        || &out[0].serial[..2] != b"Sn"
    {
        return TestResult::Fail("Baseboard decode mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("firmware/smbios", smoke_smbios_baseboard_record);

fn smoke_smbios_processor_record() -> TestResult {
    // SMBIOS 2.6+ Type 4 layout (offsets within entry):
    //   0..1 type, 1..2 length, 2..4 handle,
    //   4    socket-designation string idx
    //   5    processor type
    //   6    family
    //   7    manufacturer string idx
    //   8..16 processor ID
    //   16   version string idx
    //   17   voltage
    //   18..20 external clock
    //   20..22 max speed
    //   22..24 current speed
    //   24   status
    //   25   upgrade
    //   26..28 L1 cache handle
    //   28..30 L2 cache handle
    //   30..32 L3 cache handle
    //   32..35 serial / asset / part string idx
    //   35   core count
    //   36   cores enabled
    //   37   thread count
    let fixed_len: u8 = 38;
    let mut entry: Vec<u8> = Vec::with_capacity(fixed_len as usize);
    entry.push(4); entry.push(fixed_len);
    entry.extend_from_slice(&0u16.to_le_bytes());
    entry.push(1);                                        // socket idx
    entry.push(0x03);                                     // processor type
    entry.push(0xC1);                                     // family
    entry.push(0);                                        // mfr idx
    entry.extend_from_slice(&[0u8; 8]);                   // processor ID
    entry.push(0);                                        // version idx
    entry.push(0);                                        // voltage
    entry.extend_from_slice(&0u16.to_le_bytes());         // external clock
    entry.extend_from_slice(&3000u16.to_le_bytes());      // max speed
    entry.extend_from_slice(&2400u16.to_le_bytes());      // current speed
    entry.push(0x41);                                     // status
    entry.push(0);                                        // upgrade
    entry.extend_from_slice(&0xFFFFu16.to_le_bytes());    // L1
    entry.extend_from_slice(&0xFFFFu16.to_le_bytes());    // L2
    entry.extend_from_slice(&0xFFFFu16.to_le_bytes());    // L3
    entry.push(0);                                        // serial idx
    entry.push(0);                                        // asset idx
    entry.push(0);                                        // part idx
    entry.push(8);                                        // core count
    entry.push(8);                                        // cores enabled
    entry.push(16);                                       // thread count
    debug_assert_eq!(entry.len(), fixed_len as usize);

    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(&entry);
    buf.extend_from_slice(b"CPU0\0");
    buf.push(0);

    buf.push(127); buf.push(4); buf.extend_from_slice(&0u16.to_le_bytes());
    buf.push(0); buf.push(0);

    smbios::parse_stream(&buf);
    let mut out = [SmbiosProcessor::ZERO; 1];
    let n = smbios::copy_processors(&mut out);
    if n != 1 { return TestResult::Fail("expected 1 Processor record"); }
    if &out[0].socket_designation[..4] != b"CPU0"
        || out[0].processor_type != 0x03
        || out[0].family != 0xC1
        || out[0].max_speed_mhz != 3000
        || out[0].current_speed_mhz != 2400
        || out[0].status != 0x41
        || out[0].core_count != 8
        || out[0].thread_count != 16
    {
        return TestResult::Fail("Processor decode mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("firmware/smbios", smoke_smbios_processor_record);

fn smoke_smbios_memory_device() -> TestResult {
    let fixed_len: u8 = 28;
    let mut entry: Vec<u8> = Vec::with_capacity(fixed_len as usize);
    entry.push(17); entry.push(fixed_len);
    entry.extend_from_slice(&0u16.to_le_bytes());
    entry.extend_from_slice(&0u16.to_le_bytes());         // phys array
    entry.extend_from_slice(&0u16.to_le_bytes());         // err info
    entry.extend_from_slice(&64u16.to_le_bytes());        // total width
    entry.extend_from_slice(&64u16.to_le_bytes());        // data width
    entry.extend_from_slice(&8192u16.to_le_bytes());      // size MB
    entry.push(0x09);                                     // form factor
    entry.push(0);                                        // device set
    entry.push(1);                                        // device locator
    entry.push(2);                                        // bank locator
    entry.push(0x18);                                     // memory type
    entry.extend_from_slice(&0u16.to_le_bytes());         // type detail
    entry.extend_from_slice(&3200u16.to_le_bytes());      // speed
    entry.push(3);                                        // mfr
    entry.push(4);                                        // serial
    entry.push(0); entry.push(0); entry.push(0);
    debug_assert_eq!(entry.len(), fixed_len as usize);

    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(&entry);
    buf.extend_from_slice(b"DIMM_A0\0");
    buf.extend_from_slice(b"BANK0\0");
    buf.extend_from_slice(b"NARFRam\0");
    buf.extend_from_slice(b"S/N-77\0");
    buf.push(0);

    buf.push(127); buf.push(4); buf.extend_from_slice(&0u16.to_le_bytes());
    buf.push(0); buf.push(0);

    smbios::parse_stream(&buf);
    let mut out = [SmbiosMemoryDevice::ZERO; 1];
    let n = smbios::copy_memory_devices(&mut out);
    if n != 1 { return TestResult::Fail("expected 1 Memory Device record"); }
    if out[0].size_mb != 8192
        || out[0].form_factor != 0x09
        || &out[0].device_locator[..7] != b"DIMM_A0"
        || &out[0].bank_locator[..5] != b"BANK0"
        || out[0].memory_type != 0x18
        || out[0].speed_mts != 3200
        || &out[0].manufacturer[..7] != b"NARFRam"
        || &out[0].serial_number[..6] != b"S/N-77"
    {
        return TestResult::Fail("Memory Device decode mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("firmware/smbios", smoke_smbios_memory_device);

fn smoke_smbios_skips_unknown() -> TestResult {
    let mut buf: Vec<u8> = Vec::new();
    buf.push(99); buf.push(4); buf.extend_from_slice(&0u16.to_le_bytes());
    buf.push(0); buf.push(0);

    let fixed_len: u8 = 18;
    buf.push(0); buf.push(fixed_len);
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.push(1); buf.push(0);
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.push(0); buf.push(0xAB);
    while buf.len() - 6 < fixed_len as usize { buf.push(0); }
    buf.extend_from_slice(b"V\0");
    buf.push(0);

    buf.push(127); buf.push(4); buf.extend_from_slice(&0u16.to_le_bytes());
    buf.push(0); buf.push(0);

    let n = smbios::parse_stream(&buf);
    if n < 3 { return TestResult::Fail("expected ≥ 3 structures observed"); }
    let mut out = [SmbiosBios::ZERO; 1];
    let nb = smbios::copy_bios(&mut out);
    if nb != 1 || out[0].rom_size != 0xAB {
        return TestResult::Fail("BIOS record after unknown skip");
    }
    TestResult::Pass
}
kernel_test_in!("firmware/smbios", smoke_smbios_skips_unknown);

/// Helper: append a fixed-size structure with no string pool.
fn push_minimal(buf: &mut Vec<u8>, kind: u8, fixed_len: u8) {
    let entry_start = buf.len();
    buf.push(kind);
    buf.push(fixed_len);
    buf.extend_from_slice(&0u16.to_le_bytes());           // handle
    while buf.len() - entry_start < fixed_len as usize {
        buf.push(0);
    }
    buf.push(0); buf.push(0);                             // empty pool
}

fn smoke_smbios_full_dispatch_coverage() -> TestResult {
    // Push one minimal entry of every supported type, then verify
    // the corresponding `is/copy` accessor sees ≥ 1 result.
    let mut buf: Vec<u8> = Vec::new();
    push_minimal(&mut buf, 3,  20);                       // chassis
    push_minimal(&mut buf, 7,  19);                       // cache
    push_minimal(&mut buf, 8,  9);                        // port
    push_minimal(&mut buf, 9,  17);                       // slot
    push_minimal(&mut buf, 11, 5);                        // OEM strings
    push_minimal(&mut buf, 12, 5);                        // sys config
    push_minimal(&mut buf, 13, 22);                       // BIOS language
    push_minimal(&mut buf, 14, 5);                        // group assoc
    push_minimal(&mut buf, 15, 17);                       // event log
    push_minimal(&mut buf, 16, 23);                       // physical mem array
    push_minimal(&mut buf, 18, 23);                       // mem err 32
    push_minimal(&mut buf, 19, 31);                       // mem array addr
    push_minimal(&mut buf, 20, 35);                       // mem device addr
    push_minimal(&mut buf, 21, 7);                        // pointing
    push_minimal(&mut buf, 22, 26);                       // battery
    push_minimal(&mut buf, 23, 13);                       // sys reset
    push_minimal(&mut buf, 24, 5);                        // hw security
    push_minimal(&mut buf, 25, 9);                        // sys power ctrl
    push_minimal(&mut buf, 26, 20);                       // voltage probe
    push_minimal(&mut buf, 27, 15);                       // cooling
    push_minimal(&mut buf, 28, 20);                       // temp probe
    push_minimal(&mut buf, 29, 20);                       // current probe
    push_minimal(&mut buf, 30, 6);                        // remote access
    push_minimal(&mut buf, 31, 18);                       // BIS
    push_minimal(&mut buf, 32, 11);                       // boot info
    push_minimal(&mut buf, 33, 31);                       // mem err 64
    push_minimal(&mut buf, 34, 11);                       // mgmt device
    push_minimal(&mut buf, 35, 11);                       // mgmt device component
    push_minimal(&mut buf, 36, 16);                       // mgmt device threshold
    push_minimal(&mut buf, 37, 7);                        // mem channel
    push_minimal(&mut buf, 38, 18);                       // IPMI
    push_minimal(&mut buf, 39, 22);                       // power supply
    push_minimal(&mut buf, 40, 5);                        // additional info
    push_minimal(&mut buf, 41, 11);                       // onboard ext
    push_minimal(&mut buf, 42, 6);                        // mgmt ctrl HCI
    push_minimal(&mut buf, 43, 32);                       // TPM
    push_minimal(&mut buf, 44, 7);                        // proc addl
    push_minimal(&mut buf, 45, 24);                       // FW inventory
    push_minimal(&mut buf, 46, 9);                        // string property
    push_minimal(&mut buf, 126, 4);                       // inactive
    push_minimal(&mut buf, 127, 4);                       // end-of-table

    smbios::parse_stream(&buf);

    let mut chassis = [SmbiosChassis::ZERO; 1];
    if smbios::copy_chassis(&mut chassis) != 1 { return TestResult::Fail("type 3"); }
    let mut caches = [SmbiosCache::ZERO; 1];
    if smbios::copy_caches(&mut caches) != 1 { return TestResult::Fail("type 7"); }
    let mut ports = [SmbiosPortConnector::ZERO; 1];
    if smbios::copy_port_connectors(&mut ports) != 1 { return TestResult::Fail("type 8"); }
    let mut slots = [SmbiosSystemSlot::ZERO; 1];
    if smbios::copy_system_slots(&mut slots) != 1 { return TestResult::Fail("type 9"); }
    if smbios::oem_strings().is_none() { return TestResult::Fail("type 11"); }
    if smbios::system_config().is_none() { return TestResult::Fail("type 12"); }
    let mut bl = [SmbiosBiosLanguage::ZERO; 1];
    if smbios::copy_bios_language(&mut bl) != 1 { return TestResult::Fail("type 13"); }
    let mut ga = [SmbiosGroupAssoc::ZERO; 1];
    if smbios::copy_group_assoc(&mut ga) != 1 { return TestResult::Fail("type 14"); }
    let mut el = [SmbiosEventLog::ZERO; 1];
    if smbios::copy_event_log(&mut el) != 1 { return TestResult::Fail("type 15"); }
    let mut pma = [SmbiosPhysicalMemoryArray::ZERO; 1];
    if smbios::copy_physical_memory_arrays(&mut pma) != 1 { return TestResult::Fail("type 16"); }
    let mut me32 = [SmbiosMemoryError32::ZERO; 1];
    if smbios::copy_memory_error32(&mut me32) != 1 { return TestResult::Fail("type 18"); }
    let mut maa = [SmbiosMemoryArrayAddr::ZERO; 1];
    if smbios::copy_memory_array_addrs(&mut maa) != 1 { return TestResult::Fail("type 19"); }
    let mut mda = [SmbiosMemoryDeviceAddr::ZERO; 1];
    if smbios::copy_memory_device_addrs(&mut mda) != 1 { return TestResult::Fail("type 20"); }
    let mut pd = [SmbiosPointingDevice::ZERO; 1];
    if smbios::copy_pointing_devices(&mut pd) != 1 { return TestResult::Fail("type 21"); }
    let mut bat = [SmbiosBattery::ZERO; 1];
    if smbios::copy_batteries(&mut bat) != 1 { return TestResult::Fail("type 22"); }
    let mut sr = [SmbiosSystemReset::ZERO; 1];
    if smbios::copy_system_reset(&mut sr) != 1 { return TestResult::Fail("type 23"); }
    if smbios::hw_security().is_none() { return TestResult::Fail("type 24"); }
    if smbios::system_power_controls().is_none() { return TestResult::Fail("type 25"); }
    let mut vp = [SmbiosVoltageProbe::ZERO; 1];
    if smbios::copy_voltage_probes(&mut vp) != 1 { return TestResult::Fail("type 26"); }
    let mut cd = [SmbiosCoolingDevice::ZERO; 1];
    if smbios::copy_cooling_devices(&mut cd) != 1 { return TestResult::Fail("type 27"); }
    let mut tp = [SmbiosTemperatureProbe::ZERO; 1];
    if smbios::copy_temperature_probes(&mut tp) != 1 { return TestResult::Fail("type 28"); }
    let mut cp = [SmbiosCurrentProbe::ZERO; 1];
    if smbios::copy_current_probes(&mut cp) != 1 { return TestResult::Fail("type 29"); }
    if smbios::remote_access().is_none() { return TestResult::Fail("type 30"); }
    if smbios::bis().is_none() { return TestResult::Fail("type 31"); }
    let mut bi = [SmbiosBootInfo::ZERO; 1];
    if smbios::copy_boot_info(&mut bi) != 1 { return TestResult::Fail("type 32"); }
    let mut me64 = [SmbiosMemoryError64::ZERO; 1];
    if smbios::copy_memory_error64(&mut me64) != 1 { return TestResult::Fail("type 33"); }
    let mut md = [SmbiosMgmtDevice::ZERO; 1];
    if smbios::copy_mgmt_devices(&mut md) != 1 { return TestResult::Fail("type 34"); }
    let mut mdc = [SmbiosMgmtDeviceComponent::ZERO; 1];
    if smbios::copy_mgmt_device_components(&mut mdc) != 1 { return TestResult::Fail("type 35"); }
    let mut mdt = [SmbiosMgmtDeviceThreshold::ZERO; 1];
    if smbios::copy_mgmt_device_thresholds(&mut mdt) != 1 { return TestResult::Fail("type 36"); }
    let mut mc = [SmbiosMemoryChannel::ZERO; 1];
    if smbios::copy_memory_channels(&mut mc) != 1 { return TestResult::Fail("type 37"); }
    if smbios::ipmi_device().is_none() { return TestResult::Fail("type 38"); }
    let mut ps = [SmbiosPowerSupply::ZERO; 1];
    if smbios::copy_power_supplies(&mut ps) != 1 { return TestResult::Fail("type 39"); }
    let mut ai = [SmbiosAdditionalInfo::ZERO; 1];
    if smbios::copy_additional_info(&mut ai) != 1 { return TestResult::Fail("type 40"); }
    let mut oe = [SmbiosOnboardExt::ZERO; 1];
    if smbios::copy_onboard_ext(&mut oe) != 1 { return TestResult::Fail("type 41"); }
    if smbios::mgmt_ctrl_hci().is_none() { return TestResult::Fail("type 42"); }
    if smbios::tpm_device().is_none() { return TestResult::Fail("type 43"); }
    let mut pa = [SmbiosProcessorAdditional::ZERO; 1];
    if smbios::copy_processor_additional(&mut pa) != 1 { return TestResult::Fail("type 44"); }
    let mut fw = [SmbiosFirmwareInventory::ZERO; 1];
    if smbios::copy_firmware_inventory(&mut fw) != 1 { return TestResult::Fail("type 45"); }
    let mut sp = [SmbiosStringProperty::ZERO; 1];
    if smbios::copy_string_properties(&mut sp) != 1 { return TestResult::Fail("type 46"); }
    if smbios::inactive_count() != 1 { return TestResult::Fail("type 126"); }
    let _ = (SmbiosOemStrings::ZERO, SmbiosSystemConfig::ZERO,
             SmbiosHwSecurity::ZERO, SmbiosSystemPowerControls::ZERO,
             SmbiosRemoteAccess::ZERO, SmbiosBis::ZERO,
             SmbiosIpmiDevice::ZERO, SmbiosMgmtCtrlHci::ZERO,
             SmbiosTpmDevice::ZERO);
    TestResult::Pass
}
kernel_test_in!("firmware/smbios", smoke_smbios_full_dispatch_coverage);
