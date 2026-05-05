//! SMBIOS / DMI table parser.
//!
//! Spec: `firmware/smbios/specification/spec.md`.
//!
//! The parser consumes a slice spanning the SMBIOS structure
//! stream (everything that follows the entry point's header).
//! Callers pick the obtain-bytes path that matches the platform
//! — QEMU `fw_cfg`'s `etc/smbios/smbios-tables` key, the EFI
//! configuration table, or the legacy 0xF0000–0xFFFFF anchor
//! scan. The output lives in static tables guarded by an
//! `IrqSafeSpinLock` so the parser is callable from any
//! pre-userspace context.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]
#![allow(dead_code)]

extern crate alloc;

use core::sync::atomic::{AtomicBool, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

mod tests;

/// Force-link hook. The crate has no boot-time initcalls of its own
/// (parsing happens on demand from the entry-point discovery code),
/// but `frame/` calls this to keep the linker from dropping the
/// `kernel_test_in!` registrations in `tests.rs`.
pub fn register_initcalls() {}

pub const MAX_BIOS:                 usize = 1;
pub const MAX_SYSTEM:               usize = 1;
pub const MAX_BASEBOARD:            usize = 4;
pub const MAX_CHASSIS:              usize = 4;
pub const MAX_PROCESSORS:           usize = 16;
pub const MAX_CACHES:               usize = 16;
pub const MAX_PORT_CONNECTORS:      usize = 16;
pub const MAX_SYSTEM_SLOTS:         usize = 16;
pub const MAX_PHYSICAL_MEM_ARRAYS:  usize = 4;
pub const MAX_MEMORY_DEVICES:       usize = 16;
pub const MAX_MEM_ERROR_INFO:       usize = 4;
pub const MAX_MEM_ARRAY_ADDRS:      usize = 4;
pub const MAX_MEM_DEVICE_ADDRS:     usize = 16;
pub const MAX_BOOT_INFO:            usize = 1;
pub const MAX_OEM_STRINGS:          usize = 8;
pub const MAX_SYSTEM_CONFIG:        usize = 4;
pub const MAX_BIOS_LANGUAGE:        usize = 1;
pub const MAX_GROUP_ASSOC:          usize = 8;
pub const MAX_EVENT_LOG:            usize = 1;
pub const MAX_POINTING_DEVICES:     usize = 4;
pub const MAX_BATTERIES:            usize = 4;
pub const MAX_SYSTEM_RESET:         usize = 1;
pub const MAX_HW_SECURITY:          usize = 1;
pub const MAX_SYSTEM_POWER_CTRL:    usize = 1;
pub const MAX_VOLTAGE_PROBES:       usize = 8;
pub const MAX_COOLING_DEVICES:      usize = 8;
pub const MAX_TEMPERATURE_PROBES:   usize = 8;
pub const MAX_CURRENT_PROBES:       usize = 8;
pub const MAX_REMOTE_ACCESS:        usize = 1;
pub const MAX_BIS:                  usize = 1;
pub const MAX_MEM_ERR64:            usize = 4;
pub const MAX_MGMT_DEVICES:         usize = 4;
pub const MAX_MGMT_DEVICE_COMP:     usize = 8;
pub const MAX_MGMT_DEVICE_THRESH:   usize = 8;
pub const MAX_MEMORY_CHANNELS:      usize = 4;
pub const MAX_IPMI_DEVICES:         usize = 1;
pub const MAX_POWER_SUPPLIES:       usize = 4;
pub const MAX_ADDITIONAL_INFO:      usize = 4;
pub const MAX_ONBOARD_EXT:          usize = 8;
pub const MAX_MGMT_CTRL_HCI:        usize = 1;
pub const MAX_TPM_DEVICES:          usize = 1;
pub const MAX_PROC_ADDITIONAL:      usize = 16;
pub const MAX_FW_INVENTORY:         usize = 8;
pub const MAX_STRING_PROPERTY:      usize = 8;

#[derive(Copy, Clone, Debug)]
pub struct SmbiosBios {
    pub vendor:       [u8; 64],
    pub version:      [u8; 64],
    pub release_date: [u8; 16],
    pub rom_size:     u8,
}

impl SmbiosBios {
    pub const ZERO: Self = Self {
        vendor: [0; 64], version: [0; 64],
        release_date: [0; 16], rom_size: 0,
    };
}

#[derive(Copy, Clone, Debug)]
pub struct SmbiosSystem {
    pub manufacturer: [u8; 64],
    pub product_name: [u8; 64],
    pub version:      [u8; 64],
    pub serial_number:[u8; 64],
    pub uuid:         [u8; 16],
    pub wake_up_type: u8,
}

impl SmbiosSystem {
    pub const ZERO: Self = Self {
        manufacturer: [0; 64], product_name: [0; 64],
        version: [0; 64], serial_number: [0; 64],
        uuid: [0; 16], wake_up_type: 0,
    };
}

#[derive(Copy, Clone, Debug)]
pub struct SmbiosBaseboard {
    pub manufacturer: [u8; 64],
    pub product:      [u8; 64],
    pub version:      [u8; 64],
    pub serial:       [u8; 64],
}

impl SmbiosBaseboard {
    pub const ZERO: Self = Self {
        manufacturer: [0; 64], product: [0; 64],
        version: [0; 64], serial: [0; 64],
    };
}

#[derive(Copy, Clone, Debug)]
pub struct SmbiosProcessor {
    pub socket_designation: [u8; 32],
    pub processor_type:     u8,
    pub family:             u8,
    pub max_speed_mhz:      u16,
    pub current_speed_mhz:  u16,
    pub status:             u8,
    pub core_count:         u8,
    pub thread_count:       u8,
}

impl SmbiosProcessor {
    pub const ZERO: Self = Self {
        socket_designation: [0; 32],
        processor_type: 0, family: 0,
        max_speed_mhz: 0, current_speed_mhz: 0,
        status: 0, core_count: 0, thread_count: 0,
    };
}

#[derive(Copy, Clone, Debug)]
pub struct SmbiosMemoryDevice {
    pub size_mb:        u32,
    pub form_factor:    u8,
    pub device_locator: [u8; 32],
    pub bank_locator:   [u8; 32],
    pub memory_type:    u8,
    pub speed_mts:      u16,
    pub manufacturer:   [u8; 64],
    pub serial_number:  [u8; 32],
}

impl SmbiosMemoryDevice {
    pub const ZERO: Self = Self {
        size_mb: 0, form_factor: 0,
        device_locator: [0; 32], bank_locator: [0; 32],
        memory_type: 0, speed_mts: 0,
        manufacturer: [0; 64], serial_number: [0; 32],
    };
}

#[derive(Copy, Clone, Debug)]
pub struct SmbiosChassis {
    pub manufacturer: [u8; 64],
    pub chassis_type: u8,             // bit 7 = lock present
    pub version:      [u8; 32],
    pub serial:       [u8; 32],
    pub asset_tag:    [u8; 32],
    pub bootup_state: u8,
    pub power_state:  u8,
    pub thermal_state:u8,
    pub security_state: u8,
    pub oem_defined:  u32,
    pub height_u:     u8,             // height in U
    pub power_cords:  u8,
}

impl SmbiosChassis {
    pub const ZERO: Self = Self {
        manufacturer: [0; 64], chassis_type: 0,
        version: [0; 32], serial: [0; 32], asset_tag: [0; 32],
        bootup_state: 0, power_state: 0,
        thermal_state: 0, security_state: 0,
        oem_defined: 0, height_u: 0, power_cords: 0,
    };
}

#[derive(Copy, Clone, Debug)]
pub struct SmbiosCache {
    pub socket_designation: [u8; 32],
    pub configuration:      u16,      // includes level (bits[2:0] + 1)
    pub max_size_kb:        u32,
    pub installed_size_kb:  u32,
    pub supported_sram:     u16,
    pub current_sram:       u16,
    pub speed_ns:           u8,
    pub error_correction:   u8,
    pub system_cache_type:  u8,
    pub associativity:      u8,
}

impl SmbiosCache {
    pub const ZERO: Self = Self {
        socket_designation: [0; 32],
        configuration: 0, max_size_kb: 0, installed_size_kb: 0,
        supported_sram: 0, current_sram: 0,
        speed_ns: 0, error_correction: 0,
        system_cache_type: 0, associativity: 0,
    };
}

#[derive(Copy, Clone, Debug)]
pub struct SmbiosPortConnector {
    pub internal_designator: [u8; 32],
    pub internal_type:       u8,
    pub external_designator: [u8; 32],
    pub external_type:       u8,
    pub port_type:           u8,
}

impl SmbiosPortConnector {
    pub const ZERO: Self = Self {
        internal_designator: [0; 32], internal_type: 0,
        external_designator: [0; 32], external_type: 0,
        port_type: 0,
    };
}

#[derive(Copy, Clone, Debug)]
pub struct SmbiosSystemSlot {
    pub designation:    [u8; 32],
    pub slot_type:      u8,
    pub data_bus_width: u8,
    pub current_usage:  u8,
    pub slot_length:    u8,
    pub slot_id:        u16,
    pub characteristics_1: u8,
    pub characteristics_2: u8,
    pub segment_group:  u16,
    pub bus:            u8,
    pub dev_func:       u8,
}

impl SmbiosSystemSlot {
    pub const ZERO: Self = Self {
        designation: [0; 32],
        slot_type: 0, data_bus_width: 0, current_usage: 0,
        slot_length: 0, slot_id: 0,
        characteristics_1: 0, characteristics_2: 0,
        segment_group: 0, bus: 0, dev_func: 0,
    };
}

#[derive(Copy, Clone, Debug)]
pub struct SmbiosPhysicalMemoryArray {
    pub location:       u8,
    pub use_:           u8,
    pub error_correction:u8,
    pub max_capacity_kb: u64,         // promoted from the 32-bit field; with extended fold
    pub error_handle:   u16,
    pub num_devices:    u16,
}

impl SmbiosPhysicalMemoryArray {
    pub const ZERO: Self = Self {
        location: 0, use_: 0, error_correction: 0,
        max_capacity_kb: 0, error_handle: 0, num_devices: 0,
    };
}

#[derive(Copy, Clone, Debug)]
pub struct SmbiosMemoryError32 {
    pub error_type:        u8,
    pub error_granularity: u8,
    pub error_operation:   u8,
    pub vendor_syndrome:   u32,
    pub mem_array_addr:    u32,
    pub device_addr:       u32,
    pub resolution:        u32,
}

impl SmbiosMemoryError32 {
    pub const ZERO: Self = Self {
        error_type: 0, error_granularity: 0, error_operation: 0,
        vendor_syndrome: 0,
        mem_array_addr: 0, device_addr: 0, resolution: 0,
    };
}

#[derive(Copy, Clone, Debug)]
pub struct SmbiosMemoryArrayAddr {
    pub starting_addr_kb:  u64,
    pub ending_addr_kb:    u64,
    pub array_handle:      u16,
    pub partition_width:   u8,
}

impl SmbiosMemoryArrayAddr {
    pub const ZERO: Self = Self {
        starting_addr_kb: 0, ending_addr_kb: 0,
        array_handle: 0, partition_width: 0,
    };
}

#[derive(Copy, Clone, Debug)]
pub struct SmbiosMemoryDeviceAddr {
    pub starting_addr_kb:  u64,
    pub ending_addr_kb:    u64,
    pub mem_device_handle: u16,
    pub mem_array_addr_handle: u16,
    pub partition_row_pos: u8,
    pub interleave_pos:    u8,
    pub interleave_data_depth: u8,
}

impl SmbiosMemoryDeviceAddr {
    pub const ZERO: Self = Self {
        starting_addr_kb: 0, ending_addr_kb: 0,
        mem_device_handle: 0, mem_array_addr_handle: 0,
        partition_row_pos: 0, interleave_pos: 0,
        interleave_data_depth: 0,
    };
}

#[derive(Copy, Clone, Debug)]
pub struct SmbiosBootInfo {
    pub status: u8,                   // 0 = no errors detected
}

impl SmbiosBootInfo {
    pub const ZERO: Self = Self { status: 0 };
}

#[derive(Copy, Clone, Debug)]
pub struct SmbiosOemStrings {
    pub count:   u8,
    pub strings: [[u8; 64]; 4],       // first 4 strings, NUL-padded
}

impl SmbiosOemStrings {
    pub const ZERO: Self = Self { count: 0, strings: [[0; 64]; 4] };
}

#[derive(Copy, Clone, Debug)]
pub struct SmbiosSystemConfig {
    pub count:   u8,
    pub strings: [[u8; 64]; 4],
}

impl SmbiosSystemConfig {
    pub const ZERO: Self = Self { count: 0, strings: [[0; 64]; 4] };
}

#[derive(Copy, Clone, Debug)]
pub struct SmbiosBiosLanguage {
    pub installable_count: u8,
    pub flags:             u8,
    pub current:           [u8; 64],
}

impl SmbiosBiosLanguage {
    pub const ZERO: Self = Self {
        installable_count: 0, flags: 0, current: [0; 64],
    };
}

#[derive(Copy, Clone, Debug)]
pub struct SmbiosGroupAssoc {
    pub group_name: [u8; 64],
    pub item_count: u8,               // (Length - 5) / 3
}

impl SmbiosGroupAssoc {
    pub const ZERO: Self = Self { group_name: [0; 64], item_count: 0 };
}

#[derive(Copy, Clone, Debug)]
pub struct SmbiosEventLog {
    pub log_area_length: u16,
    pub header_offset:   u16,
    pub data_offset:     u16,
    pub access_method:   u8,
    pub status:          u8,
    pub change_token:    u32,
}

impl SmbiosEventLog {
    pub const ZERO: Self = Self {
        log_area_length: 0, header_offset: 0, data_offset: 0,
        access_method: 0, status: 0, change_token: 0,
    };
}

#[derive(Copy, Clone, Debug)]
pub struct SmbiosPointingDevice {
    pub kind:               u8,
    pub interface:          u8,
    pub buttons:            u8,
}

impl SmbiosPointingDevice {
    pub const ZERO: Self = Self { kind: 0, interface: 0, buttons: 0 };
}

#[derive(Copy, Clone, Debug)]
pub struct SmbiosBattery {
    pub location:        [u8; 32],
    pub manufacturer:    [u8; 64],
    pub manufacture_date:[u8; 16],
    pub serial:          [u8; 32],
    pub device_name:     [u8; 64],
    pub device_chemistry:u8,
    pub design_capacity_mwh: u32,     // adjusted by Type 22 multiplier
    pub design_voltage_mv:   u16,
}

impl SmbiosBattery {
    pub const ZERO: Self = Self {
        location: [0; 32], manufacturer: [0; 64],
        manufacture_date: [0; 16], serial: [0; 32],
        device_name: [0; 64], device_chemistry: 0,
        design_capacity_mwh: 0, design_voltage_mv: 0,
    };
}

#[derive(Copy, Clone, Debug)]
pub struct SmbiosSystemReset {
    pub capabilities: u8,
    pub reset_count:  u16,
    pub reset_limit:  u16,
    pub timer_interval_min: u16,
    pub timeout_min:        u16,
}

impl SmbiosSystemReset {
    pub const ZERO: Self = Self {
        capabilities: 0, reset_count: 0, reset_limit: 0,
        timer_interval_min: 0, timeout_min: 0,
    };
}

#[derive(Copy, Clone, Debug)]
pub struct SmbiosHwSecurity {
    pub settings: u8,                 // bits[7:6] = power-on, [5:4] = keyboard, [3:2] = admin, [1:0] = front-panel
}

impl SmbiosHwSecurity {
    pub const ZERO: Self = Self { settings: 0 };
}

#[derive(Copy, Clone, Debug)]
pub struct SmbiosSystemPowerControls {
    pub next_scheduled_power_on: [u8; 5],    // BCD month / day / hour / minute / second
}

impl SmbiosSystemPowerControls {
    pub const ZERO: Self = Self { next_scheduled_power_on: [0; 5] };
}

#[derive(Copy, Clone, Debug)]
pub struct SmbiosVoltageProbe {
    pub description:  [u8; 64],
    pub location:     u8,                  // location/status combined byte
    pub max_value:    u16,
    pub min_value:    u16,
    pub resolution:   u16,
    pub tolerance:    u16,
    pub accuracy:     u16,
    pub nominal:      u16,
}

impl SmbiosVoltageProbe {
    pub const ZERO: Self = Self {
        description: [0; 64], location: 0,
        max_value: 0, min_value: 0, resolution: 0,
        tolerance: 0, accuracy: 0, nominal: 0,
    };
}

#[derive(Copy, Clone, Debug)]
pub struct SmbiosCoolingDevice {
    pub temperature_probe_handle: u16,
    pub kind_status:              u8,      // bits[7:5] = type, [4:0] = status
    pub cooling_unit_group:       u8,
    pub nominal_speed_rpm:        u16,
    pub description:              [u8; 64],
}

impl SmbiosCoolingDevice {
    pub const ZERO: Self = Self {
        temperature_probe_handle: 0, kind_status: 0,
        cooling_unit_group: 0, nominal_speed_rpm: 0,
        description: [0; 64],
    };
}

#[derive(Copy, Clone, Debug)]
pub struct SmbiosTemperatureProbe {
    pub description: [u8; 64],
    pub location:    u8,
    pub max_value:   u16,
    pub min_value:   u16,
    pub resolution:  u16,
    pub tolerance:   u16,
    pub accuracy:    u16,
    pub nominal:     u16,
}

impl SmbiosTemperatureProbe {
    pub const ZERO: Self = Self {
        description: [0; 64], location: 0,
        max_value: 0, min_value: 0, resolution: 0,
        tolerance: 0, accuracy: 0, nominal: 0,
    };
}

#[derive(Copy, Clone, Debug)]
pub struct SmbiosCurrentProbe {
    pub description: [u8; 64],
    pub location:    u8,
    pub max_value:   u16,
    pub min_value:   u16,
    pub resolution:  u16,
    pub tolerance:   u16,
    pub accuracy:    u16,
    pub nominal:     u16,
}

impl SmbiosCurrentProbe {
    pub const ZERO: Self = Self {
        description: [0; 64], location: 0,
        max_value: 0, min_value: 0, resolution: 0,
        tolerance: 0, accuracy: 0, nominal: 0,
    };
}

#[derive(Copy, Clone, Debug)]
pub struct SmbiosRemoteAccess {
    pub manufacturer_name: [u8; 64],
    pub connections:       u8,
}
impl SmbiosRemoteAccess {
    pub const ZERO: Self = Self { manufacturer_name: [0; 64], connections: 0 };
}

#[derive(Copy, Clone, Debug)]
pub struct SmbiosBis {
    pub structure_present: bool,
}
impl SmbiosBis {
    pub const ZERO: Self = Self { structure_present: false };
}

#[derive(Copy, Clone, Debug)]
pub struct SmbiosMemoryError64 {
    pub error_type:        u8,
    pub error_granularity: u8,
    pub error_operation:   u8,
    pub vendor_syndrome:   u32,
    pub mem_array_addr:    u64,
    pub device_addr:       u64,
    pub resolution:        u32,
}
impl SmbiosMemoryError64 {
    pub const ZERO: Self = Self {
        error_type: 0, error_granularity: 0, error_operation: 0,
        vendor_syndrome: 0,
        mem_array_addr: 0, device_addr: 0, resolution: 0,
    };
}

#[derive(Copy, Clone, Debug)]
pub struct SmbiosMgmtDevice {
    pub description: [u8; 64],
    pub kind:        u8,
    pub address:     u32,
    pub address_type:u8,
}
impl SmbiosMgmtDevice {
    pub const ZERO: Self = Self {
        description: [0; 64], kind: 0, address: 0, address_type: 0,
    };
}

#[derive(Copy, Clone, Debug)]
pub struct SmbiosMgmtDeviceComponent {
    pub description:        [u8; 64],
    pub mgmt_device_handle: u16,
    pub component_handle:   u16,
    pub threshold_handle:   u16,
}
impl SmbiosMgmtDeviceComponent {
    pub const ZERO: Self = Self {
        description: [0; 64],
        mgmt_device_handle: 0,
        component_handle:   0,
        threshold_handle:   0,
    };
}

#[derive(Copy, Clone, Debug)]
pub struct SmbiosMgmtDeviceThreshold {
    pub lower_non_critical: u16,
    pub upper_non_critical: u16,
    pub lower_critical:     u16,
    pub upper_critical:     u16,
    pub lower_non_recoverable: u16,
    pub upper_non_recoverable: u16,
}
impl SmbiosMgmtDeviceThreshold {
    pub const ZERO: Self = Self {
        lower_non_critical: 0, upper_non_critical: 0,
        lower_critical: 0, upper_critical: 0,
        lower_non_recoverable: 0, upper_non_recoverable: 0,
    };
}

#[derive(Copy, Clone, Debug)]
pub struct SmbiosMemoryChannel {
    pub channel_type:        u8,
    pub max_load:            u8,
    pub memory_device_count: u8,
}
impl SmbiosMemoryChannel {
    pub const ZERO: Self = Self {
        channel_type: 0, max_load: 0, memory_device_count: 0,
    };
}

#[derive(Copy, Clone, Debug)]
pub struct SmbiosIpmiDevice {
    pub interface_type:    u8,
    pub spec_revision:     u8,
    pub i2c_target_addr:   u8,
    pub nv_storage_dev_addr: u8,
    pub base_address:      u64,
    pub base_modifier:     u8,
    pub interrupt_number:  u8,
}
impl SmbiosIpmiDevice {
    pub const ZERO: Self = Self {
        interface_type: 0, spec_revision: 0,
        i2c_target_addr: 0, nv_storage_dev_addr: 0,
        base_address: 0, base_modifier: 0, interrupt_number: 0,
    };
}

#[derive(Copy, Clone, Debug)]
pub struct SmbiosPowerSupply {
    pub power_unit_group:    u8,
    pub location:            [u8; 32],
    pub device_name:         [u8; 64],
    pub manufacturer:        [u8; 64],
    pub serial_number:       [u8; 32],
    pub max_power_capacity_mw: u16,
    pub characteristics:     u16,
}
impl SmbiosPowerSupply {
    pub const ZERO: Self = Self {
        power_unit_group: 0,
        location: [0; 32], device_name: [0; 64],
        manufacturer: [0; 64], serial_number: [0; 32],
        max_power_capacity_mw: 0, characteristics: 0,
    };
}

#[derive(Copy, Clone, Debug)]
pub struct SmbiosAdditionalInfo {
    pub entry_count: u8,
}
impl SmbiosAdditionalInfo {
    pub const ZERO: Self = Self { entry_count: 0 };
}

#[derive(Copy, Clone, Debug)]
pub struct SmbiosOnboardExt {
    pub reference_designation: [u8; 64],
    pub device_type:           u8,
    pub device_type_instance:  u8,
    pub segment_group:         u16,
    pub bus:                   u8,
    pub dev_func:              u8,
}
impl SmbiosOnboardExt {
    pub const ZERO: Self = Self {
        reference_designation: [0; 64],
        device_type: 0, device_type_instance: 0,
        segment_group: 0, bus: 0, dev_func: 0,
    };
}

#[derive(Copy, Clone, Debug)]
pub struct SmbiosMgmtCtrlHci {
    pub interface_type: u8,
    pub data_len:       u8,
}
impl SmbiosMgmtCtrlHci {
    pub const ZERO: Self = Self { interface_type: 0, data_len: 0 };
}

#[derive(Copy, Clone, Debug)]
pub struct SmbiosTpmDevice {
    pub vendor_id:       [u8; 4],
    pub major_spec:      u8,
    pub minor_spec:      u8,
    pub firmware_version_1: u32,
    pub firmware_version_2: u32,
    pub characteristics: u64,
    pub oem_defined:     u32,
}
impl SmbiosTpmDevice {
    pub const ZERO: Self = Self {
        vendor_id: [0; 4], major_spec: 0, minor_spec: 0,
        firmware_version_1: 0, firmware_version_2: 0,
        characteristics: 0, oem_defined: 0,
    };
}

#[derive(Copy, Clone, Debug)]
pub struct SmbiosProcessorAdditional {
    pub referenced_handle: u16,
    pub block_length:      u8,
}
impl SmbiosProcessorAdditional {
    pub const ZERO: Self = Self { referenced_handle: 0, block_length: 0 };
}

#[derive(Copy, Clone, Debug)]
pub struct SmbiosFirmwareInventory {
    pub component_name:      [u8; 64],
    pub version:             [u8; 64],
    pub version_format:      u8,
    pub release_date:        [u8; 32],
    pub manufacturer:        [u8; 64],
    pub state:               u8,
}
impl SmbiosFirmwareInventory {
    pub const ZERO: Self = Self {
        component_name: [0; 64], version: [0; 64],
        version_format: 0, release_date: [0; 32],
        manufacturer: [0; 64], state: 0,
    };
}

#[derive(Copy, Clone, Debug)]
pub struct SmbiosStringProperty {
    pub property_id:       u16,
    pub value:             [u8; 64],
    pub parent_handle:     u16,
}
impl SmbiosStringProperty {
    pub const ZERO: Self = Self {
        property_id: 0, value: [0; 64], parent_handle: 0,
    };
}

struct Tables {
    bios:           [SmbiosBios; MAX_BIOS],
    system:         [SmbiosSystem; MAX_SYSTEM],
    baseboards:     [SmbiosBaseboard; MAX_BASEBOARD],
    chassis:        [SmbiosChassis; MAX_CHASSIS],
    processors:     [SmbiosProcessor; MAX_PROCESSORS],
    caches:         [SmbiosCache; MAX_CACHES],
    port_connectors:[SmbiosPortConnector; MAX_PORT_CONNECTORS],
    system_slots:   [SmbiosSystemSlot; MAX_SYSTEM_SLOTS],
    phys_arrays:    [SmbiosPhysicalMemoryArray; MAX_PHYSICAL_MEM_ARRAYS],
    memory:         [SmbiosMemoryDevice; MAX_MEMORY_DEVICES],
    mem_err32:      [SmbiosMemoryError32; MAX_MEM_ERROR_INFO],
    mem_array_addrs:[SmbiosMemoryArrayAddr; MAX_MEM_ARRAY_ADDRS],
    mem_device_addrs:[SmbiosMemoryDeviceAddr; MAX_MEM_DEVICE_ADDRS],
    boot_info:      [SmbiosBootInfo; MAX_BOOT_INFO],
    oem_strings:    [SmbiosOemStrings; 1],
    sys_config:     [SmbiosSystemConfig; 1],
    bios_lang:      [SmbiosBiosLanguage; MAX_BIOS_LANGUAGE],
    group_assoc:    [SmbiosGroupAssoc; MAX_GROUP_ASSOC],
    event_log:      [SmbiosEventLog; MAX_EVENT_LOG],
    pointing:       [SmbiosPointingDevice; MAX_POINTING_DEVICES],
    batteries:      [SmbiosBattery; MAX_BATTERIES],
    system_reset:   [SmbiosSystemReset; MAX_SYSTEM_RESET],
    hw_security:    [SmbiosHwSecurity; MAX_HW_SECURITY],
    sys_power_ctrl: [SmbiosSystemPowerControls; MAX_SYSTEM_POWER_CTRL],
    voltage_probes: [SmbiosVoltageProbe; MAX_VOLTAGE_PROBES],
    cooling:        [SmbiosCoolingDevice; MAX_COOLING_DEVICES],
    temp_probes:    [SmbiosTemperatureProbe; MAX_TEMPERATURE_PROBES],
    current_probes: [SmbiosCurrentProbe; MAX_CURRENT_PROBES],
    remote_access:  [SmbiosRemoteAccess; MAX_REMOTE_ACCESS],
    bis:            [SmbiosBis; MAX_BIS],
    mem_err64:      [SmbiosMemoryError64; MAX_MEM_ERR64],
    mgmt_devices:   [SmbiosMgmtDevice; MAX_MGMT_DEVICES],
    mgmt_dev_comp:  [SmbiosMgmtDeviceComponent; MAX_MGMT_DEVICE_COMP],
    mgmt_dev_thresh:[SmbiosMgmtDeviceThreshold; MAX_MGMT_DEVICE_THRESH],
    mem_channels:   [SmbiosMemoryChannel; MAX_MEMORY_CHANNELS],
    ipmi:           [SmbiosIpmiDevice; MAX_IPMI_DEVICES],
    power_supplies: [SmbiosPowerSupply; MAX_POWER_SUPPLIES],
    additional:     [SmbiosAdditionalInfo; MAX_ADDITIONAL_INFO],
    onboard_ext:    [SmbiosOnboardExt; MAX_ONBOARD_EXT],
    mgmt_ctrl_hci:  [SmbiosMgmtCtrlHci; MAX_MGMT_CTRL_HCI],
    tpm:            [SmbiosTpmDevice; MAX_TPM_DEVICES],
    proc_addl:      [SmbiosProcessorAdditional; MAX_PROC_ADDITIONAL],
    fw_inventory:   [SmbiosFirmwareInventory; MAX_FW_INVENTORY],
    string_prop:    [SmbiosStringProperty; MAX_STRING_PROPERTY],
    inactive_count: u32,
    n_bios:         usize,
    n_system:       usize,
    n_baseboard:    usize,
    n_chassis:      usize,
    n_processor:    usize,
    n_cache:        usize,
    n_port:         usize,
    n_slot:         usize,
    n_phys_array:   usize,
    n_memory:       usize,
    n_mem_err32:    usize,
    n_mem_array_addr:  usize,
    n_mem_device_addr: usize,
    n_boot_info:    usize,
    n_oem_strings:  usize,
    n_sys_config:   usize,
    n_bios_lang:    usize,
    n_group_assoc:  usize,
    n_event_log:    usize,
    n_pointing:     usize,
    n_batteries:    usize,
    n_system_reset: usize,
    n_hw_security:  usize,
    n_sys_power_ctrl: usize,
    n_voltage:      usize,
    n_cooling:      usize,
    n_temp:         usize,
    n_current:      usize,
    n_remote_access:usize,
    n_bis:          usize,
    n_mem_err64:    usize,
    n_mgmt_devices: usize,
    n_mgmt_dev_comp:usize,
    n_mgmt_dev_thresh: usize,
    n_mem_channels: usize,
    n_ipmi:         usize,
    n_power_supplies: usize,
    n_additional:   usize,
    n_onboard_ext:  usize,
    n_mgmt_ctrl_hci:usize,
    n_tpm:          usize,
    n_proc_addl:    usize,
    n_fw_inventory: usize,
    n_string_prop:  usize,
}

impl Tables {
    const EMPTY: Self = Self {
        bios:           [SmbiosBios::ZERO;             MAX_BIOS],
        system:         [SmbiosSystem::ZERO;           MAX_SYSTEM],
        baseboards:     [SmbiosBaseboard::ZERO;        MAX_BASEBOARD],
        chassis:        [SmbiosChassis::ZERO;          MAX_CHASSIS],
        processors:     [SmbiosProcessor::ZERO;        MAX_PROCESSORS],
        caches:         [SmbiosCache::ZERO;            MAX_CACHES],
        port_connectors:[SmbiosPortConnector::ZERO;    MAX_PORT_CONNECTORS],
        system_slots:   [SmbiosSystemSlot::ZERO;       MAX_SYSTEM_SLOTS],
        phys_arrays:    [SmbiosPhysicalMemoryArray::ZERO; MAX_PHYSICAL_MEM_ARRAYS],
        memory:         [SmbiosMemoryDevice::ZERO;    MAX_MEMORY_DEVICES],
        mem_err32:      [SmbiosMemoryError32::ZERO;   MAX_MEM_ERROR_INFO],
        mem_array_addrs:[SmbiosMemoryArrayAddr::ZERO; MAX_MEM_ARRAY_ADDRS],
        mem_device_addrs:[SmbiosMemoryDeviceAddr::ZERO; MAX_MEM_DEVICE_ADDRS],
        boot_info:      [SmbiosBootInfo::ZERO;        MAX_BOOT_INFO],
        oem_strings:    [SmbiosOemStrings::ZERO;      1],
        sys_config:     [SmbiosSystemConfig::ZERO;    1],
        bios_lang:      [SmbiosBiosLanguage::ZERO;    MAX_BIOS_LANGUAGE],
        group_assoc:    [SmbiosGroupAssoc::ZERO;      MAX_GROUP_ASSOC],
        event_log:      [SmbiosEventLog::ZERO;        MAX_EVENT_LOG],
        pointing:       [SmbiosPointingDevice::ZERO;  MAX_POINTING_DEVICES],
        batteries:      [SmbiosBattery::ZERO;         MAX_BATTERIES],
        system_reset:   [SmbiosSystemReset::ZERO;     MAX_SYSTEM_RESET],
        hw_security:    [SmbiosHwSecurity::ZERO;      MAX_HW_SECURITY],
        sys_power_ctrl: [SmbiosSystemPowerControls::ZERO; MAX_SYSTEM_POWER_CTRL],
        voltage_probes: [SmbiosVoltageProbe::ZERO;    MAX_VOLTAGE_PROBES],
        cooling:        [SmbiosCoolingDevice::ZERO;   MAX_COOLING_DEVICES],
        temp_probes:    [SmbiosTemperatureProbe::ZERO; MAX_TEMPERATURE_PROBES],
        current_probes: [SmbiosCurrentProbe::ZERO;    MAX_CURRENT_PROBES],
        remote_access:  [SmbiosRemoteAccess::ZERO;    MAX_REMOTE_ACCESS],
        bis:            [SmbiosBis::ZERO;             MAX_BIS],
        mem_err64:      [SmbiosMemoryError64::ZERO;   MAX_MEM_ERR64],
        mgmt_devices:   [SmbiosMgmtDevice::ZERO;      MAX_MGMT_DEVICES],
        mgmt_dev_comp:  [SmbiosMgmtDeviceComponent::ZERO; MAX_MGMT_DEVICE_COMP],
        mgmt_dev_thresh:[SmbiosMgmtDeviceThreshold::ZERO; MAX_MGMT_DEVICE_THRESH],
        mem_channels:   [SmbiosMemoryChannel::ZERO;   MAX_MEMORY_CHANNELS],
        ipmi:           [SmbiosIpmiDevice::ZERO;      MAX_IPMI_DEVICES],
        power_supplies: [SmbiosPowerSupply::ZERO;     MAX_POWER_SUPPLIES],
        additional:     [SmbiosAdditionalInfo::ZERO;  MAX_ADDITIONAL_INFO],
        onboard_ext:    [SmbiosOnboardExt::ZERO;      MAX_ONBOARD_EXT],
        mgmt_ctrl_hci:  [SmbiosMgmtCtrlHci::ZERO;     MAX_MGMT_CTRL_HCI],
        tpm:            [SmbiosTpmDevice::ZERO;       MAX_TPM_DEVICES],
        proc_addl:      [SmbiosProcessorAdditional::ZERO; MAX_PROC_ADDITIONAL],
        fw_inventory:   [SmbiosFirmwareInventory::ZERO; MAX_FW_INVENTORY],
        string_prop:    [SmbiosStringProperty::ZERO;  MAX_STRING_PROPERTY],
        inactive_count: 0,
        n_bios:         0,
        n_system:       0,
        n_baseboard:    0,
        n_chassis:      0,
        n_processor:    0,
        n_cache:        0,
        n_port:         0,
        n_slot:         0,
        n_phys_array:   0,
        n_memory:       0,
        n_mem_err32:    0,
        n_mem_array_addr:  0,
        n_mem_device_addr: 0,
        n_boot_info:    0,
        n_oem_strings:  0,
        n_sys_config:   0,
        n_bios_lang:    0,
        n_group_assoc:  0,
        n_event_log:    0,
        n_pointing:     0,
        n_batteries:    0,
        n_system_reset: 0,
        n_hw_security:  0,
        n_sys_power_ctrl: 0,
        n_voltage:      0,
        n_cooling:      0,
        n_temp:         0,
        n_current:      0,
        n_remote_access:0,
        n_bis:          0,
        n_mem_err64:    0,
        n_mgmt_devices: 0,
        n_mgmt_dev_comp:0,
        n_mgmt_dev_thresh: 0,
        n_mem_channels: 0,
        n_ipmi:         0,
        n_power_supplies: 0,
        n_additional:   0,
        n_onboard_ext:  0,
        n_mgmt_ctrl_hci:0,
        n_tpm:          0,
        n_proc_addl:    0,
        n_fw_inventory: 0,
        n_string_prop:  0,
    };
}

static DATA:   IrqSafeSpinLock<Tables> = IrqSafeSpinLock::new(Tables::EMPTY);
static PARSED: AtomicBool = AtomicBool::new(false);

/// Locate the n-th NUL-terminated string in the pool that
/// starts at `pool[0]`. SMBIOS uses 1-based string indices;
/// returns `&[]` for index 0 or when the pool is exhausted.
fn lookup_string(pool: &[u8], idx: u8) -> &[u8] {
    if idx == 0 { return &[]; }
    let mut start = 0usize;
    let mut count = 0u8;
    while start < pool.len() {
        let end = match pool[start..].iter().position(|&b| b == 0) {
            Some(off) => start + off,
            None      => return &[],
        };
        count += 1;
        if count == idx {
            return &pool[start..end];
        }
        start = end + 1;
    }
    &[]
}

fn copy_truncated(dst: &mut [u8], src: &[u8]) {
    let n = src.len().min(dst.len());
    dst[..n].copy_from_slice(&src[..n]);
    for slot in &mut dst[n..] { *slot = 0; }
}

fn pool_end(pool: &[u8]) -> usize {
    // String pool ends at the first double-NUL (or single NUL when
    // the pool has zero strings — in which case the body is just
    // \0\0).
    let mut i = 0;
    while i + 1 < pool.len() {
        if pool[i] == 0 && pool[i + 1] == 0 { return i + 2; }
        i += 1;
    }
    pool.len()
}

fn parse_bios(t: &mut Tables, fmt: &[u8], pool: &[u8]) {
    if fmt.len() < 9 || t.n_bios >= MAX_BIOS { return; }
    let mut rec = SmbiosBios::ZERO;
    copy_truncated(&mut rec.vendor,       lookup_string(pool, fmt[4]));
    copy_truncated(&mut rec.version,      lookup_string(pool, fmt[5]));
    copy_truncated(&mut rec.release_date, lookup_string(pool, fmt[8]));
    rec.rom_size = if fmt.len() > 9 { fmt[9] } else { 0 };
    let i = t.n_bios;
    t.bios[i] = rec;
    t.n_bios = i + 1;
}

fn parse_system(t: &mut Tables, fmt: &[u8], pool: &[u8]) {
    if fmt.len() < 25 || t.n_system >= MAX_SYSTEM { return; }
    let mut rec = SmbiosSystem::ZERO;
    copy_truncated(&mut rec.manufacturer,  lookup_string(pool, fmt[4]));
    copy_truncated(&mut rec.product_name,  lookup_string(pool, fmt[5]));
    copy_truncated(&mut rec.version,       lookup_string(pool, fmt[6]));
    copy_truncated(&mut rec.serial_number, lookup_string(pool, fmt[7]));
    rec.uuid.copy_from_slice(&fmt[8..24]);
    rec.wake_up_type = fmt[24];
    let i = t.n_system;
    t.system[i] = rec;
    t.n_system = i + 1;
}

fn parse_baseboard(t: &mut Tables, fmt: &[u8], pool: &[u8]) {
    if fmt.len() < 9 || t.n_baseboard >= MAX_BASEBOARD { return; }
    let mut rec = SmbiosBaseboard::ZERO;
    copy_truncated(&mut rec.manufacturer, lookup_string(pool, fmt[4]));
    copy_truncated(&mut rec.product,      lookup_string(pool, fmt[5]));
    copy_truncated(&mut rec.version,      lookup_string(pool, fmt[6]));
    copy_truncated(&mut rec.serial,       lookup_string(pool, fmt[7]));
    let i = t.n_baseboard;
    t.baseboards[i] = rec;
    t.n_baseboard = i + 1;
}

fn parse_processor(t: &mut Tables, fmt: &[u8], pool: &[u8]) {
    if fmt.len() < 36 || t.n_processor >= MAX_PROCESSORS { return; }
    let mut rec = SmbiosProcessor::ZERO;
    copy_truncated(&mut rec.socket_designation, lookup_string(pool, fmt[4]));
    rec.processor_type    = fmt[5];
    rec.family            = fmt[6];
    rec.max_speed_mhz     = u16::from_le_bytes([fmt[20], fmt[21]]);
    rec.current_speed_mhz = u16::from_le_bytes([fmt[22], fmt[23]]);
    rec.status            = fmt[24];
    rec.core_count        = if fmt.len() > 35 { fmt[35] } else { 0 };
    rec.thread_count      = if fmt.len() > 37 { fmt[37] } else { 0 };
    let i = t.n_processor;
    t.processors[i] = rec;
    t.n_processor = i + 1;
}

fn parse_memory_device(t: &mut Tables, fmt: &[u8], pool: &[u8]) {
    // Type 17 fixed section is at least 28 bytes for SMBIOS 2.1.
    if fmt.len() < 28 || t.n_memory >= MAX_MEMORY_DEVICES { return; }
    let mut rec = SmbiosMemoryDevice::ZERO;
    let size_raw = u16::from_le_bytes([fmt[12], fmt[13]]);
    rec.size_mb = if size_raw == 0x7FFF && fmt.len() >= 32 {
        // Extended size encoding at fmt[28..32] — value is in MB.
        u32::from_le_bytes([fmt[28], fmt[29], fmt[30], fmt[31]]) & 0x7FFF_FFFF
    } else if size_raw & 0x8000 != 0 {
        // bit 15 set ⇒ KB granularity
        ((size_raw & 0x7FFF) as u32) / 1024
    } else {
        size_raw as u32
    };
    rec.form_factor = fmt[14];
    copy_truncated(&mut rec.device_locator, lookup_string(pool, fmt[16]));
    copy_truncated(&mut rec.bank_locator,   lookup_string(pool, fmt[17]));
    rec.memory_type = fmt[18];
    if fmt.len() >= 23 {
        rec.speed_mts = u16::from_le_bytes([fmt[21], fmt[22]]);
    }
    if fmt.len() >= 24 {
        copy_truncated(&mut rec.manufacturer,
                       lookup_string(pool, fmt[23]));
    }
    if fmt.len() >= 25 {
        copy_truncated(&mut rec.serial_number,
                       lookup_string(pool, fmt[24]));
    }
    let i = t.n_memory;
    t.memory[i] = rec;
    t.n_memory = i + 1;
}

fn parse_chassis(t: &mut Tables, fmt: &[u8], pool: &[u8]) {
    if fmt.len() < 9 || t.n_chassis >= MAX_CHASSIS { return; }
    let mut rec = SmbiosChassis::ZERO;
    copy_truncated(&mut rec.manufacturer, lookup_string(pool, fmt[4]));
    rec.chassis_type = fmt[5];
    copy_truncated(&mut rec.version,     lookup_string(pool, fmt[6]));
    copy_truncated(&mut rec.serial,      lookup_string(pool, fmt[7]));
    copy_truncated(&mut rec.asset_tag,   lookup_string(pool, fmt[8]));
    if fmt.len() > 12 {
        rec.bootup_state    = fmt[9];
        rec.power_state     = fmt[10];
        rec.thermal_state   = fmt[11];
        rec.security_state  = fmt[12];
    }
    if fmt.len() > 16 {
        rec.oem_defined = u32::from_le_bytes([fmt[13], fmt[14], fmt[15], fmt[16]]);
    }
    if fmt.len() > 17 { rec.height_u    = fmt[17]; }
    if fmt.len() > 18 { rec.power_cords = fmt[18]; }
    let i = t.n_chassis;
    t.chassis[i] = rec;
    t.n_chassis = i + 1;
}

fn parse_cache(t: &mut Tables, fmt: &[u8], pool: &[u8]) {
    if fmt.len() < 15 || t.n_cache >= MAX_CACHES { return; }
    let mut rec = SmbiosCache::ZERO;
    copy_truncated(&mut rec.socket_designation, lookup_string(pool, fmt[4]));
    rec.configuration     = u16::from_le_bytes([fmt[5], fmt[6]]);
    rec.max_size_kb       = decode_cache_size(u16::from_le_bytes([fmt[7], fmt[8]])) as u32;
    rec.installed_size_kb = decode_cache_size(u16::from_le_bytes([fmt[9], fmt[10]])) as u32;
    rec.supported_sram    = u16::from_le_bytes([fmt[11], fmt[12]]);
    rec.current_sram      = u16::from_le_bytes([fmt[13], fmt[14]]);
    if fmt.len() > 15 { rec.speed_ns          = fmt[15]; }
    if fmt.len() > 16 { rec.error_correction  = fmt[16]; }
    if fmt.len() > 17 { rec.system_cache_type = fmt[17]; }
    if fmt.len() > 18 { rec.associativity     = fmt[18]; }
    let i = t.n_cache;
    t.caches[i] = rec;
    t.n_cache = i + 1;
}

/// Decode the legacy 16-bit "max cache size" field. Bit 15 set
/// flags 64-KB granularity; otherwise the value is in 1-KB units.
fn decode_cache_size(raw: u16) -> u32 {
    if raw & 0x8000 != 0 {
        ((raw & 0x7FFF) as u32) * 64
    } else {
        raw as u32
    }
}

fn parse_port_connector(t: &mut Tables, fmt: &[u8], pool: &[u8]) {
    if fmt.len() < 9 || t.n_port >= MAX_PORT_CONNECTORS { return; }
    let mut rec = SmbiosPortConnector::ZERO;
    copy_truncated(&mut rec.internal_designator, lookup_string(pool, fmt[4]));
    rec.internal_type = fmt[5];
    copy_truncated(&mut rec.external_designator, lookup_string(pool, fmt[6]));
    rec.external_type = fmt[7];
    rec.port_type = fmt[8];
    let i = t.n_port;
    t.port_connectors[i] = rec;
    t.n_port = i + 1;
}

fn parse_system_slot(t: &mut Tables, fmt: &[u8], pool: &[u8]) {
    if fmt.len() < 13 || t.n_slot >= MAX_SYSTEM_SLOTS { return; }
    let mut rec = SmbiosSystemSlot::ZERO;
    copy_truncated(&mut rec.designation, lookup_string(pool, fmt[4]));
    rec.slot_type      = fmt[5];
    rec.data_bus_width = fmt[6];
    rec.current_usage  = fmt[7];
    rec.slot_length    = fmt[8];
    rec.slot_id        = u16::from_le_bytes([fmt[9], fmt[10]]);
    rec.characteristics_1 = fmt[11];
    rec.characteristics_2 = fmt[12];
    if fmt.len() > 16 {
        rec.segment_group = u16::from_le_bytes([fmt[13], fmt[14]]);
        rec.bus           = fmt[15];
        rec.dev_func      = fmt[16];
    }
    let i = t.n_slot;
    t.system_slots[i] = rec;
    t.n_slot = i + 1;
}

fn parse_physical_memory_array(t: &mut Tables, fmt: &[u8], _pool: &[u8]) {
    if fmt.len() < 15 || t.n_phys_array >= MAX_PHYSICAL_MEM_ARRAYS { return; }
    let mut rec = SmbiosPhysicalMemoryArray::ZERO;
    rec.location          = fmt[4];
    rec.use_              = fmt[5];
    rec.error_correction  = fmt[6];
    let max_capacity_32 = u32::from_le_bytes([fmt[7], fmt[8], fmt[9], fmt[10]]);
    rec.max_capacity_kb = if max_capacity_32 == 0x8000_0000 && fmt.len() >= 23 {
        // Extended Maximum Capacity at 15..23 (bytes for SMBIOS 2.7+).
        u64::from_le_bytes([
            fmt[15], fmt[16], fmt[17], fmt[18],
            fmt[19], fmt[20], fmt[21], fmt[22],
        ]) / 1024
    } else {
        max_capacity_32 as u64
    };
    rec.error_handle = u16::from_le_bytes([fmt[11], fmt[12]]);
    rec.num_devices  = u16::from_le_bytes([fmt[13], fmt[14]]);
    let i = t.n_phys_array;
    t.phys_arrays[i] = rec;
    t.n_phys_array = i + 1;
}

fn parse_memory_error32(t: &mut Tables, fmt: &[u8], _pool: &[u8]) {
    if fmt.len() < 23 || t.n_mem_err32 >= MAX_MEM_ERROR_INFO { return; }
    let mut rec = SmbiosMemoryError32::ZERO;
    rec.error_type        = fmt[4];
    rec.error_granularity = fmt[5];
    rec.error_operation   = fmt[6];
    rec.vendor_syndrome   = u32::from_le_bytes([fmt[7], fmt[8], fmt[9], fmt[10]]);
    rec.mem_array_addr    = u32::from_le_bytes([fmt[11], fmt[12], fmt[13], fmt[14]]);
    rec.device_addr       = u32::from_le_bytes([fmt[15], fmt[16], fmt[17], fmt[18]]);
    rec.resolution        = u32::from_le_bytes([fmt[19], fmt[20], fmt[21], fmt[22]]);
    let i = t.n_mem_err32;
    t.mem_err32[i] = rec;
    t.n_mem_err32 = i + 1;
}

fn parse_mem_array_addr(t: &mut Tables, fmt: &[u8], _pool: &[u8]) {
    if fmt.len() < 15 || t.n_mem_array_addr >= MAX_MEM_ARRAY_ADDRS { return; }
    let mut rec = SmbiosMemoryArrayAddr::ZERO;
    let start_32 = u32::from_le_bytes([fmt[4], fmt[5], fmt[6], fmt[7]]);
    let end_32   = u32::from_le_bytes([fmt[8], fmt[9], fmt[10], fmt[11]]);
    rec.array_handle    = u16::from_le_bytes([fmt[12], fmt[13]]);
    rec.partition_width = fmt[14];
    rec.starting_addr_kb = if start_32 == 0xFFFF_FFFF && fmt.len() >= 31 {
        u64::from_le_bytes([
            fmt[15], fmt[16], fmt[17], fmt[18],
            fmt[19], fmt[20], fmt[21], fmt[22],
        ]) / 1024
    } else {
        start_32 as u64
    };
    rec.ending_addr_kb = if end_32 == 0xFFFF_FFFF && fmt.len() >= 31 {
        u64::from_le_bytes([
            fmt[23], fmt[24], fmt[25], fmt[26],
            fmt[27], fmt[28], fmt[29], fmt[30],
        ]) / 1024
    } else {
        end_32 as u64
    };
    let i = t.n_mem_array_addr;
    t.mem_array_addrs[i] = rec;
    t.n_mem_array_addr = i + 1;
}

fn parse_mem_device_addr(t: &mut Tables, fmt: &[u8], _pool: &[u8]) {
    if fmt.len() < 19 || t.n_mem_device_addr >= MAX_MEM_DEVICE_ADDRS { return; }
    let mut rec = SmbiosMemoryDeviceAddr::ZERO;
    let start_32 = u32::from_le_bytes([fmt[4], fmt[5], fmt[6], fmt[7]]);
    let end_32   = u32::from_le_bytes([fmt[8], fmt[9], fmt[10], fmt[11]]);
    rec.mem_device_handle      = u16::from_le_bytes([fmt[12], fmt[13]]);
    rec.mem_array_addr_handle  = u16::from_le_bytes([fmt[14], fmt[15]]);
    rec.partition_row_pos      = fmt[16];
    rec.interleave_pos         = fmt[17];
    rec.interleave_data_depth  = fmt[18];
    rec.starting_addr_kb = if start_32 == 0xFFFF_FFFF && fmt.len() >= 35 {
        u64::from_le_bytes([
            fmt[19], fmt[20], fmt[21], fmt[22],
            fmt[23], fmt[24], fmt[25], fmt[26],
        ]) / 1024
    } else {
        start_32 as u64
    };
    rec.ending_addr_kb = if end_32 == 0xFFFF_FFFF && fmt.len() >= 35 {
        u64::from_le_bytes([
            fmt[27], fmt[28], fmt[29], fmt[30],
            fmt[31], fmt[32], fmt[33], fmt[34],
        ]) / 1024
    } else {
        end_32 as u64
    };
    let i = t.n_mem_device_addr;
    t.mem_device_addrs[i] = rec;
    t.n_mem_device_addr = i + 1;
}

fn parse_boot_info(t: &mut Tables, fmt: &[u8], _pool: &[u8]) {
    if fmt.len() < 11 || t.n_boot_info >= MAX_BOOT_INFO { return; }
    let mut rec = SmbiosBootInfo::ZERO;
    rec.status = fmt[10];
    let i = t.n_boot_info;
    t.boot_info[i] = rec;
    t.n_boot_info = i + 1;
}

fn parse_oem_strings(t: &mut Tables, fmt: &[u8], pool: &[u8]) {
    if fmt.len() < 5 || t.n_oem_strings >= 1 { return; }
    let mut rec = SmbiosOemStrings::ZERO;
    rec.count = fmt[4];
    for i in 0..rec.count.min(4) {
        copy_truncated(&mut rec.strings[i as usize], lookup_string(pool, i + 1));
    }
    t.oem_strings[0] = rec;
    t.n_oem_strings = 1;
}

fn parse_system_config(t: &mut Tables, fmt: &[u8], pool: &[u8]) {
    if fmt.len() < 5 || t.n_sys_config >= 1 { return; }
    let mut rec = SmbiosSystemConfig::ZERO;
    rec.count = fmt[4];
    for i in 0..rec.count.min(4) {
        copy_truncated(&mut rec.strings[i as usize], lookup_string(pool, i + 1));
    }
    t.sys_config[0] = rec;
    t.n_sys_config = 1;
}

fn parse_bios_language(t: &mut Tables, fmt: &[u8], pool: &[u8]) {
    if fmt.len() < 22 || t.n_bios_lang >= MAX_BIOS_LANGUAGE { return; }
    let mut rec = SmbiosBiosLanguage::ZERO;
    rec.installable_count = fmt[4];
    rec.flags             = fmt[5];
    copy_truncated(&mut rec.current, lookup_string(pool, fmt[21]));
    let i = t.n_bios_lang;
    t.bios_lang[i] = rec;
    t.n_bios_lang = i + 1;
}

fn parse_group_assoc(t: &mut Tables, fmt: &[u8], pool: &[u8]) {
    if fmt.len() < 5 || t.n_group_assoc >= MAX_GROUP_ASSOC { return; }
    let mut rec = SmbiosGroupAssoc::ZERO;
    copy_truncated(&mut rec.group_name, lookup_string(pool, fmt[4]));
    rec.item_count = ((fmt.len() as u8).saturating_sub(5)) / 3;
    let i = t.n_group_assoc;
    t.group_assoc[i] = rec;
    t.n_group_assoc = i + 1;
}

fn parse_event_log(t: &mut Tables, fmt: &[u8], _pool: &[u8]) {
    if fmt.len() < 17 || t.n_event_log >= MAX_EVENT_LOG { return; }
    let mut rec = SmbiosEventLog::ZERO;
    rec.log_area_length = u16::from_le_bytes([fmt[4], fmt[5]]);
    rec.header_offset   = u16::from_le_bytes([fmt[6], fmt[7]]);
    rec.data_offset     = u16::from_le_bytes([fmt[8], fmt[9]]);
    rec.access_method   = fmt[10];
    rec.status          = fmt[11];
    rec.change_token    = u32::from_le_bytes([fmt[12], fmt[13], fmt[14], fmt[15]]);
    let i = t.n_event_log;
    t.event_log[i] = rec;
    t.n_event_log = i + 1;
}

fn parse_pointing_device(t: &mut Tables, fmt: &[u8], _pool: &[u8]) {
    if fmt.len() < 7 || t.n_pointing >= MAX_POINTING_DEVICES { return; }
    let mut rec = SmbiosPointingDevice::ZERO;
    rec.kind      = fmt[4];
    rec.interface = fmt[5];
    rec.buttons   = fmt[6];
    let i = t.n_pointing;
    t.pointing[i] = rec;
    t.n_pointing = i + 1;
}

fn parse_battery(t: &mut Tables, fmt: &[u8], pool: &[u8]) {
    if fmt.len() < 16 || t.n_batteries >= MAX_BATTERIES { return; }
    let mut rec = SmbiosBattery::ZERO;
    copy_truncated(&mut rec.location,         lookup_string(pool, fmt[4]));
    copy_truncated(&mut rec.manufacturer,     lookup_string(pool, fmt[5]));
    copy_truncated(&mut rec.manufacture_date, lookup_string(pool, fmt[6]));
    copy_truncated(&mut rec.serial,           lookup_string(pool, fmt[7]));
    copy_truncated(&mut rec.device_name,      lookup_string(pool, fmt[8]));
    rec.device_chemistry     = fmt[9];
    let raw_capacity = u16::from_le_bytes([fmt[10], fmt[11]]);
    rec.design_voltage_mv    = u16::from_le_bytes([fmt[12], fmt[13]]);
    let multiplier = if fmt.len() > 21 { fmt[21] as u32 } else { 1 };
    rec.design_capacity_mwh  = (raw_capacity as u32) * multiplier;
    let i = t.n_batteries;
    t.batteries[i] = rec;
    t.n_batteries = i + 1;
}

fn parse_system_reset(t: &mut Tables, fmt: &[u8], _pool: &[u8]) {
    if fmt.len() < 13 || t.n_system_reset >= MAX_SYSTEM_RESET { return; }
    let mut rec = SmbiosSystemReset::ZERO;
    rec.capabilities       = fmt[4];
    rec.reset_count        = u16::from_le_bytes([fmt[5], fmt[6]]);
    rec.reset_limit        = u16::from_le_bytes([fmt[7], fmt[8]]);
    rec.timer_interval_min = u16::from_le_bytes([fmt[9], fmt[10]]);
    rec.timeout_min        = u16::from_le_bytes([fmt[11], fmt[12]]);
    let i = t.n_system_reset;
    t.system_reset[i] = rec;
    t.n_system_reset = i + 1;
}

fn parse_hw_security(t: &mut Tables, fmt: &[u8], _pool: &[u8]) {
    if fmt.len() < 5 || t.n_hw_security >= MAX_HW_SECURITY { return; }
    t.hw_security[0] = SmbiosHwSecurity { settings: fmt[4] };
    t.n_hw_security = 1;
}

fn parse_system_power_controls(t: &mut Tables, fmt: &[u8], _pool: &[u8]) {
    if fmt.len() < 9 || t.n_sys_power_ctrl >= MAX_SYSTEM_POWER_CTRL { return; }
    let mut rec = SmbiosSystemPowerControls::ZERO;
    rec.next_scheduled_power_on.copy_from_slice(&fmt[4..9]);
    t.sys_power_ctrl[0] = rec;
    t.n_sys_power_ctrl = 1;
}

fn parse_voltage_probe(t: &mut Tables, fmt: &[u8], pool: &[u8]) {
    if fmt.len() < 20 || t.n_voltage >= MAX_VOLTAGE_PROBES { return; }
    let mut rec = SmbiosVoltageProbe::ZERO;
    copy_truncated(&mut rec.description, lookup_string(pool, fmt[4]));
    rec.location   = fmt[5];
    rec.max_value  = u16::from_le_bytes([fmt[6], fmt[7]]);
    rec.min_value  = u16::from_le_bytes([fmt[8], fmt[9]]);
    rec.resolution = u16::from_le_bytes([fmt[10], fmt[11]]);
    rec.tolerance  = u16::from_le_bytes([fmt[12], fmt[13]]);
    rec.accuracy   = u16::from_le_bytes([fmt[14], fmt[15]]);
    rec.nominal    = u16::from_le_bytes([fmt[18], fmt[19]]);
    let i = t.n_voltage;
    t.voltage_probes[i] = rec;
    t.n_voltage = i + 1;
}

fn parse_cooling_device(t: &mut Tables, fmt: &[u8], pool: &[u8]) {
    if fmt.len() < 12 || t.n_cooling >= MAX_COOLING_DEVICES { return; }
    let mut rec = SmbiosCoolingDevice::ZERO;
    rec.temperature_probe_handle = u16::from_le_bytes([fmt[4], fmt[5]]);
    rec.kind_status              = fmt[6];
    rec.cooling_unit_group       = fmt[7];
    rec.nominal_speed_rpm        = u16::from_le_bytes([fmt[12.min(fmt.len()-1)], fmt[13.min(fmt.len()-1)]]);
    if fmt.len() > 14 {
        copy_truncated(&mut rec.description, lookup_string(pool, fmt[14]));
    }
    let i = t.n_cooling;
    t.cooling[i] = rec;
    t.n_cooling = i + 1;
}

fn parse_temperature_probe(t: &mut Tables, fmt: &[u8], pool: &[u8]) {
    if fmt.len() < 20 || t.n_temp >= MAX_TEMPERATURE_PROBES { return; }
    let mut rec = SmbiosTemperatureProbe::ZERO;
    copy_truncated(&mut rec.description, lookup_string(pool, fmt[4]));
    rec.location   = fmt[5];
    rec.max_value  = u16::from_le_bytes([fmt[6], fmt[7]]);
    rec.min_value  = u16::from_le_bytes([fmt[8], fmt[9]]);
    rec.resolution = u16::from_le_bytes([fmt[10], fmt[11]]);
    rec.tolerance  = u16::from_le_bytes([fmt[12], fmt[13]]);
    rec.accuracy   = u16::from_le_bytes([fmt[14], fmt[15]]);
    rec.nominal    = u16::from_le_bytes([fmt[18], fmt[19]]);
    let i = t.n_temp;
    t.temp_probes[i] = rec;
    t.n_temp = i + 1;
}

fn parse_current_probe(t: &mut Tables, fmt: &[u8], pool: &[u8]) {
    if fmt.len() < 20 || t.n_current >= MAX_CURRENT_PROBES { return; }
    let mut rec = SmbiosCurrentProbe::ZERO;
    copy_truncated(&mut rec.description, lookup_string(pool, fmt[4]));
    rec.location   = fmt[5];
    rec.max_value  = u16::from_le_bytes([fmt[6], fmt[7]]);
    rec.min_value  = u16::from_le_bytes([fmt[8], fmt[9]]);
    rec.resolution = u16::from_le_bytes([fmt[10], fmt[11]]);
    rec.tolerance  = u16::from_le_bytes([fmt[12], fmt[13]]);
    rec.accuracy   = u16::from_le_bytes([fmt[14], fmt[15]]);
    rec.nominal    = u16::from_le_bytes([fmt[18], fmt[19]]);
    let i = t.n_current;
    t.current_probes[i] = rec;
    t.n_current = i + 1;
}

fn parse_remote_access(t: &mut Tables, fmt: &[u8], pool: &[u8]) {
    if fmt.len() < 6 || t.n_remote_access >= MAX_REMOTE_ACCESS { return; }
    let mut rec = SmbiosRemoteAccess::ZERO;
    copy_truncated(&mut rec.manufacturer_name, lookup_string(pool, fmt[4]));
    rec.connections = fmt[5];
    t.remote_access[0] = rec;
    t.n_remote_access = 1;
}

fn parse_bis(t: &mut Tables, _fmt: &[u8], _pool: &[u8]) {
    if t.n_bis >= MAX_BIS { return; }
    t.bis[0] = SmbiosBis { structure_present: true };
    t.n_bis = 1;
}

fn parse_memory_error64(t: &mut Tables, fmt: &[u8], _pool: &[u8]) {
    if fmt.len() < 31 || t.n_mem_err64 >= MAX_MEM_ERR64 { return; }
    let mut rec = SmbiosMemoryError64::ZERO;
    rec.error_type        = fmt[4];
    rec.error_granularity = fmt[5];
    rec.error_operation   = fmt[6];
    rec.vendor_syndrome   = u32::from_le_bytes([fmt[7], fmt[8], fmt[9], fmt[10]]);
    rec.mem_array_addr = u64::from_le_bytes([
        fmt[11], fmt[12], fmt[13], fmt[14],
        fmt[15], fmt[16], fmt[17], fmt[18],
    ]);
    rec.device_addr = u64::from_le_bytes([
        fmt[19], fmt[20], fmt[21], fmt[22],
        fmt[23], fmt[24], fmt[25], fmt[26],
    ]);
    rec.resolution = u32::from_le_bytes([fmt[27], fmt[28], fmt[29], fmt[30]]);
    let i = t.n_mem_err64;
    t.mem_err64[i] = rec;
    t.n_mem_err64 = i + 1;
}

fn parse_mgmt_device(t: &mut Tables, fmt: &[u8], pool: &[u8]) {
    if fmt.len() < 11 || t.n_mgmt_devices >= MAX_MGMT_DEVICES { return; }
    let mut rec = SmbiosMgmtDevice::ZERO;
    copy_truncated(&mut rec.description, lookup_string(pool, fmt[4]));
    rec.kind         = fmt[5];
    rec.address      = u32::from_le_bytes([fmt[6], fmt[7], fmt[8], fmt[9]]);
    rec.address_type = fmt[10];
    let i = t.n_mgmt_devices;
    t.mgmt_devices[i] = rec;
    t.n_mgmt_devices = i + 1;
}

fn parse_mgmt_device_component(t: &mut Tables, fmt: &[u8], pool: &[u8]) {
    if fmt.len() < 11 || t.n_mgmt_dev_comp >= MAX_MGMT_DEVICE_COMP { return; }
    let mut rec = SmbiosMgmtDeviceComponent::ZERO;
    copy_truncated(&mut rec.description, lookup_string(pool, fmt[4]));
    rec.mgmt_device_handle = u16::from_le_bytes([fmt[5], fmt[6]]);
    rec.component_handle   = u16::from_le_bytes([fmt[7], fmt[8]]);
    rec.threshold_handle   = u16::from_le_bytes([fmt[9], fmt[10]]);
    let i = t.n_mgmt_dev_comp;
    t.mgmt_dev_comp[i] = rec;
    t.n_mgmt_dev_comp = i + 1;
}

fn parse_mgmt_device_threshold(t: &mut Tables, fmt: &[u8], _pool: &[u8]) {
    if fmt.len() < 16 || t.n_mgmt_dev_thresh >= MAX_MGMT_DEVICE_THRESH { return; }
    let rec = SmbiosMgmtDeviceThreshold {
        lower_non_critical:    u16::from_le_bytes([fmt[4],  fmt[5]]),
        upper_non_critical:    u16::from_le_bytes([fmt[6],  fmt[7]]),
        lower_critical:        u16::from_le_bytes([fmt[8],  fmt[9]]),
        upper_critical:        u16::from_le_bytes([fmt[10], fmt[11]]),
        lower_non_recoverable: u16::from_le_bytes([fmt[12], fmt[13]]),
        upper_non_recoverable: u16::from_le_bytes([fmt[14], fmt[15]]),
    };
    let i = t.n_mgmt_dev_thresh;
    t.mgmt_dev_thresh[i] = rec;
    t.n_mgmt_dev_thresh = i + 1;
}

fn parse_memory_channel(t: &mut Tables, fmt: &[u8], _pool: &[u8]) {
    if fmt.len() < 7 || t.n_mem_channels >= MAX_MEMORY_CHANNELS { return; }
    let rec = SmbiosMemoryChannel {
        channel_type:        fmt[4],
        max_load:            fmt[5],
        memory_device_count: fmt[6],
    };
    let i = t.n_mem_channels;
    t.mem_channels[i] = rec;
    t.n_mem_channels = i + 1;
}

fn parse_ipmi(t: &mut Tables, fmt: &[u8], _pool: &[u8]) {
    if fmt.len() < 16 || t.n_ipmi >= MAX_IPMI_DEVICES { return; }
    let mut rec = SmbiosIpmiDevice::ZERO;
    rec.interface_type      = fmt[4];
    rec.spec_revision       = fmt[5];
    rec.i2c_target_addr     = fmt[6];
    rec.nv_storage_dev_addr = fmt[7];
    rec.base_address = u64::from_le_bytes([
        fmt[8], fmt[9], fmt[10], fmt[11],
        fmt[12], fmt[13], fmt[14], fmt[15],
    ]);
    if fmt.len() > 17 {
        rec.base_modifier    = fmt[16];
        rec.interrupt_number = fmt[17];
    }
    t.ipmi[0] = rec;
    t.n_ipmi = 1;
}

fn parse_power_supply(t: &mut Tables, fmt: &[u8], pool: &[u8]) {
    if fmt.len() < 16 || t.n_power_supplies >= MAX_POWER_SUPPLIES { return; }
    let mut rec = SmbiosPowerSupply::ZERO;
    rec.power_unit_group = fmt[4];
    copy_truncated(&mut rec.location,        lookup_string(pool, fmt[5]));
    copy_truncated(&mut rec.device_name,     lookup_string(pool, fmt[6]));
    copy_truncated(&mut rec.manufacturer,    lookup_string(pool, fmt[7]));
    copy_truncated(&mut rec.serial_number,   lookup_string(pool, fmt[8]));
    rec.max_power_capacity_mw = u16::from_le_bytes([fmt[12], fmt[13]]);
    rec.characteristics       = u16::from_le_bytes([fmt[14], fmt[15]]);
    let i = t.n_power_supplies;
    t.power_supplies[i] = rec;
    t.n_power_supplies = i + 1;
}

fn parse_additional_info(t: &mut Tables, fmt: &[u8], _pool: &[u8]) {
    if fmt.len() < 5 || t.n_additional >= MAX_ADDITIONAL_INFO { return; }
    let i = t.n_additional;
    t.additional[i] = SmbiosAdditionalInfo { entry_count: fmt[4] };
    t.n_additional = i + 1;
}

fn parse_onboard_ext(t: &mut Tables, fmt: &[u8], pool: &[u8]) {
    if fmt.len() < 11 || t.n_onboard_ext >= MAX_ONBOARD_EXT { return; }
    let mut rec = SmbiosOnboardExt::ZERO;
    copy_truncated(&mut rec.reference_designation, lookup_string(pool, fmt[4]));
    rec.device_type           = fmt[5];
    rec.device_type_instance  = fmt[6];
    rec.segment_group         = u16::from_le_bytes([fmt[7], fmt[8]]);
    rec.bus                   = fmt[9];
    rec.dev_func              = fmt[10];
    let i = t.n_onboard_ext;
    t.onboard_ext[i] = rec;
    t.n_onboard_ext = i + 1;
}

fn parse_mgmt_ctrl_hci(t: &mut Tables, fmt: &[u8], _pool: &[u8]) {
    if fmt.len() < 6 || t.n_mgmt_ctrl_hci >= MAX_MGMT_CTRL_HCI { return; }
    t.mgmt_ctrl_hci[0] = SmbiosMgmtCtrlHci {
        interface_type: fmt[4],
        data_len:       fmt[5],
    };
    t.n_mgmt_ctrl_hci = 1;
}

fn parse_tpm_device(t: &mut Tables, fmt: &[u8], _pool: &[u8]) {
    if fmt.len() < 32 || t.n_tpm >= MAX_TPM_DEVICES { return; }
    let mut rec = SmbiosTpmDevice::ZERO;
    rec.vendor_id.copy_from_slice(&fmt[4..8]);
    rec.major_spec = fmt[8];
    rec.minor_spec = fmt[9];
    rec.firmware_version_1 = u32::from_le_bytes([fmt[10], fmt[11], fmt[12], fmt[13]]);
    rec.firmware_version_2 = u32::from_le_bytes([fmt[14], fmt[15], fmt[16], fmt[17]]);
    // Description string @ fmt[18] — skipped; characteristics @ fmt[19..27].
    rec.characteristics = u64::from_le_bytes([
        fmt[19], fmt[20], fmt[21], fmt[22],
        fmt[23], fmt[24], fmt[25], fmt[26],
    ]);
    rec.oem_defined = u32::from_le_bytes([fmt[27], fmt[28], fmt[29], fmt[30]]);
    t.tpm[0] = rec;
    t.n_tpm = 1;
}

fn parse_proc_additional(t: &mut Tables, fmt: &[u8], _pool: &[u8]) {
    if fmt.len() < 7 || t.n_proc_addl >= MAX_PROC_ADDITIONAL { return; }
    let i = t.n_proc_addl;
    t.proc_addl[i] = SmbiosProcessorAdditional {
        referenced_handle: u16::from_le_bytes([fmt[4], fmt[5]]),
        block_length:      fmt[6],
    };
    t.n_proc_addl = i + 1;
}

fn parse_fw_inventory(t: &mut Tables, fmt: &[u8], pool: &[u8]) {
    if fmt.len() < 24 || t.n_fw_inventory >= MAX_FW_INVENTORY { return; }
    let mut rec = SmbiosFirmwareInventory::ZERO;
    copy_truncated(&mut rec.component_name, lookup_string(pool, fmt[4]));
    copy_truncated(&mut rec.version,        lookup_string(pool, fmt[5]));
    rec.version_format = fmt[6];
    // ID-string idx, ID format byte, release-date string, manufacturer string, ...
    if fmt.len() > 9 {
        copy_truncated(&mut rec.release_date,  lookup_string(pool, fmt[9]));
    }
    if fmt.len() > 10 {
        copy_truncated(&mut rec.manufacturer,  lookup_string(pool, fmt[10]));
    }
    if fmt.len() > 13 { rec.state = fmt[13]; }
    let i = t.n_fw_inventory;
    t.fw_inventory[i] = rec;
    t.n_fw_inventory = i + 1;
}

fn parse_string_property(t: &mut Tables, fmt: &[u8], pool: &[u8]) {
    if fmt.len() < 9 || t.n_string_prop >= MAX_STRING_PROPERTY { return; }
    let mut rec = SmbiosStringProperty::ZERO;
    rec.property_id   = u16::from_le_bytes([fmt[4], fmt[5]]);
    copy_truncated(&mut rec.value, lookup_string(pool, fmt[6]));
    rec.parent_handle = u16::from_le_bytes([fmt[7], fmt[8]]);
    let i = t.n_string_prop;
    t.string_prop[i] = rec;
    t.n_string_prop = i + 1;
}

/// Parse a structure-stream slice. Returns the number of
/// structures observed (recognised + skipped).
pub fn parse_stream(bytes: &[u8]) -> u32 {
    let mut tables = DATA.lock();
    *tables = Tables::EMPTY;

    let mut cur = 0usize;
    let mut count = 0u32;
    while cur + 4 <= bytes.len() {
        let kind = bytes[cur];
        let len = bytes[cur + 1] as usize;
        // Type 127 is the end-of-table marker.
        if kind == 127 { count += 1; break; }
        if len < 4 || cur + len > bytes.len() { break; }
        let fmt  = &bytes[cur..cur + len];
        let pool = &bytes[cur + len..];
        let pool_len = pool_end(pool);

        match kind {
            0  => parse_bios(&mut tables, fmt, pool),
            1  => parse_system(&mut tables, fmt, pool),
            2  => parse_baseboard(&mut tables, fmt, pool),
            3  => parse_chassis(&mut tables, fmt, pool),
            4  => parse_processor(&mut tables, fmt, pool),
            7  => parse_cache(&mut tables, fmt, pool),
            8  => parse_port_connector(&mut tables, fmt, pool),
            9  => parse_system_slot(&mut tables, fmt, pool),
            16 => parse_physical_memory_array(&mut tables, fmt, pool),
            17 => parse_memory_device(&mut tables, fmt, pool),
            18 => parse_memory_error32(&mut tables, fmt, pool),
            19 => parse_mem_array_addr(&mut tables, fmt, pool),
            20 => parse_mem_device_addr(&mut tables, fmt, pool),
            11 => parse_oem_strings(&mut tables, fmt, pool),
            12 => parse_system_config(&mut tables, fmt, pool),
            13 => parse_bios_language(&mut tables, fmt, pool),
            14 => parse_group_assoc(&mut tables, fmt, pool),
            15 => parse_event_log(&mut tables, fmt, pool),
            21 => parse_pointing_device(&mut tables, fmt, pool),
            22 => parse_battery(&mut tables, fmt, pool),
            23 => parse_system_reset(&mut tables, fmt, pool),
            24 => parse_hw_security(&mut tables, fmt, pool),
            25 => parse_system_power_controls(&mut tables, fmt, pool),
            26 => parse_voltage_probe(&mut tables, fmt, pool),
            27 => parse_cooling_device(&mut tables, fmt, pool),
            28 => parse_temperature_probe(&mut tables, fmt, pool),
            29 => parse_current_probe(&mut tables, fmt, pool),
            30 => parse_remote_access(&mut tables, fmt, pool),
            31 => parse_bis(&mut tables, fmt, pool),
            32 => parse_boot_info(&mut tables, fmt, pool),
            33 => parse_memory_error64(&mut tables, fmt, pool),
            34 => parse_mgmt_device(&mut tables, fmt, pool),
            35 => parse_mgmt_device_component(&mut tables, fmt, pool),
            36 => parse_mgmt_device_threshold(&mut tables, fmt, pool),
            37 => parse_memory_channel(&mut tables, fmt, pool),
            38 => parse_ipmi(&mut tables, fmt, pool),
            39 => parse_power_supply(&mut tables, fmt, pool),
            40 => parse_additional_info(&mut tables, fmt, pool),
            41 => parse_onboard_ext(&mut tables, fmt, pool),
            42 => parse_mgmt_ctrl_hci(&mut tables, fmt, pool),
            43 => parse_tpm_device(&mut tables, fmt, pool),
            44 => parse_proc_additional(&mut tables, fmt, pool),
            45 => parse_fw_inventory(&mut tables, fmt, pool),
            46 => parse_string_property(&mut tables, fmt, pool),
            126 => tables.inactive_count += 1,
            // 5/6/10 are deprecated; observed but not decoded.
            5 | 6 | 10 => {}
            _  => {}
        }

        cur += len + pool_len;
        count += 1;
        if count > 1024 { break; }   // sanity cap
    }
    drop(tables);
    PARSED.store(true, Ordering::Release);
    count
}

pub fn is_known() -> bool { PARSED.load(Ordering::Acquire) }

pub fn copy_bios(out: &mut [SmbiosBios]) -> usize {
    let t = DATA.lock();
    let n = t.n_bios.min(out.len());
    out[..n].copy_from_slice(&t.bios[..n]);
    n
}

pub fn copy_system(out: &mut [SmbiosSystem]) -> usize {
    let t = DATA.lock();
    let n = t.n_system.min(out.len());
    out[..n].copy_from_slice(&t.system[..n]);
    n
}

pub fn copy_baseboard(out: &mut [SmbiosBaseboard]) -> usize {
    let t = DATA.lock();
    let n = t.n_baseboard.min(out.len());
    out[..n].copy_from_slice(&t.baseboards[..n]);
    n
}

pub fn copy_processors(out: &mut [SmbiosProcessor]) -> usize {
    let t = DATA.lock();
    let n = t.n_processor.min(out.len());
    out[..n].copy_from_slice(&t.processors[..n]);
    n
}

pub fn copy_memory_devices(out: &mut [SmbiosMemoryDevice]) -> usize {
    let t = DATA.lock();
    let n = t.n_memory.min(out.len());
    out[..n].copy_from_slice(&t.memory[..n]);
    n
}

pub fn copy_chassis(out: &mut [SmbiosChassis]) -> usize {
    let t = DATA.lock();
    let n = t.n_chassis.min(out.len());
    out[..n].copy_from_slice(&t.chassis[..n]);
    n
}

pub fn copy_caches(out: &mut [SmbiosCache]) -> usize {
    let t = DATA.lock();
    let n = t.n_cache.min(out.len());
    out[..n].copy_from_slice(&t.caches[..n]);
    n
}

pub fn copy_port_connectors(out: &mut [SmbiosPortConnector]) -> usize {
    let t = DATA.lock();
    let n = t.n_port.min(out.len());
    out[..n].copy_from_slice(&t.port_connectors[..n]);
    n
}

pub fn copy_system_slots(out: &mut [SmbiosSystemSlot]) -> usize {
    let t = DATA.lock();
    let n = t.n_slot.min(out.len());
    out[..n].copy_from_slice(&t.system_slots[..n]);
    n
}

pub fn copy_physical_memory_arrays(out: &mut [SmbiosPhysicalMemoryArray]) -> usize {
    let t = DATA.lock();
    let n = t.n_phys_array.min(out.len());
    out[..n].copy_from_slice(&t.phys_arrays[..n]);
    n
}

pub fn copy_memory_error32(out: &mut [SmbiosMemoryError32]) -> usize {
    let t = DATA.lock();
    let n = t.n_mem_err32.min(out.len());
    out[..n].copy_from_slice(&t.mem_err32[..n]);
    n
}

pub fn copy_memory_array_addrs(out: &mut [SmbiosMemoryArrayAddr]) -> usize {
    let t = DATA.lock();
    let n = t.n_mem_array_addr.min(out.len());
    out[..n].copy_from_slice(&t.mem_array_addrs[..n]);
    n
}

pub fn copy_memory_device_addrs(out: &mut [SmbiosMemoryDeviceAddr]) -> usize {
    let t = DATA.lock();
    let n = t.n_mem_device_addr.min(out.len());
    out[..n].copy_from_slice(&t.mem_device_addrs[..n]);
    n
}

pub fn copy_boot_info(out: &mut [SmbiosBootInfo]) -> usize {
    let t = DATA.lock();
    let n = t.n_boot_info.min(out.len());
    out[..n].copy_from_slice(&t.boot_info[..n]);
    n
}

pub fn oem_strings() -> Option<SmbiosOemStrings> {
    let t = DATA.lock();
    if t.n_oem_strings == 0 { None } else { Some(t.oem_strings[0]) }
}

pub fn system_config() -> Option<SmbiosSystemConfig> {
    let t = DATA.lock();
    if t.n_sys_config == 0 { None } else { Some(t.sys_config[0]) }
}

pub fn copy_bios_language(out: &mut [SmbiosBiosLanguage]) -> usize {
    let t = DATA.lock();
    let n = t.n_bios_lang.min(out.len());
    out[..n].copy_from_slice(&t.bios_lang[..n]);
    n
}

pub fn copy_group_assoc(out: &mut [SmbiosGroupAssoc]) -> usize {
    let t = DATA.lock();
    let n = t.n_group_assoc.min(out.len());
    out[..n].copy_from_slice(&t.group_assoc[..n]);
    n
}

pub fn copy_event_log(out: &mut [SmbiosEventLog]) -> usize {
    let t = DATA.lock();
    let n = t.n_event_log.min(out.len());
    out[..n].copy_from_slice(&t.event_log[..n]);
    n
}

pub fn copy_pointing_devices(out: &mut [SmbiosPointingDevice]) -> usize {
    let t = DATA.lock();
    let n = t.n_pointing.min(out.len());
    out[..n].copy_from_slice(&t.pointing[..n]);
    n
}

pub fn copy_batteries(out: &mut [SmbiosBattery]) -> usize {
    let t = DATA.lock();
    let n = t.n_batteries.min(out.len());
    out[..n].copy_from_slice(&t.batteries[..n]);
    n
}

pub fn copy_system_reset(out: &mut [SmbiosSystemReset]) -> usize {
    let t = DATA.lock();
    let n = t.n_system_reset.min(out.len());
    out[..n].copy_from_slice(&t.system_reset[..n]);
    n
}

pub fn hw_security() -> Option<SmbiosHwSecurity> {
    let t = DATA.lock();
    if t.n_hw_security == 0 { None } else { Some(t.hw_security[0]) }
}

pub fn system_power_controls() -> Option<SmbiosSystemPowerControls> {
    let t = DATA.lock();
    if t.n_sys_power_ctrl == 0 { None } else { Some(t.sys_power_ctrl[0]) }
}

pub fn copy_voltage_probes(out: &mut [SmbiosVoltageProbe]) -> usize {
    let t = DATA.lock();
    let n = t.n_voltage.min(out.len());
    out[..n].copy_from_slice(&t.voltage_probes[..n]);
    n
}

pub fn copy_cooling_devices(out: &mut [SmbiosCoolingDevice]) -> usize {
    let t = DATA.lock();
    let n = t.n_cooling.min(out.len());
    out[..n].copy_from_slice(&t.cooling[..n]);
    n
}

pub fn copy_temperature_probes(out: &mut [SmbiosTemperatureProbe]) -> usize {
    let t = DATA.lock();
    let n = t.n_temp.min(out.len());
    out[..n].copy_from_slice(&t.temp_probes[..n]);
    n
}

pub fn copy_current_probes(out: &mut [SmbiosCurrentProbe]) -> usize {
    let t = DATA.lock();
    let n = t.n_current.min(out.len());
    out[..n].copy_from_slice(&t.current_probes[..n]);
    n
}

pub fn remote_access() -> Option<SmbiosRemoteAccess> {
    let t = DATA.lock();
    if t.n_remote_access == 0 { None } else { Some(t.remote_access[0]) }
}

pub fn bis() -> Option<SmbiosBis> {
    let t = DATA.lock();
    if t.n_bis == 0 { None } else { Some(t.bis[0]) }
}

pub fn copy_memory_error64(out: &mut [SmbiosMemoryError64]) -> usize {
    let t = DATA.lock();
    let n = t.n_mem_err64.min(out.len());
    out[..n].copy_from_slice(&t.mem_err64[..n]);
    n
}

pub fn copy_mgmt_devices(out: &mut [SmbiosMgmtDevice]) -> usize {
    let t = DATA.lock();
    let n = t.n_mgmt_devices.min(out.len());
    out[..n].copy_from_slice(&t.mgmt_devices[..n]);
    n
}

pub fn copy_mgmt_device_components(out: &mut [SmbiosMgmtDeviceComponent]) -> usize {
    let t = DATA.lock();
    let n = t.n_mgmt_dev_comp.min(out.len());
    out[..n].copy_from_slice(&t.mgmt_dev_comp[..n]);
    n
}

pub fn copy_mgmt_device_thresholds(out: &mut [SmbiosMgmtDeviceThreshold]) -> usize {
    let t = DATA.lock();
    let n = t.n_mgmt_dev_thresh.min(out.len());
    out[..n].copy_from_slice(&t.mgmt_dev_thresh[..n]);
    n
}

pub fn copy_memory_channels(out: &mut [SmbiosMemoryChannel]) -> usize {
    let t = DATA.lock();
    let n = t.n_mem_channels.min(out.len());
    out[..n].copy_from_slice(&t.mem_channels[..n]);
    n
}

pub fn ipmi_device() -> Option<SmbiosIpmiDevice> {
    let t = DATA.lock();
    if t.n_ipmi == 0 { None } else { Some(t.ipmi[0]) }
}

pub fn copy_power_supplies(out: &mut [SmbiosPowerSupply]) -> usize {
    let t = DATA.lock();
    let n = t.n_power_supplies.min(out.len());
    out[..n].copy_from_slice(&t.power_supplies[..n]);
    n
}

pub fn copy_additional_info(out: &mut [SmbiosAdditionalInfo]) -> usize {
    let t = DATA.lock();
    let n = t.n_additional.min(out.len());
    out[..n].copy_from_slice(&t.additional[..n]);
    n
}

pub fn copy_onboard_ext(out: &mut [SmbiosOnboardExt]) -> usize {
    let t = DATA.lock();
    let n = t.n_onboard_ext.min(out.len());
    out[..n].copy_from_slice(&t.onboard_ext[..n]);
    n
}

pub fn mgmt_ctrl_hci() -> Option<SmbiosMgmtCtrlHci> {
    let t = DATA.lock();
    if t.n_mgmt_ctrl_hci == 0 { None } else { Some(t.mgmt_ctrl_hci[0]) }
}

pub fn tpm_device() -> Option<SmbiosTpmDevice> {
    let t = DATA.lock();
    if t.n_tpm == 0 { None } else { Some(t.tpm[0]) }
}

pub fn copy_processor_additional(out: &mut [SmbiosProcessorAdditional]) -> usize {
    let t = DATA.lock();
    let n = t.n_proc_addl.min(out.len());
    out[..n].copy_from_slice(&t.proc_addl[..n]);
    n
}

pub fn copy_firmware_inventory(out: &mut [SmbiosFirmwareInventory]) -> usize {
    let t = DATA.lock();
    let n = t.n_fw_inventory.min(out.len());
    out[..n].copy_from_slice(&t.fw_inventory[..n]);
    n
}

pub fn copy_string_properties(out: &mut [SmbiosStringProperty]) -> usize {
    let t = DATA.lock();
    let n = t.n_string_prop.min(out.len());
    out[..n].copy_from_slice(&t.string_prop[..n]);
    n
}

/// Number of Type-126 (Inactive) records observed in the most
/// recent `parse_stream` call.
pub fn inactive_count() -> u32 {
    DATA.lock().inactive_count
}
