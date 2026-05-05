# tables-boot-dbgp-wpbt-msct-xenv — boot/debug/Windows/system/Xen

> Status: **v0.1**.

Adds parsers for:

  * **BOOT** — Simple Boot Flag Table.
  * **DBGP** — Debug Port Table (the legacy single-port sibling
    of DBG2).
  * **WPBT** — Windows Platform Binary Table.
  * **MSCT** — Maximum System Characteristics Table.
  * **XENV** — Xen Environment Table.

## 1. BOOT

| field         | size | meaning                      |
|---------------|------|------------------------------|
| CmosIndex     | 1 B  | CMOS index for boot-flag byte |
| Reserved      | 3 B  |                                |

```rust
pub struct BootInfo {
    pub cmos_index: u8,
}

pub unsafe fn parse_boot(rsdp_phys: PhysAddr) -> Result<(), AcpiError>;
pub fn boot_info() -> Option<BootInfo>;
```

## 2. DBGP

| field          | size | meaning                                  |
|----------------|------|------------------------------------------|
| InterfaceType  | 1 B  | 0 = Full 16550, 1 = 16550 subset, ...    |
| Reserved       | 3 B  |                                           |
| BaseAddress    | 12 B | GAS                                       |

```rust
pub struct DbgpInfo {
    pub iface:         u8,
    pub addr_space_id: u8,
    pub base:          u64,
}

pub unsafe fn parse_dbgp(rsdp_phys: PhysAddr) -> Result<(), AcpiError>;
pub fn dbgp_info() -> Option<DbgpInfo>;
```

## 3. WPBT

| field           | size | meaning                                |
|-----------------|------|----------------------------------------|
| HandoffSize     | 4 B  | length of the binary in bytes           |
| HandoffAddr     | 8 B  | physical address of the binary           |
| LayoutType      | 1 B  | 1 = native EXE                          |
| ContentType     | 1 B  |                                          |
| ArgumentLength  | 2 B  |                                          |
| Argument        | var  | UTF-16 LE                                |

```rust
pub struct WpbtInfo {
    pub handoff_size: u32,
    pub handoff_addr: u64,
    pub layout_type:  u8,
    pub content_type: u8,
}

pub unsafe fn parse_wpbt(rsdp_phys: PhysAddr) -> Result<(), AcpiError>;
pub fn wpbt_info() -> Option<WpbtInfo>;
```

## 4. MSCT

| field                | size | meaning                              |
|----------------------|------|--------------------------------------|
| ProximityDomainOffset| 4 B  | offset to first PDIS                  |
| MaxProximityDomains  | 4 B  | max+1 of proximity-domain values      |
| MaxClockDomains      | 4 B  |                                       |
| MaxPhysAddrCap       | 8 B  |                                       |

Each PDIS (Proximity Domain Information Structure):

| field                | size | meaning                              |
|----------------------|------|--------------------------------------|
| Revision             | 1 B  |                                       |
| Length               | 1 B  |                                       |
| ProximityDomainRange | 4 B  | low + high domain (2 + 2)             |
| MaxProcessorCapacity | 4 B  |                                       |
| MaxMemoryCapacity    | 8 B  |                                       |

```rust
pub struct MsctInfo {
    pub max_proximity_domains: u32,
    pub max_clock_domains:     u32,
    pub max_phys_addr_cap:     u64,
}

pub struct MsctPdis {
    pub low_domain:           u16,
    pub high_domain:          u16,
    pub max_processor_capacity: u32,
    pub max_memory_capacity:    u64,
}

pub unsafe fn parse_msct(rsdp_phys: PhysAddr) -> Result<u32, AcpiError>;
pub fn is_msct_known() -> bool;
pub fn msct_info() -> Option<MsctInfo>;
pub fn copy_msct_pdis(out: &mut [MsctPdis]) -> usize;
```

## 5. XENV

| field         | size | meaning                                  |
|---------------|------|------------------------------------------|
| GrantTblPhys  | 8 B  | grant table base                          |
| GrantTblSize  | 8 B  | grant table size                          |
| Vector        | 4 B  | event-channel interrupt SPI               |
| Polarity      | 1 B  |                                           |
| Mode          | 1 B  |                                           |
| Reserved      | 2 B  |                                           |

```rust
pub struct XenvInfo {
    pub grant_table_base: u64,
    pub grant_table_size: u64,
    pub event_vector:     u32,
}

pub unsafe fn parse_xenv(rsdp_phys: PhysAddr) -> Result<(), AcpiError>;
pub fn xenv_info() -> Option<XenvInfo>;
```

## 6. Test surface

| smoke                                | asserts                          |
|--------------------------------------|----------------------------------|
| `smoke_acpi_boot_synthetic_decode`   | CMOS index round-trip            |
| `smoke_acpi_dbgp_synthetic_decode`   | iface + base round-trip          |
| `smoke_acpi_wpbt_synthetic_decode`   | handoff size + addr round-trip   |
| `smoke_acpi_msct_synthetic_decode`   | header + one PDIS parse          |
| `smoke_acpi_xenv_synthetic_decode`   | grant table + vector round-trip  |

## 7. Out of scope (v0.1)

- BOOT live CMOS read (the OS uses `CmosIndex` to find the
  boot-flag byte; reading it lives in the RTC driver).
- WPBT EXE handoff invocation; we surface only the location +
  type + size.
- MSCT per-domain processor / memory capacity application
  policies.
- XENV grant-table mapping.
