# tables-ec-audio-iscsi-csrt-agdi — ECDT + NHLT + IBFT + CSRT + AGDI

> Status: **v0.1**.

Adds parsers for:

  * **ECDT** — Embedded Controller Boot Resources Table.
  * **NHLT** — Non-HD Audio Link Table.
  * **IBFT** — iSCSI Boot Firmware Table.
  * **CSRT** — Core System Resource Table.
  * **AGDI** — Arm Generic Diagnostic Dump and Reset Interface.

## 1. ECDT

| field            | size | meaning                                  |
|------------------|------|------------------------------------------|
| EcControlGas     | 12 B | command/status register GAS              |
| EcDataGas        | 12 B | data register GAS                         |
| Uid              | 4 B  | unique ID                                 |
| GpeBitNumber     | 1 B  | GPE for SCI                               |
| EcId[]           | var  | NUL-terminated namespace path             |

```rust
pub struct EcdtInfo {
    pub control_addr: u64,
    pub data_addr:    u64,
    pub uid:          u32,
    pub gpe_bit:      u8,
}

pub unsafe fn parse_ecdt(rsdp_phys: PhysAddr) -> Result<(), AcpiError>;
pub fn ecdt_info() -> Option<EcdtInfo>;
```

## 2. NHLT

| field         | size | meaning                          |
|---------------|------|----------------------------------|
| EndpointCount | 1 B  |                                   |
| Endpoints[N] (variable)                          |

Each Endpoint header:

| field        | size | meaning                                  |
|--------------|------|------------------------------------------|
| Length       | 4 B  |                                           |
| LinkType     | 1 B  | 0 = HDA, 1 = DSP, 2 = PDM, 3 = SSP        |
| InstanceId   | 1 B  |                                           |
| VendorId     | 2 B  |                                           |
| DeviceId     | 2 B  |                                           |
| RevisionId   | 2 B  |                                           |
| SubsystemId  | 4 B  |                                           |
| DeviceType   | 1 B  | 0 = BT, 1 = FM, 2 = Modem, 3 = HDMI       |
| Direction    | 1 B  | 0 = Render, 1 = Capture                  |
| VirtualBusId | 1 B  |                                           |

```rust
pub struct NhltEndpoint {
    pub link_type:   u8,
    pub instance_id: u8,
    pub vendor_id:   u16,
    pub device_id:   u16,
    pub direction:   u8,
}

pub unsafe fn parse_nhlt(rsdp_phys: PhysAddr) -> Result<u32, AcpiError>;
pub fn is_nhlt_known() -> bool;
pub fn copy_nhlt_endpoints(out: &mut [NhltEndpoint]) -> usize;
```

## 3. IBFT

| field            | size | meaning                                |
|------------------|------|----------------------------------------|
| Reserved         | 12 B |                                         |
| Structures[]     | var  |                                         |

Each structure header:

| field        | size | meaning                                  |
|--------------|------|------------------------------------------|
| Id           | 1 B  | 1 = Control, 2 = Initiator, 3 = NIC, 4 = Target |
| Version      | 1 B  |                                           |
| Length       | 2 B  |                                           |
| Index        | 1 B  |                                           |
| Flags        | 1 B  |                                           |

For Id = 4 (Target):

| field            | size | meaning                                |
|------------------|------|----------------------------------------|
| Header (6 B)                                                |
| TargetIp[16]     | 16 B | IPv6-mapped target address              |
| TargetPort       | 2 B  |                                           |
| TargetLun        | 8 B  |                                           |

```rust
pub struct IbftTarget {
    pub ip:        [u8; 16],
    pub port:      u16,
    pub lun:       u64,
}

pub unsafe fn parse_ibft(rsdp_phys: PhysAddr) -> Result<u32, AcpiError>;
pub fn is_ibft_known() -> bool;
pub fn copy_ibft_targets(out: &mut [IbftTarget]) -> usize;
```

## 4. CSRT

Each Resource Group:

| field         | size | meaning                                  |
|---------------|------|------------------------------------------|
| Length        | 4 B  |                                           |
| VendorId      | 4 B  |                                           |
| SubVendorId   | 4 B  |                                           |
| DeviceId      | 2 B  |                                           |
| SubDeviceId   | 2 B  |                                           |
| Revision      | 2 B  |                                           |
| Reserved      | 2 B  |                                           |
| SharedInfoLen | 4 B  |                                           |

```rust
pub struct CsrtGroup {
    pub vendor_id:    u32,
    pub device_id:    u16,
    pub revision:     u16,
}

pub unsafe fn parse_csrt(rsdp_phys: PhysAddr) -> Result<u32, AcpiError>;
pub fn is_csrt_known() -> bool;
pub fn copy_csrt_groups(out: &mut [CsrtGroup]) -> usize;
```

## 5. AGDI

| field           | size | meaning                                |
|-----------------|------|----------------------------------------|
| Flags           | 1 B  | bit 0 = signalling: 0 = SDEI, 1 = SMC  |
| Reserved        | 3 B  |                                         |
| SdeiEventNumber | 4 B  |                                         |
| SmcId           | 8 B  |                                         |

```rust
pub struct AgdiInfo {
    pub use_smc:           bool,
    pub sdei_event_number: u32,
    pub smc_id:            u64,
}

pub unsafe fn parse_agdi(rsdp_phys: PhysAddr) -> Result<(), AcpiError>;
pub fn agdi_info() -> Option<AgdiInfo>;
```

## 6. Test surface

| smoke                                | asserts                          |
|--------------------------------------|----------------------------------|
| `smoke_acpi_ecdt_synthetic_decode`   | control + data + UID round-trip   |
| `smoke_acpi_nhlt_synthetic_decode`   | one endpoint parses               |
| `smoke_acpi_ibft_synthetic_decode`   | one Target structure parses        |
| `smoke_acpi_csrt_synthetic_decode`   | one Resource Group parses         |
| `smoke_acpi_agdi_synthetic_decode`   | flags + ids round-trip            |

## 7. Out of scope (v0.1)

- ECDT namespace-string walk (we surface (control, data, UID,
  GPE)).
- NHLT format-config / capability blobs per endpoint.
- IBFT NIC / Initiator / Control structures.
- CSRT Resource Descriptor walk.
- AGDI dispatch on actual SDEI / SMC.
