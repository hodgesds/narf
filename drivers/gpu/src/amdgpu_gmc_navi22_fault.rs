//! Fault reporting for the Navi22 hubs: the L2 protection-fault status as
//! `gfxhub_v2_1_print_l2_protection_fault_status` and
//! `mmhub_v2_0_print_l2_protection_fault_status` print it.
use super::Hub;

/// `GCVM_L2_PROTECTION_FAULT_STATUS` / `MMVM_L2_PROTECTION_FAULT_STATUS`:
/// the same fields on gc_10_3_0 and mmhub_2_0_0.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FaultStatus(pub u32);
impl FaultStatus {
    pub const fn more_faults(self) -> u32 {
        self.0 & 1 // linux-lit: 1=MMVM_L2_PROTECTION_FAULT_STATUS__MORE_FAULTS_MASK
    }
    pub const fn walker_error(self) -> u32 {
        // linux-lit: 1=MMVM_L2_PROTECTION_FAULT_STATUS__WALKER_ERROR__SHIFT
        (self.0 >> 1) & 7
    }
    pub const fn permission_faults(self) -> u32 {
        // linux-lit: 4=MMVM_L2_PROTECTION_FAULT_STATUS__PERMISSION_FAULTS__SHIFT
        (self.0 >> 4) & 0xf
    }
    pub const fn mapping_error(self) -> u32 {
        // linux-lit: 8=MMVM_L2_PROTECTION_FAULT_STATUS__MAPPING_ERROR__SHIFT
        (self.0 >> 8) & 1
    }
    pub const fn cid(self) -> u32 {
        (self.0 >> 9) & 0x1ff // linux-lit: 9=MMVM_L2_PROTECTION_FAULT_STATUS__CID__SHIFT
    }
    pub const fn rw(self) -> u32 {
        (self.0 >> 18) & 1 // linux-lit: 18=MMVM_L2_PROTECTION_FAULT_STATUS__RW__SHIFT
    }
    pub const fn vmid(self) -> u32 {
        (self.0 >> 20) & 0xf // linux-lit: 20=MMVM_L2_PROTECTION_FAULT_STATUS__VMID__SHIFT
    }
}

/// gfxhub_v2_1.c `gfxhub_client_ids`.
const GFXHUB_CLIENTS: [&str; 18] = [
    "CB/DB",
    "Reserved",
    "GE1",
    "GE2",
    "CPF",
    "CPC",
    "CPG",
    "RLC",
    "TCP",
    "SQC (inst)",
    "SQC (data)",
    "SQG",
    "Reserved",
    "SDMA0",
    "SDMA1",
    "GCR",
    "SDMA2",
    "SDMA3",
];

/// A `[cid][rw]` client table (`struct amdgpu_mmhub_client_ids`): read
/// name, write name.
type Clients = [(Option<&'static str>, Option<&'static str>)];

/// mmhub_v2_0.c `mmhub_client_ids_sienna_cichlid` (MMHUB 2.1.0, 2.1.1).
const SIENNA_CICHLID: [(Option<&str>, Option<&str>); 44] = {
    let mut t = [(None, None); 44];
    t[0].1 = Some("DBGU0");
    t[1].1 = Some("DBGU1");
    t[2].1 = Some("DCEDWB");
    t[3] = (Some("DCEDMC"), Some("DCEDMC"));
    t[4] = (Some("DCEVGA"), Some("DCEVGA"));
    t[5] = (Some("MP0"), Some("MP0"));
    t[6] = (Some("MP1"), Some("MP1"));
    t[7].1 = Some("XDP");
    t[8].0 = Some("VMC");
    t[9] = (Some("VCNU0"), Some("VCNU0"));
    t[10] = (Some("JPEG"), Some("JPEG"));
    t[11].1 = Some("VCN0");
    t[12] = (Some("VCNU1"), Some("VCNU1"));
    t[13] = (Some("VCN1"), Some("VCN1"));
    t[14] = (Some("HDP"), Some("HDP"));
    t[15] = (Some("OSS"), Some("OSS"));
    t[32 + 11].0 = Some("VCN0");
    t
};

/// mmhub_v2_0.c `mmhub_client_ids_beige_goby` (MMHUB 2.1.2).
const BEIGE_GOBY: [(Option<&str>, Option<&str>); 16] = {
    let mut t = [(None, None); 16];
    t[0].1 = Some("DBGU0");
    t[1].1 = Some("DBGU1");
    t[2].1 = Some("DCEDWB");
    t[3] = (Some("DCEDMC"), Some("DCEDMC"));
    t[4] = (Some("DCEVGA"), Some("DCEVGA"));
    t[5] = (Some("MP0"), Some("MP0"));
    t[6] = (Some("MP1"), Some("MP1"));
    t[7].1 = Some("XDP");
    t[8].0 = Some("VMC");
    t[9] = (Some("VCNU0"), Some("VCNU0"));
    t[11] = (Some("VCN0"), Some("VCN0"));
    t[14] = (Some("HDP"), Some("HDP"));
    t[15] = (Some("OSS"), Some("OSS"));
    t
};

/// `mmhub_v2_0_init_client_info`: the MMHUB IP version's client table.
fn mmhub_clients(version: (u8, u8, u8)) -> &'static Clients {
    match version {
        (2, 1, 0) | (2, 1, 1) => &SIENNA_CICHLID,
        (2, 1, 2) => &BEIGE_GOBY,
        _ => &[],
    }
}

/// The UTCL2 client a fault status names on `hub`: `gfxhub_client_ids[cid]`
/// on GFXHUB, `amdgpu_mmhub_client_name(cid, rw)` over the MMHUB IP's table
/// on MMHUB. `None` is Linux's "unknown".
pub fn fault_client(hub: Hub, mmhub: (u8, u8, u8), cid: u32, write: bool) -> Option<&'static str> {
    match hub {
        Hub::Gfx => GFXHUB_CLIENTS.get(cid as usize).copied(),
        Hub::Mm => mmhub_clients(mmhub)
            .get(cid as usize)
            .and_then(|&(read, written)| if write { written } else { read }),
    }
}

/// One fault's decoded L2 status, as the fault service prints it: the
/// fields `*_print_l2_protection_fault_status` prints, the hub, the client
/// name with its raw CID ("Faulty UTCL2 client ID: %s (0x%x)") and the VMID.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StatusLine {
    pub hub: Hub,
    /// The discovered MMHUB IP version, which selects its client table.
    pub mmhub: (u8, u8, u8),
    pub status: FaultStatus,
}
impl core::fmt::Display for StatusLine {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = self.status;
        write!(
            f,
            "status={:#x} hub={} client={} ({:#x}) more={} walker={} permission={:#x} mapping={} rw={} vmid={}",
            s.0,
            match self.hub {
                Hub::Gfx => "GFX",
                Hub::Mm => "MM",
            },
            fault_client(self.hub, self.mmhub, s.cid(), s.rw() != 0).unwrap_or("unknown"),
            s.cid(),
            s.more_faults(),
            s.walker_error(),
            s.permission_faults(),
            s.mapping_error(),
            s.rw(),
            s.vmid(),
        )
    }
}
