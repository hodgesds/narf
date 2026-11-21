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

/// The UTCL2 client a fault status names on `hub`.
pub fn fault_client(
    _hub: Hub,
    _mmhub: (u8, u8, u8),
    cid: u32,
    _write: bool,
) -> Option<&'static str> {
    GFXHUB_CLIENTS.get(cid as usize).copied()
}

/// One fault's decoded L2 status, as the fault service prints it.
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
            "status={:#x} client={} walker={} permission={:#x} mapping={} rw={}",
            s.0,
            fault_client(self.hub, self.mmhub, s.cid(), s.rw() != 0).unwrap_or("?"),
            s.walker_error(),
            s.permission_faults(),
            s.mapping_error(),
            s.rw(),
        )
    }
}
