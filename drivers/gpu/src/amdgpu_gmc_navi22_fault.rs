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

/// One hub context's programmed registers, read back for a fault report.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ContextRegs {
    /// `*VM_CONTEXTn_CNTL`.
    pub cntl: u32,
    /// `*VM_CONTEXTn_PAGE_TABLE_BASE_ADDR_LO32/HI32`.
    pub base: u64,
    /// `*VM_CONTEXTn_PAGE_TABLE_START_ADDR` / `_END_ADDR` (page numbers).
    pub start: u64,
    pub end: u64,
}

/// Why a lent client VMID faulted, as far as the CPU can tell.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultCause {
    /// No registered address space holds the IV's PASID.
    NoSpace,
    /// The client's VM maps nothing at the address.
    Unmapped,
    /// Mapped, but the client's tables do not translate the address.
    NotTranslated,
    /// The faulting hub's context is disabled.
    ContextDisabled,
    /// The address lies outside the context's START..=END range.
    ContextRange,
    /// The faulting hub's context does not point at the client's root: the
    /// job's VM flush did not land there.
    ContextElsewhere,
    /// Mapped, translated by the client's tables, and the faulting hub's
    /// context points at their root: the hub cannot walk what the CPU wrote.
    HubWalk,
}

/// Evidence for one fault on a lent client VMID: both hubs' context
/// registers for the VMID (faulting hub first) and what the client's
/// address space holds at the address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientFaultReport {
    pub fault: super::Fault,
    pub contexts: Option<[(Hub, ContextRegs); 2]>,
    pub space: Option<crate::amdgpu_vm::FaultVa>,
}
impl ClientFaultReport {
    /// The first explanation the evidence supports, in walk order: the
    /// client's VM, then the faulting hub's context. `None` when the
    /// context registers could not be read.
    pub fn cause(&self) -> Option<FaultCause> {
        let Some(space) = self.space.as_ref() else {
            return Some(FaultCause::NoSpace);
        };
        if space.mapping.is_none() {
            return Some(FaultCause::Unmapped);
        }
        if !space.translates() {
            return Some(FaultCause::NotTranslated);
        }
        let (_, context) = self.contexts?[0];
        // linux-lit: 1=MMVM_CONTEXT1_CNTL__ENABLE_CONTEXT_MASK
        if context.cntl & 1 == 0 {
            return Some(FaultCause::ContextDisabled);
        }
        let page = self.fault.address >> 12; // linux: n/a (AMDGPU_GPU_PAGE_SHIFT)
        if page < context.start || page > context.end {
            return Some(FaultCause::ContextRange);
        }
        if space.root != Some(context.base) {
            return Some(FaultCause::ContextElsewhere);
        }
        Some(FaultCause::HubWalk)
    }
}
const fn hub_name(hub: Hub) -> &'static str {
    match hub {
        Hub::Gfx => "GFX",
        Hub::Mm => "MM",
    }
}
/// Three console lines: the address space at the address, both hubs'
/// contexts for the VMID, and the cause.
impl core::fmt::Display for ClientFaultReport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        const PREFIX: &str = "amdgpu: navi22 GPU page fault";
        let va = crate::amdgpu_vm::sign_extend(self.fault.address);
        write!(f, "{PREFIX} va={va:#x} pasid={}: ", self.fault.pasid)?;
        match &self.space {
            None => write!(f, "no address space holds this PASID")?,
            Some(space) => {
                match &space.mapping {
                    Some(m) => write!(
                        f,
                        "mapped va={:#x}+{:#x} handle={} offset={:#x} flags={:#x} {}",
                        crate::amdgpu_vm::sign_extend(m.va),
                        m.size,
                        m.gem_handle,
                        m.offset,
                        m.vm_flags,
                        match space.system {
                            Some(true) => "system",
                            Some(false) => "vram",
                            None => "unbacked",
                        },
                    )?,
                    None => write!(f, "unmapped")?,
                }
                match space.root {
                    Some(root) => write!(f, " root={root:#x} walk=")?,
                    None => write!(f, " root=none walk=")?,
                }
                for (i, entry) in space.walk.iter().enumerate() {
                    let sep = if i == 0 { "" } else { "," };
                    write!(f, "{sep}{entry:#x}")?;
                }
                if space.walk.is_empty() {
                    write!(f, "none")?;
                }
            }
        }
        write!(f, "\n{PREFIX} vmid={} ", self.fault.vmid)?;
        match &self.contexts {
            None => write!(f, "contexts unreadable")?,
            Some(contexts) => {
                for (i, (hub, c)) in contexts.iter().enumerate() {
                    write!(
                        f,
                        "{}{} cntl={:#x} base={:#x} start={:#x} end={:#x}",
                        if i == 0 { "" } else { ", " },
                        hub_name(*hub),
                        c.cntl,
                        c.base,
                        c.start,
                        c.end,
                    )?;
                }
            }
        }
        let hub = hub_name(self.fault.hub);
        write!(f, "\n{PREFIX} cause: ")?;
        match self.cause() {
            None => write!(f, "unknown (contexts unreadable)"),
            Some(FaultCause::NoSpace) => write!(f, "no live address space holds the IV's PASID"),
            Some(FaultCause::Unmapped) => write!(f, "the address is unmapped in the client's VM"),
            Some(FaultCause::NotTranslated) => {
                write!(f, "mapped, but the client's tables do not translate it")
            }
            Some(FaultCause::ContextDisabled) => write!(f, "the {hub} context is disabled"),
            Some(FaultCause::ContextRange) => {
                write!(f, "the address is outside the {hub} context's range")
            }
            Some(FaultCause::ContextElsewhere) => write!(
                f,
                "the {hub} context does not point at the client's root: the VM flush did not land"
            ),
            Some(FaultCause::HubWalk) => write!(
                f,
                "mapped, the client's tables translate it and the {hub} context points at their root: the hub cannot walk them"
            ),
        }
    }
}
