//! Typed native Navi48 (SOC21) interrupt-vector sources. Pure decoding: no
//! MMIO, no acknowledgement and no completion. Client IDs follow Linux
//! soc15_ih_clientid.h; source IDs follow ivsrcid/gfx/irqsrcs_gfx_12_0_0.h,
//! vcn/irqsrcs_vcn_5_0.h, dcn/irqsrcs_dcn_1_0.h (as mapped by DCN401's
//! irq_service_dcn401.c) and nbio/irqsrcs_nbif_7_4.h. Payload layouts follow
//! gfx_v12_0.c, sdma_v7_0.c, amdgpu_dm_irq.c and kfd_int_process_v11.c.
use crate::amdgpu_ih7 as ih;

pub const CLIENT_IH: u8 = 0x00;
pub const CLIENT_BIF: u8 = 0x03;
pub const CLIENT_DCN: u8 = 0x04;
pub const CLIENT_GFX: u8 = 0x0a;
pub const CLIENT_VCN1: u8 = 0x0e;
pub const CLIENT_THM: u8 = 0x0f;
pub const CLIENT_VCN: u8 = 0x10;
pub const CLIENT_VMC: u8 = 0x12;
pub const CLIENT_ROM_SMUIO: u8 = 0x16;
pub const CLIENT_DF: u8 = 0x17;
pub const CLIENT_MP1: u8 = 0x1f;

/// A CP hardware queue slot as encoded in an IV ring ID: ME in bits 3:2, pipe
/// in 1:0 and queue in 6:4 (gfx_v12_0_eop_irq). Bit 7 is reserved.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Queue {
    pub me: u8,
    pub pipe: u8,
    pub queue: u8,
}
impl Queue {
    pub const fn from_ring(ring: u8) -> Self {
        Self {
            me: (ring >> 2) & 3,
            pipe: ring & 3,
            queue: (ring >> 4) & 7,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommandFault {
    BadOpcode,
    PrivilegedRegister,
    PrivilegedInstruction,
    /// CP_PM4_PKT_RSVD_BIT_ERROR.
    ReservedBits,
    /// CP_WAIT_MEM_SEM_FAULT.
    SemaphoreWait,
    /// CP_GPF.
    ProtectionFault,
}
/// SDMA7 error sources reported through the GFX client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SdmaFault {
    SrbmWrite,
    DoorbellInvalid,
    QueueHang,
    AtomicTimeout,
    PollTimeout,
    PageTimeout,
    PageNull,
    PageFault,
    VmHole,
    Frozen,
    SemaphoreIncomplete,
    SemaphoreWait,
}
/// SQ error-word types (kfd_int_process_v11.c SQ_INTERRUPT_ERROR_TYPE). EDC
/// FUE/FED are poison consumption, not process faults.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShaderError {
    IllegalInstruction,
    MemoryViolation,
}
/// Poison / RAS sources. Each one means data the GPU produced or consumed may
/// be corrupt; Linux answers them with RAS poison handling and a GPU reset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Poison {
    /// GFX UTCL2_DATA_POISONING.
    Utcl2,
    /// RLC_GC_FED_INTERRUPT.
    RlcFed,
    /// CP_ECC_ERROR.
    CpEcc,
    /// CP_FUE_ERROR.
    CpFue,
    SdmaEcc {
        instance: u8,
    },
    SdmaSramEcc {
        instance: u8,
    },
    /// SQ EDC FUE (fatal) or FED error words.
    Shader {
        fatal: bool,
    },
    /// VCN5 UVD/DJPEG/EJPEG poison on the given VCN client instance.
    Media {
        instance: u8,
        source: u8,
    },
    /// DF client source 0, GMC12's UMC ECC interrupt (gmc_v12_0 ecc_irq).
    Umc,
    /// NBIF ERREVENT_ATHUB (nbif_v6_3_1 ras_err_event_athub_irq).
    Athub,
}
/// A device fault, attributable through its queue or VM identity. VM faults
/// keep their richer latch decoding in amdgpu_navi48_faults.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    Vm {
        mm_hub: bool,
    },
    Command {
        fault: CommandFault,
        queue: Queue,
    },
    Sdma {
        fault: SdmaFault,
        instance: u8,
        queue: u8,
    },
    Shader {
        error: ShaderError,
        detail: u32,
    },
}
/// DCN401 interrupt sources (to_dal_irq_source_dcn401). Instance numbers are
/// zero-based OTG/HUBP/HPD indices; HPD context IDs come from source data 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Display {
    Hpd(u8),
    HpdRx(u8),
    /// OTG VSTARTUP, which Linux reports as VBLANK.
    Vblank(u8),
    /// OTG vertical interrupt 0 (VLINE0).
    Vline0(u8),
    /// HUBP flip accepted.
    Flip(u8),
    /// OTG VUPDATE without lock.
    Vupdate(u8),
    /// DMCUB outbox low-priority ready.
    DmubOutbox,
}
/// VCN5 unified-queue and JPEG traps. VCN source 119 can wake its owner;
/// other media messages remain diagnostic until their engine is supported.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Media {
    Vcn { instance: u8, source: u8 },
    Jpeg { instance: u8, source: u8 },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    /// IH ring1 self-IV (ih_v7_0_self_irq); ring housekeeping only.
    IhSelf,
    /// CP end of pipe. Kernel queues match exactly by slot; otherwise the
    /// doorbell in source data 0 names a user queue (gfx_v12_0_eop_irq).
    Eop {
        queue: Queue,
        doorbell: u32,
    },
    /// SDMA trap: instance in ring bits 7:4, queue in 3:0 (sdma_v7_0).
    SdmaTrap {
        instance: u8,
        queue: u8,
    },
    /// SDMA user-queue fence; doorbell offset from source data 0 >> 2.
    SdmaFence {
        doorbell: u32,
    },
    Fault(Fault),
    Poison(Poison),
    Display(Display),
    /// SQ auto or wave-message word: diagnostic, never completion.
    ShaderMessage {
        encoding: u8,
        data: u32,
    },
    Media(Media),
    /// Thermal, SMUIO and MP1 sources, owned by the SMU driver.
    Power,
    Unknown,
}

fn gfx(v: &ih::Vector) -> Class {
    let queue = Queue::from_ring(v.ring);
    let command = |fault| Class::Fault(Fault::Command { fault, queue });
    let instance = v.ring >> 4;
    let sdma = |fault| {
        Class::Fault(Fault::Sdma {
            fault,
            instance,
            queue: v.ring & 15,
        })
    };
    match v.source {
        0 => Class::Fault(Fault::Vm { mm_hub: false }),
        1 => Class::Poison(Poison::Utcl2),
        49 => Class::SdmaTrap {
            instance,
            queue: v.ring & 15,
        },
        50 => sdma(SdmaFault::SrbmWrite),
        54 => sdma(SdmaFault::DoorbellInvalid),
        55 => sdma(SdmaFault::QueueHang),
        56 => sdma(SdmaFault::AtomicTimeout),
        57 => sdma(SdmaFault::PollTimeout),
        58 => sdma(SdmaFault::PageTimeout),
        59 => sdma(SdmaFault::PageNull),
        60 => sdma(SdmaFault::PageFault),
        61 => sdma(SdmaFault::VmHole),
        62 => Class::Poison(Poison::SdmaEcc { instance }),
        63 => sdma(SdmaFault::Frozen),
        64 => Class::Poison(Poison::SdmaSramEcc { instance }),
        65 => sdma(SdmaFault::SemaphoreIncomplete),
        66 => sdma(SdmaFault::SemaphoreWait),
        70 => Class::SdmaFence {
            doorbell: v.data[0] >> 2,
        },
        128 => Class::Poison(Poison::RlcFed),
        180 => command(CommandFault::ReservedBits),
        181 => Class::Eop {
            queue,
            doorbell: v.data[0],
        },
        183 => command(CommandFault::BadOpcode),
        184 => command(CommandFault::PrivilegedRegister),
        185 => command(CommandFault::PrivilegedInstruction),
        186 => command(CommandFault::SemaphoreWait),
        195 => command(CommandFault::ProtectionFault),
        197 => Class::Poison(Poison::CpEcc),
        201 => Class::Poison(Poison::CpFue),
        239 => {
            let encoding = ((v.data[1] >> 6) & 3) as u8;
            if encoding != 2 {
                return Class::ShaderMessage {
                    encoding,
                    data: v.data[0],
                };
            }
            match (v.data[0] >> 21) & 15 {
                0 => Class::Poison(Poison::Shader { fatal: true }),
                1 => Class::Fault(Fault::Shader {
                    error: ShaderError::IllegalInstruction,
                    detail: v.data[0] & 0x1fffff,
                }),
                2 => Class::Fault(Fault::Shader {
                    error: ShaderError::MemoryViolation,
                    detail: v.data[0] & 0x1fffff,
                }),
                3 => Class::Poison(Poison::Shader { fatal: false }),
                _ => Class::Unknown,
            }
        }
        _ => Class::Unknown,
    }
}
fn display(v: &ih::Vector) -> Class {
    let d = match v.source {
        9 => match v.data[0] {
            n @ 0..=5 => Display::Hpd(n as u8),
            n @ 6..=11 => Display::HpdRx(n as u8 - 6),
            _ => return Class::Unknown,
        },
        s @ 0x1e..=0x22 => Display::Vline0(s - 0x1e),
        0x38 => Display::Vline0(5),
        s @ 0x3c..=0x41 => Display::Vblank(s - 0x3c),
        s @ 0x4f..=0x54 => Display::Flip(s - 0x4f),
        s @ 0x57..=0x5c => Display::Vupdate(s - 0x57),
        0x68 => Display::DmubOutbox,
        _ => return Class::Unknown,
    };
    Class::Display(d)
}
fn media(v: &ih::Vector, instance: u8) -> Class {
    match v.source {
        114 | 119 | 120 | 124 => Class::Media(Media::Vcn {
            instance,
            source: v.source,
        }),
        149 | 151 | 153 | 171..=175 | 177 | 178 => Class::Media(Media::Jpeg {
            instance,
            source: v.source,
        }),
        160..=162 => Class::Poison(Poison::Media {
            instance,
            source: v.source,
        }),
        _ => Class::Unknown,
    }
}
/// Classify one complete IV. Unknown client/source pairs stay `Unknown`; no
/// class here is a completion by itself.
pub fn classify(event: &ih::Event) -> Class {
    let v = &event.vector;
    match v.client {
        CLIENT_IH if v.source == 0 => Class::IhSelf,
        CLIENT_GFX => gfx(v),
        CLIENT_VMC if v.source == 0 => Class::Fault(Fault::Vm { mm_hub: true }),
        CLIENT_DCN => display(v),
        CLIENT_VCN => media(v, 0),
        CLIENT_VCN1 => media(v, 1),
        CLIENT_DF if v.source == 0 => Class::Poison(Poison::Umc),
        CLIENT_BIF if v.source == 0x61 => Class::Poison(Poison::Athub),
        CLIENT_THM | CLIENT_ROM_SMUIO | CLIENT_MP1 => Class::Power,
        _ => Class::Unknown,
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_navi48_sources_tests.rs"]
mod tests;
