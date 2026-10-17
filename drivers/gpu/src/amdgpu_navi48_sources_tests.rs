use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

pub(crate) fn iv(client: u8, source: u8, ring: u8, data: [u32; 2]) -> ih::Event {
    ih::Event {
        ih_ring: 0,
        vector: ih::Vector::decode([
            u32::from(client) | (u32::from(source) << 8) | (u32::from(ring) << 16),
            0,
            0,
            0,
            data[0],
            data[1],
            0,
            0,
        ]),
    }
}
fn c(client: u8, source: u8, ring: u8, data: [u32; 2]) -> Class {
    classify(&iv(client, source, ring, data))
}

fn navi48_sources_decode_completion_queue_identity_like_linux() -> TestResult {
    // gfx_v12_0_eop_irq: ME 3:2, pipe 1:0, queue 6:4; bit 7 reserved.
    assert_eq!(
        c(CLIENT_GFX, 181, 0xda, [0x1234, 0]),
        Class::Eop {
            queue: Queue {
                me: 2,
                pipe: 2,
                queue: 5
            },
            doorbell: 0x1234
        }
    );
    assert_eq!(Queue::from_ring(0x80), Queue::from_ring(0));
    // sdma_v7_0_process_trap_irq: instance 7:4, queue 3:0.
    assert_eq!(
        c(CLIENT_GFX, 49, 0x13, [0, 0]),
        Class::SdmaTrap {
            instance: 1,
            queue: 3
        }
    );
    // sdma_v7_0_process_fence_irq shifts out the doorbell offset field.
    assert_eq!(
        c(CLIENT_GFX, 70, 0, [0x40, 0]),
        Class::SdmaFence { doorbell: 0x10 }
    );
    // Legacy GRBM_CP client (0x14) is not SOC21's GC client.
    assert_eq!(c(0x14, 181, 0, [0, 0]), Class::Unknown);
    assert_eq!(c(CLIENT_IH, 0, 0, [0, 0]), Class::IhSelf);
    assert_eq!(c(CLIENT_IH, 1, 0, [0, 0]), Class::Unknown);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-interrupts",
    navi48_sources_decode_completion_queue_identity_like_linux
);

fn navi48_sources_classify_faults_poison_and_shader_errors() -> TestResult {
    let q = Queue::from_ring(4);
    for (source, fault) in [
        (180, CommandFault::ReservedBits),
        (183, CommandFault::BadOpcode),
        (184, CommandFault::PrivilegedRegister),
        (185, CommandFault::PrivilegedInstruction),
        (186, CommandFault::SemaphoreWait),
        (195, CommandFault::ProtectionFault),
    ] {
        assert_eq!(
            c(CLIENT_GFX, source, 4, [0, 0]),
            Class::Fault(Fault::Command { fault, queue: q })
        );
    }
    for (source, fault) in [
        (50, SdmaFault::SrbmWrite),
        (54, SdmaFault::DoorbellInvalid),
        (55, SdmaFault::QueueHang),
        (56, SdmaFault::AtomicTimeout),
        (57, SdmaFault::PollTimeout),
        (58, SdmaFault::PageTimeout),
        (59, SdmaFault::PageNull),
        (60, SdmaFault::PageFault),
        (61, SdmaFault::VmHole),
        (63, SdmaFault::Frozen),
        (65, SdmaFault::SemaphoreIncomplete),
        (66, SdmaFault::SemaphoreWait),
    ] {
        assert_eq!(
            c(CLIENT_GFX, source, 0x12, [0, 0]),
            Class::Fault(Fault::Sdma {
                fault,
                instance: 1,
                queue: 2
            })
        );
    }
    assert_eq!(
        c(CLIENT_GFX, 0, 0, [0, 0]),
        Class::Fault(Fault::Vm { mm_hub: false })
    );
    assert_eq!(
        c(CLIENT_VMC, 0, 0, [0, 0]),
        Class::Fault(Fault::Vm { mm_hub: true })
    );
    for (client, source, ring, poison) in [
        (CLIENT_GFX, 1, 0, Poison::Utcl2),
        (CLIENT_GFX, 128, 0, Poison::RlcFed),
        (CLIENT_GFX, 197, 0, Poison::CpEcc),
        (CLIENT_GFX, 201, 0, Poison::CpFue),
        (CLIENT_GFX, 62, 0x10, Poison::SdmaEcc { instance: 1 }),
        (CLIENT_GFX, 64, 0, Poison::SdmaSramEcc { instance: 0 }),
        (CLIENT_DF, 0, 0, Poison::Umc),
        (CLIENT_BIF, 0x61, 0, Poison::Athub),
        (
            CLIENT_VCN1,
            160,
            0,
            Poison::Media {
                instance: 1,
                source: 160,
            },
        ),
    ] {
        assert_eq!(c(client, source, ring, [0, 0]), Class::Poison(poison));
    }
    // kfd_int_process_v11: encoding in context_id1[7:6], type in ctx0[24:21].
    let error = |kind: u32| [(kind << 21) | 0x1234, 2 << 6];
    assert_eq!(
        c(CLIENT_GFX, 239, 0, error(0)),
        Class::Poison(Poison::Shader { fatal: true })
    );
    assert_eq!(
        c(CLIENT_GFX, 239, 0, error(1)),
        Class::Fault(Fault::Shader {
            error: ShaderError::IllegalInstruction,
            detail: 0x1234
        })
    );
    assert_eq!(
        c(CLIENT_GFX, 239, 0, error(2)),
        Class::Fault(Fault::Shader {
            error: ShaderError::MemoryViolation,
            detail: 0x1234
        })
    );
    assert_eq!(
        c(CLIENT_GFX, 239, 0, error(3)),
        Class::Poison(Poison::Shader { fatal: false })
    );
    assert_eq!(c(CLIENT_GFX, 239, 0, error(9)), Class::Unknown);
    assert_eq!(
        c(CLIENT_GFX, 239, 0, [7, 1 << 6]),
        Class::ShaderMessage {
            encoding: 1,
            data: 7
        }
    );
    // A wave message is never a fault even if its data resembles an error.
    assert!(matches!(
        c(CLIENT_GFX, 239, 0, [1 << 21, 0]),
        Class::ShaderMessage { encoding: 0, .. }
    ));
    for source in [10, 48, 51, 52, 53, 177, 187, 188, 192, 200, 233, 255] {
        assert_eq!(c(CLIENT_GFX, source, 0, [0, 0]), Class::Unknown);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-interrupts",
    navi48_sources_classify_faults_poison_and_shader_errors
);

fn navi48_sources_map_dcn401_display_media_and_power_owners() -> TestResult {
    for ctx in 0..6 {
        assert_eq!(
            c(CLIENT_DCN, 9, 0, [ctx, 0]),
            Class::Display(Display::Hpd(ctx as u8))
        );
        assert_eq!(
            c(CLIENT_DCN, 9, 0, [ctx + 6, 0]),
            Class::Display(Display::HpdRx(ctx as u8))
        );
    }
    assert_eq!(c(CLIENT_DCN, 9, 0, [12, 0]), Class::Unknown);
    for (source, display) in [
        (0x1e, Display::Vline0(0)),
        (0x22, Display::Vline0(4)),
        (0x38, Display::Vline0(5)),
        (0x3c, Display::Vblank(0)),
        (0x41, Display::Vblank(5)),
        (0x4f, Display::Flip(0)),
        (0x54, Display::Flip(5)),
        (0x57, Display::Vupdate(0)),
        (0x5c, Display::Vupdate(5)),
        (0x68, Display::DmubOutbox),
    ] {
        assert_eq!(c(CLIENT_DCN, source, 0, [0, 0]), Class::Display(display));
    }
    for source in [0, 0x23, 0x55, 0x5d, 0x69] {
        assert_eq!(c(CLIENT_DCN, source, 0, [0, 0]), Class::Unknown);
    }
    assert_eq!(
        c(CLIENT_VCN, 119, 0, [0, 0]),
        Class::Media(Media::Vcn {
            instance: 0,
            source: 119
        })
    );
    assert_eq!(
        c(CLIENT_VCN, 153, 0, [0, 0]),
        Class::Media(Media::Jpeg {
            instance: 0,
            source: 153
        })
    );
    assert_eq!(c(CLIENT_VCN, 0, 0, [0, 0]), Class::Unknown);
    for client in [CLIENT_THM, CLIENT_ROM_SMUIO, CLIENT_MP1] {
        assert_eq!(c(client, 0xfe, 0, [0, 0]), Class::Power);
    }
    assert_eq!(c(CLIENT_VMC, 1, 0, [0, 0]), Class::Unknown);
    assert_eq!(c(0x1b, 0, 0, [0, 0]), Class::Unknown);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-interrupts",
    navi48_sources_map_dcn401_display_media_and_power_owners
);
