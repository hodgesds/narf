//! Xe query results describe observed resources, never hypothetical engines.
use crate::{
    intel_gpu_engine::Engine,
    intel_gpu_render::DeviceInfo,
    intel_gpu_topology::EuType,
    intel_gpu_uapi::{put32, put64, u32_at, u64_at},
    intel_gpu_xe_vm::{read, zero},
};
use alloc::{vec, vec::Vec};
use narf_filesystem::{FsError, IoctlContext};

pub(crate) fn query(
    info: &DeviceInfo,
    address: u64,
    user: &dyn IoctlContext,
) -> Result<(), FsError> {
    let wire = read(user, address, 40)?;
    query_wire(info, address, user, &wire)
}

pub(crate) async fn query_user(
    info: &DeviceInfo,
    address: u64,
    user: &dyn IoctlContext,
) -> Result<(), FsError> {
    let wire = read(user, address, 40)?;
    if u32_at(&wire, 8) != 6 || u32_at(&wire, 12) == 0 {
        return query_wire(info, address, user, &wire);
    }
    zero(&wire[..8])?;
    zero(&wire[24..40])?;
    if u32_at(&wire, 12) != 40 {
        return Err(FsError::InvalidData);
    }
    let data = u64_at(&wire, 16);
    let input = read(user, data, 40)?;
    let clock = u32_at(&input, 8) as i32;
    if !matches!(clock, 0 | 1 | 4 | 7) {
        return Err(FsError::InvalidData);
    }
    // Like xe_query.c, the engine pad is ignored. Only main GT0's published
    // logical instance 0 of RCS or BCS can be sampled.
    let engine = Engine::from_xe_class(u16::from_le_bytes([input[0], input[1]]))
        .filter(|_| input[2..6] == [0; 4])
        .ok_or(FsError::InvalidData)?;
    let destination = data.checked_add(12).ok_or(FsError::BadAddress)?;
    let status = info
        .backend
        .as_ref()
        .and_then(|b| b.status())
        .ok_or(FsError::NoDevice)?;
    // A known class this GT did not publish (fused-off CCS0) is EINVAL.
    if !status.engines.contains(engine) {
        return Err(FsError::InvalidData);
    }
    let stamp = info
        .backend
        .as_ref()
        .ok_or(FsError::NoDevice)?
        .engine_cycles(engine, clock)
        .await?;
    let mut output = [0; 28];
    put32(&mut output, 0, stamp.width);
    put64(&mut output, 4, stamp.engine_cycles);
    put64(&mut output, 12, stamp.cpu_timestamp);
    put64(&mut output, 20, stamp.cpu_delta);
    user.write(destination, &output)
}

fn query_wire(
    info: &DeviceInfo,
    address: u64,
    user: &dyn IoctlContext,
    wire: &[u8],
) -> Result<(), FsError> {
    zero(&wire[..8])?;
    zero(&wire[24..40])?;
    let payload = match u32_at(wire, 8) {
        0 => {
            // drm_xe_query_engines in xe_hw_engine id order: RCS0, BCS0, CCS0.
            let engines: alloc::vec::Vec<Engine> = info
                .backend
                .as_ref()
                .and_then(|b| b.status())
                .filter(|status| status.platform == info.platform)
                .map_or_else(alloc::vec::Vec::new, |status| {
                    status.engines.iter().collect()
                });
            let mut reply = vec![0; 8 + engines.len() * 32];
            put32(&mut reply, 0, engines.len() as u32);
            for (i, engine) in engines.iter().enumerate() {
                reply[8 + i * 32..10 + i * 32].copy_from_slice(&engine.xe_class().to_le_bytes());
            }
            reply
        }
        1 if info.memory_bytes != 0 => {
            // header8 + drm_xe_mem_region88 per region: SYSMEM/0, VRAM/1.
            let regions = 1 + usize::from(info.vram.is_some());
            let mut reply = vec![0; 8 + regions * 88];
            put32(&mut reply, 0, regions as u32);
            put32(&mut reply, 12, 4096);
            put64(&mut reply, 16, info.memory_bytes);
            if let Some(vram) = &info.vram {
                let used = vram.used();
                reply[96..98].copy_from_slice(&1u16.to_le_bytes());
                reply[98..100].copy_from_slice(&1u16.to_le_bytes());
                put32(&mut reply, 100, 4096); // BMG has no NEED64K VRAM flag
                put64(&mut reply, 104, vram.total());
                put64(&mut reply, 112, used);
                put64(&mut reply, 120, vram.visible());
                put64(&mut reply, 128, used); // every allocation is CPU-visible
            }
            reply
        }
        2 => {
            let facts = info
                .backend
                .as_ref()
                .and_then(|b| b.device_facts())
                .ok_or(FsError::NoDevice)?;
            let mut reply = vec![0; 48];
            put32(&mut reply, 0, 5);
            put64(
                &mut reply,
                8,
                u64::from(info.device_id) | u64::from(facts.revision) << 16,
            );
            let mut config_flags = 0;
            if info.platform == crate::intel_gpu_gt::GtPlatform::Battlemage {
                config_flags |= 8;
            }
            if info.vram.is_some() {
                config_flags |= 1; // DRM_XE_QUERY_CONFIG_FLAG_HAS_VRAM
            }
            put64(&mut reply, 16, config_flags);
            put64(&mut reply, 24, 4096);
            put64(&mut reply, 32, 48);
            put64(&mut reply, 40, 1); // highest unprivileged Xe priority: normal
            reply
        }
        3 => {
            let facts = info
                .backend
                .as_ref()
                .and_then(|b| b.device_facts())
                .ok_or(FsError::NoDevice)?;
            let mut reply = vec![0; 104];
            put32(&mut reply, 0, 1);
            put32(&mut reply, 20, facts.reference_clock);
            // query_gt_list: near is the tile's VRAM bit on dGFX, far the rest.
            if info.vram.is_some() {
                put64(&mut reply, 24, 2);
                put64(&mut reply, 32, 1);
            } else {
                put64(
                    &mut reply,
                    if info.platform.is_discrete() { 32 } else { 24 },
                    1,
                );
            }
            reply[40..42].copy_from_slice(&(facts.graphics_version / 100).to_le_bytes());
            reply[42..44].copy_from_slice(&(facts.graphics_version % 100).to_le_bytes());
            reply[44..46].copy_from_slice(&u16::from(facts.graphics_step).to_le_bytes());
            reply
        }
        4 => info
            .hwconfig
            .as_ref()
            .ok_or(FsError::NoDevice)?
            .as_bytes()
            .to_vec(),
        5 => {
            let topology = info
                .topology
                .as_ref()
                .filter(|t| t.platform() == info.platform)
                .ok_or(FsError::NoDevice)?;
            let mut reply = Vec::new();
            for (kind, mask) in [
                (1u16, topology.geometry_dss().to_le_bytes().to_vec()),
                (2, topology.compute_dss().to_le_bytes().to_vec()),
                (
                    if topology.eu_type() == EuType::Simd16 {
                        5
                    } else {
                        4
                    },
                    topology.eu_mask_per_dss().to_le_bytes().to_vec(),
                ),
            ] {
                let mut header = [0u8; 8];
                header[2..4].copy_from_slice(&kind.to_le_bytes());
                put32(&mut header, 4, mask.len() as u32);
                reply.extend_from_slice(&header);
                reply.extend_from_slice(&mask);
            }
            reply
        }
        6 => {
            if u32_at(wire, 12) != 0 {
                if u32_at(wire, 12) != 40 {
                    return Err(FsError::InvalidData);
                }
                return Err(FsError::WouldBlock);
            }
            vec![0; 40]
        }
        7 => {
            let size = u32_at(wire, 12);
            let mut reply = if size == 0 {
                vec![0; 32]
            } else {
                if size != 32 {
                    return Err(FsError::InvalidData);
                }
                let reply = read(user, u64_at(wire, 16), 32)?;
                zero(&reply[2..4])?;
                zero(&reply[20..32])?;
                let kind = u16::from_le_bytes(reply[..2].try_into().unwrap());
                if kind > 1 {
                    return Err(FsError::InvalidData);
                }
                if kind != 0 {
                    return Err(FsError::NoDevice);
                }
                reply
            };
            if size != 0 {
                let status = info
                    .backend
                    .as_ref()
                    .and_then(|b| b.status())
                    .filter(|s| s.platform == info.platform && s.epoch != 0)
                    .ok_or(FsError::NoDevice)?;
                put32(&mut reply, 4, 0);
                put32(&mut reply, 8, u32::from(status.submission_version.0));
                put32(&mut reply, 12, u32::from(status.submission_version.1));
                put32(&mut reply, 16, u32::from(status.submission_version.2));
            }
            reply
        }
        _ => return Err(FsError::InvalidData),
    };
    if u32_at(wire, 12) == 0 {
        user.write(
            address.checked_add(12).ok_or(FsError::BadAddress)?,
            &(payload.len() as u32).to_le_bytes(),
        )
    } else if u32_at(wire, 12) as usize != payload.len() {
        Err(FsError::InvalidData)
    } else {
        user.write(u64_at(wire, 16), &payload)
    }
}
