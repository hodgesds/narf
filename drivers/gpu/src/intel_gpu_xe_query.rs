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
    if u32_at(&wire, 8) == 7 && u32_at(&wire, 12) != 0 {
        zero(&wire[..8])?;
        zero(&wire[24..40])?;
        if u32_at(&wire, 12) != 32 {
            return Err(FsError::InvalidData);
        }
        let data = u64_at(&wire, 16);
        let mut reply = read(user, data, 32)?;
        zero(&reply[2..4])?;
        zero(&reply[20..32])?;
        let kind = u16::from_le_bytes(reply[..2].try_into().unwrap());
        if kind > 1 {
            return Err(FsError::InvalidData);
        }
        if kind == 1 {
            let backend = info.backend.as_ref().ok_or(FsError::NoDevice)?;
            backend
                .status()
                .filter(|s| s.platform == info.platform && s.epoch != 0)
                .ok_or(FsError::NoDevice)?;
            let (major, minor, patch) = backend.huc_version().await?;
            put32(&mut reply, 4, 0);
            put32(&mut reply, 8, u32::from(major));
            put32(&mut reply, 12, u32::from(minor));
            put32(&mut reply, 16, u32::from(patch));
            return user.write(data, &reply);
        }
    }
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
    // Like xe_query.c, the engine pad is ignored. GT0's published logical
    // instances (including BMG COPY1 -> BCS8) and, while the standalone media
    // GT is published, GT1's VCS/VECS logical instances can be sampled.
    let class = u16::from_le_bytes([input[0], input[1]]);
    let logical = u16::from_le_bytes([input[2], input[3]]);
    // query_engine_cycles: gt_id >= max_gt_per_tile and xe_device_get_gt
    // are EINVAL; gt_id 1 exists only while GT1 is published.
    let media = match u16::from_le_bytes([input[4], input[5]]) {
        0 => None,
        1 => Some(
            info.backend
                .as_ref()
                .and_then(|b| b.media_gt())
                .ok_or(FsError::InvalidData)?,
        ),
        _ => return Err(FsError::InvalidData),
    };
    let destination = data.checked_add(12).ok_or(FsError::BadAddress)?;
    let stamp = if let Some(media) = media {
        // xe_gt_hw_engine(gt, class, instance, true) on GT1: render, copy
        // and compute classes, or an absent logical instance, are EINVAL.
        let engine = media
            .engines
            .from_class_instance(class, logical)
            .ok_or(FsError::InvalidData)?;
        info.backend
            .as_ref()
            .ok_or(FsError::NoDevice)?
            .media_engine_cycles(engine, clock)
            .await?
    } else {
        let status = info
            .backend
            .as_ref()
            .and_then(|b| b.status())
            .ok_or(FsError::NoDevice)?;
        // A known class this GT did not publish (fused-off CCS0) is EINVAL.
        let engine = status
            .engines
            .from_class_instance(class, logical)
            .ok_or(FsError::InvalidData)?;
        info.backend
            .as_ref()
            .ok_or(FsError::NoDevice)?
            .engine_cycles(engine, clock)
            .await?
    };
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
    let mut payload = match u32_at(wire, 8) {
        0 => {
            // drm_xe_query_engines: for_each_gt, then xe_hw_engine id order
            // (RCS0, BCS0, CCS0 on GT0; VCS, VECS on the media GT1), each
            // with its GT's dense logical instance and gt_id.
            let status = info
                .backend
                .as_ref()
                .and_then(|b| b.status())
                .filter(|status| status.platform == info.platform);
            let present = status.map_or_else(Default::default, |status| status.engines);
            let media = status
                .and(info.backend.as_ref().and_then(|b| b.media_gt()))
                .map_or_else(Default::default, |media| media.engines);
            let engines: alloc::vec::Vec<(Engine, u16, u16)> = present
                .iter()
                .map(|engine| (engine, 0, present.logical_instance(engine)))
                .chain(
                    media
                        .iter()
                        .map(|engine| (engine, 1, media.logical_instance(engine))),
                )
                .map(|(engine, gt, logical)| (engine, gt, logical.expect("published engine")))
                .collect();
            let mut reply = vec![0; 8 + engines.len() * 32];
            put32(&mut reply, 0, engines.len() as u32);
            for (i, (engine, gt, logical)) in engines.iter().enumerate() {
                reply[8 + i * 32..10 + i * 32].copy_from_slice(&engine.xe_class().to_le_bytes());
                reply[10 + i * 32..12 + i * 32].copy_from_slice(&logical.to_le_bytes());
                reply[12 + i * 32..14 + i * 32].copy_from_slice(&gt.to_le_bytes());
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
                let (used, visible_used) = vram.usage();
                reply[96..98].copy_from_slice(&1u16.to_le_bytes());
                reply[98..100].copy_from_slice(&1u16.to_le_bytes());
                put32(&mut reply, 100, vram.page_size() as u32);
                put64(&mut reply, 104, vram.total());
                put64(&mut reply, 112, used);
                put64(&mut reply, 120, vram.visible());
                put64(&mut reply, 128, visible_used);
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
            if crate::intel_gpu_xe::low_latency_supported(info) {
                config_flags |= crate::intel_gpu_xe_uapi::QUERY_CONFIG_HAS_LOW_LATENCY;
            }
            if info.platform.is_xe2() && !info.platform.is_ptl() {
                config_flags |= 8;
            }
            if info.vram.is_some() {
                config_flags |= 1; // DRM_XE_QUERY_CONFIG_FLAG_HAS_VRAM
            }
            put64(&mut reply, 16, config_flags);
            put64(&mut reply, 24, 4096);
            put64(&mut reply, 32, 48);
            // Caller-dependent max priority is sampled only for an exact
            // payload query, after size negotiation below (xe_query.c).
            reply
        }
        3 => {
            let facts = info
                .backend
                .as_ref()
                .and_then(|b| b.device_facts())
                .ok_or(FsError::NoDevice)?;
            // query_gt_list: GT0 (type MAIN), then the published standalone
            // media GT (type MEDIA, tile 0, gt_id 1) with its own clock and
            // GMD_ID arch/release/revid.
            let media = info.backend.as_ref().and_then(|b| b.media_gt());
            let count = 1 + usize::from(media.is_some());
            let mut reply = vec![0; 8 + 96 * count];
            put32(&mut reply, 0, count as u32);
            for gt in 0..count {
                let at = 8 + gt * 96;
                // near is the tile's VRAM bit on dGFX, far the rest.
                if info.vram.is_some() {
                    put64(&mut reply, at + 16, 2);
                    put64(&mut reply, at + 24, 1);
                } else {
                    put64(
                        &mut reply,
                        at + if info.platform.is_discrete() { 24 } else { 16 },
                        1,
                    );
                }
            }
            put32(&mut reply, 20, facts.reference_clock);
            reply[40..42].copy_from_slice(&(facts.graphics_version / 100).to_le_bytes());
            reply[42..44].copy_from_slice(&(facts.graphics_version % 100).to_le_bytes());
            reply[44..46].copy_from_slice(&u16::from(facts.graphics_step).to_le_bytes());
            if let Some(media) = media {
                reply[104..106].copy_from_slice(&1u16.to_le_bytes()); // GT_TYPE_MEDIA
                reply[108..110].copy_from_slice(&1u16.to_le_bytes()); // gt_id 1
                put32(&mut reply, 116, media.reference_clock);
                reply[136..138].copy_from_slice(&((media.gmd >> 22) as u16).to_le_bytes());
                reply[138..140].copy_from_slice(&(((media.gmd >> 14) & 0xff) as u16).to_le_bytes());
                reply[140..142].copy_from_slice(&((media.gmd & 0x3f) as u16).to_le_bytes());
            }
            reply
        }
        // xe_query.c query_hwconfig: source-unsupported families negotiate
        // a zero-length table, rather than inventing firmware records.
        4 if !info.platform.has_hwconfig() => Vec::new(),
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
            let width = if info.platform.is_ptl() { 12 } else { 4 };
            let mut masks = vec![
                (
                    0u16,
                    1u16,
                    topology.geometry_dss().to_le_bytes()[..width].to_vec(),
                ),
                (0, 2, topology.compute_dss().to_le_bytes()[..width].to_vec()),
                (
                    0,
                    if topology.eu_type() == EuType::Simd16 {
                        5
                    } else {
                        4
                    },
                    topology.eu_mask_per_dss().to_le_bytes().to_vec(),
                ),
            ];
            // query_gt_topology walks for_each_gt: the published media GT
            // follows with its own GSI-read fuses in the same per-GT layout
            // (geometry, compute, then SIMD8 EU per DSS at graphics 12.7x).
            // xe_gt_topology_report_l3 keeps a media GT's L3 bank entry
            // before media version 30, as xe_l3_bank_mask_t's 8 bytes. GT0's
            // entries above remain NARF's existing ones (no L3 bank entry).
            if let Some(media) = info.backend.as_ref().and_then(|b| b.media_gt()) {
                masks.extend([
                    (1, 1, media.topology.geometry.to_le_bytes().to_vec()),
                    (1, 2, media.topology.compute.to_le_bytes().to_vec()),
                    (1, 3, media.topology.l3_bank.to_le_bytes().to_vec()),
                    (1, 4, media.topology.eu_per_dss.to_le_bytes().to_vec()),
                ]);
            }
            for (gt, kind, mask) in masks {
                let mut header = [0u8; 8];
                header[..2].copy_from_slice(&gt.to_le_bytes());
                header[2..4].copy_from_slice(&kind.to_le_bytes());
                put32(&mut header, 4, mask.len() as u32);
                reply.extend_from_slice(&header);
                reply.extend_from_slice(&mask);
            }
            reply
        }
        10 => crate::intel_gpu_eu_stall::query(
            info.backend
                .as_ref()
                .and_then(|backend| backend.eu_stall_info())
                .ok_or(FsError::NoDevice)?,
        )?,
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
        if u32_at(wire, 8) == 2 {
            put64(&mut payload, 40, crate::intel_gpu_xe::max_queue_priority());
        }
        user.write(u64_at(wire, 16), &payload)
    }
}
