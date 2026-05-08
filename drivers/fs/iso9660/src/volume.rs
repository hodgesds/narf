//! ISO 9660 Volume management.

use alloc::sync::{Arc, Weak};
use narf_block::{BlockDevice, BlockRequest, BlockOp, QosHint};
use narf_driver_runtime::{alloc_coherent, DmaBuffer, DomainId, Cap};
use narf_capabilities::Read;
use narf_filesystem::{FsError, FsInstance, DirOps};
use super::descriptor::{PrimaryVolumeDescriptor, vd_type};
use super::dir::DirectoryRecord;

#[derive(Debug)]
pub struct Iso9660Volume<B: BlockDevice> {
    pub device: Arc<B>,
    pub pvd: PrimaryVolumeDescriptor,
    pub domain: DomainId,
    pub self_weak: Weak<Iso9660Volume<B>>,
}

impl<B: BlockDevice + 'static> Iso9660Volume<B> {
    pub async fn mount(device: Arc<B>, domain: DomainId) -> Result<Arc<Self>, FsError> {
        let block_size = device.logical_block_size() as usize;
        let buffer = alloc_coherent(block_size, domain).map_err(|_| FsError::Io(narf_block::BlockError::IOError))?;
        
        // Volume Descriptors start at sector 16
        let mut current_sec = 16u64;
        let mut pvd: Option<PrimaryVolumeDescriptor> = None;

        loop {
            let cap: Cap<DmaBuffer, Read> = Cap::bootstrap();
            let req = BlockRequest {
                op: BlockOp::Read,
                lba: current_sec,
                blocks: 1,
                buffer: cap,
                qos: QosHint::Latency,
                user_tag: 0,
            };
            
            let completion = device.submit(req).await;
            completion.result.map_err(FsError::Io)?;

            let header_ptr = buffer.phys_addr().raw() as *const super::descriptor::VolumeDescriptorHeader;
            let header = unsafe { *header_ptr };

            if &header.standard_identifier != b"CD001" {
                return Err(FsError::Unsupported);
            }

            match header.vd_type {
                vd_type::PRIMARY => {
                    let pvd_ptr = buffer.phys_addr().raw() as *const PrimaryVolumeDescriptor;
                    pvd = Some(unsafe { *pvd_ptr });
                }
                vd_type::TERMINATOR => break,
                _ => {}
            }

            current_sec += 1;
            if current_sec > 100 { // Safety limit
                return Err(FsError::Unsupported);
            }
        }

        let pvd = pvd.ok_or(FsError::Unsupported)?;

        Ok(Arc::new_cyclic(|self_weak| {
            Iso9660Volume {
                device,
                pvd,
                domain,
                self_weak: self_weak.clone(),
            }
        }))
    }
}

impl<B: BlockDevice + 'static> FsInstance for Iso9660Volume<B> {
    fn root(&self) -> Arc<dyn DirOps> {
        let root_record_ptr = &self.pvd.root_directory_record as *const u8 as *const DirectoryRecord;
        let root_record = unsafe { *root_record_ptr };

        Arc::new(super::node::Iso9660Node::new(
            self.self_weak.upgrade().expect("Iso9660Volume root called after drop"),
            &root_record,
        ))
    }

    fn name(&self) -> &str {
        "iso9660"
    }
}
