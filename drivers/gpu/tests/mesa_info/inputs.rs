// Host-only observed-state inputs. These describe representative model cards;
// the INFO answers below are executed production builders, not C expected data.
#[no_mangle]
pub extern "C" fn narf_init(navi44: bool) {
    use crate::amdgpu_discovery::{GcInfo,IpBlock,HW_ID_GC,HW_ID_SDMA0,HW_ID_VCN};
    let se=if navi44 {2}else{4};
    let gc=GcInfo{version_major:1,version_minor:3,num_se:se,num_sa_per_se:2,
        num_cu_per_sa:8,num_rb_per_se:4,num_tccs:16,num_gprs:256,
        num_max_gs_thds:32,gs_table_depth:32,gsprim_buff_depth:1792,
        parameter_cache_depth:1024,double_offchip_lds_buffer:1,wave_size:32,
        max_waves_per_simd:16,max_scratch_slots_per_cu:32,lds_size:65536,
        num_sc_per_se:1,num_packer_per_sc:2,tcp_l1_size:32,num_sqc_per_wgp:1,
        sqc_inst_cache_size:32,sqc_data_cache_size:32,gl1c_size_per_instance:256,
        gl1c_per_sa:1,gl2c_per_gpu:8192};
    let block=|hw_id,major,minor,revision|IpBlock{hw_id,major,minor,revision,instance:0,
        sub_revision:0,variant:0,base_addrs:[0x1260,0,0,0,0],num_bases:1};
    *SNAP.lock()=Some(Snapshot{did:if navi44{0x7590}else{0x7550},
        family:Family::Navi4,vram_size:if navi44{8<<30}else{16<<30},visible_vram_size:256<<20,
        is_apu:false,gc:Some(gc),ip_blocks:vec![block(HW_ID_GC,12,0,if navi44{0}else{1}),
        block(HW_ID_SDMA0,7,0,0),block(HW_ID_VCN,5,0,0)],navi22:Default::default(),
        reference_clock_10khz:10000,vram_type:uapi::AMDGPU_VRAM_TYPE_GDDR6,vram_bit_width:if navi44{128}else{256}});
    let mut bitmap=[[0;4];4];for row in bitmap.iter_mut().take(se as usize){row[0]=255;row[1]=255;}
    *NAVI48_TOPOLOGY.lock()=Some(crate::amdgpu_gfx12_topology::Topology{active_cus:se*16,
        cu_bitmap:bitmap,active_arrays:((1u16<<(se*2))-1),enabled_rb_mask:(1<<(se*4))-1,gb_addr_config:0x26442043});
    *RDNA4_IDENTITY.lock()=Some(Rdna4Identity{rev_id:0,pci_rev:0,mall_size:if navi44{32<<20}else{64<<20}});
    *NAVI48_CLOCKS.lock()=Some([500_000,3_000_000,96_000,1_250_000]);
    *NAVI48_FIRMWARE.lock()=Some([(uapi::AMDGPU_INFO_FW_GFX_ME,0x10000,47),
        (uapi::AMDGPU_INFO_FW_GFX_PFP,0x10000,47),(uapi::AMDGPU_INFO_FW_GFX_MEC,0x10000,48)]);
    *NAVI48_MEDIA.lock()=Navi48MediaInfo{proven:0,vcn_firmware:Some(0x0110a001)};
}
#[no_mangle]
pub unsafe extern "C" fn narf_dispatch(request:usize)->i32 {
    match dispatch_for(0x45,request,Some(&crate::amdgpu_vm::VmState)) {
        Ok(_)=>0,Err(FsError::BadAddress)=>-14,Err(FsError::NotFound)=>-19,
        Err(FsError::InvalidData)=>-22,Err(FsError::Unsupported)=>-25,
    }
}
#[no_mangle]
pub extern "C" fn narf_cap(cap:u64)->u64{crate::drm_ioctl_bridge::amdgpu_cap_value(cap)}

#[no_mangle]
pub extern "C" fn narf_vcn_firmware(raw:u32){NAVI48_MEDIA.lock().vcn_firmware=Some(raw);}
#[no_mangle]
pub extern "C" fn narf_media_ready(ready:bool){crate::MEDIA_READY.store(ready,std::sync::atomic::Ordering::Relaxed);}

#[no_mangle]
pub extern "C" fn narf_withdraw_vcn_firmware(){NAVI48_MEDIA.lock().vcn_firmware=None;}
#[no_mangle]
pub extern "C" fn narf_unsupported_vcn(){let mut snap=SNAP.lock();let ip=snap.as_mut().unwrap().ip_blocks.iter_mut().find(|ip|ip.hw_id==crate::amdgpu_discovery::HW_ID_VCN).unwrap();ip.major=4;ip.revision=2;}
