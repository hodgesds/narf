#!/usr/bin/env python3
"""Compile actual Rust INFO/GET_CAP dispatch/builders with host transport inputs."""
from pathlib import Path
import re

def item(source, pattern):
    m=re.search(pattern,source,re.M);assert m,pattern
    begin=source.rfind('\n',0,m.start())+1;opening=source.index('{',m.start());depth=1;end=opening+1
    while depth:
        depth+=(source[end]=='{')-(source[end]=='}');end+=1
    return source[begin:end]

def build(gpu,output):
    src=gpu/'src';info=(src/'amdgpu_info.rs').read_text();discovery=(src/'amdgpu_discovery.rs').read_text();rdna=(src/'amdgpu_rdna4.rs').read_text();vm=(src/'amdgpu_vm.rs').read_text();amdgpu=(src/'amdgpu.rs').read_text();gem=(src/'amdgpu_gem.rs').read_text();ioctl=(src/'drm/ioctl.rs').read_text()
    consts=lambda s: '\n'.join(re.findall(r'^pub const \w+[^;]+;',s,re.M))
    derived=lambda s,p,d='Clone,Copy,Debug,Default': '#[derive('+d+')]\n'+item(s,p)
    parts=['#![allow(dead_code,unused_imports)]\nextern crate alloc;\nextern crate self as narf_filesystem;\nextern crate self as narf_lib;\n#[derive(Debug,Clone,Copy)]pub enum FsError{InvalidData,BadAddress,Unsupported,NotFound}\npub mod sync{pub struct IrqSafeSpinLock<T>(std::sync::Mutex<T>);impl<T>IrqSafeSpinLock<T>{pub const fn new(v:T)->Self{Self(std::sync::Mutex::new(v))}pub fn lock(&self)->std::sync::MutexGuard<\'_,T>{self.0.lock().unwrap()}}}']
    uapi_host=output.with_name('amdgpu_uapi_host.rs');uapi_source=(src/'amdgpu_uapi.rs').read_text();uapi_host.write_text(uapi_source.split('// ── kernel tests ──')[0]+uapi_source[uapi_source.index('impl core::fmt::Debug'):])
    parts+=['#[path="'+str(uapi_host)+'"]mod amdgpu_uapi;', '#[path="'+str(src/'drm_uapi.rs')+'"]mod drm_uapi;', '#[path="'+str(src/'amdgpu_video_caps_navi48.rs')+'"]mod amdgpu_video_caps_navi48;']
    parts+=['mod amdgpu{'+derived(amdgpu,r'pub enum Family','Clone,Copy,Debug,PartialEq,Eq')+'pub const AMD_VENDOR:u16=0x1002;pub fn family_for_pci_id(v:u16,d:u16)->Option<Family>{(v==AMD_VENDOR && matches!(d,0x7550|0x7590)).then_some(Family::Navi4)}}']
    parts+=['mod amdgpu_discovery{'+consts(discovery[discovery.index('pub const HW_ID_MP1'):discovery.index('pub struct IpBlock')])+derived(discovery,r'pub struct IpBlock','Clone,Copy,Debug,PartialEq,Eq')+derived(discovery,r'pub struct GcInfo','Clone,Copy,Debug,Default,PartialEq,Eq')+'impl GcInfo{'+item(discovery,r'    pub fn total_cus')+'}'+item(discovery,r'pub fn find_ip')+'}']
    parts+=['mod amdgpu_gfx12_topology{'+derived((src/'amdgpu_gfx12_topology.rs').read_text(),r'pub struct Topology','Clone,Copy,Debug')+'}']
    parts+=['mod amdgpu_rdna4{use crate::amdgpu_discovery::{self as ip,IpBlock};'+derived(rdna,r'pub enum Rdna4Chip','Clone,Copy,Debug,PartialEq,Eq')+'impl Rdna4Chip{'+''.join(item(rdna,r'    pub (?:const )?fn '+n+r'\(')for n in ['from_gc','from_ip_blocks','external_rev'])+'}}']
    parts+=['mod amdgpu_rdna2{pub struct Profile{pub gc_version:(u8,u8,u8)}pub fn for_pci_id(_:u16,_:u16)->Option<Profile>{None}}', 'mod amdgpu_info_navi22{#[derive(Default,Clone,Debug)]pub struct Published;pub fn query(_: &crate::answers::Snapshot,_:u32,_:[u32;4])->Option<Result<Vec<u8>,crate::FsError>>{None}}']
    # VM geometry functions are the real implementation; no restated VA answer.
    geom=derived(vm,r'pub struct Geometry','Clone,Copy,Debug');level='#[derive(Clone,Copy,Debug)]pub enum Level{Pdb2}';fmt='#[derive(Clone,Copy,Debug)]pub enum PteFormat{Nv10}'
    gmc=re.search(r'    pub const GMC11: Geometry = Geometry \{.*?\n    \};',vm,re.S)[0]
    wanted=['GPU_PAGE_SHIFT','GPU_PAGE_SIZE','VA_RESERVED_BOTTOM','VA_RESERVED_TRAP','VA_RESERVED_SEQ64','VA_RESERVED_CSA','VA_RESERVED_TOP','GMC_HOLE_START','GMC_HOLE_END']
    vmconst='\n'.join(re.search(r'^pub const '+n+r'[^;]+;',vm,re.M)[0]for n in wanted)
    parts+=['mod amdgpu_vm{'+vmconst+level+fmt+geom+derived(vm,r'pub struct VaInfo','Clone,Copy,Debug')+'impl Geometry{'+gmc+''.join(item(vm,r'    pub fn '+n+r'\(')for n in ['fragment_bytes','usable','va_info'])+'}pub struct VmState;impl VmState{pub fn card(&self)->Option<u32>{Some(42)}pub fn fault(&self)->Fault{Fault{addr:0,status:0,vmhub:0}}}pub struct Fault{pub addr:u64,pub status:u32,pub vmhub:u32}}']
    parts+=['mod amdgpu_gem{'+derived(gem,r'pub struct HeapUsage','Clone,Copy,Debug')+'pub fn gtt_limit()->u64{8<<30}pub fn gtt_used()->u64{16<<20}pub fn vram_heap_usage(_:u32)->Option<HeapUsage>{Some(HeapUsage{visible:(128<<20,8<<20),unmapped:(6<<30,1<<30)})}}']
    # Ring admission is an explicit ready-owner input, not a fabricated INFO field.
    ring_source=(src/'amdgpu_navi48_platform_media.rs').read_text();ring=item(ring_source,r'pub\(super\) fn native_ring')
    platform=(src/'amdgpu_navi48_platform.rs').read_text();ring_consts='\n'.join(re.search(r'^(?:pub(?:\([^)]*\))? )?const '+n+r'[^;]+;',platform,re.M)[0]for n in ['SDMA_RING','MEDIA_RING','JPEG_RING'])
    max_ibs=re.search(r'^pub const MAX_JOB_IBS[^;]+;',(src/'amdgpu_gfx12_queue.rs').read_text(),re.M)[0]
    parts+=['static MEDIA_READY:std::sync::atomic::AtomicBool=std::sync::atomic::AtomicBool::new(true);','mod amdgpu_gfx12_queue{'+max_ibs+'}', 'mod amdgpu_cs{use crate::amdgpu_uapi as uapi;'+ring_consts+ring+'pub struct Ready;pub fn submitter(_:u32)->Option<Ready>{Some(Ready)}impl Ready{pub fn ring_for(&self,ip:u32,inst:u32,ring:u32)->Option<u32>{native_ring(ip,inst,ring,true,crate::MEDIA_READY.load(std::sync::atomic::Ordering::Relaxed),crate::MEDIA_READY.load(std::sync::atomic::Ordering::Relaxed))}pub fn max_ibs(&self,_:u32)->u32{crate::amdgpu_gfx12_queue::MAX_JOB_IBS as u32}}}', 'mod amdgpu_smuio14{#[derive(Clone,Copy)]pub struct ClockReader;impl ClockReader{pub fn read(self)->Option<u64>{None}}}']
    caps=item(ioctl,r'pub fn cap_value');capmod=item(ioctl,r'pub mod drm_cap')
    bridge=(src/'drm_ioctl_bridge.rs').read_text();parts+=['mod drm{pub mod ioctl{'+capmod+caps+'}}','mod drm_ioctl_bridge{use crate::FsError;pub unsafe fn copy_in(p:usize,n:usize)->Result<Vec<u8>,FsError>{Ok(unsafe{std::slice::from_raw_parts(p as *const u8,n)}.to_vec())}pub unsafe fn copy_out(p:usize,b:&[u8])->Result<(),FsError>{unsafe{std::ptr::copy_nonoverlapping(b.as_ptr(),p as *mut u8,b.len())};Ok(())}'+item(bridge,r'pub fn amdgpu_cap_value')+'}']
    funcs=['family_id','rdna4','as_bytes','heap_info','dev_info','dev_info_topology','memory_info','memory_info_heap','vram_gtt_heap','vram_gtt','hw_ip_info','available_rings','hw_id_for_ip_type','hw_ip_count','query','answers_navi22','card_heap','query_against','dispatch_for','firmware_version','read_mmr_reg','timestamp','video_caps']
    declarations='use alloc::{vec,vec::Vec};use crate::{FsError,amdgpu::Family,amdgpu_discovery::{self,GcInfo},amdgpu_uapi as uapi,drm_uapi};'+re.search(r'^const AMDGPU_GPU_PAGE_SIZE[^;]+;',info,re.M)[0]+re.search(r'^const GFX_HW_CONTEXTS[^;]+;',info,re.M)[0]
    declarations+=derived(info,r'pub struct Snapshot','Clone,Debug')+derived(info,r'pub\(crate\) struct Rdna4Identity','Clone,Copy,Debug')+derived(info,r'struct Navi48MediaInfo','Clone,Copy')
    declarations+='pub static SNAP:sync::IrqSafeSpinLock<Option<Snapshot>>=sync::IrqSafeSpinLock::new(None);fn snapshot()->Option<Snapshot>{SNAP.lock().clone()}fn rdna4_identity()->Option<Rdna4Identity>{*RDNA4_IDENTITY.lock()}'+'''static RDNA4_IDENTITY:sync::IrqSafeSpinLock<Option<Rdna4Identity>>=sync::IrqSafeSpinLock::new(None);static NAVI48_TOPOLOGY:sync::IrqSafeSpinLock<Option<crate::amdgpu_gfx12_topology::Topology>>=sync::IrqSafeSpinLock::new(None);static NAVI48_CLOCKS:sync::IrqSafeSpinLock<Option<[u32;4]>>=sync::IrqSafeSpinLock::new(None);static NAVI48_FIRMWARE:sync::IrqSafeSpinLock<Option<[(u32,u32,u32);3]>>=sync::IrqSafeSpinLock::new(None);static NAVI48_MEDIA:sync::IrqSafeSpinLock<Navi48MediaInfo>=sync::IrqSafeSpinLock::new(Navi48MediaInfo{proven:0,vcn_firmware:None});static NAVI48_CLOCK:sync::IrqSafeSpinLock<Option<crate::amdgpu_smuio14::ClockReader>>=sync::IrqSafeSpinLock::new(None);'''
    declarations+=''.join(item(info,r'(?:pub(?:\(crate\))? )?fn '+n+r'(?:<[^>]+>)?\(')for n in funcs)
    declarations+=(Path(__file__).with_name('inputs.rs')).read_text()
    parts+=['mod answers{use crate::sync;'+declarations+'}'];output.write_text('\n'.join(parts))
