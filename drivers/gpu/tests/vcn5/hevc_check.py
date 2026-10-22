#!/usr/bin/env python3
"""Compare the fixed Main8 codec message with unchanged Mesa 26.2.4 types/builder.
Usage: hevc_check.py /path/to/mesa-26.2.4 [--ffmpeg /path/to/ffmpeg]
The optional independent decoder also checks every source-pixel value.
"""
from pathlib import Path
import argparse
import hashlib
import json
import re
import subprocess
import struct
import tempfile
import sys

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('mesa',type=Path)
parser.add_argument('--ffmpeg',type=Path)
parser.add_argument('--igt',type=Path)
parser.add_argument('--main10',action='store_true')
parser.add_argument('--surface-build-dir',type=Path)
a=parser.parse_args()
gpu=Path(__file__).resolve().parents[2]
from decode_primary import primary_pieces
pieces=primary_pieces(a.mesa)
with tempfile.TemporaryDirectory(prefix='narf-hevc-main8-') as temp:
    p=Path(temp)
    (p/'primary.h').write_text('\n'.join(pieces)+'\n')
    rust='''#[derive(Debug,PartialEq,Eq)] enum Error {Invalid}
#[allow(dead_code)] #[path="WORDS"] mod d;
fn main(){
for data in [d::create_message().as_slice(),d::decode_message().as_slice(),d::destroy_message().as_slice()] {for b in data {print!("{b:02x}");}println!();}
for at in [0,4,1<<48,(1<<48)-4096] {assert_eq!(d::ib(at,d::Phase::Decode),Err(Error::Invalid));}
let base=0x8_1000_0000;
for phase in [d::Phase::Create,d::Phase::Decode,d::Phase::Destroy] {let words=d::ib(base,phase).unwrap();assert_eq!(words[2],words[4..].iter().fold(0u32,|s,w|s.wrapping_add(*w)));}
for b in d::STREAM {print!("{b:02x}");}println!();
for at in 0..d::TARGET_BYTES {print!("{:02x}",d::expected(at));}println!();
for at in [d::SESSION,d::CREATE_MSG,d::DECODE_MSG,d::DESTROY_MSG,d::DPB,d::TARGET,d::FEEDBACK,d::BITSTREAM,d::SCALING,d::CONTEXT] { print!("{} ",base+at); }println!();
for (n,phase) in [d::Phase::Create,d::Phase::Decode,d::Phase::Destroy].into_iter().enumerate() {print!("{n}");for w in d::ib(base,phase).unwrap(){print!(" {w:08x}");}println!();}
}'''.replace('WORDS',str(gpu/('src/amdgpu_vcn_navi48_hevc10_words.rs' if a.main10 else 'src/amdgpu_vcn_navi48_hevc_words.rs')))
    (p/'harness.rs').write_text(rust)
    surface_args=[sys.executable,str(Path(__file__).with_name('hevc_surface_check.py')),str(a.mesa),'--gpu',str(gpu),'--emit-json',str(p/'surfaces.json')]
    if a.surface_build_dir:surface_args+=['--build-dir',str(a.surface_build_dir)]
    subprocess.run(surface_args,check=True)
    layouts=json.loads((p/'surfaces.json').read_text());layout=next(row for row in layouts if row['policy']==0 and row['depth']==(10 if a.main10 else 8))
    subprocess.run(['cc' ,'-std=c11','-Wall','-Wextra','-Werror','-Wno-sign-compare','-Wno-unused-but-set-variable','-Wno-unused-variable','-I'+str(p),str(Path(__file__).with_name('hevc_reference.c')),'-lm','-o',str(p/'native')],check=True)
    subprocess.run(['rustc','--edition=2021',str(p/'harness.rs'),'-o',str(p/'rust')],check=True)
    actual=subprocess.check_output([str(p/'rust')],text=True).splitlines()
    stream=bytes.fromhex(actual[3]);picture=bytes.fromhex(actual[4])
    expected=subprocess.check_output([str(p/'native'),str(len(stream)),str(10 if a.main10 else 8)]+[str(layout[key])for key in ['y_pitch','uv_pitch','y_height','uv_height','y_size','uv_size','uv_offset']],text=True).splitlines()
    assert actual[:3]==expected,(actual[:3],expected)
    assert hashlib.sha256(stream).hexdigest()==('11f4e8621dd28676980f61687c94a746cb68ce586e7bf9075a072bcbf729b85f' if a.main10 else '26a5c91dacb9c140fe7dc624a3f57d9005657bc2b51d7a12ed34269b73458256')
    assert hashlib.sha256(picture).hexdigest()==('7c8a710cc653140480b728b7769d34d2f77c46cc30766530e9fc7b6742646c01' if a.main10 else 'af4b8817ee41af9585b6687e9969414a065e7f1a673e9204784daaab0820618b')
    if a.igt:
        source=(a.igt/'lib/amdgpu/amd_vcn_shared.c').read_text()
        header=(a.igt/'lib/amdgpu/amd_vcn_shared.h').read_text()
        shared=(a.igt/'lib/amdgpu/amd_mmd_shared.h').read_text()
        native=[source[:source.index('#include')],header[:header.index('#ifndef')],shared[:shared.index('#include')]]
        for name in ['rvcn_decode_buffer','rvcn_decode_ib_package']:
            native.append(re.search(r'struct '+name+r'\s*\{[^}]*\};',header)[0])
        native.append(re.search(r'enum decoder_error_type\s*\{[^}]*\};',shared)[0])
        native+=re.findall(r'^#define\s+DECODE_\w+\s+[^\n]+',header,re.M)
        for name in ['amdgpu_cs_sq_head','amdgpu_cs_sq_ib_tail','vcn_dec_cmd']:
            match=re.search(r'^'+name+r'\s*\(',source,re.M);start=source.rfind('void',0,match.start());opening=source.index('{',match.start());depth=1;end=opening+1
            while depth:
                depth+=(source[end]=='{')-(source[end]=='}');end+=1
            native.append(source[start:end])
        (p/'native_decode_funcs.h').write_text('\n'.join(native)+'\n')
        subprocess.run(['cc','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-Wno-sign-compare','-Wno-unused-but-set-variable','-Wno-unused-variable','-I'+str(p),str(Path(__file__).with_name('decode_reference.c')),'-o',str(p/'descriptor')],check=True)
        output=subprocess.check_output([str(p/'descriptor')]+actual[5].split(),text=True).splitlines()
        assert output==actual[6:9],(output,actual[6:9])
    if a.ffmpeg:
        (p/'proof.hevc').write_bytes(stream)
        subprocess.run([str(a.ffmpeg),'-v','error','-i',str(p/'proof.hevc'),'-frames:v','1','-pix_fmt','yuv420p10le' if a.main10 else 'yuv420p','-f','rawvideo',str(p/'decoded.i420')],check=True)
        raw=(p/'decoded.i420').read_bytes();n=128*128
        if a.main10:
            assert len(raw)==n*3
            values=struct.unpack('<'+'H'*(len(raw)//2),raw)
            out=values[:n]+tuple(v for pair in zip(values[n:n+n//4],values[n+n//4:])for v in pair)
            decoded=struct.pack('<'+'H'*len(out),*(v<<6 for v in out))
        else:
            assert len(raw)==n*3//2
            decoded=raw[:n]+bytes(v for pair in zip(raw[n:n+n//4],raw[n+n//4:]) for v in pair)
        assert decoded==picture
        trace=subprocess.run([str(a.ffmpeg),'-v','trace','-i',str(p/'proof.hevc'),'-map','0:v:0','-c:v','copy','-bsf:v','trace_headers','-f','rawvideo',str(p/'trace.hevc')],capture_output=True,text=True,check=True).stderr
        assert 'Failed to read' not in trace and 'out of range' not in trace
        for field,value in {'general_profile_idc':2 if a.main10 else 1,'pic_width_in_luma_samples':128,'pic_height_in_luma_samples':128,'bit_depth_luma_minus8':2 if a.main10 else 0,'bit_depth_chroma_minus8':2 if a.main10 else 0,'log2_max_pic_order_cnt_lsb_minus4':4,'sps_max_dec_pic_buffering_minus1[0]':2,'log2_min_luma_coding_block_size_minus3':0,'log2_diff_max_min_luma_coding_block_size':3,'log2_min_luma_transform_block_size_minus2':0,'log2_diff_max_min_luma_transform_block_size':3,'scaling_list_enabled_flag':0,'amp_enabled_flag':0,'sample_adaptive_offset_enabled_flag':0,'sps_temporal_mvp_enabled_flag':0,'strong_intra_smoothing_enabled_flag':0,'pps_loop_filter_across_slices_enabled_flag':1,'pps_deblocking_filter_disabled_flag':1,'slice_type':2}.items():
            assert re.search(r'\b'+re.escape(field)+r'\s+[01]+\s*=\s*'+str(value)+r'\b',trace),field
print(('Main10' if a.main10 else 'Main8')+' create/decode/destroy messages match Mesa 26.2.4; fixture hashes match'+('; independent decode/header trace passed' if a.ffmpeg else ''))
