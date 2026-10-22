#!/usr/bin/env python3
"""Compare fixed VP9 Tier3 messages, probabilities and IBs against Mesa26.2.4."""
import argparse
from pathlib import Path
import hashlib
import json
import re
import struct
import subprocess
import sys
import tempfile
from decode_primary import primary_pieces
p=argparse.ArgumentParser(description=__doc__);p.add_argument('mesa',type=Path);p.add_argument('--ffmpeg',type=Path);p.add_argument('--surface-build-dir',type=Path);p.add_argument('--profile2',action='store_true');a=p.parse_args();gpu=Path(__file__).resolve().parents[2]
with tempfile.TemporaryDirectory(prefix='narf-vp9-tier3-')as temp:
    t=Path(temp);(t/'primary.h').write_text('\n'.join(primary_pieces(a.mesa,'vp9')))
    rust='''#[derive(Debug,PartialEq,Eq)]enum Error{Invalid}
#[allow(dead_code)]#[path="HEVC"]mod hevc_words;
#[allow(dead_code)]#[path="HEVC10"]mod hevc10_words;
#[allow(dead_code)]#[path="VP9BASE"]mod vp9_words;
#[allow(dead_code)]#[path="VP9"]mod d;
fn main(){for bytes in [d::create_message().as_slice(),d::decode_message().as_slice(),d::destroy_message().as_slice(),d::DEFAULT_PROBS]{for b in bytes{print!("{b:02x}");}println!();}
let base=0x8_1000_0000;for at in [d::SESSION,d::CREATE_MSG,d::DECODE_MSG,d::DESTROY_MSG,d::TARGET,d::FEEDBACK,d::BITSTREAM,d::PROBS,d::CONTEXT]{print!("{} ",base+at);}println!();
for phase in[d::Phase::Create,d::Phase::Decode,d::Phase::Destroy]{let ib=d::ib(base,phase).unwrap();for(i,w)in ib.as_slice().iter().enumerate(){print!("{}{:08x}",if i==0{""}else{" "},w);}println!();}
for b in d::STREAM{print!("{b:02x}");}println!();for at in 0..d::TARGET_BYTES{print!("{:02x}",d::expected(at));}println!();
for base in[0,4,1<<48,(1<<48)-4096]{assert_eq!(d::ib(base,d::Phase::Decode),Err(Error::Invalid));}}
'''.replace('HEVC10',str(gpu/'src/amdgpu_vcn_navi48_hevc10_words.rs')).replace('HEVC',str(gpu/'src/amdgpu_vcn_navi48_hevc_words.rs')).replace('VP9BASE',str(gpu/'src/amdgpu_vcn_navi48_vp9_words.rs')).replace('VP9',str(gpu/('src/amdgpu_vcn_navi48_vp9_10_words.rs' if a.profile2 else 'src/amdgpu_vcn_navi48_vp9_words.rs')))
    (t/'harness.rs').write_text(rust);subprocess.run(['rustc','--edition=2021',str(t/'harness.rs'),'-o',str(t/'rust')],check=True)
    actual=subprocess.check_output([str(t/'rust')],text=True).splitlines();stream=bytes.fromhex(actual[8]);picture=bytes.fromhex(actual[9]);assert len(stream)==(69 if a.profile2 else 64)
    command=[sys.executable,str(Path(__file__).with_name('hevc_surface_check.py')),str(a.mesa),'--gpu',str(gpu),'--emit-json',str(t/'surfaces.json')]
    if a.surface_build_dir:command+=['--build-dir',str(a.surface_build_dir)]
    subprocess.run(command,check=True);surface=next(row for row in json.loads((t/'surfaces.json').read_text())if row['policy']==0 and row['depth']==(10 if a.profile2 else 8))
    subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror','-Wno-sign-compare','-Wno-unused-but-set-variable','-Wno-unused-variable','-Wno-unused-function','-I'+str(t),str(Path(__file__).with_name('vp9_reference.c')),'-lm','-o',str(t/'native')],check=True)
    native=subprocess.check_output([str(t/'native'),str(len(stream))]+[str(surface[k])for k in ['y_pitch','uv_pitch','y_height','uv_height','y_size','uv_size','uv_offset']]+actual[4].split()+[str(10 if a.profile2 else 8)],text=True).splitlines()
    assert len(native)==7
    for index,(have,want) in enumerate(zip(actual[:4]+actual[5:8],native)):
        lhs=bytes.fromhex(have.replace(' ',''));rhs=bytes.fromhex(want.replace(' ',''))
        assert have==want,(index,[(i,h,w)for i,(h,w)in enumerate(zip(lhs,rhs))if h!=w][:24])
    assert hashlib.sha256(stream).hexdigest()==('43fa8123ae12129fa97147b98d948fa4c6c49dfd804f5430ad2d2077c7ce4576' if a.profile2 else '8720e79f246912d0d8001e0517b68f81be764b9d0102334ddf500f613ee6e453')
    assert hashlib.sha256(bytes.fromhex(actual[3])).hexdigest()=='1e47124c4a2c369b8bcbd24bf681106e22ddb2929fc0260a1907bf7ae86af593'
    if a.ffmpeg:
        ivf=struct.pack('<4sHH4sHHIIII',b'DKIF',0,32,b'VP90',128,128,1,1,1,0)+struct.pack('<IQ',len(stream),0)+stream;(t/'proof.ivf').write_bytes(ivf)
        subprocess.run([str(a.ffmpeg),'-v','error','-i',str(t/'proof.ivf'),'-frames:v','1','-pix_fmt','yuv420p10le' if a.profile2 else 'yuv420p','-f','rawvideo',str(t/'decoded.i420')],check=True)
        raw=(t/'decoded.i420').read_bytes();n=128*128
        if a.profile2:
            assert len(raw)==n*3;v=struct.unpack('<'+'H'*(len(raw)//2),raw);out=v[:n]+tuple(x for pair in zip(v[n:n+n//4],v[n+n//4:])for x in pair);decoded=struct.pack('<'+'H'*len(out),*(x<<6 for x in out))
        else:
            assert len(raw)==n*3//2;decoded=raw[:n]+bytes(x for pair in zip(raw[n:n+n//4],raw[n+n//4:])for x in pair)
        assert decoded==picture
        r=subprocess.run([str(a.ffmpeg),'-v','trace','-i',str(t/'proof.ivf'),'-map','0:v:0','-c:v','copy','-bsf:v','trace_headers','-f','rawvideo',str(t/'trace.vp9')],check=True,capture_output=True,text=True)
        assert 'out of range'not in r.stderr and 'Failed to read'not in r.stderr
        fields={'profile_low_bit':0,'profile_high_bit':1 if a.profile2 else 0,'frame_type':0,'show_frame':1,'error_resilient_mode':1,'frame_width_minus_1':127,'frame_height_minus_1':127,'frame_context_idx':0,'loop_filter_level':0,'loop_filter_sharpness':0,'loop_filter_delta_enabled':1,'loop_filter_delta_update':1,'loop_filter_ref_deltas[0]':1,'loop_filter_ref_deltas[2]':-1,'loop_filter_ref_deltas[3]':-1,'update_mode_delta[0]':0,'update_mode_delta[1]':0,'base_q_idx':0,'delta_q_y_dc.delta_coded':0,'delta_q_uv_dc.delta_coded':0,'delta_q_uv_ac.delta_coded':0,'segmentation_enabled':0,'tile_cols_log2':0,'tile_rows_log2':0,'header_size_in_bytes':10}
        if a.profile2:fields['ten_or_twelve_bit']=0
        for name,value in fields.items():assert re.search(r'\b'+re.escape(name)+r'\s+[01]*\s*=\s*'+str(value)+r'\b',r.stderr),name
        assert ('Frame:  size 128x128  subsample 1x1  bit_depth '+('10' if a.profile2 else '8')+'  tiles 1x1.') in r.stderr
        traced=[(int(m.group(1)),len(m.group(2)))for m in re.finditer(r'\]\s+(\d+)\s+\S+\s+([01]+)\s*=\s*-?\d+',r.stderr)]
        assert max(pos+bits for pos,bits in traced)==struct.unpack_from('<I',bytes.fromhex(actual[1]),244+112)[0]*8
        assert struct.unpack_from('<I',bytes.fromhex(actual[1]),244+108)[0]==fields['header_size_in_bytes']
print(('VP9 Profile2' if a.profile2 else 'VP9 Profile0')+' Tier3 full messages, probability initialization, unified reference-list IB and independent pixels/header trace passed.')
