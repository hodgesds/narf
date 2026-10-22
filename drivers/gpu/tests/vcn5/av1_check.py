#!/usr/bin/env python3
"""Independent Mesa AV1 tier3/context/CDF/IB and FFmpeg known-keyframe checks."""
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
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('mesa',type=Path)
p.add_argument('--ffmpeg',type=Path)
p.add_argument('--surface-build-dir',type=Path)
a=p.parse_args();gpu=Path(__file__).resolve().parents[2]
with tempfile.TemporaryDirectory(prefix='narf-av1-tier3-')as temp:
    t=Path(temp);(t/'primary.h').write_text('\n'.join(primary_pieces(a.mesa,'av1')))
    rust='''#[derive(Debug,PartialEq,Eq)]enum Error{Invalid}
#[allow(dead_code)]#[path="WORDS"]mod d;
fn main(){for bytes in[d::create_message().as_slice(),d::keyframe_message(d::fixed()).unwrap().as_slice(),d::destroy_message().as_slice(),d::DEFAULT_CDF]{for b in bytes{print!("{b:02x}");}println!();}
let base=0x8_1000_0000;for at in[d::SESSION,d::CREATE_MSG,d::DECODE_MSG,d::DESTROY_MSG,d::TARGET,d::FEEDBACK,d::BITSTREAM,d::PROBS,d::CONTEXT]{print!("{} ",base+at);}println!();
for phase in[d::Phase::Create,d::Phase::Decode,d::Phase::Destroy]{let ib=d::ib(base,phase).unwrap();for(i,w)in ib.as_slice().iter().enumerate(){print!("{}{:08x}",if i==0{""}else{" "},w);}println!();}
for b in d::STREAM{print!("{b:02x}");}println!();for at in 0..d::TARGET_BYTES{print!("{:02x}",d::expected(at));}println!();
let mut f=d::fixed();f.base_q_idx=7;f.quant_delta=[-2,3,-4,3,-4];f.filter_level=[11,12,13,14];f.sharpness=5;f.mode_ref_delta_enabled=true;f.mode_ref_delta_update=true;f.ref_deltas=[-2,-1,0,1,2,3,4,5];f.mode_deltas=[-3,4];f.tx_mode=2;for b in d::keyframe_message(f).unwrap(){print!("{b:02x}");}println!();
for base in[0,4,1<<48,(1<<48)-4096]{assert_eq!(d::ib(base,d::Phase::Decode),Err(Error::Invalid));}
for i in 0..12{let mut f=d::fixed();match i{0=>f.bitstream_bytes=0,1=>f.bitstream_bytes=d::BITSTREAM_BYTES as u32+1,2=>f.tile_offset=u32::MAX,3=>f.tile_bytes=0,4=>f.tile_offset=0,5=>f.quant_delta[0]=64,6=>f.quant_delta[3]=1,7=>f.filter_level[0]=64,8=>f.ref_deltas[0]=64,9=>f.mode_ref_delta_update=true,10=>f.tx_mode=1,11=>f.reduced_tx_set=true,_=>unreachable!()};assert_eq!(d::keyframe_message(f),Err(Error::Invalid));}}
'''.replace('WORDS',str(gpu/'src/amdgpu_vcn_navi48_av1_words.rs'))
    (t/'harness.rs').write_text(rust);subprocess.run(['rustc','--edition=2021',str(t/'harness.rs'),'-o',str(t/'rust')],check=True)
    actual=subprocess.check_output([str(t/'rust')],text=True).splitlines();stream=bytes.fromhex(actual[8]);picture=bytes.fromhex(actual[9]);assert len(stream)==193
    command=[sys.executable,str(Path(__file__).with_name('hevc_surface_check.py')),str(a.mesa),'--gpu',str(gpu),'--width','256','--height','128','--emit-json',str(t/'surfaces.json')]
    if a.surface_build_dir:command+=['--build-dir',str(a.surface_build_dir)]
    subprocess.run(command,check=True);surface=next(row for row in json.loads((t/'surfaces.json').read_text())if row['policy']==0 and row['depth']==8)
    subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror','-Wno-sign-compare','-Wno-unused-but-set-variable','-Wno-unused-variable','-Wno-unused-function','-Wno-unused-const-variable','-I'+str(t),str(Path(__file__).with_name('av1_reference.c')),'-lm','-o',str(t/'native')],check=True)
    args=[str(t/'native'),str(len(stream))]+[str(surface[k])for k in['y_pitch','uv_pitch','y_height','uv_height','y_size','uv_size','uv_offset']]+actual[4].split()
    native=subprocess.check_output(args+['0'],text=True).splitlines();assert len(native)==7
    for index,(have,want)in enumerate(zip(actual[:4]+actual[5:8],native)):
        lhs=bytes.fromhex(have.replace(' ',''));rhs=bytes.fromhex(want.replace(' ',''));assert have==want,(index,[(i,h,w)for i,(h,w)in enumerate(zip(lhs,rhs))if h!=w][:32])
    assert subprocess.check_output(args+['1'],text=True).strip()==actual[10],'nonzero parsed-field packing'
    assert hashlib.sha256(stream).hexdigest()=='5687498d2f4309175866e5ce58f8b21b97810e98eaa738a4cf7bd9d21aace1c2'
    assert hashlib.sha256(bytes.fromhex(actual[3])).hexdigest()=='3e7d9954ccdda4207222de61f3661396e0c43d39fc59bdba0f79da5443ed5890'
    if a.ffmpeg:
        ivf=struct.pack('<4sHH4sHHIIII',b'DKIF',0,32,b'AV01',256,128,1,1,1,0)+struct.pack('<IQ',len(stream),0)+stream;(t/'proof.ivf').write_bytes(ivf)
        subprocess.run([str(a.ffmpeg),'-v','error','-i',str(t/'proof.ivf'),'-frames:v','1','-pix_fmt','yuv420p','-f','rawvideo',str(t/'decoded.i420')],check=True)
        raw=(t/'decoded.i420').read_bytes();n=256*128;assert len(raw)==n*3//2
        assert raw[:n]+bytes(x for pair in zip(raw[n:n+n//4],raw[n+n//4:])for x in pair)==picture
        result=subprocess.run([str(a.ffmpeg),'-v','trace','-i',str(t/'proof.ivf'),'-map','0:v:0','-c:v','copy','-bsf:v','trace_headers','-f','rawvideo',str(t/'trace.av1')],check=True,capture_output=True,text=True)
        assert 'out of range'not in result.stderr and 'Failed to read'not in result.stderr
        fields={'seq_profile':0,'still_picture':1,'reduced_still_picture_header':1,'max_frame_width_minus_1':255,'max_frame_height_minus_1':127,'use_128x128_superblock':0,'enable_filter_intra':0,'enable_intra_edge_filter':0,'enable_superres':0,'enable_cdef':0,'enable_restoration':0,'high_bitdepth':0,'mono_chrome':0,'separate_uv_delta_q':0,'film_grain_params_present':0,'disable_cdf_update':1,'allow_screen_content_tools':0,'render_and_frame_size_different':0,'uniform_tile_spacing_flag':1,'tile_cols_log2':0,'tile_rows_log2':0,'base_q_idx':0,'delta_q_y_dc.delta_coded':0,'delta_q_u_dc.delta_coded':0,'delta_q_u_ac.delta_coded':0,'using_qmatrix':0,'segmentation_enabled':0,'reduced_tx_set':0}
        for name,value in fields.items():assert re.search(r'\b'+re.escape(name)+r'\s+[01]*\s*=\s*'+str(value)+r'\b',result.stderr),name
        # CBS positions are relative to each OBU. The final frame-header field
        # plus byte alignment independently locates the tile in the whole stream.
        frame_trace=result.stderr.split('Frame Header')[-1].split('Tile Group')[0]
        syntax=[(int(m.group(1)),len(m.group(2)))for m in re.finditer(r'\]\s+(\d+)\s+\S+\s+([01]+)\s*=\s*-?\d+',frame_trace)]
        frame=next(i for i in range(len(stream))if stream[i]==0x32)
        assert frame+max(pos+bits for pos,bits in syntax)//8==struct.unpack_from('<I',bytes.fromhex(actual[1]),244+1528)[0]
        assert len(stream)-struct.unpack_from('<I',bytes.fromhex(actual[1]),244+1528)[0]==struct.unpack_from('<I',bytes.fromhex(actual[1]),244+1532)[0]
print('AV1 tier3 full messages, CDF/context, IBs, nonzero parsed-field packing and independent pixels/header trace passed.')
