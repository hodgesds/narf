#!/usr/bin/env python3
"""Compare 320x128 roundtrip descriptors/IBs with actual Mesa/Addrlib.
This is source packing coverage; encoder fixtures/pixel traces are checked
separately by the native encoder's primary harness. No stream is decoded here.
"""
import argparse
from pathlib import Path
import json
import subprocess
import sys
import tempfile
from decode_primary import primary_pieces
p=argparse.ArgumentParser(description=__doc__);p.add_argument('mesa',type=Path);p.add_argument('--surface-build-dir',type=Path);a=p.parse_args();gpu=Path(__file__).resolve().parents[2]
with tempfile.TemporaryDirectory(prefix='narf-av1-320-')as temporary:
    t=Path(temporary);(t/'primary.h').write_text('\n'.join(primary_pieces(a.mesa,'av1')))
    rust='''#[derive(Debug,PartialEq,Eq)]enum Error{Invalid}
#[allow(dead_code)]#[path="BASE"]mod av1_words;
#[allow(dead_code)]#[path="WORDS"]mod d;
#[allow(dead_code)]#[path="PARSER"]mod parser;
fn main(){let f=av1_words::fixed();for b in[d::create_message().as_slice(),d::keyframe_message(f).unwrap().as_slice(),d::destroy_message().as_slice(),d::DEFAULT_CDF]{for n in b{print!("{n:02x}");}println!();}
let base=0x8_1000_0000;for at in[d::SESSION,d::CREATE_MSG,d::DECODE_MSG,d::DESTROY_MSG,d::TARGET,d::FEEDBACK,d::BITSTREAM,d::PROBS,d::CONTEXT]{print!("{} ",base+at);}println!();
for phase in[d::Phase::Create,d::Phase::Decode,d::Phase::Destroy]{let ib=d::ib(base,phase).unwrap();for(i,w)in ib.as_slice().iter().enumerate(){print!("{}{:08x}",if i==0{""}else{" "},w);}println!();}
let mut f=f;f.base_q_idx=7;f.quant_delta=[-2,3,-4,3,-4];f.filter_level=[11,12,13,14];f.sharpness=5;f.mode_ref_delta_enabled=true;f.mode_ref_delta_update=true;f.ref_deltas=[-2,-1,0,1,2,3,4,5];f.mode_deltas=[-3,4];f.tx_mode=2;for b in d::keyframe_message(f).unwrap(){print!("{b:02x}");}println!();
let stream=include_bytes!("STREAM");let p=parser::inspect(stream).unwrap();let f=av1_words::Keyframe {bitstream_bytes:stream.len() as u32+9,tile_offset:p.tile_offset+9,tile_bytes:p.tile_bytes,base_q_idx:p.base_q_idx,quant_delta:p.quant_delta,filter_level:p.filter_level,sharpness:p.sharpness,mode_ref_delta_enabled:p.mode_ref_delta_enabled,mode_ref_delta_update:p.mode_ref_delta_update,ref_deltas:p.ref_deltas,mode_deltas:p.mode_deltas,tx_mode:p.tx_mode,reduced_tx_set:p.reduced_tx_set};for b in d::keyframe_message(f).unwrap(){print!("{b:02x}");}println!();
assert_eq!(d::BYTES,37101568);assert_eq!((0..d::TARGET_BYTES).filter_map(d::expected).count()as u64,d::LOGICAL_BYTES);
assert_eq!(d::expected(319),Some(80));assert_eq!(d::expected(320),None);assert_eq!(d::expected(384*64),Some(144));assert_eq!(d::expected(49152),Some(64));assert_eq!(d::expected(49152+320),None);}
'''.replace('BASE',str(gpu/'src/amdgpu_vcn_navi48_av1_words.rs')).replace('WORDS',str(gpu/'src/amdgpu_vcn_navi48_av1_320_words.rs')).replace('PARSER',str(gpu/'src/amdgpu_vcn_navi48_av1_encoded.rs')).replace('"STREAM"','"'+str(gpu/'fixtures/vcn5/av1_encode/reference-frame.obu')+'"')
    (t/'harness.rs').write_text(rust);subprocess.run(['rustc','--edition=2021',str(t/'harness.rs'),'-o',str(t/'rust')],check=True);actual=subprocess.check_output([str(t/'rust')],text=True).splitlines()
    command=[sys.executable,str(Path(__file__).with_name('hevc_surface_check.py')),str(a.mesa),'--gpu',str(gpu),'--width','320','--height','128','--emit-json',str(t/'surfaces.json')]
    if a.surface_build_dir:command+=['--build-dir',str(a.surface_build_dir)]
    subprocess.run(command,check=True);surface=next(r for r in json.loads((t/'surfaces.json').read_text())if r['depth']==8 and r['policy']==0)
    # Only host input geometry changes. All executable primary assignments,
    # type layouts, context/CDF and packet constructors remain unchanged.
    reference=Path(__file__).with_name('av1_reference.c').read_text()
    for before,after in[('.max_width=256','.max_width=320'),('.width=256','.width=320'),('a->width=a->max_width=256','a->width=a->max_width=320'),('tile_col_start_sb[1]=4','tile_col_start_sb[1]=5')]:
        assert before in reference,before;reference=reference.replace(before,after)
    # The actual compact CQ1 frame's parser descriptor also goes through the
    # unchanged builder, separately from the synthetic signed-field stress case.
    reference=reference.replace('if(scenario){','if(scenario==2){a->quantization.base_q_idx=4;a->loop_filter.loop_filter_flags.mode_ref_delta_enabled=1;a->tx_mode=2;a->tile_info.tile_size[0]=36;}else if(scenario){')
    (t/'reference.c').write_text(reference)
    subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror','-Wno-sign-compare','-Wno-unused-function','-Wno-unused-variable','-Wno-unused-but-set-variable','-Wno-unused-const-variable','-I'+str(t),str(t/'reference.c'),'-lm','-o',str(t/'native')],check=True)
    args=[str(t/'native'),'193']+[str(surface[k])for k in['y_pitch','uv_pitch','y_height','uv_height','y_size','uv_size','uv_offset']]+actual[4].split()
    assert subprocess.check_output(args+['0'],text=True).splitlines()==actual[:4]+actual[5:8]
    assert subprocess.check_output(args+['1'],text=True).strip()==actual[8]
    actual_size=(gpu/'fixtures/vcn5/av1_encode/reference-frame.obu').stat().st_size+9
    args[1]=str(actual_size)
    assert subprocess.check_output(args+['2'],text=True).strip()==actual[9]
print('320x128 source packing matches actual Mesa/Addrlib; 73728 B target, 61440 logical pixels, zero padding contract. No decode claim.')
