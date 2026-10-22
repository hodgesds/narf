#!/usr/bin/env python3
"""Execute unchanged Mesa VCN5 AV1 constructors and independently verify bytes.
Depends on sibling frozen HEVC encoder extractor and actual Addrlib helper.
No GPU access, firmware execution, codec simulation or timing claims.
"""
from pathlib import Path
import argparse,re,sys,subprocess,tempfile,json,hashlib,struct
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('mesa',type=Path);p.add_argument('--build-dir',type=Path);p.add_argument('--surface-build-dir',type=Path);p.add_argument('--ffmpeg',type=Path)
a=p.parse_args();m=a.mesa.resolve();gpu=Path(__file__).resolve().parents[2]
tmp=None if a.build_dir else tempfile.TemporaryDirectory(prefix='narf-av1-encode-');h=a.build_dir or Path(tmp.name);h.mkdir(exist_ok=True,parents=True);mm=m/'src/gallium/drivers/radeonsi/mm'
# Exact source selection/resource adapters shared with the frozen HEVC
# oracle, with direct path arguments and no imported script execution.
from encode_primary import primary_encoder
block=primary_encoder(m,h)
def func(source,name):
 mat=re.search(r'^(?:static )?(?:void|unsigned int|unsigned|uint32_t|bool|int)\s+'+name+r'\s*\(',source,re.M);assert mat,name
 return block(source[mat.start():],mat[0])
state=(m/'src/gallium/include/pipe/p_video_state.h').read_text();enums=(m/'src/gallium/include/pipe/p_video_enums.h').read_text();defs='\n'.join(p.read_text(errors='ignore')for p in(m/'src/gallium/include/pipe').glob('*.h'))
# Extract actual selected pipe inputs recursively; only base/dynarray opaque
# driver adapters are unused by any encoder constructor.
seen=set();parts=[];seen_enum=set();seen_define=set()
def macro(name):
 if name in seen_define:return
 seen_define.add(name)
 mat=re.search(r'^#define\s+'+name+r'\s+([^\n]+)',defs,re.M)
 if mat:parts.append('#define '+name+' '+mat[1])
def enum(n):
 if n in seen_enum:return
 seen_enum.add(n)
 src=state if 'enum '+n+'\n'in state or 'enum '+n+' {'in state else enums
 b=block(src,'enum '+n)
 for x in re.findall(r'\bPIPE_[A-Z0-9_]+\b',b):macro(x)
 parts.append(b+';')
def structure(n):
 if n in seen:return
 seen.add(n)
 if n in ('pipe_picture_desc','util_dynarray'):
  parts.append('struct '+n+' {unsigned unused;};');return
 mat=re.search(r'\bstruct '+n+r'\s*\{',state);assert mat,n
 b=block(state,mat[0])
 for sub in re.findall(r'\bstruct\s+(\w+)\s+\w+',b[b.index('{')+1:]):structure(sub)
 for e in re.findall(r'\benum\s+(\w+)',b):
  if e!='pipe_av1_enc_frame_type':enum(e)
 for x in re.findall(r'\bPIPE_[A-Z0-9_]+\b',b):macro(x)
 parts.append(b+';')
structure('pipe_av1_enc_picture_desc')
p=h/'enc_primary.h';text=p.read_text();newtypes='\n'.join(parts)
text=text.replace('struct radeon_encoder {','struct radeon_encoder {').replace('struct resource *si,*dpb,*meta,*stats,*roi;','struct resource *si,*dpb,*meta,*stats,*roi,*cdf;')
text=text.replace('static unsigned radeon_enc_av1_picture_type(unsigned x){(void)x;abort();}',func((mm/'radeon_vcn_enc.c').read_text(),'radeon_enc_av1_picture_type'))
text+='\n#define PIPE_AV1_ENC_SB_SIZE 64\n#define RENCODE_AV1_MIN_TILE_WIDTH 256\n#define MIN2(a,b) ((a)<(b)?(a):(b))\n#define CLAMP(v,l,h) MIN2(MAX2(v,l),h)\n#define IS_POT_NONZERO(v) ((v)&&!((v)&((v)-1)))\n#define util_logbase2(v) (31-__builtin_clz(v))\n#define AV1_SELECT_SCREEN_CONTENT_TOOLS 2\n#define AV1_SELECT_INTEGER_MV 2\n'+newtypes+'\n'
bits=(mm/'radeon_bitstream.c').read_text();text+=bits[bits.index('static void radeon_bs_code_leb128('):]+'\n'
text+='struct tile_1d_layout {uint32_t nb_main_sb,nb_main_tile,nb_border_sb,nb_border_tile;bool uniform_tile_flag;};\n'
for name in ['radeon_enc_av1_tile_log2','radeon_enc_value_bits','radeon_enc_av1_bs_copy_end','radeon_enc_av1_bs_instruction_type']:
 text+=func((mm/'radeon_vcn_enc.c').read_text(),name)+'\n'
for name in ['radeon_enc_av1_obu_header','radeon_enc_write_sequence_header','radeon_enc_av1_frame_header_common','radeon_enc_av1_tile_group']:
 text+=func((mm/'radeon_vcn_enc_4_0.c').read_text(),name)+'\n'
for name in ['radeon_enc_cdf_default_table','radeon_enc_spec_misc_av1','radeon_enc_encode_params_av1','radeon_enc_is_av1_uniform_tile','radeon_enc_av1_tile_layout','radeon_enc_av1_tile_default','radeon_enc_tile_config_av1','radeon_enc_av1_tile_info','radeon_enc_av1_write_delta_q','radeon_enc_av1_quantization_params','radeon_enc_av1_frame_header','radeon_enc_obu_instruction']:
 text+=func((mm/'radeon_vcn_enc_5_0.c').read_text(),name)+'\n'
(h/'av1_primary.h').write_text(text)

flags=['-std=gnu11','-Wall','-Wextra','-Werror','-Wno-sign-compare','-Wno-unused-function','-Wno-unused-parameter','-I'+str(m/'src/amd/common'),'-I'+str(h)]
subprocess.run(['cc',*flags,str(Path(__file__).with_name('av1_encode_reference.c')),'-o',str(h/'av1')],check=True)
fixture=gpu/'fixtures/vcn5/av1_encode'
manifest=json.loads((fixture/'manifest.json').read_text())
for name,info in manifest['files'].items():
 data=(fixture/name).read_bytes();assert len(data)==info['bytes'];assert hashlib.sha256(data).hexdigest()==info['sha256']
# Actual native C array export, including implicit zero-initialized tail;
# no Python byte/table reconstruction is accepted as the reference.
(h/'cdf.c').write_text('#include <stdio.h>\n#include "ac_vcn_enc_av1_default_cdf.h"\nint main(void){return fwrite(rvcn_av1_cdf_default_table,1,VCN_ENC_AV1_DEFAULT_CDF_SIZE,stdout)!=VCN_ENC_AV1_DEFAULT_CDF_SIZE;}\n')
subprocess.run(['cc',*flags,str(h/'cdf.c'),'-o',str(h/'cdf')],check=True)
assert subprocess.check_output([str(h/'cdf')])==(fixture/'cdf.bin').read_bytes()
surfaces=h/'surfaces.json'
subprocess.run([sys.executable,str(Path(__file__).with_name('hevc_surface_check.py')),str(m),'--gpu',str(gpu),'--width','320','--height','128','--build-dir',str(a.surface_build_dir or h/'surfaces'),'--emit-json',str(surfaces)],check=True)
layouts=json.loads(surfaces.read_text());input_layout=next(x for x in layouts if x['depth']==8 and x['policy']==256)
assert all((x['y_pitch'],x['uv_pitch'],x['uv_offset'],x['target_size'])==(512,256,65536,98304) for x in layouts if x['depth']==8 and x['policy']==256)
rust='extern crate alloc;#[derive(Debug,PartialEq,Eq)]enum Error{Invalid,Unsupported}\n#[allow(dead_code)]#[path="/tmp/rx9000-av1-encode-followup/modified/drivers/gpu/src/amdgpu_vcn_navi48_av1_encode_words.rs"]mod e;\nfn main(){let b=0x810000000;for o in [e::SESSION,e::CPB,e::INPUT,e::METADATA,e::OUTPUT,e::FEEDBACK,e::CDF]{print!("{} ",b+o);}println!("{} {}",e::OUTPUT_BYTES,e::BYTES);for p in [e::Phase::Create,e::Phase::Encode,e::Phase::Destroy]{for w in e::ib(b,p,0x1000a).unwrap(){print!("{w:08x} ");}println!();}}\n'
rust=rust.replace('/tmp/rx9000-av1-encode-followup/modified/drivers/gpu/src/amdgpu_vcn_navi48_av1_encode_words.rs',str(gpu/'src/amdgpu_vcn_navi48_av1_encode_words.rs'))
(h/'words.rs').write_text(rust)
subprocess.run(['rustc','--edition=2021',str(h/'words.rs'),'-o',str(h/'words')],check=True)
rows=subprocess.check_output([str(h/'words')],text=True).splitlines();values=rows[0].split();assert values[-1]=='1884160'
expected=subprocess.check_output([str(h/'av1'),*values[:-1],*[str(input_layout[k])for k in ['y_pitch','uv_pitch','uv_offset']]],text=True).splitlines()
assert expected[0]=='sizes 1340416 50176'
assert bytes.fromhex(expected[1].split()[1])==(fixture/'headers.bin').read_bytes()
assert [x.split()for x in rows[1:]]==[x.split()for x in expected[2:]],'AV1 packets differ from unchanged Mesa'
# Execute the same native parser regressions through a minimal host boundary.
cases=(gpu/'src/amdgpu_vcn_navi48_av1_encoded_tests.rs').read_text().replace('../fixtures/vcn5/av1_encode/',str(fixture)+'/')
cases+='\npub fn run_all(){vcn5_av1_encoded_parser_matches_independent_lossless_and_lossy_output();vcn5_av1_encoded_parser_refuses_unsupported_shape_length_and_alignment();vcn5_av1_encoded_parser_preserves_dynamic_quant_filter_and_signed_updates();}\n'
(h/'parser-cases.rs').write_text(cases)
(h/'parser.rs').write_text('extern crate alloc;use alloc::{vec,vec::Vec};#[derive(Debug,PartialEq)]enum TestResult{Pass}macro_rules! kernel_test_in{($($x:tt)*)=>{}}#[path="'+str(gpu/'src/amdgpu_vcn_navi48_av1_encoded.rs')+'"]mod av1_encoded;#[path="'+str(h/'parser-cases.rs')+'"]mod cases;fn main(){cases::run_all();}')
subprocess.run(['rustc','--edition=2021','-D','warnings',str(h/'parser.rs'),'-o',str(h/'parser')],check=True);subprocess.run([str(h/'parser')],check=True)
if a.ffmpeg:
 # CPU sequence and actual independently encoded frame share exact fixed
 # source parameters. Native firmware is not presumed to generate these bytes.
 data=(fixture/'headers.bin').read_bytes()+(fixture/'reference-frame.obu').read_bytes()
 ivf=struct.pack('<4sHH4sHHIIII',b'DKIF',0,32,b'AV01',320,128,25,1,1,0)+struct.pack('<IQ',len(data),0)+data
 (h/'reference.ivf').write_bytes(ivf)
 subprocess.run([str(a.ffmpeg),'-y','-v','error','-i',str(h/'reference.ivf'),'-frames:v','1','-pix_fmt','yuv420p','-f','rawvideo',str(h/'reference.i420')],check=True)
 b=(h/'reference.i420').read_bytes();n=320*128;assert len(b)==n*3//2
 nv12=b[:n]+bytes(v for pair in zip(b[n:n+n//4],b[n+n//4:])for v in pair)
 assert nv12==(fixture/'frame.bin').read_bytes(),'Independent AV1 roundtrip differs'
 with(h/'trace.log').open('w')as out:
  subprocess.run([str(a.ffmpeg),'-y','-v','verbose','-i',str(h/'reference.ivf'),'-map','0:v','-c:v','copy','-bsf:v','trace_headers','-f','rawvideo',str(h/'copy.bin')],stdout=out,stderr=out,check=True)
 trace=(h/'trace.log').read_text()
 for name,value in [('base_q_idx',4),('disable_cdf_update',1),('allow_screen_content_tools',0),('uniform_tile_spacing_flag',1),('tx_mode',2),('reduced_tx_set',0)]:
  assert re.search(r'\b'+name+r'\s+[^\n]*= '+str(value)+r'\s*$',trace,re.M),(name,value)
print('Actual AV1 encoder commands, native default CDF, Addrlib input planes, strict parser and independent exact-pixel roundtrip pass.')
