from pathlib import Path
import re
import argparse,sys,subprocess,tempfile
p=argparse.ArgumentParser(description="Compare fixed HEVC encode/roundtrip with unchanged Mesa26.2.4 constructors and independent FFmpeg.")
p.add_argument('mesa',type=Path);p.add_argument('--ffmpeg',type=Path)
p.add_argument('--build-dir',type=Path)
p.add_argument('--surface-build-dir',type=Path)
args=p.parse_args();m=args.mesa.resolve();gpu=Path(__file__).resolve().parents[2];temporary=None if args.build_dir else tempfile.TemporaryDirectory(prefix='narf-hevc-encode-');r=args.build_dir or Path(temporary.name);r.mkdir(parents=True,exist_ok=True);h=r;mm=m/'src/gallium/drivers/radeonsi/mm'
def block(s,marker):
 a=s.index(marker);o=s.index('{',a);d=1;e=o+1
 while d:d+=(s[e]=='{')-(s[e]=='}');e+=1
 return s[a:e]
def func(s,name):
 a=re.search(r'^(?:static )?(?:void|unsigned int|unsigned|uint32_t|bool|int)\s+'+name+r'\(',s,re.M)
 assert a,name
 return block(s[a.start():],a[0])
state=(m/'src/gallium/include/pipe/p_video_state.h').read_text()
structs=state[state.index('struct pipe_h265_st_ref_pic_set\n'):state.index('struct pipe_h265_enc_rate_control\n')]
constants=set(re.findall(r'\bPIPE_[A-Z0-9_]+\b',structs))
allheaders='\n'.join(p.read_text(errors='ignore')for p in (m/'src/gallium/include/pipe').glob('*.h'))
defs=[]
for name in sorted(constants):
 mat=re.search(r'^#define\s+'+name+r'\s+([^\n]+)',allheaders,re.M)
 assert mat,name
 defs.append('#define '+name+' '+mat[1])
bshead=(mm/'radeon_bitstream.h').read_text();bsstruct=bshead[bshead.index('struct radeon_bitstream {'):bshead.index('void radeon_bs_h264_sps')]
source=(mm/'radeon_bitstream.c').read_text()
common=source[source.index('static const uint32_t'):source.index('static void radeon_bs_h264_hrd_parameters')]
hevc=source[source.index('static void radeon_bs_hevc_profile_tier('):source.index('static void radeon_bs_code_leb128(')]
header='\n'.join([source[:source.index('#include')],'#include <stdint.h>\n#include <stdbool.h>\n#include <string.h>\n#include <stdio.h>\n#include <assert.h>\n#define PIPE_H2645_EXTENDED_SAR 255\nstruct radeon_cmdbuf {struct {uint32_t *buf;unsigned cdw;}current;};','\n'.join(defs),structs,bsstruct,common,hevc])
(h/'header_funcs.h').write_text(header)
state=(m/'src/gallium/include/pipe/p_video_state.h').read_text()
pieces=[(h/'header_funcs.h').read_text(),'#include <stdlib.h>\n#include "ac_vcn_enc.h"\n']
for n in ['pipe_h2645_enc_picture_type','pipe_av1_enc_frame_type']:
 pieces.append(block(state,'enum '+n)+';')
pieces.append('struct pipe_h265_enc_picture_desc {struct pipe_h265_enc_seq_param seq;struct pipe_h265_enc_pic_param pic;struct pipe_h265_enc_slice_param slice;};')
hdr=(mm/'radeon_vcn_enc.h').read_text();pieces.append(block(hdr,'struct radeon_enc_pic {')+';')
pieces.append('''
enum pipe_video_format {PIPE_VIDEO_FORMAT_MPEG4_AVC,PIPE_VIDEO_FORMAT_HEVC,PIPE_VIDEO_FORMAT_AV1};
#define align(n,a) (((n)+(a)-1)&~((a)-1))
#define MAX2(a,b) ((a)>(b)?(a):(b))
#define DIV_ROUND_UP(n,d) (((n)+(d)-1)/(d))
#define UNREACHABLE(...) abort()
#define u_reduce_video_profile(p) (p)
#define util_logbase2_ceil(x) ((x)<=1?0:32-__builtin_clz((x)-1))
#define RADEON_DOMAIN_VRAM 1
#define RADEON_DOMAIN_GTT 2
#define RADEON_ENC_ERR(...) abort()
struct resource {uint64_t buf;unsigned domains;};
struct surface {unsigned meta_offset; struct {struct {unsigned surf_pitch,swizzle_mode;uint64_t surf_offset;}gfx9;}u;};
struct si_screen {struct {enum vcn_version vcn_ip_version;}info;};
struct radeon_encoder {
 struct {unsigned profile,width,height;}base;
 void *screen;unsigned alignment,dpb_size,metadata_size,dpb_slots;struct radeon_cmdbuf cs;rvcn_enc_cmd_t cmd;struct radeon_enc_pic enc_pic;
 struct {struct {bool dependent_slice_segments;}hevc;}*caps;
 struct resource *si,*dpb,*meta,*stats,*roi;struct {struct resource *res;}*fb;
 struct surface *luma,*chroma;
 uint64_t handle,bs_handle;unsigned bs_size,bs_offset,total_task_size;uint32_t *p_task_size;
};
''')
a=hdr.index('#define RADEON_ENC_CS');b=hdr.index('#define RADEON_ENC_ADDR_SWAP');macros=hdr[a:b];macros=re.sub(r'#define RADEON_ENC_READ\(buf, domain, off\).*?#define RADEON_ENC_END\(\)', '''#define RADEON_ENC_READ(buf,domain,off) addr(enc,(buf)+(off))
#define RADEON_ENC_WRITE(buf,domain,off) addr(enc,(buf)+(off))
#define RADEON_ENC_READWRITE(buf,domain,off) addr(enc,(buf)+(off))
#define RADEON_ENC_END()''',macros,flags=re.S);pieces.append(macros)
pieces.append('static void addr(struct radeon_encoder *enc,uint64_t a){RADEON_ENC_CS(a>>32);RADEON_ENC_CS((uint32_t)a);}')
# Unchanged command table initialization, real primary enum values.
cmd=(m/'src/amd/common/ac_vcn_enc.c').read_text();pieces.append(cmd[cmd.index('#define RENCODE_IB_PARAM_SESSION_INFO'):cmd.index('void ac_vcn_enc_init_cmds')]+func(cmd,'ac_vcn_enc_init_cmds'))
pieces.append(func((mm/'radeon_vcn_enc.c').read_text(),'radeon_enc_h2645_picture_type'))
pieces.append('static unsigned radeon_enc_av1_picture_type(unsigned x){(void)x;abort();}')
versions={v:(mm/('radeon_vcn_enc_'+v+'.c')).read_text()for v in ['1_2','2_0','5_0']}
select={
'1_2':['session_info','task_info','layer_control','layer_select','slice_control_hevc','rc_session_init','rc_layer_init','slice_header_hevc','bitstream','feedback','intra_refresh','qp_map','encode_latency','op_init','op_close','op_enc','op_init_rc','op_init_rc_vbv'],
'2_0':['quality_params','loop_filter_hevc','input_format'],
'5_0':['session_init','encode_params','encode_params_hevc','spec_misc_hevc','ref_swizzle_mode','ctx','ctx_override','metadata','output_format','rc_per_pic']}
for n in ['get_rec_alignment','radeon_enc_rec_offset','radeon_enc_rec_meta_offset','pre_encode_size','setup_dpb']:
 pieces.append(func((mm/'radeon_vcn_enc.c').read_text(),n))
for v,names in select.items():
 for n in names:pieces.append(func(versions[v],'radeon_enc_'+n))
(h/'enc_primary.h').write_text('\n'.join(pieces))

subprocess.run(['cc','-std=gnu11','-Wall','-Wextra','-Werror','-Wno-sign-compare','-Wno-unused-function','-Wno-unused-parameter','-I'+str(m/'src/amd/common'),'-I'+str(h),str(Path(__file__).with_name('hevc_encode_reference.c')),'-o',str(h/'enc')],check=True)
fixture=gpu/'fixtures/vcn5/hevc_encode'
# Actual primary plane-format mapping and GFX12 Addrlib supply encoder input
# and decoder target surfaces, rather than hand-entered pitch assumptions.
import json
surfaces=h/'surfaces.json'
subprocess.run([sys.executable,str(Path(__file__).with_name('hevc_surface_check.py')),str(m),'--gpu',str(gpu),'--width','384','--height','128','--build-dir',str(args.surface_build_dir or h/'surfaces'),'--emit-json',str(surfaces)],check=True)
layouts=json.loads(surfaces.read_text())
input_layout=next(row for row in layouts if row['policy']==256 and row['depth']==8)
target_layout=next(row for row in layouts if row['policy']==0 and row['depth']==8)
for row in layouts:
 if row['depth']==8:
  ref=input_layout if row['policy']==256 else target_layout
  assert all(row[k]==ref[k] for k in ['y_pitch','uv_pitch','uv_offset','target_size'])

assert subprocess.check_output([str(h/'enc')])==(fixture/'headers.bin').read_bytes()
import hashlib,json
manifest=json.loads((fixture/'manifest.json').read_text())
for name,info in manifest['files'].items():
 data=(fixture/name).read_bytes();assert len(data)==info['bytes'];assert hashlib.sha256(data).hexdigest()==info['sha256']
rust="""extern crate alloc;#[derive(Debug,PartialEq,Eq)]enum Error{Invalid,EncodeOutput,Unsupported}
#[allow(dead_code)]#[path=\"ENC\"]mod e;
#[allow(dead_code)]#[path=\"DEC\"]mod d;
fn main(){let b=0x810000000;for at in [e::SESSION,e::CPB,e::INPUT,e::METADATA,e::OUTPUT,e::FEEDBACK]{print!(\"{} \",b+at);}println!(\"{}\",e::OUTPUT_BYTES);for p in [e::Phase::Create,e::Phase::Encode,e::Phase::Destroy]{for w in e::ib(b,p,0x1000a).unwrap(){print!(\"{w:08x} \");}println!();}
for minor in 0..=255 {let fw=(1<<20)|(minor<<12);assert_eq!(e::interface(fw),if minor<8 {None}else{Some(0x10000|minor.min(10))});}assert_eq!(e::interface(0),None);assert_eq!(e::interface(2<<20|10<<12),None);
assert!(e::ib(b,e::Phase::Encode,0x10007).is_err());assert!(e::ib(b,e::Phase::Encode,0x2000a).is_err());
let stream=include_bytes!(\"STREAM\");assert!(e::valid_output(stream));assert_eq!(e::HEADER_PREFIX%16,0);assert!(e::HEADERS.len()as u64<=e::HEADER_PREFIX);
for i in [0,4,1<<48,(1<<48)-4096]{assert!(e::ib(i,e::Phase::Encode,0x1000a).is_err());assert!(d::ib(i,d::Phase::Decode).is_err());}
assert!(d::decode_message(0).is_err());assert!(d::decode_message(d::BITSTREAM_BYTES as u32+1).is_err());
for byte in d::create_message(){print!(\"{byte:02x}\");}println!();for byte in d::decode_message(stream.len()as u32).unwrap(){print!(\"{byte:02x}\");}println!();for byte in d::destroy_message(){print!(\"{byte:02x}\");}println!();
for i in 0..stream.len(){let mut v=stream.to_vec();v.truncate(i);if i<=e::HEADER_PREFIX as usize+8{assert!(!e::valid_output(&v));}}
for i in 0..e::HEADERS.len(){let mut v=stream.to_vec();v[i]^=1;assert!(!e::valid_output(&v));}
for byte in [0,1,2,3,4,5,6,7,8,255]{let mut v=stream.to_vec();v[e::HEADER_PREFIX as usize+4]=byte;assert!(!e::valid_output(&v));}
}""".replace('ENC',str(gpu/'src/amdgpu_vcn_navi48_hevc_encode_words.rs')).replace('DEC',str(gpu/'src/amdgpu_vcn_navi48_hevc_roundtrip_words.rs')).replace('\"STREAM\"','\"'+str(fixture/'reference.hevc')+'\"')
(h/'words.rs').write_text(rust);subprocess.run(['rustc','--edition=2021',str(h/'words.rs'),'-o',str(h/'words')],check=True)
rows=subprocess.check_output([str(h/'words')],text=True).splitlines()
expected=subprocess.check_output([str(h/'enc')]+rows[0].split()+[str(input_layout[k])for k in ['y_pitch','uv_pitch','uv_offset']],text=True).splitlines()
assert [x.split()for x in rows[1:4]]==[x.split()for x in expected],'Encoder packets differ from unchanged Mesa'
# Execute existing checked primary extraction setup, retaining unchanged generic
# create/decode/header/context/DPB code rather than restating generic assignments.
from decode_primary import primary_pieces
(h/'primary.h').write_text('\n'.join(primary_pieces(m,'hevc'))+'\n')
# Exact producer SPS/PPS values are inputs to unchanged build_hevc_msg.
c=Path(__file__).with_name('hevc_reference.c').read_text().replace('.max_num_ref=3','.max_num_ref=2').replace('0x4e415201','0x4e415203').replace('hevc->pps_flags.pps_loop_filter_across_slices_enabled_flag=1;','hevc->sps_flags.strong_intra_smoothing_enabled_flag=1;').replace('sps_max_dec_pic_buffering_minus1=2','sps_max_dec_pic_buffering_minus1=1')
c=c.replace('.max_width=128','.max_width=384').replace('.width=128','.width=384')
(h/'roundtrip.c').write_text(c)
subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror','-Wno-sign-compare','-Wno-unused-but-set-variable','-Wno-unused-variable','-I'+str(h),str(h/'roundtrip.c'),'-lm','-o',str(h/'roundtrip')],check=True)
expected=subprocess.check_output([str(h/'roundtrip'),str((fixture/'reference.hevc').stat().st_size),'8']+[str(target_layout[k])for k in ['y_pitch','uv_pitch','y_height','uv_height','y_size','uv_size','uv_offset']],text=True).splitlines()
assert rows[4:7]==expected,'Roundtrip messages differ from unchanged Mesa'
# Compact output sample pitches/plane sizes match the already checked GFX12
# Addrlib oracle; execute it for both chip revisions when requested separately.
if args.ffmpeg:
 target=h/'decoded.i420';subprocess.run([str(args.ffmpeg),'-y','-v','error','-i',str(fixture/'reference.hevc'),'-frames:v','1','-pix_fmt','yuv420p','-f','rawvideo',str(target)],check=True)
 b=target.read_bytes();n=384*128;assert len(b)==n*3//2
 nv12=b[:n]+bytes(v for pair in zip(b[n:n+n//4],b[n+n//4:])for v in pair)
 assert nv12==(fixture/'frame.bin').read_bytes(),'Independent roundtrip differs from source'
print('Exact HEVC encoder packets, CPU headers, dynamic decoder messages and independent fixture roundtrip pass.')
