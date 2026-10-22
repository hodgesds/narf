"""Extract unchanged Mesa common VCN encoder constructors for host oracles.
Address/resource adapters only replace host winsys storage, not packet logic.
"""
from pathlib import Path
import re

def primary_encoder(m:Path,h:Path):
    mm=m/'src/gallium/drivers/radeonsi/mm'
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

    return block
