# SPDX-License-Identifier: MIT
"""Extract unchanged VCN decode primary blocks for fixed-proof references."""
from pathlib import Path
import re

def primary_pieces(mesa,codec='hevc'):
    h=(mesa/'src/amd/common/ac_vcn_dec.h').read_text()
    c=(mesa/'src/amd/common/ac_vcn_dec.c').read_text()
    v=(mesa/'src/amd/common/ac_video_dec.h').read_text()

    def func(source,name):
        match=re.search(r'^'+name+r'\s*\(',source,re.M)
        start=source.rfind('\nstatic ',0,match.start())+1
        opening=source.index('{',match.start());depth=1;end=opening+1
        while depth:
            depth+=(source[end]=='{')-(source[end]=='}');end+=1
        return source[start:end]

    def structure(source,name):
        match=re.search(r'typedef struct '+name+r'\s*\{',source)
        opening=source.index('{',match.start());depth=1;end=opening+1
        while depth:depth+=(source[end]=='{')-(source[end]=='}');end+=1
        return source[match.start():source.index(';',end)+1]

    video=(mesa/'src/amd/common/ac_video.h').read_text()
    family=(mesa/'src/amd/common/amd_family.h').read_text()
    def enum(source,name):return re.search(r'enum '+name+r'\s*\{.*?\};',source,re.S)[0]
    def regular_struct(source,name):return re.search(r'struct '+name+r'\s*\{.*?\n\};',source,re.S)[0]
    def block(source,marker):
        start=source.index(marker);opening=source.index('{',start);depth=1;end=opening+1
        while depth:depth+=(source[end]=='{')-(source[end]=='}');end+=1
        return source[start:end]
    pieces=[h[:h.index('#ifndef')],v[:v.index('#ifndef')],video[:video.index('#ifndef')],family[:family.index('#ifndef')],c[:c.index('#include')], '#include <stdint.h>\n#include <stdbool.h>\n#include <string.h>\n#include <stdio.h>\n#include <stddef.h>\n#include <assert.h>\n#include <stdlib.h>\n#include <math.h>']
    pieces+=re.findall(r'^#define H265_\w+[^\n]*',v,re.M)
    pieces+=re.findall(r'^#define RDECODE_(?:CMD|CMDBUF|MESSAGE|CODEC|MSG|ARRAY_MODE|VCN5|FLAGS|AV1_VER|IB_PARAM)\w+[^\n]*',h,re.M)
    pieces+=['#define RDECODE_PKT0(index,count) ((index)|((count)<<16))','#define RDECODE_SESSION_CONTEXT_SIZE (128*1024)', '#define align(n,a) (((n)+(a)-1)&~((a)-1))','#define DIV_ROUND_UP(n,d) (((n)+(d)-1)/(d))','#define MAX2(a,b) ((a)>(b)?(a):(b))','#define UNREACHABLE(s) abort()']
    for source,name in [(video,'ac_video_codec'),(video,'ac_video_subsample'),(video,'ac_video_dec_tier'),(v,'ac_video_dec_protected_content'),(family,'vcn_version')]:pieces.append(enum(source,name))
    if codec=='vp9':
        pieces+=re.findall(r'^#define VP9_\w+[^\n]*',v,re.M)
        pieces+=re.findall(r'^#define RDECODE_(?:FRAME_HDR_INFO_VP9_|VP9_PROBS_DATA_SIZE)\w*[^\n]*',h,re.M)
        pieces+=['#define CLAMP(n,a,b) ((n)<(a)?(a):((n)>(b)?(b):(n)))',enum(v,'ac_video_dec_vp9_seg_level_features'),regular_struct(v,'ac_video_dec_vp9')]
        for name in ['rvcn_dec_message_vp9_s','rvcn_dec_vp9_nmv_ctx_mask_s','rvcn_dec_vp9_nmv_component_s','rvcn_dec_vp9_probs_s','rvcn_dec_vp9_probs_segment_s','rvcn_dec_ref_buffer_s','rvcn_dec_ref_buffers_header_s']:pieces.append(structure(h,name))
        pieces.append((mesa/'src/amd/common/ac_vcn_vp9_default.h').read_text())
    if codec=='av1':
        pieces+=re.findall(r'^#define AV1_\w+[^\n]*',v,re.M)
        pieces+=re.findall(r'^#define RDECODE_FRAME_HDR_INFO_AV1_\w+[^\n]*',h,re.M)
        pieces.append((mesa/'src/amd/common/ac_vcn_av1_default.h').read_text())
        pieces.append(regular_struct(v,'ac_video_dec_av1_ref_frame'))
        pieces.append(regular_struct(v,'ac_video_dec_av1'))
        pieces.append(re.search(r'typedef enum\s*\{[^}]*RVCN_DEC_AV1_IDENTITY[^}]*\}\s*rvcn_dec_transformation_type_e;',h,re.S)[0])
        for name in ['rvcn_dec_warped_motion_params_t','rvcn_dec_film_grain_params_t']:
            pieces.append(re.search(r'typedef struct\s*\{[^}]*\}\s*'+name+';',h,re.S)[0])
        for name in ['rvcn_dec_av1_tile_info_s','rvcn_dec_message_av1_s','rvcn_dec_av1_fg_init_buf_s','rvcn_dec_av1_segment_fg_s','rvcn_dec_ref_buffer_s','rvcn_dec_ref_buffers_header_s']:
            pieces.append(structure(h,name))
        # Film grain is excluded by this bounded keyframe fixture. The exact
        # builder still rejects an accidental call into an untested host path.
        pieces.append('static void ac_vcn_av1_init_film_grain_buffer(unsigned v,rvcn_dec_film_grain_params_t *p,rvcn_dec_av1_fg_init_buf_t *b){(void)v;(void)p;(void)b;abort();}')
        for name in ['ac_vcn_dec_frame_ctx_size_av1','ac_vcn_dec_calc_ctx_size_av1','ac_vcn_av1_init_mode_probs','ac_vcn_av1_init_mv_probs','ac_vcn_av1_default_coef_probs','ac_vcn_vcn4_av1_init_mode_probs','ac_vcn_vcn4_av1_init_mv_probs','ac_vcn_vcn4_av1_default_coef_probs','ac_vcn_av1_init_probs']:
            pieces.append(func(c,name))
    pieces.append(regular_struct(v,'ac_video_dec_hevc'));pieces.append(regular_struct(v,'ac_video_dec_session_param'))
    for name in ['rvcn_dec_message_index_s','rvcn_dec_message_header_s','rvcn_dec_message_create_s','rvcn_dec_message_decode_s','rvcn_dec_message_hevc_s','rvcn_dec_hevc_its_s','rvcn_dec_message_drm_s','rvcn_dec_message_drm_keyblob_s','rvcn_dec_message_dynamic_dpb_s','rvcn_dec_message_dynamic_dpb_t2_s','rvcn_decode_buffer_s','rvcn_decode_ib_package_s','rvcn_dec_feature_index_s','rvcn_dec_feedback_header_s']:pieces.append(structure(h,name))
    pieces+=['#define PIPE_FORMAT_NV12 1\n#define RDECODE_DITHERING_RANDOM 5',
    """enum {AMD_IP_VCN_DEC,AMD_IP_VCN_UNIFIED};
    struct radeon_info {enum vcn_version vcn_ip_version;};
    struct radeon_surf {uint64_t total_size;uint32_t tile_swizzle;union {struct {unsigned surf_pitch,surf_height,swizzle_mode;uint64_t surf_slice_size;}gfx9;}u;};
    struct ac_video_surface {int format;uint64_t size;struct {uint64_t va;struct radeon_surf *surf;}planes[3];};
    struct ac_video_dec {struct ac_video_dec_session_param param;int ip_type;};
    struct ac_vcn_decoder {struct ac_video_dec base;unsigned stream_handle,addr_mode,av1_version,hw_ctx_size,dpb_alignment,it_probs_offset,feedback_offset,subsample_offset;enum vcn_version vcn_version;struct {unsigned data0,data1,cmd;}reg;};
    struct ac_video_dec_create_cmd {void *embedded_ptr;};
    struct ac_video_dec_decode_cmd {void *embedded_ptr;uint64_t embedded_va,session_va,session_tmz_va,bitstream_va;unsigned width,height,bitstream_size,tier,num_refs;bool low_latency;struct {int mode;}protected_content;struct {struct ac_video_dec_hevc hevc;struct {int profile;}vc1;}codec_param;struct ac_video_surface decode_surface,ref_surfaces[1];};
    struct ac_cmdbuf {unsigned dummy;};
    struct cmd_buffer {struct ac_vcn_decoder *dec;struct ac_cmdbuf cs;void *it_probs_ptr;uint32_t decode_buffer_flags;rvcn_decode_buffer_t *decode_buffer;};
    #define ac_cmdbuf_begin(cs) ((void)(cs))
    #define ac_cmdbuf_emit(x) ((void)(x))
    #define ac_cmdbuf_end() ((void)0)
    static void ac_vcn_dec_init_regs(void *p,enum vcn_version v) {(void)p;(void)v;}
    """,func(c,'build_hevc_msg'),func(c,'stream_type'),func(c,'calc_ctx_size_hevc')]
    pieces.append('uint32_t ac_vcn_dec_dpb_alignment(const struct radeon_info *,struct ac_video_dec_session_param *);')
    # These public functions have no static qualifier; preserve their full bodies.
    for name in ['ac_vcn_dec_dpb_alignment','ac_vcn_dec_dpb_size']:
        m=re.search(r'^'+name+r'\s*\(',c,re.M);start=c.rfind('uint32_t',0,m.start());op=c.index('{',m.start());depth=1;end=op+1
        while depth:depth+=(c[end]=='{')-(c[end]=='}');end+=1
        pieces.append(c[start:end])
    pieces.append(func(c,'send_cmd'))
    create=func(c,'vcn_build_create_cmd');body=create[create.index('{')+1:create.index('   struct cmd_buffer cmd_buf')]
    pieces.append('static unsigned primary_create(struct ac_video_dec *decoder,struct ac_video_dec_create_cmd *cmd){'+body+'return header->total_size;}')
    init=c[c.index('   switch (dec->vcn_version)',c.index('ac_vcn_create_video_decoder(')):];init=block(init,'   switch (dec->vcn_version)')
    pieces.append('static void primary_mode(struct ac_vcn_decoder *dec){'+init+'}')
    decode=func(c,'vcn_build_decode_cmd');prefix=decode[decode.index('{')+1:decode.index('   struct cmd_buffer cmd_buf')]
    codec_branch=decode[decode.index('      index_codec->message_id = RDECODE_MESSAGE_HEVC;'):decode.index('   case AC_VIDEO_CODEC_VP9:',decode.index('      index_codec->message_id = RDECODE_MESSAGE_HEVC;'))].replace('      break;','')
    finish=decode[decode.index('   if (codec_size == 0)'):decode.index('   } else if (cmd->tier == AC_VIDEO_DEC_TIER1)',decode.index('   if (codec_size == 0)'))]+'   }\n'
    feedback=block(decode,'   if (dec->feedback_offset)')
    bind=decode[decode.index('   send_cmd(&cmd_buf, RDECODE_CMD_SESSION_CONTEXT_BUFFER'):decode.index('   if (decoder->ip_type == AMD_IP_VCN_UNIFIED)',decode.index('   send_cmd(&cmd_buf, RDECODE_CMD_SESSION_CONTEXT_BUFFER'))]
    pieces.append('static unsigned primary_decode(struct ac_video_dec *decoder,struct ac_video_dec_decode_cmd *cmd){'+prefix+'struct cmd_buffer cmd_buf={.dec=dec,.it_probs_ptr=emb+dec->it_probs_offset};rvcn_decode_buffer_t buffers={0};cmd_buf.decode_buffer=&buffers;uint32_t codec_size=0;'+codec_branch+finish+feedback+bind+'return header->total_size;}')
    if codec in ('vp9','av1'):
        # Only host input scaffolding changes. All executable codec/generic
        # assignments and Tier3 packet construction remain original source.
        pieces=[piece.replace('struct ac_video_dec_hevc hevc;struct', 'struct ac_video_dec_hevc hevc;struct ac_video_dec_'+codec+' '+codec+';struct').replace('struct ac_cmdbuf {unsigned dummy;};','struct ac_cmdbuf {uint32_t *buf;unsigned cdw,max_dw;};').replace('tier,num_refs;bool','tier,num_refs;unsigned ref_id[9];bool')for piece in pieces]
        pieces.insert(-1,func(c,'build_'+codec+'_msg'))
        sq=(mesa/'src/amd/common/ac_vcn.c').read_text();sqh=(mesa/'src/amd/common/ac_vcn.h').read_text()
        pieces.insert(-1,re.search(r'struct rvcn_sq_var\s*\{[^}]*\};',sqh)[0])
        pieces.insert(-1,'\n'.join(re.findall(r'^#define RADEON_VCN_\w+[^\n]*',sqh,re.M)))
        pieces.insert(-1,func(c,'add_ib_decode_buffer'))
        for name in ['ac_vcn_sq_header','ac_vcn_sq_tail']:
            m=re.search(r'^'+name+r'\s*\(',sq,re.M);start=sq.rfind('void',0,m.start());opening=sq.index('{',m.start());depth=1;end=opening+1
            while depth:depth+=(sq[end]=='{')-(sq[end]=='}');end+=1
            pieces.insert(-1,sq[start:end])
        pieces=[piece.replace('#define ac_cmdbuf_begin(cs) ((void)(cs))','#define ac_cmdbuf_begin(cs) struct ac_cmdbuf *emit_cs=(cs)').replace('#define ac_cmdbuf_emit(x) ((void)(x))','#define ac_cmdbuf_emit(x) (emit_cs->buf[emit_cs->cdw++]=(x))')for piece in pieces]
        if codec=='vp9':
            pieces.insert(-1,func(c,'calc_ctx_size_vp9'))
            pieces.insert(-1,func(c,'ac_vcn_vp9_fill_probs_table'))
        branch=decode[decode.index('      index_codec->message_id = RDECODE_MESSAGE_VP9;'):decode.index('   case AC_VIDEO_CODEC_AV1:',decode.index('      index_codec->message_id = RDECODE_MESSAGE_VP9;'))].replace('      break;','')
        if codec=='av1':
            branch=decode[decode.index('      index_codec->message_id = RDECODE_MESSAGE_AV1;'):decode.index('   case AC_VIDEO_CODEC_MPEG2:',decode.index('      index_codec->message_id = RDECODE_MESSAGE_AV1;'))].replace('      break;','')
        tier3=block(decode,'else if (cmd->tier == AC_VIDEO_DEC_TIER3)')
        pieces[-1]='static rvcn_decode_buffer_t primary_buffers;static uint32_t primary_cs_buffer[128];static unsigned primary_ref_dw;\nstatic unsigned primary_decode(struct ac_video_dec *decoder,struct ac_video_dec_decode_cmd *cmd){'+prefix+'struct cmd_buffer cmd_buf={.dec=dec,.it_probs_ptr=emb+dec->it_probs_offset,.decode_buffer=&primary_buffers,.cs={.buf=primary_cs_buffer,.max_dw=128}};uint32_t codec_size=0;'+branch+finish+tier3+feedback+bind+'primary_buffers.valid_buf_flag=cmd_buf.decode_buffer_flags;primary_ref_dw=cmd_buf.cs.cdw;return header->total_size;}'
    return pieces
