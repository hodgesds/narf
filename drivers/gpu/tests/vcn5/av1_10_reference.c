// SPDX-License-Identifier: MIT
// Fixture inputs + actual primary generic/Tier3/VP9/probability/IB constructors.
#include "primary.h"
// Host-only distinct format tags: unchanged codec code tests only NV12 equality.
// Real P010 sample bytes/geometry come from the unchanged format/Addrlib helper.
#define PIPE_FORMAT_P010 (PIPE_FORMAT_NV12 + 1)
static void dump(const void*p,size_t n){const uint8_t*b=p;for(size_t i=0;i<n;i++)printf("%02x",b[i]);puts("");}
static void descriptor(struct ac_vcn_decoder*dec,uint64_t session,uint64_t message,bool frame){
    uint32_t ib[64]={16,RADEON_VCN_SIGNATURE};struct ac_cmdbuf cs={.buf=ib+4,.max_dw=60};struct rvcn_sq_var sq={0};
    ac_vcn_sq_header(&cs,&sq,RADEON_VCN_ENGINE_TYPE_DECODE);rvcn_decode_buffer_t *buffer=add_ib_decode_buffer(&cs);
    if(frame){*buffer=primary_buffers;memcpy(cs.buf+cs.cdw,primary_cs_buffer,primary_ref_dw*4);cs.cdw+=primary_ref_dw;}
    else{struct cmd_buffer cb={.dec=dec,.decode_buffer=buffer};send_cmd(&cb,RDECODE_CMD_SESSION_CONTEXT_BUFFER,session);send_cmd(&cb,RDECODE_CMD_MSG_BUFFER,message);buffer->valid_buf_flag=cb.decode_buffer_flags;}
    ac_vcn_sq_tail(&cs,&sq);ib[3]=cs.cdw;for(unsigned i=4;i<cs.cdw+4;i++)ib[2]+=ib[i];
    for(unsigned i=0;i<cs.cdw+4;i++){printf("%s%08x",i?" ":"",ib[i]);}puts("");
}
int main(int argc,char**argv){
    assert(argc==19);unsigned bsd=strtoul(argv[1],NULL,10),scenario=strtoul(argv[18],NULL,10);
    uint64_t at[9];for(unsigned i=0;i<9;i++)at[i]=strtoull(argv[9+i],NULL,10);
    struct ac_vcn_decoder dec={0};dec.vcn_version=VCN_5_0_0;dec.base.ip_type=AMD_IP_VCN_UNIFIED;
    dec.base.param=(struct ac_video_dec_session_param){.codec=AC_VIDEO_CODEC_AV1,.sub_sample=AC_VIDEO_SUBSAMPLE_420,.max_width=256,.max_height=128,.max_bit_depth=10,.max_num_ref=9};
    dec.stream_handle=0x4e415207;primary_mode(&dec);dec.hw_ctx_size=ac_vcn_dec_calc_ctx_size_av1(dec.av1_version);
    struct radeon_info info={.vcn_ip_version=dec.vcn_version};dec.dpb_alignment=ac_vcn_dec_dpb_alignment(&info,&dec.base.param);
    _Alignas(uint32_t)uint8_t create[56]={0};struct ac_video_dec_create_cmd cc={.embedded_ptr=create};if(!scenario)dump(create,primary_create(&dec.base,&cc));
    _Alignas(uint32_t)uint8_t emb[65536]={0};dec.it_probs_offset=at[7]-at[2];dec.feedback_offset=at[5]-at[2];
    struct radeon_surf y={0},uv={0};y.u.gfx9.surf_pitch=strtoul(argv[2],NULL,10);uv.u.gfx9.surf_pitch=strtoul(argv[3],NULL,10);
    y.u.gfx9.surf_height=strtoul(argv[4],NULL,10);uv.u.gfx9.surf_height=strtoul(argv[5],NULL,10);y.total_size=strtoull(argv[6],NULL,10);uv.total_size=strtoull(argv[7],NULL,10);
    struct ac_video_dec_decode_cmd cmd={.embedded_ptr=emb,.embedded_va=at[2],.session_va=at[0],.bitstream_va=at[6],.width=256,.height=128,.bitstream_size=bsd,.tier=AC_VIDEO_DEC_TIER3};
    cmd.decode_surface.format=PIPE_FORMAT_P010;cmd.decode_surface.planes[0].surf=&y;cmd.decode_surface.planes[0].va=at[4];cmd.decode_surface.planes[1].surf=&uv;cmd.decode_surface.planes[1].va=at[4]+strtoull(argv[8],NULL,10);
    struct ac_video_dec_av1*a=&cmd.codec_param.av1;a->width=a->max_width=256;a->height=a->max_height=128;a->bit_depth=10;a->superres_denom=8;a->primary_ref_frame=7;a->pic_flags.show_frame=1;a->pic_flags.disable_cdf_update=1;a->pic_flags.disable_frame_end_update_cdf=1;a->pic_flags.ref_frame_update=1;
    a->quantization.qm_y=a->quantization.qm_u=a->quantization.qm_v=255;
    a->color_config_flags.subsampling_x=a->color_config_flags.subsampling_y=1;
    a->tile_info.tile_cols=a->tile_info.tile_rows=1;a->tile_info.tile_col_start_sb[1]=4;a->tile_info.tile_row_start_sb[1]=2;a->tile_info.tile_offset[0]=16;a->tile_info.tile_size[0]=180;
    const int8_t deltas[8]={1,0,0,0,-1,0,-1,-1};memcpy(a->loop_filter.loop_filter_ref_deltas,deltas,8);
    for(unsigned i=0;i<8;i++){a->ref_frame_id_list[i]=0x7f;a->global_motion.gm_params[i][2]=a->global_motion.gm_params[i][5]=1<<16;}
    for(unsigned i=0;i<7;i++){a->ref_frames[i].ref_id=0x7f;}
    if(scenario){
        a->quantization.base_q_idx=7;a->quantization.delta_q_y_dc=-2;
        a->quantization.delta_q_u_dc=a->quantization.delta_q_v_dc=3;
        a->quantization.delta_q_u_ac=a->quantization.delta_q_v_ac=-4;
        for(unsigned i=0;i<4;i++)a->loop_filter.loop_filter_level[i]=11+i;
        a->loop_filter.loop_filter_sharpness=5;
        a->loop_filter.loop_filter_flags.mode_ref_delta_enabled=1;
        a->loop_filter.loop_filter_flags.mode_ref_delta_update=1;
        for(unsigned i=0;i<8;i++)a->loop_filter.loop_filter_ref_deltas[i]=(int)i-2;
        a->loop_filter.loop_filter_mode_deltas[0]=-3;a->loop_filter.loop_filter_mode_deltas[1]=4;
        a->tx_mode=2;
    }
    dump(emb,primary_decode(&dec.base,&cmd));
    if(scenario)return 0;
    uint32_t destroy[6]={40,24,0,2,dec.stream_handle,0};dump(destroy,sizeof(destroy));
    unsigned frame_ctx=ac_vcn_dec_frame_ctx_size_av1(dec.av1_version);uint8_t*cdf=calloc(4,frame_ctx);
    ac_vcn_av1_init_probs(dec.av1_version,cdf);dump(cdf,frame_ctx*4);free(cdf);
    descriptor(&dec,at[0],at[1],false);descriptor(&dec,at[0],at[2],true);descriptor(&dec,at[0],at[3],false);
}
