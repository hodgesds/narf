// SPDX-License-Identifier: MIT
// Fixture inputs + actual primary generic/Tier3/VP9/probability/IB constructors.
#include "primary.h"
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
    assert(argc==19);unsigned bsd=strtoul(argv[1],NULL,10), depth=strtoul(argv[18],NULL,10);
    uint64_t at[9];for(unsigned i=0;i<9;i++)at[i]=strtoull(argv[9+i],NULL,10);
    struct ac_vcn_decoder dec={0};dec.vcn_version=VCN_5_0_0;dec.base.ip_type=AMD_IP_VCN_UNIFIED;
    dec.base.param=(struct ac_video_dec_session_param){.codec=AC_VIDEO_CODEC_VP9,.sub_sample=AC_VIDEO_SUBSAMPLE_420,.max_width=128,.max_height=128,.max_bit_depth=depth,.max_num_ref=9};
    dec.stream_handle=depth==10?0x4e415204:0x4e415203;primary_mode(&dec);dec.hw_ctx_size=calc_ctx_size_vp9(&dec);
    struct radeon_info info={.vcn_ip_version=dec.vcn_version};dec.dpb_alignment=ac_vcn_dec_dpb_alignment(&info,&dec.base.param);
    _Alignas(uint32_t) uint8_t create[56]={0};struct ac_video_dec_create_cmd create_cmd={.embedded_ptr=create};dump(create,primary_create(&dec.base,&create_cmd));
    _Alignas(uint32_t) uint8_t emb[16384]={0};dec.it_probs_offset=at[7]-at[2];dec.feedback_offset=at[5]-at[2];
    struct radeon_surf y={0},uv={0};y.u.gfx9.surf_pitch=strtoul(argv[2],NULL,10);uv.u.gfx9.surf_pitch=strtoul(argv[3],NULL,10);
    y.u.gfx9.surf_height=strtoul(argv[4],NULL,10);uv.u.gfx9.surf_height=strtoul(argv[5],NULL,10);y.total_size=strtoull(argv[6],NULL,10);uv.total_size=strtoull(argv[7],NULL,10);
    struct ac_video_dec_decode_cmd cmd={.embedded_ptr=emb,.embedded_va=at[2],.session_va=at[0],.bitstream_va=at[6],.width=128,.height=128,.bitstream_size=bsd,.tier=AC_VIDEO_DEC_TIER3};
    cmd.decode_surface.format=depth==10?2:PIPE_FORMAT_NV12;cmd.decode_surface.planes[0].surf=&y;cmd.decode_surface.planes[0].va=at[4];cmd.decode_surface.planes[1].surf=&uv;cmd.decode_surface.planes[1].va=at[4]+strtoull(argv[8],NULL,10);
    struct ac_video_dec_vp9 *vp9=&cmd.codec_param.vp9;vp9->pic_flags.error_resilient_mode=1;vp9->pic_flags.frame_parallel_decoding_mode=1;vp9->pic_flags.show_frame=1;vp9->pic_flags.use_uncompressed_header=1;
    vp9->color_config_flags.subsampling_x=vp9->color_config_flags.subsampling_y=1;
    vp9->bit_depth_luma_minus8=vp9->bit_depth_chroma_minus8=depth-8;
    vp9->width=vp9->height=128;vp9->loop_filter.loop_filter_flags.mode_ref_delta_enabled=vp9->loop_filter.loop_filter_flags.mode_ref_delta_update=1;
    vp9->loop_filter.loop_filter_ref_deltas[0]=1;vp9->loop_filter.loop_filter_ref_deltas[2]=vp9->loop_filter.loop_filter_ref_deltas[3]=-1;
    vp9->compressed_header_size=10;vp9->uncompressed_header_size=18;
    for(unsigned i=0;i<VP9_NUM_REF_FRAMES;i++){vp9->ref_frame_id_list[i]=0x7f;}for(unsigned i=0;i<VP9_TOTAL_REFS_PER_FRAME;i++){vp9->ref_frames[i]=0x7f;}
    unsigned size=primary_decode(&dec.base,&cmd);dump(emb,size);
    uint32_t destroy[6]={40,24,0,2,dec.stream_handle,0};dump(destroy,sizeof(destroy));
    rvcn_dec_vp9_probs_t probabilities={0};ac_vcn_vp9_fill_probs_table(&probabilities);dump(&probabilities,sizeof(probabilities));
    descriptor(&dec,at[0],at[1],false);descriptor(&dec,at[0],at[2],true);descriptor(&dec,at[0],at[3],false);
}
