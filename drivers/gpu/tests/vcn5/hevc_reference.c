// SPDX-License-Identifier: MIT
// Proof inputs only; generic headers/decode, codec, sizing and flags execute
// unchanged primary source blocks. Surfaces come from actual GFX12 Addrlib.
#include "primary.h"
static void dump(const void*p,size_t n){const uint8_t*b=p;for(size_t i=0;i<n;i++)printf("%02x",b[i]);puts("");}
int main(int argc,char**argv){
    assert(argc==10);unsigned bsd=(unsigned)strtoul(argv[1],NULL,10);bool ten=atoi(argv[2])==10;
    struct ac_vcn_decoder dec={0};dec.vcn_version=VCN_5_0_0;dec.base.ip_type=AMD_IP_VCN_UNIFIED;
    dec.base.param=(struct ac_video_dec_session_param){.codec=AC_VIDEO_CODEC_HEVC,.sub_sample=AC_VIDEO_SUBSAMPLE_420,.max_width=128,.max_height=128,.max_bit_depth=ten?10:8,.max_num_ref=3};
    dec.stream_handle=ten?0x4e415202:0x4e415201;primary_mode(&dec);
    struct radeon_info info={.vcn_ip_version=dec.vcn_version};
    dec.dpb_alignment=ac_vcn_dec_dpb_alignment(&info,&dec.base.param);dec.hw_ctx_size=calc_ctx_size_hevc(&dec);
    _Alignas(uint32_t) uint8_t create[56]={0};struct ac_video_dec_create_cmd create_cmd={.embedded_ptr=create};
    dump(create,primary_create(&dec.base,&create_cmd));
    _Alignas(uint32_t) uint8_t embedded[16384]={0};dec.feedback_offset=8192;dec.it_probs_offset=12288;
    struct radeon_surf y={0},uv={0};
    y.u.gfx9.surf_pitch=strtoul(argv[3],NULL,10);uv.u.gfx9.surf_pitch=strtoul(argv[4],NULL,10);
    y.u.gfx9.surf_height=strtoul(argv[5],NULL,10);uv.u.gfx9.surf_height=strtoul(argv[6],NULL,10);
    y.total_size=strtoull(argv[7],NULL,10);uv.total_size=strtoull(argv[8],NULL,10);
    struct ac_video_dec_decode_cmd cmd={.embedded_ptr=embedded,.embedded_va=0x100000,.session_va=0x200000,.bitstream_va=0x300000,.width=128,.height=128,.bitstream_size=bsd,.tier=AC_VIDEO_DEC_TIER0};
    cmd.decode_surface.format=ten?0:PIPE_FORMAT_NV12;
    cmd.decode_surface.planes[0].surf=&y;cmd.decode_surface.planes[0].va=0x400000;
    cmd.decode_surface.planes[1].surf=&uv;cmd.decode_surface.planes[1].va=cmd.decode_surface.planes[0].va+strtoull(argv[9],NULL,10);
    cmd.ref_surfaces[0].size=ac_vcn_dec_dpb_size(&info,&dec.base.param);
    struct ac_video_dec_hevc *hevc=&cmd.codec_param.hevc;
    hevc->pps_flags.pps_loop_filter_across_slices_enabled_flag=1;hevc->pps_flags.pps_deblocking_filter_disabled_flag=1;
    hevc->chroma_format_idc=1;hevc->log2_max_pic_order_cnt_lsb_minus4=4;hevc->sps_max_dec_pic_buffering_minus1=2;
    hevc->log2_diff_max_min_luma_coding_block_size=3;hevc->log2_diff_max_min_transform_block_size=3;hevc->pic_flags.is_ref_pic_flag=1;
    for(unsigned i=0;i<H265_MAX_NUM_REF_PICS;i++)hevc->ref_pic_id_list[i]=0x7f;
    memset(hevc->ref_pic_set_st_curr_before,255,sizeof(hevc->ref_pic_set_st_curr_before));memset(hevc->ref_pic_set_st_curr_after,255,sizeof(hevc->ref_pic_set_st_curr_after));memset(hevc->ref_pic_set_lt_curr,255,sizeof(hevc->ref_pic_set_lt_curr));
    memset(hevc->scaling_list_4x4,16,sizeof(hevc->scaling_list_4x4));memset(hevc->scaling_list_8x8,16,sizeof(hevc->scaling_list_8x8));memset(hevc->scaling_list_16x16,16,sizeof(hevc->scaling_list_16x16));memset(hevc->scaling_list_32x32,16,sizeof(hevc->scaling_list_32x32));memset(hevc->scaling_list_dc_coef_16x16,16,sizeof(hevc->scaling_list_dc_coef_16x16));memset(hevc->scaling_list_dc_coef_32x32,16,sizeof(hevc->scaling_list_dc_coef_32x32));
    if(ten){hevc->bit_depth_luma_minus8=2;hevc->bit_depth_chroma_minus8=2;}
    unsigned size=primary_decode(&dec.base,&cmd);dump(embedded,size);
    const uint8_t *scaling=embedded+dec.it_probs_offset;
    for(unsigned i=0;i<sizeof(rvcn_dec_hevc_its_t);i++)assert(scaling[i]==16);
    uint32_t destroy[6]={40,24,0,2,dec.stream_handle,0};dump(destroy,sizeof(destroy));
}
