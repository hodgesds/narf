// SPDX-License-Identifier: MIT
// Fixed original proof inputs; packet layouts execute unchanged Mesa functions.
#include "enc_primary.h"
static void dump(struct radeon_encoder *enc) {
 unsigned n=enc->cs.current.cdw;*enc->p_task_size=enc->total_task_size;
 uint32_t head[]={0x10,0x30000002,0,n-4,0x10,0x30000001,2,(n-4)*4};
 memcpy(enc->cs.current.buf,head,sizeof(head));
 for(unsigned i=4;i<n;i++)enc->cs.current.buf[2]+=enc->cs.current.buf[i];
 for(unsigned i=0;i<n;i++)printf("%08x ",enc->cs.current.buf[i]);
 puts("");
}
static void task(struct radeon_encoder *e,bool fb){e->cs.current.cdw=8;radeon_enc_session_info(e);e->total_task_size=0;radeon_enc_task_info(e,fb);}
static void headers(void){
 struct pipe_h265_enc_vid_param v={0}; struct pipe_h265_enc_seq_param s={0};struct pipe_h265_enc_pic_param p={0};
 v.vps_base_layer_internal_flag=1;v.vps_base_layer_available_flag=1;v.vps_temporal_id_nesting_flag=1;v.vps_max_dec_pic_buffering_minus1[0]=1;
 v.profile_tier_level.profile_tier.general_profile_idc=1;
 v.profile_tier_level.profile_tier.general_profile_compatibility_flag=0x60000000;
 v.profile_tier_level.profile_tier.general_progressive_source_flag=1;
 v.profile_tier_level.profile_tier.general_non_packed_constraint_flag=1;
 v.profile_tier_level.profile_tier.general_frame_only_constraint_flag=1;
 v.profile_tier_level.general_level_idc=60;
 s.profile_tier_level=v.profile_tier_level;s.sps_temporal_id_nesting_flag=1;s.chroma_format_idc=1;s.pic_width_in_luma_samples=384;s.pic_height_in_luma_samples=128;
 s.sps_max_dec_pic_buffering_minus1[0]=1;s.log2_max_pic_order_cnt_lsb_minus4=4;
 s.log2_min_luma_coding_block_size_minus3=0;s.log2_diff_max_min_luma_coding_block_size=3;
 s.log2_diff_max_min_transform_block_size=3;s.max_transform_hierarchy_depth_intra=0;s.max_transform_hierarchy_depth_inter=0;
 s.strong_intra_smoothing_enabled_flag=1;
 p.deblocking_filter_control_present_flag=1;p.pps_deblocking_filter_disabled_flag=1;
 uint8_t bytes[4096]={0};struct radeon_bitstream bs;
 radeon_bs_reset(&bs,bytes,NULL);radeon_bs_hevc_vps(&bs,&v);radeon_bs_hevc_sps(&bs,&s);radeon_bs_hevc_pps(&bs,&p);radeon_bs_flush_headers(&bs);
 fwrite(bytes,1,bs.bits_output/8,stdout);
}
static void speed(struct radeon_encoder *enc){RADEON_ENC_BEGIN(RENCODE_IB_OP_SET_SPEED_ENCODING_MODE);RADEON_ENC_END();}
int main(int argc,char**argv){if(argc==1){headers();return 0;}assert(argc==11);uint64_t session=strtoull(argv[1],0,0),cpb=strtoull(argv[2],0,0),input=strtoull(argv[3],0,0),metadata=strtoull(argv[4],0,0),out=strtoull(argv[5],0,0),feedback=strtoull(argv[6],0,0);unsigned output_size=strtoul(argv[7],0,0);
 uint32_t words[4096]={0};struct radeon_encoder enc={0},*e=&enc;enc.cs.current.buf=words;
 struct resource si={.buf=session},dpb={.buf=cpb},meta={.buf=metadata},fb={.buf=feedback};
 enc.si=&si;enc.dpb=&dpb;enc.meta=&meta;enc.bs_handle=out;enc.bs_size=output_size;enc.bs_offset=80;
 typeof(*enc.fb) f={.res=&fb};enc.fb=&f;
 typeof(*enc.caps) caps={.hevc.dependent_slice_segments=true};enc.caps=&caps;
 struct surface y={.u.gfx9={.surf_pitch=strtoul(argv[8],0,0)}},uv={.u.gfx9={.surf_pitch=strtoul(argv[9],0,0),.surf_offset=strtoull(argv[10],0,0)}};enc.handle=input;enc.luma=&y;enc.chroma=&uv;enc.base.profile=PIPE_VIDEO_FORMAT_HEVC;
 ac_vcn_enc_init_cmds(&enc.cmd,VCN_5_0_0);
 struct pipe_h265_enc_picture_desc pic={0};enc.enc_pic.hevc.desc=&pic;
 enc.enc_pic.picture_type=PIPE_H2645_ENC_PICTURE_TYPE_IDR;enc.enc_pic.nal_unit_type=19;
 enc.enc_pic.num_temporal_layers=1;enc.enc_pic.session_info.interface_version=0x1000a;
 enc.enc_pic.session_init.aligned_picture_width=384;enc.enc_pic.session_init.aligned_picture_height=128;
 enc.enc_pic.rc_session_init.vbv_buffer_level=48;
 enc.enc_pic.rc_layer_init[0].frame_rate_num=25;enc.enc_pic.rc_layer_init[0].frame_rate_den=1;
 enc.enc_pic.rc_per_pic.qp_i=20;enc.enc_pic.rc_per_pic.qp_p=20;enc.enc_pic.rc_per_pic.qp_b=20;
 enc.enc_pic.rc_per_pic.max_qp_i=51;enc.enc_pic.rc_per_pic.max_qp_p=51;enc.enc_pic.rc_per_pic.max_qp_b=51;
 enc.enc_pic.hevc_slice_ctrl.fixed_ctbs_per_slice.num_ctbs_per_slice=12;enc.enc_pic.hevc_slice_ctrl.fixed_ctbs_per_slice.num_ctbs_per_slice_segment=12;
 enc.enc_pic.hevc_spec_misc.amp_disabled=1;enc.enc_pic.hevc_spec_misc.strong_intra_smoothing_enabled=1;enc.enc_pic.hevc_spec_misc.half_pel_enabled=1;enc.enc_pic.hevc_spec_misc.quarter_pel_enabled=1;enc.enc_pic.hevc_spec_misc.transform_skip_disabled=1;
 enc.enc_pic.hevc_deblock.deblocking_filter_disabled=1;enc.enc_pic.hevc_deblock.disable_sao=1;
 enc.enc_pic.enc_params.allowed_max_bitstream_size=output_size-80;enc.enc_pic.enc_params.reference_picture_index=0xffffffff;
 struct si_screen screen={.info.vcn_ip_version=VCN_5_0_0};enc.screen=&screen;enc.base.width=384;enc.base.height=128;enc.alignment=256;
 assert(setup_dpb(e,2)==393216);assert(enc.metadata_size==2048);
 task(e,false);radeon_enc_op_init(e);radeon_enc_session_init(e);radeon_enc_layer_control(e);radeon_enc_rc_session_init(e);radeon_enc_encode_latency(e);radeon_enc_layer_select(e);radeon_enc_rc_layer_init(e);radeon_enc_layer_select(e);radeon_enc_rc_per_pic(e);radeon_enc_op_init_rc(e);radeon_enc_op_init_rc_vbv(e);dump(e);
 task(e,true);radeon_enc_slice_control_hevc(e);radeon_enc_layer_select(e);radeon_enc_quality_params(e);radeon_enc_slice_control_hevc(e);radeon_enc_spec_misc_hevc(e);radeon_enc_loop_filter_hevc(e);radeon_enc_slice_header_hevc(e);radeon_enc_encode_params(e);radeon_enc_encode_params_hevc(e);radeon_enc_ctx(e);radeon_enc_ctx_override(e);radeon_enc_bitstream(e);radeon_enc_feedback(e);radeon_enc_metadata(e);radeon_enc_intra_refresh(e);radeon_enc_qp_map(e);radeon_enc_input_format(e);radeon_enc_output_format(e);speed(e);radeon_enc_op_enc(e);dump(e);
 task(e,false);radeon_enc_op_close(e);dump(e);
}
