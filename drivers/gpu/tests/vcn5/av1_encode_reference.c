// SPDX-License-Identifier: MIT
#include "av1_primary.h"
static void task(struct radeon_encoder *enc,bool feedback){enc->cs.current.cdw=8;radeon_enc_session_info(enc);enc->total_task_size=0;radeon_enc_task_info(enc,feedback);}
static void speed(struct radeon_encoder *enc){RADEON_ENC_BEGIN(RENCODE_IB_OP_SET_SPEED_ENCODING_MODE);RADEON_ENC_END();}
static void dump(struct radeon_encoder *enc){unsigned n=enc->cs.current.cdw;*enc->p_task_size=enc->total_task_size;uint32_t head[]={0x10,0x30000002,0,n-4,0x10,0x30000001,2,(n-4)*4};memcpy(enc->cs.current.buf,head,sizeof(head));for(unsigned i=4;i<n;i++)enc->cs.current.buf[2]+=enc->cs.current.buf[i];for(unsigned i=0;i<n;i++)printf("%08x ",enc->cs.current.buf[i]);puts("");}
int main(int argc,char**argv){assert(argc==12);uint64_t addr[7];for(unsigned i=0;i<7;i++)addr[i]=strtoull(argv[i+1],NULL,0);
 uint32_t words[4096]={0};struct radeon_encoder e={0},*enc=&e;enc->cs.current.buf=words;
 struct resource si={.buf=addr[0]},dpb={.buf=addr[1]},meta={.buf=addr[3]},fb={.buf=addr[5]},cdf={.buf=addr[6]};
 enc->si=&si;enc->dpb=&dpb;enc->meta=&meta;enc->cdf=&cdf;enc->bs_handle=addr[4];enc->bs_size=strtoul(argv[8],NULL,0);enc->bs_offset=16;
 typeof(*enc->fb) f={.res=&fb};enc->fb=&f;
 struct surface y={.u.gfx9={.surf_pitch=strtoul(argv[9],NULL,0)}},uv={.u.gfx9={.surf_pitch=strtoul(argv[10],NULL,0),.surf_offset=strtoull(argv[11],NULL,0)}};enc->handle=addr[2];enc->luma=&y;enc->chroma=&uv;enc->base.profile=PIPE_VIDEO_FORMAT_AV1;
 ac_vcn_enc_init_cmds(&enc->cmd,VCN_5_0_0);
 struct pipe_av1_enc_picture_desc pic={0};enc->enc_pic.av1.desc=&pic;
 pic.seq.seq_bits.still_picture=1;pic.seq.seq_bits.reduced_still_picture_header=1;pic.seq.seq_bits.force_screen_content_tools=2;pic.seq.seq_bits.force_integer_mv=2;
 pic.seq.num_temporal_layers=1;pic.seq.pic_width_in_luma_samples=320;pic.seq.pic_height_in_luma_samples=128;
 pic.seq.color_config.chroma_sample_position=0;pic.seq.color_config.color_range=0;
 pic.frame_type=PIPE_AV1_ENC_FRAME_TYPE_KEY;pic.enable_frame_obu=1;pic.show_frame=1;pic.refresh_frame_flags=255;pic.primary_ref_frame=7;pic.disable_cdf_update=1;pic.disable_frame_end_update_cdf=1;
 enc->enc_pic.frame_type=PIPE_AV1_ENC_FRAME_TYPE_KEY;enc->enc_pic.pic_width_in_luma_samples=320;enc->enc_pic.pic_height_in_luma_samples=128;
 enc->enc_pic.av1.coded_width=320;enc->enc_pic.av1.coded_height=128;enc->enc_pic.av1.primary_ref_frame=7;enc->enc_pic.av1_tile_splitting_legacy_flag=true;
 enc->enc_pic.num_temporal_layers=1;enc->enc_pic.session_info.interface_version=0x1000a;
 enc->enc_pic.session_init.encode_standard=RENCODE_ENCODE_STANDARD_AV1;enc->enc_pic.session_init.aligned_picture_width=320;enc->enc_pic.session_init.aligned_picture_height=128;
 enc->enc_pic.rc_session_init.vbv_buffer_level=48;enc->enc_pic.rc_layer_init[0].frame_rate_num=25;enc->enc_pic.rc_layer_init[0].frame_rate_den=1;
 enc->enc_pic.rc_per_pic.qp_i=enc->enc_pic.rc_per_pic.qp_p=enc->enc_pic.rc_per_pic.qp_b=1;
 enc->enc_pic.rc_per_pic.min_qp_i=enc->enc_pic.rc_per_pic.min_qp_p=enc->enc_pic.rc_per_pic.min_qp_b=1;
 enc->enc_pic.rc_per_pic.max_qp_i=enc->enc_pic.rc_per_pic.max_qp_p=enc->enc_pic.rc_per_pic.max_qp_b=255;
 enc->enc_pic.enc_params.allowed_max_bitstream_size=enc->bs_size-enc->bs_offset;enc->enc_pic.enc_params.reference_picture_index=0xffffffff;
 enc->enc_pic.av1_spec_misc.disable_cdf_update=1;enc->enc_pic.av1_spec_misc.disable_frame_end_update_cdf=1;
 enc->enc_pic.av1_tile_config.num_tile_cols=enc->enc_pic.av1_tile_config.num_tile_rows=1;
 for(unsigned i=0;i<7;i++)enc->enc_pic.av1_enc_params.ref_frames[i]=255;
 enc->enc_pic.av1_enc_params.lsm_reference_frame_index[0]=enc->enc_pic.av1_enc_params.lsm_reference_frame_index[1]=0xffffffff;
 struct si_screen screen={.info.vcn_ip_version=VCN_5_0_0};enc->screen=&screen;enc->base.width=320;enc->base.height=128;enc->alignment=256;
 setup_dpb(enc,2);
 printf("sizes %u %u\n",enc->dpb_size,enc->metadata_size);
 uint8_t seq[4096]={0},obu[]={0x0a};unsigned size=radeon_enc_write_sequence_header(enc,obu,seq);printf("header ");for(unsigned i=0;i<size;i++)printf("%02x",seq[i]);puts("");
 task(enc,false);radeon_enc_op_init(enc);radeon_enc_session_init(enc);radeon_enc_layer_control(enc);radeon_enc_rc_session_init(enc);radeon_enc_encode_latency(enc);radeon_enc_layer_select(enc);radeon_enc_rc_layer_init(enc);radeon_enc_layer_select(enc);radeon_enc_rc_per_pic(enc);radeon_enc_op_init_rc(enc);radeon_enc_op_init_rc_vbv(enc);dump(enc);
 task(enc,true);radeon_enc_layer_select(enc);radeon_enc_quality_params(enc);radeon_enc_spec_misc_av1(enc);radeon_enc_tile_config_av1(enc);radeon_enc_obu_instruction(enc);radeon_enc_encode_params(enc);radeon_enc_encode_params_av1(enc);radeon_enc_cdf_default_table(enc);radeon_enc_ctx(enc);radeon_enc_ctx_override(enc);radeon_enc_bitstream(enc);radeon_enc_feedback(enc);radeon_enc_metadata(enc);radeon_enc_intra_refresh(enc);radeon_enc_qp_map(enc);radeon_enc_input_format(enc);radeon_enc_output_format(enc);speed(enc);radeon_enc_op_enc(enc);dump(enc);
 task(enc,false);radeon_enc_op_close(enc);dump(enc);
}
