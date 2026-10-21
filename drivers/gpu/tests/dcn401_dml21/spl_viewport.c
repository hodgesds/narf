/* One pipe's SPL viewports for harness_surfaces.c's mcache programming.
 * A separate translation unit: SPL builds against tests/dcn401_spl's host
 * stand-ins, which clash with the DML21 harness's.
 *
 * spl_calculate_scaler_params with the spl_in
 * translate_SPL_in_params_from_pipe_ctx builds on DCN401 for an amdgpu_dm
 * plane (as tests/dcn401_spl/harness.c, alpha off): the plane's source
 * rectangle at the surface origin, its destination and the stream, the
 * pipe's ODM slice (resource_get_odm_slice_src_rect) and its MPC slice.
 * The viewports are what dml21_get_pipe_mcache_config hands DML21
 * (scl_data.viewport and viewport_c, x and width). */
#include <string.h>
#include "dc_spl.h"

int narf_spl_warnings;

/* dscl401_spl_calc_lb_num_partitions, copied from dcn401_dpp.c by check.sh. */
#include "spl_lb.inc"

/* video: 0 RGB, 1 dml2_420_8 (SPL 420BPP8), 2 dml2_420_10 (420BPP10).
 * Fills vp[4] and vp_c[4] (x, y, width, height); returns the SPL result. */
int narf_spl_viewports(int src_w, int src_h, int dst_w, int dst_h, int stream_w, int stream_h,
		       int odm_x, int odm_w, int mpc_index, int mpc_count, int rotation,
		       int video, int vp[4], int vp_c[4])
{
	static struct spl_in in;
	static struct spl_out out;
	static struct dscl_prog_data p;

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));
	memset(&p, 0, sizeof(p));
	in.callbacks.spl_calc_lb_num_partitions = dscl401_spl_calc_lb_num_partitions;
	in.basic_in.format = video == 0 ? SPL_PIXEL_FORMAT_ARGB8888 :
		video == 2 ? SPL_PIXEL_FORMAT_420BPP10 : SPL_PIXEL_FORMAT_420BPP8;
	in.basic_out.view_format = SPL_VIEW_3D_NONE;
	in.basic_in.src_rect = (struct spl_rect){ 0, 0, src_w, src_h };
	in.basic_in.dst_rect = (struct spl_rect){ 0, 0, dst_w, dst_h };
	in.basic_in.clip_rect = in.basic_in.dst_rect;
	in.basic_out.src_rect = (struct spl_rect){ 0, 0, stream_w, stream_h };
	in.basic_out.dst_rect = in.basic_out.src_rect;
	in.basic_in.rotation = (enum spl_rotation_angle)rotation;
	in.basic_in.horizontal_mirror = false;
	in.basic_in.num_h_slices_recout_width_align.use_recout_width_aligned = false;
	in.basic_in.num_h_slices_recout_width_align.num_slices_recout_width.mpc_num_h_slices = mpc_count;
	in.basic_in.mpc_h_slice_index = mpc_index;
	in.basic_out.odm_slice_rect = (struct spl_rect){ odm_x, 0, odm_w, stream_h };
	in.basic_out.odm_combine_factor = 0;
	in.odm_slice_index = 0;
	in.basic_out.output_size.width = stream_w;
	in.basic_out.output_size.height = stream_h;
	in.basic_out.max_downscale_src_width = 7680;
	in.basic_out.always_scale = false;
	in.basic_out.alpha_en = false;
	in.basic_out.use_two_pixels_per_container = false;
	in.prefer_easf = true;
	in.disable_easf = false;
	in.adaptive_sharpness.enable = false;
	in.lls_pref = LLS_PREF_DONT_CARE;
	in.upsp_mode = video ? UPSP_HORIZONTAL_VERTICAL_UPSAMPLING : UPSP_BYPASS;
	in.basic_in.cositing = CHROMA_COSITING_NONE;
	in.h_active = odm_w;
	in.v_active = stream_h;
	out.dscl_prog_data = &p;
	int ok = spl_calculate_scaler_params(&in, &out);
	vp[0] = p.viewport.x;
	vp[1] = p.viewport.y;
	vp[2] = p.viewport.width;
	vp[3] = p.viewport.height;
	vp_c[0] = p.viewport_c.x;
	vp_c[1] = p.viewport_c.y;
	vp_c[2] = p.viewport_c.width;
	vp_c[3] = p.viewport_c.height;
	return ok;
}
