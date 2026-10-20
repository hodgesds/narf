/* Linux SPL reference for amdgpu_dcn401_spl.rs and the DCN401 DSCL/HUBP
 * scaler programming in amdgpu_dcn401_dscl.rs. Build with check.sh.
 *
 * Reads one plane per line on stdin:
 *   src_x src_y src_w src_h dst_x dst_y dst_w dst_h stream_w stream_h
 *   odm_x odm_w rotation mirror alpha
 * (the ODM slice spans the stream's height) and runs
 * spl_calculate_scaler_params with the spl_in that
 * translate_SPL_in_params_from_pipe_ctx builds on DCN401 for an amdgpu_dm
 * RGB plane (see amdgpu_dcn401_spl.rs for the fixed inputs). It prints
 * "OK" or "FAIL" (the result), then the writes
 * dpp401_dscl_set_scaler_manual_scale (DSCL, use_spl, prefer_easf, no DSCL
 * low-power) and hubp401_set_viewport issue for pipe 0, in order:
 *   <reg>&<mask>=<value>  a register write; <mask> is the union of the
 *                         fields the REG_SET/REG_UPDATE names (Linux's
 *                         dcn_4_1_0 shifts and masks pack the values)
 *   w<reg>&<mask>=<value> a REG_WAIT for those field values
 *   c<type>/<taps>/<n>/<fnv1a> one dpp401_dscl_set_scaler_filter load: the
 *                         filter type, taps, and the FNV-1a hash of its <n>
 *                         SCL_COEF_RAM_TAP_DATA words (after TAP_SELECT)
 *   t                     the SCL_MODE coefficient RAM swap (SCL_COEF_RAM_SELECT
 *                         = !CURRENT, SCL_CHROMA_COEF_MODE 0)
 *   T                     the same swap with SCL_CHROMA_COEF_MODE 1 (YCbCr)
 * With the argument "video" each line starts with an extra 4:2:0 format
 * column: 8 for NV12/NV21 (SPL_PIXEL_FORMAT_420BPP8) or 10 for P010
 * (420BPP10); see video_inputs.txt.
 * A first-time programming: the DPP has no filter cached.
 * dpp401_dscl_find_lb_memory_config and dscl401_calc_lb_num_partitions run
 * on DC's scaler data as translate_SPL_out_params_to_pipe_ctx leaves it.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dc_spl.h"
#include "asic_reg/dcn/dcn_4_1_0_offset.h"
#include "asic_reg/dcn/dcn_4_1_0_sh_mask.h"

int narf_spl_warnings;

/* dscl401_spl_calc_lb_num_partitions, copied from dcn401_dpp.c by check.sh. */
#include "spl_lb.inc"

#define FM(r, f) ((uint32_t)DSCL0_##r##__##f##_MASK)
#define FV(r, f, v) ((((uint32_t)(v)) << DSCL0_##r##__##f##__SHIFT) & FM(r, f))
#define REG(r) (unsigned)regDSCL0_##r

static void w(unsigned reg, uint32_t mask, uint32_t value)
{
	printf(" %x&%x=%x", reg, mask, value & mask);
}
static void wait(unsigned reg, uint32_t mask, uint32_t value)
{
	printf(" w%x&%x=%x", reg, mask, value & mask);
}

/* dpp401_dscl_set_scaler_filter. */
static void coef(uint32_t taps, uint32_t type, const uint16_t *filter)
{
	const int pairs = (taps + 1) / 2;
	uint32_t h = 2166136261u;
	int n = 0;

	for (int phase = 0; phase < 64 / 2 + 1; phase++)
		for (int pair = 0; pair < pairs; pair++) {
			uint16_t even = filter[phase * taps + 2 * pair];
			uint16_t odd = (uint32_t)(pair * 2 + 1) < taps ?
				filter[phase * taps + 2 * pair + 1] : 0;
			uint32_t v = FV(SCL_COEF_RAM_TAP_DATA, SCL_COEF_RAM_EVEN_TAP_COEF, even) |
				FV(SCL_COEF_RAM_TAP_DATA, SCL_COEF_RAM_EVEN_TAP_COEF_EN, 1) |
				FV(SCL_COEF_RAM_TAP_DATA, SCL_COEF_RAM_ODD_TAP_COEF, odd) |
				FV(SCL_COEF_RAM_TAP_DATA, SCL_COEF_RAM_ODD_TAP_COEF_EN, 1);
			for (int b = 0; b < 4; b++) {
				h ^= (v >> (8 * b)) & 0xff;
				h *= 16777619u;
			}
			n++;
		}
	printf(" c%u/%u/%d/%08x", type, taps, n, h);
}

/* dscl401_calc_lb_num_partitions on DC's scaler data. */
static void dc_partitions(const struct dscl_prog_data *d, bool alpha, int config,
			  int *y, int *c)
{
	int line = d->viewport.width < d->recout.width ? d->viewport.width : d->recout.width;
	int line_c = d->viewport_c.width < d->recout.width ? d->viewport_c.width : d->recout.width;
	int lb, lb_c, lb_a, a;

	if (line == 0)
		line = 1;
	if (line_c == 0)
		line_c = 1;
	if (config == 1)
		lb = lb_c = lb_a = 970;
	else if (config == 2)
		lb = lb_c = lb_a = 1290;
	else if (d->viewport.width == (int)d->mpc_size.width &&
		 d->viewport.height == (int)d->mpc_size.height)
		lb = lb_c = lb_a = 970 + 1290 + 1170;
	else
		lb = lb_c = lb_a = 970 + 1290 + 484;
	*y = lb / ((line + 5) / 6);
	*c = lb_c / ((line_c + 5) / 6);
	a = lb_a / ((line + 5) / 6);
	if (alpha && a < *y)
		*y = a;
	if (*y > 64)
		*y = 64;
	if (*c > 64)
		*c = 64;
}

static bool lb_valid(int ceil_vratio, int parts, int vtaps)
{
	if (ceil_vratio > 2)
		return vtaps <= parts - ceil_vratio + 2;
	return vtaps <= parts;
}

/* dpp401_dscl_find_lb_memory_config (RGB, no use_max_lb). */
static int lb_config(const struct dscl_prog_data *d, bool alpha)
{
	int vtaps = d->taps.v_taps + 1, vtaps_c = d->taps.v_taps_c + 1, y, c;
	/* populate_ratios_from_splratios then dc_fixpt_ceil. */
	int ceil_v = (int)(((((long long)d->ratios.v_scale_ratio >> 5) << 13) + 0xffffffffLL) >> 32);
	int ceil_v_c = (int)(((((long long)d->ratios.v_scale_ratio_c >> 5) << 13) + 0xffffffffLL) >> 32);

	for (int config = 1; config <= 2; config++) {
		dc_partitions(d, alpha, config, &y, &c);
		if (lb_valid(ceil_v, y, vtaps) && lb_valid(ceil_v_c, c, vtaps_c))
			return config;
	}
	return 0;
}

/* dpp401_dscl_program_isharp with isharp_en = 0. */
static void isharp(void)
{
	unsigned pwr = REG(ISHARP_DELTA_LUT_MEM_PWR_CTRL);
	uint32_t force = FM(ISHARP_DELTA_LUT_MEM_PWR_CTRL, ISHARP_DELTA_LUT_MEM_PWR_FORCE);
	uint32_t dis = FM(ISHARP_DELTA_LUT_MEM_PWR_CTRL, ISHARP_DELTA_LUT_MEM_PWR_DIS);

	w(pwr, force | dis, dis);
	wait(pwr, FM(ISHARP_DELTA_LUT_MEM_PWR_CTRL, ISHARP_DELTA_LUT_MEM_PWR_STATE), 0);
	w(REG(ISHARP_MODE), FM(ISHARP_MODE, ISHARP_EN) | FM(ISHARP_MODE, ISHARP_NOISEDET_EN) |
	  FM(ISHARP_MODE, ISHARP_NOISEDET_MODE) | FM(ISHARP_MODE, ISHARP_LBA_MODE) |
	  FM(ISHARP_MODE, ISHARP_FMT_MODE) | FM(ISHARP_MODE, ISHARP_FMT_NORM), 0);
	w(pwr, force | dis, 0);
}

#define PWL3(D, n, s)                                                                       \
	w(REG(DSCL_EASF_##D##_BF##n##_PWL_SEG##s),                                           \
	  FM(DSCL_EASF_##D##_BF##n##_PWL_SEG##s, SCL_EASF_##D##_BF##n##_PWL_IN_SEG##s) |     \
	  FM(DSCL_EASF_##D##_BF##n##_PWL_SEG##s, SCL_EASF_##D##_BF##n##_PWL_BASE_SEG##s) |   \
	  FM(DSCL_EASF_##D##_BF##n##_PWL_SEG##s, SCL_EASF_##D##_BF##n##_PWL_SLOPE_SEG##s),   \
	  FV(DSCL_EASF_##D##_BF##n##_PWL_SEG##s, SCL_EASF_##D##_BF##n##_PWL_IN_SEG##s, IN) | \
	  FV(DSCL_EASF_##D##_BF##n##_PWL_SEG##s, SCL_EASF_##D##_BF##n##_PWL_BASE_SEG##s, BASE) | \
	  FV(DSCL_EASF_##D##_BF##n##_PWL_SEG##s, SCL_EASF_##D##_BF##n##_PWL_SLOPE_SEG##s, SLOPE))
#define PWL2(D, n, s)                                                                       \
	w(REG(DSCL_EASF_##D##_BF##n##_PWL_SEG##s),                                           \
	  FM(DSCL_EASF_##D##_BF##n##_PWL_SEG##s, SCL_EASF_##D##_BF##n##_PWL_IN_SEG##s) |     \
	  FM(DSCL_EASF_##D##_BF##n##_PWL_SEG##s, SCL_EASF_##D##_BF##n##_PWL_BASE_SEG##s),    \
	  FV(DSCL_EASF_##D##_BF##n##_PWL_SEG##s, SCL_EASF_##D##_BF##n##_PWL_IN_SEG##s, IN) | \
	  FV(DSCL_EASF_##D##_BF##n##_PWL_SEG##s, SCL_EASF_##D##_BF##n##_PWL_BASE_SEG##s, BASE))

/* dpp401_dscl_program_easf_v/h: one direction. */
#define EASF_DIR(D, d)                                                                       \
	do {                                                                                 \
		w(REG(DSCL_EASF_##D##_MODE),                                                 \
		  FM(DSCL_EASF_##D##_MODE, SCL_EASF_##D##_EN) |                              \
		  FM(DSCL_EASF_##D##_MODE, SCL_EASF_##D##_2TAP_SHARP_FACTOR) |               \
		  FM(DSCL_EASF_##D##_MODE, SCL_EASF_##D##_RINGEST_FORCE_EN),                 \
		  FV(DSCL_EASF_##D##_MODE, SCL_EASF_##D##_EN, p->easf_##d##_en) |            \
		  FV(DSCL_EASF_##D##_MODE, SCL_EASF_##D##_2TAP_SHARP_FACTOR, p->easf_##d##_sharp_factor) | \
		  FV(DSCL_EASF_##D##_MODE, SCL_EASF_##D##_RINGEST_FORCE_EN, p->easf_##d##_ring)); \
		if (!p->easf_##d##_en)                                                       \
			break;                                                               \
		w(REG(DSCL_EASF_##D##_BF_CNTL),                                              \
		  FM(DSCL_EASF_##D##_BF_CNTL, SCL_EASF_##D##_BF1_EN) |                       \
		  FM(DSCL_EASF_##D##_BF_CNTL, SCL_EASF_##D##_BF2_MODE) |                     \
		  FM(DSCL_EASF_##D##_BF_CNTL, SCL_EASF_##D##_BF3_MODE) |                     \
		  FM(DSCL_EASF_##D##_BF_CNTL, SCL_EASF_##D##_BF2_FLAT1_GAIN) |               \
		  FM(DSCL_EASF_##D##_BF_CNTL, SCL_EASF_##D##_BF2_FLAT2_GAIN) |               \
		  FM(DSCL_EASF_##D##_BF_CNTL, SCL_EASF_##D##_BF2_ROC_GAIN),                  \
		  FV(DSCL_EASF_##D##_BF_CNTL, SCL_EASF_##D##_BF1_EN, p->easf_##d##_bf1_en) | \
		  FV(DSCL_EASF_##D##_BF_CNTL, SCL_EASF_##D##_BF2_MODE, p->easf_##d##_bf2_mode) | \
		  FV(DSCL_EASF_##D##_BF_CNTL, SCL_EASF_##D##_BF3_MODE, p->easf_##d##_bf3_mode) | \
		  FV(DSCL_EASF_##D##_BF_CNTL, SCL_EASF_##D##_BF2_FLAT1_GAIN, p->easf_##d##_bf2_flat1_gain) | \
		  FV(DSCL_EASF_##D##_BF_CNTL, SCL_EASF_##D##_BF2_FLAT2_GAIN, p->easf_##d##_bf2_flat2_gain) | \
		  FV(DSCL_EASF_##D##_BF_CNTL, SCL_EASF_##D##_BF2_ROC_GAIN, p->easf_##d##_bf2_roc_gain)); \
		THREE_TAP;                                                                   \
		w(REG(DSCL_EASF_##D##_RINGEST_EVENTAP_REDUCE),                               \
		  FM(DSCL_EASF_##D##_RINGEST_EVENTAP_REDUCE, SCL_EASF_##D##_RINGEST_EVENTAP_REDUCEG1) | \
		  FM(DSCL_EASF_##D##_RINGEST_EVENTAP_REDUCE, SCL_EASF_##D##_RINGEST_EVENTAP_REDUCEG2), \
		  FV(DSCL_EASF_##D##_RINGEST_EVENTAP_REDUCE, SCL_EASF_##D##_RINGEST_EVENTAP_REDUCEG1, p->easf_##d##_ringest_eventap_reduceg1) | \
		  FV(DSCL_EASF_##D##_RINGEST_EVENTAP_REDUCE, SCL_EASF_##D##_RINGEST_EVENTAP_REDUCEG2, p->easf_##d##_ringest_eventap_reduceg2)); \
		w(REG(DSCL_EASF_##D##_RINGEST_EVENTAP_GAIN),                                 \
		  FM(DSCL_EASF_##D##_RINGEST_EVENTAP_GAIN, SCL_EASF_##D##_RINGEST_EVENTAP_GAIN1) | \
		  FM(DSCL_EASF_##D##_RINGEST_EVENTAP_GAIN, SCL_EASF_##D##_RINGEST_EVENTAP_GAIN2), \
		  FV(DSCL_EASF_##D##_RINGEST_EVENTAP_GAIN, SCL_EASF_##D##_RINGEST_EVENTAP_GAIN1, p->easf_##d##_ringest_eventap_gain1) | \
		  FV(DSCL_EASF_##D##_RINGEST_EVENTAP_GAIN, SCL_EASF_##D##_RINGEST_EVENTAP_GAIN2, p->easf_##d##_ringest_eventap_gain2)); \
		w(REG(DSCL_EASF_##D##_BF_FINAL_MAX_MIN),                                     \
		  FM(DSCL_EASF_##D##_BF_FINAL_MAX_MIN, SCL_EASF_##D##_BF_MAXA) |             \
		  FM(DSCL_EASF_##D##_BF_FINAL_MAX_MIN, SCL_EASF_##D##_BF_MAXB) |             \
		  FM(DSCL_EASF_##D##_BF_FINAL_MAX_MIN, SCL_EASF_##D##_BF_MINA) |             \
		  FM(DSCL_EASF_##D##_BF_FINAL_MAX_MIN, SCL_EASF_##D##_BF_MINB),              \
		  FV(DSCL_EASF_##D##_BF_FINAL_MAX_MIN, SCL_EASF_##D##_BF_MAXA, p->easf_##d##_bf_maxa) | \
		  FV(DSCL_EASF_##D##_BF_FINAL_MAX_MIN, SCL_EASF_##D##_BF_MAXB, p->easf_##d##_bf_maxb) | \
		  FV(DSCL_EASF_##D##_BF_FINAL_MAX_MIN, SCL_EASF_##D##_BF_MINA, p->easf_##d##_bf_mina) | \
		  FV(DSCL_EASF_##D##_BF_FINAL_MAX_MIN, SCL_EASF_##D##_BF_MINB, p->easf_##d##_bf_minb)); \
		BF1(D, d, 0); BF1(D, d, 1); BF1(D, d, 2); BF1(D, d, 3);                       \
		BF1(D, d, 4); BF1(D, d, 5); BF1(D, d, 6);                                     \
		{ uint32_t IN = p->easf_##d##_bf1_pwl_in_seg7, BASE = p->easf_##d##_bf1_pwl_base_seg7; \
		  PWL2(D, 1, 7); }                                                            \
		BF3(D, d, 0); BF3(D, d, 1); BF3(D, d, 2); BF3(D, d, 3); BF3(D, d, 4);         \
		{ uint32_t IN = p->easf_##d##_bf3_pwl_in_set5, BASE = p->easf_##d##_bf3_pwl_base_set5; \
		  PWL2(D, 3, 5); }                                                            \
	} while (0)
#define BF1(D, d, s)                                                                         \
	do { uint32_t IN = p->easf_##d##_bf1_pwl_in_seg##s, BASE = p->easf_##d##_bf1_pwl_base_seg##s, \
		 SLOPE = p->easf_##d##_bf1_pwl_slope_seg##s; PWL3(D, 1, s); } while (0)
#define BF3(D, d, s)                                                                         \
	do { uint32_t IN = p->easf_##d##_bf3_pwl_in_set##s, BASE = p->easf_##d##_bf3_pwl_base_set##s, \
		 SLOPE = p->easf_##d##_bf3_pwl_slope_set##s; PWL3(D, 3, s); } while (0)

#define V3(n, f1, v1, f2, v2)                                                                \
	w(REG(DSCL_EASF_V_RINGEST_3TAP_CNTL##n),                                             \
	  FM(DSCL_EASF_V_RINGEST_3TAP_CNTL##n, f1) | FM(DSCL_EASF_V_RINGEST_3TAP_CNTL##n, f2), \
	  FV(DSCL_EASF_V_RINGEST_3TAP_CNTL##n, f1, p->v1) | FV(DSCL_EASF_V_RINGEST_3TAP_CNTL##n, f2, p->v2))

static void easf(const struct dscl_prog_data *p)
{
	w(REG(DSCL_SC_MODE), FM(DSCL_SC_MODE, SCL_SC_MATRIX_MODE) | FM(DSCL_SC_MODE, SCL_SC_LTONL_EN),
	  FV(DSCL_SC_MODE, SCL_SC_MATRIX_MODE, p->easf_matrix_mode) |
	  FV(DSCL_SC_MODE, SCL_SC_LTONL_EN, p->easf_ltonl_en));
	w(REG(DSCL_SC_MATRIX_C0C1), FM(DSCL_SC_MATRIX_C0C1, SCL_SC_MATRIX_C0) |
	  FM(DSCL_SC_MATRIX_C0C1, SCL_SC_MATRIX_C1),
	  FV(DSCL_SC_MATRIX_C0C1, SCL_SC_MATRIX_C0, p->easf_matrix_c0) |
	  FV(DSCL_SC_MATRIX_C0C1, SCL_SC_MATRIX_C1, p->easf_matrix_c1));
	w(REG(DSCL_SC_MATRIX_C2C3), FM(DSCL_SC_MATRIX_C2C3, SCL_SC_MATRIX_C2) |
	  FM(DSCL_SC_MATRIX_C2C3, SCL_SC_MATRIX_C3),
	  FV(DSCL_SC_MATRIX_C2C3, SCL_SC_MATRIX_C2, p->easf_matrix_c2) |
	  FV(DSCL_SC_MATRIX_C2C3, SCL_SC_MATRIX_C3, p->easf_matrix_c3));
#define THREE_TAP                                                                            \
	V3(1, SCL_EASF_V_RINGEST_3TAP_DNTILT_UPTILT, easf_v_ringest_3tap_dntilt_uptilt,       \
	   SCL_EASF_V_RINGEST_3TAP_UPTILT_MAXVAL, easf_v_ringest_3tap_uptilt_max);            \
	V3(2, SCL_EASF_V_RINGEST_3TAP_DNTILT_SLOPE, easf_v_ringest_3tap_dntilt_slope,         \
	   SCL_EASF_V_RINGEST_3TAP_UPTILT1_SLOPE, easf_v_ringest_3tap_uptilt1_slope);         \
	V3(3, SCL_EASF_V_RINGEST_3TAP_UPTILT2_SLOPE, easf_v_ringest_3tap_uptilt2_slope,       \
	   SCL_EASF_V_RINGEST_3TAP_UPTILT2_OFFSET, easf_v_ringest_3tap_uptilt2_offset)
	EASF_DIR(V, v);
#undef THREE_TAP
#define THREE_TAP do {} while (0)
	EASF_DIR(H, h);
#undef THREE_TAP
}

#define HUBP(r) (unsigned)regHUBP0_DCSURF_##r
#define HM(r, f) ((uint32_t)HUBP0_DCSURF_##r##__##f##_MASK)
#define HV(r, f, v) ((((uint32_t)(v)) << HUBP0_DCSURF_##r##__##f##__SHIFT) & HM(r, f))
#define VP(r, sfx, R)                                                                        \
	w(HUBP(r##_DIMENSION##sfx), HM(r##_DIMENSION##sfx, r##_WIDTH##sfx) |                   \
	  HM(r##_DIMENSION##sfx, r##_HEIGHT##sfx),                                             \
	  HV(r##_DIMENSION##sfx, r##_WIDTH##sfx, (R).width) |                                  \
	  HV(r##_DIMENSION##sfx, r##_HEIGHT##sfx, (R).height));                                \
	w(HUBP(r##_START##sfx), HM(r##_START##sfx, r##_X_START##sfx) |                         \
	  HM(r##_START##sfx, r##_Y_START##sfx),                                                \
	  HV(r##_START##sfx, r##_X_START##sfx, (R).x) | HV(r##_START##sfx, r##_Y_START##sfx, (R).y))

int main(int argc, char **argv)
{
	/* "video": each line starts with a 4:2:0 format, 8 (NV12/NV21,
	 * SPL_PIXEL_FORMAT_420BPP8) or 10 (P010, 420BPP10). */
	const bool video = argc > 1 && !strcmp(argv[1], "video");
	long b[16], *a = b + video;

	while (1) {
		for (int i = 0; i < 15 + video; i++)
			if (scanf("%ld", &b[i]) != 1)
				return 0;
		static struct spl_in in;
		static struct spl_out out;
		static struct dscl_prog_data p;

		memset(&in, 0, sizeof(in));
		memset(&p, 0, sizeof(p));
		narf_spl_warnings = 0;
		in.callbacks.spl_calc_lb_num_partitions = dscl401_spl_calc_lb_num_partitions;
		in.basic_in.format = !video ? SPL_PIXEL_FORMAT_ARGB8888 :
			b[0] == 10 ? SPL_PIXEL_FORMAT_420BPP10 : SPL_PIXEL_FORMAT_420BPP8;
		in.basic_out.view_format = SPL_VIEW_3D_NONE;
		in.basic_in.src_rect = (struct spl_rect){ a[0], a[1], a[2], a[3] };
		in.basic_in.dst_rect = (struct spl_rect){ a[4], a[5], a[6], a[7] };
		in.basic_in.clip_rect = in.basic_in.dst_rect;
		in.basic_out.src_rect = (struct spl_rect){ 0, 0, a[8], a[9] };
		in.basic_out.dst_rect = in.basic_out.src_rect;
		in.basic_in.rotation = (enum spl_rotation_angle)a[12];
		in.basic_in.horizontal_mirror = a[13];
		in.basic_in.num_h_slices_recout_width_align.use_recout_width_aligned = false;
		in.basic_in.num_h_slices_recout_width_align.num_slices_recout_width.mpc_num_h_slices = 1;
		in.basic_in.mpc_h_slice_index = 0;
		in.basic_out.odm_slice_rect = (struct spl_rect){ a[10], 0, a[11], a[9] };
		in.basic_out.odm_combine_factor = 0;
		in.odm_slice_index = 0;
		in.basic_out.output_size.width = a[8];
		in.basic_out.output_size.height = a[9];
		in.basic_out.max_downscale_src_width = 7680;
		in.basic_out.always_scale = false;
		in.basic_out.alpha_en = a[14];
		in.basic_out.use_two_pixels_per_container = false;
		in.prefer_easf = true;
		in.disable_easf = false;
		in.adaptive_sharpness.enable = false;
		in.lls_pref = LLS_PREF_DONT_CARE;
		/* resource_is_upsp_required: 4:2:0 upsamples both ways (unused by DCN401). */
		in.upsp_mode = video ? UPSP_HORIZONTAL_VERTICAL_UPSAMPLING : UPSP_BYPASS;
		in.basic_in.cositing = CHROMA_COSITING_NONE;
		in.h_active = a[11];
		in.v_active = a[9];
		in.is_fullscreen = false;
		in.is_hdr_on = false;
		in.sdr_white_level_nits = 0;
		out.dscl_prog_data = &p;

		bool ok = spl_calculate_scaler_params(&in, &out);
		printf("%s", ok ? "OK" : "FAIL");
		if (narf_spl_warnings)
			printf(" WARN");

		/* dpp401_dscl_set_scaler_manual_scale. */
		w(REG(DSCL_AUTOCAL), FM(DSCL_AUTOCAL, AUTOCAL_MODE) | FM(DSCL_AUTOCAL, AUTOCAL_NUM_PIPE) |
		  FM(DSCL_AUTOCAL, AUTOCAL_PIPE_ID), 0);
		w(REG(DSCL_CONTROL), FM(DSCL_CONTROL, SCL_BOUNDARY_MODE), 0);
		w(REG(RECOUT_START), FM(RECOUT_START, RECOUT_START_X) | FM(RECOUT_START, RECOUT_START_Y),
		  FV(RECOUT_START, RECOUT_START_X, p.recout.x) | FV(RECOUT_START, RECOUT_START_Y, p.recout.y));
		w(REG(RECOUT_SIZE), FM(RECOUT_SIZE, RECOUT_WIDTH) | FM(RECOUT_SIZE, RECOUT_HEIGHT),
		  FV(RECOUT_SIZE, RECOUT_WIDTH, p.recout.width) | FV(RECOUT_SIZE, RECOUT_HEIGHT, p.recout.height));
		w(REG(MPC_SIZE), FM(MPC_SIZE, MPC_WIDTH) | FM(MPC_SIZE, MPC_HEIGHT),
		  FV(MPC_SIZE, MPC_WIDTH, p.mpc_size.width) | FV(MPC_SIZE, MPC_HEIGHT, p.mpc_size.height));
		w(REG(SCL_MODE), FM(SCL_MODE, DSCL_MODE), FV(SCL_MODE, DSCL_MODE, p.dscl_mode));
		/* dpp401_dscl_set_lb, float format; dcn401 max_lb_partitions 63.
		 * DCN401's use_max_lb gives a 4:2:0 plane LB_MEMORY_CONFIG_3. */
		w(REG(LB_DATA_FORMAT), FM(LB_DATA_FORMAT, INTERLEAVE_EN) | FM(LB_DATA_FORMAT, ALPHA_EN),
		  FV(LB_DATA_FORMAT, ALPHA_EN, a[14]));
		w(REG(LB_MEMORY_CTRL), FM(LB_MEMORY_CTRL, MEMORY_CONFIG) | FM(LB_MEMORY_CTRL, LB_MAX_PARTITIONS),
		  FV(LB_MEMORY_CTRL, MEMORY_CONFIG, video ? 3 : lb_config(&p, a[14])) |
		  FV(LB_MEMORY_CTRL, LB_MAX_PARTITIONS, 63));
		if (p.dscl_mode == SCL_MODE_SCALING_444_BYPASS) {
			/* dpp401_dscl_disable_easf. */
			w(REG(DSCL_EASF_V_MODE), FM(DSCL_EASF_V_MODE, SCL_EASF_V_EN), p.easf_v_en);
			w(REG(DSCL_EASF_H_MODE), FM(DSCL_EASF_H_MODE, SCL_EASF_H_EN), p.easf_h_en);
			isharp();
		} else {
			/* No SCL_BLACK_OFFSET register on DCN401. */
			w(REG(SCL_HORZ_FILTER_SCALE_RATIO), FM(SCL_HORZ_FILTER_SCALE_RATIO, SCL_H_SCALE_RATIO),
			  FV(SCL_HORZ_FILTER_SCALE_RATIO, SCL_H_SCALE_RATIO, p.ratios.h_scale_ratio));
			w(REG(SCL_VERT_FILTER_SCALE_RATIO), FM(SCL_VERT_FILTER_SCALE_RATIO, SCL_V_SCALE_RATIO),
			  FV(SCL_VERT_FILTER_SCALE_RATIO, SCL_V_SCALE_RATIO, p.ratios.v_scale_ratio));
			w(REG(SCL_HORZ_FILTER_SCALE_RATIO_C), FM(SCL_HORZ_FILTER_SCALE_RATIO_C, SCL_H_SCALE_RATIO_C),
			  FV(SCL_HORZ_FILTER_SCALE_RATIO_C, SCL_H_SCALE_RATIO_C, p.ratios.h_scale_ratio_c));
			w(REG(SCL_VERT_FILTER_SCALE_RATIO_C), FM(SCL_VERT_FILTER_SCALE_RATIO_C, SCL_V_SCALE_RATIO_C),
			  FV(SCL_VERT_FILTER_SCALE_RATIO_C, SCL_V_SCALE_RATIO_C, p.ratios.v_scale_ratio_c));
#define INIT(r, fr, in_, f, i)                                                               \
			w(REG(r), FM(r, fr) | FM(r, in_), FV(r, fr, p.init.f) | FV(r, in_, p.init.i))
			INIT(SCL_HORZ_FILTER_INIT, SCL_H_INIT_FRAC, SCL_H_INIT_INT, h_filter_init_frac, h_filter_init_int);
			INIT(SCL_HORZ_FILTER_INIT_C, SCL_H_INIT_FRAC_C, SCL_H_INIT_INT_C, h_filter_init_frac_c, h_filter_init_int_c);
			INIT(SCL_VERT_FILTER_INIT, SCL_V_INIT_FRAC, SCL_V_INIT_INT, v_filter_init_frac, v_filter_init_int);
			INIT(SCL_VERT_FILTER_INIT_BOT, SCL_V_INIT_FRAC_BOT, SCL_V_INIT_INT_BOT, v_filter_init_bot_frac, v_filter_init_bot_int);
			INIT(SCL_VERT_FILTER_INIT_C, SCL_V_INIT_FRAC_C, SCL_V_INIT_INT_C, v_filter_init_frac_c, v_filter_init_int_c);
			INIT(SCL_VERT_FILTER_INIT_BOT_C, SCL_V_INIT_FRAC_BOT_C, SCL_V_INIT_INT_BOT_C, v_filter_init_bot_frac_c, v_filter_init_bot_int_c);
			w(REG(SCL_TAP_CONTROL), FM(SCL_TAP_CONTROL, SCL_V_NUM_TAPS) | FM(SCL_TAP_CONTROL, SCL_H_NUM_TAPS) |
			  FM(SCL_TAP_CONTROL, SCL_V_NUM_TAPS_C) | FM(SCL_TAP_CONTROL, SCL_H_NUM_TAPS_C),
			  FV(SCL_TAP_CONTROL, SCL_V_NUM_TAPS, p.taps.v_taps) | FV(SCL_TAP_CONTROL, SCL_H_NUM_TAPS, p.taps.h_taps) |
			  FV(SCL_TAP_CONTROL, SCL_V_NUM_TAPS_C, p.taps.v_taps_c) | FV(SCL_TAP_CONTROL, SCL_H_NUM_TAPS_C, p.taps.h_taps_c));
			isharp();
			/* dpp401_dscl_set_scl_filter (chroma coefficients for YCbCr). DC's
			 * taps are SPL's plus one; scl_data.sharpness is zero. */
			uint32_t ht = p.taps.h_taps + 1, hc = p.taps.h_taps_c + 1;
			uint32_t vt = p.taps.v_taps + 1, vc = p.taps.v_taps_c + 1;
			bool h2 = ht < 3 && hc < 3 && ht > 1 && hc > 1;
			bool v2 = vt < 3 && vc < 3 && vt > 1 && vc > 1;
			w(REG(DSCL_2TAP_CONTROL), FM(DSCL_2TAP_CONTROL, SCL_H_2TAP_HARDCODE_COEF_EN) |
			  FM(DSCL_2TAP_CONTROL, SCL_H_2TAP_SHARP_EN) | FM(DSCL_2TAP_CONTROL, SCL_H_2TAP_SHARP_FACTOR) |
			  FM(DSCL_2TAP_CONTROL, SCL_V_2TAP_HARDCODE_COEF_EN) | FM(DSCL_2TAP_CONTROL, SCL_V_2TAP_SHARP_EN) |
			  FM(DSCL_2TAP_CONTROL, SCL_V_2TAP_SHARP_FACTOR),
			  FV(DSCL_2TAP_CONTROL, SCL_H_2TAP_HARDCODE_COEF_EN, h2) |
			  FV(DSCL_2TAP_CONTROL, SCL_V_2TAP_HARDCODE_COEF_EN, v2));
			if (!v2 || !h2) {
				/* A YCbCr plane runs in chroma coefficient mode: its
				 * chroma filters load after the luma ones and the swap
				 * sets SCL_CHROMA_COEF_MODE ("T"). */
				const uint16_t *fhc = video ? p.filter_h_c : NULL;
				const uint16_t *fvc = video ? p.filter_v_c : NULL;

				if (p.filter_h || p.filter_v || fhc || fvc) {
					if (!h2 && p.filter_h)
						coef(ht, 1, p.filter_h);
					if (!v2 && p.filter_v)
						coef(vt, 0, p.filter_v);
					if (!h2 && fhc)
						coef(hc, 3, fhc);
					if (!v2 && fvc)
						coef(vc, 2, fvc);
					printf(video ? " T" : " t");
				}
			}
			easf(&p);
		}
		/* hubp401_set_viewport. */
		VP(PRI_VIEWPORT, , p.viewport);
		VP(SEC_VIEWPORT, , p.viewport);
		VP(PRI_VIEWPORT, _C, p.viewport_c);
		VP(SEC_VIEWPORT, _C, p.viewport_c);
		putchar('\n');
	}
}
