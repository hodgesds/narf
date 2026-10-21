/* The pieces of DC the extracted pipe acquisition code touches, as host C.
 * check.sh prepends this to the functions it cuts out of the Linux tree. */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dc_spl.h"

#define MAX_PIPES 6
#define MAX_SURFACES 4
#define MAX_STREAMS 6
#define FREE_PIPE_INDEX_NOT_FOUND -1
#define ASSERT(x) ((void)(x))
#define DC_LOGGER_INIT(x) ((void)(x))
#define DC_LOG_WARNING(...) ((void)0)
#define dm_error(...) ((void)0)

enum dc_status {
	DC_OK = 1,
	DC_NO_CONTROLLER_RESOURCE,
	DC_ERROR_UNEXPECTED,
};
enum pipe_type { OTG_MASTER, OPP_HEAD, DPP_PIPE, FREE_PIPE };

struct dc_crtc_timing;
struct timing_generator_funcs {
	bool (*is_two_pixels_per_container)(const struct dc_crtc_timing *timing);
};
struct timing_generator { int inst; const struct timing_generator_funcs *funcs; };
struct mem_input { int inst; };
struct hubp { int inst; };
struct input_pixel_processor { int inst; };
struct transform { int inst; };
struct dpp { int inst; };
enum dc_pixel_encoding { PIXEL_ENCODING_RGB, PIXEL_ENCODING_YCBCR422, PIXEL_ENCODING_YCBCR444,
	PIXEL_ENCODING_YCBCR420 };
struct output_pixel_processor;
struct opp_funcs {
	uint32_t (*opp_get_left_edge_extra_pixel_count)(struct output_pixel_processor *opp,
			enum dc_pixel_encoding encoding, bool is_primary);
};
struct output_pixel_processor { int inst; const struct opp_funcs *funcs; };
struct display_stream_compressor { int inst; };
struct dsc_padding_params { int h_padding; int dsc_hactive_padding; };
struct logger { int unused; };

struct rect { int x, y, width, height; };
/* A plane's DC rectangles (amdgpu_dm_plane_fill_dc_scaling_info): its
 * source in the surface and destination on the stream. A zero-width source
 * is a plane the script gave no geometry. */
struct dc_plane_state { int id; struct rect src_rect, dst_rect; };
struct dc_crtc_timing_flags { uint32_t DSC; };
struct dc_crtc_timing {
	struct dc_crtc_timing_flags flags;
	uint32_t h_addressable, v_addressable;
	uint32_t h_border_left, h_border_right, v_border_top, v_border_bottom;
	enum dc_pixel_encoding pixel_encoding;
};
struct dc;
struct dc_context { struct dc *dc; struct logger *logger; };
struct dc_stream_state {
	struct dc_context *ctx;
	struct dc_crtc_timing timing;
	uint32_t stream_id;
};

struct stream_resource {
	struct output_pixel_processor *opp;
	struct timing_generator *tg;
	struct display_stream_compressor *dsc;
};
struct plane_resource {
	struct mem_input *mi;
	struct input_pixel_processor *ipp;
	struct transform *xfm;
	struct dpp *dpp;
	struct hubp *hubp;
	uint8_t mpcc_inst;
};
struct pipe_ctx {
	struct dc_plane_state *plane_state;
	struct dc_stream_state *stream;
	struct plane_resource plane_res;
	struct stream_resource stream_res;
	struct dsc_padding_params dsc_padding_params;
	uint8_t pipe_idx;
	struct pipe_ctx *top_pipe;
	struct pipe_ctx *bottom_pipe;
	struct pipe_ctx *next_odm_pipe;
	struct pipe_ctx *prev_odm_pipe;
};
struct resource_context {
	struct pipe_ctx pipe_ctx[MAX_PIPES];
	bool is_dsc_acquired[MAX_PIPES];
};
struct dc_stream_status {
	int plane_count;
	struct dc_plane_state *plane_states[MAX_SURFACES];
};
struct dc_state {
	struct dc_stream_state *streams[MAX_STREAMS];
	struct dc_stream_status stream_status[MAX_STREAMS];
	uint8_t stream_count;
	struct resource_context res_ctx;
};

struct resource_pool;
struct resource_funcs {
	struct pipe_ctx *(*acquire_free_pipe_as_secondary_dpp_pipe)(
			const struct dc_state *cur_ctx, struct dc_state *new_ctx,
			const struct resource_pool *pool, const struct pipe_ctx *opp_head_pipe);
	struct pipe_ctx *(*acquire_free_pipe_as_secondary_opp_head)(
			const struct dc_state *cur_ctx, struct dc_state *new_ctx,
			const struct resource_pool *pool, const struct pipe_ctx *otg_master);
	void (*release_pipe)(struct dc_state *context, struct pipe_ctx *pipe,
			const struct resource_pool *pool);
	enum dc_status (*add_stream_to_ctx)(struct dc *dc, struct dc_state *new_ctx,
			struct dc_stream_state *stream);
	void (*build_pipe_pix_clk_params)(struct pipe_ctx *pipe_ctx);
};
struct resource_caps { int num_opp, num_dsc; };
struct resource_pool {
	struct mem_input *mis[MAX_PIPES];
	struct hubp *hubps[MAX_PIPES];
	struct input_pixel_processor *ipps[MAX_PIPES];
	struct transform *transforms[MAX_PIPES];
	struct dpp *dpps[MAX_PIPES];
	struct output_pixel_processor *opps[MAX_PIPES];
	struct timing_generator *timing_generators[MAX_PIPES];
	struct display_stream_compressor *dscs[MAX_PIPES];
	unsigned int pipe_count;
	unsigned int timing_generator_count;
	const struct resource_funcs *funcs;
	const struct resource_caps *res_cap;
};
struct dc_config { bool enable_windowed_mpo_odm; };
struct dc {
	struct dc_context *ctx;
	struct dc_state *current_state;
	struct resource_pool *res_pool;
	struct dc_config config;
};

/* DML2's pipe-mapping context, reduced to the callbacks DCN401 sets
 * (dcn401_resource.c's dml2_options.callbacks) and its scratch. */
struct dml_display_cfg_st { int unused; };
struct dml2_dml_to_dc_pipe_mapping { int unused; };
struct dml2_pipe_combine_factor {
	unsigned int source;
	unsigned int target;
};
struct dml2_dc_callbacks {
	struct dc *dc;
	bool (*update_pipes_for_stream_with_slice_count)(
			struct dc_state *new_ctx, const struct dc_state *cur_ctx,
			const struct resource_pool *pool, const struct dc_stream_state *stream,
			int new_slice_count);
	bool (*update_pipes_for_plane_with_slice_count)(
			struct dc_state *new_ctx, const struct dc_state *cur_ctx,
			const struct resource_pool *pool, const struct dc_plane_state *plane,
			int slice_count);
	struct pipe_ctx *(*get_otg_master_for_stream)(struct resource_context *res_ctx,
			const struct dc_stream_state *stream);
	int (*get_odm_slice_count)(const struct pipe_ctx *opp_head);
	int (*get_mpc_slice_count)(const struct pipe_ctx *opp_head);
	int (*get_dpp_pipes_for_plane)(const struct dc_plane_state *plane,
			struct resource_context *res_ctx, struct pipe_ctx *dpp_pipes[MAX_PIPES]);
};
struct dml2_configuration_options { struct dml2_dc_callbacks callbacks; };
struct dml2_pipe_combine_scratch {
	struct dml2_pipe_combine_factor odm_factors[MAX_PIPES];
	struct dml2_pipe_combine_factor mpc_factors[MAX_PIPES][MAX_PIPES];
};
struct dml2_context {
	struct dml2_configuration_options config;
	struct dml2_pipe_combine_scratch pipe_combine_scratch;
};

/* What the extracted code calls outside the pipe acquisition.
 * resource_build_scaling_params runs SPL on the pipe's slice of its plane
 * (harness.c). */
static bool resource_build_scaling_params(struct pipe_ctx *pipe_ctx);
static void resource_build_test_pattern_params(struct resource_context *res_ctx,
		struct pipe_ctx *otg_master)
{
	(void)res_ctx;
	(void)otg_master;
}
static void dc_stream_retain(struct dc_stream_state *stream) { (void)stream; }
static void dc_stream_release(struct dc_stream_state *stream) { (void)stream; }
static void dc_stream_release_3dlut_for_stream(const struct dc *dc,
		struct dc_stream_state *stream)
{
	(void)dc;
	(void)stream;
}
static void dc_plane_state_retain(struct dc_plane_state *plane) { (void)plane; }
static void dc_plane_state_release(struct dc_plane_state *plane) { (void)plane; }
static struct dc_stream_status *dc_state_get_stream_status(struct dc_state *state,
		const struct dc_stream_state *stream)
{
	for (int i = 0; i < state->stream_count; i++)
		if (state->streams[i] == stream)
			return &state->stream_status[i];
	return NULL;
}

/* The extracted functions, declared up front (they call each other in
 * file order, which differs from the order check.sh concatenates them). */
bool resource_is_pipe_type(const struct pipe_ctx *pipe_ctx, enum pipe_type type);
struct pipe_ctx *resource_get_otg_master_for_stream(struct resource_context *res_ctx,
		const struct dc_stream_state *stream);
int resource_get_opp_heads_for_otg_master(const struct pipe_ctx *otg_master,
		struct resource_context *res_ctx, struct pipe_ctx *opp_heads[MAX_PIPES]);
int resource_get_dpp_pipes_for_plane(const struct dc_plane_state *plane,
		struct resource_context *res_ctx, struct pipe_ctx *dpp_pipes[MAX_PIPES]);
struct pipe_ctx *resource_get_otg_master(const struct pipe_ctx *pipe_ctx);
struct pipe_ctx *resource_get_opp_head(const struct pipe_ctx *pipe_ctx);
int resource_get_odm_slice_index(const struct pipe_ctx *pipe_ctx);
int resource_get_odm_slice_dst_width(struct pipe_ctx *otg_master, bool is_last_segment);
struct rect resource_get_odm_slice_dst_rect(struct pipe_ctx *pipe_ctx);
struct rect resource_get_odm_slice_src_rect(struct pipe_ctx *pipe_ctx);
int resource_get_mpc_slice_index(const struct pipe_ctx *pipe_ctx);
int resource_get_mpc_slice_count(const struct pipe_ctx *pipe);
int resource_get_odm_slice_count(const struct pipe_ctx *pipe);
int resource_find_free_pipe_used_as_sec_opp_head_by_cur_otg_master(
		const struct resource_context *cur_res_ctx, struct resource_context *new_res_ctx,
		const struct pipe_ctx *cur_otg_master);
int resource_find_free_pipe_used_in_cur_mpc_blending_tree(
		const struct resource_context *cur_res_ctx, struct resource_context *new_res_ctx,
		const struct pipe_ctx *cur_opp_head);
int recource_find_free_pipe_not_used_in_cur_res_ctx(
		const struct resource_context *cur_res_ctx, struct resource_context *new_res_ctx,
		const struct resource_pool *pool);
int recource_find_free_pipe_used_as_otg_master_in_cur_res_ctx(
		const struct resource_context *cur_res_ctx, struct resource_context *new_res_ctx,
		const struct resource_pool *pool);
int resource_find_free_pipe_used_as_cur_sec_dpp(
		const struct resource_context *cur_res_ctx, struct resource_context *new_res_ctx,
		const struct resource_pool *pool);
int resource_find_free_pipe_used_as_cur_sec_dpp_in_mpcc_combine(
		const struct resource_context *cur_res_ctx, struct resource_context *new_res_ctx,
		const struct resource_pool *pool);
int resource_find_any_free_pipe(struct resource_context *new_res_ctx,
		const struct resource_pool *pool);
bool resource_append_dpp_pipes_for_plane_composition(struct dc_state *new_ctx,
		struct dc_state *cur_ctx, struct resource_pool *pool,
		struct pipe_ctx *otg_master_pipe, struct dc_plane_state *plane_state);
void resource_remove_dpp_pipes_for_plane_composition(struct dc_state *context,
		const struct resource_pool *pool, const struct dc_plane_state *plane_state);
bool resource_update_pipes_for_stream_with_slice_count(struct dc_state *new_ctx,
		const struct dc_state *cur_ctx, const struct resource_pool *pool,
		const struct dc_stream_state *stream, int new_slice_count);
bool resource_update_pipes_for_plane_with_slice_count(struct dc_state *new_ctx,
		const struct dc_state *cur_ctx, const struct resource_pool *pool,
		const struct dc_plane_state *plane, int new_slice_count);
enum dc_status resource_add_otg_master_for_stream_output(struct dc_state *new_ctx,
		const struct resource_pool *pool, struct dc_stream_state *stream);
void resource_remove_otg_master_for_stream_output(struct dc_state *context,
		const struct resource_pool *pool, struct dc_stream_state *stream);
static bool acquire_otg_master_pipe_for_stream(const struct dc_state *cur_ctx,
		struct dc_state *new_ctx, const struct resource_pool *pool,
		struct dc_stream_state *stream);
static int acquire_first_split_pipe(struct resource_context *res_ctx,
		const struct resource_pool *pool, struct dc_stream_state *stream);
static int get_num_of_free_pipes(const struct resource_pool *pool,
		const struct dc_state *context);
static struct pipe_ctx *get_tail_pipe(struct pipe_ctx *head_pipe);
static struct pipe_ctx *get_last_opp_head(struct pipe_ctx *opp_head);
static struct pipe_ctx *get_last_dpp_pipe_in_mpcc_combine(struct pipe_ctx *dpp_pipe);
static bool update_pipe_params_after_odm_slice_count_change(struct pipe_ctx *otg_master,
		struct dc_state *context, const struct resource_pool *pool);
static bool update_pipe_params_after_mpc_slice_count_change(
		const struct dc_plane_state *plane, struct dc_state *context,
		const struct resource_pool *pool);
static bool add_plane_to_opp_head_pipes(struct pipe_ctx *otg_master_pipe,
		struct dc_plane_state *plane_state, struct dc_state *context);
static bool acquire_secondary_dpp_pipes_and_add_plane(struct pipe_ctx *otg_master_pipe,
		struct dc_plane_state *plane_state, struct dc_state *new_ctx,
		struct dc_state *cur_ctx, struct resource_pool *pool);
static bool acquire_pipes_and_add_odm_slice(struct pipe_ctx *otg_master_pipe,
		struct dc_state *new_ctx, const struct dc_state *cur_ctx,
		const struct resource_pool *pool);
static bool release_pipes_and_remove_odm_slice(struct pipe_ctx *otg_master_pipe,
		struct dc_state *context, const struct resource_pool *pool);
static bool acquire_dpp_pipe_and_add_mpc_slice(struct pipe_ctx *dpp_pipe,
		struct dc_state *new_ctx, const struct dc_state *cur_ctx,
		const struct resource_pool *pool);
static bool release_dpp_pipe_and_remove_mpc_slice(struct pipe_ctx *dpp_pipe,
		struct dc_state *context, const struct resource_pool *pool);
int dcn32_find_optimal_free_pipe_as_secondary_dpp_pipe(
		const struct resource_context *cur_res_ctx, struct resource_context *new_res_ctx,
		const struct resource_pool *pool, const struct pipe_ctx *new_opp_head);
struct pipe_ctx *dcn32_acquire_free_pipe_as_secondary_dpp_pipe(
		const struct dc_state *cur_ctx, struct dc_state *new_ctx,
		const struct resource_pool *pool, const struct pipe_ctx *opp_head_pipe);
struct pipe_ctx *dcn32_acquire_free_pipe_as_secondary_opp_head(
		const struct dc_state *cur_ctx, struct dc_state *new_ctx,
		const struct resource_pool *pool, const struct pipe_ctx *otg_master);
static struct pipe_ctx *dcn32_acquire_idle_pipe_for_head_pipe_in_layer(
		struct dc_state *state, const struct resource_pool *pool,
		struct dc_stream_state *stream, const struct pipe_ctx *head_pipe);
static struct pipe_ctx *find_idle_secondary_pipe_check_mpo(
		struct resource_context *res_ctx, const struct resource_pool *pool,
		const struct pipe_ctx *primary_pipe);
static int find_optimal_free_pipe_as_secondary_opp_head(
		const struct resource_context *cur_res_ctx, struct resource_context *new_res_ctx,
		const struct resource_pool *pool, const struct pipe_ctx *new_otg_master);
void dcn20_acquire_dsc(const struct dc *dc, struct resource_context *res_ctx,
		struct display_stream_compressor **dsc, int pipe_idx);
void dcn20_release_dsc(struct resource_context *res_ctx, const struct resource_pool *pool,
		struct display_stream_compressor **dsc);
void dcn20_release_pipe(struct dc_state *context, struct pipe_ctx *pipe,
		const struct resource_pool *pool);
static unsigned int get_target_odm_factor(const struct dml2_context *ctx,
		struct dc_state *state, const struct dml_display_cfg_st *disp_cfg,
		struct dml2_dml_to_dc_pipe_mapping *mapping, const struct dc_stream_state *stream);
static unsigned int get_target_mpc_factor(struct dml2_context *ctx, struct dc_state *state,
		const struct dml_display_cfg_st *disp_cfg,
		struct dml2_dml_to_dc_pipe_mapping *mapping, const struct dc_stream_status *status,
		const struct dc_stream_state *stream, int plane_idx);
