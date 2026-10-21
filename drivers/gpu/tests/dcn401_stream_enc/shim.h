/* The DC types the stream-encoder acquisition functions cut out of
 * dc_resource.c and dcn10_resource.c read, reduced to their used fields
 * (core_types.h, dc_types.h, grph_object_id.h, hw_shared.h). */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ASSERT(x) do { if (!(x)) { fprintf(stderr, "ASSERT %s\n", #x); exit(2); } } while (0)
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define MAX_PIPES 6
#define MAX_HPO_DP2_ENCODERS 4
#define MAX_HPO_DP2_LINK_ENCODERS 4

enum engine_id {
	ENGINE_ID_DIGA,
	ENGINE_ID_DIGB,
	ENGINE_ID_DIGC,
	ENGINE_ID_DIGD,
	ENGINE_ID_DIGE,
	ENGINE_ID_DIGF,
	ENGINE_ID_DIGG,
	ENGINE_ID_DACA,
	ENGINE_ID_DACB,
	ENGINE_ID_VCE,
	ENGINE_ID_HPO_0,
	ENGINE_ID_HPO_1,
	ENGINE_ID_HPO_DP_0,
	ENGINE_ID_HPO_DP_1,
	ENGINE_ID_HPO_DP_2,
	ENGINE_ID_HPO_DP_3,
	ENGINE_ID_VIRTUAL,
	ENGINE_ID_COUNT,
	ENGINE_ID_UNKNOWN = (-1L)
};

enum display_endpoint_type {
	DISPLAY_ENDPOINT_PHY = 0,
	DISPLAY_ENDPOINT_USB4_DPIA,
	DISPLAY_ENDPOINT_UNKNOWN = -1
};

struct stream_encoder {
	enum engine_id id;
};
struct hpo_dp_stream_encoder {
	int inst;
};
struct hpo_dp_link_encoder {
	int inst;
};
struct link_encoder {
	enum engine_id preferred_engine;
};
struct dc_link {
	unsigned int link_index;
	enum display_endpoint_type ep_type;
	struct link_encoder *link_enc;
	enum engine_id dpia_preferred_eng_id;
};
struct dc_stream_state {
	struct dc_link *link;
};
struct resource_context {
	bool is_stream_enc_acquired[MAX_PIPES * 2];
	bool is_hpo_dp_stream_enc_acquired[MAX_HPO_DP2_ENCODERS];
	unsigned int hpo_dp_link_enc_to_link_idx[MAX_HPO_DP2_LINK_ENCODERS];
	int hpo_dp_link_enc_ref_cnts[MAX_HPO_DP2_LINK_ENCODERS];
};
struct resource_pool {
	struct stream_encoder *stream_enc[MAX_PIPES * 2];
	unsigned int stream_enc_count;
	struct hpo_dp_stream_encoder *hpo_dp_stream_enc[MAX_HPO_DP2_ENCODERS];
	unsigned int hpo_dp_stream_enc_count;
	struct hpo_dp_link_encoder *hpo_dp_link_enc[MAX_HPO_DP2_LINK_ENCODERS];
	unsigned int hpo_dp_link_enc_count;
};
struct link_resource {
	struct hpo_dp_link_encoder *hpo_dp_link_enc;
};
struct pipe_ctx {
	struct link_resource link_res;
};
