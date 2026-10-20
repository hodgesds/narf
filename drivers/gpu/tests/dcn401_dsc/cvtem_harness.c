/* Linux's hpo_enc401_hdmi_set_dsc_config, compiled on the host: check.sh
 * extracts the function from dcn401_hpo_frl_stream_encoder.c into
 * set_dsc_config.c, included below with just the types it reads, its
 * register updates dropped and its packet writes printed. Each stdin line:
 *   <h_addressable> <h_total> <h_front_porch> <h_sync_width> <num_slices_h>
 *   <bits_per_pixel_x16> <PPS, 128 bytes hex>
 * prints, in write order, " <packet index>:<hb0..hb3 sb0..sb31 hex>" for
 * each packet. */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

enum dc_pixel_encoding {
	PIXEL_ENCODING_UNDEFINED,
	PIXEL_ENCODING_RGB,
	PIXEL_ENCODING_YCBCR422,
	PIXEL_ENCODING_YCBCR444,
	PIXEL_ENCODING_YCBCR420,
};
enum optc_dsc_mode {
	OPTC_DSC_DISABLED = 0,
	OPTC_DSC_ENABLED_444 = 1,
	OPTC_DSC_ENABLED_NATIVE_SUBSAMPLED = 2,
};
struct dc_dsc_config {
	uint32_t num_slices_h;
	uint32_t bits_per_pixel;
	bool ycbcr422_simple;
};
struct dc_crtc_timing {
	uint32_t h_total, h_border_left, h_addressable, h_border_right;
	uint32_t h_front_porch, h_sync_width;
	enum dc_pixel_encoding pixel_encoding;
	struct dc_dsc_config dsc_cfg;
};
struct dc_info_packet {
	bool valid;
	uint8_t hb0, hb1, hb2, hb3;
	uint8_t sb[32];
};
struct hpo_frl_stream_encoder {
	int unused;
};
struct dcn401_hpo_frl_stream_encoder {
	struct hpo_frl_stream_encoder base;
};
#define DCN401_HPO_FRL_STRENC_FROM_HPO_FRL_STRENC(e) ((struct dcn401_hpo_frl_stream_encoder *)(e))
#define REG_UPDATE(...) ((void)0)
#define REG_UPDATE_2(...) ((void)0)

static void hpo_enc401_update_hdmi_info_packet(struct dcn401_hpo_frl_stream_encoder *enc,
		uint32_t index, const struct dc_info_packet *p)
{
	int i;

	(void)enc;
	printf(" %u:%02x%02x%02x%02x", index, p->hb0, p->hb1, p->hb2, p->hb3);
	for (i = 0; i < 32; i++)
		printf("%02x", p->sb[i]);
}

#include "set_dsc_config.c"

int main(void)
{
	struct dcn401_hpo_frl_stream_encoder enc = { 0 };
	unsigned int ha, ht, hfp, hsw, slices, bpp;
	char hex[257];

	while (scanf("%u %u %u %u %u %u %256s", &ha, &ht, &hfp, &hsw, &slices, &bpp, hex) == 7) {
		struct dc_crtc_timing t = { 0 };
		uint8_t pps[128];
		int i;

		for (i = 0; i < 128; i++)
			sscanf(hex + 2 * i, "%2hhx", &pps[i]);
		t.h_addressable = ha;
		t.h_total = ht;
		t.h_front_porch = hfp;
		t.h_sync_width = hsw;
		t.pixel_encoding = PIXEL_ENCODING_RGB;
		t.dsc_cfg.num_slices_h = slices;
		t.dsc_cfg.bits_per_pixel = bpp;
		hpo_enc401_hdmi_set_dsc_config(&enc.base, &t, pps);
		printf("\n");
	}
	return 0;
}
