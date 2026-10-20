/* Host harness for drivers/gpu/tests/dcn401_hdr/check.sh: the Linux
 * functions check.sh cuts out of the tree (linux_types.h, linux_fns.h),
 * compiled against the minimal stand-in types below.
 *
 * Each input line is one query; the output line is Linux's answer:
 *   meta <h|d|n> <hdr_output_metadata hex|-> <sink eotf bitmap>
 *     amdgpu_dm_fill_hdr_info_packet for an HDMI (h) or DP (d) connector,
 *     or one without the property set (n: no blob):
 *     "ret <errno> valid <0|1> <hb0..hb3 sb0..sb31 hex>"
 *   eq <blob hex|-> <blob hex|->
 *     drm_connector_atomic_hdr_metadata_equal: "eq <0|1>"
 *   edid <extension blocks hex>
 *     the CTA HDR Static Metadata Data Blocks drm_add_display_info parses,
 *     over the blocks edid_filter_invalid_blocks keeps: "none" (no block
 *     parsed) or "hdr <eotf> <type> <max_cll> <max_fall> <min_cll> lum
 *     <min> <max>"
 *   cs <drm colorspace> <rgb> <y_only> <pix_clk_100hz> <broadcast_rgb>
 *     amdgpu_dm_get_output_color_space: "<enum dc_color_space>"
 *   sig <dc_color_space> <dc_pixel_encoding> <bpc> <qs> <gamma22> <vsc> <misc1>
 *     set_avi_info_frame's C/EC/Q/YQ, enc401's MSA MISC0/MISC1 and
 *     mod_build_vsc_infopacket: "avi <c> <ec> <q> <yq> msa <misc0> <misc1>
 *     vsc <-|36 bytes hex>"
 *   hpo <dc_color_space> <dc_pixel_encoding> <bpc> <vsc>
 *     dcn31_hpo_dp_stream_enc_set_stream_attribute's MISC0/MISC1 (the
 *     128b/132b stream's MSA6/MSA7 lane 3): "msa <misc0> <misc1>"
 * `--generate` prints "input = output" for the deterministic vector set.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/types.h>
#include <linux/hdmi.h>

#define EINVAL 22
#define ENOSPC 28
/* include/uapi/drm/drm_mode.h */
#define DRM_MODE_CONNECTOR_DisplayPort 10
#define DRM_MODE_CONNECTOR_HDMIA 11
#define DRM_MODE_CONNECTOR_eDP 14
#define EXPORT_SYMBOL(x)
#define EXPORT_IF_KUNIT(x)
#define STATIC_IFN_KUNIT static
#define INLINE_IFN_KUNIT
#define DRM_DEBUG_KMS(...) ((void)0)
#define drm_dbg_kms(...) ((void)0)
#define print_hex_dump(...) ((void)0)
#define BUILD_BUG_ON(x) _Static_assert(!(x), #x)

#include "linux_types.h"

struct drm_luminance_range_info {
	u32 min_luminance;
	u32 max_luminance;
};
struct drm_display_info {
	struct hdr_sink_metadata hdr_sink_metadata;
	struct drm_luminance_range_info luminance_range;
};
struct drm_connector {
	int connector_type;
	struct drm_display_info display_info;
};
struct drm_property_blob {
	size_t length;
	void *data;
};
struct drm_connector_state {
	struct drm_connector *connector;
	struct drm_property_blob *hdr_output_metadata;
	u32 colorspace;
	struct {
		enum drm_hdmi_broadcast_rgb broadcast_rgb;
	} hdmi;
};
struct dc_info_packet {
	bool valid;
	u8 hb0, hb1, hb2, hb3;
	u8 sb[32];
};
struct dc_crtc_timing {
	struct {
		u32 Y_ONLY : 1;
		u32 INTERLACE : 1;
		u32 DSC : 1;
	} flags;
	enum dc_pixel_encoding pixel_encoding;
	enum dc_color_depth display_color_depth;
	u32 pix_clk_100hz;
	enum dc_timing_3d_format timing_3d_format;
};
struct dc_link {
	struct {
		enum dc_psr_version psr_version;
	} psr_settings;
	struct {
		struct {
			bool replay_supported;
			enum dc_replay_version replay_version;
		} config;
	} replay_settings;
};
struct dc_stream_state {
	struct dc_crtc_timing timing;
	enum view_3d_format view_format;
	struct dc_link *link;
	bool use_vsc_sdp_for_colorimetry;
	enum dc_color_space output_color_space;
	int qs_bit;
	struct {
		enum dc_transfer_func_predefined tf;
	} out_transfer_func;
};
struct avi_bits {
	u8 C0_C1, EC0_EC2, Q0_Q1, YQ0_YQ1;
};
struct avi_info {
	struct avi_bits bits;
};
struct cea_db_iter {
	const u8 *collection;
	int index, end;
};

#include "linux_fns.h"

static void hex(const u8 *p, size_t n, char *out)
{
	for (size_t i = 0; i < n; i++)
		sprintf(out + 2 * i, "%02x", p[i]);
	out[2 * n] = 0;
}
static size_t unhex(const char *s, u8 *out, size_t max)
{
	size_t n = strlen(s) / 2;
	if (n > max)
		n = max;
	for (size_t i = 0; i < n; i++) {
		unsigned v;
		sscanf(s + 2 * i, "%2x", &v);
		out[i] = v;
	}
	return n;
}

static void q_meta(char kind, const char *blob, unsigned sink_eotf, char *out)
{
	static u8 data[64];
	struct drm_property_blob b = { 0, data };
	struct drm_connector c = { 0 };
	struct drm_connector_state s = { 0 };
	struct dc_info_packet p;
	u8 raw[36];
	char h[80];
	int r;

	c.connector_type = kind == 'd' ? DRM_MODE_CONNECTOR_DisplayPort : DRM_MODE_CONNECTOR_HDMIA;
	c.display_info.hdr_sink_metadata.hdmi_type1.eotf = sink_eotf;
	s.connector = &c;
	if (kind != 'n' && strcmp(blob, "-")) {
		b.length = unhex(blob, data, sizeof(data));
		s.hdr_output_metadata = &b;
	}
	r = amdgpu_dm_fill_hdr_info_packet(&s, &p);
	raw[0] = p.hb0;
	raw[1] = p.hb1;
	raw[2] = p.hb2;
	raw[3] = p.hb3;
	memcpy(raw + 4, p.sb, 32);
	hex(raw, 36, h);
	sprintf(out, "ret %d valid %d %s", -r, p.valid, h);
}

static void q_eq(const char *a, const char *b, char *out)
{
	static u8 da[64], db[64];
	struct drm_property_blob ba = { 0, da }, bb = { 0, db };
	struct drm_connector_state sa = { 0 }, sb = { 0 };

	if (strcmp(a, "-")) {
		ba.length = unhex(a, da, sizeof(da));
		sa.hdr_output_metadata = &ba;
	}
	if (strcmp(b, "-")) {
		bb.length = unhex(b, db, sizeof(db));
		sb.hdr_output_metadata = &bb;
	}
	sprintf(out, "eq %d", drm_connector_atomic_hdr_metadata_equal(&sa, &sb));
}

/* drm_add_display_info's cea_db_iter_for_each over the EDID CTA
 * extensions (no DisplayID), dispatching only the HDR metadata block, on a
 * display_info that drm_reset_display_info cleared. */
static void q_edid(const char *blocks, char *out)
{
	static u8 e[128 * 8];
	struct drm_connector c = { 0 };
	struct hdr_static_metadata *m = &c.display_info.hdr_sink_metadata.hdmi_type1;
	size_t n = unhex(blocks, e, sizeof(e)) / 128;
	int parsed = 0;

	for (size_t b = 0; b < n; b++) {
		const u8 *ext = e + 128 * b;
		u8 sum = 0;
		struct cea_db_iter it;
		const struct cea_db *db;
		int size;

		for (int i = 0; i < 128; i++)
			sum += ext[i];
		if (sum) /* edid_filter_invalid_blocks */
			continue;
		if (ext[0] != 0x02 || cea_revision(ext) < 3)
			continue;
		size = cea_db_collection_size(ext);
		if (!size)
			continue;
		it.collection = ext;
		it.index = 4;
		it.end = 4 + size;
		while ((db = __cea_db_iter_current_block(&it))) {
			if (cea_db_is_hdmi_hdr_metadata_block(db)) {
				drm_parse_hdr_metadata_block(&c, (const u8 *)db);
				parsed = 1;
			}
			it.index += sizeof(*db) + cea_db_payload_len(db);
		}
	}
	if (!parsed) {
		strcpy(out, "none");
		return;
	}
	sprintf(out, "hdr %u %u %u %u %u lum %u %u", m->eotf, m->metadata_type, m->max_cll,
		m->max_fall, m->min_cll, c.display_info.luminance_range.min_luminance,
		c.display_info.luminance_range.max_luminance);
}

static void q_cs(unsigned cs, int rgb, int y_only, unsigned clk, unsigned brgb, char *out)
{
	struct dc_crtc_timing t = { 0 };
	struct drm_connector_state s = { 0 };

	t.pixel_encoding = rgb ? PIXEL_ENCODING_RGB : PIXEL_ENCODING_YCBCR420;
	t.flags.Y_ONLY = y_only;
	t.pix_clk_100hz = clk;
	s.colorspace = cs;
	s.hdmi.broadcast_rgb = brgb;
	sprintf(out, "%d", amdgpu_dm_get_output_color_space(&t, &s));
}

static enum dc_color_depth depth(unsigned bpc)
{
	switch (bpc) {
	case 6: return COLOR_DEPTH_666;
	case 8: return COLOR_DEPTH_888;
	case 10: return COLOR_DEPTH_101010;
	case 12: return COLOR_DEPTH_121212;
	case 16: return COLOR_DEPTH_161616;
	default: return COLOR_DEPTH_UNDEFINED;
	}
}

static void q_sig(unsigned cs, unsigned enc, unsigned bpc, int qs, int gamma22, int vsc,
		  unsigned misc1, char *out)
{
	struct dc_link link = { 0 };
	struct dc_stream_state s = { 0 };
	struct avi_info avi = { 0 };
	struct dc_info_packet p = { 0 };
	uint32_t m0, m1;
	/* set_avi_info_frame's Y0_Y1_Y2 */
	uint32_t y = enc == PIXEL_ENCODING_YCBCR422 ? 1 :
		     enc == PIXEL_ENCODING_YCBCR444 ? 2 :
		     enc == PIXEL_ENCODING_YCBCR420 ? 3 : 0;
	char v[80];

	link.psr_settings.psr_version = DC_PSR_VERSION_UNSUPPORTED;
	link.replay_settings.config.replay_version = DC_REPLAY_VERSION_UNSUPPORTED;
	s.link = &link;
	s.timing.pixel_encoding = enc;
	s.timing.display_color_depth = depth(bpc);
	s.timing.timing_3d_format = TIMING_3D_FORMAT_NONE;
	s.view_format = VIEW_3D_FORMAT_NONE;
	s.use_vsc_sdp_for_colorimetry = vsc;
	s.qs_bit = qs;
	s.out_transfer_func.tf = gamma22 ? TRANSFER_FUNCTION_GAMMA22 : TRANSFER_FUNCTION_SRGB;
	s.output_color_space = cs;
	set_avi_colorimetry(&avi, &s, y);
	dp_msa_misc(&s.timing, cs, vsc, misc1, &m0, &m1);
	mod_build_vsc_infopacket(&s, &p, cs, gamma22 ? TRANSFER_FUNC_GAMMA_22 : TRANSFER_FUNC_UNKNOWN);
	if (p.valid) {
		u8 raw[36] = { p.hb0, p.hb1, p.hb2, p.hb3 };
		memcpy(raw + 4, p.sb, 32);
		hex(raw, 36, v);
	} else {
		strcpy(v, "-");
	}
	sprintf(out, "avi %u %u %u %u msa %u %u vsc %s", avi.bits.C0_C1, avi.bits.EC0_EC2,
		avi.bits.Q0_Q1, avi.bits.YQ0_YQ1, m0, m1, v);
}

static void q_hpo(unsigned cs, unsigned enc, unsigned bpc, int vsc, char *out)
{
	struct dc_crtc_timing t = { 0 };
	uint32_t m0, m1;

	t.pixel_encoding = enc;
	t.display_color_depth = depth(bpc);
	hpo_msa_misc(&t, cs, vsc, &m0, &m1);
	sprintf(out, "msa %u %u", m0, m1);
}

static void answer(char *line, char *out)
{
	char kind[8], a[2048], b[2048];
	unsigned n[8];

	if (sscanf(line, "meta %7s %2047s %x", kind, a, &n[0]) == 3)
		q_meta(kind[0], a, n[0], out);
	else if (sscanf(line, "eq %2047s %2047s", a, b) == 2)
		q_eq(a, b, out);
	else if (sscanf(line, "edid %2047s", a) == 1)
		q_edid(a, out);
	else if (sscanf(line, "cs %u %u %u %u %u", &n[0], &n[1], &n[2], &n[3], &n[4]) == 5)
		q_cs(n[0], n[1], n[2], n[3], n[4], out);
	else if (sscanf(line, "sig %u %u %u %u %u %u %x", &n[0], &n[1], &n[2], &n[3], &n[4],
			&n[5], &n[6]) == 7)
		q_sig(n[0], n[1], n[2], n[3], n[4], n[5], n[6], out);
	else if (sscanf(line, "hpo %u %u %u %u", &n[0], &n[1], &n[2], &n[3]) == 4)
		q_hpo(n[0], n[1], n[2], n[3], out);
	else
		strcpy(out, "?");
}

/* --generate */
static uint32_t seed = 4011;
static uint32_t rnd(void)
{
	seed = seed * 1103515245u + 12345u;
	return seed >> 8;
}
static void emit(const char *in)
{
	char line[4096], out[256];
	strcpy(line, in);
	answer(line, out);
	printf("%s = %s\n", in, out);
}
static void blob_hex(char *out, int eotf, int type, int outer)
{
	u8 b[32] = { 0 };
	uint32_t ot = outer;
	memcpy(b, &ot, 4);
	b[4] = eotf;
	b[5] = type;
	for (int i = 6; i < 32; i++)
		b[i] = rnd();
	hex(b, 32, out);
}
/* A CTA extension (revision rev, DTD offset d) whose collection is `dbc`,
 * checksummed unless bad. */
static void cta(char *out, int rev, int d, const u8 *dbc, int len, int bad)
{
	u8 e[128] = { 0x02, rev, d, 0 };
	u8 sum = 0;
	memcpy(e + 4, dbc, len);
	for (int i = 0; i < 127; i++)
		sum += e[i];
	e[127] = (u8)(0x100 - sum) + (bad ? 1 : 0);
	hex(e, 128, out);
}
static int hdr_db(u8 *p, int len, int fill)
{
	/* extended tag block: header, tag 6, then len-1 payload bytes */
	p[0] = 7 << 5 | len;
	p[1] = 6;
	for (int i = 2; i <= len; i++)
		p[i] = fill ? rnd() : 0;
	return len + 1;
}
static void generate(void)
{
	char in[4096], x[1024], y[1024];
	static const char conn[] = "hdn";

	/* HDR metadata: every EOTF code, valid and other descriptor IDs, an
	 * outer metadata_type DRM ignores, extreme values, sink EOTF maps. */
	for (int c = 0; c < 3; c++)
		for (int eotf = 0; eotf < 8; eotf++)
			for (int t = 0; t < 3; t++) {
				blob_hex(x, eotf, t == 2 ? 0xff : t, t == 1 ? 7 : 0);
				sprintf(in, "meta %c %s %x", conn[c], x, rnd() & 0xff);
				emit(in);
			}
	for (int i = 0; i < 60; i++) {
		blob_hex(x, rnd() % 256, rnd() % 4 ? 0 : rnd() % 256, rnd() % 3);
		if (i % 7 == 0)
			memset(x + 8, i % 2 ? 'f' : '0', 48);
		sprintf(in, "meta %c %s %x", conn[i % 2], x, rnd() & 0xff);
		emit(in);
	}
	sprintf(in, "meta h - 0");
	emit(in);

	/* Blob equality */
	blob_hex(x, 2, 0, 0);
	strcpy(y, x);
	sprintf(in, "eq %s %s", x, y);
	emit(in);
	y[63] = y[63] == '0' ? '1' : '0';
	sprintf(in, "eq %s %s", x, y);
	emit(in);
	sprintf(in, "eq %s -", x);
	emit(in);
	sprintf(in, "eq - %s", x);
	emit(in);
	sprintf(in, "eq - -");
	emit(in);
	sprintf(in, "eq %s %.62s", x, x);
	emit(in);

	/* EDID HDR static metadata blocks */
	for (int len = 0; len <= 10; len++)
		for (int k = 0; k < 4; k++) {
			u8 dbc[64];
			int at = 0;
			if (k & 1) { /* a VCDB before it */
				dbc[at++] = 7 << 5 | 2;
				dbc[at++] = 0;
				dbc[at++] = 0x40;
			}
			if (len)
				at += hdr_db(dbc + at, len, 1);
			else
				dbc[at++] = 7 << 5; /* empty extended block */
			if (k & 2) { /* a video block after it */
				dbc[at++] = 2 << 5 | 2;
				dbc[at++] = 16;
				dbc[at++] = 4;
			}
			cta(x, 3, 4 + at, dbc, at, 0);
			sprintf(in, "edid %s", x);
			emit(in);
		}
	for (int i = 0; i < 80; i++) {
		u8 dbc[100];
		int at = 0, nblocks = 1 + rnd() % 3;
		char all[2048] = "";
		for (int b = 0; b < nblocks; b++) {
			at = 0;
			int nb = rnd() % 4;
			for (int j = 0; j < nb && at < 90; j++) {
				if (rnd() % 2)
					at += hdr_db(dbc + at, 2 + rnd() % 6, 1);
				else {
					int l = rnd() % 6;
					dbc[at++] = (rnd() % 8) << 5 | l;
					for (int q = 0; q < l; q++)
						dbc[at++] = rnd();
				}
			}
			int rev = rnd() % 5 ? 3 : rnd() % 4;
			int d = rnd() % 8 ? 4 + at : rnd() % 130;
			if (d > 127 && rnd() % 2)
				d = 127;
			cta(x, rev, d, dbc, at, rnd() % 12 == 0);
			strcat(all, x);
		}
		sprintf(in, "edid %s", all);
		emit(in);
	}

	/* Colorspace -> dc_color_space */
	static const unsigned cspaces[] = { 0, 1, 2, 7, 9, 10, 15 };
	static const unsigned clks[] = { 251750, 270000, 270300, 270301, 1485000 };
	for (unsigned i = 0; i < sizeof(cspaces) / sizeof(cspaces[0]); i++)
		for (int rgb = 0; rgb < 2; rgb++)
			for (int yo = 0; yo < 2; yo++)
				for (unsigned k = 0; k < 5; k++)
					for (int br = 0; br < 3; br++) {
						sprintf(in, "cs %u %d %d %u %d", cspaces[i], rgb, yo, clks[k], br);
						emit(in);
					}

	/* Signalling for every dc_color_space */
	static const unsigned bpcs[] = { 6, 8, 10, 12, 16 };
	for (unsigned cs = 0; cs <= COLOR_SPACE_YCBCR709_BLACK; cs++)
		for (unsigned enc = PIXEL_ENCODING_RGB; enc <= PIXEL_ENCODING_YCBCR420; enc++)
			for (unsigned b = 0; b < 5; b++)
				for (int qs = 0; qs < 2; qs++)
					for (int g = 0; g < 2; g++) {
						int vsc = (cs + enc + b + qs + g) % 2;
						unsigned m1 = (cs * 37 + enc * 11 + b * 5) & 0xff;
						sprintf(in, "sig %u %u %u %d %d %d %x", cs, enc, bpcs[b], qs, g, vsc, m1);
						emit(in);
					}

	/* The 128b/132b stream's MSA MISC bytes */
	for (unsigned cs = 0; cs <= COLOR_SPACE_YCBCR709_BLACK; cs++)
		for (unsigned enc = PIXEL_ENCODING_RGB; enc <= PIXEL_ENCODING_YCBCR420; enc++)
			for (unsigned b = 0; b < 5; b++)
				for (int vsc = 0; vsc < 2; vsc++) {
					sprintf(in, "hpo %u %u %u %d", cs, enc, bpcs[b], vsc);
					emit(in);
				}
}

int main(int argc, char **argv)
{
	char line[8192], out[256];

	if (argc > 1 && !strcmp(argv[1], "--generate")) {
		generate();
		return 0;
	}
	while (fgets(line, sizeof(line), stdin)) {
		line[strcspn(line, "\n")] = 0;
		answer(line, out);
		puts(out);
	}
	return 0;
}
