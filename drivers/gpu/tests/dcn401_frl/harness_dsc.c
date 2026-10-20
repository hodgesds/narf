/* Linux's compressed HDMI FRL capacity check (dml1_frl_cap_chk_compressed),
 * as hpo_enc3_validate_hdmi_frl_output feeds it for a DSC stream, then
 * frl_modify_borrow_mode_for_dsc_padding with no padding, as
 * hdmi_frl_decide_link_settings applies it to the decided link:
 *   harness_dsc <lanes> <rate_gbps> <pix_clk_100hz> <h_active> <h_blank>
 *               <bpc> <encoding 0=444 1=422 2=420> <audio_packet_type>
 *               <f_audio> <layout> <slices> <slice_width> <bpp_x16> <vic>
 *               <all_bpp>
 * Prints "<result> <audio_packets_line> <borrow_mode> <hc_active>
 * <hc_blank> <padding_borrow_mode>". */
#include "dml1_frl_cap_chk.h"
#include <stdlib.h>

int main(int argc, char **argv)
{
	struct frl_cap_chk_params p = {0};
	struct frl_cap_chk_intermediates inter = {0};
	int lanes, gbps, rate, res, pad = -1;

	if (argc != 16)
		return 2;
	lanes = atoi(argv[1]);
	gbps = atoi(argv[2]);
	p.lanes = lanes;
	p.r_bit_nominal = gbps * 1.0e9;
	p.f_pixel_clock_nominal = (double)strtoul(argv[3], NULL, 10) * 100;
	p.h_active = atoi(argv[4]);
	p.h_blank = atoi(argv[5]);
	p.bpc = atoi(argv[6]);
	p.pixel_encoding = atoi(argv[7]);
	p.audio_packet_type = atoi(argv[8]);
	p.f_audio = atoi(argv[9]);
	p.layout = atoi(argv[10]);
	p.compressed = true;
	p.slices = atoi(argv[11]);
	p.slice_width = atoi(argv[12]);
	p.bpp_target = atoi(argv[13]) / 16.0;
	p.vic = atoi(argv[14]);
	p.allow_all_bpp = atoi(argv[15]) != 0;
	res = dml1_frl_cap_chk_compressed(&p, &inter);
	switch (gbps) {
	case 3: rate = FRL_LINK_RATE_3GBPS; break;
	case 6: rate = lanes == 4 ? FRL_LINK_RATE_6GBPS_4LANE : FRL_LINK_RATE_6GBPS; break;
	case 8: rate = FRL_LINK_RATE_8GBPS; break;
	case 10: rate = FRL_LINK_RATE_10GBPS; break;
	default: rate = FRL_LINK_RATE_12GBPS; break;
	}
	if (res == FRL_CAP_CHK_OK)
		pad = frl_modify_borrow_mode_for_dsc_padding(strtoul(argv[3], NULL, 10),
			p.h_active, p.h_active, p.h_blank, p.h_blank,
			p.borrow_params.hc_active_target, p.borrow_params.hc_blank_target,
			lanes, rate);
	printf("%d %d %d %d %d %d\n", res, p.borrow_params.audio_packets_line,
	       (int)p.borrow_params.borrow_mode, p.borrow_params.hc_active_target,
	       p.borrow_params.hc_blank_target, pad);
	return 0;
}
