/* Linux's uncompressed HDMI FRL capacity check (dml1_frl_cap_chk.c), as
 * hpo_enc3_validate_hdmi_frl_output feeds it, on the command line:
 *   harness <lanes> <rate_gbps> <pix_clk_100hz> <h_active> <h_blank> <bpc>
 *           <encoding 0=444 1=422 2=420> <audio_packet_type> <f_audio>
 *           <layout>
 * Prints "<result> <audio_packets_line> <borrow_mode>". */
#include "dml1_frl_cap_chk.h"
#include <stdlib.h>

int main(int argc, char **argv)
{
	struct frl_cap_chk_params p = {0};
	struct frl_cap_chk_intermediates inter = {0};

	if (argc != 11)
		return 2;
	p.lanes = atoi(argv[1]);
	p.r_bit_nominal = atoi(argv[2]) * 1.0e9;
	p.f_pixel_clock_nominal = (double)strtoul(argv[3], NULL, 10) * 100;
	p.h_active = atoi(argv[4]);
	p.h_blank = atoi(argv[5]);
	p.bpc = atoi(argv[6]);
	p.pixel_encoding = atoi(argv[7]);
	p.audio_packet_type = atoi(argv[8]);
	p.f_audio = atoi(argv[9]);
	p.layout = atoi(argv[10]);
	int res = dml1_frl_cap_chk_uncompressed(&p, &inter);
	printf("%d %d %d\n", res, p.borrow_params.audio_packets_line,
	       (int)p.borrow_params.borrow_mode);
	return 0;
}
