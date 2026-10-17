/* Shared by harness.c and harness_multi.c, after the DML21 headers.
 *
 * ODM combine: a plane on n > 1 pipes appends " /<n>" to its values, then each
 * further pipe's refcyc_h_blank_end (DLG moves the blank end by that pipe's
 * share of the line). Every other register of every further pipe must equal
 * pipe 0's, or that pipe prints PIPEDIFF, which no vector accepts.
 */
#include <stdio.h>
#include <string.h>

static void print_odm_pipes(const struct dml2_per_plane_programming *pp)
{
	unsigned int n = pp->num_dpps_required;

	if (n < 2)
		return;
	printf(" /%u", n);
	for (unsigned int i = 1; i < n; i++) {
		struct dml2_dchub_per_pipe_register_set r = *pp->pipe_regs[i];

		r.dlg_regs.refcyc_h_blank_end = pp->pipe_regs[0]->dlg_regs.refcyc_h_blank_end;
		if (memcmp(&r, pp->pipe_regs[0], sizeof(r))) {
			printf(" PIPEDIFF");
			continue;
		}
		printf(" %u", pp->pipe_regs[i]->dlg_regs.refcyc_h_blank_end);
	}
}
