/* Drives DRM's extracted MST payload helpers through fixed-seed sequences
 * of stream additions and removals on one topology manager, as amdgpu_dm
 * commits them one stream at a time beside the streams already running.
 * One vector per line:
 *   seq <l|u> <link_kbps> <op>... = <result>... | <table>
 * l is an 8b/10b link, u 128b/132b (drm_dp_mst_update_slots). Op a<pbn>
 * adds a stream of <pbn>: its result is <time slots>=<writes> after
 * drm_dp_atomic_find_time_slots, drm_dp_mst_atomic_check_payload_alloc_limits,
 * drm_dp_add_payload_part1 and part2, or <time slots>=E<errno> when the
 * check refuses it (the state is then discarded). Op r<vcpi> removes that
 * stream: drm_dp_atomic_release_time_slots, drm_dp_remove_payload_part1
 * and part2; its result is the writes. Writes are DPCD payload-table rows
 * w<vcpi>.<start>.<slots> and ALLOCATE_PAYLOAD requests m<vcpi>.<pbn>.
 * The table lists every payload as <vcpi>@<start>+<slots> in start order. */
static u64 state = 0x6d7374706179ULL;
static u32 rnd(void)
{
	state ^= state << 13;
	state ^= state >> 7;
	state ^= state << 17;
	return (u32)(state >> 16);
}

struct drm_dp_mst_atomic_payload pool[64];
static struct drm_dp_mst_port port;

int main(void)
{
	static const u32 links[] = {
		/* 8b/10b: lanes x RBR/HBR/HBR2/HBR3, with and without FEC. */
		1296000, 2592000, 5184000, 2160000, 4320000, 8640000, 4320000, 8640000,
		17280000, 6480000, 12960000, 25920000, 25660800, 17107200,
		/* 128b/132b: UHBR10/13.5/20 on 1, 2 and 4 lanes. */
		9671000, 19342000, 38684000, 13056000, 26112000, 52223000, 19342000, 38684000,
		77368000,
	};
	struct drm_dp_aux aux = { 0 };
	for (int n = 0; n < 3000; n++) {
		struct drm_dp_mst_topology_mgr mgr = { .aux = &aux, .max_payloads = 4 };
		struct drm_dp_mst_topology_state st = { 0 };
		struct dc_link link;
		char line[2048], results[1536] = "";
		int used = 0;
		INIT_LIST_HEAD(&st.payloads);
		link.kbps = links[rnd() % (sizeof(links) / sizeof(links[0]))];
		bool uhbr = link.kbps >= 9671000 && link.kbps % 1000 == 0 && rnd() % 4 != 0;
		drm_dp_mst_update_slots(&st, uhbr ? DP_CAP_ANSI_128B132B : DP_CAP_ANSI_8B10B);
		st.pbn_div.full = dm_mst_get_pbn_divider(&link);
		snprintf(line, sizeof(line), "seq %c %u", uhbr ? 'u' : 'l', link.kbps);
		int ops = 1 + rnd() % 12;
		for (int k = 0; k < ops; k++) {
			struct drm_dp_mst_atomic_payload *pos, *victim = NULL;
			int count = 0, pick;
			char op[16], res[96];
			list_for_each_entry(pos, &st.payloads, next)
				count++;
			trace[0] = 0;
			if (count && rnd() % 3 == 0) {
				pick = rnd() % count;
				list_for_each_entry(pos, &st.payloads, next)
					if (pick-- == 0)
						victim = pos;
				struct drm_dp_mst_atomic_payload old = *victim;
				snprintf(op, sizeof(op), " r%d", victim->vcpi);
				/* drm_dp_atomic_release_time_slots' release. */
				victim->pbn = 0;
				victim->delete = true;
				st.payload_mask &= ~BIT(victim->vcpi - 1);
				drm_dp_remove_payload_part1(&mgr, &st, victim);
				drm_dp_remove_payload_part2(&mgr, &st, &old, victim);
				list_del(&victim->next);
				snprintf(res, sizeof(res), " %s", trace);
			} else {
				/* Skewed toward payloads that fit, with some that do not. */
				int pbn = rnd() % 4 ? 1 + rnd() % 1200 : 1 + rnd() % 6000;
				struct drm_dp_mst_atomic_payload *p = &pool[used++ % 64];
				memset(p, 0, sizeof(*p));
				p->port = &port;
				/* drm_dp_atomic_find_time_slots for a new payload. */
				p->vc_start_slot = -1;
				p->payload_allocation_status = DRM_DP_MST_PAYLOAD_ALLOCATION_NONE;
				list_add(&p->next, &st.payloads);
				p->time_slots = DIV_ROUND_UP(dfixed_const(pbn), st.pbn_div.full);
				p->pbn = pbn;
				u32 mask = st.payload_mask;
				int ret = drm_dp_mst_atomic_check_payload_alloc_limits(&mgr, &st);
				snprintf(op, sizeof(op), " a%d", pbn);
				if (ret) {
					/* A refused atomic state is discarded whole. */
					st.payload_mask = mask;
					list_del(&p->next);
					snprintf(res, sizeof(res), " %d=E%d", p->time_slots, -ret);
				} else {
					drm_dp_add_payload_part1(&mgr, &st, p);
					drm_dp_add_payload_part2(&mgr, p);
					snprintf(res, sizeof(res), " %d=%s", p->time_slots, trace);
				}
			}
			strncat(line, op, sizeof(line) - strlen(line) - 1);
			strncat(results, res, sizeof(results) - strlen(results) - 1);
		}
		printf("%s =%s |", line, results);
		/* The table in start-slot order. */
		int printed = 0;
		for (int s = 0; s < 64; s++) {
			struct drm_dp_mst_atomic_payload *pos;
			list_for_each_entry(pos, &st.payloads, next)
				if (pos->vc_start_slot == s) {
					printf("%s%d@%d+%d", printed ? "," : " ", pos->vcpi,
					       pos->vc_start_slot, pos->time_slots);
					printed = 1;
				}
		}
		printf("%s\n", printed ? "" : " -");
	}
	return 0;
}
