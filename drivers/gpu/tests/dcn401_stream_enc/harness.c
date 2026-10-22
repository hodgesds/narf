/* DCN401 stream-encoder acquisition as Linux DC runs it, replayed over the
 * DCN 4.0.1 pool (res_cap_dcn4_01: four DIO stream encoders DIGA-DIGD, one
 * virtual stream encoder after them, four HPO DP stream and four HPO DP
 * link encoders, four Azalia audio endpoints). Host-only; check.sh compiles it after shim.h and the
 * functions it cuts out of the Linux tree.
 *
 * resource_map_pool_resources acquires a stream's encoders after its OTG
 * master: the DIO stream encoder from the pool's
 * find_first_free_match_stream_enc_for_link (dcn10's for DCN401), marked
 * with update_stream_engine_usage, then for a 128b/132b DP stream the
 * first free HPO DP stream encoder (update_hpo_dp_stream_engine_usage)
 * and its link's HPO DP link encoder (add_hpo_dp_link_enc_to_ctx), then
 * for a stream with audio the endpoint find_first_free_audio gives its
 * DIO stream encoder's engine id (update_audio_usage).
 * resource_remove_otg_master_for_stream_output releases them in that
 * order. Each fixed-seed sequence adds and removes up to four streams on
 * four PHY links (UNIPHY A-E: preferred engines DIGA-DIGE).
 * One vector per line:
 *   seq <op>... = <result>...
 * Op +<s>.<link>.<engine>.<h>.<a> adds stream s on link <link> whose link
 * encoder prefers DIG <engine>, 128b/132b when h is 1, with audio when a
 * is 1; its result is <dio>.<hpo stream>.<hpo link>.<audio> (- for none)
 * or E when an encoder is missing (the context is then discarded, as the commit fails). Op -<s>
 * removes stream s; its result is r.
 * Then find_first_free_audio alone over every acquisition state of the
 * four DIO stream encoders and four endpoints, for each engine id
 * DIGA-DIGE:
 *   audio <stream encoders acquired> <audio acquired> <id> = <audio>|-
 * with the acquired sets as bitmasks of pool index. */
static u64 state = 0x656e636f64657273ULL;
static unsigned int rnd(void)
{
	state ^= state << 13;
	state ^= state >> 7;
	state ^= state << 17;
	return (unsigned int)(state >> 16);
}

struct stream {
	bool live;
	struct dc_link link;
	struct link_encoder link_enc;
	struct dc_stream_state st;
	struct stream_encoder *stream_enc;
	struct hpo_dp_stream_encoder *hpo_dp_stream_enc;
	struct pipe_ctx pipe;
	struct audio *audio;
	bool hpo;
	bool has_audio;
};

static int index_of_stream_enc(const struct resource_pool *pool, struct stream_encoder *e)
{
	for (unsigned int i = 0; i < pool->stream_enc_count; i++)
		if (pool->stream_enc[i] == e)
			return (int)i;
	return -1;
}

int main(void)
{
	static struct stream_encoder dio[5];
	static struct hpo_dp_stream_encoder hpo[4];
	static struct hpo_dp_link_encoder hpo_link[4];
	static struct audio audios[4];
	struct resource_pool pool = { 0 };
	for (int i = 0; i < 4; i++) {
		dio[i].id = (enum engine_id)(ENGINE_ID_DIGA + i);
		pool.stream_enc[i] = &dio[i];
		hpo[i].inst = i;
		pool.hpo_dp_stream_enc[i] = &hpo[i];
		hpo_link[i].inst = i;
		pool.hpo_dp_link_enc[i] = &hpo_link[i];
		audios[i].inst = (unsigned int)i;
		pool.audios[i] = &audios[i];
	}
	pool.audio_count = 4;
	dio[4].id = ENGINE_ID_VIRTUAL;
	pool.stream_enc[4] = &dio[4];
	pool.stream_enc_count = 5;
	pool.hpo_dp_stream_enc_count = 4;
	pool.hpo_dp_link_enc_count = 4;
	for (int n = 0; n < 2000; n++) {
		struct resource_context res = { 0 };
		struct stream streams[4] = { 0 };
		char line[1024] = "seq", results[1024] = " =";
		int ops = 1 + rnd() % 14;
		for (int k = 0; k < ops; k++) {
			int s = rnd() % 4;
			struct stream *x = &streams[s];
			char op[32], res_s[32];
			if (x->live) {
				/* resource_remove_otg_master_for_stream_output. */
				update_stream_engine_usage(&res, &pool, x->stream_enc, false);
				if (x->hpo) {
					update_hpo_dp_stream_engine_usage(&res, &pool,
							x->hpo_dp_stream_enc, false);
					remove_hpo_dp_link_enc_from_ctx(&res, &x->pipe, &x->st);
				}
				if (x->audio)
					update_audio_usage(&res, &pool, x->audio, false);
				x->live = false;
				snprintf(op, sizeof(op), " -%d", s);
				snprintf(res_s, sizeof(res_s), " r");
			} else {
				struct resource_context saved = res;
				x->link.link_index = rnd() % 4;
				x->link.ep_type = DISPLAY_ENDPOINT_PHY;
				x->link_enc.preferred_engine = (enum engine_id)(ENGINE_ID_DIGA + rnd() % 5);
				x->link.link_enc = &x->link_enc;
				x->st.link = &x->link;
				x->hpo = rnd() % 2;
				/* Every stream on one link codes the same way. */
				for (int o = 0; o < 4; o++)
					if (o != s && streams[o].live &&
					    streams[o].link.link_index == x->link.link_index)
						x->hpo = streams[o].hpo;
				x->has_audio = rnd() % 4 != 0;
				snprintf(op, sizeof(op), " +%d.%u.%d.%d.%d", s, x->link.link_index,
					 x->link_enc.preferred_engine, x->hpo, x->has_audio);
				memset(&x->pipe, 0, sizeof(x->pipe));
				x->stream_enc = dcn10_find_first_free_match_stream_enc_for_link(&res, &pool,
						&x->st);
				x->hpo_dp_stream_enc = NULL;
				x->audio = NULL;
				bool ok = x->stream_enc != NULL;
				if (ok) {
					update_stream_engine_usage(&res, &pool, x->stream_enc, true);
					if (x->hpo) {
						x->hpo_dp_stream_enc =
							find_first_free_match_hpo_dp_stream_enc_for_link(
								&res, &pool, &x->st);
						ok = x->hpo_dp_stream_enc != NULL;
						if (ok) {
							update_hpo_dp_stream_engine_usage(&res, &pool,
									x->hpo_dp_stream_enc, true);
							ok = add_hpo_dp_link_enc_to_ctx(&res, &pool, &x->pipe,
									&x->st);
						}
					}
				}
				if (ok && x->has_audio) {
					x->audio = find_first_free_audio(&res, &pool, x->stream_enc->id,
							DCN_VERSION_4_01);
					if (x->audio)
						update_audio_usage(&res, &pool, x->audio, true);
				}
				if (ok) {
					x->live = true;
					char h[8] = "-", l[8] = "-", a[8] = "-";
					if (x->hpo) {
						snprintf(h, sizeof(h), "%d", x->hpo_dp_stream_enc->inst);
						snprintf(l, sizeof(l), "%d", x->pipe.link_res.hpo_dp_link_enc->inst);
					}
					if (x->audio)
						snprintf(a, sizeof(a), "%u", x->audio->inst);
					snprintf(res_s, sizeof(res_s), " %d.%s.%s.%s",
						 index_of_stream_enc(&pool, x->stream_enc), h, l, a);
				} else {
					res = saved;
					snprintf(res_s, sizeof(res_s), " E");
				}
			}
			strncat(line, op, sizeof(line) - strlen(line) - 1);
			strncat(results, res_s, sizeof(results) - strlen(results) - 1);
		}
		printf("%s%s\n", line, results);
	}
	for (int se = 0; se < 16; se++)
		for (int aud = 0; aud < 16; aud++)
			for (int id = 0; id < 5; id++) {
				struct resource_context res = { 0 };
				for (int i = 0; i < 4; i++) {
					res.is_stream_enc_acquired[i] = se >> i & 1;
					res.is_audio_acquired[i] = aud >> i & 1;
				}
				struct audio *a = find_first_free_audio(&res, &pool,
						(enum engine_id)(ENGINE_ID_DIGA + id), DCN_VERSION_4_01);
				if (a)
					printf("audio %d %d %d = %u\n", se, aud, id, a->inst);
				else
					printf("audio %d %d %d = -\n", se, aud, id);
			}
	return 0;
}
