/* Drives the extracted Linux functions with fixed-seed inputs; one vector
 * per line ("<kind> <inputs> = <outputs>", bytes as hex). */
static u64 state = 0x5eed1234abcd9876ULL;
static u32 rnd(void)
{
	state ^= state << 13;
	state ^= state >> 7;
	state ^= state << 17;
	return (u32)(state >> 16);
}
static void hex(const u8 *b, int n)
{
	if (!n)
		printf("-");
	for (int i = 0; i < n; i++)
		printf("%02x", b[i]);
}
static u8 sent[16][64];
static int sent_len[16], sent_n;
static int drm_dp_send_sideband_msg(struct drm_dp_mst_topology_mgr *mgr, bool up, u8 *msg, int len)
{
	(void)mgr;
	(void)up;
	memcpy(sent[sent_n], msg, len);
	sent_len[sent_n++] = len;
	return 0;
}
static void rand_bytes(u8 *b, int n)
{
	for (int i = 0; i < n; i++)
		b[i] = rnd();
}
/* Print a parsed reply's fields in a fixed order. */
static void print_reply(bool ok, const struct drm_dp_sideband_msg_reply_body *r)
{
	printf("%d %d %d", ok, r->reply_type, r->req_type);
	if (r->reply_type == DP_SIDEBAND_REPLY_NAK) {
		printf(" ");
		hex(r->u.nak.guid.b, 16);
		printf(" %d %d", r->u.nak.reason, r->u.nak.nak_data);
		return;
	}
	if (!ok)
		return;
	switch (r->req_type) {
	case DP_LINK_ADDRESS: {
		const struct drm_dp_link_address_ack_reply *l = &r->u.link_addr;
		printf(" ");
		hex(l->guid.b, 16);
		printf(" %d", l->nports);
		for (int i = 0; i < l->nports; i++) {
			const struct drm_dp_link_addr_reply_port *p = &l->ports[i];
			printf(" %d,%d,%d,%d,%d,%d,%d,", p->input_port, p->peer_device_type,
			       p->port_number, p->mcs, p->ddps, p->legacy_device_plug_status,
			       p->dpcd_revision);
			hex(p->peer_guid.b, 16);
			printf(",%d,%d", p->num_sdp_streams, p->num_sdp_stream_sinks);
		}
		break;
	}
	case DP_ENUM_PATH_RESOURCES:
		printf(" %d %d %d %d", r->u.path_resources.port_number,
		       r->u.path_resources.fec_capable, r->u.path_resources.full_payload_bw_number,
		       r->u.path_resources.avail_payload_bw_number);
		break;
	case DP_ALLOCATE_PAYLOAD:
		printf(" %d %d %d", r->u.allocate_payload.port_number, r->u.allocate_payload.vcpi,
		       r->u.allocate_payload.allocated_pbn);
		break;
	case DP_QUERY_PAYLOAD:
		printf(" %d %d", r->u.query_payload.port_number, r->u.query_payload.allocated_pbn);
		break;
	case DP_REMOTE_DPCD_READ:
		printf(" %d ", r->u.remote_dpcd_read_ack.port_number);
		hex(r->u.remote_dpcd_read_ack.bytes, r->u.remote_dpcd_read_ack.num_bytes);
		break;
	case DP_REMOTE_DPCD_WRITE:
		printf(" %d", r->u.remote_dpcd_write_ack.port_number);
		break;
	case DP_REMOTE_I2C_READ:
		printf(" %d ", r->u.remote_i2c_read_ack.port_number);
		hex(r->u.remote_i2c_read_ack.bytes, r->u.remote_i2c_read_ack.num_bytes);
		break;
	case DP_POWER_UP_PHY:
	case DP_POWER_DOWN_PHY:
		printf(" %d", r->u.port_number.port_number);
		break;
	}
}
static const u8 reply_types[] = {
	DP_LINK_ADDRESS, DP_ENUM_PATH_RESOURCES, DP_ALLOCATE_PAYLOAD, DP_QUERY_PAYLOAD,
	DP_REMOTE_DPCD_READ, DP_REMOTE_DPCD_WRITE, DP_REMOTE_I2C_READ, DP_REMOTE_I2C_WRITE,
	DP_POWER_UP_PHY, DP_POWER_DOWN_PHY, DP_CLEAR_PAYLOAD_ID_TABLE,
};
int main(void)
{
	struct drm_dp_mst_topology_mgr mgr = { .max_dpcd_transaction_bytes = 16 };
	/* Sideband headers. */
	for (int n = 0; n < 300; n++) {
		struct drm_dp_sideband_msg_hdr h = { 0 }, d = { 0 };
		u8 buf[16];
		int len;
		u8 hdrlen = 0;
		h.lct = 1 + rnd() % 15;
		h.lcr = rnd() % 16;
		rand_bytes(h.rad, h.lct / 2);
		h.broadcast = rnd() & 1;
		h.path_msg = rnd() & 1;
		h.msg_len = rnd() % 64;
		h.somt = rnd() & 1;
		h.eomt = rnd() & 1;
		h.seqno = rnd() & 1;
		drm_dp_encode_sideband_msg_hdr(&h, buf, &len);
		bool ok = drm_dp_decode_sideband_msg_hdr(&mgr, &d, buf, len, &hdrlen);
		printf("hdr %d %d ", h.lct, h.lcr);
		hex(h.rad, 8);
		printf(" %d %d %d %d %d %d = ", h.broadcast, h.path_msg, h.msg_len, h.somt, h.eomt,
		       h.seqno);
		hex(buf, len);
		printf(" %d\n", ok);
	}
	/* Data CRCs. */
	for (int n = 0; n < 200; n++) {
		u8 b[64];
		int len = rnd() % 48;
		rand_bytes(b, len);
		printf("crc ");
		hex(b, len);
		printf(" = %d\n", drm_dp_msg_data_crc4(b, len));
	}
	/* Request bodies: type, then its fields. */
	static const u8 req_types[] = {
		DP_LINK_ADDRESS, DP_ENUM_PATH_RESOURCES, DP_POWER_UP_PHY, DP_POWER_DOWN_PHY,
		DP_ALLOCATE_PAYLOAD, DP_QUERY_PAYLOAD, DP_REMOTE_DPCD_READ, DP_REMOTE_DPCD_WRITE,
		DP_REMOTE_I2C_READ, DP_REMOTE_I2C_WRITE, DP_CLEAR_PAYLOAD_ID_TABLE,
	};
	for (int n = 0; n < 400; n++) {
		struct drm_dp_sideband_msg_req_body q = { 0 };
		static struct drm_dp_sideband_msg_tx tx;
		static u8 data[4][64];
		memset(&tx, 0, sizeof(tx));
		q.req_type = req_types[rnd() % ARRAY_SIZE(req_types)];
		printf("req %d", q.req_type);
		switch (q.req_type) {
		case DP_ENUM_PATH_RESOURCES:
		case DP_POWER_UP_PHY:
		case DP_POWER_DOWN_PHY:
			q.u.port_num.port_number = rnd() % 16;
			printf(" %d", q.u.port_num.port_number);
			break;
		case DP_ALLOCATE_PAYLOAD:
			q.u.allocate_payload.port_number = rnd() % 16;
			q.u.allocate_payload.vcpi = rnd() % 128;
			q.u.allocate_payload.pbn = rnd() % 65536;
			q.u.allocate_payload.number_sdp_streams = rnd() % 8;
			printf(" %d %d %d %d", q.u.allocate_payload.port_number,
			       q.u.allocate_payload.vcpi, q.u.allocate_payload.pbn,
			       q.u.allocate_payload.number_sdp_streams);
			for (int i = 0; i < q.u.allocate_payload.number_sdp_streams; i++) {
				q.u.allocate_payload.sdp_stream_sink[i] = rnd() % 16;
				printf(" %d", q.u.allocate_payload.sdp_stream_sink[i]);
			}
			break;
		case DP_QUERY_PAYLOAD:
			q.u.query_payload.port_number = rnd() % 16;
			q.u.query_payload.vcpi = rnd() % 128;
			printf(" %d %d", q.u.query_payload.port_number, q.u.query_payload.vcpi);
			break;
		case DP_REMOTE_DPCD_READ:
			q.u.dpcd_read.port_number = rnd() % 16;
			q.u.dpcd_read.dpcd_address = rnd() % 0x100000;
			q.u.dpcd_read.num_bytes = rnd() % 256;
			printf(" %d %d %d", q.u.dpcd_read.port_number, q.u.dpcd_read.dpcd_address,
			       q.u.dpcd_read.num_bytes);
			break;
		case DP_REMOTE_DPCD_WRITE:
			q.u.dpcd_write.port_number = rnd() % 16;
			q.u.dpcd_write.dpcd_address = rnd() % 0x100000;
			q.u.dpcd_write.num_bytes = rnd() % 16;
			rand_bytes(data[0], q.u.dpcd_write.num_bytes);
			q.u.dpcd_write.bytes = data[0];
			printf(" %d %d ", q.u.dpcd_write.port_number, q.u.dpcd_write.dpcd_address);
			hex(data[0], q.u.dpcd_write.num_bytes);
			break;
		case DP_REMOTE_I2C_READ:
			q.u.i2c_read.port_number = rnd() % 16;
			q.u.i2c_read.num_transactions = rnd() % 4;
			printf(" %d %d", q.u.i2c_read.port_number, q.u.i2c_read.num_transactions);
			for (int i = 0; i < q.u.i2c_read.num_transactions; i++) {
				q.u.i2c_read.transactions[i].i2c_dev_id = rnd() % 128;
				q.u.i2c_read.transactions[i].num_bytes = rnd() % 8;
				rand_bytes(data[i], q.u.i2c_read.transactions[i].num_bytes);
				q.u.i2c_read.transactions[i].bytes = data[i];
				q.u.i2c_read.transactions[i].no_stop_bit = rnd() & 1;
				q.u.i2c_read.transactions[i].i2c_transaction_delay = rnd() % 16;
				printf(" %d,", q.u.i2c_read.transactions[i].i2c_dev_id);
				hex(data[i], q.u.i2c_read.transactions[i].num_bytes);
				printf(",%d,%d", q.u.i2c_read.transactions[i].no_stop_bit,
				       q.u.i2c_read.transactions[i].i2c_transaction_delay);
			}
			q.u.i2c_read.read_i2c_device_id = rnd() % 128;
			q.u.i2c_read.num_bytes_read = rnd() % 256;
			printf(" %d %d", q.u.i2c_read.read_i2c_device_id, q.u.i2c_read.num_bytes_read);
			break;
		case DP_REMOTE_I2C_WRITE:
			q.u.i2c_write.port_number = rnd() % 16;
			q.u.i2c_write.write_i2c_device_id = rnd() % 128;
			q.u.i2c_write.num_bytes = rnd() % 16;
			rand_bytes(data[0], q.u.i2c_write.num_bytes);
			q.u.i2c_write.bytes = data[0];
			printf(" %d %d ", q.u.i2c_write.port_number, q.u.i2c_write.write_i2c_device_id);
			hex(data[0], q.u.i2c_write.num_bytes);
			break;
		}
		drm_dp_encode_sideband_req(&q, &tx);
		printf(" = ");
		hex(tx.msg, tx.cur_len);
		printf("\n");
	}
	/* Transmission: a body to a branch at (lct, rad), as 48-byte chunks. */
	for (int n = 0; n < 200; n++) {
		static struct drm_dp_sideband_msg_tx tx;
		struct drm_dp_mst_branch mstb = { 0 };
		memset(&tx, 0, sizeof(tx));
		mstb.lct = 1 + rnd() % 15;
		rand_bytes(mstb.rad, mstb.lct / 2);
		tx.dst = &mstb;
		tx.path_msg = rnd() & 1;
		tx.cur_len = 1 + rnd() % 200;
		rand_bytes(tx.msg, tx.cur_len);
		if (rnd() % 4 == 0)
			tx.msg[0] = DP_CLEAR_PAYLOAD_ID_TABLE;
		sent_n = 0;
		while (process_single_tx_qlock(&mgr, &tx, false) == 0)
			;
		printf("tx %d ", mstb.lct);
		hex(mstb.rad, 8);
		printf(" %d ", tx.path_msg);
		hex(tx.msg, tx.cur_len);
		printf(" =");
		for (int i = 0; i < sent_n; i++) {
			printf(" ");
			hex(sent[i], sent_len[i]);
		}
		printf("\n");
	}
	/* Replies: random ACK/NAK bodies sent back in chunks, reassembled and
	 * parsed as the reply to their request type. */
	for (int n = 0; n < 400; n++) {
		static struct drm_dp_sideband_msg_tx tx;
		static struct drm_dp_sideband_msg_rx rx;
		struct drm_dp_sideband_msg_reply_body rep = { 0 };
		struct drm_dp_mst_branch mstb = { .lct = 1 };
		memset(&tx, 0, sizeof(tx));
		memset(&rx, 0, sizeof(rx));
		u8 type = reply_types[rnd() % ARRAY_SIZE(reply_types)];
		bool nak = rnd() % 8 == 0;
		int len = 1 + rnd() % 120;
		rand_bytes(tx.msg, len);
		tx.msg[0] = (nak ? 0x80 : 0) | type;
		if (type == DP_LINK_ADDRESS && len > 17)
			tx.msg[17] = (tx.msg[17] & 0xf0) | rnd() % 8;
		if ((type == DP_REMOTE_DPCD_READ || type == DP_REMOTE_I2C_READ) && len > 2)
			tx.msg[2] %= len;
		tx.cur_len = len;
		tx.dst = &mstb;
		sent_n = 0;
		while (process_single_tx_qlock(&mgr, &tx, false) == 0)
			;
		bool ok = true;
		for (int i = 0; i < sent_n && ok; i++) {
			struct drm_dp_sideband_msg_hdr hdr;
			u8 hdrlen;
			ok = drm_dp_decode_sideband_msg_hdr(&mgr, &hdr, sent[i], sent_len[i], &hdrlen) &&
			     drm_dp_sideband_msg_set_header(&rx, &hdr, hdrlen) &&
			     drm_dp_sideband_append_payload(&rx, sent[i] + hdrlen,
							    sent_len[i] - hdrlen);
		}
		printf("rx ");
		hex(tx.msg, len);
		printf(" = %d %d ", ok, rx.curlen);
		ok = ok && rx.have_eomt;
		print_reply(ok && drm_dp_sideband_parse_reply(&mgr, &rx, &rep), &rep);
		printf("\n");
	}
	/* Up requests: CONNECTION_STATUS_NOTIFY and RESOURCE_STATUS_NOTIFY. */
	for (int n = 0; n < 100; n++) {
		static struct drm_dp_sideband_msg_rx rx;
		struct drm_dp_sideband_msg_req_body req;
		memset(&rx, 0, sizeof(rx));
		rx.curlen = 1 + rnd() % 24;
		rand_bytes(rx.msg, rx.curlen);
		rx.msg[0] = rnd() & 1 ? DP_CONNECTION_STATUS_NOTIFY : DP_RESOURCE_STATUS_NOTIFY;
		bool ok = drm_dp_sideband_parse_req(&mgr, &rx, &req);
		printf("up ");
		hex(rx.msg, rx.curlen);
		printf(" = %d %d", ok, req.req_type);
		if (ok && req.req_type == DP_CONNECTION_STATUS_NOTIFY) {
			const struct drm_dp_connection_status_notify *c = &req.u.conn_stat;
			printf(" %d ", c->port_number);
			hex(c->guid.b, 16);
			printf(" %d %d %d %d %d", c->legacy_device_plug_status,
			       c->displayport_device_plug_status, c->message_capability_status,
			       c->input_port, c->peer_device_type);
		} else if (ok) {
			printf(" %d ", req.u.resource_stat.port_number);
			hex(req.u.resource_stat.guid.b, 16);
			printf(" %d", req.u.resource_stat.available_pbn);
		}
		printf("\n");
	}
	/* Up-request ACK replies. */
	for (int t = 0; t < 2; t++) {
		static struct drm_dp_sideband_msg_tx tx;
		u8 type = t ? DP_RESOURCE_STATUS_NOTIFY : DP_CONNECTION_STATUS_NOTIFY;
		memset(&tx, 0, sizeof(tx));
		drm_dp_encode_up_ack_reply(&tx, type);
		printf("upack %d = ", type);
		hex(tx.msg, tx.cur_len);
		printf("\n");
	}
	/* PBN for a mode (clock kHz, bpp x16). */
	for (int n = 0; n < 300; n++) {
		int clock = 25000 + rnd() % 1200000;
		int bpp = (6 + rnd() % 31) * 16 + (rnd() % 4 == 0 ? rnd() % 16 : 0);
		printf("pbn %d %d = %d\n", clock, bpp, drm_dp_calc_pbn_mode(clock, bpp));
	}
	return 0;
}
