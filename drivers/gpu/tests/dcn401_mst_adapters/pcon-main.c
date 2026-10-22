int main(void) {
 assert(sizeof(union hdmi_encoded_link_bw)==1);
 for(unsigned code=1;code<=6;code++) {
  union hdmi_encoded_link_bw post={.raw=(uint8_t)(1u<<code)};
  assert(intersect_frl_link_bw_support(48000000,post)==dc_link_bw_kbps_from_raw_frl_link_rate_data(0,code));
 }
 union hdmi_encoded_link_bw done={.raw=0x80};assert(intersect_frl_link_bw_support(48000000,done)==0);
 struct dc dc={.caps={true}};struct dc_link link={&dc};struct dc_sink sink={.edid_caps={6,2}};
 struct amdgpu_dm_connector c={.dc_link=&link,.dc_sink=&sink};
 c.mst_downstream_port_caps.bytes.byte0.bits.DWN_STRM_PORTX_TYPE=3;
 c.mst_downstream_port_caps.bytes.byte2.bits.MAX_ENCODED_LINK_BW_SUPPORT=3;
 unsigned raw=0,dsc=0;assert(get_conv_frl_bw(&c,&raw,&dsc));assert(raw==24000000&&dsc==18000000);
 dc.caps.dp_hdmi21_pcon_support=false;raw=dsc=0;assert(!get_conv_frl_bw(&c,&raw,&dsc));assert(raw==0&&dsc==0);
 puts("Linux actual converter/EDID FRL intersection + trained-bandwidth functions PASS");
}
