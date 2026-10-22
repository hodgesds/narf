int main(void) {
 struct drm_dp_aux aux={0};
 apply_synaptics_fifo_reset_wa(&aux);
 static const unsigned expected[][3]={
 {1,0,5},{0x31,0x220998,4},{0x21,0x220998,4},
 {0x31,0x220d98,4},{0x21,0x220d98,4},{0x31,0x221198,4},{0x21,0x221198,4},
 {0x31,0x220998,4},{0x21,0x220998,4},{0x31,0x220d98,4},
 {0x31,0x221198,4},{0x21,0x221198,4},{2,0,0}};
 assert(count==sizeof(expected)/sizeof(expected[0]));
 assert(memcmp(commands[0].data,"PRIUS",5)==0);
 for(unsigned i=0;i<count;i++) {
  assert(commands[i].cmd==expected[i][0]);
  assert(commands[i].offset==expected[i][1]);
  assert(commands[i].length==expected[i][2]);
 }
 puts("Linux exact Synaptics FIFO sequence: 13 commands PASS");
}
