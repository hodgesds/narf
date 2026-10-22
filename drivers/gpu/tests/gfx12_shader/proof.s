// One wave32: s[0:1] = output address, s2 = salt, v0 = workitem X.
// Store salt XOR (lane * 4), with explicit VALU and global-store waits.
.text
v_lshlrev_b32_e32 v0, 2, v0
s_delay_alu instid0(VALU_DEP_1)
v_xor_b32_e32 v1, s2, v0
global_store_b32 v0, v1, s[0:1] scope:SCOPE_SYS
s_wait_storecnt 0
s_endpgm
