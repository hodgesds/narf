static void reset(void)
{
    regs[DAL_RESP_REG] = DALSMC_Result_OK;
    regs[DAL_ARG_REG] = regs[DAL_MSG_REG] = 0;
    sent = stalled = rejected = delay_us = 0;
}
int main(void)
{
    struct clk_mgr_internal owner = {0};
    uint32_t result;
    for (unsigned int stale = 1; stale <= 0xfd; stale += 0xfc) {
        reset();
        regs[DAL_RESP_REG] = stale;
        result = 0;
        assert(dcn401_smu_send_msg_with_param(&owner, 9, 0x60064, &result));
        assert(result == 123000 && sent == 1 && delay_us == 0);
    }
    reset();
    stalled = 1;
    result = 77;
    assert(!dcn401_smu_send_msg_with_param(&owner, 0xe, 0, &result));
    assert(result == 77 && sent == 1 && delay_us >= 2000000);
    assert(dcn401_smu_send_msg_with_param(&owner, 0xd, 0, NULL));
    assert(sent == 2 && delay_us >= 4000000);
    assert(messages[0] == 0xe && messages[1] == 0xd);
    assert(arguments[0] == 0 && arguments[1] == 0);

    reset();
    rejected = 1;
    result = 77;
    assert(!dcn401_smu_send_msg_with_param(&owner, 0x1a, 1, &result));
    assert(result == 77 && delay_us == 0);
    assert(dcn401_smu_send_msg_with_param(&owner, 0x18, 0x12c0060, &result));
    assert(result == 123000 && sent == 2 && delay_us == 0);

    // This is a documented NARF restriction: Linux sends even when the
    // inherited mailbox never becomes ready; NARF only permits replacing
    // the known timed-out ignored-result transaction exercised above.
    reset();
    regs[DAL_RESP_REG] = 0;
    assert(dcn401_smu_send_msg_with_param(&owner, 5, 8, NULL));
    assert(sent == 1 && delay_us >= 2000000);
    puts("dcn401 DAL: stale replies, post-write timeouts, replacement and refusals match Linux");
    return 0;
}
