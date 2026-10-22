/* Only the register and timing boundary is modeled. check.sh extracts Linux's
 * wait and send functions without rewriting their decisions or retry counts. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

enum { DAL_RESP_REG, DAL_ARG_REG, DAL_MSG_REG };
enum { DALSMC_Result_OK = 1 };
struct clk_mgr_internal { unsigned int unused; };
static uint32_t regs[3];
static unsigned int sent, stalled, rejected, delay_us;
static uint32_t arguments[8], messages[8];
static uint32_t reg_read(unsigned int at) { return regs[at]; }
static void reg_write(unsigned int at, uint32_t value)
{
    regs[at] = value;
    if (at != DAL_MSG_REG)
        return;
    assert(regs[DAL_RESP_REG] == 0);
    assert(sent < 8);
    messages[sent] = value;
    arguments[sent++] = regs[DAL_ARG_REG];
    if (sent == stalled)
        return;
    regs[DAL_RESP_REG] = sent == rejected ? 0xfd : DALSMC_Result_OK;
    regs[DAL_ARG_REG] = 123000;
}
static void udelay(unsigned int us) { delay_us += us; }
static void msleep(unsigned int ms) { delay_us += ms * 1000; }
#define REG_READ(at) reg_read(at)
#define REG_WRITE(at, value) reg_write(at, value)
#define TRACE_SMU_MSG_ENTER(...) ((void)0)
#define TRACE_SMU_MSG_EXIT(...) ((void)0)
