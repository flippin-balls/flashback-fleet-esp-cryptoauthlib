/* ---- PER-COMMAND ELAPSED-TIME DEADLINE -----------------------------------------------------
 *
 * Split out of atca_hal.c so it can be COMPILED AND TESTED ON A HOST. The bound this enforces
 * was previously argued from arithmetic, and an on-device attempt to demonstrate it measured the
 * wrong thing entirely -- it clamped SDA, which kills the command in the send phase, before the
 * poll loop the deadline lives in. Both arms returned a transport error, neither exercised the
 * deadline, and the harness would have reported a pass.
 *
 * So the clock is INJECTABLE and the logic has no ESP dependencies. A host test can advance time
 * deterministically and assert on the exact boundary, with no hardware and no wedged bus.
 *
 * See atca_hal.h for the contract and for what this does NOT promise.
 */
#include "atca_deadline.h"
#include <stddef.h>

static uint32_t s_deadline_budget_ms  = 0;   /* 0 = disabled, and disabled is the default */
static int64_t  s_deadline_expires_us = 0;

/* Default clock. Weak so a host test can supply its own without touching this file; on target it
 * resolves to the monotonic timer. Monotonic matters: a wall clock can step backwards and would
 * silently extend a deadline. */
static atca_deadline_clock_fn s_clock = NULL;

void atca_deadline_set_clock(atca_deadline_clock_fn fn)
{
    s_clock = fn;
}

static int64_t deadline_now_us(void)
{
    if (NULL != s_clock)
    {
        return s_clock();
    }
    return atca_deadline_default_clock_us();
}

void atca_deadline_set_ms(uint32_t ms)
{
    s_deadline_budget_ms = ms;
}

uint32_t atca_deadline_get_ms(void)
{
    return s_deadline_budget_ms;
}

void atca_deadline_begin(void)
{
    if (s_deadline_budget_ms == 0u)
    {
        s_deadline_expires_us = 0;
        return;
    }
    s_deadline_expires_us = deadline_now_us() + ((int64_t)s_deadline_budget_ms * 1000);
}

void atca_deadline_end(void)
{
    /* Clears the EXPIRY, not the budget: the policy stays in force for the next command, but the
     * timestamp must not outlive the command that set it. Without this, a direct wake or idle --
     * neither of which passes through calib_execute_command() -- inherits a stale expired
     * deadline and is refused before it starts. */
    s_deadline_expires_us = 0;
}

bool atca_deadline_expired(void)
{
    if (s_deadline_budget_ms == 0u || s_deadline_expires_us == 0)
    {
        return false;
    }
    return deadline_now_us() >= s_deadline_expires_us;
}

uint32_t atca_deadline_remaining_ms(uint32_t cap)
{
    if (s_deadline_budget_ms == 0u || s_deadline_expires_us == 0)
    {
        return cap;
    }
    int64_t left_us = s_deadline_expires_us - deadline_now_us();
    if (left_us <= 0)
    {
        return 0u;
    }
    uint32_t left_ms = (uint32_t)(left_us / 1000);
    return (left_ms < cap) ? left_ms : cap;
}

bool atca_deadline_can_start(void)
{
    if (s_deadline_budget_ms == 0u || s_deadline_expires_us == 0)
    {
        return true;   /* no deadline in force: unchanged behaviour */
    }
    return atca_deadline_remaining_ms(UINT32_MAX) >= ATCA_DEADLINE_MIN_SLICE_MS;
}
