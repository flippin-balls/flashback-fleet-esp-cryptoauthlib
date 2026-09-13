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

/* Absolute stop for a whole SEQUENCE of commands. 0 = no total in force.
 *
 * Separate from the per-command budget because they answer different questions. The budget says
 * "no single command may take longer than this"; the total says "all of this, together, must be
 * done by then". A caller sitting under a watchdog needs the second one, and before this existed
 * it could only ask for the first -- and was silently given N times what it asked for. */
static int64_t  s_total_expires_us    = 0;

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
    int64_t per = 0;

    if (s_deadline_budget_ms != 0u)
    {
        per = deadline_now_us() + ((int64_t)s_deadline_budget_ms * 1000);
    }

    /* THE TOTAL WINS WHENEVER IT IS SOONER, and applies even with no per-command budget set.
     *
     * Doing the clamp here is the whole point: begin() is the one place every command passes
     * through, so the bound cannot be forgotten by a caller or escaped by a code path that runs
     * more commands than its caller expected it to. */
    if (s_total_expires_us != 0)
    {
        if (per == 0 || s_total_expires_us < per)
        {
            per = s_total_expires_us;
        }
    }

    s_deadline_expires_us = per;   /* 0 => no deadline in force */
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
    /* Keyed on the EXPIRY, not on s_deadline_budget_ms. Testing the budget here would ignore a
     * total set by a caller that never set a per-command budget -- exactly how a sequence bound
     * gets silently dropped. */
    if (s_deadline_expires_us == 0)
    {
        return false;
    }
    return deadline_now_us() >= s_deadline_expires_us;
}

uint32_t atca_deadline_remaining_ms(uint32_t cap)
{
    if (s_deadline_expires_us == 0)
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
    if (s_deadline_expires_us == 0)
    {
        return true;   /* no deadline in force: unchanged behaviour */
    }
    return atca_deadline_remaining_ms(UINT32_MAX) >= ATCA_DEADLINE_MIN_SLICE_MS;
}

void atca_deadline_set_total_ms(uint32_t ms)
{
    s_total_expires_us = (ms == 0u) ? 0 : (deadline_now_us() + ((int64_t)ms * 1000));
}

uint32_t atca_deadline_total_remaining_ms(void)
{
    int64_t left_us;

    if (s_total_expires_us == 0)
    {
        return UINT32_MAX;   /* no total in force */
    }

    left_us = s_total_expires_us - deadline_now_us();
    if (left_us <= 0)
    {
        return 0u;
    }
    return (uint32_t)(left_us / 1000);
}
