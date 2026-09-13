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

/* The default state: one global, exactly as before a provider exists. */
static atca_deadline_state_t s_default_state = { 0u, 0, 0, false };
static atca_deadline_state_t *(*s_state_fn)(void) = NULL;

void atca_deadline_set_state_provider(atca_deadline_state_t *(*fn)(void))
{
    s_state_fn = fn;
}

/* Every accessor goes through this. A provider that returns per-task storage makes two callers
 * independent; without one, behaviour is identical to the single global it replaced. */
static atca_deadline_state_t *dl(void)
{
    if (NULL != s_state_fn)
    {
        atca_deadline_state_t *st = s_state_fn();
        if (NULL != st)
        {
            return st;   /* a provider that returns NULL degrades to the global, never crashes */
        }
    }
    return &s_default_state;
}



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
    dl()->budget_ms = ms;
}

uint32_t atca_deadline_get_ms(void)
{
    return dl()->budget_ms;
}

void atca_deadline_begin(void)
{
    int64_t per = 0;

    if (dl()->budget_ms != 0u)
    {
        per = deadline_now_us() + ((int64_t)dl()->budget_ms * 1000);
    }

    /* THE TOTAL WINS WHENEVER IT IS SOONER, and applies even with no per-command budget set.
     *
     * Doing the clamp here is the whole point: begin() is the one place every command passes
     * through, so the bound cannot be forgotten by a caller or escaped by a code path that runs
     * more commands than its caller expected it to. */
    if (dl()->total_expires_us != 0)
    {
        if (per == 0 || dl()->total_expires_us < per)
        {
            per = dl()->total_expires_us;
        }
    }

    dl()->expires_us = per;   /* 0 => no deadline in force */
}

void atca_deadline_end(void)
{
    /* Clears the EXPIRY, not the budget: the policy stays in force for the next command, but the
     * timestamp must not outlive the command that set it. Without this, a direct wake or idle --
     * neither of which passes through calib_execute_command() -- inherits a stale expired
     * deadline and is refused before it starts. */
    dl()->expires_us = 0;
}

bool atca_deadline_expired(void)
{
    if (dl()->refuse)
    {
        return true;   /* no exclusive state: every command is already over its limit */
    }

    /* Keyed on the EXPIRY, not on dl()->budget_ms. Testing the budget here would ignore a
     * total set by a caller that never set a per-command budget -- exactly how a sequence bound
     * gets silently dropped. */
    if (dl()->expires_us == 0)
    {
        return false;
    }
    return deadline_now_us() >= dl()->expires_us;
}

uint32_t atca_deadline_remaining_ms(uint32_t cap)
{
    if (dl()->expires_us == 0)
    {
        return cap;
    }
    int64_t left_us = dl()->expires_us - deadline_now_us();
    if (left_us <= 0)
    {
        return 0u;
    }
    uint32_t left_ms = (uint32_t)(left_us / 1000);
    return (left_ms < cap) ? left_ms : cap;
}

bool atca_deadline_can_start(void)
{
    if (dl()->refuse)
    {
        return false;   /* refuse BEFORE the command is issued, not after it has run long */
    }

    if (dl()->expires_us == 0)
    {
        return true;   /* no deadline in force: unchanged behaviour */
    }
    return atca_deadline_remaining_ms(UINT32_MAX) >= ATCA_DEADLINE_MIN_SLICE_MS;
}

void atca_deadline_set_total_ms(uint32_t ms)
{
    dl()->total_expires_us = (ms == 0u) ? 0 : (deadline_now_us() + ((int64_t)ms * 1000));
}

uint32_t atca_deadline_total_remaining_ms(void)
{
    int64_t left_us;

    if (dl()->total_expires_us == 0)
    {
        return UINT32_MAX;   /* no total in force */
    }

    left_us = dl()->total_expires_us - deadline_now_us();
    if (left_us <= 0)
    {
        return 0u;
    }
    return (uint32_t)(left_us / 1000);
}

int64_t atca_deadline_push_total_ms(uint32_t ms)
{
    const int64_t saved = dl()->total_expires_us;
    int64_t want;

    if (ms == 0u)
    {
        return saved;   /* "no opinion": inherit whatever the caller already has */
    }

    want = deadline_now_us() + ((int64_t)ms * 1000);

    /* NEVER EXTEND AN OUTER TOTAL. An inner operation may ask for more than its caller has left;
     * granting it would let a nested call escape the bound its caller is enforcing, which is the
     * whole failure this exists to stop. Tighter wins; that is the only direction that is safe. */
    if (saved == 0 || want < saved)
    {
        dl()->total_expires_us = want;
    }

    return saved;
}

void atca_deadline_pop_total(int64_t saved_stop_us)
{
    dl()->total_expires_us = saved_stop_us;
}
