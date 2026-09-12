/* Deterministic proof that the ATECC per-command deadline bounds a hung bus.
 *
 * WHY THIS EXISTS RATHER THAN AN ON-DEVICE TEST. The first attempt at demonstrating this held
 * SDA low on a real bridge and timed the same command with the budget on and off. That could
 * never have worked: clamping SDA fails the command in its SEND phase, which breaks out of
 * calib_execute_command() BEFORE the response poll loop where the deadline is enforced. Both
 * arms returned a transport error, neither ever evaluated the deadline, and the harness would
 * have printed a number that looked like a pass.
 *
 * The lesson is the shape of it: a test that cannot FAIL for the right reason proves nothing.
 * So this one injects the clock, simulates the real poll structure with the real constants, and
 * includes a case that FAILS if the bound is removed.
 */
#include "atca_deadline.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fail = 0;
#define CHECK(cond, msg, ...) do { \
    if (!(cond)) { printf("  FAIL: " msg "\n", ##__VA_ARGS__); g_fail = 1; } \
    else         { printf("  ok  : " msg "\n", ##__VA_ARGS__); } } while (0)

/* ---- injectable virtual clock ---------------------------------------------------------- */
static int64_t g_now_us = 0;
static int64_t fake_clock(void) { return g_now_us; }
static void    advance_ms(int64_t ms) { g_now_us += ms * 1000; }

/* The host build never calls this, but the unit references it when no clock is injected. */
int64_t atca_deadline_default_clock_us(void) { return g_now_us; }

/* ---- the real constants from calib_execution.c ------------------------------------------ */
#define POLL_MAX_MS    2500
#define POLL_FREQ_MS   2
#define HAL_RX_MS      200      /* what one receive burns on a bus that never answers */
#define MAX_DELAY_COUNT (POLL_MAX_MS / POLL_FREQ_MS)   /* 1250, plus the first attempt */

/* Simulates the poll loop's SHAPE: every receive burns its full timeout and fails, exactly as a
 * wedged bus behaves. Returns iterations run; reports whether it ended on the deadline. */
static int simulate_poll_loop(int enforce_deadline, int *out_timed_out, int64_t *out_elapsed_ms)
{
    int64_t t0 = g_now_us;
    int iterations = 0;
    int timed_out = 0;
    int max_delay_count = MAX_DELAY_COUNT;

    do {
        if (enforce_deadline && !atca_deadline_can_start()) { timed_out = 1; break; }

        /* the receive: burns its (possibly shortened) timeout, then fails */
        uint32_t slice = enforce_deadline ? atca_deadline_remaining_ms(HAL_RX_MS) : HAL_RX_MS;
        advance_ms(slice);
        iterations++;

        if (enforce_deadline && atca_deadline_expired()) { timed_out = 1; break; }
        advance_ms(POLL_FREQ_MS);
    } while (max_delay_count-- > 0);

    *out_timed_out = timed_out;
    *out_elapsed_ms = (g_now_us - t0) / 1000;
    return iterations;
}

int main(void)
{
    atca_deadline_set_clock(fake_clock);

    printf("\n== primitive ==\n");
    atca_deadline_set_ms(0);
    atca_deadline_begin();
    CHECK(!atca_deadline_expired(), "disabled never expires");
    CHECK(atca_deadline_remaining_ms(200) == 200, "disabled returns the cap unchanged");
    CHECK(atca_deadline_can_start(), "disabled always permits a start");

    atca_deadline_set_ms(2500);
    atca_deadline_begin();
    CHECK(!atca_deadline_expired(), "fresh budget is not expired");
    CHECK(atca_deadline_remaining_ms(200) == 200, "plenty left is clamped to the cap");
    advance_ms(2400);
    CHECK(atca_deadline_remaining_ms(200) == 100, "near the end, remaining < cap is returned");
    CHECK(atca_deadline_can_start(), "100 ms left still permits a start");
    advance_ms(95);
    CHECK(!atca_deadline_can_start(),
          "under one tick (%u ms) refuses to start rather than arming an unrepresentable timeout",
          ATCA_DEADLINE_MIN_SLICE_MS);
    advance_ms(10);
    CHECK(atca_deadline_expired(), "past the budget reports expired");
    CHECK(atca_deadline_remaining_ms(200) == 0, "expired returns 0, never a bogus 1 ms");

    printf("\n== end() clears the expiry so a later direct wake is not refused ==\n");
    CHECK(atca_deadline_expired(), "expired before end()");
    atca_deadline_end();
    CHECK(!atca_deadline_expired(), "end() clears the stale expiry");
    CHECK(atca_deadline_can_start(), "a direct wake after end() may start");
    CHECK(atca_deadline_get_ms() == 2500, "end() keeps the POLICY, only drops the timestamp");

    printf("\n== the bound, against a bus that never answers ==\n");
    int timed_out; int64_t elapsed;

    g_now_us = 0;
    atca_deadline_set_ms(0);
    atca_deadline_begin();
    int unbounded_iters = simulate_poll_loop(0, &timed_out, &elapsed);
    printf("  unbounded: %d iterations, %lld ms\n", unbounded_iters, (long long)elapsed);
    CHECK(unbounded_iters >= MAX_DELAY_COUNT,
          "unbounded runs the full %d-iteration ladder", MAX_DELAY_COUNT);
    CHECK(elapsed > 200000, "unbounded exceeds 200 s (measured %lld ms) -- the problem", (long long)elapsed);
    CHECK(!timed_out, "unbounded never reports a timeout");

    g_now_us = 0;
    atca_deadline_set_ms(2500);
    atca_deadline_begin();
    int bounded_iters = simulate_poll_loop(1, &timed_out, &elapsed);
    printf("  bounded  : %d iterations, %lld ms\n", bounded_iters, (long long)elapsed);
    CHECK(timed_out, "bounded reports a TIMEOUT rather than a transport error");
    CHECK(elapsed <= 2500 + HAL_RX_MS,
          "bounded finishes within budget + one slice (%lld ms <= %d ms)",
          (long long)elapsed, 2500 + HAL_RX_MS);
    CHECK(bounded_iters < unbounded_iters / 10,
          "bounded does far fewer iterations (%d vs %d)", bounded_iters, unbounded_iters);

    printf("\n== the case that FAILS if the bound is removed ==\n");
    /* If someone deletes the enforcement, `bounded` becomes `unbounded` and this assertion is
     * what catches it. A test that cannot fail for the right reason is worthless -- see the
     * header comment. */
    CHECK(elapsed < 200000,
          "with the bound, elapsed (%lld ms) is NOT the 200 s+ unbounded figure", (long long)elapsed);

    printf("\n%s\n", g_fail ? "RESULT: FAIL" : "RESULT: PASS");
    return g_fail;
}
