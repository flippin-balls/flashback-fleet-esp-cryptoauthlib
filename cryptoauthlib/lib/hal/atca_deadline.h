/* ATECC per-command elapsed-time deadline.
 *
 * Deliberately standalone: no atca_config.h, no ESP headers, no cryptoauthlib types. That is
 * what lets this be compiled and tested ON A HOST with an injected clock, which is the only way
 * the bound gets PROVEN rather than asserted.
 *
 * Background: cryptoauthlib bounds command polling in ITERATIONS
 * (ATCA_POLLING_MAX_TIME_MSEC / ATCA_POLLING_FREQUENCY_TIME_MSEC = 1250, plus the first attempt),
 * not in wall clock. Each iteration can block in the HAL, so one command can occupy roughly
 * 1251 x (2 + 200) ms -- about 252 s -- with every individual limit respected.
 *
 * DEFAULT IS OFF, and off preserves the previous timeout and retry behaviour: expired() is
 * always false, remaining_ms() returns its cap, can_start() is always true. Provisioning and
 * enrollment take as long as they need unless a caller deliberately opts in.
 *
 * The budget is ABSOLUTE and captured once per command, so retries inside a command consume it
 * rather than each restarting it.
 *
 * NOT a hard real-time guarantee: ESP-IDF transfer timeouts cover the bus mutex and internal
 * waits rather than being end-to-end caps, so the achievable bound is
 * "deadline + one bounded driver operation + scheduling tolerance".
 */
#ifndef ATCA_DEADLINE_H
#define ATCA_DEADLINE_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Smallest transfer timeout worth arming.
 *
 * FreeRTOS timeouts are in ticks and this build runs CONFIG_FREERTOS_HZ=100 -- one tick is 10 ms.
 * A shorter timeout rounds toward zero ticks, so a healthy transfer can be armed and declared
 * failed before its completion interrupt arrives. An earlier version returned 1 ms here, on the
 * mistaken belief that 0 meant "wait forever" (IDF 5.5 uses -1 for that) -- which would have
 * manufactured bus failures from a nearly-spent budget. Below one tick we decline to start. */
#define ATCA_DEADLINE_MIN_SLICE_MS  10u

/** Monotonic clock, microseconds. */
typedef int64_t (*atca_deadline_clock_fn)(void);

/** HOST TESTS ONLY: advance time deterministically. NULL restores the platform clock. */
void atca_deadline_set_clock(atca_deadline_clock_fn fn);

/** Platform clock, defined by the port (esp_timer on ESP-IDF). */
int64_t atca_deadline_default_clock_us(void);

/** Budget for each subsequent command. 0 disables (default). */
/* PER-COMMAND allowance. Each command gets this much, restarted by atca_deadline_begin(). */
void     atca_deadline_set_ms(uint32_t ms);

/* TOTAL allowance across however many commands follow, as one absolute wall-clock stop.
 *
 * The per-command budget alone does NOT bound a sequence: begin() restarts the allowance at
 * every command, so an operation running N commands takes up to N x the "budget" its caller
 * asked for. A caller that must not exceed a watchdog cannot express that with set_ms() alone.
 *
 * Set this and every subsequent command is clamped to whatever is LEFT of it, so the sequence
 * as a whole stops on time. 0 clears it. The stop is captured when this is called, so call it
 * immediately before the work it bounds. */
void     atca_deadline_set_total_ms(uint32_t ms);

/* Milliseconds left on the TOTAL, or UINT32_MAX when no total is in force. For a caller that
 * wants to REPORT the overrun rather than merely suffer it. */
uint32_t atca_deadline_total_remaining_ms(void);

/* NESTED totals.
 *
 * set_total_ms(0) CLEARS, which is wrong for anything called from inside another bounded
 * operation: an inner probe that clears on exit destroys the total its caller was running under,
 * and every command after it gets a fresh allowance. That is how a loop with a 20 s budget still
 * reached 34 s -- the budget survived the probe but not past it.
 *
 * push/pop instead. push never EXTENDS an outer stop: if the caller already has less time than
 * you asked for, you get the caller's. pop puts back exactly what was there.
 *
 *     const int64_t saved = atca_deadline_push_total_ms(10000);
 *     ... work ...
 *     atca_deadline_pop_total(saved);
 */
int64_t atca_deadline_push_total_ms(uint32_t ms);
void    atca_deadline_pop_total(int64_t saved_stop_us);
uint32_t atca_deadline_get_ms(void);

/** Begin / end one command's budget. end() drops the EXPIRY, keeps the POLICY -- without it a
 *  later direct wake or idle inherits a spent deadline and is refused before it starts. */
void atca_deadline_begin(void);
void atca_deadline_end(void);

/** True once the current command's budget is spent. Always false when disabled. */
bool atca_deadline_expired(void);

/** Milliseconds left, clamped to `cap`; 0 when expired; `cap` when disabled. */
uint32_t atca_deadline_remaining_ms(uint32_t cap);

/** May a transfer be STARTED now? False only when too little budget remains to arm a meaningful
 *  timeout -- callers should report the timeout rather than begin I/O that cannot finish. */
bool atca_deadline_can_start(void);

#ifdef __cplusplus
}
#endif
#endif /* ATCA_DEADLINE_H */
