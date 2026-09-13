/* Does PRODUCTION enforce the ATECC command deadline?
 *
 * This drives the REAL calib_execute_command() from calib_execution.c, with the transport and
 * the clock stubbed. That distinction is the entire point.
 *
 * An earlier host test reimplemented the poll loop's shape and called the deadline helpers from
 * its own copy. It passed, and it proved nothing: deleting the checks from calib_execution.c
 * would have left it green, because the test was exercising the primitive rather than the code
 * that is supposed to use the primitive. I "validated" that test by sabotaging the primitive --
 * which the test called directly -- so of course it failed. Wrong experiment, confident result.
 *
 * If someone removes the enforcement from calib_execute_command(), THIS test fails -- verified by
 * doing exactly that: the bound degrades from 2500 ms to 4978 ms and the timing assertion trips.
 *
 * BE PRECISE ABOUT THE STUBS. They do NOT "know nothing about deadlines" -- an earlier version of
 * this comment said so and it was wrong. They deliberately MIRROR the real HAL: refuse to start
 * outside budget, clamp the transfer to what remains. That is why two assertions survive the
 * sabotage above; loop-level enforcement is not the only thing holding the line, and the timing
 * assertion is what catches its removal.
 *
 * AND WHAT THIS DOES NOT ESTABLISH: a hard on-device bound. The transport here is modeled, not
 * the ESP32 HAL, so this proves the command layer enforces the budget against a transport that
 * behaves as specified. Real driver and scheduling overhead are not measured.
 */
#include "cryptoauthlib.h"
#include "calib/calib_execution.h"
#include "atca_deadline.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

static int g_fail = 0;
#define CHECK(c, m, ...) do { \
    if (!(c)) { printf("  FAIL: " m "\n", ##__VA_ARGS__); g_fail = 1; } \
    else      { printf("  ok  : " m "\n", ##__VA_ARGS__); } } while (0)

/* ---- virtual clock ----------------------------------------------------------------------- */
static int64_t g_now_us = 0;
static int64_t fake_clock(void) { return g_now_us; }
int64_t atca_deadline_default_clock_us(void) { return g_now_us; }
int64_t esp_timer_get_time(void) { return g_now_us; }

/* ---- stubbed transport: burns virtual time, always fails, knows nothing about deadlines ---- */
#define WAKE_COST_MS      2
#define SEND_COST_MS      2
#define RECEIVE_COST_MS 200     /* the HAL's per-transfer timeout on a bus that never answers */

static int g_wakes, g_sends, g_receives;

void atca_delay_ms(uint32_t ms) { g_now_us += (int64_t)ms * 1000; }
void atca_delay_us(uint32_t us) { g_now_us += (int64_t)us; }

ATCA_STATUS calib_wakeup(ATCADevice device) {
    /* calib_basic.c, not the unit under test. Fails like a chip that will not wake. */
    (void)device; atca_delay_ms(WAKE_COST_MS); return ATCA_COMM_FAIL;
}
ATCA_STATUS calib_idle(ATCADevice device) {
    (void)device; atca_delay_ms(2); return ATCA_SUCCESS;
}
/* STUBBED AT THE TRANSPORT BOUNDARY, not at calib_execute_send/receive.
 *
 * Those two live inside calib_execution.c, so stubbing them would have replaced code under test
 * with my own. Stubbing atsend/atreceive instead means the REAL calib_execute_send(),
 * calib_execute_receive() and calib_execute_command() all run, including their own retry
 * structure. The only thing faked is the wire. */
ATCA_STATUS atsend(ATCAIface i, uint8_t wa, uint8_t *tx, int len) {
    (void)i; (void)wa; (void)tx; (void)len;
    g_sends++;
    /* Mirrors the HAL: refuse outside budget, otherwise burn the (clamped) transfer time. */
    if (!atca_deadline_can_start()) { return ATCA_TIMEOUT; }
    atca_delay_ms(atca_deadline_remaining_ms(SEND_COST_MS));
    return ATCA_SUCCESS;                 /* the send lands; the response never comes */
}
ATCA_STATUS atreceive(ATCAIface i, uint8_t wa, uint8_t *rx, uint16_t *len) {
    (void)i; (void)wa; (void)rx; (void)len;
    g_receives++;
    if (!atca_deadline_can_start()) { return ATCA_TIMEOUT; }
    atca_delay_ms(atca_deadline_remaining_ms(RECEIVE_COST_MS));
    return ATCA_RX_NO_RESPONSE;          /* a bus that never answers */
}
ATCA_STATUS atcontrol(ATCAIface i, uint8_t o, void* p, size_t n) {
    (void)i; (void)o; (void)p; (void)n; return ATCA_UNIMPLEMENTED;
}
ATCA_STATUS atwake(ATCAIface i) { (void)i; g_wakes++; atca_delay_ms(WAKE_COST_MS); return ATCA_COMM_FAIL; }
bool atca_iface_is_kit(ATCAIface i) { (void)i; return false; }
bool atca_iface_is_swi(ATCAIface i) { (void)i; return false; }
ATCA_STATUS atca_trace_msg(ATCA_STATUS s, const char *m) { (void)m; return s; }
ATCA_STATUS atca_trace(ATCA_STATUS s) { return s; }
/* calib_command.c, not under test. Maps a response byte to an error status; for this harness
 * the response never arrives, so it is never consulted meaningfully. */
ATCA_STATUS isATCAError(uint8_t *data) { (void)data; return ATCA_SUCCESS; }
int      atca_iface_get_retries(ATCAIface i) { (void)i; return 2; }
uint8_t  atcab_get_device_address(ATCADevice d) { (void)d; return 0x60; }
bool     atcab_is_ca2_device(ATCADeviceType t) { (void)t; return false; }
ATCA_STATUS atCheckCrc(const uint8_t *r) { (void)r; return ATCA_SUCCESS; }

/* ---- a device just real enough for the code under test ---------------------------------- */
static struct atca_device  g_dev;
static ATCAIfaceCfg g_cfg;

static ATCADevice make_device(void) {
    memset(&g_dev, 0, sizeof(g_dev));
    memset(&g_cfg, 0, sizeof(g_cfg));
    g_cfg.iface_type = ATCA_I2C_IFACE;
    g_cfg.devtype    = ATECC608;
    g_dev.mIface.mIfaceCFG = &g_cfg;
    g_dev.device_state = ATCA_DEVICE_STATE_UNKNOWN;
    return &g_dev;
}

static ATCA_STATUS run_one(int64_t *elapsed_ms, int *receives) {
    ATCAPacket packet;
    memset(&packet, 0, sizeof(packet));
    packet.txsize = 4;
    g_wakes = g_sends = g_receives = 0;
    int64_t t0 = g_now_us;
    ATCA_STATUS st = calib_execute_command(&packet, make_device());
    *elapsed_ms = (g_now_us - t0) / 1000;
    *receives = g_receives;
    return st;
}

int main(void)
{
    atca_deadline_set_clock(fake_clock);
    int64_t elapsed; int receives;

    printf("\n== production WITHOUT a deadline (the problem) ==\n");
    g_now_us = 0;
    atca_deadline_set_ms(0);
    ATCA_STATUS st_un = run_one(&elapsed, &receives);
    int64_t unbounded_ms = elapsed; int unbounded_rx = receives;
    printf("  status=%d receives=%d elapsed=%lld ms\n", (int)st_un, receives, (long long)elapsed);
    CHECK(elapsed > 200000, "unbounded exceeds 200 s (%lld ms)", (long long)elapsed);
    CHECK(st_un != ATCA_TIMEOUT, "unbounded does not report a timeout");

    printf("\n== production WITH a 2500 ms deadline ==\n");
    g_now_us = 0;
    atca_deadline_set_ms(2500);
    ATCA_STATUS st_b = run_one(&elapsed, &receives);
    printf("  status=%d receives=%d elapsed=%lld ms\n", (int)st_b, receives, (long long)elapsed);
    CHECK(st_b == ATCA_TIMEOUT, "bounded returns ATCA_TIMEOUT (got %d)", (int)st_b);
    CHECK(elapsed <= 2500 + RECEIVE_COST_MS,
          "bounded finishes within budget + one transfer (%lld ms)", (long long)elapsed);
    CHECK(receives < unbounded_rx / 10,
          "bounded does far fewer receives (%d vs %d)", receives, unbounded_rx);
    CHECK(elapsed < unbounded_ms / 50,
          "bounded is orders faster than unbounded (%lld vs %lld ms)",
          (long long)elapsed, (long long)unbounded_ms);

    printf("\n== the device is left UNKNOWN after a timeout, not asserted IDLE ==\n");
    CHECK(g_dev.device_state == ATCA_DEVICE_STATE_UNKNOWN,
          "device_state is UNKNOWN (got %u)", (unsigned)g_dev.device_state);

    printf("\n== the expiry does not outlive its command ==\n");
    CHECK(!atca_deadline_expired(),
          "after the command, a later direct wake is not refused by a stale expiry");

    /* ---------------------------------------------------------------------------------------
     * THE PER-COMMAND BUDGET DOES NOT BOUND A SEQUENCE.
     *
     * Every test above runs ONE command, and a single command is precisely the case where a
     * per-command budget and a total are indistinguishable. That is why the sequence bug
     * survived a passing suite: the shape of the test could not see it.
     *
     * A real recovery is a SEQUENCE -- atcab_release(), then atecc_init() (which reads the
     * config zone), then a serial-number read. atca_deadline_begin() restarts the allowance at
     * each one, so a caller asking for "2500 ms" got 2500 ms EACH. Under hermes-bridge's 30 s
     * task watchdog that is the difference between a bound that protects the device and a bound
     * that lets it reboot by watchdog while believing itself bounded. */
    printf("\n== N commands under a PER-COMMAND budget only: the bound does not hold ==\n");
    g_now_us = 0;
    atca_deadline_set_total_ms(0);        /* no total: the old behaviour */
    atca_deadline_set_ms(2500);
    int64_t seq_start = g_now_us;
    for (int i = 0; i < 3; i++) { (void)run_one(&elapsed, &receives); }
    int64_t per_cmd_only_ms = (g_now_us - seq_start) / 1000;
    printf("  3 commands, 2500 ms per-command budget -> %lld ms total\n",
           (long long)per_cmd_only_ms);
    CHECK(per_cmd_only_ms > 2500 * 2,
          "a per-command budget lets 3 commands run well past it (%lld ms)",
          (long long)per_cmd_only_ms);

    printf("\n== the same N commands under a 2500 ms TOTAL ==\n");
    g_now_us = 0;
    atca_deadline_set_ms(2500);
    atca_deadline_set_total_ms(2500);
    seq_start = g_now_us;
    ATCA_STATUS last = ATCA_SUCCESS;
    int ran = 0;
    for (int i = 0; i < 3; i++) { last = run_one(&elapsed, &receives); ran++; }
    int64_t total_ms = (g_now_us - seq_start) / 1000;
    printf("  3 commands, 2500 ms TOTAL -> %lld ms total, last status=%d\n",
           (long long)total_ms, (int)last);
    CHECK(total_ms <= 2500 + RECEIVE_COST_MS,
          "the whole sequence finishes within the total (%lld ms)", (long long)total_ms);
    CHECK(total_ms < per_cmd_only_ms / 2,
          "the total is decisively tighter than the per-command budget (%lld vs %lld ms)",
          (long long)total_ms, (long long)per_cmd_only_ms);
    CHECK(last == ATCA_TIMEOUT,
          "a command starting after the total is spent reports ATCA_TIMEOUT (got %d)",
          (int)last);
    (void)ran;

    printf("\n== a total with NO per-command budget still bounds ==\n");
    /* The clamp lives in begin(); keying the checks off s_deadline_budget_ms instead of the
     * expiry would silently drop this case. */
    g_now_us = 0;
    atca_deadline_set_ms(0);
    atca_deadline_set_total_ms(1500);
    seq_start = g_now_us;
    for (int i = 0; i < 3; i++) { (void)run_one(&elapsed, &receives); }
    int64_t total_only_ms = (g_now_us - seq_start) / 1000;
    printf("  3 commands, total only -> %lld ms\n", (long long)total_only_ms);
    CHECK(total_only_ms <= 1500 + RECEIVE_COST_MS,
          "a bare total bounds the sequence with no per-command budget (%lld ms)",
          (long long)total_only_ms);

    printf("\n== clearing the total restores unbounded behaviour ==\n");
    g_now_us = 0;
    atca_deadline_set_total_ms(0);
    atca_deadline_set_ms(0);
    CHECK(atca_deadline_total_remaining_ms() == UINT32_MAX,
          "total_remaining reports 'no total' once cleared");
    ATCA_STATUS st_clear = run_one(&elapsed, &receives);
    printf("  status=%d elapsed=%lld ms\n", (int)st_clear, (long long)elapsed);
    CHECK(elapsed > 200000,
          "with the total cleared the old unbounded behaviour is back (%lld ms)",
          (long long)elapsed);

    /* ---------------------------------------------------------------------------------------
     * AN INNER SCOPE MUST NOT DESTROY ITS CALLER'S TOTAL.
     *
     * This is the bug that survived the first total: a wrapper set a total, did its work, and
     * cleared it with set_total_ms(0) on the way out. Anything the CALLER did afterwards -- still
     * inside the caller's own budget -- ran with no total at all. codex walked it to 34 s inside
     * a loop that had asked for 20 s: probe returns, clears, then three AES commands run free. */
    printf("\n== inner scope clears the outer total (the bug) ==\n");
    g_now_us = 0;
    atca_deadline_set_ms(2500);
    atca_deadline_set_total_ms(2500);            /* the "loop" budget */
    atca_deadline_set_total_ms(2500);            /* an inner wrapper opens its own ... */
    atca_deadline_set_total_ms(0);               /* ... and clears on exit -- outer is GONE */
    seq_start = g_now_us;
    for (int i = 0; i < 3; i++) { (void)run_one(&elapsed, &receives); }
    int64_t after_clear_ms = (g_now_us - seq_start) / 1000;
    printf("  3 commands after an inner clear -> %lld ms\n", (long long)after_clear_ms);
    CHECK(after_clear_ms > 2500 * 2,
          "clearing an inner total frees the rest of the caller's work (%lld ms)",
          (long long)after_clear_ms);

    printf("\n== push/pop keeps the outer total intact ==\n");
    g_now_us = 0;
    atca_deadline_set_ms(2500);
    int64_t outer = atca_deadline_push_total_ms(2500);   /* the loop's budget */
    int64_t inner = atca_deadline_push_total_ms(2500);   /* an inner wrapper */
    atca_deadline_pop_total(inner);                      /* inner exits */
    seq_start = g_now_us;
    for (int i = 0; i < 3; i++) { (void)run_one(&elapsed, &receives); }
    int64_t nested_ms = (g_now_us - seq_start) / 1000;
    atca_deadline_pop_total(outer);
    printf("  3 commands after an inner pop -> %lld ms\n", (long long)nested_ms);
    CHECK(nested_ms <= 2500 + RECEIVE_COST_MS,
          "the caller's total still bounds work done AFTER the inner scope (%lld ms)",
          (long long)nested_ms);
    CHECK(nested_ms < after_clear_ms / 2,
          "push/pop is decisively tighter than clear (%lld vs %lld ms)",
          (long long)nested_ms, (long long)after_clear_ms);

    printf("\n== push never EXTENDS an outer total ==\n");
    /* An inner operation asking for more than its caller has left must not be granted it. */
    g_now_us = 0;
    atca_deadline_set_ms(0);
    outer = atca_deadline_push_total_ms(1000);      /* caller has 1 s */
    inner = atca_deadline_push_total_ms(60000);     /* inner asks for 60 s */
    seq_start = g_now_us;
    (void)run_one(&elapsed, &receives);
    int64_t greedy_ms = (g_now_us - seq_start) / 1000;
    atca_deadline_pop_total(inner);
    atca_deadline_pop_total(outer);
    printf("  inner asked 60000 ms inside a 1000 ms caller -> %lld ms\n", (long long)greedy_ms);
    CHECK(greedy_ms <= 1000 + RECEIVE_COST_MS,
          "the tighter OUTER total wins (%lld ms)", (long long)greedy_ms);

    printf("\n== pop restores exactly, and the outermost pop clears ==\n");
    g_now_us = 0;
    atca_deadline_set_ms(0);
    outer = atca_deadline_push_total_ms(5000);
    CHECK(outer == 0, "push from no-total saves 'no total'");
    inner = atca_deadline_push_total_ms(1000);
    atca_deadline_pop_total(inner);
    CHECK(atca_deadline_total_remaining_ms() > 1000,
          "after popping the inner scope the OUTER budget is what remains");
    atca_deadline_pop_total(outer);
    CHECK(atca_deadline_total_remaining_ms() == UINT32_MAX,
          "popping the outermost scope leaves no total in force");

    printf("\n%s\n", g_fail ? "RESULT: FAIL" : "RESULT: PASS");
    return g_fail;
}
