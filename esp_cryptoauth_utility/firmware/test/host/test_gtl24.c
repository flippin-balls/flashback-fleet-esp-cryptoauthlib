/*
 * Host test for the GTL 24 console commands (main/gtl24_cmds.c) and their ATECC operations (main/gtl24_slots.c), run
 * against the virtual ATECC608 (virtual_atecc.c) configured with TEMPLATE V2 -- the exact 128 bytes the bench flow
 * writes. Every command goes through the real handler with a byte stream exactly like the host's: "<command>" then
 * the raw payload and one NUL.
 *
 * Build + run: sh build_gtl24.sh   (--mutate: damage each rule in a copy and require RED)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ecu_console_interface.h"
#include "esp_console.h"
#include "esp_rom_crc.h"
#include "gtl24.h"
#include "virtual_atecc.h"

extern esp_console_cmd_t vt_cmds[16];
extern int vt_ncmds;

static int g_fail = 0, g_checks = 0;
#define CHECK(cond, ...)                                                                                               \
    do {                                                                                                               \
        g_checks++;                                                                                                    \
        if (!(cond)) {                                                                                                 \
            g_fail++;                                                                                                  \
            printf("FAIL %s:%d: ", __FILE__, __LINE__);                                                                \
            printf(__VA_ARGS__);                                                                                       \
            printf("\n");                                                                                              \
        }                                                                                                              \
    } while (0)

/* device-config-management fbf_device_config/provisioning/default_config_v2.py ATECC608_TEMPLATE_V2 at dcm b4572ee
 * (slots 10-12: WriteConfig Always, clear, Lockable -- the record; 13/15: PubInvalid, secret; 14: Never, secret). */
static const char *TEMPLATE_V2_HEX =
    "01230000000050000000000000c07100c000000287809646848096468280868086808646864686460f000f000f009e109f809e10ffffffff"
    "00000000ffffffff0000000000000000f0000000000000000000000000005555ffff0a640000000013001c0013001c0013001c005c001800"
    "180018003c003c003c00120010001200";
static uint8_t TEMPLATE_V2[128];

static void hex2bin(const char *h, uint8_t *out, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        sscanf(h + 2 * i, "%2x", &v);
        out[i] = (uint8_t)v;
    }
}

static esp_console_cmd_func_t find(const char *name)
{
    for (int i = 0; i < vt_ncmds; i++)
        if (strcmp(vt_cmds[i].command, name) == 0) return vt_cmds[i].func;
    return NULL;
}

/* Run one command line against whatever the stream holds. Returns the handler's code; the output is in vt_captured(). */
static int call(const char *line)
{
    vt_capture_reset();
    char buf[256];
    snprintf(buf, sizeof buf, "%s", line);
    char *argv[8];
    int argc = 0;
    for (char *t = strtok(buf, " "); t && argc < 8; t = strtok(NULL, " ")) argv[argc++] = t;
    esp_console_cmd_func_t f = find(argv[0]);
    if (!f) return -999;
    return f(argc, argv);
}

/* Run "line" with an optional payload the way the host sends it (payload bytes, then one NUL when `nul`). */
static int run(const char *line, const uint8_t *payload, size_t n, int nul)
{
    va_clear_input();
    if (payload) va_feed(payload, n);
    if (nul) { const uint8_t z = 0; va_feed(&z, 1); }
    return call(line);
}

/* app_main.c scli_loop, modelled: read to '\r' (at most 1023 bytes), drop the last character, run the line through the
 * registry. Ends when the stream is exhausted (the target's read would block). Returns the lines dispatched. */
static int session(void)
{
    vt_capture_reset();
    int lines = 0;
    for (;;) {
        char line[1024] = {0};
        int i = 0;
        do {
            if (get_console_interface()->read_bytes((uint8_t *)&line[i], 1, portMAX_DELAY) <= 0) return lines;
            i++;
        } while (i < 1023 && line[i - 1] != '\r');
        const size_t len = strlen(line);
        if (len == 0) continue;   /* (the target writes linebuf[-1] here -- pre-existing; no stream below reaches it) */
        line[len - 1] = '\0';
        lines++;
        char *argv[8];
        int argc = 0;
        for (char *t = strtok(line, " "); t && argc < 8; t = strtok(NULL, " ")) argv[argc++] = t;
        esp_console_cmd_func_t f = argc ? find(argv[0]) : NULL;
        if (f) f(argc, argv);
    }
}

static const uint8_t NUL1[1] = {0};
static void feed_str_after(uint32_t gap_ms, const char *str) { va_feed_after(gap_ms, (const uint8_t *)str, strlen(str)); }

static int count(const char *hay, const char *needle)
{
    int c = 0;
    for (const char *p = strstr(hay, needle); p; p = strstr(p + 1, needle)) c++;
    return c;
}

static int ok(void) { return strstr(vt_captured(), "Status: Success") != NULL && strstr(vt_captured(), "Status: Failure") == NULL; }
static int failed(void) { return strstr(vt_captured(), "Status: Failure") != NULL && strstr(vt_captured(), "Status: Success") == NULL; }

static void blank_v2(void) { va_reset(TEMPLATE_V2); VA_ATCAB_INIT = true; VA_CLI_READY = true; va_clear_input(); }

/* The stub halted: it wrote the prompt itself (a handler that returns leaves the prompt to the console loop). */
static int halted(void) { return VA.prompts > 0; }

/* A fresh stub load on the same chip: what re-running the flow does after a halt. */
static void reload(void) { VA.prompts = 0; VA.atcab_calls = 0; }

static void fill(uint8_t *b, size_t n, unsigned seed)
{
    for (size_t i = 0; i < n; i++) b[i] = (uint8_t)((i * 37u + seed) & 0xFFu);
    b[0] = 0x00; b[n / 2] = 0x00;   /* binary payloads carry NULs: framing is by length, never by NUL */
}

static void test_registration(void)
{
    const char *names[] = {"write-slot", "read-slot", "lock-slot", "write-pubkey", "sleep"};
    for (int i = 0; i < 5; i++) CHECK(find(names[i]) != NULL, "%s registered", names[i]);
    CHECK(vt_ncmds == 5, "exactly the five commands (%d)", vt_ncmds);
}

/* The bench flow's order: config locked, trust anchors 13-15, data lock, the record 10-12, read back, slot locks. */
static void test_template_v2_flow(void)
{
    blank_v2();
    va_lock_config();
    uint8_t pub[3][64];
    for (int k = 0; k < 3; k++) {
        fill(pub[k], 64, 11u * (unsigned)k + 1u);
        char line[32];
        snprintf(line, sizeof line, "write-pubkey %d", 13 + k);
        run(line, pub[k], 64, 1);
        CHECK(ok() && va_pending() == 0, "write-pubkey %d before the data lock: %s", 13 + k, vt_captured());
        uint8_t stored[72] = {0};
        memcpy(&stored[4], pub[k], 32);
        memcpy(&stored[40], &pub[k][32], 32);
        CHECK(memcmp(VA.data[13 + k], stored, 72) == 0, "slot %d holds (pad, X, pad, Y)", 13 + k);
    }
    CHECK(VA.word_writes == 0, "public keys go in as whole blocks only (%d word writes)", VA.word_writes);
    va_lock_data();

    uint8_t rec[3][72];
    for (int k = 0; k < 3; k++) {
        fill(rec[k], 72, 101u + (unsigned)k);
        char line[32];
        snprintf(line, sizeof line, "write-slot %d 0 72", 10 + k);
        run(line, rec[k], 72, 1);
        CHECK(ok() && va_pending() == 0, "write-slot %d after the data lock: %s", 10 + k, vt_captured());
        CHECK(memcmp(VA.data[10 + k], rec[k], 72) == 0, "slot %d holds the record bytes, NULs included", 10 + k);
    }
    for (int k = 0; k < 3; k++) {
        char line[32], want[200];
        snprintf(line, sizeof line, "read-slot %d 72", 10 + k);
        run(line, NULL, 0, 0);
        char *hex = want;
        hex += sprintf(hex, "Data: ");
        for (int i = 0; i < 72; i++) hex += sprintf(hex, "%02x", rec[k][i]);
        const char *st = strstr(vt_captured(), "Status: Success");
        const char *da = strstr(vt_captured(), want);
        CHECK(ok() && st && da && st < da, "read-slot %d: Data after Status, exact bytes: %s", 10 + k, vt_captured());
    }
    for (int k = 0; k < 3; k++) {
        char line[32];
        snprintf(line, sizeof line, "lock-slot %d", 10 + k);
        run(line, NULL, 0, 0);
        CHECK(ok() && va_slot_locked(10 + k), "lock-slot %d", 10 + k);
    }
    run("lock-slot 10", NULL, 0, 0);
    CHECK(failed(), "a second lock of the same slot fails");
    run("write-slot 10 0 72", rec[0], 72, 1);
    CHECK(failed() && va_pending() == 0, "a locked record slot refuses a write");
    CHECK(!halted(), "a whole flow never halts");
}

static void test_pubkey_rules(void)
{
    uint8_t pub[64];
    fill(pub, 64, 7);
    blank_v2();
    run("write-pubkey 13", pub, 64, 1);
    CHECK(failed() && VA.refused > 0, "no data write before the config lock");
    blank_v2();
    va_lock_config();
    va_lock_data();
    run("write-pubkey 14", pub, 64, 1);
    CHECK(failed() && va_pending() == 0, "slot 14 (WriteConfig Never) refuses after the data lock");
    run("write-pubkey 13", pub, 64, 1);
    CHECK(ok(), "slot 13 (PubInvalid) takes block writes after the data lock");
    CHECK(!halted(), "a refusal by the chip is not a framing error");
    VA.atcab_calls = 0;
    run("write-pubkey 7", pub, 64, 1);
    CHECK(failed() && halted() && VA.atcab_calls == 0, "slot 7 is not a public-key slot: refused, the stub halts");
    /* Why write-pubkey and not write-slot: a secret slot refuses the 4-byte words a 72-byte write ends with. */
    blank_v2();
    va_lock_config();
    uint8_t raw[72];
    fill(raw, 72, 3);
    run("write-slot 13 0 72", raw, 72, 1);
    CHECK(failed(), "write-slot into secret slot 13 fails on its trailing words");
}

static void test_framing(void)
{
    uint8_t rec[72];
    fill(rec, 72, 9);
    blank_v2();
    va_lock_config();
    va_lock_data();
    run("write-slot 11 0 72", rec, 64, 0);   /* the host dies 8 bytes short */
    CHECK(failed() && halted() && VA.atcab_calls == 0, "a short payload: Failure, halt, no write: %s", vt_captured());
    CHECK(strstr(vt_captured(), "got 64 of 72 bytes") && !strstr(vt_captured(), "terminator"),
          "and says exactly that (no terminator noise): %s", vt_captured());
    const char *st = strstr(vt_captured(), "Status: Failure");
    const char *why = strstr(vt_captured(), "FRAMING ERROR");
    CHECK(st && why && st < why, "the reason follows the Status line (the host shows that text): %s", vt_captured());
    reload();
    uint8_t longer[76];
    fill(longer, 76, 5);
    longer[72] = 0x41;
    run("write-slot 11 0 72", longer, 76, 1);   /* 4 bytes more than declared */
    CHECK(failed() && halted() && va_pending() == 0 && VA.atcab_calls == 0, "a length mismatch: Failure, halt, no write");
    CHECK(strstr(vt_captured(), "not the NUL terminator") != NULL, "says why");
    reload();
    longer[72] = 0x00;   /* codex R1.2: the byte at <len> happens to be 0x00 */
    run("write-slot 11 0 72", longer, 76, 1);
    CHECK(failed() && halted() && VA.atcab_calls == 0, "an oversized payload with 0x00 at <len>: Failure, halt, no write");
    CHECK(strstr(vt_captured(), "more input after") != NULL, "says why: %s", vt_captured());
    reload();
    run("write-slot 11 0 72", rec, 72, 0);   /* no NUL */
    CHECK(failed() && halted() && strstr(vt_captured(), "no NUL terminator") &&
              !strstr(vt_captured(), "not the NUL terminator"),
          "a missing NUL: Failure, halt, and says so: %s", vt_captured());
    reload();
    run("write-slot 11 0 72", NULL, 0, 0);   /* nothing at all */
    CHECK(failed() && halted() && strstr(vt_captured(), "got 0 of 72"), "no payload at all: Failure, not a hang");
    reload();
    run("write-slot 11 0 72", rec, 72, 1);
    CHECK(ok() && !halted() && memcmp(VA.data[11], rec, 72) == 0, "a fresh load takes a proper payload");

    /* write-pubkey frames the same way (before the data lock, as the flow writes the trust anchors) */
    blank_v2();
    va_lock_config();
    uint8_t pub[70];
    fill(pub, 70, 13);
    run("write-pubkey 13", pub, 60, 0);
    CHECK(failed() && halted() && VA.atcab_calls == 0 && strstr(vt_captured(), "got 60 of 64"),
          "a short public key: Failure, halt, nothing written: %s", vt_captured());
    reload();
    pub[64] = 0x00;
    run("write-pubkey 13", pub, 70, 1);
    CHECK(failed() && halted() && VA.atcab_calls == 0 && strstr(vt_captured(), "more input after"),
          "an oversized public key with 0x00 at byte 64: Failure, halt, nothing written");
    reload();
    run("write-pubkey 13", pub, 64, 1);
    CHECK(ok() && !halted(), "a whole public key frame is written");
}

/* Arrival times: the waits are bounded and the frame must be followed by a quiet line. */
static int timed_write(uint32_t first_ms, uint32_t mid_ms, uint32_t nul_ms, uint32_t extra_ms, uint8_t *rec)
{
    fill(rec, 72, 55);
    blank_v2();
    va_lock_config();
    va_lock_data();
    va_feed_after(first_ms, rec, 32);
    va_feed_after(mid_ms, &rec[32], 40);
    va_feed_after(nul_ms, NUL1, 1);
    if (extra_ms) feed_str_after(extra_ms, "lock-slot 11\r");
    return call("write-slot 10 0 72");
}

static void test_timing(void)
{
    uint8_t rec[72];
    timed_write(4900, 0, 0, 0, rec);
    CHECK(ok() && !halted() && memcmp(VA.data[10], rec, 72) == 0, "the first byte may take 4.9 s: %s", vt_captured());
    CHECK(va_now() == 4900 + 100, "the answer waits a 100 ms quiet line after the NUL (now %u)", (unsigned)va_now());
    timed_write(5100, 0, 0, 0, rec);
    CHECK(failed() && halted() && VA.atcab_calls == 0 && strstr(vt_captured(), "got 0 of 72"), "5.1 s: halt");
    timed_write(100, 900, 0, 0, rec);
    CHECK(ok() && !halted(), "a 0.9 s gap mid-payload is tolerated");
    timed_write(100, 1100, 0, 0, rec);
    CHECK(failed() && halted() && VA.atcab_calls == 0 && strstr(vt_captured(), "got 32 of 72"), "a 1.1 s gap: halt");
    timed_write(100, 0, 900, 0, rec);
    CHECK(ok() && !halted(), "the NUL may take 0.9 s");
    timed_write(100, 0, 1100, 0, rec);
    CHECK(failed() && halted() && strstr(vt_captured(), "no NUL terminator"), "the NUL after 1.1 s: halt");
    timed_write(100, 0, 0, 90, rec);
    CHECK(failed() && halted() && VA.atcab_calls == 0 && !va_slot_locked(11) && strstr(vt_captured(), "more input after"),
          "input 90 ms after the NUL: halt, no write, the trailing command not run: %s", vt_captured());
    CHECK(count(vt_captured(), "Status: Failure") == 2 && VA.prompts == 2,
          "the halted stub answers the trailing line too (Failure + prompt), so the host never waits forever");
}

/* The console loop itself: no byte of a broken frame is ever dispatched, and a whole frame's bytes are data. */
static void test_session(void)
{
    /* codex R1.2's stream: an oversized payload whose byte at <len> is 0x00, followed by a command */
    blank_v2();
    va_lock_config();
    va_lock_data();
    feed_str_after(0, "write-slot 10 0 4\r");
    feed_str_after(100, "ABCD");
    va_feed(NUL1, 1);
    feed_str_after(0, "lock-slot 11\r");
    va_feed(NUL1, 1);
    CHECK(session() == 1 && !va_slot_locked(11) && VA.atcab_calls == 0 && halted(),
          "R1.2: the trailing \"lock-slot 11\" is never dispatched, nothing written: %s", vt_captured());

    /* codex R1.1's stream: the payload stalls past the next-byte wait, then the rest carries a command */
    blank_v2();
    va_lock_config();
    va_lock_data();
    uint8_t part[32];
    memset(part, 'x', sizeof part);
    feed_str_after(0, "write-slot 11 0 72\r");
    va_feed_after(100, part, 32);
    feed_str_after(1500, "lock-slot 11\r");
    va_feed(part, 27);
    va_feed(NUL1, 1);
    CHECK(session() == 1 && !va_slot_locked(11) && VA.atcab_calls == 0 && halted() &&
              !strstr(vt_captured(), "Status: Success"),
          "R1.1: the late remainder is never dispatched: %s", vt_captured());

    /* untrusted arguments: the payload's length is unknown, so the stub halts before reading it */
    blank_v2();
    va_lock_config();
    va_lock_data();
    feed_str_after(0, "write-slot 10 0\r");
    feed_str_after(100, "lock-slot 11\r");
    va_feed(NUL1, 1);
    CHECK(session() == 1 && !va_slot_locked(11) && halted(), "bad arguments: the payload is never dispatched");

    /* the host's real stream: a whole frame whose bytes contain "\rlock-slot 11\r" is data, then the next commands */
    blank_v2();
    va_lock_config();
    va_lock_data();
    uint8_t rec[72];
    fill(rec, 72, 77);
    memcpy(&rec[10], "\rlock-slot 11\r", 14);
    feed_str_after(0, "write-slot 10 0 72\r");
    va_feed_after(100, rec, 72);
    va_feed(NUL1, 1);
    feed_str_after(300, "read-slot 10 72\r");
    feed_str_after(300, "lock-slot 10\r");
    const int n = session();
    CHECK(n == 3 && memcmp(VA.data[10], rec, 72) == 0 && va_slot_locked(10) && !va_slot_locked(11) && !halted() &&
              count(vt_captured(), "Status: Success") == 3,
          "a whole frame: written as data, then exactly the host's next two commands (%d lines): %s", n, vt_captured());

    /* not initialized: the whole frame is consumed, the next line is the host's */
    blank_v2();
    VA_CLI_READY = false;
    feed_str_after(0, "write-slot 10 0 72\r");
    va_feed_after(100, rec, 72);
    va_feed(NUL1, 1);
    feed_str_after(300, "sleep\r");
    CHECK(session() == 2 && !halted() && !va_slot_locked(11) && VA.atcab_calls == 0 &&
              count(vt_captured(), "Status: Failure") == 2,
          "not initialized: the frame is consumed whole, then the host's next command");
}
static void test_bad_arguments(void)
{
    uint8_t rec[72];
    fill(rec, 72, 21);
    const char *bad[] = {"write-slot 10 0", "write-slot 10junk 0 72", "write-slot 16 0 72", "write-slot -1 0 72",
                         "write-slot 10 0 0", "write-slot 10 0 417", "write-slot 10 x 72", "write-slot 10 0 72 9 9",
                         "write-slot 10 0 99999999999999999999"};
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        blank_v2();
        va_lock_config();
        va_lock_data();
        run(bad[i], rec, 72, 1);
        CHECK(failed() && halted() && VA.atcab_calls == 0 && strstr(vt_captured(), "Reading") == NULL,
              "\"%s\": the payload length cannot be trusted -- Failure and halt before reading it, no chip call", bad[i]);
    }
    blank_v2();
    va_lock_config();
    va_lock_data();
    run("write-slot 10 2 72", rec, 72, 1);
    CHECK(failed() && !halted() && va_pending() == 0 && VA.block_writes + VA.word_writes == 0,
          "unaligned offset refused by the chip layer (whole frame consumed, no halt)");
    run("write-slot 10 0 70", rec, 70, 1);
    CHECK(failed() && va_pending() == 0 && VA.block_writes + VA.word_writes == 0, "unaligned length refused");
    run("write-slot 10 4 72", rec, 72, 1);
    CHECK(failed() && VA.block_writes + VA.word_writes == 0, "past the end of a 72-byte slot refused");
    run("write-slot 10 64 8", rec, 8, 1);
    CHECK(ok() && memcmp(&VA.data[10][64], rec, 8) == 0, "the slot's last word is reachable");
    const char *badpk[] = {"write-pubkey", "write-pubkey 13 1 1", "write-pubkey 16", "write-pubkey 13x", "write-pubkey 7"};
    uint8_t pub[64];
    fill(pub, 64, 1);
    for (size_t i = 0; i < sizeof badpk / sizeof badpk[0]; i++) {
        blank_v2();
        va_lock_config();
        run(badpk[i], pub, 64, 1);
        CHECK(failed() && halted() && VA.atcab_calls == 0 && strstr(vt_captured(), "Reading") == NULL,
              "\"%s\": Failure and halt before reading the payload, no chip call", badpk[i]);
    }
    const char *badno[] = {"read-slot 10", "read-slot 10 0", "read-slot 10 73", "read-slot 17 72", "lock-slot",
                           "lock-slot 10junk", "lock-slot 16", "sleep now"};
    for (size_t i = 0; i < sizeof badno / sizeof badno[0]; i++) {
        blank_v2();
        va_lock_config();
        va_lock_data();
        run(badno[i], NULL, 0, 0);
        CHECK(failed() && !halted() && !va_slot_locked(10) && VA.sleeps == 0, "\"%s\": Failure, no effect, no halt",
              badno[i]);
    }
}

static void test_not_initialized(void)
{
    uint8_t rec[72];
    fill(rec, 72, 2);
    blank_v2();
    va_lock_config();
    va_lock_data();
    VA_CLI_READY = false;
    run("write-slot 10 0 72", rec, 72, 1);
    CHECK(failed() && !halted() && va_pending() == 0 && VA.block_writes + VA.word_writes == 0,
          "write-slot before init: Failure, the whole frame consumed");
    run("write-pubkey 13", rec, 64, 1);
    CHECK(failed() && !halted() && va_pending() == 0, "write-pubkey before init: Failure, the whole frame consumed");
    run("write-slot 10 0 72", rec, 64, 0);
    CHECK(failed() && halted() && VA.atcab_calls == 0, "before init, a broken frame still halts");
    reload();
    run("write-pubkey 13", rec, 60, 0);
    CHECK(failed() && halted() && VA.atcab_calls == 0, "before init, a broken public-key frame still halts");
    reload();
    run("read-slot 10 72", NULL, 0, 0);
    CHECK(failed() && strstr(vt_captured(), "Data:") == NULL, "read-slot before init");
    run("lock-slot 10", NULL, 0, 0);
    CHECK(failed() && !va_slot_locked(10), "lock-slot before init");
    run("sleep", NULL, 0, 0);
    CHECK(failed() && VA.sleeps == 0, "sleep before init");
    VA_CLI_READY = true;
    VA_ATCAB_INIT = false;
    run("write-slot 10 0 72", rec, 72, 1);
    CHECK(failed() && VA.block_writes + VA.word_writes == 0, "the handler refuses without atcab init too");
    run("lock-slot 10", NULL, 0, 0);
    CHECK(failed() && !va_slot_locked(10), "lock-slot without atcab init");
    run("sleep", NULL, 0, 0);
    CHECK(failed() && VA.sleeps == 0, "sleep without atcab init");
    run("write-pubkey 13", rec, 64, 1);
    CHECK(failed() && VA.block_writes == 0, "write-pubkey without atcab init");
    run("read-slot 10 72", NULL, 0, 0);
    CHECK(failed(), "read-slot without atcab init");
}

static void test_read_rules(void)
{
    blank_v2();
    va_lock_config();
    run("read-slot 10 72", NULL, 0, 0);
    CHECK(failed() && strstr(vt_captured(), "Data:") == NULL, "no clear read before the data lock, and no Data line");
    va_lock_data();
    run("read-slot 13 72", NULL, 0, 0);
    CHECK(failed() && strstr(vt_captured(), "Data:") == NULL, "no clear read of a secret slot");
    run("read-slot 10 70", NULL, 0, 0);
    CHECK(failed(), "an unaligned length is refused");
    run("read-slot 10 4", NULL, 0, 0);
    CHECK(ok() && strstr(vt_captured(), "Data: 00000000"), "a 4-byte read: %s", vt_captured());
}

static void test_lock_rules(void)
{
    blank_v2();
    va_lock_config();
    run("lock-slot 10", NULL, 0, 0);
    CHECK(failed() && !va_slot_locked(10), "no slot lock before the data lock");
    va_lock_data();
    run("lock-slot 0", NULL, 0, 0);
    CHECK(failed() && !va_slot_locked(0), "slot 0 is not Lockable");
    run("lock-slot 12", NULL, 0, 0);
    CHECK(ok() && va_slot_locked(12) && !va_slot_locked(10) && !va_slot_locked(11), "only the named slot locks");
}

/* The chip-side layer refuses, WITHOUT a chip call, anything outside the slot or off the word grid -- it does not lean
 * on CryptoAuthLib's own checks -- and it sizes slots 0-7 at 36 B, slot 8 at 416 B, 9-15 at 72 B. */
static void test_handlers_direct(void)
{
    static unsigned char b[416];
    int e = 0;
    blank_v2();
    va_lock_config();
    va_lock_data();
    struct { int slot, off; size_t len; } bad[] = {{10, 2, 72}, {10, 2, 4}, {10, 0, 70}, {10, 4, 72}, {16, 0, 4}, {-1, 0, 4},
                                                   {10, -4, 4}, {10, 0, 0}, {1, 0, 40}, {8, 0, 420}, {9, 72, 4}};
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        VA.atcab_calls = 0;
        CHECK(atecc_write_slot(bad[i].slot, bad[i].off, b, bad[i].len, &e) == ESP_FAIL && VA.atcab_calls == 0,
              "atecc_write_slot(%d, %d, %u) refused before any chip call", bad[i].slot, bad[i].off, (unsigned)bad[i].len);
    }
    VA.atcab_calls = 0;
    CHECK(atecc_write_slot(1, 32, b, 4, &e) == ESP_FAIL && VA.atcab_calls == 1, "slot 1's last word reaches the chip");
    VA.atcab_calls = 0;
    CHECK(atecc_write_slot(10, 0, NULL, 4, &e) == ESP_FAIL && VA.atcab_calls == 0, "NULL buffer refused");
    struct { int slot; size_t len; } rbad[] = {{10, 76}, {10, 6}, {10, 0}, {1, 40}, {16, 4}, {-1, 4}, {8, 420}};
    for (size_t i = 0; i < sizeof rbad / sizeof rbad[0]; i++) {
        VA.atcab_calls = 0;
        CHECK(atecc_read_slot(rbad[i].slot, b, rbad[i].len, &e) == ESP_FAIL && VA.atcab_calls == 0,
              "atecc_read_slot(%d, %u) refused before any chip call", rbad[i].slot, (unsigned)rbad[i].len);
    }
    VA.atcab_calls = 0;
    CHECK(atecc_read_slot(8, b, 416, &e) == ESP_FAIL && VA.atcab_calls == 1, "slot 8 is 416 B: the read reaches the chip");
    VA.atcab_calls = 0;
    CHECK(atecc_read_slot(1, b, 36, &e) == ESP_FAIL && VA.atcab_calls == 1, "slot 1 is 36 B: the read reaches the chip");
    VA.atcab_calls = 0;
    CHECK(atecc_write_pubkey_slot(7, b, &e) == ESP_FAIL && VA.atcab_calls == 0, "a public key never goes to slot 7");
    CHECK(atecc_write_pubkey_slot(16, b, &e) == ESP_FAIL && VA.atcab_calls == 0, "nor to slot 16");
    CHECK(atecc_write_pubkey_slot(13, NULL, &e) == ESP_FAIL && VA.atcab_calls == 0, "nor from NULL");
    CHECK(atecc_lock_slot(16, &e) == ESP_FAIL && atecc_lock_slot(-1, &e) == ESP_FAIL && VA.atcab_calls == 0,
          "lock-slot range refused before any chip call");
}

static void test_sleep_failure(void)
{
    blank_v2();
    VA.fail_sleep = true;
    run("sleep", NULL, 0, 0);
    CHECK(failed() && !VA.asleep, "a sleep the chip refuses is a Failure");
}

static void test_sleep(void)
{
    blank_v2();
    va_lock_config();
    va_lock_data();
    run("sleep", NULL, 0, 0);
    CHECK(ok() && VA.asleep && VA.sleeps == 1, "sleep");
    run("read-slot 10 4", NULL, 0, 0);
    CHECK(ok() && !VA.asleep && VA.wakes == 1, "the next command runs after a wake");
}

/* I9y7WaYU step 1: the optional payload CRC32, decimal, zlib's crc32(). The constants below were computed with Python's
 * zlib.crc32(), independently of the shim the stub links against. */
#define CRC_REC_201 "3954926006"   /* zlib.crc32(fill(72, 201)) */
#define CRC_PUB_202 "1410416443"   /* zlib.crc32(fill(64, 202)) */
#define CRC_R21     "130108043"    /* zlib.crc32(b"ABCD\0lock-slot 11\r"): what a host sending that payload computes */
static void test_crc(void)
{
    static const uint8_t check[] = "123456789";
    CHECK(esp_rom_crc32_le(0, check, 9) == 0xCBF43926u, "the CRC is the standard CRC-32 (check value)");
    uint8_t rec[72], pub[64];
    fill(rec, 72, 201);
    fill(pub, 64, 202);

    blank_v2();
    va_lock_config();
    va_lock_data();
    run("write-slot 10 0 72 " CRC_REC_201, rec, 72, 1);
    CHECK(ok() && !halted() && memcmp(VA.data[10], rec, 72) == 0, "write-slot with the right CRC32: written");
    VA.atcab_calls = 0;
    run("write-slot 11 0 72 3954926007", rec, 72, 1);
    CHECK(failed() && halted() && VA.atcab_calls == 0 && strstr(vt_captured(), "CRC32 of the 72 bytes is 3954926006"),
          "a wrong CRC32: Failure and halt before any chip call, and it says why: %s", vt_captured());
    reload();
    run("write-slot 11 0 72 0003954926006", rec, 72, 1);
    CHECK(ok() && memcmp(VA.data[11], rec, 72) == 0, "leading zeros are still the same decimal number");
    run("write-slot 12 0 72", rec, 72, 1);
    CHECK(ok() && memcmp(VA.data[12], rec, 72) == 0, "no CRC32: accepted as before (step 1 keeps the old host working)");
    const char *bad[] = {"write-slot 10 0 72 12x", "write-slot 10 0 72 -1", "write-slot 10 0 72 +5",
                         "write-slot 10 0 72 0x1F", "write-slot 10 0 72 4294967296", "write-slot 10 0 72 1 2"};
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        reload();
        run(bad[i], rec, 72, 1);
        CHECK(failed() && halted() && VA.atcab_calls == 0 && !strstr(vt_captured(), "Reading"),
              "\"%s\": a CRC32 that is not a whole decimal u32 halts before the payload is read", bad[i]);
    }
    reload();
    run("write-slot 10 0 72 4294967295", rec, 72, 1);
    CHECK(halted() && strstr(vt_captured(), "Reading") && strstr(vt_captured(), "the host sent 4294967295"),
          "4294967295 is a valid CRC32 argument (it parses; this payload's CRC just differs)");

    blank_v2();
    va_lock_config();
    run("write-pubkey 13 " CRC_PUB_202, pub, 64, 1);
    CHECK(ok() && !halted() && memcmp(&VA.data[13][4], pub, 32) == 0, "write-pubkey with the right CRC32: written");
    VA.atcab_calls = 0;
    run("write-pubkey 15 1410416442", pub, 64, 1);
    CHECK(failed() && halted() && VA.atcab_calls == 0, "write-pubkey with a wrong CRC32: halt before any chip call");
    const char *badpk[] = {"write-pubkey 13 x", "write-pubkey 13 +1", "write-pubkey 13 1 2"};
    for (size_t i = 0; i < sizeof badpk / sizeof badpk[0]; i++) {
        reload();
        run(badpk[i], pub, 64, 1);
        CHECK(failed() && halted() && VA.atcab_calls == 0 && !strstr(vt_captured(), "Reading"),
              "\"%s\": halt before the payload is read", badpk[i]);
    }

    /* Not initialized: the whole frame is consumed and its CRC32 still checked (codex R1.1 on I9y7WaYU) -- a refusal
     * must not hand a broken frame's late remainder to the console loop either. */
    blank_v2();
    VA_CLI_READY = false;
    run("write-slot 10 0 72 " CRC_REC_201, rec, 72, 1);
    CHECK(failed() && !halted() && va_pending() == 0 && VA.atcab_calls == 0,
          "not initialized, right CRC32: Failure, frame consumed, no halt");
    run("write-slot 10 0 72", rec, 72, 1);
    CHECK(failed() && !halted() && va_pending() == 0, "not initialized, no CRC32: Failure, frame consumed, no halt");
    run("write-slot 10 0 72 1", rec, 72, 1);
    CHECK(failed() && halted() && VA.atcab_calls == 0, "not initialized, wrong CRC32: halt");
    reload();
    run("write-pubkey 13 " CRC_PUB_202, pub, 64, 1);
    CHECK(failed() && !halted() && va_pending() == 0, "not initialized, write-pubkey, right CRC32: Failure, no halt");
    run("write-pubkey 13 1", pub, 64, 1);
    CHECK(failed() && halted() && VA.atcab_calls == 0, "not initialized, write-pubkey, wrong CRC32: halt");
    reload();
    feed_str_after(0, "write-slot 10 0 4 " CRC_R21 "\r");
    feed_str_after(100, "ABCD");
    va_feed(NUL1, 1);
    feed_str_after(150, "lock-slot 11\r");
    va_feed(NUL1, 1);
    CHECK(session() == 1 && !va_slot_locked(11) && halted(),
          "not initialized, R2.1's stream with the CRC32: the late suffix is never dispatched");
    VA_CLI_READY = true;

    /* codex R2.1 on #12, closed: a host sending "ABCD\0lock-slot 11\r" for a declared 4 bytes, the suffix arriving after
     * the quiet line. Its CRC32 is over everything it sent, so the stub's CRC over 4 bytes differs: halt. */
    blank_v2();
    va_lock_config();
    va_lock_data();
    feed_str_after(0, "write-slot 10 0 4 " CRC_R21 "\r");
    feed_str_after(100, "ABCD");
    va_feed(NUL1, 1);
    feed_str_after(150, "lock-slot 11\r");
    va_feed(NUL1, 1);
    CHECK(session() == 1 && !va_slot_locked(11) && VA.atcab_calls == 0 && halted(),
          "R2.1 with the CRC32: the late \"lock-slot 11\" is never dispatched, nothing written: %s", vt_captured());
    /* ... and without it, the residual this card exists for (step 3 makes the CRC32 mandatory). */
    blank_v2();
    va_lock_config();
    va_lock_data();
    feed_str_after(0, "write-slot 10 0 4\r");
    feed_str_after(100, "ABCD");
    va_feed(NUL1, 1);
    feed_str_after(150, "lock-slot 11\r");
    va_feed(NUL1, 1);
    CHECK(session() == 2 && va_slot_locked(11),
          "R2.1 WITHOUT the CRC32: the late suffix still runs -- why step 3 makes the CRC32 mandatory");
}

int main(void)
{
    hex2bin(TEMPLATE_V2_HEX, TEMPLATE_V2, 128);
    if (register_gtl24_commands() != ESP_OK) { printf("FAIL: registration\n"); return 1; }
    test_registration();
    test_template_v2_flow();
    test_pubkey_rules();
    test_framing();
    test_bad_arguments();
    test_not_initialized();
    test_read_rules();
    test_lock_rules();
    test_sleep();
    test_timing();
    test_session();
    test_handlers_direct();
    test_sleep_failure();
    test_crc();
    printf("%s: %d checks, %d failed\n", g_fail ? "FAIL" : "PASS", g_checks, g_fail);
    return g_fail ? 1 : 0;
}
