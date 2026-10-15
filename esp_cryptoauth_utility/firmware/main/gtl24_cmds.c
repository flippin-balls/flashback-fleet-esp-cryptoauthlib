/*
 * GTL 24: console commands write-slot / read-slot / lock-slot / write-pubkey / sleep.
 *
 * THE WIRE (the host side is device-config-management CommandInterpreter.exec_cmd): the host writes "<command>\r"; for
 * a command that carries data it waits 100 ms, writes the raw bytes, then one NUL. The bytes are BINARY (a certificate
 * record, a public key) and may contain 0x00, so a payload is LENGTH-delimited: exactly <len> bytes, then the NUL,
 * which must be there. The host parses "Status: Success|Failure"; read-slot's "Data: <hex>" follows the Status line
 * (the host keeps what is printed after it).
 *
 * FAIL-STOP FRAMING. A payload is accepted only as a COMPLETE frame: exactly <len> bytes, then the NUL, then a quiet
 * line (the host sends nothing more until the response). Anything else -- a short or late payload, a missing or wrong
 * terminator, more bytes after the terminator (an oversized payload whose byte at <len> happens to be 0x00), or a
 * command whose arguments cannot be trusted to give the length -- is a broken frame, and the stub HALTS: "Status:
 * Failure" and the prompt (the host's exec_cmd returns only at ">>"), then it runs nothing ever again -- every further
 * line is answered "Status: Failure" and the prompt, and its bytes are discarded -- until the stub is reloaded (the
 * flow does that on every run, and resumes). Finite silence cannot prove a late byte will not arrive, so the only safe
 * recovery boundary is a fresh stub. The real host always frames correctly, so this only ever fires on a transport
 * fault -- before an irreversible operation, which is exactly when stopping is right. Every read is bounded, so a host
 * that never sends the payload gets the Failure, not a stub that hangs.
 *
 * PAYLOAD CRC32 (Trello I9y7WaYU, step 1 of 3). write-slot and write-pubkey take an OPTIONAL last argument: the CRC32 of
 * the payload, in decimal, exactly as write-config / program-dev-cert take theirs (zlib's crc32() on the host,
 * esp_rom_crc32_le(0, ...) here). It binds the declared <len> to the bytes the host sent: a payload that is longer than
 * declared fails the check even when its byte at <len> is 0x00 and the rest arrives after the quiet line -- the one
 * case the framing alone cannot see (codex R2.1 on #12). A mismatch is a broken frame: the stub halts, before any chip
 * call. Step 2: the host always sends it. Step 3: the stub requires it.
 */
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <freertos/FreeRTOS.h>

#include "esp_console.h"
#include "esp_err.h"
#include "esp_log.h"
#include "esp_rom_crc.h"

#include "ecu_console_interface.h"
#include "gtl24.h"

static const char *TAG = "secure_element";

#define GTL24_MAX_WRITE      416   /* the largest data slot (slot 8) */
#define GTL24_FIRST_BYTE_MS  5000  /* the host sends the payload ~100 ms after the command line */
#define GTL24_NEXT_BYTE_MS   1000
#define GTL24_SETTLE_MS      100   /* after the NUL the line must stay quiet this long: nothing follows a whole frame */

static esp_err_t finish(esp_err_t ret);

/* The prompt, exactly as the console loop (app_main.c scli_loop) writes it: the host's exec_cmd returns at ">>". */
static void prompt(void)
{
    fflush(stdout);
    (void)get_console_interface()->write_bytes("\n>>\n", 4, portMAX_DELAY);
}

/* FAIL-STOP. Never returns on the target: the console loop never runs again, so no byte that arrives from here on --
 * the rest of a broken payload, however late -- can be dispatched as a command. Each line is answered as a refusal so
 * the host does not wait forever. (Host tests: returns when the test's byte stream is exhausted.) */
static void gtl24_halt(void)
{
    ecu_console_interface_t *console = get_console_interface();
    uint8_t b;
    for (;;) {
        prompt();
        for (;;) {
            const int n = console->read_bytes(&b, 1, portMAX_DELAY);
            if (n > 0 && b == '\r') {
                break;
            }
#ifdef GTL24_HOST_TEST
            if (n <= 0) {
                return;
            }
#endif
        }
        finish(ESP_FAIL);
        printf("HALTED after a framing error: nothing runs until the stub is reloaded (re-run the flow)\n");
    }
}

/* Report the broken frame and halt. The reason follows the Status line: the host shows that text in its error. */
static esp_err_t fail_stop(const char *what)
{
    finish(ESP_FAIL);
    printf("FRAMING ERROR (%s): the stub HALTS so that no stray byte can run as a command; re-run the flow (it reloads "
           "the stub)\n", what);
    gtl24_halt();
    return ESP_FAIL;
}

/* Consume one COMPLETE frame: exactly len bytes (into buf, or discarded when buf is NULL), the NUL terminator, then a
 * quiet line. False on anything else. */
static bool consume_frame(unsigned char *buf, size_t len)
{
    ecu_console_interface_t *console = get_console_interface();
    uint8_t b;
    for (size_t i = 0; i < len; i++) {
        const int wait_ms = (i == 0) ? GTL24_FIRST_BYTE_MS : GTL24_NEXT_BYTE_MS;
        if (console->read_bytes(&b, 1, pdMS_TO_TICKS(wait_ms)) <= 0) {
            ESP_LOGE(TAG, "payload: got %u of %u bytes", (unsigned)i, (unsigned)len);
            return false;
        }
        if (buf != NULL) {
            buf[i] = b;
        }
    }
    if (console->read_bytes(&b, 1, pdMS_TO_TICKS(GTL24_NEXT_BYTE_MS)) <= 0) {
        ESP_LOGE(TAG, "payload: no NUL terminator after %u bytes", (unsigned)len);
        return false;
    }
    if (b != 0) {
        ESP_LOGE(TAG, "payload: byte after %u bytes is 0x%02x, not the NUL terminator (length mismatch)", (unsigned)len,
                 b);
        return false;
    }
    if (console->read_bytes(&b, 1, pdMS_TO_TICKS(GTL24_SETTLE_MS)) > 0) {
        ESP_LOGE(TAG, "payload: more input after the %u-byte frame and its NUL (length mismatch)", (unsigned)len);
        return false;
    }
    return true;
}

/* Whole-token decimal parse with bounds: "10junk", "", overflow or out-of-range -> false. atoi() would turn
 * "lock-slot 10junk" into an irreversible lock of slot 10. */
static bool parse_int(const char *tok, long lo, long hi, int *out)
{
    if (tok == NULL || *tok == '\0') {
        return false;
    }
    char *end = NULL;
    errno = 0;
    const long v = strtol(tok, &end, 10);
    if (errno != 0 || end == tok || *end != '\0' || v < lo || v > hi) {
        return false;
    }
    *out = (int)v;
    return true;
}

static esp_err_t finish(esp_err_t ret)
{
    ESP_LOGI(TAG, "Status: %s\n", (ret == ESP_OK) ? "Success" : "Failure");
    fflush(stdout);
    return (ret == ESP_OK) ? ESP_OK : ESP_FAIL;
}

/* The optional payload CRC32: a whole decimal token, digits only (strtoul would take "-1" as 4294967295), at most
 * 4294967295. */
static bool parse_crc32(const char *tok, uint32_t *out)
{
    if (tok == NULL || *tok == '\0') {
        return false;
    }
    for (const char *p = tok; *p != '\0'; p++) {
        if (*p < '0' || *p > '9') {
            return false;
        }
    }
    char *end = NULL;
    errno = 0;
    const unsigned long long v = strtoull(tok, &end, 10);
    if (errno != 0 || *end != '\0' || v > 0xFFFFFFFFull) {
        return false;
    }
    *out = (uint32_t)v;
    return true;
}

/* The payload against the CRC32 the host sent for it. */
static bool crc32_matches(const unsigned char *buf, size_t len, uint32_t expected)
{
    const uint32_t got = esp_rom_crc32_le(0, buf, (uint32_t)len);
    if (got != expected) {
        ESP_LOGE(TAG, "payload: CRC32 of the %u bytes is %lu, the host sent %lu (length or content mismatch)",
                 (unsigned)len, (unsigned long)got, (unsigned long)expected);
        return false;
    }
    return true;
}

static esp_err_t write_slot_cmd(int argc, char **argv)
{
    static unsigned char buf[GTL24_MAX_WRITE];
    int err_code = 0;
    int slot, offset, len;
    uint32_t crc = 0;
    const bool have_crc = (argc == 5);
    if ((argc != 4 && argc != 5) || !parse_int(argv[1], 0, 15, &slot) ||
        !parse_int(argv[2], 0, GTL24_MAX_WRITE, &offset) || !parse_int(argv[3], 1, GTL24_MAX_WRITE, &len) ||
        (have_crc && !parse_crc32(argv[4], &crc))) {
        ESP_LOGE(TAG, "Usage: write-slot <slot> <offset> <len> [<crc32>]  (then <len> raw bytes + NUL)");
        return fail_stop("write-slot arguments: the payload length cannot be trusted");
    }
    /* Not initialized or not, the frame is consumed whole and its CRC32 checked: a refusal must not leave a broken
     * frame's late remainder to the console loop either (codex R1.1 on I9y7WaYU). */
    const bool ready = ecu_cli_atecc_ready();
    if (!ready) {
        ESP_LOGE(TAG, "Please initialize device before calling this function");
    } else {
        printf("Reading %d bytes of data...\n", len);
        fflush(stdout);
    }
    if (!consume_frame(buf, (size_t)len)) {
        return fail_stop("write-slot payload");
    }
    if (have_crc && !crc32_matches(buf, (size_t)len, crc)) {
        return fail_stop("write-slot payload CRC32");
    }
    if (!ready) {
        return finish(ESP_ERR_INVALID_STATE);
    }
    return finish(atecc_write_slot(slot, offset, buf, (size_t)len, &err_code));
}

static esp_err_t read_slot_cmd(int argc, char **argv)
{
    static unsigned char buf[GTL24_MAX_WRITE];
    int err_code = 0;
    int slot, len;
    if (argc != 3 || !parse_int(argv[1], 0, 15, &slot) || !parse_int(argv[2], 1, GTL24_MAX_WRITE, &len)) {
        ESP_LOGE(TAG, "Usage: read-slot <slot> <len>");
        return finish(ESP_ERR_INVALID_ARG);
    }
    if (!ecu_cli_atecc_ready()) {
        ESP_LOGE(TAG, "Please initialize device before calling this function");
        return finish(ESP_ERR_INVALID_STATE);
    }
    const esp_err_t ret = atecc_read_slot(slot, buf, (size_t)len, &err_code);
    /* The host keeps only what is printed AFTER the Status line, up to the next prompt -- read-config's order. */
    finish(ret);
    if (ret == ESP_OK) {
        printf("\nData: ");
        for (int i = 0; i < len; i++) {
            printf("%02x", buf[i]);
        }
        printf("\n");
        fflush(stdout);
    }
    return (ret == ESP_OK) ? ESP_OK : ESP_FAIL;
}

static esp_err_t lock_slot_cmd(int argc, char **argv)
{
    int err_code = 0;
    int slot;
    if (argc != 2 || !parse_int(argv[1], 0, 15, &slot)) {
        ESP_LOGE(TAG, "Usage: lock-slot <slot>  (IRREVERSIBLE)");
        return finish(ESP_ERR_INVALID_ARG);
    }
    if (!ecu_cli_atecc_ready()) {
        ESP_LOGE(TAG, "Please initialize device before calling this function");
        return finish(ESP_ERR_INVALID_STATE);
    }
    return finish(atecc_lock_slot(slot, &err_code));
}

static esp_err_t write_pubkey_cmd(int argc, char **argv)
{
    unsigned char pub[64];
    int err_code = 0;
    int slot;
    uint32_t crc = 0;
    const bool have_crc = (argc == 3);
    if ((argc != 2 && argc != 3) || !parse_int(argv[1], 8, 15, &slot) || (have_crc && !parse_crc32(argv[2], &crc))) {
        ESP_LOGE(TAG, "Usage: write-pubkey <slot 8-15> [<crc32>]  (then 64 raw bytes X||Y + NUL)");
        return fail_stop("write-pubkey arguments");
    }
    const bool ready = ecu_cli_atecc_ready();
    if (!ready) {
        ESP_LOGE(TAG, "Please initialize device before calling this function");
    } else {
        printf("Reading 64 bytes of data...\n");
        fflush(stdout);
    }
    if (!consume_frame(pub, sizeof pub)) {
        return fail_stop("write-pubkey payload");
    }
    if (have_crc && !crc32_matches(pub, sizeof pub, crc)) {
        return fail_stop("write-pubkey payload CRC32");
    }
    if (!ready) {
        return finish(ESP_ERR_INVALID_STATE);
    }
    return finish(atecc_write_pubkey_slot(slot, pub, &err_code));
}

static esp_err_t sleep_cmd(int argc, char **argv)
{
    (void)argv;
    int err_code = 0;
    if (argc != 1) {
        ESP_LOGE(TAG, "Usage: sleep");
        return finish(ESP_ERR_INVALID_ARG);
    }
    if (!ecu_cli_atecc_ready()) {
        ESP_LOGE(TAG, "Please initialize device before calling this function");
        return finish(ESP_ERR_INVALID_STATE);
    }
    return finish(atecc_sleep(&err_code));
}

esp_err_t register_gtl24_commands(void)
{
    const esp_console_cmd_t cmds[] = {
        {.command = "write-slot",
         .help = "Write <len> raw bytes at <offset> of a data slot, optionally CRC32-checked (decimal, as write-config)\n"
                 "  Usage: write-slot <slot> <offset> <len> [<crc32>]",
         .func = &write_slot_cmd},
        {.command = "read-slot",
         .help = "Read <len> bytes from the start of a data slot (clear-readable slots, after the data lock)\n"
                 "  Usage: read-slot <slot> <len>",
         .func = &read_slot_cmd},
        {.command = "lock-slot",
         .help = "Individually lock a Lockable data slot (IRREVERSIBLE; after the data lock)\n  Usage: lock-slot <slot>",
         .func = &lock_slot_cmd},
        {.command = "write-pubkey",
         .help = "Write a P-256 public key (64 bytes X||Y) to slot 8-15 in stored format, optionally CRC32-checked\n"
                 "  Usage: write-pubkey <slot> [<crc32>]",
         .func = &write_pubkey_cmd},
        {.command = "sleep",
         .help = "Put the ATECC to sleep; the next command runs after a wake\n  Usage: sleep",
         .func = &sleep_cmd},
    };
    esp_err_t ret = ESP_OK;
    for (size_t i = 0; i < sizeof(cmds) / sizeof(cmds[0]); i++) {
        ret |= esp_console_cmd_register(&cmds[i]);
    }
    return ret;
}
