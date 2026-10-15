/*
 * GTL 24: console commands write-slot / read-slot / lock-slot / write-pubkey / sleep.
 *
 * THE WIRE (the host side is device-config-management CommandInterpreter.exec_cmd): the host writes "<command>\r"; for
 * a command that carries data it waits 100 ms, writes the raw bytes, then one NUL. The bytes are BINARY (a certificate
 * record, a public key) and may contain 0x00, so a payload is LENGTH-delimited: exactly <len> bytes, then the NUL,
 * which must be there. The host parses "Status: Success|Failure"; read-slot's "Data: <hex>" follows the Status line
 * (the host keeps what is printed after it).
 *
 * A payload is ALWAYS consumed. When a command that carries data is refused before it can read it (bad arguments, the
 * chip not initialized), the bytes the host sends anyway are drained until the line goes quiet; otherwise the console
 * loop would read them as the next command line. Every read is bounded: a host that never sends the payload gets
 * "Status: Failure", not a stub that hangs until reset.
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

#include "ecu_console_interface.h"
#include "gtl24.h"

static const char *TAG = "secure_element";

#define GTL24_MAX_WRITE      416   /* the largest data slot (slot 8) */
#define GTL24_FIRST_BYTE_MS  5000  /* the host sends the payload ~100 ms after the command line */
#define GTL24_NEXT_BYTE_MS   1000
#define GTL24_DRAIN_QUIET_MS 300   /* a drain ends after this much silence ... */
#define GTL24_DRAIN_MAX      2048  /* ... or after this many bytes, whichever comes first */

/* Discard input until the line has been quiet for GTL24_DRAIN_QUIET_MS (or GTL24_DRAIN_MAX bytes). */
static void drain_payload(void)
{
    ecu_console_interface_t *console = get_console_interface();
    uint8_t b;
    for (int n = 0; n < GTL24_DRAIN_MAX; n++) {
        if (console->read_bytes(&b, 1, pdMS_TO_TICKS(GTL24_DRAIN_QUIET_MS)) <= 0) {
            return;
        }
    }
}

/* Exactly len bytes, then the NUL terminator. Anything short, late or misframed is a failure, and whatever is left of
 * the payload is drained so it cannot become the next command. */
static esp_err_t read_payload(unsigned char *buf, size_t len)
{
    ecu_console_interface_t *console = get_console_interface();
    for (size_t i = 0; i < len; i++) {
        const int wait_ms = (i == 0) ? GTL24_FIRST_BYTE_MS : GTL24_NEXT_BYTE_MS;
        if (console->read_bytes(&buf[i], 1, pdMS_TO_TICKS(wait_ms)) <= 0) {
            ESP_LOGE(TAG, "payload: got %u of %u bytes", (unsigned)i, (unsigned)len);
            return ESP_FAIL;
        }
    }
    uint8_t term = 0xFF;
    if (console->read_bytes(&term, 1, pdMS_TO_TICKS(GTL24_NEXT_BYTE_MS)) <= 0) {
        ESP_LOGE(TAG, "payload: no NUL terminator after %u bytes", (unsigned)len);
        return ESP_FAIL;
    }
    if (term != 0) {
        ESP_LOGE(TAG, "payload: byte after %u bytes is 0x%02x, not the NUL terminator (length mismatch)", (unsigned)len,
                 term);
        drain_payload();
        return ESP_FAIL;
    }
    return ESP_OK;
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

static esp_err_t write_slot_cmd(int argc, char **argv)
{
    static unsigned char buf[GTL24_MAX_WRITE];
    int err_code = 0;
    int slot, offset, len;
    if (argc != 4 || !parse_int(argv[1], 0, 15, &slot) || !parse_int(argv[2], 0, GTL24_MAX_WRITE, &offset) ||
        !parse_int(argv[3], 1, GTL24_MAX_WRITE, &len)) {
        ESP_LOGE(TAG, "Usage: write-slot <slot> <offset> <len>  (then <len> raw bytes + NUL)");
        drain_payload();
        return finish(ESP_ERR_INVALID_ARG);
    }
    if (!ecu_cli_atecc_ready()) {
        ESP_LOGE(TAG, "Please initialize device before calling this function");
        drain_payload();
        return finish(ESP_ERR_INVALID_STATE);
    }
    printf("Reading %d bytes of data...\n", len);
    fflush(stdout);
    if (read_payload(buf, (size_t)len) != ESP_OK) {
        return finish(ESP_FAIL);
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
    if (argc != 2 || !parse_int(argv[1], 8, 15, &slot)) {
        ESP_LOGE(TAG, "Usage: write-pubkey <slot 8-15>  (then 64 raw bytes X||Y + NUL)");
        drain_payload();
        return finish(ESP_ERR_INVALID_ARG);
    }
    if (!ecu_cli_atecc_ready()) {
        ESP_LOGE(TAG, "Please initialize device before calling this function");
        drain_payload();
        return finish(ESP_ERR_INVALID_STATE);
    }
    printf("Reading 64 bytes of data...\n");
    fflush(stdout);
    if (read_payload(pub, sizeof pub) != ESP_OK) {
        return finish(ESP_FAIL);
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
         .help = "Write <len> raw bytes at <offset> of a data slot\n  Usage: write-slot <slot> <offset> <len>",
         .func = &write_slot_cmd},
        {.command = "read-slot",
         .help = "Read <len> bytes from the start of a data slot (clear-readable slots, after the data lock)\n"
                 "  Usage: read-slot <slot> <len>",
         .func = &read_slot_cmd},
        {.command = "lock-slot",
         .help = "Individually lock a Lockable data slot (IRREVERSIBLE; after the data lock)\n  Usage: lock-slot <slot>",
         .func = &lock_slot_cmd},
        {.command = "write-pubkey",
         .help = "Write a P-256 public key (64 bytes X||Y) to slot 8-15 in stored format\n  Usage: write-pubkey <slot>",
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
