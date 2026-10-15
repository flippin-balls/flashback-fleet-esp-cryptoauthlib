/* The virtual ATECC608 (see virtual_atecc.h), the console byte stream, the output capture and the esp_console registry. */
#include "virtual_atecc.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "cryptoauthlib.h"
#include "ecu_console_interface.h"
#include "esp_console.h"
#include "gtl24.h"

vatecc_t VA;
bool VA_ATCAB_INIT = true;
bool VA_CLI_READY = true;

/* ---- chip --------------------------------------------------------------------------------------------------------- */

int va_slot_size(int slot) { return slot < 8 ? 36 : (slot == 8 ? 416 : 72); }

void va_reset(const uint8_t config[128])
{
    memset(&VA, 0, sizeof VA);
    memcpy(VA.config, config, 128);
    VA.config[86] = 0x55;   /* LockValue: data unlocked */
    VA.config[87] = 0x55;   /* LockConfig: config unlocked */
    VA.config[88] = 0xFF;   /* SlotLocked: every slot unlocked */
    VA.config[89] = 0xFF;
}

static bool cfg_locked(void) { return VA.config[87] != 0x55; }
static bool data_locked(void) { return VA.config[86] != 0x55; }
void va_lock_config(void) { VA.config[87] = 0x00; }
void va_lock_data(void) { VA.config[86] = 0x00; }
static unsigned sc(int s) { return VA.config[20 + 2 * s] | (VA.config[21 + 2 * s] << 8); }
static unsigned kc(int s) { return VA.config[96 + 2 * s] | (VA.config[97 + 2 * s] << 8); }
bool va_slot_locked(int s) { return !(((VA.config[88] | (VA.config[89] << 8)) >> s) & 1u); }
static bool is_secret(int s) { return (sc(s) >> 7) & 1u; }
static bool is_private(int s) { return kc(s) & 1u; }
static unsigned write_config(int s) { return (sc(s) >> 12) & 0xFu; }

static void wake(void)
{
    if (VA.asleep) { VA.asleep = false; VA.wakes++; }
}

/* One Write command: a whole block (n == 32, at a block boundary) or a word (n == 4). */
static ATCA_STATUS chip_write(int slot, size_t off, const uint8_t *d, size_t n)
{
    wake();
    const bool block = (n == 32);
    if (!cfg_locked() || is_private(slot) || va_slot_locked(slot) || (!block && is_secret(slot))) { VA.refused++; return ATCA_EXECUTION_ERROR; }
    if (data_locked()) {
        const unsigned wc = write_config(slot);
        if (!(wc == 0x0 || (wc == 0x1 && block))) { VA.refused++; return ATCA_EXECUTION_ERROR; }
    }
    const size_t size = (size_t)va_slot_size(slot);
    if (off >= size) { VA.refused++; return ATCA_EXECUTION_ERROR; }
    const size_t keep = (off + n > size) ? size - off : n;   /* a block write to a slot's last, partial block */
    memcpy(&VA.data[slot][off], d, keep);
    if (block) VA.block_writes++; else VA.word_writes++;
    return ATCA_SUCCESS;
}

static ATCA_STATUS chip_read(int slot, size_t off, uint8_t *d, size_t n)
{
    wake();
    if (!data_locked() || is_secret(slot)) { VA.refused++; return ATCA_EXECUTION_ERROR; }
    memcpy(d, &VA.data[slot][off], n);
    return ATCA_SUCCESS;
}

/* ---- the CryptoAuthLib calls (calib's checks and block/word walk) ------------------------------------------------- */

ATCA_STATUS atcab_write_bytes_zone(uint8_t zone, uint16_t slot, size_t offset, const uint8_t *data, size_t length)
{
    VA.atcab_calls++;
    if (zone != ATCA_ZONE_DATA || slot > 15u) return ATCA_BAD_PARAM;
    if (length == 0u) return ATCA_SUCCESS;
    if (data == NULL || offset % 4u != 0u || length % 4u != 0u) return ATCA_BAD_PARAM;
    if (offset + length > (size_t)va_slot_size(slot)) return ATCA_BAD_PARAM;
    size_t i = 0;
    while (i < length) {
        const size_t at = offset + i;
        const size_t n = (at % 32u == 0u && length - i >= 32u) ? 32u : 4u;
        const ATCA_STATUS st = chip_write(slot, at, &data[i], n);
        if (st != ATCA_SUCCESS) return st;
        i += n;
    }
    return ATCA_SUCCESS;
}

ATCA_STATUS atcab_read_bytes_zone(uint8_t zone, uint16_t slot, size_t offset, uint8_t *data, size_t length)
{
    VA.atcab_calls++;
    if (zone != ATCA_ZONE_DATA || slot > 15u || data == NULL) return ATCA_BAD_PARAM;
    if (length == 0u) return ATCA_SUCCESS;
    if (offset + length > (size_t)va_slot_size(slot)) return ATCA_BAD_PARAM;
    size_t i = 0;
    while (i < length) {
        const size_t at = offset + i;
        const size_t n = (at % 32u == 0u && length - i >= 32u) ? 32u : 4u;
        const size_t take = (n > length - i) ? length - i : n;
        const ATCA_STATUS st = chip_read(slot, at, &data[i], take);
        if (st != ATCA_SUCCESS) return st;
        i += take;
    }
    return ATCA_SUCCESS;
}

ATCA_STATUS atcab_lock_data_slot(uint16_t slot)
{
    VA.atcab_calls++;
    wake();
    if (slot > 15u) return ATCA_BAD_PARAM;
    if (!data_locked() || !((kc(slot) >> 5) & 1u) || va_slot_locked(slot)) { VA.refused++; return ATCA_EXECUTION_ERROR; }
    unsigned bits = (VA.config[88] | (VA.config[89] << 8)) & ~(1u << slot);
    VA.config[88] = (uint8_t)(bits & 0xFFu);
    VA.config[89] = (uint8_t)(bits >> 8);
    return ATCA_SUCCESS;
}

ATCA_STATUS atcab_write_pubkey(uint16_t slot, const uint8_t *public_key)
{
    VA.atcab_calls++;
    if (public_key == NULL) return ATCA_BAD_PARAM;
    uint8_t f[96];
    memset(f, 0, sizeof f);
    memcpy(&f[4], &public_key[0], 32);
    memcpy(&f[40], &public_key[32], 32);
    for (int b = 0; b < 3; b++) {
        const ATCA_STATUS st = chip_write(slot, (size_t)b * 32u, &f[b * 32], 32);
        if (st != ATCA_SUCCESS) return st;
    }
    return ATCA_SUCCESS;
}

ATCA_STATUS atcab_sleep(void)
{
    VA.atcab_calls++;
    if (VA.fail_sleep) { VA.fail_sleep = false; return ATCA_EXECUTION_ERROR; }
    VA.asleep = true;
    VA.sleeps++;
    return ATCA_SUCCESS;
}

/* ---- readiness (owned by handlers.c / commands.c on the target) --------------------------------------------------- */

bool atecc_is_initialized(void) { return VA_ATCAB_INIT; }
bool ecu_cli_atecc_ready(void) { return VA_CLI_READY; }

/* ---- the console byte stream ------------------------------------------------------------------------------------- */

static uint8_t s_in[8192];
static size_t s_in_head, s_in_tail;

void va_feed(const uint8_t *b, size_t n)
{
    for (size_t i = 0; i < n && s_in_tail < sizeof s_in; i++) s_in[s_in_tail++] = b[i];
}
size_t va_pending(void) { return s_in_tail - s_in_head; }
void va_clear_input(void) { s_in_head = s_in_tail = 0; }

static int vc_read(uint8_t *buf, size_t length, TickType_t ticks)
{
    (void)ticks;   /* an empty stream is a timeout, whatever the wait */
    size_t n = 0;
    while (n < length && s_in_head < s_in_tail) buf[n++] = s_in[s_in_head++];
    return (int)n;
}
static int vc_write(const char *buf, size_t length, TickType_t ticks) { (void)buf; (void)ticks; return (int)length; }
static esp_err_t vc_done(TickType_t ticks) { (void)ticks; return ESP_OK; }
static ecu_console_interface_t s_console = {.read_bytes = vc_read, .write_bytes = vc_write, .wait_tx_done = vc_done};
ecu_console_interface_t *get_console_interface(void) { return &s_console; }

/* ---- output capture ---------------------------------------------------------------------------------------------- */

static char s_out[16384];
static size_t s_out_n;

int vt_printf(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    const int w = vsnprintf(s_out + s_out_n, sizeof s_out - s_out_n, fmt, ap);
    va_end(ap);
    if (w > 0) s_out_n += ((size_t)w < sizeof s_out - s_out_n) ? (size_t)w : sizeof s_out - s_out_n - 1;
    return w;
}
int vt_fflush(FILE *f) { (void)f; return 0; }
void vt_capture_reset(void) { s_out_n = 0; s_out[0] = '\0'; }
const char *vt_captured(void) { return s_out; }

/* ---- esp_console registry ----------------------------------------------------------------------------------------- */

esp_console_cmd_t vt_cmds[16];
int vt_ncmds;
esp_err_t esp_console_cmd_register(const esp_console_cmd_t *cmd)
{
    if (vt_ncmds >= 16) return ESP_FAIL;
    vt_cmds[vt_ncmds++] = *cmd;
    return ESP_OK;
}
