/*
 * GTL 24: the ATECC operations behind write-slot / read-slot / lock-slot / write-pubkey / sleep.
 *
 * The bench flow (device-config-management provisioning/replacement.py) writes the on-chip certificate record across
 * slots 10-12 (72 B each) after the data lock, reads it back, locks each record slot individually, writes the trust
 * anchors into 13-15 before the data lock, and puts the chip to sleep before the config lock. The existing write-data
 * only writes 32 B at block 0.
 *
 * Every function refuses what calib would silently round or truncate, and returns ESP_OK only on ATCA_SUCCESS: a failed
 * operation must never read as success on the console (write-enc-data's rule).
 */
#include <stddef.h>

#include "esp_err.h"
#include "esp_log.h"
#include "cryptoauthlib.h"

#include "gtl24.h"

static const char *TAG = "secure_element";

/* ATECC608 data slot sizes: 0-7 36 B, 8 416 B, 9-15 72 B. */
static int slot_size(int slot)
{
    if (slot < 8) {
        return 36;
    }
    if (slot == 8) {
        return 416;
    }
    return 72;
}

esp_err_t atecc_write_slot(int slot, int offset, unsigned char *data_buf, size_t data_len, int *err_ret)
{
    int ret = ATCA_BAD_PARAM;
    if (!atecc_is_initialized()) {
        ESP_LOGE(TAG, "Device is not initialized");
        goto exit;
    }
    if (data_buf == NULL || slot < 0 || slot > 15 || offset < 0 || data_len == 0) {
        goto exit;
    }
    /* calib_write_bytes_zone works in 4-byte words; refuse anything it would round, and anything past the slot. */
    if ((offset % 4) != 0 || (data_len % 4) != 0 || (size_t)offset + data_len > (size_t)slot_size(slot)) {
        ESP_LOGE(TAG, "write-slot %d: offset %d len %u must be word-aligned and inside the %d-byte slot", slot, offset,
                 (unsigned)data_len, slot_size(slot));
        goto exit;
    }
    ret = atcab_write_bytes_zone(ATCA_ZONE_DATA, (uint16_t)slot, (size_t)offset, data_buf, data_len);
    if (ret != ATCA_SUCCESS) {
        ESP_LOGE(TAG, "write-slot %d failed, returned %02x", slot, ret);
        goto exit;
    }
    *err_ret = ret;
    return ESP_OK;
exit:
    *err_ret = ret;
    return ESP_FAIL;
}

esp_err_t atecc_read_slot(int slot, unsigned char *data_buf, size_t data_len, int *err_ret)
{
    int ret = ATCA_BAD_PARAM;
    if (!atecc_is_initialized()) {
        ESP_LOGE(TAG, "Device is not initialized");
        goto exit;
    }
    if (data_buf == NULL || slot < 0 || slot > 15 || data_len == 0 || (data_len % 4) != 0 ||
        data_len > (size_t)slot_size(slot)) {
        goto exit;
    }
    ret = atcab_read_bytes_zone(ATCA_ZONE_DATA, (uint16_t)slot, 0, data_buf, data_len);
    if (ret != ATCA_SUCCESS) {
        ESP_LOGE(TAG, "read-slot %d failed, returned %02x", slot, ret);
        goto exit;
    }
    *err_ret = ret;
    return ESP_OK;
exit:
    *err_ret = ret;
    return ESP_FAIL;
}

esp_err_t atecc_lock_slot(int slot, int *err_ret)
{
    int ret = ATCA_BAD_PARAM;
    if (!atecc_is_initialized()) {
        ESP_LOGE(TAG, "Device is not initialized");
        goto exit;
    }
    if (slot < 0 || slot > 15) {
        goto exit;
    }
    ret = atcab_lock_data_slot((uint16_t)slot);
    if (ret != ATCA_SUCCESS) {
        ESP_LOGE(TAG, "lock-slot %d failed, returned %02x", slot, ret);
        goto exit;
    }
    *err_ret = ret;
    return ESP_OK;
exit:
    *err_ret = ret;
    return ESP_FAIL;
}

esp_err_t atecc_write_pubkey_slot(int slot, const unsigned char *pubkey64, int *err_ret)
{
    int ret = ATCA_BAD_PARAM;
    if (!atecc_is_initialized()) {
        ESP_LOGE(TAG, "Device is not initialized");
        goto exit;
    }
    if (pubkey64 == NULL || slot < 8 || slot > 15) {
        goto exit;
    }
    /* atcab_write_pubkey writes the 72-byte stored format (pad, X, pad, Y) as three whole 32-byte blocks, which a
     * secret public-key slot needs: 4-byte writes are refused there (template v2 slots 13-15 are IsSecret). */
    ret = atcab_write_pubkey((uint16_t)slot, pubkey64);
    if (ret != ATCA_SUCCESS) {
        ESP_LOGE(TAG, "write-pubkey %d failed, returned %02x", slot, ret);
        goto exit;
    }
    *err_ret = ret;
    return ESP_OK;
exit:
    *err_ret = ret;
    return ESP_FAIL;
}

esp_err_t atecc_sleep(int *err_ret)
{
    int ret = ATCA_BAD_PARAM;
    if (!atecc_is_initialized()) {
        ESP_LOGE(TAG, "Device is not initialized");
        *err_ret = ret;
        return ESP_FAIL;
    }
    /* WAKE FIRST (IkV6BHhH 11b, 2026-10-23). After the previous command the chip is already idle/asleep and does not
     * acknowledge on the bus, so a bare sleep word is NACKed ("HAL_I2C: Send: Device not responding at address 0x60")
     * and `sleep` reported Failure on a healthy chip -- which made device-config-management's sleep/wake read-back
     * gate refuse every template-v2 lock. Wake it, then put it to sleep from a known-awake state: the next command
     * then genuinely runs after a fresh wake, under the stored ChipMode, which is what that gate exists to check. */
    ret = atcab_wakeup();
    if (ret != ATCA_SUCCESS) {
        ESP_LOGE(TAG, "sleep: wake failed (0x%02x) -- the chip was NOT put to sleep", ret);
        *err_ret = ret;
        return ESP_FAIL;
    }
    ret = atcab_sleep();
    *err_ret = ret;
    return (ret == ATCA_SUCCESS) ? ESP_OK : ESP_FAIL;
}
