/*
 * Copyright 2021 Espressif Systems (Shanghai) CO LTD
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifdef CONFIG_ECU_DEBUGGING
#define ECU_DEBUG_LOG ESP_LOGI
#else
#define ECU_DEBUG_LOG(...)
#endif /* MFG_DEBUG */

#include <string.h>
#include "stdio.h"
#include "mbedtls/base64.h"

#include "esp_log.h"
#include "esp_err.h"
#include "esp_rom_crc.h"
#include "esp_partition.h"
#include "esp_flash_partitions.h"
#include "spi_flash_mmap.h"

#include "handlers.h"

/* Cryptoauthlib includes */
#include "cryptoauthlib.h"
#include "cert_def_3_device_csr.h"
#include "cert_def_2_device.h"
#include "cert_def_1_signer.h"
#include "atcacert/atcacert_client.h"
#include "atcacert/atcacert_pem.h"
#include "tng_atcacert_client.h"

#include "mbedtls/atca_mbedtls_wrap.h"
#include "ecu_console_interface.h"

static const char *TAG = "secure_element";
static bool is_atcab_init = false;

static atcacert_def_t g_cert_def_common;
uint8_t *g_cert_template_device;

static const uint8_t public_key_x509_header[] = {
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A,
    0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04
};


int convert_pem_to_der( const unsigned char *input, size_t ilen,
                        unsigned char *output, size_t *olen )
{
    int ret;
    const unsigned char *s1, *s2, *end = input + ilen;
    size_t len = 0;

    s1 = (unsigned char *) strstr( (const char *) input, "-----BEGIN" );
    if ( s1 == NULL ) {
        return ( -1 );
    }

    s2 = (unsigned char *) strstr( (const char *) input, "-----END" );
    if ( s2 == NULL ) {
        return ( -1 );
    }

    s1 += 10;
    while ( s1 < end && *s1 != '-' ) {
        s1++;
    }
    while ( s1 < end && *s1 == '-' ) {
        s1++;
    }
    if ( *s1 == '\r' ) {
        s1++;
    }
    if ( *s1 == '\n' ) {
        s1++;
    }

    if ( s2 <= s1 || s2 > end ) {
        return ( -1 );
    }
    ret = mbedtls_base64_decode( NULL, 0, &len, (const unsigned char *) s1, s2 - s1 );
    if ( ret == MBEDTLS_ERR_BASE64_INVALID_CHARACTER ) {
        return ( ret );
    }

    if ( len > *olen ) {
        return ( -1 );
    }
    if ( ( ret = mbedtls_base64_decode( output, len, &len, (const unsigned char *) s1,
                                        s2 - s1 ) ) != 0 ) {
        return ( ret );
    }

    *olen = len;

    return ( 0 );
}

extern void hal_esp32_i2c_set_pin_config(uint8_t i2c_sda_pin, uint8_t i2c_scl_pin);

esp_err_t init_atecc608_device(char *device_type)
{
    int ret = 0;

    // Temporarily suppress I2C errors during chip type detection
    esp_log_level_t original_level = esp_log_level_get("i2c.master");
    esp_log_level_set("i2c.master", ESP_LOG_NONE);

    // Addresses are the 7-BIT form: this fork's HAL stores atcai2c.address as
    // 7-bit and derives the bus byte itself (legacy driver shifts LEFT at send;
    // the i2c_master driver uses it raw — see commit 0266483). The old 8-bit
    // values (0xC0/0x6A/0x6C) shifted out of range and made EVERY ATECC op fail
    // with ATCA_COMM_FAIL (-16) on both drivers — this is why utility builds
    // from this branch could not talk to RAK hardware while device firmware
    // (which passes CONFIG_ATCA_I2C_ADDRESS=0x60) worked fine.

    // Try TrustCustom (7-bit 0x60, bus byte 0xC0) - most common for blank chips
    cfg_ateccx08a_i2c_default.atcai2c.address = 0x60;
    ret = atcab_init(&cfg_ateccx08a_i2c_default);
    if (ret == ATCA_SUCCESS) {
        esp_log_level_set("i2c.master", original_level);
        ESP_LOGI(TAG, "Device is of type TrustCustom");
        sprintf(device_type, "%s", "TrustCustom");
        return ESP_OK;
    }

    // Try Trust&Go (7-bit 0x35, bus byte 0x6A)
    cfg_ateccx08a_i2c_default.atcai2c.address = 0x35;
    ret = atcab_init(&cfg_ateccx08a_i2c_default);
    if (ret == ATCA_SUCCESS) {
        esp_log_level_set("i2c.master", original_level);
        ESP_LOGI(TAG, "Device is of type Trust&Go");
        sprintf(device_type, "%s", "Trust&Go");
        return ESP_OK;
    }

    // Try TrustFlex (7-bit 0x36, bus byte 0x6C)
    cfg_ateccx08a_i2c_default.atcai2c.address = 0x36;
    ret = atcab_init(&cfg_ateccx08a_i2c_default);
    if (ret == ATCA_SUCCESS) {
        esp_log_level_set("i2c.master", original_level);
        ESP_LOGI(TAG, "Device is of type TrustFlex");
        sprintf(device_type, "%s", "TrustFlex");
        return ESP_OK;
    }

    // Restore log level even if all failed
    esp_log_level_set("i2c.master", original_level);
    return ESP_FAIL;
}

esp_err_t init_atecc608a(char *device_type, uint8_t i2c_sda_pin, uint8_t i2c_scl_pin, int *err_ret)
{
    int ret = 0;
    ECU_DEBUG_LOG(TAG, "Initialize the ATECC interface...");
    hal_esp32_i2c_set_pin_config(i2c_sda_pin,i2c_scl_pin);
    ESP_LOGI(TAG, "I2C pins selected are SDA = %d, SCL = %d", i2c_sda_pin, i2c_scl_pin);

    esp_err_t esp_ret = init_atecc608_device(device_type);
    if (esp_ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to initialize atca device");
    }

    ECU_DEBUG_LOG(TAG, "\t\t OK");

    is_atcab_init = true;
    *err_ret = ret;
    return ESP_OK;
}

esp_err_t atecc_print_info(uint8_t *serial_no, int *err_ret)
{
    uint8_t rev_info[4] = {};
    int ret = -1;
    if (ATCA_SUCCESS != (ret = atcab_info(rev_info))) {
        ESP_LOGE(TAG, "Error in reading revision information, ret is %02x", ret);
        goto exit;
    }
    ESP_LOG_BUFFER_HEX("ATECC CHIP REVISION", rev_info, 4);
    if (rev_info[3] == 0x03) {
        ESP_LOGI(TAG, "Since the last byte of chip revision is 0x03. This is an ATECC608B chip");
    } else if (rev_info[3] == 0x02) {
        ESP_LOGI(TAG, "Since the last byte of chip revision is 0x02. This is a ATECC608A chip");
    }

    if (ATCA_SUCCESS != (ret = atcab_read_serial_number(serial_no))) {
        ESP_LOGE(TAG, "Error in reading serial number, ret is %02x", ret);
        goto exit;
    }
    ESP_LOG_BUFFER_HEX("ATECC CHIP SERIAL NUMBER", serial_no, 9);
    *err_ret = ret;
    return ESP_OK;
exit:
    *err_ret = ret;
    return ESP_FAIL;
}

static void print_public_key(uint8_t pubkey[ATCA_PUB_KEY_SIZE])
{
    uint8_t buf[128];
    uint8_t *tmp;
    size_t buf_len = sizeof(buf);

    /* Calculate where the raw data will fit into the buffer */
    tmp = buf + sizeof(buf) - ATCA_PUB_KEY_SIZE - sizeof(public_key_x509_header);

    /* Copy the header */
    memcpy(tmp, public_key_x509_header, sizeof(public_key_x509_header));

    /* Copy the key bytes */
    memcpy(tmp + sizeof(public_key_x509_header), pubkey, ATCA_PUB_KEY_SIZE);

    /* Convert to base 64 */
    (void)atcab_base64encode(tmp, ATCA_PUB_KEY_SIZE + sizeof(public_key_x509_header), (char *)buf, &buf_len);

    /* Add a null terminator */
    buf[buf_len] = 0;

    /* Print out the key */
    ECU_DEBUG_LOG(TAG, "\r\n-----BEGIN PUBLIC KEY-----\r\n%s\r\n-----END PUBLIC KEY-----\r\n", buf);
}

esp_err_t atecc_keygen(int slot, unsigned char *pub_key_buf, int pub_key_buf_len, int *err_ret)
{
    int ret = 0;
    bzero(pub_key_buf, pub_key_buf_len);
    if (!is_atcab_init) {
        ESP_LOGE(TAG, "gevice is not initialized");
        goto exit;
    }
    ECU_DEBUG_LOG(TAG, "generating priv key ..");

    if (ATCA_SUCCESS != (ret = atcab_genkey(slot, pub_key_buf))) {
        ESP_LOGE(TAG, "failed\n !atcab_genkey returned -0x%02x", -ret);
        goto exit;
    }
    ECU_DEBUG_LOG(TAG, "\t\t OK");
    print_public_key(pub_key_buf);
    *err_ret = ret;
    return ESP_OK;

exit:
    ESP_LOGE(TAG, "failure in generating Key");
    *err_ret = ret;
    return ESP_FAIL;
}

esp_err_t atecc_gen_pubkey(int slot, unsigned char *pub_key_buf, int pub_key_buf_len, int *err_ret)
{
    int ret = -1;
    if (!is_atcab_init) {
        ESP_LOGE(TAG, "\ndevice is not initialized");
        goto exit;
    }
    bzero(pub_key_buf, pub_key_buf_len);
    ECU_DEBUG_LOG(TAG, "Get the public key...");
    if (0 != (ret = atcab_get_pubkey(slot, pub_key_buf))) {
        ESP_LOGE(TAG, " failed\n  ! atcab_get_pubkey returned %02x", ret);
        goto exit;
    }
    ECU_DEBUG_LOG("\t\t OK\n");
    print_public_key(pub_key_buf);
    *err_ret = ret;
    return ESP_OK;

exit:
    *err_ret = ret;
    ESP_LOGE(TAG, "\ngenerate public key failed");
    return ESP_FAIL;
}

esp_err_t atecc_csr_gen(unsigned char *csr_buf, size_t csr_buf_len, int *err_ret)
{
    int ret = 0;
    if (!is_atcab_init) {
        ESP_LOGE(TAG, "device is not initialized");
        goto exit;
    }
    bzero(csr_buf, csr_buf_len);
    ECU_DEBUG_LOG(TAG, "generating csr ..");

    // Debug: Print cert_def configuration
    ESP_LOGI(TAG, "CSR cert_def config:");
    ESP_LOGI(TAG, "  private_key_slot: %d", g_csr_def_3_device.private_key_slot);
    ESP_LOGI(TAG, "  tbs_cert_loc: offset=%d, count=%d",
             g_csr_def_3_device.tbs_cert_loc.offset,
             g_csr_def_3_device.tbs_cert_loc.count);
    ESP_LOGI(TAG, "  public_key (cert): offset=%d, count=%d",
             g_csr_def_3_device.std_cert_elements[0].offset,
             g_csr_def_3_device.std_cert_elements[0].count);
    ESP_LOGI(TAG, "  signature (cert): offset=%d, count=%d",
             g_csr_def_3_device.std_cert_elements[1].offset,
             g_csr_def_3_device.std_cert_elements[1].count);
    ESP_LOGI(TAG, "  template_size: %d", g_csr_def_3_device.cert_template_size);

    ret = atcacert_create_csr_pem(&g_csr_def_3_device, (char *)csr_buf, &csr_buf_len);
    if (ret != ATCA_SUCCESS) {
        ESP_LOGE(TAG, "create csr pem failed, returned %02x", ret);
        goto exit;
    }
    ECU_DEBUG_LOG(TAG, "\t\t OK");
    *err_ret = ret;
    return ESP_OK;

exit:
    ESP_LOGE(TAG, "Failure, Exiting , ret is %02x", ret);
    *err_ret = ret;
    return ESP_FAIL;

}

esp_err_t get_cert_def(unsigned char *cert_def_array, size_t data_len, cert_type_t cert_type)
{
    if (cert_type == CERT_TYPE_DEVICE) {
        g_cert_def_common = g_cert_def_2_device;
    } else if (cert_type == CERT_TYPE_SIGNER) {
        g_cert_def_common = g_cert_def_1_signer;
    }
    ecu_console_interface_t *console_interface = get_console_interface();
    if (console_interface == NULL) {
        ESP_LOGE(TAG, "Console interface is NULL");
        return ESP_FAIL;
    }
    int i = 0;
    memset(cert_def_array, 0xff, data_len);
    do {
        esp_err_t ret;
        ret = console_interface->read_bytes((uint8_t *) &cert_def_array[i], 1, portMAX_DELAY);
        if (ret > 0) {
            if (cert_def_array[i] == '\0') {
                break;
            }
            i++;
        }
    } while (i < data_len - 1 && cert_def_array[i] != '\0');

    char str[4] = {};
    int count = 0;
    /* converting the offsets and counts to int, 4 bytes at a time */
    for (count = 0 ; count < 8; count++) {
        memcpy(str, &cert_def_array[4 * ((2 * count) + 0)], 4);
        g_cert_def_common.std_cert_elements[count].offset = (uint16_t)atoi(str);
        memcpy(str, &cert_def_array[4 * ((2 * count) + 1)], 4);
        g_cert_def_common.std_cert_elements[count].count = (uint16_t)atoi(str);
    }

    memcpy(str, &cert_def_array[4 * ((2 * count) + 0)], 4);
    g_cert_def_common.tbs_cert_loc.offset = (uint16_t)atoi(str);

    memcpy(str, &cert_def_array[4 * ((2 * count) + 1)], 4);
    g_cert_def_common.tbs_cert_loc.count = (uint16_t)atoi(str);

    count = count + 1;
    /* converting to total number of bytes used */
    count = count * 8;
    int template_size = ((strlen((const char *)&cert_def_array[0]) - count ) / 2);
    int pos = 0;
    char temp[2];
    g_cert_template_device = (uint8_t *)calloc(template_size, sizeof(uint8_t));
    /* Converting the templates from string to hex, 2 bytes at a time */
    for (int i = 0; i < template_size; i++) {
        memcpy(temp, &cert_def_array[count], 2);
        g_cert_template_device[pos] = strtol((const char *)temp, NULL, 16);
        pos ++;
        count = count + 2;
    }
    atcacert_cert_element_t *cert_element;

    cert_element = (atcacert_cert_element_t *)calloc(2, sizeof(atcacert_cert_element_t));

    if (cert_type == CERT_TYPE_SIGNER) {
        cert_element[0].device_loc.offset = 35 - g_cert_def_common.std_cert_elements[STDCERT_ISSUE_DATE].offset;
        cert_element[0].device_loc.count = g_cert_def_common.std_cert_elements[STDCERT_ISSUE_DATE].count;
        cert_element[0].cert_loc.offset = g_cert_def_common.std_cert_elements[STDCERT_ISSUE_DATE].offset;
        cert_element[0].cert_loc.count = g_cert_def_common.std_cert_elements[STDCERT_ISSUE_DATE].count;

        cert_element[1].device_loc.offset = 50 - g_cert_def_common.std_cert_elements[STDCERT_EXPIRE_DATE].offset;
        cert_element[1].device_loc.count = g_cert_def_common.std_cert_elements[STDCERT_EXPIRE_DATE].count;
        cert_element[1].cert_loc.offset = g_cert_def_common.std_cert_elements[STDCERT_EXPIRE_DATE].offset;
        cert_element[1].cert_loc.count = g_cert_def_common.std_cert_elements[STDCERT_EXPIRE_DATE].count;

        g_cert_def_common.cert_elements = cert_element;
        g_cert_def_common.cert_elements_count = 2;
    }

    g_cert_def_common.cert_template = g_cert_template_device;
    g_cert_def_common.cert_template_size = template_size;

    return ESP_OK;
}

#define ATECC608A_DEVICE_CERT_SLOT 10
#define ATECC608A_SIGNER_CERT_SLOT 12
esp_err_t atecc_input_cert(unsigned char *cert_buf, size_t cert_len, cert_type_t cert_type, bool lock, int *err_ret, uint32_t expected_crc)
{
    int ret = -1;

    if (!is_atcab_init) {
        ESP_LOGE(TAG, "\ndevice is not initialized");
        goto exit;
    }
    int i = 0;
    ecu_console_interface_t *console_interface = get_console_interface();
    if (console_interface == NULL) {
        ESP_LOGE(TAG, "Console interface is NULL");
        return ESP_FAIL;
    }
    memset(cert_buf, 0xff, cert_len);
    do {
        esp_err_t esp_ret;
        esp_ret = console_interface->read_bytes((uint8_t *) &cert_buf[i], 1, portMAX_DELAY);
        if (esp_ret > 0) {
            if (cert_buf[i] == '\0') {
                break;
            }
            i++;
        }
    } while (i < cert_len - 1 && cert_buf[i] != '\0');

    // Compute CRC32
    uint32_t calculated_crc = esp_rom_crc32_le(0, cert_buf, i);
    if (calculated_crc != expected_crc) {
        ESP_LOGE(TAG, "CRC32 mismatch! Expected: %ld, Received: %ld", expected_crc, calculated_crc);
        return ESP_ERR_INVALID_CRC;
    }

    uint8_t der_cert[800];
    size_t der_cert_size = 800;
    if (convert_pem_to_der(cert_buf, cert_len, (unsigned char *)der_cert, &der_cert_size) != 0) {
        ESP_LOGE(TAG, "error in converting to der");
        return ESP_FAIL;
    }

    der_cert[der_cert_size] = 0;
    der_cert_size += 1;

    if (cert_type == CERT_TYPE_DEVICE) {
        ECU_DEBUG_LOG(TAG, "writing device cert ..");
        if (ATCA_SUCCESS != (ret = atcacert_write_cert((const atcacert_def_t *)&g_cert_def_common, der_cert, der_cert_size + 1))) {
            ESP_LOGE(TAG, "writecert failed , ret is %02x\nPlease make sure that the device cert slot is not locked", ret);
            goto exit;
        }
        if (lock) {
            ret = atcab_lock_data_slot(ATECC608A_DEVICE_CERT_SLOT);
            if (ret != ATCA_SUCCESS) {
                ESP_LOGE(TAG, "Failed to lock slot 10 (device certificate)\nThis action is supposed to fail if the slot is already locked");
                goto exit;
            }
            ESP_LOGI(TAG, "Slot %d has been locked, and cannot be used again", ATECC608A_DEVICE_CERT_SLOT);
        }

    } else if (cert_type == CERT_TYPE_SIGNER) {
        ECU_DEBUG_LOG(TAG, "writing signer cert ..");
        if (ATCA_SUCCESS != (ret = atcacert_write_cert(&g_cert_def_common, der_cert, der_cert_size + 1))) {
            ESP_LOGE(TAG, "writecert failed , ret is %02x\nPlease make sure that the signer cert slot is not locked", ret);
            goto exit;
        }
        if (lock) {
            ret = atcab_lock_data_slot(ATECC608A_SIGNER_CERT_SLOT);
            if (ret != ATCA_SUCCESS) {
                ESP_LOGE(TAG, "Failed to lock slot 12 (signer certificate),\nThis action is supposed to fail if the slot is already locked");
                goto exit;
            }
            ESP_LOGI(TAG, "Slot %d has been locked, and cannot be used again", ATECC608A_DEVICE_CERT_SLOT);
        }
    } else {
        ESP_LOGE(TAG, "wrong cert type");
        goto exit;
    }
    ECU_DEBUG_LOG(TAG, "\t\t OK");
    *err_ret = ret;
    return ESP_OK;
exit:
    ESP_LOGE(TAG, "failure, exiting");
    *err_ret = ret;
    return ESP_FAIL;
}

#define ATECC_CONFIG_SIZE 128
esp_err_t atecc_write_config(unsigned char *config_buf, size_t config_len, int *err_ret, uint32_t expected_crc)
{
    int ret = -1;
    bool is_locked = false;

    if (!is_atcab_init) {
        ESP_LOGE(TAG, "Device is not initialized");
        goto exit;
    }

    // Check if config zone is already locked
    if (ATCA_SUCCESS != (ret = atcab_is_locked(LOCK_ZONE_CONFIG, &is_locked))) {
        ESP_LOGE(TAG, "Failed to check config lock status, returned %02x", ret);
        goto exit;
    }

    if (is_locked) {
        ESP_LOGE(TAG, "Config zone is already locked, cannot write config");
        ret = ATCA_FUNC_FAIL;
        goto exit;
    }

    // Read config data from UART
    ecu_console_interface_t *console_interface = get_console_interface();
    if (console_interface == NULL) {
        ESP_LOGE(TAG, "Console interface is NULL");
        return ESP_FAIL;
    }

    memset(config_buf, 0xff, config_len);

    // Read exactly ATECC_CONFIG_SIZE bytes of binary data
    // NOTE: We cannot use null-termination here because binary config data
    // may contain 0x00 bytes (e.g., at offset 2-5 in typical configs)
    int i = 0;
    while (i < ATECC_CONFIG_SIZE) {
        esp_err_t esp_ret;
        esp_ret = console_interface->read_bytes((uint8_t *)&config_buf[i], 1, portMAX_DELAY);
        if (esp_ret > 0) {
            i++;
        } else if (esp_ret < 0) {
            ESP_LOGE(TAG, "Error reading config data at byte %d", i);
            ret = ATCA_COMM_FAIL;
            goto exit;
        }
        // If esp_ret == 0, just retry (timeout without data)
    }

    // After reading 128 bytes, consume the null terminator
    uint8_t null_term;
    esp_err_t esp_ret = console_interface->read_bytes(&null_term, 1, pdMS_TO_TICKS(100));
    if (esp_ret > 0 && null_term != '\0') {
        ESP_LOGW(TAG, "Expected null terminator after config data, got 0x%02x", null_term);
    }

    ESP_LOGI(TAG, "Read %d bytes of config data", i);
    if (i != ATECC_CONFIG_SIZE) {
        ESP_LOGE(TAG, "Invalid config size: %d bytes (expected %d)", i, ATECC_CONFIG_SIZE);
        ret = ATCA_BAD_PARAM;
        goto exit;
    }

    // Verify CRC32
    uint32_t calculated_crc = esp_rom_crc32_le(0, config_buf, ATECC_CONFIG_SIZE);
    if (calculated_crc != expected_crc) {
        ESP_LOGE(TAG, "CRC32 mismatch! Expected: %lu, Calculated: %lu", expected_crc, calculated_crc);
        ret = ATCA_CHECKMAC_VERIFY_FAILED;
        goto exit;
    }

    ESP_LOGI(TAG, "Writing config to ATECC608...");

    // ATECC608 Config Zone Layout (128 bytes total):
    // Bytes 0-15:   Read-only (serial number, revision) - CANNOT be written
    // Bytes 16-127: Writable config data (112 bytes)
    // Byte 84:      NOT writable (reserved for chip modes)
    //
    // Following Arduino ECCX08 library pattern:
    // https://github.com/arduino-libraries/ArduinoECCX08/blob/master/src/ECCX08.cpp#L400
    //
    // Write in 4-byte chunks, skipping bytes 0-15 (read-only) and byte 84 (reserved)

    for (int i = 16; i < 128; i += 4) {
        // Skip byte 84 - it's not writable (reserved/chip modes)
        if (i == 84) {
            ESP_LOGI(TAG, "Skipping bytes 84-87 (not writable)");
            continue;
        }

        // Write 4 bytes at a time using atcab_write_bytes_zone
        // Zone: ATCA_ZONE_CONFIG (0)
        // Slot: 0 (config zone doesn't use slot concept, but pass 0)
        // Offset: byte address
        // Data: 4 bytes from config_buf
        ret = atcab_write_bytes_zone(ATCA_ZONE_CONFIG, 0, i, &config_buf[i], 4);
        if (ret != ATCA_SUCCESS) {
            ESP_LOGE(TAG, "Failed to write config bytes %d-%d, returned %02x", i, i+3, ret);
            goto exit;
        }

        ECU_DEBUG_LOG(TAG, "Config bytes %d-%d written successfully", i, i+3);
    }

    ESP_LOGI(TAG, "Config zone written successfully");
    *err_ret = ret;
    return ESP_OK;

    exit:
    *err_ret = ret;
    return ESP_FAIL;
}

esp_err_t atecc_is_config_locked(bool *is_locked, int *err_ret)
{
    int ret = -1;

    if (!is_atcab_init) {
        ESP_LOGE(TAG, "Device is not initialized");
        goto exit;
    }

    if (is_locked == NULL) {
        ESP_LOGE(TAG, "is_locked pointer is NULL");
        goto exit;
    }

    ret = atcab_is_locked(LOCK_ZONE_CONFIG, is_locked);
    if (ret != ATCA_SUCCESS) {
        ESP_LOGE(TAG, "Failed to check config lock status, returned %02x", ret);
        goto exit;
    }

    ECU_DEBUG_LOG(TAG, "Config zone lock status: %s", *is_locked ? "LOCKED" : "UNLOCKED");
    *err_ret = ret;
    return ESP_OK;

exit:
    *err_ret = ret;
    return ESP_FAIL;
}

esp_err_t atecc_is_data_locked(bool *is_locked, int *err_ret)
{
    int ret = -1;

    if (!is_atcab_init) {
        ESP_LOGE(TAG, "Device is not initialized");
        goto exit;
    }

    if (is_locked == NULL) {
        ESP_LOGE(TAG, "is_locked pointer is NULL");
        goto exit;
    }

    ret = atcab_is_locked(LOCK_ZONE_DATA, is_locked);
    if (ret != ATCA_SUCCESS) {
        ESP_LOGE(TAG, "Failed to check data lock status, returned %02x", ret);
        goto exit;
    }

    ECU_DEBUG_LOG(TAG, "Data zone lock status: %s", *is_locked ? "LOCKED" : "UNLOCKED");
    *err_ret = ret;
    return ESP_OK;

exit:
    *err_ret = ret;
    return ESP_FAIL;
}

esp_err_t atecc_lock_config_zone(int *err_ret)
{
    int ret = -1;
    bool is_locked = false;

    if (!is_atcab_init) {
        ESP_LOGE(TAG, "Device is not initialized");
        goto exit;
    }

    // Check if already locked
    ret = atcab_is_locked(LOCK_ZONE_CONFIG, &is_locked);
    if (ret != ATCA_SUCCESS) {
        ESP_LOGE(TAG, "Failed to check config lock status, returned %02x", ret);
        goto exit;
    }

    if (is_locked) {
        ESP_LOGW(TAG, "Config zone is already locked");
        *err_ret = ret;
        return ESP_OK;
    }

    // Lock config zone
    ret = atcab_lock_config_zone();
    if (ret != ATCA_SUCCESS) {
        ESP_LOGE(TAG, "Failed to lock config zone, returned %02x", ret);
        goto exit;
    }

    ESP_LOGI(TAG, "Config zone locked successfully");
    *err_ret = ret;
    return ESP_OK;

exit:
    *err_ret = ret;
    return ESP_FAIL;
}

esp_err_t atecc_lock_data_zone(int *err_ret)
{
    int ret = -1;
    bool is_locked = false;

    if (!is_atcab_init) {
        ESP_LOGE(TAG, "Device is not initialized");
        goto exit;
    }

    // Check if already locked
    ret = atcab_is_locked(LOCK_ZONE_DATA, &is_locked);
    if (ret != ATCA_SUCCESS) {
        ESP_LOGE(TAG, "Failed to check data lock status, returned %02x", ret);
        goto exit;
    }

    if (is_locked) {
        ESP_LOGW(TAG, "Data zone is already locked");
        *err_ret = ret;
        return ESP_OK;
    }

    // Lock data zone
    ret = atcab_lock_data_zone();
    if (ret != ATCA_SUCCESS) {
        ESP_LOGE(TAG, "Failed to lock data zone, returned %02x", ret);
        goto exit;
    }

    ESP_LOGI(TAG, "Data zone locked successfully");
    *err_ret = ret;
    return ESP_OK;

exit:
    *err_ret = ret;
    return ESP_FAIL;
}

esp_err_t atecc_read_config(unsigned char *config_buf, size_t config_len, int *err_ret)
{
    int ret = -1;

    if (!is_atcab_init) {
        ESP_LOGE(TAG, "Device is not initialized");
        goto exit;
    }

    if (config_buf == NULL || config_len < ATECC_CONFIG_SIZE) {
        ESP_LOGE(TAG, "Invalid buffer");
        ret = ATCA_BAD_PARAM;
        goto exit;
    }

    // Read the entire config zone (128 bytes)
    ret = atcab_read_config_zone(config_buf);
    if (ret != ATCA_SUCCESS) {
        ESP_LOGE(TAG, "Failed to read config zone, returned %02x", ret);
        goto exit;
    }

    ESP_LOGI(TAG, "Config zone read successfully");
    *err_ret = ret;
    return ESP_OK;

    exit:
    *err_ret = ret;
    return ESP_FAIL;
}

esp_err_t atecc_write_data(int slot, unsigned char *data_buf, size_t data_len, int *err_ret)
{
    int ret = -1;
    bool is_data_locked = false;

    if (!is_atcab_init) {
        ESP_LOGE(TAG, "Device is not initialized");
        goto exit;
    }

    if (data_buf == NULL) {
        ESP_LOGE(TAG, "Invalid data buffer");
        ret = ATCA_BAD_PARAM;
        goto exit;
    }

    if (slot < 0 || slot > 15) {
        ESP_LOGE(TAG, "Invalid slot number %d (must be 0-15)", slot);
        ret = ATCA_BAD_PARAM;
        goto exit;
    }

    // Data must be 32 bytes for ATECC608
    if (data_len != 32) {
        ESP_LOGE(TAG, "Data length must be 32 bytes, got %d", data_len);
        ret = ATCA_BAD_PARAM;
        goto exit;
    }

    // Check if data zone is locked
    ret = atcab_is_locked(LOCK_ZONE_DATA, &is_data_locked);
    if (ret != ATCA_SUCCESS) {
        ESP_LOGE(TAG, "Failed to check data lock status, returned %02x", ret);
        goto exit;
    }

    if (is_data_locked) {
        ESP_LOGW(TAG, "Data zone is locked - write may fail if slot requires encryption");
    }

    // Write data to slot (block 0)
    // For slots configured with EncRead/WriteConfig protection, this will fail
    // if data zone is locked. Those slots must be written with atcab_write_enc_bytes()
    ret = atcab_write_bytes_zone(ATCA_ZONE_DATA, slot, 0, data_buf, data_len);
    if (ret != ATCA_SUCCESS) {
        ESP_LOGE(TAG, "Failed to write data to slot %d, returned %02x", slot, ret);
        ESP_LOGE(TAG, "Hint: If slot requires write protection, data zone must be unlocked");
        goto exit;
    }

    ESP_LOGI(TAG, "Successfully wrote %d bytes to slot %d", data_len, slot);
    *err_ret = ret;
    return ESP_OK;

exit:
    *err_ret = ret;
    return ESP_FAIL;
}

esp_err_t atecc_write_enc_data(int target_slot, int block, int enckey_slot,
                                unsigned char *data_buf, unsigned char *enckey_buf,
                                unsigned char *num_in, size_t data_len, int *err_ret)
{
    int ret = ATCA_BAD_PARAM;

    if (!is_atcab_init || !data_buf || !enckey_buf || data_len != 32 ||
        target_slot > 15 || enckey_slot > 15 || block > 7) {
        goto exit;
    }

    ECU_DEBUG_LOG(TAG, "Write enc slot %d blk %d", target_slot, block);

    ret = atcab_write_enc(target_slot, block, data_buf, enckey_buf, enckey_slot, num_in);
    if (ret != ATCA_SUCCESS) {
        ESP_LOGE(TAG, "Write enc failed: %02x", ret);
        goto exit;
    }

    ESP_LOGI(TAG, "Write enc slot %d OK", target_slot);
    *err_ret = ret;
    return ESP_OK;

exit:
    *err_ret = ret;
    return ESP_FAIL;
}


/* ===== GTL 24: template-v2 bench commands ======================================================
 * The bench flow (device-config-management provisioning/replacement.py) needs to write the on-chip
 * certificate record across slots 10-12 (72 B each), read it back after the data lock, lock each record
 * slot individually, write stored-format public keys into 13-15, and put the chip to sleep so the next
 * command runs after a wake. The existing write-data only writes 32 B at block 0. */

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
    if (!is_atcab_init) {
        ESP_LOGE(TAG, "Device is not initialized");
        goto exit;
    }
    if (data_buf == NULL || slot < 0 || slot > 15 || offset < 0 || data_len == 0) {
        goto exit;
    }
    /* calib_write_bytes_zone works in 4-byte words; refuse anything it would silently round. */
    if ((offset % 4) != 0 || (data_len % 4) != 0 || offset + (int)data_len > slot_size(slot)) {
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
    if (!is_atcab_init) {
        ESP_LOGE(TAG, "Device is not initialized");
        goto exit;
    }
    if (data_buf == NULL || slot < 0 || slot > 15 || data_len == 0 || (data_len % 4) != 0 || (int)data_len > slot_size(slot)) {
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
    if (!is_atcab_init) {
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

esp_err_t atecc_write_pubkey_slot(int slot, unsigned char *pubkey64, int *err_ret)
{
    int ret = ATCA_BAD_PARAM;
    if (!is_atcab_init) {
        ESP_LOGE(TAG, "Device is not initialized");
        goto exit;
    }
    if (pubkey64 == NULL || slot < 8 || slot > 15) {
        goto exit;
    }
    /* atcab_write_pubkey stores the 72-byte (pad, X, pad, Y) format as whole 32-byte blocks, which a secret
     * public-key slot needs: 4-byte writes are refused there. */
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
    if (!is_atcab_init) {
        ESP_LOGE(TAG, "Device is not initialized");
        *err_ret = ret;
        return ESP_FAIL;
    }
    ret = atcab_sleep();
    *err_ret = ret;
    return (ret == ATCA_SUCCESS) ? ESP_OK : ESP_FAIL;
}
