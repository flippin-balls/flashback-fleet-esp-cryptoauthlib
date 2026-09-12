/*
 * Copyright 2018-2025 Espressif Systems (Shanghai) PTE LTD
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <string.h>
#include <soc/soc_caps.h>

#include "esp_err.h"
#include "esp_log.h"
#include "esp_rom_sys.h"
#include "cryptoauthlib.h"
#include "esp_idf_version.h"

#if defined(CONFIG_ATCA_I2C_USE_LEGACY_DRIVER)
#include <driver/i2c.h>
#else
#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 2, 0)
#include <driver/i2c_master.h>
#else
#include <driver/i2c.h>
#endif
#endif

static uint8_t I2C_SDA_PIN = CONFIG_ATCA_I2C_SDA_PIN;
static uint8_t I2C_SCL_PIN = CONFIG_ATCA_I2C_SCL_PIN;

#ifndef LOG_LOCAL_LEVEL
#define LOG_LOCAL_LEVEL                    ESP_LOG_INFO
#endif

#define MAX_I2C_BUSES SOC_I2C_NUM

#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 3, 0)

#if SOC_HP_I2C_NUM >= 2
#define I2C_PORT_2 I2C_NUM_1
#elif SOC_LP_I2C_NUM >= 1
#define I2C_PORT_2 LP_I2C_NUM_0
#endif // SOC_HP_I2C_NUM >= 2

#else // ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 3, 0)

#if SOC_I2C_NUM >= 2
#define I2C_PORT_2 I2C_NUM_1
#endif // SOC_I2C_NUM >= 2

#endif // !ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 3, 0)

void hal_esp32_i2c_set_pin_config(uint8_t sda_pin, uint8_t scl_pin)
{
    I2C_SDA_PIN = sda_pin;
    I2C_SCL_PIN = scl_pin;
}

const char* TAG = "HAL_I2C";

#if ESP_IDF_VERSION < ESP_IDF_VERSION_VAL(5, 2, 0) || defined(CONFIG_ATCA_I2C_USE_LEGACY_DRIVER)

// ============================================================================
// LEGACY I2C DRIVER IMPLEMENTATION (ESP-IDF < 5.2 or CONFIG_ATCA_I2C_USE_LEGACY_DRIVER)
// ============================================================================

#define ACK_CHECK_EN                       0x1  /*!< I2C master will check ack from slave*/
#define ACK_CHECK_DIS                      0x0  /*!< I2C master will not check ack from slave */
#define ACK_VAL                            0x0  /*!< I2C ack value */
#define NACK_VAL                           0x1  /*!< I2C nack value */

typedef struct atcaI2Cmaster {
    int id;
    i2c_config_t conf;
    int ref_ct;
} ATCAI2CMaster_t;

ATCAI2CMaster_t i2c_hal_data[MAX_I2C_BUSES];

ATCA_STATUS status;

/** \brief method to change the bus speed of I2C
 * \param[in] iface  interface on which to change bus speed
 * \param[in] speed  baud rate (typically 100000 or 400000)
 */
ATCA_STATUS hal_i2c_change_baud(ATCAIface iface, uint32_t speed)
{
    esp_err_t rc;
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);
    int bus = cfg->atcai2c.bus;

    i2c_hal_data[bus].conf.master.clk_speed = speed;

    rc = i2c_param_config(i2c_hal_data[bus].id, &i2c_hal_data[bus].conf);
    if (rc == ESP_OK) {
        return ATCA_SUCCESS;
    } else {
        return ATCA_COMM_FAIL;
    }
}

/** \brief initialize an I2C interface using given config
 * \param[in] hal - opaque ptr to HAL data
 * \param[in] cfg - interface configuration
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS hal_i2c_init(ATCAIface iface, ATCAIfaceCfg *cfg)
{
    esp_err_t rc = ESP_FAIL;
    int bus = cfg->atcai2c.bus;

    ESP_LOGI("HAL_I2C", "Init: bus=%d, addr=0x%02X, sda=%d, scl=%d",
             bus, cfg->atcai2c.address, I2C_SDA_PIN, I2C_SCL_PIN);

    if (bus >= 0 && bus < MAX_I2C_BUSES) {
        if (0 == i2c_hal_data[bus].ref_ct) {
            ESP_LOGI("HAL_I2C", "Init: First init, installing driver");
            i2c_hal_data[bus].ref_ct = 1;
            i2c_hal_data[bus].conf.mode = I2C_MODE_MASTER;
            // Enable internal pull-ups for I2C (ATECC608A needs pull-ups)
            i2c_hal_data[bus].conf.sda_pullup_en = GPIO_PULLUP_ENABLE;
            i2c_hal_data[bus].conf.scl_pullup_en = GPIO_PULLUP_ENABLE;
            // Use baud from config - wake sequence requires <= 100kHz
            i2c_hal_data[bus].conf.master.clk_speed = cfg->atcai2c.baud;

            switch (bus) {
            case 0:
                i2c_hal_data[bus].id = I2C_NUM_0;
                break;
            case 1:
#if SOC_I2C_NUM >= 2
                i2c_hal_data[bus].id = I2C_PORT_2;
#endif
                break;
            default:
                break;
            }
            i2c_hal_data[bus].conf.sda_io_num = I2C_SDA_PIN;
            i2c_hal_data[bus].conf.scl_io_num = I2C_SCL_PIN;

            rc = i2c_param_config(i2c_hal_data[bus].id, &i2c_hal_data[bus].conf);
            rc = i2c_driver_install(i2c_hal_data[bus].id, I2C_MODE_MASTER, 0, 0, 0);
            ESP_LOGI("HAL_I2C", "Init: Driver installed, rc=%d", rc);
        } else {
            ESP_LOGI("HAL_I2C", "Init: Reusing existing driver (ref=%d)", i2c_hal_data[bus].ref_ct);
            i2c_hal_data[bus].ref_ct++;
        }

        iface->hal_data = &i2c_hal_data[bus];
    }

    if (ESP_OK == rc) {
        ESP_LOGI("HAL_I2C", "Init: SUCCESS");
        return ATCA_SUCCESS;
    } else {
        ESP_LOGE("HAL_I2C", "Init: FAILED rc=%d", rc);
        return ATCA_COMM_FAIL;
    }
}

/** \brief HAL implementation of I2C post init
 * \param[in] iface  instance
 * \return ATCA_SUCCESS
 */
ATCA_STATUS hal_i2c_post_init(ATCAIface iface)
{
    return ATCA_SUCCESS;
}

/** \brief HAL implementation of I2C send
 * \param[in] iface         instance
 * \param[in] word_address  device transaction type
 * \param[in] txdata        pointer to space to bytes to send
 * \param[in] txlength      number of bytes to send
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS hal_i2c_send(ATCAIface iface, uint8_t word_address, uint8_t *txdata, int txlength)
{
    ATCAIfaceCfg *cfg = iface->mIfaceCFG;
    esp_err_t rc;
    uint8_t device_address = 0xFFu;

    if (!cfg) {
        ESP_LOGE("HAL_I2C", "Send: NULL config");
        return ATCA_BAD_PARAM;
    }

#ifdef ATCA_ENABLE_DEPRECATED
    device_address = ATCA_IFACECFG_VALUE(cfg, atcai2c.slave_address);
#else
    device_address = ATCA_IFACECFG_VALUE(cfg, atcai2c.address);
#endif

    // Try simple address probe first to verify device is responding
    // device_address from config is 7-bit, need to shift left and add R/W bit
    uint8_t write_byte = (device_address << 1) | I2C_MASTER_WRITE;
    i2c_cmd_handle_t probe_cmd = i2c_cmd_link_create();
    i2c_master_start(probe_cmd);
    i2c_master_write_byte(probe_cmd, write_byte, ACK_CHECK_EN);
    i2c_master_stop(probe_cmd);
    rc = i2c_master_cmd_begin(cfg->atcai2c.bus, probe_cmd, 100);
    i2c_cmd_link_delete(probe_cmd);

    if (ESP_OK != rc) {
        ESP_LOGE("HAL_I2C", "Send: Device not responding at address 0x%02X (esp_err=%d)", device_address, rc);
        return ATCA_COMM_FAIL;
    }

    // Device responded, now send the actual command
    i2c_cmd_handle_t cmd = i2c_cmd_link_create();
    (void)i2c_master_start(cmd);
    (void)i2c_master_write_byte(cmd, write_byte, ACK_CHECK_EN);  // Use shifted address
    (void)i2c_master_write_byte(cmd, word_address, ACK_CHECK_EN);

    if (NULL != txdata && 0u < txlength) {
        (void)i2c_master_write(cmd, txdata, txlength, ACK_CHECK_EN);
    }
    (void)i2c_master_stop(cmd);

    rc = i2c_master_cmd_begin(cfg->atcai2c.bus, cmd, 100);  // Increased from 10 to 100 ticks
    (void)i2c_cmd_link_delete(cmd);

    if (ESP_OK != rc) {
        ESP_LOGE("HAL_I2C", "Send: I2C transaction failed (esp_err=%d)", rc);
        return ATCA_COMM_FAIL;
    }
    return ATCA_SUCCESS;
}

/** \brief HAL implementation of I2C receive function
 * \param[in]    iface          Device to interact with.
 * \param[in]    address        Device address
 * \param[out]   rxdata         Data received will be returned here.
 * \param[in,out] rxlength      As input, the size of the rxdata buffer.
 *                              As output, the number of bytes received.
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS hal_i2c_receive(ATCAIface iface, uint8_t address, uint8_t *rxdata, uint16_t *rxlength)
{
    ATCAIfaceCfg *cfg = iface->mIfaceCFG;
    esp_err_t rc;
    i2c_cmd_handle_t cmd;
    ATCA_STATUS status = ATCA_COMM_FAIL;

    if ((NULL == cfg) || (NULL == rxlength) || (NULL == rxdata)) {
        ESP_LOGE("HAL_I2C", "Receive: NULL pointer encountered");
        return ATCA_TRACE(ATCA_BAD_PARAM, "NULL pointer encountered");
    }

    cmd = i2c_cmd_link_create();
    (void)i2c_master_start(cmd);
    // address is 7-bit, need to shift and add READ bit
    uint8_t read_byte = (address << 1) | I2C_MASTER_READ;
    (void)i2c_master_write_byte(cmd, read_byte, ACK_CHECK_EN);

    // Read all bytes: ACK for all except the last, NACK for the last
    for (size_t i = 0; i < *rxlength; i++) {
        bool is_last = (i == *rxlength - 1);
        (void)i2c_master_read_byte(cmd, rxdata + i, is_last ? NACK_VAL : ACK_VAL);
    }
    (void)i2c_master_stop(cmd);

    rc = i2c_master_cmd_begin(cfg->atcai2c.bus, cmd, 1000);  // 10 seconds for clock stretching
    (void)i2c_cmd_link_delete(cmd);

    if (ESP_OK == rc) {
        status = ATCA_SUCCESS;
    } else {
        ESP_LOGE("HAL_I2C", "Receive: Failed with esp_err=%d", rc);
    }

    return status;
}

/** \brief wake up ATECC device using I2C bus
 * \param[in] iface  interface to logical device to wakeup
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS hal_i2c_wake(ATCAIface iface)
{
    ATCAIfaceCfg *cfg = iface->mIfaceCFG;
    esp_err_t rc;
    uint8_t data[4] = {0};

    if (!cfg) {
        ESP_LOGE("HAL_I2C", "Wake: NULL config");
        return ATCA_BAD_PARAM;
    }

    ESP_LOGI("HAL_I2C", "Wake: Sending wake pulse to 0x00");

    // Send wake pulse to address 0x00
    i2c_cmd_handle_t cmd = i2c_cmd_link_create();
    (void)i2c_master_start(cmd);
    (void)i2c_master_write_byte(cmd, 0x00 | I2C_MASTER_WRITE, NACK_VAL);  // Wake address, expect NACK
    (void)i2c_master_stop(cmd);
    rc = i2c_master_cmd_begin(cfg->atcai2c.bus, cmd, 10);
    (void)i2c_cmd_link_delete(cmd);

    ESP_LOGI("HAL_I2C", "Wake: Pulse sent, rc=%d (ESP_OK=%d)", rc, ESP_OK);

    // Wait 1500 microseconds for device to wake
    ESP_LOGI("HAL_I2C", "Wake: Waiting 1500us");
    esp_rom_delay_us(1500);

    // Read wake response (should be 0x11)
    ESP_LOGI("HAL_I2C", "Wake: Reading response from addr 0x%02X", cfg->atcai2c.address);
    cmd = i2c_cmd_link_create();
    (void)i2c_master_start(cmd);
    (void)i2c_master_write_byte(cmd, (cfg->atcai2c.address << 1) | I2C_MASTER_READ, ACK_CHECK_EN);
    (void)i2c_master_read(cmd, data, 4, NACK_VAL);
    (void)i2c_master_stop(cmd);
    rc = i2c_master_cmd_begin(cfg->atcai2c.bus, cmd, 10);
    (void)i2c_cmd_link_delete(cmd);

    ESP_LOGI("HAL_I2C", "Wake: Response rc=%d, data=[0x%02X 0x%02X 0x%02X 0x%02X]",
             rc, data[0], data[1], data[2], data[3]);

    // Verify wake token (0x11)
    if (ESP_OK == rc && data[0] == 0x11) {
        ESP_LOGI("HAL_I2C", "Wake: SUCCESS - got 0x11");
        return ATCA_SUCCESS;
    }

    ESP_LOGE("HAL_I2C", "Wake: FAILED - expected 0x11, got 0x%02X (rc=%d)", data[0], rc);
    return ATCA_COMM_FAIL;
}

/** \brief manages reference count on given bus and releases resource if no more references exist
 * \param[in] hal_data - opaque pointer to hal data structure - known only to the HAL implementation
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS hal_i2c_release(void *hal_data)
{
    ATCAI2CMaster_t *hal = (ATCAI2CMaster_t*)hal_data;

    if (hal && --(hal->ref_ct) <= 0) {
        i2c_driver_delete(hal->id);
    }
    return ATCA_SUCCESS;
}

/** \brief Perform control operations for the kit protocol
 * \param[in]     iface          Interface to interact with.
 * \param[in]     option         Control parameter identifier
 * \param[in]     param          Optional pointer to parameter value
 * \param[in]     paramlen       Length of the parameter
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS hal_i2c_control(ATCAIface iface, uint8_t option, void* param, size_t paramlen)
{
    (void)param;
    (void)paramlen;

    if (iface && iface->mIfaceCFG) {
        switch (option) {
        case ATCA_HAL_CONTROL_WAKE:
            /* atwake() in atca_iface.c routes here via halcontrol.
             * Without this case, wake returns ATCA_UNIMPLEMENTED and the
             * chip is never actually pulsed. */
            return hal_i2c_wake(iface);
        case ATCA_HAL_CHANGE_BAUD:
            return hal_i2c_change_baud(iface, *(uint32_t*)param);
        case ATCA_HAL_CONTROL_SELECT:
        case ATCA_HAL_CONTROL_DESELECT:
            return ATCA_SUCCESS;
        default:
            return ATCA_UNIMPLEMENTED;
        }
    }
    return ATCA_BAD_PARAM;
}

#else

// ============================================================================
// NEW I2C DRIVER IMPLEMENTATION (ESP-IDF >= 5.2 and !CONFIG_ATCA_I2C_USE_LEGACY_DRIVER)
// ============================================================================

typedef struct atcaI2Cmaster {
    int port_num;
    i2c_master_bus_handle_t bus_handle;
    i2c_master_dev_handle_t dev_handle;
    /* Second device handle registered at address 0x00, used only to drive
     * the ATECC wake pulse. The wake protocol requires a write to 0x00 that
     * the chip NACKs while it transitions out of sleep; the new I2C driver
     * routes every transaction through a registered device, so we keep a
     * dedicated handle for it rather than re-registering on every wake. */
    i2c_master_dev_handle_t wake_handle;
    uint32_t speed;
    uint8_t device_address;
    int ref_ct;
    bool initialized;
} ATCAI2CMaster_t;

ATCAI2CMaster_t i2c_hal_data[MAX_I2C_BUSES];

/** \brief method to change the bus speed of I2C
 * \param[in] iface  interface on which to change bus speed
 * \param[in] speed  baud rate (typically 100000 or 400000)
 */
ATCA_STATUS hal_i2c_change_baud(ATCAIface iface, uint32_t speed)
{
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);
    int bus = cfg->atcai2c.bus;

    if (bus >= MAX_I2C_BUSES || !i2c_hal_data[bus].bus_handle) {
        return ATCA_COMM_FAIL;
    }

    // Store the new speed for future device registrations
    i2c_hal_data[bus].speed = speed;

    // If device is already registered, we need to re-register with new speed
    if (i2c_hal_data[bus].dev_handle) {
        esp_err_t rc;

        // Remove old device
        rc = i2c_master_bus_rm_device(i2c_hal_data[bus].dev_handle);
        if (rc != ESP_OK) {
            return ATCA_COMM_FAIL;
        }

        // Re-add device with new speed
        i2c_device_config_t dev_cfg = {
            .dev_addr_length = I2C_ADDR_BIT_LEN_7,
            .device_address = i2c_hal_data[bus].device_address,
            .scl_speed_hz = speed,
            .scl_wait_us = 0,  // Use default timing
        };

        rc = i2c_master_bus_add_device(i2c_hal_data[bus].bus_handle, &dev_cfg, &i2c_hal_data[bus].dev_handle);
        if (rc != ESP_OK) {
            return ATCA_COMM_FAIL;
        }
    }

    return ATCA_SUCCESS;
}

/** \brief initialize an I2C interface using given config
 * \param[in] hal - opaque ptr to HAL data
 * \param[in] cfg - interface configuration
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS hal_i2c_init(ATCAIface iface, ATCAIfaceCfg *cfg)
{
    esp_err_t rc = ESP_FAIL;
    int bus = cfg->atcai2c.bus;

    if (bus >= 0 && bus < MAX_I2C_BUSES) {
        if (0 == i2c_hal_data[bus].ref_ct) {
            i2c_hal_data[bus].ref_ct = 1;
            i2c_hal_data[bus].port_num = bus;
            i2c_hal_data[bus].speed = 100000; // Standard 100kHz for ATECC608A
            i2c_hal_data[bus].initialized = false;

            // Configure I2C master bus
            i2c_master_bus_config_t bus_config = {
                .i2c_port = bus,
                .sda_io_num = I2C_SDA_PIN,
                .scl_io_num = I2C_SCL_PIN,
                .clk_source = I2C_CLK_SRC_DEFAULT,
                .glitch_ignore_cnt = 7,
                .intr_priority = 0,
                .trans_queue_depth = 0,  // 0 = synchronous mode
                .flags.enable_internal_pullup = true,
            };

            rc = i2c_new_master_bus(&bus_config, &i2c_hal_data[bus].bus_handle);
            if (rc != ESP_OK) {
                /* ROLL BACK. ref_ct was claimed at the top of this branch, before any of the
                 * work that can fail. Returning without releasing it leaves the slot looking
                 * OWNED with nothing behind it, and every later init then takes the reuse
                 * branch below -- which, before this change, always reported failure. The
                 * boot retry loop in main.cpp is the visible victim: after one genuine
                 * failure it cannot succeed, so the retries are decorative. */
                i2c_hal_data[bus].bus_handle = NULL;
                i2c_hal_data[bus].initialized = false;
                i2c_hal_data[bus].ref_ct = 0;
                return ATCA_COMM_FAIL;
            }

            // Get device address. Per the legacy hal_i2c_send convention in
            // this file (line 204), atcai2c.address is stored in 7-bit form
            // (e.g. 0x60 for ATECC608A). The new i2c_master driver also
            // expects 7-bit, so use the value directly without shifting.
            // (Shifting >> 1 here would give 0x30 — a different device
            // entirely — and the chip would never ACK.)
#ifdef ATCA_ENABLE_DEPRECATED
            i2c_hal_data[bus].device_address = ATCA_IFACECFG_VALUE(cfg, atcai2c.slave_address);
#else
            i2c_hal_data[bus].device_address = ATCA_IFACECFG_VALUE(cfg, atcai2c.address);
#endif

            // Configure I2C device
            i2c_device_config_t dev_cfg = {
                .dev_addr_length = I2C_ADDR_BIT_LEN_7,
                .device_address = i2c_hal_data[bus].device_address,
                .scl_speed_hz = i2c_hal_data[bus].speed,
                .scl_wait_us = 0,
            };

            rc = i2c_master_bus_add_device(i2c_hal_data[bus].bus_handle, &dev_cfg, &i2c_hal_data[bus].dev_handle);
            if (rc != ESP_OK) {
                i2c_del_master_bus(i2c_hal_data[bus].bus_handle);
                i2c_hal_data[bus].bus_handle = NULL;      /* deleted -- do not leave it dangling */
                i2c_hal_data[bus].dev_handle = NULL;
                i2c_hal_data[bus].initialized = false;
                i2c_hal_data[bus].ref_ct = 0;             /* see the rollback note above */
                return ATCA_COMM_FAIL;
            }

            // Register a second device handle at address 0x00 for the ATECC
            // wake pulse. The chip's wake protocol requires a write to 0x00
            // that NACKs while the chip transitions out of sleep; with the
            // new I2C driver every transmit must target a registered device,
            // so we keep this dedicated handle for the lifetime of the bus.
            i2c_device_config_t wake_cfg = {
                .dev_addr_length = I2C_ADDR_BIT_LEN_7,
                .device_address = 0x00,
                .scl_speed_hz = i2c_hal_data[bus].speed,
                .scl_wait_us = 0,
            };

            rc = i2c_master_bus_add_device(i2c_hal_data[bus].bus_handle, &wake_cfg, &i2c_hal_data[bus].wake_handle);
            if (rc != ESP_OK) {
                i2c_master_bus_rm_device(i2c_hal_data[bus].dev_handle);
                i2c_del_master_bus(i2c_hal_data[bus].bus_handle);
                i2c_hal_data[bus].dev_handle = NULL;
                i2c_hal_data[bus].bus_handle = NULL;
                i2c_hal_data[bus].wake_handle = NULL;
                i2c_hal_data[bus].initialized = false;
                i2c_hal_data[bus].ref_ct = 0;             /* see the rollback note above */
                return ATCA_COMM_FAIL;
            }

            i2c_hal_data[bus].initialized = true;
        } else if (i2c_hal_data[bus].initialized) {
            /* A GENUINE REUSE IS A SUCCESS, and this branch used to say otherwise.
             *
             * `rc` is seeded ESP_FAIL at the top and was never assigned here, so every
             * re-entrant init returned ATCA_COMM_FAIL even when the bus was perfectly healthy
             * and the reference count had just been incremented. The caller then treats a
             * working chip as a dead one. */
            i2c_hal_data[bus].ref_ct++;
            rc = ESP_OK;
        } else {
            /* ref_ct claimed but never successfully initialised.
             *
             * DO NOT "RECOVER" BY RESETTING ref_ct AND RETRYING THE FRESH PATH. That is
             * precisely the state a CONCURRENTLY INITIALISING task occupies between claiming
             * the slot and finishing construction, so resetting would delete a bus another
             * task is still building. Failing loudly is correct; the rollbacks above are what
             * make this state unreachable in the sequential case. */
            ESP_LOGE("HAL_I2C", "bus %d: ref_ct=%d but not initialized - refusing to reuse a "
                                "half-built interface", bus, i2c_hal_data[bus].ref_ct);
            return ATCA_COMM_FAIL;
        }

        iface->hal_data = &i2c_hal_data[bus];
    }

    if (ESP_OK == rc) {
        return ATCA_SUCCESS;
    } else {
        return ATCA_COMM_FAIL;
    }
}

/** \brief HAL implementation of I2C post init
 * \param[in] iface  instance
 * \return ATCA_SUCCESS
 */
ATCA_STATUS hal_i2c_post_init(ATCAIface iface)
{
    return ATCA_SUCCESS;
}

/** \brief HAL implementation of I2C send
 * \param[in] iface         instance
 * \param[in] word_address  device transaction type
 * \param[in] txdata        pointer to space to bytes to send
 * \param[in] txlength      number of bytes to send
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS hal_i2c_send(ATCAIface iface, uint8_t word_address, uint8_t *txdata, int txlength)
{
    ATCAIfaceCfg *cfg = iface->mIfaceCFG;
    esp_err_t rc;
    ATCAI2CMaster_t *hal_data;

    if (!cfg) {
        return ATCA_BAD_PARAM;
    }

    hal_data = (ATCAI2CMaster_t*)iface->hal_data;
    if (!hal_data || !hal_data->dev_handle || !hal_data->initialized) {
        return ATCA_BAD_PARAM;
    }

#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 4, 0)
    // For ESP-IDF v5.4+, use multi-buffer transmit
    i2c_master_transmit_multi_buffer_info_t buffer_info[2] = {
        {.write_buffer = (uint8_t*) &word_address, .buffer_size = 1},
        {.write_buffer = (uint8_t*)txdata, .buffer_size = txlength},
    };

    rc = i2c_master_multi_buffer_transmit(hal_data->dev_handle, buffer_info, 2, 200);
#else
    // For ESP-IDF v5.2 and v5.3, use dynamic allocation for the write buffer
    // Prepare write buffer: word_address + txdata
    size_t write_size = 1;
    if (NULL != txdata && 0u < txlength) {
        write_size += txlength;
    }

    uint8_t *write_buffer = malloc(write_size);
    if (!write_buffer) {
        return ATCA_COMM_FAIL;
    }

    write_buffer[0] = word_address;
    if (NULL != txdata && 0u < txlength) {
        memcpy(write_buffer + 1, txdata, txlength);
    }

    /* The send half was uncapped. With the wake ladder retrying, a command could spend its whole
     * budget transmitting into a bus that never acknowledges, while the deadline sat waiting in
     * the receive path. Refuse to start outside budget, then clamp what we do start. */
    if (!atca_deadline_can_start())
    {
        ESP_LOGW("HAL_I2C", "send declined: deadline spent");
        return ATCA_TIMEOUT;
    }
    rc = i2c_master_transmit(hal_data->dev_handle, write_buffer, write_size,
                             (int)atca_deadline_remaining_ms(200));
    free(write_buffer);
#endif // ESP_IDF_VERSION < ESP_IDF_VERSION_VAL(5, 4, 0)

    if (rc != ESP_OK) {
        return ATCA_COMM_FAIL;
    } else {
        return ATCA_SUCCESS;
    }
}

/** \brief HAL implementation of I2C receive function
 * \param[in]    iface          Device to interact with.
 * \param[in]    address        Device address
 * \param[out]   rxdata         Data received will be returned here.
 * \param[in,out] rxlength      As input, the size of the rxdata buffer.
 *                              As output, the number of bytes received.
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS hal_i2c_receive(ATCAIface iface, uint8_t address, uint8_t *rxdata, uint16_t *rxlength)
{
    ATCAIfaceCfg *cfg = iface->mIfaceCFG;
    esp_err_t rc;
    ATCA_STATUS status = ATCA_COMM_FAIL;

    if ((NULL == cfg) || (NULL == rxlength) || (NULL == rxdata)) {
        return ATCA_TRACE(ATCA_BAD_PARAM, "NULL pointer encountered");
    }

    ATCAI2CMaster_t *hal_data;

    hal_data = (ATCAI2CMaster_t*)iface->hal_data;
    if (!hal_data || !hal_data->dev_handle || !hal_data->initialized) {
        return ATCA_BAD_PARAM;
    }

    /* Never let ONE transfer outlive the command's whole budget, and never ARM a timeout too
     * short to be represented: at CONFIG_FREERTOS_HZ=100 a sub-10 ms timeout rounds toward zero
     * ticks and can fail a perfectly healthy transfer. Below that floor we decline instead --
     * reporting the budget honestly rather than manufacturing a bus failure out of it.
     * Both calls return the cap unchanged when no deadline is set. */
    if (!atca_deadline_can_start())
    {
        ESP_LOGW("HAL_I2C", "receive declined: deadline spent");
        return ATCA_TIMEOUT;
    }
    rc = i2c_master_receive(hal_data->dev_handle, rxdata, *rxlength,
                            (int)atca_deadline_remaining_ms(200));
    if (ESP_OK == rc) {
        status = ATCA_SUCCESS;
    }

    return status;
}

/** \brief wake up ATECC device using I2C bus
 *
 * The wake protocol writes to address 0x00 (which the chip NACKs while it
 * transitions from sleep), waits for the chip to come up, then reads a
 * 4-byte wake-confirm response from the regular device address. The first
 * byte of the response is 0x11 on a successful wake.
 *
 * Unlike the legacy driver, the new i2c_master driver does NOT enter a
 * critical section to reset the FSM after a NACK, so the IWDT no longer
 * panics during this sequence (which was the original motivation for this
 * migration — see openspec/changes/migrate-i2c-master-driver).
 *
 * \param[in] iface  interface to logical device to wakeup
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS hal_i2c_wake(ATCAIface iface)
{
    ATCAIfaceCfg *cfg = iface->mIfaceCFG;
    ATCAI2CMaster_t *hal_data;
    esp_err_t rc;
    uint8_t wake_resp[4] = {0};
    uint16_t wake_resp_len = sizeof(wake_resp);

    if (!cfg) {
        return ATCA_BAD_PARAM;
    }

    hal_data = (ATCAI2CMaster_t*)iface->hal_data;
    if (!hal_data || !hal_data->wake_handle || !hal_data->dev_handle || !hal_data->initialized) {
        return ATCA_BAD_PARAM;
    }

    /* Send wake pulse: write a single byte to the 0x00 wake handle. The
     * chip NACKs while waking, so any non-OK return here is the expected
     * outcome of the pulse — we do NOT treat it as failure. The new driver
     * surfaces the NACK as ESP_ERR_INVALID_STATE / ESP_ERR_TIMEOUT (and
     * occasionally ESP_FAIL depending on bus state); all are acceptable. */
    uint8_t wake_byte = 0x00;
    /* The new i2c.master driver logs this EXPECTED wake NACK at ESP_LOGE("i2c.master", ...),
     * which floods the console (~one burst per ATECC op) and buries real faults. Silence the
     * driver tag ONLY across the deliberate wake pulse, then restore ESP_LOG_ERROR so a NACK on
     * a REAL transaction (hal_i2c_send/receive — the failures we actually care about) still logs.
     * Safe: the ATECC owns a dedicated I2C bus (SDA=9/SCL=40) and cryptoauthlib serializes ops
     * under the HAL mutex, so nothing else races in this ~microsecond window. */
    esp_log_level_set("i2c.master", ESP_LOG_NONE);
    /* Entry-bounded only. The wake pulse is already 10 ms -- exactly one tick at this build's
     * FREERTOS_HZ -- so shortening it further is not representable. Refuse to start it outside
     * budget; do not try to trim it. */
    if (!atca_deadline_can_start())
    {
        ESP_LOGW("HAL_I2C", "wake declined: deadline spent");
        return ATCA_TIMEOUT;
    }
    rc = i2c_master_transmit(hal_data->wake_handle, &wake_byte, 1, 10 /* ms */);
    esp_log_level_set("i2c.master", ESP_LOG_ERROR);
    (void)rc;  // intentional: NACK is the design

    /* Hold off long enough for the chip to come fully out of sleep.
     * Use esp_rom_delay_us (busy-wait) because pdMS_TO_TICKS(3) rounds
     * to 0 at the default 100 Hz tick rate, making vTaskDelay a no-op. */
    esp_rom_delay_us(3000);

    /* Read the 4-byte wake-confirm response from the ATECC device handle.
     * Use the standard hal_i2c_receive entry point so we get consistent
     * error handling. */
    if (ATCA_SUCCESS != hal_i2c_receive(iface, cfg->atcai2c.address, wake_resp, &wake_resp_len)) {
        return ATCA_COMM_FAIL;
    }

    /* Settle delay before the caller issues the actual command. */
    esp_rom_delay_us(5000);

    /* Validate the canonical 4-byte wake response: {0x04, 0x11, 0x33, 0x43}
     * (count=4, status=0x11 "after-wake", CRC). hal_check_wake performs
     * the exact comparison cryptoauthlib expects, including the
     * self-test-failure response variant. */
    return hal_check_wake(wake_resp, (int)wake_resp_len);
}

/** \brief manages reference count on given bus and releases resource if no more references exist
 * \param[in] hal_data - opaque pointer to hal data structure - known only to the HAL implementation
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS hal_i2c_release(void *hal_data)
{
    ATCAI2CMaster_t *hal = (ATCAI2CMaster_t*)hal_data;

    if (!hal) {
        return ATCA_SUCCESS;
    }

    /* CLAMPED. The decrement used to be unconditional, so a release with no matching init drove
     * ref_ct NEGATIVE -- and `if (0 == ref_ct)` in hal_i2c_init then never matched again, sending
     * every subsequent init down the reuse branch.
     *
     * Unbalanced releases are not hypothetical in this firmware: the app releases deliberately to
     * hand the chip to esp-tls, the bus-recovery path releases before re-initialising, and
     * ESP-IDF's esp_mbedtls_cleanup() releases the GLOBAL device on any TLS teardown, including
     * connections that never touched the ATECC. */
    if (hal->ref_ct > 0) {
        hal->ref_ct--;
    }

    if (hal->ref_ct <= 0) {
        hal->ref_ct = 0;                 /* never leave it negative */
        if (hal->wake_handle) {
            i2c_master_bus_rm_device(hal->wake_handle);
            hal->wake_handle = NULL;
        }
        if (hal->dev_handle) {
            i2c_master_bus_rm_device(hal->dev_handle);
            hal->dev_handle = NULL;
        }
        if (hal->bus_handle) {
            i2c_del_master_bus(hal->bus_handle);
            hal->bus_handle = NULL;
        }
        hal->initialized = false;
    }
    return ATCA_SUCCESS;
}

/** \brief Perform control operations for the kit protocol
 * \param[in]     iface          Interface to interact with.
 * \param[in]     option         Control parameter identifier
 * \param[in]     param          Optional pointer to parameter value
 * \param[in]     paramlen       Length of the parameter
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS hal_i2c_control(ATCAIface iface, uint8_t option, void* param, size_t paramlen)
{
    (void)param;
    (void)paramlen;

    if (iface && iface->mIfaceCFG) {
        switch (option) {
        case ATCA_HAL_CONTROL_WAKE:
            /* atwake() in atca_iface.c routes here via halcontrol.
             * Without this case, wake returns ATCA_UNIMPLEMENTED and the
             * chip is never actually pulsed. */
            return hal_i2c_wake(iface);
        case ATCA_HAL_CHANGE_BAUD:
            return hal_i2c_change_baud(iface, *(uint32_t*)param);
        case ATCA_HAL_CONTROL_SELECT:
        case ATCA_HAL_CONTROL_DESELECT:
            return ATCA_SUCCESS;
        default:
            return ATCA_UNIMPLEMENTED;
        }
    }
    return ATCA_BAD_PARAM;
}

#endif // ESP_IDF_VERSION < ESP_IDF_VERSION_VAL(5, 2, 0) || defined(CONFIG_ATCA_I2C_USE_LEGACY_DRIVER)

/* The on-target clock for the command deadline. Kept HERE rather than in atca_deadline.c so that
 * unit stays free of ESP dependencies and can be compiled by a host test. */
#include "esp_timer.h"
int64_t atca_deadline_default_clock_us(void)
{
    return esp_timer_get_time();
}
