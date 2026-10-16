/*
 * GTL 24 (template v2 / generic-module provisioning): the five console commands the bench flow needs (plus write-data,
 * moved here from commands.c to frame like them) and the
 * ATECC operations behind them. Split from commands.c / handlers.c so both layers compile on the host against a
 * virtual ATECC (test/host/). Console syntax: gtl24_cmds.c. Chip rules: gtl24_slots.c.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* gtl24_slots.c -- the ATECC operations. Each returns ESP_OK only when the chip did what was asked; *err_ret gets the
 * ATCA status. */
esp_err_t atecc_write_slot(int slot, int offset, unsigned char *data_buf, size_t data_len, int *err_ret);
esp_err_t atecc_read_slot(int slot, unsigned char *data_buf, size_t data_len, int *err_ret);
esp_err_t atecc_lock_slot(int slot, int *err_ret);
esp_err_t atecc_write_pubkey_slot(int slot, const unsigned char *pubkey64, int *err_ret);
esp_err_t atecc_sleep(int *err_ret);

/* gtl24_cmds.c -- registers write-slot / read-slot / lock-slot / write-pubkey / sleep / write-data with esp_console. */
esp_err_t register_gtl24_commands(void);

/* handlers.c -- the 32-byte data write behind write-data (the same prototype as handlers.h). */
esp_err_t atecc_write_data(int slot, unsigned char *data_buf, size_t data_len, int *err_ret);

/* Readiness, from the files that own it: handlers.c (atcab initialized) and commands.c (the CLI's init succeeded). */
bool atecc_is_initialized(void);
bool ecu_cli_atecc_ready(void);

#ifdef __cplusplus
}
#endif
