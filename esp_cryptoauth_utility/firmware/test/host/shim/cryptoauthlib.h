/* Host shim: the CryptoAuthLib surface the GTL 24 sources use, served by the virtual ATECC608 (virtual_atecc.c). */
#pragma once
#include <stddef.h>
#include <stdint.h>
typedef int ATCA_STATUS;
#define ATCA_SUCCESS         0x00
#define ATCA_EXECUTION_ERROR 0xF4
#define ATCA_BAD_PARAM       0xE2
#define ATCA_COMM_FAIL       0xF0
#define ATCA_ZONE_CONFIG     0x00
#define ATCA_ZONE_OTP        0x01
#define ATCA_ZONE_DATA       0x02
ATCA_STATUS atcab_write_bytes_zone(uint8_t zone, uint16_t slot, size_t offset_bytes, const uint8_t *data, size_t length);
ATCA_STATUS atcab_read_bytes_zone(uint8_t zone, uint16_t slot, size_t offset, uint8_t *data, size_t length);
ATCA_STATUS atcab_lock_data_slot(uint16_t slot);
ATCA_STATUS atcab_write_pubkey(uint16_t slot, const uint8_t *public_key);
ATCA_STATUS atcab_wakeup(void);
ATCA_STATUS atcab_sleep(void);
