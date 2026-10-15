/* Host shim: ESP-IDF's esp_rom_crc32_le(), the reflected CRC-32 (poly 0xEDB88320) with the ones'-complement in and out
 * that zlib's crc32() computes -- so esp_rom_crc32_le(0, buf, n) == zlib.crc32(buf). Checked by test_gtl24.c against
 * the standard check value and against zlib-computed constants. */
#pragma once
#include <stdint.h>
static inline uint32_t esp_rom_crc32_le(uint32_t crc, const uint8_t *buf, uint32_t len)
{
    crc = ~crc;
    for (uint32_t i = 0; i < len; i++) {
        crc ^= buf[i];
        for (int k = 0; k < 8; k++) crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1u)));
    }
    return ~crc;
}
