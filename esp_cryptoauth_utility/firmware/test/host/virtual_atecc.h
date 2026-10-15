/*
 * A virtual ATECC608 behind the CryptoAuthLib calls the GTL 24 commands make, plus the console byte stream and the
 * output capture. It models the chip the way device-config-management's tests/fake_atecc.py does (the host side's
 * fake), cited by datasheet section only:
 *   - data writes need the config zone locked; never into a private-key slot; never into an individually locked slot;
 *     a 4-byte (word) write is refused on an IsSecret slot (only whole 32-byte blocks); after the data lock a clear
 *     write needs WriteConfig Always, and a PubInvalid slot (WriteConfig 1) takes block writes (DS 2.2.7.2, 2.4.3);
 *   - clear reads only after the data lock and never from an IsSecret slot (DS 2.4.2 Table 2-14, 2.2.7.1);
 *   - a slot lock only after the data lock, only on a Lockable slot, only once (DS 11.10, 2.4.3);
 *   - sleep, then the next command wakes the chip.
 * The CALIB layer is reproduced too: write/read_bytes_zone refuse non-word offsets and lengths and anything past the
 * slot, then go block-by-block where a whole aligned block remains and word-by-word otherwise; write_pubkey is three
 * 32-byte block writes of (pad, X, pad, Y) -- exactly the library's calib_write_pubkey.
 */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VA_SLOTS 16

typedef struct {
    uint8_t config[128];
    uint8_t data[VA_SLOTS][416];
    bool    asleep;
    int     sleeps, wakes;
    int     block_writes, word_writes, refused;
    int     atcab_calls;   /* every CryptoAuthLib call the stub made */
    bool    fail_sleep;    /* fault injection: the next atcab_sleep() fails */
} vatecc_t;

extern vatecc_t VA;
extern bool     VA_ATCAB_INIT;   /* handlers.c is_atcab_init */
extern bool     VA_CLI_READY;    /* commands.c atca_cli_status_object >= ATECC_INIT_SUCCESS */

void va_reset(const uint8_t config[128]);
int  va_slot_size(int slot);
void va_lock_config(void);
void va_lock_data(void);
bool va_slot_locked(int slot);

/* console: bytes the "host" sends after a command line */
void   va_feed(const uint8_t *b, size_t n);
size_t va_pending(void);
void   va_clear_input(void);

/* output capture */
void        vt_capture_reset(void);
const char *vt_captured(void);
