/* Host shim: everything the stub prints goes to one capture buffer the tests read (vt_* in virtual_atecc.c).
 * stdio.h is included FIRST, so a fortified libc's own inline printf keeps its name; only the code under test, compiled
 * with -DVT_CAPTURE_REMAP after this header, has its printf/fflush calls redirected. */
#pragma once
#include <stdio.h>
int vt_printf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
int vt_fflush(FILE *f);
#ifdef VT_CAPTURE_REMAP
#define printf vt_printf
#define fflush vt_fflush
#endif
