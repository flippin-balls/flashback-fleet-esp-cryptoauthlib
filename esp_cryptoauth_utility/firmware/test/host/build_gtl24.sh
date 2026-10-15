#!/bin/sh
#
# GTL 24 stub commands: build + run test_gtl24.c against the REAL main/gtl24_cmds.c and main/gtl24_slots.c and the
# virtual ATECC608 (virtual_atecc.c), configured with template v2. The ESP-IDF / CryptoAuthLib surface is shimmed
# (shim/); printf/fflush in the sources go to the capture the tests read.
#
# `--mutate`: damage each rule in a copy of the sources and require the suite to go RED (a mutant that does not apply
# is STALE; one that does not compile is UNCOMPILABLE; neither is a kill).
#
# Env: GCC (default gcc).
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
MAIN="$(cd "$HERE/../../main" && pwd)"
GCC="${GCC:-gcc}"
OUT="${GTL24_OUT:-$HERE/.build}"
mkdir -p "$OUT"

CFLAGS="-std=gnu11 -O1 -Wall -Wextra -Werror -I $HERE/shim -I $MAIN -I $HERE"

build() {   # $1 = dir holding gtl24_cmds.c / gtl24_slots.c ; $2 = binary
    # The stub's own printf/fflush go to the capture: only the two sources under test are compiled with the remap.
    for f in gtl24_cmds gtl24_slots; do
        # shellcheck disable=SC2086
        "$GCC" $CFLAGS -DVT_CAPTURE_REMAP -include "$HERE/shim/capture.h" -c "$1/$f.c" -o "$2.$f.o"
    done
    # shellcheck disable=SC2086
    "$GCC" $CFLAGS "$2.gtl24_cmds.o" "$2.gtl24_slots.o" "$HERE/virtual_atecc.c" "$HERE/test_gtl24.c" -o "$2"
}

if [ "${1:-}" != "--mutate" ]; then
    build "$MAIN" "$OUT/test_gtl24"
    exec "$OUT/test_gtl24"
fi
exec sh "$HERE/gtl24_mutate.sh"
