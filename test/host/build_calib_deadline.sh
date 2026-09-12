#!/usr/bin/env sh
# Drive the REAL calib_execute_command() with a stubbed transport and an injected clock.
# Unlike a simulated loop, removing the enforcement from calib_execution.c FAILS this test.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
OUT="$HERE/build"; GCC="${GCC:-gcc}"
mkdir -p "$OUT"
"$GCC" -std=c11 -O0 -Wall \
    -I "$ROOT/port" -I "$HERE/stubs" \
    -I "$ROOT/cryptoauthlib/lib" -I "$ROOT/cryptoauthlib/lib/hal" -I "$ROOT/cryptoauthlib/lib/calib" \
    "$ROOT/cryptoauthlib/lib/calib/calib_execution.c" \
    "$ROOT/cryptoauthlib/lib/hal/atca_deadline.c" \
    "$HERE/test_calib_deadline.c" \
    -o "$OUT/test_calib_deadline"
echo "built $OUT/test_calib_deadline"
"$OUT/test_calib_deadline"
