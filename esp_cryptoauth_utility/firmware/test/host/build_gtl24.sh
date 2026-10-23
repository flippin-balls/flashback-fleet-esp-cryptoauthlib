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
        "$GCC" $CFLAGS -DGTL24_HOST_TEST -DVT_CAPTURE_REMAP -include "$HERE/shim/capture.h" -c "$1/$f.c" -o "$2.$f.o"
    done
    # shellcheck disable=SC2086
    "$GCC" $CFLAGS "$2.gtl24_cmds.o" "$2.gtl24_slots.o" "$HERE/virtual_atecc.c" "$HERE/test_gtl24.c" -o "$2"
}

# Source asserts -- the target-only code the host build cannot run.
python3 - "$MAIN" "$HERE/../.." <<'PY'
import os, re, sys
main, fw = sys.argv[1:3]
src = lambda f: open(os.path.join(main, f)).read()
bad = []
cmds = src("gtl24_cmds.c")
body = cmds[cmds.index("static void gtl24_halt(void)\n{"):]
body = body[:body.index("\n}\n")]
target = re.sub(r"#ifdef GTL24_HOST_TEST.*?#endif", "", body, flags=re.S)
if "return" in target or target.count("for (;;)") != 2:
    bad.append("gtl24_halt must never return on the target (only under GTL24_HOST_TEST)")
for root, _, files in os.walk(fw):
    if "/test/" in root + "/" or "/build" in root or "/managed_components" in root:
        continue
    for f in files:
        if f in ("gtl24_cmds.c",) or not (f.endswith((".c", ".h", ".txt", ".cmake")) or f.startswith("sdkconfig")):
            continue
        if "GTL24_HOST_TEST" in open(os.path.join(root, f), errors="replace").read():
            bad.append("GTL24_HOST_TEST appears in the firmware build: %s" % os.path.join(root, f))
if cmds.count("GTL24_HOST_TEST") != 1:
    bad.append("gtl24_cmds.c: GTL24_HOST_TEST must guard only the halt's test exit")
if len(re.findall(r"\bregister_gtl24_commands\(\)", src("commands.c"))) != 1:
    bad.append("commands.c must call register_gtl24_commands() exactly once")
for f in ("commands.c", "handlers.c", "handlers.h"):
    for name in ('"write-slot"', '"read-slot"', '"lock-slot"', '"write-pubkey"', '"write-data"'):
        if name in src(f):
            bad.append("%s still carries %s (the commands live in gtl24_*.c)" % (f, name))
    if re.search(r"\batecc_(write_slot|read_slot|lock_slot|write_pubkey_slot|sleep)\s*\(", src(f)):
        bad.append("%s still carries a GTL 24 atecc_* function (they live in gtl24_slots.c)" % f)
# commands.c generate-keys (not host-built): template v2 generates keys in slots 0, 2 AND 4; the upstream `< 3` slot
# limit refused slot 4 on the 11b bench unit after the config lock (IkV6BHhH).
gk = re.search(r"static esp_err_t generate_key_pair\(int argc, char \*\*argv\)\s*\{(.*?)\n\}", src("commands.c"), re.S)
if not gk or "atoi(" in gk.group(1) or not re.search(r"argc == 2 && genkey_slot_arg\(argv\[1\], &slot\)", gk.group(1)) \
        or "atecc_keygen(slot," not in gk.group(1):
    bad.append("commands.c generate_key_pair must parse its slot with genkey_slot_arg (whole token, 0-15) and pass it on")
gp = re.search(r"static bool genkey_slot_arg\(const char \*tok, int \*slot\)\s*\{(.*?)\n\}", src("commands.c"), re.S)
if not gp or "v < 0 || v > 15" not in gp.group(1) or "*end != '\\0'" not in gp.group(1):
    bad.append("commands.c genkey_slot_arg must accept exactly one whole decimal token in 0-15")
# app_main.c scli_loop (not host-built): a line whose first byte is a NUL must not write linebuf[-1] (I9y7WaYU).
loop = src("app_main.c")
if "strlen((char *)linebuf) - 1" in loop or len(re.findall(
        r"const size_t n = strlen\(\(char \*\)linebuf\);\s*\n\s*if \(n > 0\) \{\s*\n\s*linebuf\[n - 1\] = '\\0';", loop)) != 1:
    bad.append("app_main.c: the console loop must drop the last character only when the line is not empty")
for b in bad:
    print("SOURCE ASSERT: " + b)
sys.exit(1 if bad else 0)
PY

if [ "${1:-}" != "--mutate" ]; then
    build "$MAIN" "$OUT/test_gtl24"
    exec "$OUT/test_gtl24"
fi
exec sh "$HERE/gtl24_mutate.sh"
