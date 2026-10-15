#!/bin/sh
# `build_gtl24.sh --mutate`: damage each rule of main/gtl24_cmds.c and main/gtl24_slots.c in a copy and require the
# suite to go RED against a GREEN baseline. STALE (the mutant no longer applies) and UNCOMPILABLE are not kills.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
MAIN="$(cd "$HERE/../../main" && pwd)"
python3 - "$HERE" "$MAIN" <<'PY'
import os, shutil, subprocess, sys, tempfile
here, main = sys.argv[1:3]
C, S = "gtl24_cmds.c", "gtl24_slots.c"
M = [
  # framing (gtl24_cmds.c)
  (C, "short payload tolerated",         "            ESP_LOGE(TAG, \"payload: got %u of %u bytes\", (unsigned)i, (unsigned)len);\n            return false;", "            ESP_LOGE(TAG, \"payload: got %u of %u bytes\", (unsigned)i, (unsigned)len);\n            break;"),
  (C, "terminator absence tolerated",    "        ESP_LOGE(TAG, \"payload: no NUL terminator after %u bytes\", (unsigned)len);\n        return false;", "        ESP_LOGE(TAG, \"payload: no NUL terminator after %u bytes\", (unsigned)len);"),
  (C, "terminator not checked",          "    if (b != 0) {", "    if (0) {"),
  (C, "settle check dropped (R1.2)",     "    if (console->read_bytes(&b, 1, pdMS_TO_TICKS(GTL24_SETTLE_MS)) > 0) {", "    if (0) {"),
  (C, "settle window zero",              "#define GTL24_SETTLE_MS      100", "#define GTL24_SETTLE_MS      0"),
  (C, "first-byte wait shortened",       "#define GTL24_FIRST_BYTE_MS  5000", "#define GTL24_FIRST_BYTE_MS  1000"),
  (C, "first-byte wait unbounded",       "#define GTL24_FIRST_BYTE_MS  5000", "#define GTL24_FIRST_BYTE_MS  600000"),
  (C, "next-byte wait unbounded (R1.1)", "#define GTL24_NEXT_BYTE_MS   1000", "#define GTL24_NEXT_BYTE_MS   600000"),
  (C, "first byte gets the short wait",  "(i == 0) ? GTL24_FIRST_BYTE_MS : GTL24_NEXT_BYTE_MS", "GTL24_NEXT_BYTE_MS"),
  (C, "no halt after a broken frame",    "    gtl24_halt();\n    return ESP_FAIL;", "    (void)gtl24_halt;\n    return ESP_FAIL;"),
  (C, "halt returns to the console loop", "        prompt();\n        for (;;) {", "        prompt();\n        return;\n        for (;;) {"),
  (C, "halted stub answers nothing",     "        finish(ESP_FAIL);\n        printf(\"HALTED", "        printf(\"HALTED"),
  (C, "halted stub prompts only once",   "    for (;;) {\n        prompt();\n        for (;;) {", "    prompt();\n    for (;;) {\n        for (;;) {"),
  (C, "reason before the Status line",   ["static esp_err_t fail_stop(const char *what)\n{\n    finish(ESP_FAIL);\n", "    gtl24_halt();\n    return ESP_FAIL;"], ["static esp_err_t fail_stop(const char *what)\n{\n", "    finish(ESP_FAIL);\n    gtl24_halt();\n    return ESP_FAIL;"]),
  (C, "bad write-slot args just fail",   "        return fail_stop(\"write-slot arguments: the payload length cannot be trusted\");", "        return finish(ESP_ERR_INVALID_ARG);"),
  (C, "bad write-pubkey args just fail", "        return fail_stop(\"write-pubkey arguments\");", "        return finish(ESP_ERR_INVALID_ARG);"),
  (C, "write-slot writes a broken frame", "    if (!consume_frame(buf, (size_t)len)) {\n        return fail_stop(\"write-slot payload\");\n    }", "    (void)consume_frame(buf, (size_t)len);"),
  (C, "CRC never checked (write-slot)",  "    if (have_crc && !crc32_matches(buf, (size_t)len, crc)) {", "    if (0) {"),
  (C, "CRC never checked (write-pubkey)", "    if (have_crc && !crc32_matches(pub, sizeof pub, crc)) {", "    if (0) {"),
  (C, "CRC mismatch tolerated",          "                 (unsigned)len, (unsigned long)got, (unsigned long)expected);\n        return false;", "                 (unsigned)len, (unsigned long)got, (unsigned long)expected);"),
  (C, "CRC over one byte less",          "esp_rom_crc32_le(0, buf, (uint32_t)len)", "esp_rom_crc32_le(0, buf, (uint32_t)len - 1u)"),
  (C, "CRC argument ignored (write-slot)", "const bool have_crc = (argc == 5);", "const bool have_crc = false;"),
  (C, "CRC argument ignored (write-pubkey)", "const bool have_crc = (argc == 3);", "const bool have_crc = false;"),
  (C, "malformed CRC accepted",          "(have_crc && !parse_crc32(argv[4], &crc))) {", "(have_crc && !parse_crc32(argv[4], &crc) && 0)) {"),
  (C, "plus sign accepted",              "        if (*p < '0' || *p > '9') {", "        if ((*p < '0' || *p > '9') && *p != '+') {"),
  (C, "CRC wider than 32 bits accepted", "v > 0xFFFFFFFFull", "v > 0x1FFFFFFFFull"),
  (C, "CRC upper bound exclusive",       "v > 0xFFFFFFFFull", "v >= 0xFFFFFFFFull"),
  (C, "write-slot argc 6 accepted",      "if ((argc != 4 && argc != 5) ||", "if ((argc < 4) ||"),
  (C, "write-pubkey argc 4 accepted",    "if ((argc != 2 && argc != 3) ||", "if ((argc < 2) ||"),
  (C, "write-slot readiness unchecked",  "    if (!ready) {\n        return finish(ESP_ERR_INVALID_STATE);\n    }\n    return finish(atecc_write_slot(", "    return finish(atecc_write_slot("),
  (C, "write-pubkey readiness unchecked (cmd)", "    if (!ready) {\n        return finish(ESP_ERR_INVALID_STATE);\n    }\n    return finish(atecc_write_pubkey_slot(", "    return finish(atecc_write_pubkey_slot("),
  (C, "uninitialised write-slot frame left", "        ESP_LOGE(TAG, \"Please initialize device before calling this function\");\n    } else {\n        printf(\"Reading %d bytes", "        ESP_LOGE(TAG, \"Please initialize device before calling this function\");\n        return finish(ESP_ERR_INVALID_STATE);\n    } else {\n        printf(\"Reading %d bytes"),
  (C, "uninitialised write-pubkey frame left", "        ESP_LOGE(TAG, \"Please initialize device before calling this function\");\n    } else {\n        printf(\"Reading 64 bytes", "        ESP_LOGE(TAG, \"Please initialize device before calling this function\");\n        return finish(ESP_ERR_INVALID_STATE);\n    } else {\n        printf(\"Reading 64 bytes"),
  (C, "uninitialised write-slot skips the CRC (R1.1)", "    if (have_crc && !crc32_matches(buf, (size_t)len, crc)) {\n        return fail_stop(\"write-slot payload CRC32\");\n    }\n    if (!ready) {\n        return finish(ESP_ERR_INVALID_STATE);\n    }", "    if (!ready) {\n        return finish(ESP_ERR_INVALID_STATE);\n    }\n    if (have_crc && !crc32_matches(buf, (size_t)len, crc)) {\n        return fail_stop(\"write-slot payload CRC32\");\n    }"),
  (C, "uninitialised write-pubkey skips the CRC (R1.1)", "    if (have_crc && !crc32_matches(pub, sizeof pub, crc)) {\n        return fail_stop(\"write-pubkey payload CRC32\");\n    }\n    if (!ready) {\n        return finish(ESP_ERR_INVALID_STATE);\n    }", "    if (!ready) {\n        return finish(ESP_ERR_INVALID_STATE);\n    }\n    if (have_crc && !crc32_matches(pub, sizeof pub, crc)) {\n        return fail_stop(\"write-pubkey payload CRC32\");\n    }"),
  (C, "write-pubkey writes a broken frame", "    if (!consume_frame(pub, sizeof pub)) {\n        return fail_stop(\"write-pubkey payload\");\n    }", "    (void)consume_frame(pub, sizeof pub);"),
  # parsing and readiness (gtl24_cmds.c)
  (C, "parse accepts trailing junk",     "end == tok || *end != '\\0' ||", "end == tok ||"),
  (C, "parse ignores the upper bound",   "v < lo || v > hi)", "v < lo || (v > hi && 0))"),
  (C, "parse ignores the lower bound",   "v < lo || v > hi)", "(v < lo && 0) || v > hi)"),
  # (not listed: dropping the errno test is EQUIVALENT -- every bound here is far below LONG_MAX, so an overflowed
  #  strtol result is out of range either way)
  (C, "write-slot len 0 allowed",        "!parse_int(argv[3], 1, GTL24_MAX_WRITE, &len)", "!parse_int(argv[3], 0, GTL24_MAX_WRITE, &len)"),
  (C, "write-pubkey slot 7 allowed",     "!parse_int(argv[1], 8, 15, &slot)", "!parse_int(argv[1], 7, 15, &slot)"),
  (C, "read-slot readiness unchecked",   "    if (!ecu_cli_atecc_ready()) {\n        ESP_LOGE(TAG, \"Please initialize device before calling this function\");\n        return finish(ESP_ERR_INVALID_STATE);\n    }\n    const esp_err_t ret", "    const esp_err_t ret"),
  (C, "lock-slot readiness unchecked",   "    if (!ecu_cli_atecc_ready()) {\n        ESP_LOGE(TAG, \"Please initialize device before calling this function\");\n        return finish(ESP_ERR_INVALID_STATE);\n    }\n    return finish(atecc_lock_slot", "    return finish(atecc_lock_slot"),
  (C, "sleep readiness unchecked (cmd)", "    if (!ecu_cli_atecc_ready()) {\n        ESP_LOGE(TAG, \"Please initialize device before calling this function\");\n        return finish(ESP_ERR_INVALID_STATE);\n    }\n    return finish(atecc_sleep", "    return finish(atecc_sleep"),
  (C, "read-slot Data before Status",    "    finish(ret);\n    if (ret == ESP_OK) {\n        printf(\"\\nData: \");", "    if (ret == ESP_OK) {\n        printf(\"\\nData: \");"),
  (C, "read-slot Data on failure",       "    finish(ret);\n    if (ret == ESP_OK) {", "    finish(ret);\n    if (1) {"),
  (C, "status inverted",                 "(ret == ESP_OK) ? \"Success\" : \"Failure\"", "(ret != ESP_OK) ? \"Success\" : \"Failure\""),
  (C, "write-slot ignores the handler",  "    return finish(atecc_write_slot(slot, offset, buf, (size_t)len, &err_code));", "    (void)atecc_write_slot(slot, offset, buf, (size_t)len, &err_code);\n    return finish(ESP_OK);"),
  (C, "sleep registered under another name", ".command = \"sleep\"", ".command = \"sleep-atecc\""),
  # chip operations (gtl24_slots.c)
  (S, "write unaligned offset allowed",  "if ((offset % 4) != 0 || (data_len % 4) != 0 ||", "if ((data_len % 4) != 0 ||"),
  (S, "write unaligned length allowed",  "if ((offset % 4) != 0 || (data_len % 4) != 0 ||", "if ((offset % 4) != 0 ||"),
  (S, "write past the slot allowed",     "|| (size_t)offset + data_len > (size_t)slot_size(slot)) {", ") {"),
  (S, "slot 8 sized like the others",    "    if (slot == 8) {\n        return 416;\n    }\n", ""),
  (S, "slots 0-7 sized 72",              "    if (slot < 8) {\n        return 36;\n    }\n", ""),
  (S, "write readiness unchecked",       "esp_err_t atecc_write_slot(int slot, int offset, unsigned char *data_buf, size_t data_len, int *err_ret)\n{\n    int ret = ATCA_BAD_PARAM;\n    if (!atecc_is_initialized()) {", "esp_err_t atecc_write_slot(int slot, int offset, unsigned char *data_buf, size_t data_len, int *err_ret)\n{\n    int ret = ATCA_BAD_PARAM;\n    if (0) {"),
  (S, "write success on chip refusal",   "        ESP_LOGE(TAG, \"write-slot %d failed, returned %02x\", slot, ret);\n        goto exit;", "        ESP_LOGE(TAG, \"write-slot %d failed, returned %02x\", slot, ret);"),
  (S, "read unaligned length allowed",   "data_len == 0 || (data_len % 4) != 0 ||", "data_len == 0 ||"),
  (S, "read past the slot allowed",      "        data_len > (size_t)slot_size(slot)) {", "        0) {"),
  (S, "read success on chip refusal",    "        ESP_LOGE(TAG, \"read-slot %d failed, returned %02x\", slot, ret);\n        goto exit;", "        ESP_LOGE(TAG, \"read-slot %d failed, returned %02x\", slot, ret);"),
  (S, "lock success on chip refusal",    "        ESP_LOGE(TAG, \"lock-slot %d failed, returned %02x\", slot, ret);\n        goto exit;", "        ESP_LOGE(TAG, \"lock-slot %d failed, returned %02x\", slot, ret);"),
  (S, "lock readiness unchecked",        "esp_err_t atecc_lock_slot(int slot, int *err_ret)\n{\n    int ret = ATCA_BAD_PARAM;\n    if (!atecc_is_initialized()) {", "esp_err_t atecc_lock_slot(int slot, int *err_ret)\n{\n    int ret = ATCA_BAD_PARAM;\n    if (0) {"),
  (S, "pubkey via write_bytes_zone",     "    ret = atcab_write_pubkey((uint16_t)slot, pubkey64);", "    { uint8_t f_[72] = {0}; for (int i_ = 0; i_ < 32; i_++) { f_[4 + i_] = pubkey64[i_]; f_[40 + i_] = pubkey64[32 + i_]; }\n      ret = atcab_write_bytes_zone(ATCA_ZONE_DATA, (uint16_t)slot, 0, f_, 72); }"),
  (S, "pubkey slot 7 allowed",           "if (pubkey64 == NULL || slot < 8 || slot > 15) {", "if (pubkey64 == NULL || slot < 7 || slot > 15) {"),
  (S, "pubkey success on chip refusal",  "        ESP_LOGE(TAG, \"write-pubkey %d failed, returned %02x\", slot, ret);\n        goto exit;", "        ESP_LOGE(TAG, \"write-pubkey %d failed, returned %02x\", slot, ret);"),
  (S, "pubkey readiness unchecked",      "esp_err_t atecc_write_pubkey_slot(int slot, const unsigned char *pubkey64, int *err_ret)\n{\n    int ret = ATCA_BAD_PARAM;\n    if (!atecc_is_initialized()) {", "esp_err_t atecc_write_pubkey_slot(int slot, const unsigned char *pubkey64, int *err_ret)\n{\n    int ret = ATCA_BAD_PARAM;\n    if (0) {"),
  (S, "sleep readiness unchecked",       "        ESP_LOGE(TAG, \"Device is not initialized\");\n        *err_ret = ret;\n        return ESP_FAIL;", "        ESP_LOGE(TAG, \"Device is not initialized\");\n        *err_ret = ret;"),
  (S, "sleep result ignored",            "    return (ret == ATCA_SUCCESS) ? ESP_OK : ESP_FAIL;\n}", "    return ESP_OK;\n}"),
]
def run(srcdir):
    env = dict(os.environ, GTL24_OUT=os.path.join(srcdir, "o"))
    b = os.path.join(srcdir, "o"); os.makedirs(b, exist_ok=True)
    cflags = ["-std=gnu11", "-O1", "-Wall", "-Wextra", "-Werror", "-I", os.path.join(here, "shim"), "-I", main, "-I", here]
    objs = []
    for f in ("gtl24_cmds", "gtl24_slots"):
        o = os.path.join(b, f + ".o")
        c = subprocess.run(["gcc"] + cflags + ["-DGTL24_HOST_TEST", "-DVT_CAPTURE_REMAP", "-include", os.path.join(here, "shim/capture.h"), "-c", os.path.join(srcdir, f + ".c"), "-o", o], capture_output=True)
        if c.returncode: return "uncompilable"
        objs.append(o)
    exe = os.path.join(b, "t")
    c = subprocess.run(["gcc"] + cflags + objs + [os.path.join(here, "virtual_atecc.c"), os.path.join(here, "test_gtl24.c"), "-o", exe], capture_output=True)
    if c.returncode: return "uncompilable"
    return "pass" if subprocess.run([exe], capture_output=True, timeout=60).returncode == 0 else "fail"
tmp = tempfile.mkdtemp()
base = os.path.join(tmp, "base"); os.makedirs(base)
for f in (C, S): shutil.copy(os.path.join(main, f), base)
if run(base) != "pass":
    print("MUTATION: baseline is not GREEN"); sys.exit(2)
killed = other = 0
for f, name, a, b in M:
    d = tempfile.mkdtemp(dir=tmp)
    for g in (C, S): shutil.copy(os.path.join(main, g), d)
    s = open(os.path.join(d, f)).read()
    pairs = list(zip(a, b)) if isinstance(a, list) else [(a, b)]
    if any(s.count(x) != 1 for x, _ in pairs): print("  STALE        %s" % name); other += 1; continue
    for x, y in pairs: s = s.replace(x, y, 1)
    open(os.path.join(d, f), "w").write(s)
    r = run(d)
    if r == "fail": killed += 1; print("  killed       %s" % name)
    else: other += 1; print("  %-12s %s" % ("UNCOMPILABLE" if r == "uncompilable" else "SURVIVED", name))
shutil.rmtree(tmp, ignore_errors=True)
print("MUTATION: %d killed, %d survived/stale/uncompilable" % (killed, other))
sys.exit(0 if other == 0 else 1)
PY
