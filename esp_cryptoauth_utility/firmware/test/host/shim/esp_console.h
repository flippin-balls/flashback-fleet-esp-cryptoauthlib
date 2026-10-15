/* Host shim: the esp_console registration the GTL 24 commands use; registered commands land in vt_cmds[]. */
#pragma once
#include "esp_err.h"
typedef int (*esp_console_cmd_func_t)(int argc, char **argv);
typedef struct {
    const char *command;
    const char *help;
    const char *hint;
    esp_console_cmd_func_t func;
    void *argtable;
} esp_console_cmd_t;
esp_err_t esp_console_cmd_register(const esp_console_cmd_t *cmd);
