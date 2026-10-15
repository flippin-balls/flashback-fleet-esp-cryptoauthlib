/* Host shim: ESP_LOGx print like the target ("I (0) tag: ...") into the capture (capture.h). */
#pragma once
#include "capture.h"
#define ESP_LOGI(tag, fmt, ...) vt_printf("I (0) %s: " fmt "\n", tag, ##__VA_ARGS__)
#define ESP_LOGW(tag, fmt, ...) vt_printf("W (0) %s: " fmt "\n", tag, ##__VA_ARGS__)
#define ESP_LOGE(tag, fmt, ...) vt_printf("E (0) %s: " fmt "\n", tag, ##__VA_ARGS__)
