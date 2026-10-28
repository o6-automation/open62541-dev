#include "FreeRTOS.h"
static inline TaskHandle_t xTaskGetCurrentTaskHandle(void) {
    return (TaskHandle_t)(uintptr_t)pthread_self();
}
