#include "FreeRTOS.h"
SemaphoreHandle_t xSemaphoreCreateRecursiveMutex(void);
SemaphoreHandle_t xSemaphoreCreateRecursiveMutexStatic(StaticSemaphore_t *storage);
BaseType_t xSemaphoreTakeRecursive(SemaphoreHandle_t mutex, uint32_t ticks);
BaseType_t xSemaphoreGiveRecursive(SemaphoreHandle_t mutex);
void vSemaphoreDelete(SemaphoreHandle_t mutex);
