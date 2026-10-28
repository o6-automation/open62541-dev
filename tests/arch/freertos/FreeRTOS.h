/* Host test double for the FreeRTOS semaphore API. Actual kernel behaviour
 * must additionally be tested on a FreeRTOS target. */
#ifndef TEST_FREERTOS_H
#define TEST_FREERTOS_H
#include <pthread.h>
#include <stdint.h>
#ifndef configUSE_MUTEXES
#define configUSE_MUTEXES 1
#endif
#ifndef configUSE_RECURSIVE_MUTEXES
#define configUSE_RECURSIVE_MUTEXES 1
#endif
#ifndef INCLUDE_xTaskGetCurrentTaskHandle
#define INCLUDE_xTaskGetCurrentTaskHandle 1
#endif
#ifndef configSUPPORT_STATIC_ALLOCATION
#define configSUPPORT_STATIC_ALLOCATION 0
#endif
#ifndef configSUPPORT_DYNAMIC_ALLOCATION
#define configSUPPORT_DYNAMIC_ALLOCATION 1
#endif
/* Exercise the fallback even if the application has no assertion handler. */
#define configASSERT(x) ((void)0)
#define pdTRUE 1
#define portMAX_DELAY UINT32_MAX
typedef int BaseType_t;
typedef void *TaskHandle_t;
typedef struct {
    pthread_mutex_t native;
    int dynamic;
} StaticSemaphore_t;
typedef StaticSemaphore_t *SemaphoreHandle_t;
#endif
