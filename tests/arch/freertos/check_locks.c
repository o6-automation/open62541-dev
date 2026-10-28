/* Test the generated architecture header against a pthread-backed semaphore
 * test double. CHECK is intentionally independent of NDEBUG/UA_DEBUG. */
#include <assert.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define UA_MULTITHREADING 100
#define UA_INLINE inline
#ifdef UA_DEBUG
#define UA_assert(x) assert(x)
#else
#define UA_assert(x) ((void)0)
#endif
#define UA_STATIC_THREAD_LOCAL static _Thread_local
#include "freertos_generated.h"

#define CHECK(x) do { if(!(x)) abort(); } while(0)
static int failAllocation, timeouts, dynamicCreates, staticCreates;
static UA_Lock lock;
static unsigned counter;

static SemaphoreHandle_t createMutex(StaticSemaphore_t *p, int dynamic) {
    if(failAllocation)
        return NULL;
    pthread_mutexattr_t attr;
    CHECK(pthread_mutexattr_init(&attr) == 0);
    CHECK(pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE) == 0);
    CHECK(pthread_mutex_init(&p->native, &attr) == 0);
    CHECK(pthread_mutexattr_destroy(&attr) == 0);
    p->dynamic = dynamic;
    return p;
}
SemaphoreHandle_t xSemaphoreCreateRecursiveMutex(void) {
    dynamicCreates++;
    if(failAllocation)
        return NULL;
    StaticSemaphore_t *p = (StaticSemaphore_t*)malloc(sizeof(*p));
    CHECK(p);
    return createMutex(p, 1);
}
SemaphoreHandle_t xSemaphoreCreateRecursiveMutexStatic(StaticSemaphore_t *p) {
    staticCreates++;
    return createMutex(p, 0);
}
BaseType_t xSemaphoreTakeRecursive(SemaphoreHandle_t p, uint32_t ticks) {
    CHECK(ticks == portMAX_DELAY);
    if(timeouts) { timeouts--; return 0; }
    return pthread_mutex_lock(&p->native) == 0;
}
BaseType_t xSemaphoreGiveRecursive(SemaphoreHandle_t p) {
    return pthread_mutex_unlock(&p->native) == 0;
}
void vSemaphoreDelete(SemaphoreHandle_t p) {
    CHECK(pthread_mutex_destroy(&p->native) == 0);
    if(p->dynamic)
        free(p);
}
static void automaticBuffer(unsigned n) {
    UA_STATIC_THREAD_LOCAL unsigned value;
    value = n;
    if(n)
        automaticBuffer(n - 1);
    CHECK(value == n);
}
static void *worker(void *arg) {
    (void)arg;
    for(unsigned i = 0; i < 10000; ++i) {
        UA_LOCK(&lock);
        UA_LOCK(&lock);
        UA_LOCK_ASSERT(&lock);
        unsigned value = counter;
        sched_yield(); /* Give competing threads a chance to expose races. */
        counter = value + 1;
        UA_UNLOCK(&lock);
        UA_UNLOCK(&lock);
    }
    return NULL;
}
static void *wrongOwner(void *arg) {
    (void)arg;
    UA_UNLOCK(&lock);
    return NULL;
}
int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "normal";
    if(strcmp(mode, "allocation-failure") == 0)
        failAllocation = 1;
    UA_LOCK_INIT(&lock);
    CHECK(dynamicCreates == !configSUPPORT_STATIC_ALLOCATION);
    CHECK(staticCreates == !!configSUPPORT_STATIC_ALLOCATION);
    if(strcmp(mode, "destroy-held") == 0) {
        UA_LOCK(&lock);
        UA_LOCK_DESTROY(&lock);
        return 0;
    }
    if(strcmp(mode, "wrong-owner") == 0) {
        UA_LOCK(&lock);
        pthread_t t;
        CHECK(pthread_create(&t, NULL, wrongOwner, NULL) == 0);
        CHECK(pthread_join(t, NULL) == 0);
        return 0;
    }
    timeouts = 2;
    UA_LOCK(&lock);
    CHECK(timeouts == 0);
    UA_UNLOCK(&lock);
    pthread_t threads[4];
    for(unsigned i = 0; i < 4; i++)
        CHECK(pthread_create(&threads[i], NULL, worker, NULL) == 0);
    for(unsigned i = 0; i < 4; i++)
        CHECK(pthread_join(threads[i], NULL) == 0);
    CHECK(counter == 40000);
    CHECK(lock.count == 0 && lock.owner == NULL);
    UA_LOCK_DESTROY(&lock);
    automaticBuffer(8);
    puts("PASS: recursion, contention, timeout retry, cleanup, automatic buffers");
    return 0;
}
