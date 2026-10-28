#include <open62541/server.h>
#if UA_MULTITHREADING < 100
#error This consumer test requires UA_MULTITHREADING=100
#endif
void consume_freertos_lock(void);
void consume_freertos_lock(void) {
    UA_Lock lock;
    UA_LOCK_INIT(&lock);
    UA_LOCK(&lock);
    UA_UNLOCK(&lock);
    UA_LOCK_DESTROY(&lock);
}
