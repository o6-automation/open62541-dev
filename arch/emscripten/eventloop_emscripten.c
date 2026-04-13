/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2026 (c) o6 Automation GmbH (Author: Andreas Ebner)
 */

#include "eventloop_emscripten.h"

#if defined(__EMSCRIPTEN__)

#include <open62541/plugin/eventloop.h>
#include <emscripten/emscripten.h>
#include <emscripten/html5.h>

/*********/
/* Timer */
/*********/

static UA_DateTime
UA_EventLoopEmscripten_nextTimer(UA_EventLoop *public_el) {
    UA_EventLoopEmscripten *el = (UA_EventLoopEmscripten *)public_el;
    if(el->delayedHead)
        return el->eventLoop.dateTime_nowMonotonic(&el->eventLoop);
    return UA_Timer_next(&el->timer);
}

static UA_StatusCode
UA_EventLoopEmscripten_addTimer(UA_EventLoop *public_el, UA_Callback cb,
                                void *application, void *data,
                                UA_Double interval_ms, UA_DateTime *baseTime,
                                UA_TimerPolicy timerPolicy,
                                UA_UInt64 *callbackId) {
    UA_EventLoopEmscripten *el = (UA_EventLoopEmscripten *)public_el;
    return UA_Timer_add(&el->timer, cb, application, data, interval_ms,
                        public_el->dateTime_nowMonotonic(public_el),
                        baseTime, timerPolicy, callbackId);
}

static UA_StatusCode
UA_EventLoopEmscripten_modifyTimer(UA_EventLoop *public_el,
                                   UA_UInt64 callbackId,
                                   UA_Double interval_ms,
                                   UA_DateTime *baseTime,
                                   UA_TimerPolicy timerPolicy) {
    UA_EventLoopEmscripten *el = (UA_EventLoopEmscripten *)public_el;
    return UA_Timer_modify(&el->timer, callbackId, interval_ms,
                           public_el->dateTime_nowMonotonic(public_el),
                           baseTime, timerPolicy);
}

static void
UA_EventLoopEmscripten_removeTimer(UA_EventLoop *public_el,
                                   UA_UInt64 callbackId) {
    UA_EventLoopEmscripten *el = (UA_EventLoopEmscripten *)public_el;
    UA_Timer_remove(&el->timer, callbackId);
}

/**********************/
/* Delayed Callbacks  */
/**********************/

static void
UA_EventLoopEmscripten_addDelayedCallback(UA_EventLoop *public_el,
                                          UA_DelayedCallback *dc) {
    UA_EventLoopEmscripten *el = (UA_EventLoopEmscripten *)public_el;
    dc->next = NULL;
    *el->delayedTail = dc;
    el->delayedTail = &dc->next;
}

static void
UA_EventLoopEmscripten_removeDelayedCallback(UA_EventLoop *public_el,
                                             UA_DelayedCallback *dc) {
    UA_EventLoopEmscripten *el = (UA_EventLoopEmscripten *)public_el;

    /* Rebuild the queue without the target entry */
    UA_DelayedCallback *oldHead = el->delayedHead;
    el->delayedHead = NULL;
    el->delayedTail = &el->delayedHead;

    UA_DelayedCallback *cur = oldHead;
    while(cur) {
        UA_DelayedCallback *next = cur->next;
        if(cur != dc)
            UA_EventLoopEmscripten_addDelayedCallback(public_el, cur);
        cur = next;
    }
}

static void
processDelayed(UA_EventLoopEmscripten *el) {
    UA_DelayedCallback *dc = el->delayedHead;
    el->delayedHead = NULL;
    el->delayedTail = &el->delayedHead;

    while(dc) {
        UA_DelayedCallback *next = dc->next;
        if(dc->callback)
            dc->callback(dc->application, dc->context);
        dc = next;
    }
}

/***********************/
/* EventLoop Lifecycle */
/***********************/

static UA_StatusCode
UA_EventLoopEmscripten_start(UA_EventLoop *public_el) {
    UA_EventLoopEmscripten *el = (UA_EventLoopEmscripten *)public_el;

    if(el->eventLoop.state != UA_EVENTLOOPSTATE_FRESH &&
       el->eventLoop.state != UA_EVENTLOOPSTATE_STOPPED) {
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    UA_LOG_DEBUG(el->eventLoop.logger, UA_LOGCATEGORY_EVENTLOOP,
                 "Starting the Emscripten EventLoop");

    /* Start all registered EventSources */
    UA_StatusCode res = UA_STATUSCODE_GOOD;
    UA_EventSource *es = el->eventLoop.eventSources;
    while(es) {
        res |= es->start(es);
        es = es->next;
    }

    *(UA_EventLoopState *)(uintptr_t)&el->eventLoop.state =
        UA_EVENTLOOPSTATE_STARTED;

    return res;
}

static void
checkClosed(UA_EventLoopEmscripten *el) {
    UA_EventSource *es = el->eventLoop.eventSources;
    while(es) {
        if(es->state != UA_EVENTSOURCESTATE_STOPPED)
            return;
        es = es->next;
    }

    if(el->delayedHead)
        return;

    *(UA_EventLoopState *)(uintptr_t)&el->eventLoop.state =
        UA_EVENTLOOPSTATE_STOPPED;

    UA_LOG_DEBUG(el->eventLoop.logger, UA_LOGCATEGORY_EVENTLOOP,
                 "The Emscripten EventLoop has stopped");
}

static void
UA_EventLoopEmscripten_stop(UA_EventLoop *public_el) {
    UA_EventLoopEmscripten *el = (UA_EventLoopEmscripten *)public_el;

    if(el->eventLoop.state != UA_EVENTLOOPSTATE_STARTED) {
        UA_LOG_WARNING(el->eventLoop.logger, UA_LOGCATEGORY_EVENTLOOP,
                       "The EventLoop is not running, cannot be stopped");
        return;
    }

    UA_LOG_DEBUG(el->eventLoop.logger, UA_LOGCATEGORY_EVENTLOOP,
                 "Stopping the Emscripten EventLoop");

    *(UA_EventLoopState *)(uintptr_t)&el->eventLoop.state =
        UA_EVENTLOOPSTATE_STOPPING;

    /* Stop all event sources */
    UA_EventSource *es = el->eventLoop.eventSources;
    for(; es; es = es->next) {
        if(es->state == UA_EVENTSOURCESTATE_STARTING ||
           es->state == UA_EVENTSOURCESTATE_STARTED) {
            es->stop(es);
        }
    }

    checkClosed(el);
}

static UA_StatusCode
UA_EventLoopEmscripten_run(UA_EventLoop *public_el, UA_UInt32 timeout) {
    UA_EventLoopEmscripten *el = (UA_EventLoopEmscripten *)public_el;

    if(el->executing) {
        /* Re-entrant call — should not normally happen, return early */
        return UA_STATUSCODE_GOOD;
    }

    el->executing = true;

    if(el->eventLoop.state == UA_EVENTLOOPSTATE_FRESH ||
       el->eventLoop.state == UA_EVENTLOOPSTATE_STOPPED) {
        UA_LOG_WARNING(el->eventLoop.logger, UA_LOGCATEGORY_EVENTLOOP,
                       "Cannot run a stopped EventLoop");
        el->executing = false;
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    /* Process timer callbacks */
    UA_DateTime now = el->eventLoop.dateTime_nowMonotonic(&el->eventLoop);
    UA_Timer_process(&el->timer, now);

    /* Process delayed callbacks */
    processDelayed(el);

    /* Check if we finished stopping */
    if(el->eventLoop.state == UA_EVENTLOOPSTATE_STOPPING)
        checkClosed(el);

    /* If a non-zero timeout is requested (synchronous service call),
     * yield to the browser event loop so WebSocket callbacks can fire.
     * The timeout parameter > 0 indicates the caller is willing to wait
     * for data. Requires ASYNCIFY. */
    if(timeout > 0) {
        el->executing = false;
        emscripten_sleep(1);
        return UA_STATUSCODE_GOOD;
    }

    el->executing = false;
    return UA_STATUSCODE_GOOD;
}

static void
UA_EventLoopEmscripten_cancel(UA_EventLoop *public_el) {
    /* No-op: the Emscripten EventLoop doesn't block */
    (void)public_el;
}

/*****************************/
/* Registering Event Sources */
/*****************************/

static UA_StatusCode
UA_EventLoopEmscripten_registerEventSource(UA_EventLoop *public_el,
                                           UA_EventSource *es) {
    UA_EventLoopEmscripten *el = (UA_EventLoopEmscripten *)public_el;

    if(es->state != UA_EVENTSOURCESTATE_FRESH) {
        UA_LOG_ERROR(el->eventLoop.logger, UA_LOGCATEGORY_NETWORK,
                     "Cannot register the EventSource \"%.*s\": already registered",
                     (int)es->name.length, (char *)es->name.data);
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    es->next = el->eventLoop.eventSources;
    el->eventLoop.eventSources = es;
    es->eventLoop = &el->eventLoop;
    es->state = UA_EVENTSOURCESTATE_STOPPED;

    UA_StatusCode res = UA_STATUSCODE_GOOD;
    if(el->eventLoop.state == UA_EVENTLOOPSTATE_STARTED)
        res = es->start(es);

    return res;
}

static UA_StatusCode
UA_EventLoopEmscripten_deregisterEventSource(UA_EventLoop *public_el,
                                             UA_EventSource *es) {
    UA_EventLoopEmscripten *el = (UA_EventLoopEmscripten *)public_el;

    if(es->state != UA_EVENTSOURCESTATE_STOPPED) {
        UA_LOG_WARNING(el->eventLoop.logger, UA_LOGCATEGORY_EVENTLOOP,
                       "Cannot deregister the EventSource %.*s: must be stopped first",
                       (int)es->name.length, es->name.data);
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    UA_EventSource **s = &el->eventLoop.eventSources;
    while(*s) {
        if(*s == es) {
            *s = es->next;
            break;
        }
        s = &(*s)->next;
    }

    es->state = UA_EVENTSOURCESTATE_FRESH;
    return UA_STATUSCODE_GOOD;
}

/***************/
/* Time Domain */
/***************/

static UA_DateTime
UA_EventLoopEmscripten_DateTime_now(UA_EventLoop *el) {
    (void)el;
    double ms = emscripten_date_now();
    return (UA_DateTime)((ms * UA_DATETIME_MSEC) + UA_DATETIME_UNIX_EPOCH);
}

static UA_DateTime
UA_EventLoopEmscripten_DateTime_nowMonotonic(UA_EventLoop *el) {
    (void)el;
    double ms = emscripten_get_now();
    return (UA_DateTime)((ms * UA_DATETIME_MSEC) + UA_DATETIME_UNIX_EPOCH);
}

static UA_Int64
UA_EventLoopEmscripten_DateTime_localTimeUtcOffset(UA_EventLoop *el) {
    (void)el;
    return UA_DateTime_localTimeUtcOffset();
}

/*************************/
/* Initialize and Delete */
/*************************/

static UA_StatusCode
UA_EventLoopEmscripten_free(UA_EventLoop *public_el) {
    UA_EventLoopEmscripten *el = (UA_EventLoopEmscripten *)public_el;

    if(el->eventLoop.state != UA_EVENTLOOPSTATE_STOPPED &&
       el->eventLoop.state != UA_EVENTLOOPSTATE_FRESH) {
        UA_LOG_WARNING(el->eventLoop.logger, UA_LOGCATEGORY_EVENTLOOP,
                       "Cannot delete a running EventLoop");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    /* Deregister and delete all EventSources */
    while(el->eventLoop.eventSources) {
        UA_EventSource *es = el->eventLoop.eventSources;
        UA_EventLoopEmscripten_deregisterEventSource(&el->eventLoop, es);
        es->free(es);
    }

    UA_Timer_clear(&el->timer);
    processDelayed(el);
    UA_KeyValueMap_clear(&el->eventLoop.params);
    UA_free(el);
    return UA_STATUSCODE_GOOD;
}

/* No-op locking — Emscripten is single-threaded */
static void UA_EventLoopEmscripten_lock(UA_EventLoop *el) { (void)el; }
static void UA_EventLoopEmscripten_unlock(UA_EventLoop *el) { (void)el; }

UA_EventLoop *
UA_EventLoop_new_Emscripten(const UA_Logger *logger) {
    UA_EventLoopEmscripten *el = (UA_EventLoopEmscripten *)
        UA_calloc(1, sizeof(UA_EventLoopEmscripten));
    if(!el)
        return NULL;

    UA_Timer_init(&el->timer);
    el->delayedHead = NULL;
    el->delayedTail = &el->delayedHead;

    el->eventLoop.logger = logger;

    /* Lifecycle */
    el->eventLoop.start  = UA_EventLoopEmscripten_start;
    el->eventLoop.stop   = UA_EventLoopEmscripten_stop;
    el->eventLoop.free   = UA_EventLoopEmscripten_free;
    el->eventLoop.run    = UA_EventLoopEmscripten_run;
    el->eventLoop.cancel = UA_EventLoopEmscripten_cancel;

    /* Time */
    el->eventLoop.dateTime_now = UA_EventLoopEmscripten_DateTime_now;
    el->eventLoop.dateTime_nowMonotonic =
        UA_EventLoopEmscripten_DateTime_nowMonotonic;
    el->eventLoop.dateTime_localTimeUtcOffset =
        UA_EventLoopEmscripten_DateTime_localTimeUtcOffset;

    /* Timers */
    el->eventLoop.nextTimer    = UA_EventLoopEmscripten_nextTimer;
    el->eventLoop.addTimer     = UA_EventLoopEmscripten_addTimer;
    el->eventLoop.modifyTimer  = UA_EventLoopEmscripten_modifyTimer;
    el->eventLoop.removeTimer  = UA_EventLoopEmscripten_removeTimer;

    /* Delayed callbacks */
    el->eventLoop.addDelayedCallback    = UA_EventLoopEmscripten_addDelayedCallback;
    el->eventLoop.removeDelayedCallback = UA_EventLoopEmscripten_removeDelayedCallback;

    /* Event source registration */
    el->eventLoop.registerEventSource   = UA_EventLoopEmscripten_registerEventSource;
    el->eventLoop.deregisterEventSource = UA_EventLoopEmscripten_deregisterEventSource;

    /* Locking (no-op) */
    el->eventLoop.lock   = UA_EventLoopEmscripten_lock;
    el->eventLoop.unlock = UA_EventLoopEmscripten_unlock;

    return &el->eventLoop;
}

#endif /* __EMSCRIPTEN__ */
