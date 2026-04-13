/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2026 (c) o6 Automation GmbH (Author: Andreas Ebner)
 */

#ifndef UA_EVENTLOOP_EMSCRIPTEN_H_
#define UA_EVENTLOOP_EMSCRIPTEN_H_

#include <open62541/config.h>
#include <open62541/plugin/eventloop.h>

#include "../common/timer.h"
#include "../common/eventloop_common.h"

#if defined(__EMSCRIPTEN__)

_UA_BEGIN_DECLS

/* TCP Bridge CM global configuration (called from JS via o6_set_bridge_url) */
void EmscriptenTCPBridge_setHost(const char *host);
void EmscriptenTCPBridge_setPort(int port);
void EmscriptenTCPBridge_setConfigured(int configured);

/**
 * Emscripten EventLoop
 * ~~~~~~~~~~~~~~~~~~~~
 * Single-threaded EventLoop for the browser environment. No file descriptors,
 * no poll/epoll. The EventLoop is driven externally by JavaScript calling
 * UA_EventLoop->run(el, 0) periodically via setInterval. */

typedef struct {
    UA_EventLoop eventLoop;

    /* Timer */
    UA_Timer timer;

    /* Delayed callbacks — single-threaded, simple linked list */
    UA_DelayedCallback *delayedHead;
    UA_DelayedCallback **delayedTail;

    /* State */
    UA_Boolean executing;
} UA_EventLoopEmscripten;

/**
 * Emscripten WebSocket ConnectionManager
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 * Uses the browser-native WebSocket API via emscripten_websocket_* functions.
 * Implements the same UA_ConnectionManager interface as the POSIX WS CM.
 * Protocol string: "ws"
 *
 * Client-only (no server/listen mode — the browser cannot accept incoming
 * WebSocket connections). */

struct EmscriptenWSConnection;
typedef struct EmscriptenWSConnection EmscriptenWSConnection;

struct EmscriptenWSConnection {
    EmscriptenWSConnection *next;  /* Singly-linked list */
    uintptr_t connectionId;

    /* Browser WebSocket handle (as returned by emscripten_websocket_new) */
    int wsHandle;

    /* Application callback */
    void *application;
    void *context;
    UA_ConnectionManager_connectionCallback applicationCB;

    /* State */
    UA_Boolean closing;
    UA_Boolean established;

    /* Deferred cleanup */
    UA_DelayedCallback dc;
};

typedef struct {
    UA_ConnectionManager cm;
    EmscriptenWSConnection *connections;
    uintptr_t lastConnectionId;
} EmscriptenWSConnectionManager;

_UA_END_DECLS

#endif /* __EMSCRIPTEN__ */
#endif /* UA_EVENTLOOP_EMSCRIPTEN_H_ */
