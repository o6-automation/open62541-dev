/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2019 (c) Fraunhofer IOSB (Author: Julius Pfrommer)
 *    Copyright 2019 (c) HMS Industrial Networks AB (Author: Jonas Green)
 *    Copyright 2026 (c) o6 Automation GmbH (Author: Julius Pfrommer)
 */

#include <open62541/server.h>

#include "ua_server_internal.h"

void
UA_ServerConfig_clear(UA_ServerConfig *config) {
    if(!config)
        return;

    /* Server Description */
    UA_BuildInfo_clear(&config->buildInfo);
    UA_ApplicationDescription_clear(&config->applicationDescription);
    /* Also allow cleanup after rejecting a nonzero count with no array. */
    if((uintptr_t)config->serverProfileArray > (uintptr_t)UA_EMPTY_ARRAY_SENTINEL)
        UA_Array_delete(config->serverProfileArray, config->serverProfileArraySize,
                        &UA_TYPES[UA_TYPES_STRING]);
    config->serverProfileArray = NULL;
    config->serverProfileArraySize = 0;

    /* Stop and delete the EventLoop */
    UA_EventLoop *el = config->eventLoop;
    if(el && !config->externalEventLoop) {
        if(el->state != UA_EVENTLOOPSTATE_FRESH &&
           el->state != UA_EVENTLOOPSTATE_STOPPED) {
            el->stop(el);
            while(el->state != UA_EVENTLOOPSTATE_STOPPED) {
                el->run(el, 100);
            }
        }
        el->free(el);
        config->eventLoop = NULL;
    }

    /* Networking */
    UA_Array_delete(config->serverUrls, config->serverUrlsSize,
                    &UA_TYPES[UA_TYPES_STRING]);
    config->serverUrls = NULL;
    config->serverUrlsSize = 0;

    UA_String_clear(&config->httpListenAddress);

    /* Drivers. The registrations themselves are static. */
    UA_free(config->driverRegistrations);
    config->driverRegistrations = NULL;
    config->driverRegistrationsSize = 0;
    for(size_t i = 0; i < config->driversSize; i++) {
        UA_String_clear(&config->drivers[i].driver);
        UA_String_clear(&config->drivers[i].name);
        UA_KeyValueMap_clear(&config->drivers[i].params);
    }
    UA_free(config->drivers);
    config->drivers = NULL;
    config->driversSize = 0;

    /* Security Policies */
    for(size_t i = 0; i < config->securityPoliciesSize; ++i) {
        UA_SecurityPolicy *policy = &config->securityPolicies[i];
        policy->clear(policy);
    }
    UA_free(config->securityPolicies);
    config->securityPolicies = NULL;
    config->securityPoliciesSize = 0;

    for(size_t i = 0; i < config->endpointsSize; ++i)
        UA_EndpointDescription_clear(&config->endpoints[i]);

    UA_free(config->endpoints);
    config->endpoints = NULL;
    config->endpointsSize = 0;

    /* Nodestore */
    if(config->nodestore) {
        config->nodestore->free(config->nodestore);
        config->nodestore = NULL;
    }

    /* Certificate Validation */
    if(config->secureChannelPKI.clear)
        config->secureChannelPKI.clear(&config->secureChannelPKI);
    if(config->sessionPKI.clear)
        config->sessionPKI.clear(&config->sessionPKI);

    /* Access Control */
    if(config->accessControl.clear)
        config->accessControl.clear(&config->accessControl);

    /* Historical data */
#ifdef UA_ENABLE_HISTORIZING
    if(config->historyDatabase.clear)
        config->historyDatabase.clear(&config->historyDatabase);
#endif

#ifdef UA_ENABLE_PUBSUB
    if(config->pubSubConfig.securityPolicies != NULL) {
        for(size_t i = 0; i < config->pubSubConfig.securityPoliciesSize; i++) {
            config->pubSubConfig.securityPolicies[i].clear(&config->pubSubConfig.securityPolicies[i]);
        }
        UA_free(config->pubSubConfig.securityPolicies);
        config->pubSubConfig.securityPolicies = NULL;
        config->pubSubConfig.securityPoliciesSize = 0;
    }
#endif /* UA_ENABLE_PUBSUB */

    /* Logger */
    if(config->logging != NULL && config->logging->clear != NULL)
        config->logging->clear(config->logging);
    config->logging = NULL;

    /* Custom Data Types */
    UA_cleanupDataTypeWithCustom(config->customDataTypes);
    config->customDataTypes = NULL;

#ifdef UA_ENABLE_RBAC
    /* RBAC Presets */
    if(config->rolePermissionPresets) {
        for(size_t i = 0; i < config->rolePermissionPresetsSize; i++)
            UA_RolePermissionSet_clear(&config->rolePermissionPresets[i]);
        UA_free(config->rolePermissionPresets);
        config->rolePermissionPresets = NULL;
        config->rolePermissionPresetsSize = 0;
    }

    /* RBAC Roles */
    if(config->roles) {
        for(size_t i = 0; i < config->rolesSize; i++)
            UA_Role_clear(&config->roles[i]);
        UA_free(config->roles);
        config->roles = NULL;
        config->rolesSize = 0;
    }
#endif
}

const UA_DriverRegistration *
getDriverRegistration(const UA_ServerConfig *config, const UA_String *name) {
    for(size_t i = 0; i < config->driverRegistrationsSize; i++) {
        UA_String regName =
            UA_STRING((char *)(uintptr_t)config->driverRegistrations[i]->name);
        if(UA_String_equal(&regName, name))
            return config->driverRegistrations[i];
    }
    return NULL;
}

UA_StatusCode
UA_ServerConfig_registerDriver(UA_ServerConfig *config,
                               const UA_DriverRegistration *registration) {
    if(!config || !registration || !registration->name || !registration->create)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    UA_String name = UA_STRING((char *)(uintptr_t)registration->name);
    if(getDriverRegistration(config, &name))
        return UA_STATUSCODE_BADALREADYEXISTS;
    const UA_DriverRegistration **registrations = (const UA_DriverRegistration **)
        UA_realloc((void *)config->driverRegistrations,
                   sizeof(UA_DriverRegistration *) *
                   (config->driverRegistrationsSize + 1));
    if(!registrations)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    registrations[config->driverRegistrationsSize] = registration;
    config->driverRegistrations = registrations;
    config->driverRegistrationsSize++;
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_ServerConfig_addDriver(UA_ServerConfig *config, const char *driver,
                          const char *name, const UA_KeyValueMap params) {
    if(!config || !driver || driver[0] == '\0')
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    UA_DriverConfiguration *drivers = (UA_DriverConfiguration *)
        UA_realloc(config->drivers,
                   sizeof(UA_DriverConfiguration) * (config->driversSize + 1));
    if(!drivers)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    config->drivers = drivers;

    UA_DriverConfiguration *entry = &drivers[config->driversSize];
    memset(entry, 0, sizeof(UA_DriverConfiguration));
    UA_String driverName = UA_STRING((char *)(uintptr_t)driver);
    UA_StatusCode res = UA_String_copy(&driverName, &entry->driver);
    if(name) {
        UA_String instanceName = UA_STRING((char *)(uintptr_t)name);
        res |= UA_String_copy(&instanceName, &entry->name);
    }
    res |= UA_KeyValueMap_copy(&params, &entry->params);
    if(res != UA_STATUSCODE_GOOD) {
        UA_String_clear(&entry->driver);
        UA_String_clear(&entry->name);
        UA_KeyValueMap_clear(&entry->params);
        return res;
    }
    config->driversSize++;
    return UA_STATUSCODE_GOOD;
}
