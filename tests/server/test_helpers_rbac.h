/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2026 (c) o6 Automation GmbH (Author: Andreas Ebner)
 */

/* In-process Sessions for the RBAC tests. A Session runs on a SecureChannel
 * without a transport. The SecurityMode of the channel is set directly, the
 * SecurityPolicy stays None. So no certificate is involved. */

#ifndef TEST_HELPERS_RBAC_H_
#define TEST_HELPERS_RBAC_H_

#include <open62541/server.h>

#include "server/ua_server_internal.h"
#include "server/ua_services.h"
#include "server/ua_subscription.h"

#include <check.h>

typedef UA_Boolean (*RbacService)(UA_Server *server, UA_Session *session,
                                  const void *request, void *response);

static UA_INLINE void
rbacService(UA_Server *server, UA_Session *session, RbacService service,
            const void *request, void *response) {
    lockServer(server);
    service(server, session, request, response);
    unlockServer(server);
}

/* Clear the channel only after the server was deleted. The listenerUrl is the
 * configured ServerUrl of the accepting listener (may be NULL). */
static UA_INLINE void
rbacChannelInit(UA_Server *server, UA_SecureChannel *channel,
                UA_MessageSecurityMode mode, const char *listenerUrl) {
    UA_SecureChannel_init(channel);
    UA_ServerConfig *config = UA_Server_getConfig(server);
    for(size_t i = 0; i < config->securityPoliciesSize; i++) {
        if(config->securityPolicies[i].policyType == UA_SECURITYPOLICYTYPE_NONE)
            channel->securityPolicy = &config->securityPolicies[i];
    }
    ck_assert_ptr_nonnull(channel->securityPolicy);
    channel->securityMode = mode;
    channel->state = UA_SECURECHANNELSTATE_OPEN;
    if(listenerUrl)
        channel->listenerUrl = UA_STRING_ALLOC(listenerUrl);
}

/* Offer the None SecurityPolicy also with Sign and SignAndEncrypt, so that
 * Sessions can be activated on channels of every mode. Before the startup. */
static UA_INLINE void
rbacAddEndpointModes(UA_ServerConfig *config) {
    ck_assert_uint_ge(config->endpointsSize, 1);
    UA_EndpointDescription ed;
    ck_assert_uint_eq(UA_EndpointDescription_copy(&config->endpoints[0], &ed),
                      UA_STATUSCODE_GOOD);
    ck_assert_int_eq(ed.securityMode, UA_MESSAGESECURITYMODE_NONE);
    for(int mode = UA_MESSAGESECURITYMODE_SIGN;
        mode <= UA_MESSAGESECURITYMODE_SIGNANDENCRYPT; mode++) {
        ed.securityMode = (UA_MessageSecurityMode)mode;
        ck_assert_uint_eq(UA_Array_appendCopy((void**)&config->endpoints,
                                              &config->endpointsSize, &ed,
                                              &UA_TYPES[UA_TYPES_ENDPOINTDESCRIPTION]),
                          UA_STATUSCODE_GOOD);
    }
    UA_EndpointDescription_clear(&ed);
}

/* An Object or Variable below the ObjectsFolder with a string NodeId */
static UA_INLINE UA_NodeId
rbacAddNode(UA_Server *server, const char *name, UA_NodeClass nodeClass) {
    UA_NodeId id = UA_NODEID_STRING(1, (char*)(uintptr_t)name);
    UA_QualifiedName qn = UA_QUALIFIEDNAME(1, (char*)(uintptr_t)name);
    UA_StatusCode res;
    if(nodeClass == UA_NODECLASS_VARIABLE) {
        UA_VariableAttributes attr = UA_VariableAttributes_default;
        UA_Int32 value = 1;
        UA_Variant_setScalar(&attr.value, &value, &UA_TYPES[UA_TYPES_INT32]);
        attr.accessLevel = UA_ACCESSLEVELMASK_READ | UA_ACCESSLEVELMASK_WRITE;
        res = UA_Server_addVariableNode(server, id, UA_NS0ID(OBJECTSFOLDER),
                                        UA_NS0ID(ORGANIZES), qn,
                                        UA_NS0ID(BASEDATAVARIABLETYPE),
                                        attr, NULL, NULL);
    } else {
        res = UA_Server_addObjectNode(server, id, UA_NS0ID(OBJECTSFOLDER),
                                      UA_NS0ID(ORGANIZES), qn,
                                      UA_NS0ID(BASEOBJECTTYPE),
                                      UA_ObjectAttributes_default, NULL, NULL);
    }
    ck_assert_uint_eq(res, UA_STATUSCODE_GOOD);
    return id;
}

/* A Role in namespace 1 with one identity mapping rule or none */
#define RBAC_NO_RULE ((UA_IdentityCriteriaType)0)

static UA_INLINE UA_NodeId
rbacAddRole(UA_Server *server, const char *name,
            UA_IdentityCriteriaType criteriaType, const char *criteria) {
    UA_IdentityMappingRuleType rule;
    UA_IdentityMappingRuleType_init(&rule);
    rule.criteriaType = criteriaType;
    rule.criteria = UA_STRING((char*)(uintptr_t)criteria);
    UA_Role role;
    UA_Role_init(&role);
    role.roleName = UA_QUALIFIEDNAME(1, (char*)(uintptr_t)name);
    role.identityMappingRules = &rule;
    role.identityMappingRulesSize = (criteriaType != RBAC_NO_RULE) ? 1 : 0;
    UA_NodeId roleId = UA_NODEID_NULL;
    ck_assert_uint_eq(UA_Server_addRole(server, &role, &roleId),
                      UA_STATUSCODE_GOOD);
    return roleId;
}

static UA_INLINE void
rbacSetRoles(UA_Server *server, const UA_NodeId *sessionId,
             size_t rolesSize, const UA_NodeId *roles) {
    UA_Variant v;
    UA_Variant_setArray(&v, (void*)(uintptr_t)roles, rolesSize,
                        &UA_TYPES[UA_TYPES_NODEID]);
    ck_assert_uint_eq(UA_Server_setSessionAttribute(server, sessionId,
                                                    UA_QUALIFIEDNAME(0, "roles"),
                                                    &v),
                      UA_STATUSCODE_GOOD);
}

/* A Session on the channel (may be NULL) that holds exactly the Role */
static UA_INLINE UA_Session *
rbacSession(UA_Server *server, UA_SecureChannel *channel, UA_NodeId role) {
    UA_CreateSessionRequest request;
    UA_CreateSessionRequest_init(&request);
    request.requestedSessionTimeout = UA_UINT32_MAX;
    UA_Session *session = NULL;
    lockServer(server);
    UA_StatusCode res = UA_Session_create(server, channel, &request, &session);
    unlockServer(server);
    ck_assert_uint_eq(res, UA_STATUSCODE_GOOD);
    rbacSetRoles(server, &session->sessionId, 1, &role);
    return session;
}

static UA_INLINE UA_Boolean
rbacHasRole(UA_Server *server, const UA_NodeId *sessionId, UA_NodeId role) {
    UA_Variant roles;
    UA_Variant_init(&roles);
    ck_assert_uint_eq(UA_Server_getSessionAttributeCopy(server, sessionId,
                                                        UA_QUALIFIEDNAME(0, "roles"),
                                                        &roles),
                      UA_STATUSCODE_GOOD);
    UA_Boolean found = false;
    for(size_t i = 0; i < roles.arrayLength; i++)
        found |= UA_NodeId_equal(&((UA_NodeId*)roles.data)[i], &role);
    UA_Variant_clear(&roles);
    return found;
}

/* ActivateSession, a NULL token type sends an empty token. The PolicyId is
 * taken from GetEndpoints, as a Client does. */
static UA_INLINE UA_StatusCode
rbacActivate(UA_Server *server, UA_SecureChannel *channel,
             const UA_NodeId *sessionId, const UA_DataType *tokenType,
             void *token) {
    lockServer(server);
    UA_Session *session = getSessionById(server, sessionId);
    ck_assert_ptr_nonnull(session);
    UA_ActivateSessionRequest request;
    UA_ActivateSessionRequest_init(&request);
    request.requestHeader.authenticationToken = session->authenticationToken;
    unlockServer(server);

    UA_String *policyId = (UA_String*)token; /* First member of every token */
    if(tokenType) {
        UA_UserTokenType type = UA_USERTOKENTYPE_ANONYMOUS;
        if(tokenType == &UA_TYPES[UA_TYPES_USERNAMEIDENTITYTOKEN])
            type = UA_USERTOKENTYPE_USERNAME;
        else if(tokenType == &UA_TYPES[UA_TYPES_ISSUEDIDENTITYTOKEN])
            type = UA_USERTOKENTYPE_ISSUEDTOKEN;
        UA_GetEndpointsRequest geReq;
        UA_GetEndpointsRequest_init(&geReq);
        geReq.endpointUrl = UA_STRING("opc.tcp://rbac.test");
        UA_GetEndpointsResponse geRes;
        UA_GetEndpointsResponse_init(&geRes);
        rbacService(server, NULL, Service_GetEndpoints, &geReq, &geRes);
        for(size_t i = 0; i < geRes.endpointsSize; i++) {
            UA_EndpointDescription *ed = &geRes.endpoints[i];
            if(ed->securityMode != channel->securityMode)
                continue;
            for(size_t j = 0; j < ed->userIdentityTokensSize; j++) {
                if(ed->userIdentityTokens[j].tokenType == type && !policyId->data)
                    UA_String_copy(&ed->userIdentityTokens[j].policyId, policyId);
            }
        }
        UA_GetEndpointsResponse_clear(&geRes);
        UA_ExtensionObject_setValueNoDelete(&request.userIdentityToken,
                                            token, tokenType);
    }

    UA_ActivateSessionResponse response;
    UA_ActivateSessionResponse_init(&response);
    lockServer(server);
    Service_ActivateSession(server, channel, &request, &response);
    unlockServer(server);
    UA_StatusCode res = response.responseHeader.serviceResult;
    UA_ActivateSessionResponse_clear(&response);
    if(tokenType)
        UA_String_clear(policyId);
    return res;
}

/* CreateSession and ActivateSession on the channel */
static UA_INLINE UA_StatusCode
rbacLogin(UA_Server *server, UA_SecureChannel *channel,
          const UA_DataType *tokenType, void *token, UA_NodeId *sessionId) {
    UA_CreateSessionRequest request;
    UA_CreateSessionRequest_init(&request);
    request.requestedSessionTimeout = 60000.0;
    UA_CreateSessionResponse response;
    UA_CreateSessionResponse_init(&response);
    lockServer(server);
    Service_CreateSession(server, channel, &request, &response);
    unlockServer(server);
    ck_assert_uint_eq(response.responseHeader.serviceResult, UA_STATUSCODE_GOOD);
    *sessionId = response.sessionId; /* A Guid NodeId, no heap memory */
    UA_CreateSessionResponse_clear(&response);
    return rbacActivate(server, channel, sessionId, tokenType, token);
}

/* Call a Method in a Session */
static UA_INLINE UA_StatusCode
rbacCall(UA_Server *server, UA_Session *session, UA_NodeId objectId,
         UA_NodeId methodId, size_t inputSize, UA_Variant *input) {
    UA_CallMethodRequest item;
    UA_CallMethodRequest_init(&item);
    item.objectId = objectId;
    item.methodId = methodId;
    item.inputArgumentsSize = inputSize;
    item.inputArguments = input;
    UA_CallRequest request;
    UA_CallRequest_init(&request);
    request.methodsToCallSize = 1;
    request.methodsToCall = &item;
    UA_CallResponse response;
    UA_CallResponse_init(&response);
    rbacService(server, session, Service_Call, &request, &response);
    ck_assert_uint_eq(response.responseHeader.serviceResult, UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(response.resultsSize, 1);
    UA_StatusCode res = response.results[0].statusCode;
    UA_CallResponse_clear(&response);
    return res;
}

static UA_INLINE UA_Session *
rbacGetSession(UA_Server *server, const UA_NodeId *sessionId) {
    lockServer(server);
    UA_Session *session = getSessionById(server, sessionId);
    unlockServer(server);
    return session;
}

#ifdef UA_ENABLE_SUBSCRIPTIONS
/* A Subscription with one MonitoredItem. For the EventNotifier the filter
 * selects the Event field with the BrowseName (namespace 0). */
static UA_INLINE UA_MonitoredItem *
rbacMonitor(UA_Server *server, UA_Session *session, const UA_NodeId nodeId,
            UA_UInt32 attributeId, const char *eventField, UA_StatusCode *status) {
    UA_CreateSubscriptionRequest subRequest;
    UA_CreateSubscriptionRequest_init(&subRequest);
    subRequest.publishingEnabled = true;
    UA_CreateSubscriptionResponse subResponse;
    UA_CreateSubscriptionResponse_init(&subResponse);
    rbacService(server, session, Service_CreateSubscription, &subRequest, &subResponse);
    ck_assert_uint_eq(subResponse.responseHeader.serviceResult, UA_STATUSCODE_GOOD);

    UA_MonitoredItemCreateRequest item;
    UA_MonitoredItemCreateRequest_init(&item);
    item.itemToMonitor.nodeId = nodeId;
    item.itemToMonitor.attributeId = attributeId;
    item.monitoringMode = UA_MONITORINGMODE_REPORTING;
    item.requestedParameters.queueSize = 10;
#ifdef UA_ENABLE_SUBSCRIPTIONS_EVENTS
    UA_QualifiedName field = UA_QUALIFIEDNAME(0, (char*)(uintptr_t)eventField);
    UA_SimpleAttributeOperand select;
    UA_SimpleAttributeOperand_init(&select);
    select.typeDefinitionId = UA_NS0ID(BASEEVENTTYPE);
    select.browsePath = &field;
    select.browsePathSize = 1;
    select.attributeId = UA_ATTRIBUTEID_VALUE;
    UA_EventFilter filter;
    UA_EventFilter_init(&filter);
    filter.selectClauses = &select;
    filter.selectClausesSize = 1;
    if(eventField)
        UA_ExtensionObject_setValueNoDelete(&item.requestedParameters.filter,
                                            &filter, &UA_TYPES[UA_TYPES_EVENTFILTER]);
#endif
    UA_CreateMonitoredItemsRequest request;
    UA_CreateMonitoredItemsRequest_init(&request);
    request.subscriptionId = subResponse.subscriptionId;
    request.timestampsToReturn = UA_TIMESTAMPSTORETURN_NEITHER;
    request.itemsToCreate = &item;
    request.itemsToCreateSize = 1;
    UA_CreateMonitoredItemsResponse response;
    UA_CreateMonitoredItemsResponse_init(&response);
    rbacService(server, session, Service_CreateMonitoredItems, &request, &response);
    ck_assert_uint_eq(response.resultsSize, 1);
    *status = response.results[0].statusCode;
    lockServer(server);
    UA_Subscription *sub = getSubscriptionById(server, subResponse.subscriptionId);
    UA_MonitoredItem *mon =
        UA_Subscription_getMonitoredItem(sub, response.results[0].monitoredItemId);
    unlockServer(server);
    UA_CreateMonitoredItemsResponse_clear(&response);
    return mon;
}
#endif

#endif /* TEST_HELPERS_RBAC_H_ */
