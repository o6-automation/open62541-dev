/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2024 (c) Fraunhofer IOSB (Author: Noel Graf)
 *    Copyright 2026 (c) o6 Automation GmbH (Author: Julius Pfrommer)
 *    Copyright 2026 (c) o6 Automation GmbH (Author: Andreas Ebner)
 */

#include "gds_core.h"

#ifdef UA_ENABLE_DRIVER_GDS_PUSH

#define STATIC_NS0ID(ID) {0, UA_NODEIDTYPE_NUMERIC, {UA_NS0ID_##ID}}

static const UA_NodeId defaultApplicationGroup =
    STATIC_NS0ID(SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP);

/*************************/
/* CertificateType Slots */
/*************************/

void
UA_GDSCertificateSlot_clearPending(UA_GDSCertificateSlot *slot) {
    UA_ByteString_clear(&slot->pendingCsr);
    slot->pendingOwner = UA_GDSREQUESTOWNER_NONE;
    slot->pendingNewKey = false;
}

UA_GDSCertificateSlot *
UA_GDSCertificateSlots_find(UA_GDSCertificateSlot *slots, size_t slotsSize,
                            const UA_NodeId *certificateTypeId) {
    for(size_t i = 0; i < slotsSize; i++) {
        if(UA_NodeId_equal(&slots[i].certificateTypeId, certificateTypeId))
            return &slots[i];
    }
    return NULL;
}

void
UA_GDSCertificateSlots_delete(UA_GDSCertificateSlot *slots, size_t slotsSize) {
    for(size_t i = 0; i < slotsSize; i++) {
        UA_GDSCertificateSlot_clearPending(&slots[i]);
        UA_NodeId_clear(&slots[i].certificateTypeId);
    }
    UA_free(slots);
}

/***********/
/* Lookups */
/***********/

UA_CertificateGroup *
UA_GDS_getCertificateGroup(UA_ServerConfig *sc, const UA_NodeId *nodeId) {
    static const UA_NodeId defaultApplicationTrustList =
        STATIC_NS0ID(SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST);
    static const UA_NodeId defaultUserTokenGroup =
        STATIC_NS0ID(SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTUSERTOKENGROUP);
    static const UA_NodeId defaultUserTokenTrustList =
        STATIC_NS0ID(SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTUSERTOKENGROUP_TRUSTLIST);
    if(UA_NodeId_equal(nodeId, &defaultApplicationGroup) ||
       UA_NodeId_equal(nodeId, &defaultApplicationTrustList))
        return &sc->secureChannelPKI;
    if(UA_NodeId_equal(nodeId, &defaultUserTokenGroup) ||
       UA_NodeId_equal(nodeId, &defaultUserTokenTrustList))
        return &sc->sessionPKI;
    return NULL;
}

UA_SecurityPolicy *
UA_GDS_getSecPolicyByUri(UA_ServerConfig *sc, const UA_String *securityPolicyUri) {
    for(size_t i = 0; i < sc->securityPoliciesSize; i++) {
        UA_SecurityPolicy *sp = &sc->securityPolicies[i];
        if(UA_String_equal(securityPolicyUri, &sp->policyUri))
            return sp;
    }
    return NULL;
}

/* The ApplicationCertificateTypes that can be updated, in the order of the
 * CertificateTypes Property (Part 12, 7.8.4) */
static const UA_UInt32 knownCertificateTypes[] = {
    UA_NS0ID_RSAMINAPPLICATIONCERTIFICATETYPE,
    UA_NS0ID_RSASHA256APPLICATIONCERTIFICATETYPE,
    UA_NS0ID_ECCNISTP256APPLICATIONCERTIFICATETYPE,
    UA_NS0ID_ECCNISTP384APPLICATIONCERTIFICATETYPE,
    UA_NS0ID_ECCBRAINPOOLP256R1APPLICATIONCERTIFICATETYPE,
    UA_NS0ID_ECCBRAINPOOLP384R1APPLICATIONCERTIFICATETYPE,
    UA_NS0ID_ECCCURVE25519APPLICATIONCERTIFICATETYPE,
    UA_NS0ID_ECCCURVE448APPLICATIONCERTIFICATETYPE
};

UA_StatusCode
UA_GDS_checkCertificateType(const UA_NodeId *certificateTypeId,
                            const UA_ByteString *certificate) {
    UA_StatusCode res =
        UA_CertificateUtils_checkCertificateType(certificate, certificateTypeId);
    if(res == UA_STATUSCODE_BADNOTSUPPORTED)
        return UA_STATUSCODE_GOOD; /* Cannot be checked */
    return (res == UA_STATUSCODE_GOOD) ?
        UA_STATUSCODE_GOOD : UA_STATUSCODE_BADCERTIFICATEINVALID;
}

/**********************/
/* Certificate Update */
/**********************/

void
UA_GDSCertificateUpdate_clear(UA_GDSCertificateUpdate *update) {
    for(size_t i = 0; i < update->endpointsSize; i++)
        UA_ByteString_clear(&update->endpointCertificates[i]);
    UA_free(update->endpointCertificates);
    UA_free(update->policies);
    memset(update, 0, sizeof(UA_GDSCertificateUpdate));
}

UA_StatusCode
UA_GDSCertificateUpdate_prepare(UA_GDSCertificateUpdate *update,
                                UA_ServerConfig *sc,
                                const UA_NodeId *certificateTypeId,
                                const UA_ByteString *certificate) {
    memset(update, 0, sizeof(UA_GDSCertificateUpdate));
    update->policies = (UA_SecurityPolicy**)
        UA_calloc(sc->endpointsSize + 1, sizeof(UA_SecurityPolicy*));
    update->endpointCertificates = (UA_ByteString*)
        UA_calloc(sc->endpointsSize + 1, sizeof(UA_ByteString));
    if(!update->policies || !update->endpointCertificates) {
        UA_GDSCertificateUpdate_clear(update);
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }
    update->endpointsSize = sc->endpointsSize;

    UA_StatusCode res = UA_STATUSCODE_GOOD;
    for(size_t i = 0; i < sc->endpointsSize; i++) {
        UA_EndpointDescription *ed = &sc->endpoints[i];
        UA_SecurityPolicy *sp = UA_GDS_getSecPolicyByUri(sc, &ed->securityPolicyUri);
        if(!sp) {
            res = UA_STATUSCODE_BADINTERNALERROR;
            goto errout;
        }
        if(!UA_NodeId_equal(&sp->certificateTypeId, certificateTypeId))
            continue;

        res = UA_ByteString_copy(certificate, &update->endpointCertificates[i]);
        if(res != UA_STATUSCODE_GOOD)
            goto errout;

        size_t j = 0;
        for(; j < update->policiesSize; j++) {
            if(update->policies[j] == sp)
                break;
        }
        if(j == update->policiesSize)
            update->policies[update->policiesSize++] = sp;
    }

    /* No endpoint uses the certificate type. The update would have no
     * effect. */
    if(update->policiesSize == 0) {
        res = UA_STATUSCODE_BADINVALIDARGUMENT;
        goto errout;
    }

    /* A SecurityPolicy#None endpoint presents the certificate of the None
     * SecurityPolicy, which is usually the replaced certificate. Update it as
     * well, so that all endpoints present the same certificate. */
    size_t typePolicies = update->policiesSize;
    for(size_t i = 0; i < sc->endpointsSize; i++) {
        if(update->endpointCertificates[i].length > 0)
            continue;
        UA_SecurityPolicy *sp =
            UA_GDS_getSecPolicyByUri(sc, &sc->endpoints[i].securityPolicyUri);
        if(!sp || sp->policyType != UA_SECURITYPOLICYTYPE_NONE ||
           sp->localCertificate.length == 0)
            continue;

        UA_Boolean replaced = false;
        for(size_t j = 0; j < typePolicies; j++) {
            if(UA_ByteString_equal(&sp->localCertificate,
                                   &update->policies[j]->localCertificate))
                replaced = true;
        }
        size_t j = typePolicies;
        for(; j < update->policiesSize; j++) {
            if(update->policies[j] == sp)
                break;
        }
        if(j == update->policiesSize && !replaced)
            continue;

        res = UA_ByteString_copy(certificate, &update->endpointCertificates[i]);
        if(res != UA_STATUSCODE_GOOD)
            goto errout;
        if(j == update->policiesSize)
            update->policies[update->policiesSize++] = sp;
    }
    return UA_STATUSCODE_GOOD;

 errout:
    UA_GDSCertificateUpdate_clear(update);
    return res;
}

UA_StatusCode
UA_GDSCertificateUpdate_commit(UA_GDSCertificateUpdate *update,
                               UA_ServerConfig *sc,
                               const UA_ByteString certificate,
                               const UA_ByteString privateKey) {
    UA_StatusCode res = UA_STATUSCODE_GOOD;
    for(size_t i = 0; i < update->policiesSize; i++) {
        res = update->policies[i]->updateCertificate(update->policies[i],
                                                     certificate, privateKey);
        if(res != UA_STATUSCODE_GOOD) {
            UA_LOG_ERROR(sc->logging, UA_LOGCATEGORY_SECURITYPOLICY,
                         "Updating the certificate failed after %u of %u "
                         "SecurityPolicies were updated",
                         (unsigned)i, (unsigned)update->policiesSize);
            UA_GDSCertificateUpdate_clear(update);
            return res;
        }
    }

    /* Commit the preallocated endpoint certificates without further errors */
    for(size_t i = 0; i < update->endpointsSize && i < sc->endpointsSize; i++) {
        if(update->endpointCertificates[i].length == 0)
            continue;
        UA_ByteString_clear(&sc->endpoints[i].serverCertificate);
        sc->endpoints[i].serverCertificate = update->endpointCertificates[i];
        UA_ByteString_init(&update->endpointCertificates[i]);
    }
    UA_GDSCertificateUpdate_clear(update);
    return UA_STATUSCODE_GOOD;
}

/********/
/* Core */
/********/

void
UA_GDSCore_init(UA_GDSCore *core, UA_Driver *drv) {
    memset(core, 0, sizeof(UA_GDSCore));
    core->drv = drv;
    LIST_INIT(&core->channels);
}

static void
UA_GDSChannel_delete(UA_GDSChannel *channel) {
    UA_NodeId_clear(&channel->certificateTypeId);
    UA_ByteString_clear(&channel->certificate);
    UA_free(channel);
}

void
UA_GDSCore_clear(UA_GDSCore *core) {
    UA_assert(core->pendingDelayedCallbacks == 0);
    UA_GDSCertificateSlots_delete(core->slots, core->slotsSize);
    core->slots = NULL;
    core->slotsSize = 0;
    UA_GDSChannel *channel, *channelTmp;
    LIST_FOREACH_SAFE(channel, &core->channels, pointers, channelTmp) {
        LIST_REMOVE(channel, pointers);
        UA_GDSChannel_delete(channel);
    }
}

UA_GDSCore *
UA_GDSCore_find(UA_Server *server, UA_GDSCore *fallback) {
    for(UA_Driver *drv = UA_Server_getDrivers(server); drv; drv = drv->next) {
        if(drv->driverType == UA_DRIVERTYPE_GDS_PUSH &&
           drv->state == UA_LIFECYCLESTATE_STARTED)
            return UA_GDSPush_getCore(drv);
    }
    return fallback;
}

UA_Boolean
UA_GDSCore_changesPending(UA_GDSCore *core) {
    return core->changesPending && core->changesPending(core);
}

/* Does an endpoint use a SecurityPolicy of the DefaultApplicationGroup with
 * the certificate type? Otherwise an update would have no effect. */
static UA_Boolean
endpointUsesCertificateType(UA_ServerConfig *sc,
                            const UA_NodeId *certificateTypeId) {
    for(size_t i = 0; i < sc->endpointsSize; i++) {
        UA_SecurityPolicy *sp =
            UA_GDS_getSecPolicyByUri(sc, &sc->endpoints[i].securityPolicyUri);
        if(sp && UA_NodeId_equal(&sp->certificateTypeId, certificateTypeId) &&
           UA_NodeId_equal(&sp->certificateGroupId, &defaultApplicationGroup))
            return true;
    }
    return false;
}

UA_StatusCode
UA_GDSCore_updateSlots(UA_GDSCore *core) {
    UA_ServerConfig *sc = UA_Server_getConfig(core->drv->server);
    const size_t knownSize =
        sizeof(knownCertificateTypes) / sizeof(knownCertificateTypes[0]);
    UA_GDSCertificateSlot *slots = (UA_GDSCertificateSlot*)
        UA_calloc(knownSize, sizeof(UA_GDSCertificateSlot));
    if(!slots)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    size_t slotsSize = 0;
    for(size_t i = 0; i < knownSize; i++) {
        UA_NodeId typeId = UA_NODEID_NUMERIC(0, knownCertificateTypes[i]);
        if(!endpointUsesCertificateType(sc, &typeId))
            continue;
        UA_GDSCertificateSlot *slot = &slots[slotsSize++];
        slot->certificateTypeId = typeId; /* Numeric, nothing to copy */
        UA_GDSCertificateSlot *old = UA_GDSCore_findSlot(core, &typeId);
        if(old) {
            *slot = *old; /* Move the pending request */
            UA_ByteString_init(&old->pendingCsr);
        }
    }
    UA_GDSCertificateSlots_delete(core->slots, core->slotsSize);
    core->slots = slots;
    core->slotsSize = slotsSize;
    return UA_STATUSCODE_GOOD;
}

UA_GDSCertificateSlot *
UA_GDSCore_findSlot(UA_GDSCore *core, const UA_NodeId *certificateTypeId) {
    return UA_GDSCertificateSlots_find(core->slots, core->slotsSize,
                                       certificateTypeId);
}

void
UA_GDSCore_handleNotification(UA_GDSCore *core,
                              UA_ApplicationNotificationType type,
                              const UA_KeyValueMap payload) {
    const UA_UInt32 *channelId = (const UA_UInt32*)
        UA_KeyValueMap_getScalar(&payload,
                                 UA_QUALIFIEDNAME(0, "securechannel-id"),
                                 &UA_TYPES[UA_TYPES_UINT32]);
    if(!channelId)
        return;

    if(type == UA_APPLICATIONNOTIFICATIONTYPE_SECURECHANNEL_OPENED) {
        const UA_ByteString *certificate = (const UA_ByteString*)
            UA_KeyValueMap_getScalar(&payload,
                                     UA_QUALIFIEDNAME(0, "remote-certificate"),
                                     &UA_TYPES[UA_TYPES_BYTESTRING]);
        const UA_NodeId *certificateTypeId = (const UA_NodeId*)
            UA_KeyValueMap_getScalar(&payload,
                                     UA_QUALIFIEDNAME(0, "certificate-type-id"),
                                     &UA_TYPES[UA_TYPES_NODEID]);
        if(!certificate || !certificateTypeId)
            return;

        UA_GDSChannel *channel = (UA_GDSChannel*)UA_calloc(1, sizeof(UA_GDSChannel));
        if(!channel) {
            UA_ServerConfig *sc = UA_Server_getConfig(core->drv->server);
            UA_LOG_WARNING(sc->logging, UA_LOGCATEGORY_SERVER,
                           "Could not register SecureChannel (oom)");
            return;
        }
        channel->channelId = *channelId;
        UA_StatusCode res = UA_NodeId_copy(certificateTypeId,
                                           &channel->certificateTypeId);
        res |= UA_ByteString_copy(certificate, &channel->certificate);
        if(res != UA_STATUSCODE_GOOD) {
            UA_GDSChannel_delete(channel);
            return;
        }
        LIST_INSERT_HEAD(&core->channels, channel, pointers);
    } else if(type == UA_APPLICATIONNOTIFICATIONTYPE_SECURECHANNEL_CLOSED) {
        UA_GDSChannel *channel;
        LIST_FOREACH(channel, &core->channels, pointers) {
            if(channel->channelId != *channelId)
                continue;
            LIST_REMOVE(channel, pointers);
            UA_GDSChannel_delete(channel);
            break;
        }
    }
}

/* Does the Certificate belong to the current key of a SecurityPolicy with the
 * CertificateType? */
static UA_Boolean
matchesCurrentKey(UA_ServerConfig *sc, const UA_NodeId *certificateTypeId,
                  const UA_ByteString *certificate) {
    for(size_t i = 0; i < sc->securityPoliciesSize; i++) {
        UA_SecurityPolicy *sp = &sc->securityPolicies[i];
        if(sp->policyType == UA_SECURITYPOLICYTYPE_NONE ||
           !UA_NodeId_equal(&sp->certificateTypeId, certificateTypeId) ||
           sp->localCertificate.length == 0)
            continue;
        if(UA_CertificateUtils_comparePublicKeys(certificate, &sp->localCertificate) ==
           UA_STATUSCODE_GOOD)
            return true;
    }
    return false;
}

static UA_Boolean
matchesPendingRequest(const UA_GDSCertificateSlot *slot,
                      const UA_ByteString *certificate) {
    return slot->pendingCsr.length > 0 &&
        UA_CertificateUtils_comparePublicKeys(certificate, &slot->pendingCsr) ==
        UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_GDSCore_checkCertificate(UA_GDSCore *core,
                            const UA_NodeId *certificateTypeId,
                            const UA_ByteString *certificate,
                            const UA_ByteString *privateKey) {
    /* The certificate type must be one of the CertificateTypes of the group */
    UA_GDSCertificateSlot *slot = UA_GDSCore_findSlot(core, certificateTypeId);
    if(!slot)
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    if(!certificate || certificate->length == 0)
        return UA_STATUSCODE_BADCERTIFICATEINVALID;

    /* The key of the certificate must fit the certificate type */
    UA_StatusCode res = UA_GDS_checkCertificateType(certificateTypeId, certificate);
    if(res != UA_STATUSCODE_GOOD)
        return res;

    if(privateKey && privateKey->length > 0) {
        if(UA_CertificateUtils_checkKeyPair(certificate, privateKey) !=
           UA_STATUSCODE_GOOD)
            return UA_STATUSCODE_BADNOTSUPPORTED;
        return UA_STATUSCODE_GOOD;
    }

    /* Validate the certificate before a keyless update */
    size_t keySize = 0;
    if(UA_CertificateUtils_getKeySize((UA_ByteString*)(uintptr_t)certificate,
                                      &keySize) != UA_STATUSCODE_GOOD)
        return UA_STATUSCODE_BADCERTIFICATEINVALID;

    /* Without a PrivateKey, the Certificate has to belong to the current key
     * or to the key of the pending signing request */
    UA_ServerConfig *sc = UA_Server_getConfig(core->drv->server);
    if(!matchesCurrentKey(sc, certificateTypeId, certificate) &&
       !matchesPendingRequest(slot, certificate))
        return UA_STATUSCODE_BADSECURITYCHECKSFAILED;
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_GDSCore_createSigningRequest(UA_GDSCore *core, UA_GDSRequestOwner owner,
                                const UA_NodeId *certificateTypeId,
                                const UA_String *subjectName,
                                const UA_ByteString *nonce,
                                UA_Boolean regenerateKey,
                                UA_ByteString *csr) {
    /* Without a SecurityPolicy for the certificate type, no CSR would be
     * created */
    UA_GDSCertificateSlot *slot = UA_GDSCore_findSlot(core, certificateTypeId);
    if(!slot)
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    /* A new request discards the key of the pending request. The key of the
     * other driver's request is kept until its certificate arrives. */
    if(slot->pendingNewKey && slot->pendingOwner != owner)
        return UA_STATUSCODE_BADTRANSACTIONPENDING;

    UA_ServerConfig *sc = UA_Server_getConfig(core->drv->server);
    if(!UA_NodeId_equal(&sc->secureChannelPKI.certificateGroupId,
                        &defaultApplicationGroup))
        return UA_STATUSCODE_BADINTERNALERROR;

    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    UA_ByteString *newPrivateKey = NULL;
    if(regenerateKey) {
        newPrivateKey = UA_ByteString_new();
        if(!newPrivateKey)
            return UA_STATUSCODE_BADOUTOFMEMORY;
    }

    /* The first SecurityPolicy creates the request (and the new key). The
     * others take over the new key. Several endpoints can share a policy,
     * which is called only once. */
    UA_SecurityPolicy **called = (UA_SecurityPolicy**)
        UA_calloc(sc->endpointsSize + 1, sizeof(UA_SecurityPolicy*));
    size_t calledSize = 0;
    if(!called) {
        retval = UA_STATUSCODE_BADOUTOFMEMORY;
        goto cleanup;
    }
    for(size_t i = 0; i < sc->endpointsSize; i++) {
        UA_SecurityPolicy *sp =
            UA_GDS_getSecPolicyByUri(sc, &sc->endpoints[i].securityPolicyUri);
        if(!sp) {
            retval = UA_STATUSCODE_BADINTERNALERROR;
            goto cleanup;
        }
        if(sp->policyType == UA_SECURITYPOLICYTYPE_NONE)
            continue;
        if(!UA_NodeId_equal(certificateTypeId, &sp->certificateTypeId) ||
           !UA_NodeId_equal(&defaultApplicationGroup, &sp->certificateGroupId))
            continue;
        size_t j = 0;
        for(; j < calledSize; j++) {
            if(called[j] == sp)
                break;
        }
        if(j < calledSize)
            continue;
        called[calledSize++] = sp;

        if(!sp->createSigningRequest) {
            retval = UA_STATUSCODE_BADNOTSUPPORTED;
            goto cleanup;
        }
        retval = sp->createSigningRequest(sp, subjectName, nonce,
                                          &UA_KEYVALUEMAP_NULL, csr,
                                          newPrivateKey);
        if(retval != UA_STATUSCODE_GOOD)
            goto cleanup;
    }

    /* Remember the request for the certificate update without a private key */
    UA_ByteString pendingCsr = UA_BYTESTRING_NULL;
    retval = UA_ByteString_copy(csr, &pendingCsr);
    if(retval == UA_STATUSCODE_GOOD) {
        UA_GDSCertificateSlot_clearPending(slot);
        slot->pendingCsr = pendingCsr;
        slot->pendingOwner = owner;
        slot->pendingNewKey = regenerateKey;
    }

cleanup:
    UA_free(called);
    if(newPrivateKey) {
        UA_ByteString_memZero(newPrivateKey);
        UA_ByteString_delete(newPrivateKey);
    }
    return retval;
}

void
UA_GDSCore_certificateInstalled(UA_GDSCore *core, UA_GDSRequestOwner owner,
                                const UA_NodeId *certificateTypeId,
                                const UA_ByteString *certificate) {
    UA_GDSCertificateSlot *slot = UA_GDSCore_findSlot(core, certificateTypeId);
    if(slot && (slot->pendingOwner == owner ||
                matchesPendingRequest(slot, certificate)))
        UA_GDSCertificateSlot_clearPending(slot);
}

void
UA_GDSCore_addDelayedCallback(UA_GDSCore *core, UA_DelayedCallback *dc) {
    UA_ServerConfig *sc = UA_Server_getConfig(core->drv->server);
    core->pendingDelayedCallbacks++;
    sc->eventLoop->addDelayedCallback(sc->eventLoop, dc);
}

void
UA_GDSCore_delayedCallbackDone(UA_GDSCore *core) {
    UA_assert(core->pendingDelayedCallbacks > 0);
    core->pendingDelayedCallbacks--;
    if(core->pendingDelayedCallbacks == 0 &&
       core->drv->state == UA_LIFECYCLESTATE_STOPPING)
        core->drv->state = UA_LIFECYCLESTATE_STOPPED;
}

void
UA_GDSCore_closeChannels(UA_GDSCore *core, size_t certificateTypesSize,
                         const UA_NodeId *certificateTypes) {
    UA_GDSChannel *channel, *channelTmp;
    LIST_FOREACH_SAFE(channel, &core->channels, pointers, channelTmp) {
        for(size_t i = 0; i < certificateTypesSize; i++) {
            if(!UA_NodeId_equal(&channel->certificateTypeId, &certificateTypes[i]))
                continue;
            UA_Server_closeSecureChannel(core->drv->server, channel->channelId,
                                         UA_SHUTDOWNREASON_CLOSE);
            break;
        }
    }
}

void
UA_GDSCore_verifyChannels(UA_GDSCore *core) {
    UA_ServerConfig *sc = UA_Server_getConfig(core->drv->server);
    UA_CertificateGroup *certGroup = &sc->secureChannelPKI;
    UA_GDSChannel *channel, *channelTmp;
    LIST_FOREACH_SAFE(channel, &core->channels, pointers, channelTmp) {
        UA_StatusCode res =
            certGroup->verifyCertificate(certGroup, &channel->certificate);
        if(res != UA_STATUSCODE_GOOD)
            UA_Server_closeSecureChannel(core->drv->server, channel->channelId,
                                         UA_SHUTDOWNREASON_CLOSE);
    }
}

/* Close the SecureChannels after a change outside of a transaction. A NULL
 * certificate type verifies the remote certificates with the TrustList. */
typedef struct {
    UA_DelayedCallback dc;
    UA_GDSCore *core;
    UA_NodeId certificateTypeId;
} UA_GDSChannelCheck;

static void
channelCheckCallback(void *application, void *context) {
    UA_GDSChannelCheck *check = (UA_GDSChannelCheck*)context;
    UA_GDSCore *core = check->core;
    if(UA_NodeId_isNull(&check->certificateTypeId))
        UA_GDSCore_verifyChannels(core);
    else
        UA_GDSCore_closeChannels(core, 1, &check->certificateTypeId);
    UA_NodeId_clear(&check->certificateTypeId);
    UA_free(check);
    UA_GDSCore_delayedCallbackDone(core);
}

static UA_GDSChannelCheck *
UA_GDSChannelCheck_new(UA_GDSCore *core, const UA_NodeId *certificateTypeId) {
    UA_GDSChannelCheck *check =
        (UA_GDSChannelCheck*)UA_calloc(1, sizeof(UA_GDSChannelCheck));
    if(!check)
        return NULL;
    if(certificateTypeId &&
       UA_NodeId_copy(certificateTypeId, &check->certificateTypeId) !=
       UA_STATUSCODE_GOOD) {
        UA_free(check);
        return NULL;
    }
    check->core = core;
    check->dc.callback = channelCheckCallback;
    check->dc.context = check;
    return check;
}

UA_StatusCode
UA_GDSCore_updateCertificate(UA_GDSCore *core, UA_GDSRequestOwner owner,
                             const UA_NodeId *certificateTypeId,
                             const UA_ByteString certificate,
                             const UA_ByteString privateKey) {
    if(UA_GDSCore_changesPending(core))
        return UA_STATUSCODE_BADTRANSACTIONPENDING;

    UA_StatusCode res = UA_GDSCore_checkCertificate(core, certificateTypeId,
                                                    &certificate, &privateKey);
    if(res != UA_STATUSCODE_GOOD)
        return res;

    UA_GDSChannelCheck *check = UA_GDSChannelCheck_new(core, certificateTypeId);
    if(!check)
        return UA_STATUSCODE_BADOUTOFMEMORY;

    UA_ServerConfig *sc = UA_Server_getConfig(core->drv->server);
    UA_GDSCertificateUpdate update;
    res = UA_GDSCertificateUpdate_prepare(&update, sc, certificateTypeId,
                                          &certificate);
    if(res == UA_STATUSCODE_GOOD)
        res = UA_GDSCertificateUpdate_commit(&update, sc, certificate, privateKey);
    if(res != UA_STATUSCODE_GOOD) {
        UA_NodeId_clear(&check->certificateTypeId);
        UA_free(check);
        return res;
    }

    UA_GDSCore_certificateInstalled(core, owner, certificateTypeId, &certificate);
    UA_GDSCore_addDelayedCallback(core, &check->dc);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
changeTrustList(UA_GDSCore *core, const UA_NodeId *certificateGroupId,
                const UA_TrustListDataType *trustList, UA_Boolean replace) {
    if(UA_GDSCore_changesPending(core))
        return UA_STATUSCODE_BADTRANSACTIONPENDING;

    UA_ServerConfig *sc = UA_Server_getConfig(core->drv->server);
    UA_CertificateGroup *group = UA_GDS_getCertificateGroup(sc, certificateGroupId);
    if(!group)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    if((replace && !group->setTrustList) || (!replace && !group->addToTrustList))
        return UA_STATUSCODE_BADNOTSUPPORTED;

    /* Only the SecureChannels depend on the DefaultApplicationGroup */
    UA_GDSChannelCheck *check = NULL;
    if(group == &sc->secureChannelPKI) {
        check = UA_GDSChannelCheck_new(core, NULL);
        if(!check)
            return UA_STATUSCODE_BADOUTOFMEMORY;
    }

    UA_StatusCode res = (replace) ?
        group->setTrustList(group, trustList) :
        group->addToTrustList(group, trustList);
    if(res != UA_STATUSCODE_GOOD) {
        UA_free(check);
        return res;
    }

    if(core->trustListChanged)
        core->trustListChanged(core, group);
    if(check)
        UA_GDSCore_addDelayedCallback(core, &check->dc);
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_GDSCore_setTrustList(UA_GDSCore *core, const UA_NodeId *certificateGroupId,
                        const UA_TrustListDataType *trustList) {
    return changeTrustList(core, certificateGroupId, trustList, true);
}

UA_StatusCode
UA_GDSCore_addToTrustList(UA_GDSCore *core, const UA_NodeId *certificateGroupId,
                          const UA_TrustListDataType *trustList) {
    return changeTrustList(core, certificateGroupId, trustList, false);
}

#endif /* UA_ENABLE_DRIVER_GDS_PUSH */
