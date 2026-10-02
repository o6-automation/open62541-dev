/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2024 (c) Fraunhofer IOSB (Author: Noel Graf)
 *    Copyright 2026 (c) o6 Automation GmbH (Author: Julius Pfrommer)
 *    Copyright 2026 (c) o6 Automation GmbH (Author: Andreas Ebner)
 */

#ifndef UA_DRIVER_GDS_CORE_H_
#define UA_DRIVER_GDS_CORE_H_

#include <open62541/server.h>
#include <open62541/plugin/certificategroup.h>

#include "open62541_queue.h"

#if defined(UA_ENABLE_DRIVER_GDS_PUSH) || defined(UA_ENABLE_DRIVER_GDS_PULL)

_UA_BEGIN_DECLS

/**
 * GDS Core
 * --------
 * The GDS Push driver (PushManagement, Part 12, 7.4) and the GDS Pull driver
 * (PullManagement, Part 12, 7.3) change the same SecurityPolicies, endpoints
 * and CertificateGroups of the server. The core holds what they share:
 *
 * - the CertificateType slots of the server with the pending signing request
 *   of each type and the driver that created it,
 * - installing a certificate in every SecurityPolicy and endpoint of its type,
 * - the open SecureChannels, which are closed when the certificate they use is
 *   replaced or their remote certificate is no longer trusted.
 *
 * The GDS Push driver hosts the core of the server. Without a GDS Push driver,
 * the GDS Pull driver uses a core of its own. All functions are called with
 * the EventLoop locked. */

/* The driver that created the pending signing request of a slot */
typedef enum {
    UA_GDSREQUESTOWNER_NONE = 0,
    UA_GDSREQUESTOWNER_PUSH, /* CreateSigningRequest of a CertificateManager */
    UA_GDSREQUESTOWNER_PULL  /* StartSigningRequest at a CertificateManager */
} UA_GDSRequestOwner;

/* A CertificateType slot of a CertificateGroup (Part 12, 7.8.3) with the state
 * of the last signing request for the type. The certificate and the key of the
 * slot are kept by the SecurityPolicies. */
typedef struct {
    UA_NodeId certificateTypeId;
    UA_ByteString pendingCsr;        /* The last signing request */
    UA_GDSRequestOwner pendingOwner;
    UA_Boolean pendingNewKey;        /* The request has a new private key */
} UA_GDSCertificateSlot;

/* Discard the state of the last signing request */
void
UA_GDSCertificateSlot_clearPending(UA_GDSCertificateSlot *slot);

UA_GDSCertificateSlot *
UA_GDSCertificateSlots_find(UA_GDSCertificateSlot *slots, size_t slotsSize,
                            const UA_NodeId *certificateTypeId);

void
UA_GDSCertificateSlots_delete(UA_GDSCertificateSlot *slots, size_t slotsSize);

/* The DefaultApplicationGroup or the DefaultUserTokenGroup of the server. Their
 * TrustList nodes resolve to the group as well. NULL otherwise. */
UA_CertificateGroup *
UA_GDS_getCertificateGroup(UA_ServerConfig *sc, const UA_NodeId *nodeId);

UA_SecurityPolicy *
UA_GDS_getSecPolicyByUri(UA_ServerConfig *sc, const UA_String *securityPolicyUri);

/* The key of the certificate must fit the certificate type (Part 12, 7.8.4):
 * Bad_CertificateInvalid otherwise. Types that the crypto backend cannot check
 * (for example certificate types of non-OPC UA applications) are accepted. */
UA_StatusCode
UA_GDS_checkCertificateType(const UA_NodeId *certificateTypeId,
                            const UA_ByteString *certificate);

/* The SecurityPolicies and endpoints changed by a certificate update */
typedef struct {
    size_t policiesSize;
    UA_SecurityPolicy **policies;
    size_t endpointsSize;
    UA_ByteString *endpointCertificates; /* Empty for unchanged endpoints */
} UA_GDSCertificateUpdate;

void
UA_GDSCertificateUpdate_clear(UA_GDSCertificateUpdate *update);

/* Resolve every SecurityPolicy and endpoint that uses the certificate type and
 * allocate the replacement endpoint certificates. Nothing is changed, so
 * configuration and allocation errors are reported before any live policy is
 * changed. A SecurityPolicy referenced by multiple endpoints is updated only
 * once. */
UA_StatusCode
UA_GDSCertificateUpdate_prepare(UA_GDSCertificateUpdate *update,
                                UA_ServerConfig *sc,
                                const UA_NodeId *certificateTypeId,
                                const UA_ByteString *certificate);

/* Update the SecurityPolicies and commit the prepared endpoint certificates.
 * SecurityPolicy implementations update their private state directly and do
 * not expose the previous private key for rollback. An unexpected failure from
 * a policy after an earlier policy succeeded is therefore logged explicitly.
 * The update is cleared. */
UA_StatusCode
UA_GDSCertificateUpdate_commit(UA_GDSCertificateUpdate *update,
                               UA_ServerConfig *sc,
                               const UA_ByteString certificate,
                               const UA_ByteString privateKey);

/* An open SecureChannel and the certificates it was opened with */
typedef struct UA_GDSChannel {
    LIST_ENTRY(UA_GDSChannel) pointers;
    UA_UInt32 channelId;
    UA_NodeId certificateTypeId;
    UA_ByteString certificate; /* The remote certificate */
} UA_GDSChannel;

typedef struct UA_GDSCore UA_GDSCore;

struct UA_GDSCore {
    UA_Driver *drv; /* The driver that hosts the core */

    /* The CertificateType slots of the DefaultApplicationGroup. These are the
     * certificate types that an endpoint uses, so that an update takes effect
     * (Part 12, 7.10.5). */
    size_t slotsSize;
    UA_GDSCertificateSlot *slots;

    LIST_HEAD(, UA_GDSChannel) channels;

    /* Delayed callbacks that use the core. When the last one has run, the idle
     * callback is called. Without it, a stopping host driver is stopped. */
    size_t pendingDelayedCallbacks;
    void (*idle)(UA_GDSCore *core);

    /* Set by the GDS Push driver. The pending changes of a transaction must not
     * be overwritten, so the GDS Pull driver waits until it is done. */
    UA_Boolean (*changesPending)(UA_GDSCore *core);

    /* Set by the GDS Push driver. Called after a TrustList was changed outside
     * of a transaction, so that its LastUpdateTime can be updated. */
    void (*trustListChanged)(UA_GDSCore *core, UA_CertificateGroup *group);
};

void
UA_GDSCore_init(UA_GDSCore *core, UA_Driver *drv);

void
UA_GDSCore_clear(UA_GDSCore *core);

/* The core of the started GDS Push driver of the server. Otherwise the core
 * given as fallback. */
UA_GDSCore *
UA_GDSCore_find(UA_Server *server, UA_GDSCore *fallback);

#ifdef UA_ENABLE_DRIVER_GDS_PUSH
/* The core of a GDS Push driver */
UA_GDSCore *
UA_GDSPush_getCore(UA_Driver *drv);
#endif

UA_Boolean
UA_GDSCore_changesPending(UA_GDSCore *core);

/* Create the slots for the certificate types that an endpoint uses. Pending
 * signing requests of the remaining types are kept. */
UA_StatusCode
UA_GDSCore_updateSlots(UA_GDSCore *core);

UA_GDSCertificateSlot *
UA_GDSCore_findSlot(UA_GDSCore *core, const UA_NodeId *certificateTypeId);

/* Track the SecureChannels. Forward the SecureChannel notifications of the
 * host driver. */
void
UA_GDSCore_handleNotification(UA_GDSCore *core,
                              UA_ApplicationNotificationType type,
                              const UA_KeyValueMap payload);

/* Check a new certificate for the slot of the type before it is installed:
 * the slot exists (Bad_InvalidArgument), the key fits the type
 * (Bad_CertificateInvalid) and the certificate belongs to the private key
 * (Bad_NotSupported). Without a private key, the certificate has to belong to
 * the current key or to the key of the pending signing request
 * (Bad_SecurityChecksFailed). The TrustList validation is up to the caller. */
UA_StatusCode
UA_GDSCore_checkCertificate(UA_GDSCore *core,
                            const UA_NodeId *certificateTypeId,
                            const UA_ByteString *certificate,
                            const UA_ByteString *privateKey);

/* Create a signing request with the SecurityPolicies of the type. The first
 * SecurityPolicy creates the request (and the new key), the others take over
 * the new key. A new request discards the pending request of the slot. If the
 * pending request of the other driver has a new key, the request is refused
 * with Bad_TransactionPending, as the key would be lost. */
UA_StatusCode
UA_GDSCore_createSigningRequest(UA_GDSCore *core, UA_GDSRequestOwner owner,
                                const UA_NodeId *certificateTypeId,
                                const UA_String *subjectName,
                                const UA_ByteString *nonce,
                                UA_Boolean regenerateKey,
                                UA_ByteString *csr);

/* The certificate of the type was installed. The pending signing request of
 * the slot is completed if it was created by the owner or if the certificate
 * belongs to its key. */
void
UA_GDSCore_certificateInstalled(UA_GDSCore *core, UA_GDSRequestOwner owner,
                                const UA_NodeId *certificateTypeId,
                                const UA_ByteString *certificate);

/* Check and install the certificate outside of a transaction. The
 * SecureChannels that use the certificate type are closed in the next
 * EventLoop iteration. Bad_TransactionPending while changes are pending. */
UA_StatusCode
UA_GDSCore_updateCertificate(UA_GDSCore *core, UA_GDSRequestOwner owner,
                             const UA_NodeId *certificateTypeId,
                             const UA_ByteString certificate,
                             const UA_ByteString privateKey);

/* Replace (setTrustList) or extend (addToTrustList) the TrustList of a
 * CertificateGroup outside of a transaction. The SecureChannels are verified
 * with the new TrustList of the DefaultApplicationGroup in the next EventLoop
 * iteration. Bad_TransactionPending while changes are pending. */
UA_StatusCode
UA_GDSCore_setTrustList(UA_GDSCore *core, const UA_NodeId *certificateGroupId,
                        const UA_TrustListDataType *trustList);

UA_StatusCode
UA_GDSCore_addToTrustList(UA_GDSCore *core, const UA_NodeId *certificateGroupId,
                          const UA_TrustListDataType *trustList);

/* Close the SecureChannels that use one of the certificate types */
void
UA_GDSCore_closeChannels(UA_GDSCore *core, size_t certificateTypesSize,
                         const UA_NodeId *certificateTypes);

/* Close the SecureChannels whose remote certificate is no longer valid */
void
UA_GDSCore_verifyChannels(UA_GDSCore *core);

/* A delayed callback that uses the core was added or has run */
void
UA_GDSCore_addDelayedCallback(UA_GDSCore *core, UA_DelayedCallback *dc);

void
UA_GDSCore_delayedCallbackDone(UA_GDSCore *core);

_UA_END_DECLS

#endif /* UA_ENABLE_DRIVER_GDS_PUSH || UA_ENABLE_DRIVER_GDS_PULL */

#endif /* UA_DRIVER_GDS_CORE_H_ */
