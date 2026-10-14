/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2024 (c) Fraunhofer IOSB (Author: Noel Graf)
 *    Copyright 2026 (c) o6 Automation GmbH (Author: Julius Pfrommer)
 *    Copyright 2026 (c) o6 Automation GmbH (Author: Andreas Ebner)
 */

#ifndef UA_DRIVER_GDS_PUSH_INTERNAL_H_
#define UA_DRIVER_GDS_PUSH_INTERNAL_H_

#include <open62541/driver/gds_push.h>

#ifdef UA_ENABLE_DRIVER_GDS_PUSH

_UA_BEGIN_DECLS

typedef struct UA_GDSPushContext UA_GDSPushContext;

/* A CertificateType slot of a CertificateGroup (Part 12, 7.8.3) with the state
 * of the last CreateSigningRequest for the type. The certificate and the key
 * of the slot are kept by the SecurityPolicies. */
typedef struct {
    UA_NodeId certificateTypeId;
    UA_ByteString pendingCsr;        /* The last CreateSigningRequest */
} UA_GDSCertificateSlot;

/* Discard the state of the last CreateSigningRequest */
void
UA_GDSCertificateSlot_clearPending(UA_GDSCertificateSlot *slot);

UA_GDSCertificateSlot *
UA_GDSCertificateSlots_find(UA_GDSCertificateSlot *slots, size_t slotsSize,
                            const UA_NodeId *certificateTypeId);

void
UA_GDSCertificateSlots_delete(UA_GDSCertificateSlot *slots, size_t slotsSize);

UA_StatusCode
UA_GDSPush_initNS0(UA_GDSPushContext *ctx);

void
UA_GDSPush_clearNS0(UA_GDSPushContext *ctx);

#ifdef UA_ENABLE_RBAC
/* Restrict the GDS PushManagement methods to the SecurityAdmin role
 * (OPC UA Part 12 v1.05 §7.2, §7.10.4) */
UA_StatusCode
UA_GDSPush_initRolePermissions(UA_Server *server);
#endif

UA_CertificateGroup *
UA_GDSPush_getCertGroup(UA_Server *server, const UA_NodeId *objectId);

/* The CertificateType slots of the DefaultApplicationGroup of the
 * ServerConfiguration. These are the certificate types that an endpoint uses,
 * so that an update takes effect (Part 12, 7.10.5). */
UA_GDSCertificateSlot *
UA_GDSPush_serverSlots(UA_GDSPushContext *ctx, size_t *slotsSize);

/* Write the CertificateTypes of the DefaultApplicationGroup from the slots */
UA_StatusCode
UA_GDSPush_writeCertificateTypes(UA_GDSPushContext *ctx);

/* The key of the certificate must fit the certificate type (Part 12, 7.8.4):
 * Bad_CertificateInvalid otherwise. Types that the crypto backend cannot check
 * (for example certificate types of non-OPC UA applications) are accepted. */
UA_StatusCode
UA_GDSPush_checkCertificateType(const UA_NodeId *certificateTypeId,
                                    const UA_ByteString *certificate);

UA_StatusCode
UA_GDSPush_writeOpenCount(UA_GDSPushContext *ctx, UA_CertificateGroup *group);

UA_StatusCode
UA_GDSPush_writeLastUpdateTime(UA_GDSPushContext *ctx, UA_CertificateGroup *group);

UA_StatusCode
UA_GDSPush_initFileInfos(UA_GDSPushContext *ctx, UA_UtcTime lastUpdateTime);

UA_StatusCode
UA_GDSPush_getFileInfoMetadata(UA_GDSPushContext *ctx,
                                  const UA_NodeId certificateGroupId,
                                  UA_UInt16 *openCount,
                                  UA_UtcTime *lastUpdateTime);

UA_Boolean
UA_GDSPush_transactionPending(UA_GDSPushContext *ctx);

UA_StatusCode
UA_GDSPush_applyChangesForSession(UA_GDSPushContext *ctx,
                                     const UA_NodeId *sessionId);

UA_StatusCode
UA_GDSPush_cancelChangesForSession(UA_GDSPushContext *ctx,
                                      const UA_NodeId *sessionId);

/* Bad_TransactionPending if another Session has a transaction */
UA_StatusCode
UA_GDSPush_checkTransaction(UA_GDSPushContext *ctx,
                                const UA_NodeId *sessionId);

/* Validate the new Certificate of an application with the TrustList of the
 * group (Part 4, 6.1.3 and Part 12, 7.10.5). The issuers must be in the
 * trusted or the issuer list. The TrustList staged in the transaction of the
 * Session is used if it exists. */
UA_StatusCode
UA_GDSPush_validateCertificate(UA_GDSPushContext *ctx,
                                   const UA_NodeId *sessionId,
                                   UA_CertificateGroup *certGroup,
                                   const UA_ByteString *certificate);

/* PushManagement requires an authenticated (Sign) or encrypted
 * (SignAndEncrypt) SecureChannel. Local calls of the admin Session are
 * allowed. Returns Bad_SecurityModeInsufficient otherwise. */
UA_StatusCode
UA_GDSPush_checkSecurityMode(UA_Server *server, const UA_NodeId *sessionId,
                                 UA_MessageSecurityMode minimum);

UA_StatusCode
UA_GDSPush_openTrustList(UA_GDSPushContext *ctx, UA_CertificateGroup *certGroup,
                            const UA_NodeId *sessionId, UA_Byte fileOpenMode,
                            UA_Variant *output);
UA_StatusCode
UA_GDSPush_getPositionTrustList(UA_GDSPushContext *ctx, UA_CertificateGroup *certGroup,
                                   const UA_NodeId *sessionId, UA_UInt32 fileHandle,
                                   UA_Variant *output);
UA_StatusCode
UA_GDSPush_closeTrustList(UA_GDSPushContext *ctx, UA_CertificateGroup *certGroup,
                             const UA_NodeId *sessionId, UA_UInt32 fileHandle);
UA_StatusCode
UA_GDSPush_closeAndUpdateTrustList(UA_GDSPushContext *ctx,
                                      UA_CertificateGroup *certGroup,
                                      const UA_NodeId *sessionId,
                                      UA_UInt32 fileHandle, UA_Variant *output);
UA_StatusCode
UA_GDSPush_setPositionTrustList(UA_GDSPushContext *ctx, UA_CertificateGroup *certGroup,
                                   const UA_NodeId *sessionId, UA_UInt32 fileHandle,
                                   UA_UInt64 position);
UA_StatusCode
UA_GDSPush_writeTrustList(UA_GDSPushContext *ctx, UA_CertificateGroup *certGroup,
                             const UA_NodeId *sessionId, UA_UInt32 fileHandle,
                             const UA_ByteString data);
UA_StatusCode
UA_GDSPush_openTrustListWithMask(UA_GDSPushContext *ctx, UA_CertificateGroup *certGroup,
                                    const UA_NodeId *sessionId, UA_UInt32 mask,
                                    UA_Variant *output);
UA_StatusCode
UA_GDSPush_getRejectedList(UA_GDSPushContext *ctx, size_t outputSize,
                              UA_Variant *output);
UA_StatusCode
UA_GDSPush_readTrustList(UA_GDSPushContext *ctx, UA_CertificateGroup *certGroup,
                            const UA_NodeId *sessionId, UA_UInt32 fileHandle,
                            UA_Int32 length, UA_Variant *output);
UA_StatusCode
UA_GDSPush_stageCertificateUpdate(UA_GDSPushContext *ctx, const UA_NodeId *sessionId,
                                const UA_NodeId *certificateGroupId,
                                const UA_NodeId *certificateTypeId,
                                const UA_ByteString *certificate,
                                const UA_String *privateKeyFormat,
                                const UA_ByteString *privateKey);
UA_StatusCode
UA_GDSPush_addCertificate(UA_GDSPushContext *ctx, UA_CertificateGroup *certGroup,
                             UA_ByteString *certificate,
                             const UA_Boolean *isTrustedCertificate);
UA_StatusCode
UA_GDSPush_removeCertificate(UA_GDSPushContext *ctx,
                                UA_CertificateGroup *certGroup,
                                const UA_NodeId *sessionId,
                                const UA_String *thumbprint,
                                const UA_Boolean *isTrustedCertificate);

_UA_END_DECLS

#endif /* UA_ENABLE_DRIVER_GDS_PUSH */

#endif /* UA_DRIVER_GDS_PUSH_INTERNAL_H_ */
