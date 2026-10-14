/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2026 (c) o6 Automation GmbH (Author: Julius Pfrommer)
 *    Copyright 2026 (c) o6 Automation GmbH (Author: Andreas Ebner)
 */

#ifndef UA_DRIVER_GDS_PUSH_H_
#define UA_DRIVER_GDS_PUSH_H_

#include <open62541/server.h>

/**
 * GDS Push Driver
 * ---------------
 *
 * The GDS Push driver implements the server side of OPC UA PushManagement
 * (Part 12, 7.4): a CertificateManager such as a GDS pushes certificates and
 * trust lists to this server. It exposes the ServerConfiguration methods for
 * updating the application certificates and the CertificateGroup trust lists.
 * Changes are collected in a transaction and applied together with the
 * ApplyChanges method. The driver also tracks active sessions and
 * SecureChannels so that abandoned transactions can be discarded and affected
 * channels can be revalidated or closed after an update. The counterpart is
 * the GDS Pull driver, with which the application requests certificates and
 * trust lists from a CertificateManager (PullManagement).
 *
 * Build open62541 with ``UA_ENABLE_DRIVER_GDS_PUSH`` enabled. PushManagement
 * additionally requires encryption and the full Namespace Zero.
 *
 * Create the driver with UA_GDSPushDriver_new() and attach its ``drv`` member
 * to the server with UA_Server_addDriver() before calling
 * UA_Server_run_startup(). A server can have at most one GDS Push driver. The
 * server takes ownership of the driver after it has been added successfully. */

#ifdef UA_ENABLE_DRIVER_GDS_PUSH

_UA_BEGIN_DECLS

typedef struct UA_GDSPushDriver {
    UA_Driver drv; /* Must be the first member */
} UA_GDSPushDriver;

/* Create a GDS Push driver. The returned driver is heap-allocated and
 * must either be passed to UA_Server_addDriver() or released with its ``free``
 * callback. No parameters are defined yet, pass UA_KEYVALUEMAP_NULL. Returns
 * NULL if allocation fails. */
UA_EXPORT UA_GDSPushDriver *
UA_GDSPushDriver_new(const UA_KeyValueMap params);

/* Update the application certificate used by the server endpoints. The GDS
 * Push driver must be attached and started. If certificateGroupId is
 * null, the DefaultApplicationGroup is used.
 *
 * The certificate type must be one of the CertificateTypes of the group. These
 * are the RSA and ECC application certificate types (RsaMin, RsaSha256,
 * EccNistP256, EccNistP384, EccBrainpoolP256r1, EccBrainpoolP384r1,
 * EccCurve25519, EccCurve448) that an endpoint uses. All SecurityPolicies with
 * the type get the new certificate. Without a private key (NULL or empty), the
 * current key or the key of the last signing request for the type is used if
 * it belongs to the certificate.
 *
 * Returns BadInvalidArgument for a null driver, an empty certificate or a
 * certificate type that is not used, BadCertificateInvalid if the key of the
 * certificate does not fit the type, BadNotSupported if the private key does
 * not belong to the certificate, BadSecurityChecksFailed if no key is known
 * for the certificate and BadInvalidState if the driver is not attached and
 * started. This function is thread-safe. */
UA_EXPORT UA_StatusCode
UA_GDSPushDriver_updateCertificate(UA_GDSPushDriver *driver,
                                const UA_NodeId certificateGroupId,
                                const UA_NodeId certificateTypeId,
                                const UA_ByteString certificate,
                                const UA_ByteString *privateKey);

/* Create a PKCS #10 DER-encoded certificate signing request. The GDS Push
 * driver must be attached and started. If certificateGroupId is null,
 * the DefaultApplicationGroup is used. With regenerateKey, a new key of the
 * certificate type is created and kept by the SecurityPolicies until the
 * signed certificate is updated without a private key. A later request for
 * the same type discards it. Returns BadInvalidArgument for a null driver or
 * output pointer and for a certificate type that is not used, and
 * BadInvalidState if the driver is not attached and started. This function
 * is thread-safe. */
UA_EXPORT UA_StatusCode
UA_GDSPushDriver_createSigningRequest(UA_GDSPushDriver *driver,
                                   const UA_NodeId certificateGroupId,
                                   const UA_NodeId certificateTypeId,
                                   const UA_String *subjectName,
                                   const UA_Boolean *regenerateKey,
                                   const UA_ByteString *nonce,
                                   UA_ByteString *csr);

_UA_END_DECLS

#endif /* UA_ENABLE_DRIVER_GDS_PUSH */

#endif /* UA_DRIVER_GDS_PUSH_H_ */
