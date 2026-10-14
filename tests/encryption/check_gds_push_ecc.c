/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2026 (c) o6 Automation GmbH (Author: Andreas Ebner)
 */

/* The GDS Push with RSA and ECC application certificates (OPC UA Part 12,
 * 7.8.4). The server has RSA endpoints and ECC endpoints with their own
 * certificates. */

#include <open62541/driver/gds_push.h>
#include <open62541/plugin/create_certificate.h>
#include <open62541/plugin/log_stdout.h>
#include <open62541/server_config_default.h>

#include <check.h>
#include <stdlib.h>
#include <string.h>

#include "test_helpers.h"
#include "certificates.h"

#ifdef UA_ENABLE_ENCRYPTION_OPENSSL
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#endif

#define TYPE(ID) UA_NODEID_NUMERIC(0, UA_NS0ID_##ID##APPLICATIONCERTIFICATETYPE)

static UA_Server *server;
static UA_GDSPushDriver *driver;

static void
setup(void) {
    /* With a TrustList, the certificate groups are Memorystores. Certificates
     * can be added to them. */
    UA_ByteString certificate = {CERT_DER_LENGTH, CERT_DER_DATA};
    UA_ByteString privateKey = {KEY_DER_LENGTH, KEY_DER_DATA};
    server = UA_Server_newForUnitTestWithSecurityPolicies(4840, &certificate,
                                                          &privateKey, &certificate, 1,
                                                          NULL, 0, NULL, 0);
    ck_assert_ptr_nonnull(server);
    UA_ServerConfig *config = UA_Server_getConfig(server);

    /* P-384 is added before P-256. The CertificateTypes have a fixed order. */
    UA_ByteString p384Certificate = {CERT_P384_DER_LENGTH, CERT_P384_DER_DATA};
    UA_ByteString p384Key = {KEY_P384_DER_LENGTH, KEY_P384_DER_DATA};
    ck_assert_uint_eq(UA_ServerConfig_addSecurityPolicyEccNistP384(
                          config, &p384Certificate, &p384Key), UA_STATUSCODE_GOOD);
    UA_ByteString p256Certificate = {CERT_P256_DER_LENGTH, CERT_P256_DER_DATA};
    UA_ByteString p256Key = {KEY_P256_DER_LENGTH, KEY_P256_DER_DATA};
    ck_assert_uint_eq(UA_ServerConfig_addSecurityPolicyEccNistP256(
                          config, &p256Certificate, &p256Key), UA_STATUSCODE_GOOD);
#ifdef UA_ENABLE_ENCRYPTION_OPENSSL
    UA_ByteString ed25519Certificate = {CERT_ED25519_DER_LENGTH, CERT_ED25519_DER_DATA};
    UA_ByteString ed25519Key = {KEY_ED25519_DER_LENGTH, KEY_ED25519_DER_DATA};
    ck_assert_uint_eq(UA_ServerConfig_addSecurityPolicyEccCurve25519(
                          config, &ed25519Certificate, &ed25519Key),
                      UA_STATUSCODE_GOOD);
#endif
    ck_assert_uint_eq(UA_ServerConfig_addAllEndpoints(config), UA_STATUSCODE_GOOD);

    driver = UA_GDSPushDriver_new(UA_KEYVALUEMAP_NULL);
    ck_assert_ptr_nonnull(driver);
    ck_assert_uint_eq(UA_Server_addDriver(server, &driver->drv),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(UA_Server_run_startup(server), UA_STATUSCODE_GOOD);
}

static void
teardown(void) {
    UA_Server_run_shutdown(server);
    UA_Server_delete(server);
    server = NULL;
    driver = NULL;
}

/* The first SecurityPolicy with the certificate type */
static UA_SecurityPolicy *
policyOfType(const UA_NodeId type) {
    UA_ServerConfig *config = UA_Server_getConfig(server);
    for(size_t i = 0; i < config->securityPoliciesSize; i++) {
        if(UA_NodeId_equal(&config->securityPolicies[i].certificateTypeId, &type))
            return &config->securityPolicies[i];
    }
    return NULL;
}

/* The certificates of all SecurityPolicies */
static UA_ByteString *
snapshotCertificates(void) {
    UA_ServerConfig *config = UA_Server_getConfig(server);
    UA_ByteString *certificates = (UA_ByteString*)
        UA_calloc(config->securityPoliciesSize, sizeof(UA_ByteString));
    ck_assert_ptr_nonnull(certificates);
    for(size_t i = 0; i < config->securityPoliciesSize; i++)
        ck_assert_uint_eq(UA_ByteString_copy(&config->securityPolicies[i].localCertificate,
                                             &certificates[i]), UA_STATUSCODE_GOOD);
    return certificates;
}

/* Only the SecurityPolicies of the type have the new certificate. The snapshot
 * is deleted. */
static void
checkCertificates(UA_ByteString *snapshot, const UA_NodeId type,
                  const UA_ByteString *newCertificate) {
    UA_ServerConfig *config = UA_Server_getConfig(server);
    for(size_t i = 0; i < config->securityPoliciesSize; i++) {
        UA_SecurityPolicy *sp = &config->securityPolicies[i];
        if(newCertificate && UA_NodeId_equal(&sp->certificateTypeId, &type))
            ck_assert(UA_ByteString_equal(&sp->localCertificate, newCertificate));
        else
            ck_assert(UA_ByteString_equal(&sp->localCertificate, &snapshot[i]));
    }
    UA_Array_delete(snapshot, config->securityPoliciesSize,
                    &UA_TYPES[UA_TYPES_BYTESTRING]);
}

/* A self-signed certificate with the ApplicationUri of the server. The
 * ecc-curve NULL creates an RSA key. */
static void
createCertificate(const char *eccCurve, UA_ByteString *certificate,
                  UA_ByteString *privateKey) {
    UA_ServerConfig *config = UA_Server_getConfig(server);
    UA_String subject[2] = {UA_STRING_STATIC("C=DE"),
                            UA_STRING_STATIC("CN=open62541 ECC test")};
    UA_String subjectAltName = UA_STRING_NULL;
    ck_assert_uint_eq(UA_String_format(&subjectAltName, "URI:%S",
                                       config->applicationDescription.applicationUri),
                      UA_STATUSCODE_GOOD);
    UA_String keyType = UA_STRING_STATIC("EC");
    UA_String curve = UA_STRING((char*)(uintptr_t)eccCurve);
    UA_UInt16 keySize = 2048;
    UA_KeyValuePair params[2];
    UA_KeyValueMap map = {1, params};
    if(eccCurve) {
        params[0].key = UA_QUALIFIEDNAME(0, "key-type");
        UA_Variant_setScalar(&params[0].value, &keyType, &UA_TYPES[UA_TYPES_STRING]);
        params[1].key = UA_QUALIFIEDNAME(0, "ecc-curve");
        UA_Variant_setScalar(&params[1].value, &curve, &UA_TYPES[UA_TYPES_STRING]);
        map.mapSize = 2;
    } else {
        params[0].key = UA_QUALIFIEDNAME(0, "key-size-bits");
        UA_Variant_setScalar(&params[0].value, &keySize, &UA_TYPES[UA_TYPES_UINT16]);
    }
    UA_StatusCode res =
        UA_CreateCertificate(UA_Log_Stdout, subject, 2, &subjectAltName, 1,
                             UA_CERTIFICATEFORMAT_DER, &map, privateKey,
                             certificate);
    UA_String_clear(&subjectAltName);
    ck_assert_uint_eq(res, UA_STATUSCODE_GOOD);
}

/* The CertificateTypes are the known types that an endpoint uses, in a fixed
 * order */
START_TEST(certificate_types) {
    UA_Variant value;
    UA_Variant_init(&value);
    ck_assert_uint_eq(UA_Server_readValue(server, UA_NODEID_NUMERIC(0,
        UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_CERTIFICATETYPES),
        &value), UA_STATUSCODE_GOOD);
    ck_assert(UA_Variant_hasArrayType(&value, &UA_TYPES[UA_TYPES_NODEID]));
    UA_NodeId expected[] = {
        TYPE(RSASHA256), TYPE(ECCNISTP256), TYPE(ECCNISTP384),
#ifdef UA_ENABLE_ENCRYPTION_OPENSSL
        TYPE(ECCCURVE25519)
#endif
    };
    size_t expectedSize = sizeof(expected) / sizeof(expected[0]);
    ck_assert_uint_eq(value.arrayLength, expectedSize);
    for(size_t i = 0; i < expectedSize; i++)
        ck_assert(UA_NodeId_equal(&((UA_NodeId*)value.data)[i], &expected[i]));
    UA_Variant_clear(&value);
} END_TEST

/* An ECC certificate changes only the SecurityPolicies of its type */
START_TEST(update_ecc_certificate) {
    UA_ByteString certificate, privateKey;
    createCertificate("prime256v1", &certificate, &privateKey);
    UA_ByteString *snapshot = snapshotCertificates();
    ck_assert_uint_eq(UA_GDSPushDriver_updateCertificate(driver, UA_NODEID_NULL,
                                                       TYPE(ECCNISTP256), certificate,
                                                       &privateKey),
                      UA_STATUSCODE_GOOD);
    checkCertificates(snapshot, TYPE(ECCNISTP256), &certificate);
    UA_ByteString_clear(&certificate);
    UA_ByteString_clear(&privateKey);
} END_TEST

/* The key of the certificate must fit the certificate type (Part 12,
 * 7.8.4) */
START_TEST(update_wrong_key_type) {
    UA_ByteString p384 = {CERT_P384_DER_LENGTH, CERT_P384_DER_DATA};
    UA_ByteString p384Key = {KEY_P384_DER_LENGTH, KEY_P384_DER_DATA};
    UA_ByteString bp256 = {CERT_BP256R1_DER_LENGTH, CERT_BP256R1_DER_DATA};
    UA_ByteString bp256Key = {KEY_BP256R1_DER_LENGTH, KEY_BP256R1_DER_DATA};
    UA_ByteString rsa = {CERT_DER_LENGTH, CERT_DER_DATA};
    UA_ByteString rsaKey = {KEY_DER_LENGTH, KEY_DER_DATA};
    UA_ByteString p256 = {CERT_P256_DER_LENGTH, CERT_P256_DER_DATA};
    UA_ByteString p256Key = {KEY_P256_DER_LENGTH, KEY_P256_DER_DATA};

    UA_ByteString *snapshot = snapshotCertificates();
    /* Another curve, another curve of the same size, RSA for ECC */
    ck_assert_uint_eq(UA_GDSPushDriver_updateCertificate(driver, UA_NODEID_NULL,
                                                       TYPE(ECCNISTP256), p384, &p384Key),
                      UA_STATUSCODE_BADCERTIFICATEINVALID);
    ck_assert_uint_eq(UA_GDSPushDriver_updateCertificate(driver, UA_NODEID_NULL,
                                                       TYPE(ECCNISTP256), bp256, &bp256Key),
                      UA_STATUSCODE_BADCERTIFICATEINVALID);
    ck_assert_uint_eq(UA_GDSPushDriver_updateCertificate(driver, UA_NODEID_NULL,
                                                       TYPE(ECCNISTP256), rsa, &rsaKey),
                      UA_STATUSCODE_BADCERTIFICATEINVALID);
    /* ECC for RSA */
    ck_assert_uint_eq(UA_GDSPushDriver_updateCertificate(driver, UA_NODEID_NULL,
                                                       TYPE(RSASHA256), p256, &p256Key),
                      UA_STATUSCODE_BADCERTIFICATEINVALID);
    /* No endpoint uses the type */
    ck_assert_uint_eq(UA_GDSPushDriver_updateCertificate(driver, UA_NODEID_NULL,
                                                       TYPE(ECCBRAINPOOLP256R1), bp256,
                                                       &bp256Key),
                      UA_STATUSCODE_BADINVALIDARGUMENT);
    checkCertificates(snapshot, TYPE(ECCNISTP256), NULL);
} END_TEST

/* Without a private key, the certificate must belong to a known key */
START_TEST(update_without_private_key) {
    UA_ByteString p256 = {CERT_P256_DER_LENGTH, CERT_P256_DER_DATA};
    ck_assert_uint_eq(UA_GDSPushDriver_updateCertificate(driver, UA_NODEID_NULL,
                                                       TYPE(ECCNISTP256), p256, NULL),
                      UA_STATUSCODE_GOOD);

    UA_ByteString certificate, privateKey;
    createCertificate("prime256v1", &certificate, &privateKey);
    UA_ByteString *snapshot = snapshotCertificates();
    ck_assert_uint_eq(UA_GDSPushDriver_updateCertificate(driver, UA_NODEID_NULL,
                                                       TYPE(ECCNISTP256), certificate,
                                                       NULL),
                      UA_STATUSCODE_BADSECURITYCHECKSFAILED);
    checkCertificates(snapshot, TYPE(ECCNISTP256), NULL);
    UA_ByteString_clear(&certificate);
    UA_ByteString_clear(&privateKey);
} END_TEST

#if defined(UA_ENABLE_ENCRYPTION_OPENSSL) && OPENSSL_VERSION_NUMBER >= 0x30000000L
/* Issue a certificate for the key and the subject of a CSR */
static UA_ByteString
signCsr(const UA_ByteString *csr) {
    const unsigned char *p = csr->data;
    X509_REQ *request = d2i_X509_REQ(NULL, &p, (long)csr->length);
    ck_assert_ptr_nonnull(request);
    EVP_PKEY *requestKey = X509_REQ_get_pubkey(request);
    ck_assert_ptr_nonnull(requestKey);
    EVP_PKEY *issuerKey = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "prime256v1");
    ck_assert_ptr_nonnull(issuerKey);

    X509 *certificate = X509_new();
    ck_assert_ptr_nonnull(certificate);
    X509_set_version(certificate, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(certificate), 2);
    X509_set_subject_name(certificate, X509_REQ_get_subject_name(request));
    X509_set_issuer_name(certificate, X509_REQ_get_subject_name(request));
    X509_gmtime_adj(X509_getm_notBefore(certificate), -3600);
    X509_gmtime_adj(X509_getm_notAfter(certificate), 3600 * 24);
    X509_set_pubkey(certificate, requestKey);
    STACK_OF(X509_EXTENSION) *extensions = X509_REQ_get_extensions(request);
    for(int i = 0; i < sk_X509_EXTENSION_num(extensions); i++)
        X509_add_ext(certificate, sk_X509_EXTENSION_value(extensions, i), -1);
    sk_X509_EXTENSION_pop_free(extensions, X509_EXTENSION_free);
    ck_assert_int_gt(X509_sign(certificate, issuerKey, EVP_sha256()), 0);

    unsigned char *der = NULL;
    int derLength = i2d_X509(certificate, &der);
    ck_assert_int_gt(derLength, 0);
    UA_ByteString result;
    ck_assert_uint_eq(UA_ByteString_allocBuffer(&result, (size_t)derLength),
                      UA_STATUSCODE_GOOD);
    memcpy(result.data, der, (size_t)derLength);
    OPENSSL_free(der);
    X509_free(certificate);
    EVP_PKEY_free(issuerKey);
    EVP_PKEY_free(requestKey);
    X509_REQ_free(request);
    return result;
}

static UA_ByteString
createSigningRequest(UA_Boolean regenerateKey) {
    UA_Byte nonceData[32];
    memset(nonceData, 0x2a, sizeof(nonceData));
    UA_ByteString nonce = {sizeof(nonceData), nonceData};
    UA_ByteString csr = UA_BYTESTRING_NULL;
    ck_assert_uint_eq(UA_GDSPushDriver_createSigningRequest(driver, UA_NODEID_NULL,
                                                          TYPE(ECCNISTP256), NULL,
                                                          &regenerateKey, &nonce,
                                                          &csr),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_gt(csr.length, 0);
    return csr;
}

/* The key of a CSR is used for the signed certificate (Part 12, 7.10.10) */
START_TEST(signing_request_new_key) {
    UA_ByteString csr = createSigningRequest(true);
    UA_ByteString certificate = signCsr(&csr);
    UA_ByteString p256 = {CERT_P256_DER_LENGTH, CERT_P256_DER_DATA};
    ck_assert(UA_CertificateUtils_comparePublicKeys(&certificate, &p256) !=
              UA_STATUSCODE_GOOD);

    UA_ByteString *snapshot = snapshotCertificates();
    ck_assert_uint_eq(UA_GDSPushDriver_updateCertificate(driver, UA_NODEID_NULL,
                                                       TYPE(ECCNISTP256), certificate,
                                                       NULL),
                      UA_STATUSCODE_GOOD);
    checkCertificates(snapshot, TYPE(ECCNISTP256), &certificate);
    UA_ByteString_clear(&certificate);
    UA_ByteString_clear(&csr);
} END_TEST

/* A request for the current key discards the key of an earlier request */
START_TEST(signing_request_discarded) {
    UA_ByteString csr = createSigningRequest(true);
    UA_ByteString certificate = signCsr(&csr);
    UA_ByteString plainCsr = createSigningRequest(false);

    UA_ByteString *snapshot = snapshotCertificates();
    ck_assert_uint_eq(UA_GDSPushDriver_updateCertificate(driver, UA_NODEID_NULL,
                                                       TYPE(ECCNISTP256), certificate,
                                                       NULL),
                      UA_STATUSCODE_BADSECURITYCHECKSFAILED);
    checkCertificates(snapshot, TYPE(ECCNISTP256), NULL);
    UA_ByteString_clear(&certificate);
    UA_ByteString_clear(&csr);
    UA_ByteString_clear(&plainCsr);
} END_TEST
#endif

static UA_StatusCode
callUpdateCertificate(const UA_NodeId type, UA_ByteString *certificate,
                      UA_ByteString *privateKey) {
    UA_NodeId group = UA_NODEID_NUMERIC(0,
        UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP);
    UA_String format = UA_STRING_STATIC("DER");
    UA_Variant input[6];
    UA_Variant_setScalar(&input[0], &group, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&input[1], (void*)(uintptr_t)&type, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&input[2], certificate, &UA_TYPES[UA_TYPES_BYTESTRING]);
    UA_Variant_setArray(&input[3], NULL, 0, &UA_TYPES[UA_TYPES_BYTESTRING]);
    UA_Variant_setScalar(&input[4], &format, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setScalar(&input[5], privateKey, &UA_TYPES[UA_TYPES_BYTESTRING]);
    UA_CallMethodRequest request;
    UA_CallMethodRequest_init(&request);
    request.objectId = UA_NODEID_NUMERIC(0, UA_NS0ID_SERVERCONFIGURATION);
    request.methodId = UA_NODEID_NUMERIC(0, UA_NS0ID_SERVERCONFIGURATION_UPDATECERTIFICATE);
    request.inputArgumentsSize = 6;
    request.inputArguments = input;
    UA_CallMethodResult result = UA_Server_call(server, &request);
    UA_StatusCode res = result.statusCode;
    UA_CallMethodResult_clear(&result);
    return res;
}

/* An RSA and an ECC certificate are applied together with ApplyChanges */
START_TEST(mixed_transaction) {
    UA_ByteString rsa, rsaKey, p384, p384Key;
    createCertificate(NULL, &rsa, &rsaKey);
    createCertificate("secp384r1", &p384, &p384Key);

    /* UpdateCertificate validates the certificates with the TrustList */
    UA_ByteString trusted[2] = {rsa, p384};
    ck_assert_uint_eq(UA_Server_addCertificates(server, UA_NODEID_NUMERIC(0,
        UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP),
        trusted, 2, NULL, 0, true, true), UA_STATUSCODE_GOOD);

    UA_ByteString *snapshot = snapshotCertificates();
    ck_assert_uint_eq(callUpdateCertificate(TYPE(RSASHA256), &rsa, &rsaKey),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(callUpdateCertificate(TYPE(ECCNISTP384), &p384, &p384Key),
                      UA_STATUSCODE_GOOD);
    /* Staged, not applied */
    checkCertificates(snapshot, TYPE(RSASHA256), NULL);

    UA_CallMethodRequest request;
    UA_CallMethodRequest_init(&request);
    request.objectId = UA_NODEID_NUMERIC(0, UA_NS0ID_SERVERCONFIGURATION);
    request.methodId = UA_NODEID_NUMERIC(0, UA_NS0ID_SERVERCONFIGURATION_APPLYCHANGES);
    UA_CallMethodResult result = UA_Server_call(server, &request);
    ck_assert_uint_eq(result.statusCode, UA_STATUSCODE_GOOD);
    UA_CallMethodResult_clear(&result);

    ck_assert(UA_ByteString_equal(&policyOfType(TYPE(RSASHA256))->localCertificate, &rsa));
    ck_assert(UA_ByteString_equal(&policyOfType(TYPE(ECCNISTP384))->localCertificate, &p384));
    ck_assert(!UA_ByteString_equal(&policyOfType(TYPE(ECCNISTP256))->localCertificate, &p384));

    UA_ByteString_clear(&rsa);
    UA_ByteString_clear(&rsaKey);
    UA_ByteString_clear(&p384);
    UA_ByteString_clear(&p384Key);
} END_TEST

/* The number of endpoints is not limited */
START_TEST(update_many_endpoints) {
    UA_ServerConfig *config = UA_Server_getConfig(server);
    UA_SecurityPolicy *p256Policy = policyOfType(TYPE(ECCNISTP256));
    ck_assert_ptr_nonnull(p256Policy);
    size_t p256Endpoint = config->endpointsSize;
    for(size_t i = 0; i < config->endpointsSize; i++) {
        if(UA_String_equal(&config->endpoints[i].securityPolicyUri,
                           &p256Policy->policyUri))
            p256Endpoint = i;
    }
    ck_assert_uint_lt(p256Endpoint, config->endpointsSize);

    const size_t added = 40;
    size_t oldSize = config->endpointsSize;
    UA_EndpointDescription *endpoints = (UA_EndpointDescription*)
        UA_realloc(config->endpoints,
                   sizeof(UA_EndpointDescription) * (oldSize + added));
    ck_assert_ptr_nonnull(endpoints);
    config->endpoints = endpoints;
    for(size_t i = 0; i < added; i++)
        ck_assert_uint_eq(UA_EndpointDescription_copy(&config->endpoints[p256Endpoint],
                                                      &config->endpoints[oldSize + i]),
                          UA_STATUSCODE_GOOD);
    config->endpointsSize += added;

    UA_ByteString certificate, privateKey;
    createCertificate("prime256v1", &certificate, &privateKey);
    ck_assert_uint_eq(UA_GDSPushDriver_updateCertificate(driver, UA_NODEID_NULL,
                                                       TYPE(ECCNISTP256), certificate,
                                                       &privateKey),
                      UA_STATUSCODE_GOOD);
    for(size_t i = 0; i < config->endpointsSize; i++) {
        if(UA_String_equal(&config->endpoints[i].securityPolicyUri,
                           &p256Policy->policyUri))
            ck_assert(UA_ByteString_equal(&config->endpoints[i].serverCertificate,
                                          &certificate));
    }
    UA_ByteString_clear(&certificate);
    UA_ByteString_clear(&privateKey);
} END_TEST

int
main(void) {
    Suite *suite = suite_create("GDS Push ECC");
    TCase *tc = tcase_create("ECC");
    tcase_add_checked_fixture(tc, setup, teardown);
    tcase_add_test(tc, certificate_types);
    tcase_add_test(tc, update_ecc_certificate);
    tcase_add_test(tc, update_wrong_key_type);
    tcase_add_test(tc, update_without_private_key);
#if defined(UA_ENABLE_ENCRYPTION_OPENSSL) && OPENSSL_VERSION_NUMBER >= 0x30000000L
    tcase_add_test(tc, signing_request_new_key);
    tcase_add_test(tc, signing_request_discarded);
#endif
    tcase_add_test(tc, mixed_transaction);
    tcase_add_test(tc, update_many_endpoints);
    suite_add_tcase(suite, tc);

    SRunner *runner = srunner_create(suite);
    srunner_set_fork_status(runner, CK_NOFORK);
    srunner_run_all(runner, CK_NORMAL);
    int failed = srunner_ntests_failed(runner);
    srunner_free(runner);
    return (failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
