/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/* Certificate validation as defined in OPC UA Part 4, 6.1.3 (Table 100) with
 * the certificate profiles of Part 6, 6.2. Each TCase covers one validation
 * step. The tests check the exact StatusCode of verifyCertificate in the
 * memorystore and in the filestore. The Security Policy Check (step 4) gets no
 * SecurityPolicy in the CertificateGroup and is tested on the SecurityPolicy
 * itself. The test PKI is described in certificates_validation.h.
 *
 * Unless stated otherwise, a test uses the default setup: R trusted, I in the
 * issuer list and the (empty) CRLs of R and I loaded. L validates against it. */

#include <open62541/plugin/certificategroup_default.h>
#include <open62541/plugin/create_certificate.h>
#include <open62541/plugin/log_stdout.h>
#include <open62541/plugin/securitypolicy_default.h>

#ifdef UA_ENABLE_ENCRYPTION_MBEDTLS
#include <mbedtls/version.h>
#endif

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "certificates_validation.h"
#include "check.h"

#if defined(__linux__) || defined(__APPLE__) || defined(__OpenBSD__)
#define TEST_FILESTORE
#include <dirent.h>
#include <unistd.h>
#define STORE_PATH "pki-cert-validation-steps"
#endif

#if defined(UA_ENABLE_ENCRYPTION_OPENSSL) || \
    (defined(UA_ENABLE_ENCRYPTION_MBEDTLS) && MBEDTLS_VERSION_MAJOR >= 3)
#define TEST_ECC_POLICY
#endif

/* Number of mesh levels used for the bounded chain search */
#define MESH_LEVELS 7

/* Mismatches are collected during a test and reported at its end. So a failing
 * test shows all mismatches, not only the first one. */

static char mismatches[8192];

static void
resetMismatches(void) {
    mismatches[0] = '\0';
}

static void
addMismatch(const char *format, ...) {
    size_t len = strlen(mismatches);
    if(len > 0 && len + 2 < sizeof(mismatches)) {
        memcpy(&mismatches[len], "; ", 3);
        len += 2;
    }
    va_list ap;
    va_start(ap, format);
    vsnprintf(&mismatches[len], sizeof(mismatches) - len, format, ap);
    va_end(ap);
}

static void
reportMismatches(void) {
    ck_assert_msg(mismatches[0] == '\0', "%s", mismatches);
}

/* Helpers for ByteStrings */

#define BS(arr) bs(arr, sizeof(arr))
#define BS_INIT(arr) {sizeof(arr), arr}

static UA_ByteString
bs(UA_Byte *data, size_t length) {
    UA_ByteString b = {length, data};
    return b;
}

static UA_ByteString
concat(size_t partsSize, const UA_ByteString *parts) {
    size_t length = 0;
    for(size_t i = 0; i < partsSize; i++)
        length += parts[i].length;
    UA_ByteString out;
    UA_StatusCode res = UA_ByteString_allocBuffer(&out, length);
    ck_assert_uint_eq(res, UA_STATUSCODE_GOOD);
    size_t pos = 0;
    for(size_t i = 0; i < partsSize; i++) {
        memcpy(&out.data[pos], parts[i].data, parts[i].length);
        pos += parts[i].length;
    }
    return out;
}

/* Encode as PEM certificate with 64 characters per line */
static UA_ByteString
toPem(const UA_ByteString *der) {
    static const char head[] = "-----BEGIN CERTIFICATE-----\n";
    static const char tail[] = "-----END CERTIFICATE-----\n";
    UA_String b64 = UA_STRING_NULL;
    UA_StatusCode res = UA_ByteString_toBase64(der, &b64);
    ck_assert_uint_eq(res, UA_STATUSCODE_GOOD);
    size_t lines = (b64.length + 63) / 64;
    UA_ByteString out;
    res = UA_ByteString_allocBuffer(&out, strlen(head) + b64.length + lines +
                                    strlen(tail));
    ck_assert_uint_eq(res, UA_STATUSCODE_GOOD);
    size_t pos = 0;
    memcpy(out.data, head, strlen(head));
    pos += strlen(head);
    for(size_t i = 0; i < b64.length; i += 64) {
        size_t n = (b64.length - i < 64) ? b64.length - i : 64;
        memcpy(&out.data[pos], &b64.data[i], n);
        pos += n;
        out.data[pos++] = '\n';
    }
    memcpy(&out.data[pos], tail, strlen(tail));
    UA_String_clear(&b64);
    return out;
}

/* Concatenate the PEM encodings of several DER certificates */
static UA_ByteString
pemChain(size_t dersSize, const UA_ByteString *ders) {
    UA_ByteString pems[8];
    ck_assert_uint_le(dersSize, 8);
    for(size_t i = 0; i < dersSize; i++)
        pems[i] = toPem(&ders[i]);
    UA_ByteString out = concat(dersSize, pems);
    for(size_t i = 0; i < dersSize; i++)
        UA_ByteString_clear(&pems[i]);
    return out;
}

/* Copy with the last byte flipped. For certificates and CRLs, the last byte is
 * part of the signature value. */
static UA_ByteString
flipLastByte(const UA_ByteString *in) {
    UA_ByteString out;
    UA_StatusCode res = UA_ByteString_copy(in, &out);
    ck_assert_uint_eq(res, UA_STATUSCODE_GOOD);
    out.data[out.length - 1] ^= 0x01;
    return out;
}

/* The test PKI. The trust list is assembled per test. */

#define PKI_MAX 16

typedef struct {
    UA_ByteString trusted[PKI_MAX];
    size_t trustedSize;
    UA_ByteString issuers[PKI_MAX];
    size_t issuersSize;
    UA_ByteString trustedCrls[PKI_MAX];
    size_t trustedCrlsSize;
    UA_ByteString issuerCrls[PKI_MAX];
    size_t issuerCrlsSize;
} Pki;

static void
pkiTrust(Pki *pki, UA_ByteString cert) {
    ck_assert_uint_lt(pki->trustedSize, PKI_MAX);
    pki->trusted[pki->trustedSize++] = cert;
}

static void
pkiIssuer(Pki *pki, UA_ByteString cert) {
    ck_assert_uint_lt(pki->issuersSize, PKI_MAX);
    pki->issuers[pki->issuersSize++] = cert;
}

static void
pkiCrl(Pki *pki, UA_ByteString crl) {
    ck_assert_uint_lt(pki->trustedCrlsSize, PKI_MAX);
    pki->trustedCrls[pki->trustedCrlsSize++] = crl;
}

static void
pkiIssuerCrl(Pki *pki, UA_ByteString crl) {
    ck_assert_uint_lt(pki->issuerCrlsSize, PKI_MAX);
    pki->issuerCrls[pki->issuerCrlsSize++] = crl;
}

static Pki
emptyPki(void) {
    Pki pki;
    memset(&pki, 0, sizeof(Pki));
    return pki;
}

/* R trusted, I in the issuer list, no CRLs */
static Pki
chainPki(void) {
    Pki pki = emptyPki();
    pkiTrust(&pki, BS(VAL_R));
    pkiIssuer(&pki, BS(VAL_I));
    return pki;
}

/* R trusted, I in the issuer list, empty CRLs of R and I */
static Pki
defaultPki(void) {
    Pki pki = chainPki();
    pkiCrl(&pki, BS(VAL_CRL_R));
    pkiCrl(&pki, BS(VAL_CRL_I));
    return pki;
}

static UA_TrustListDataType
toTrustList(Pki *pki) {
    UA_TrustListDataType tl;
    UA_TrustListDataType_init(&tl);
    tl.specifiedLists = UA_TRUSTLISTMASKS_ALL;
    tl.trustedCertificates = pki->trusted;
    tl.trustedCertificatesSize = pki->trustedSize;
    tl.issuerCertificates = pki->issuers;
    tl.issuerCertificatesSize = pki->issuersSize;
    tl.trustedCrls = pki->trustedCrls;
    tl.trustedCrlsSize = pki->trustedCrlsSize;
    tl.issuerCrls = pki->issuerCrls;
    tl.issuerCrlsSize = pki->issuerCrlsSize;
    return tl;
}

/* The certificate stores under test */

typedef enum {
    STORE_MEMORY = 0
#ifdef TEST_FILESTORE
    , STORE_FILE
#endif
} StoreKind;

#ifdef TEST_FILESTORE
#define STORE_KINDS 2
#else
#define STORE_KINDS 1
#endif

static const char *storeNames[] = {"memorystore", "filestore"};

#ifdef TEST_FILESTORE
static void
removeTree(const char *path) {
    DIR *dir = opendir(path);
    if(!dir) {
        remove(path);
        return;
    }
    struct dirent *entry;
    while((entry = readdir(dir))) {
        if(strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;
        char child[1024];
        snprintf(child, sizeof(child), "%s/%s", path, entry->d_name);
        removeTree(child);
    }
    closedir(dir);
    rmdir(path);
}
#endif

/* Create the store with the trust list of the PKI. If this fails, the group is
 * cleared already. */
static UA_StatusCode
createGroup(StoreKind kind, Pki *pki, UA_CertificateGroup *group) {
    memset(group, 0, sizeof(UA_CertificateGroup));
    UA_NodeId groupId = UA_NODEID_NUMERIC(
        0, UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP);
    UA_TrustListDataType tl = toTrustList(pki);
    if(kind == STORE_MEMORY)
        return UA_CertificateGroup_Memorystore(group, &groupId, &tl,
                                               UA_Log_Stdout, NULL);
#ifdef TEST_FILESTORE
    /* Start from an empty directory, the filestore loads what is there */
    removeTree(STORE_PATH);
    UA_StatusCode res = UA_CertificateGroup_Filestore(
        group, &groupId, UA_STRING(STORE_PATH), UA_Log_Stdout, NULL);
    if(res != UA_STATUSCODE_GOOD)
        return res;
    res = group->setTrustList(group, &tl);
    if(res != UA_STATUSCODE_GOOD)
        group->clear(group);
    return res;
#else
    return UA_STATUSCODE_BADINTERNALERROR;
#endif
}

static UA_StatusCode
verifyIn(StoreKind kind, Pki *pki, const UA_ByteString *cert) {
    UA_CertificateGroup group;
    UA_StatusCode res = createGroup(kind, pki, &group);
    ck_assert_msg(res == UA_STATUSCODE_GOOD, "%s: creating the store failed with %s",
                  storeNames[kind], UA_StatusCode_name(res));
    res = group.verifyCertificate(&group, cert);
    group.clear(&group);
    return res;
}

static void
checkResult(const char *what, StoreKind kind, UA_StatusCode res,
            UA_StatusCode expected) {
    if(res != expected)
        addMismatch("%s (%s): expected %s, got %s", what, storeNames[kind],
                    UA_StatusCode_name(expected), UA_StatusCode_name(res));
}

/* Verify in every store and check the StatusCode */
static void
expectStatus(const char *what, Pki *pki, const UA_ByteString *cert,
             UA_StatusCode expected) {
    UA_StatusCode res[STORE_KINDS];
    UA_Boolean allExpected = true;
    UA_Boolean allSame = true;
    for(int kind = 0; kind < STORE_KINDS; kind++) {
        res[kind] = verifyIn((StoreKind)kind, pki, cert);
        allExpected &= (res[kind] == expected);
        allSame &= (res[kind] == res[0]);
    }
    if(allExpected)
        return;
    if(allSame) {
        addMismatch("%s: expected %s, got %s", what, UA_StatusCode_name(expected),
                    UA_StatusCode_name(res[0]));
        return;
    }
    for(int kind = 0; kind < STORE_KINDS; kind++)
        checkResult(what, (StoreKind)kind, res[kind], expected);
}

/***************************/
/* 1 Certificate Structure */
/***************************/

START_TEST(structure_empty_bytestring) {
    Pki pki = defaultPki();
    UA_ByteString empty = UA_BYTESTRING_NULL;
    expectStatus("empty", &pki, &empty, UA_STATUSCODE_BADCERTIFICATEINVALID);
    reportMismatches();
} END_TEST

START_TEST(structure_null_data_with_length) {
    Pki pki = defaultPki();
    UA_ByteString broken = {16, NULL};
    expectStatus("NULL data", &pki, &broken, UA_STATUSCODE_BADINVALIDARGUMENT);
    reportMismatches();
} END_TEST

START_TEST(structure_garbage) {
    Pki pki = defaultPki();
    UA_Byte garbage[64];
    for(size_t i = 0; i < sizeof(garbage); i++)
        garbage[i] = (UA_Byte)(i * 37 + 11);
    UA_ByteString cert = BS(garbage);
    expectStatus("random bytes", &pki, &cert, UA_STATUSCODE_BADCERTIFICATEINVALID);

    UA_Byte badPem[] = "-----BEGIN CERTIFICATE-----\n"
        "!!!! this is not base64 !!!!\n"
        "-----END CERTIFICATE-----\n";
    cert = bs(badPem, sizeof(badPem) - 1);
    expectStatus("broken PEM", &pki, &cert, UA_STATUSCODE_BADCERTIFICATEINVALID);
    reportMismatches();
} END_TEST

START_TEST(structure_truncated_der) {
    Pki pki = defaultPki();
    UA_ByteString cert = {sizeof(VAL_L) / 2, VAL_L};
    expectStatus("truncated L", &pki, &cert, UA_STATUSCODE_BADCERTIFICATEINVALID);
    reportMismatches();
} END_TEST

/* Bytes after the certificate are neither a certificate nor a chain element */
START_TEST(structure_trailing_garbage) {
    Pki pki = defaultPki();
    UA_Byte garbage[32];
    memset(garbage, 0xab, sizeof(garbage));
    UA_ByteString parts[2] = {BS(VAL_L), BS(garbage)};
    UA_ByteString cert = concat(2, parts);
    expectStatus("L + garbage", &pki, &cert, UA_STATUSCODE_BADCERTIFICATEINVALID);
    UA_ByteString_clear(&cert);
    reportMismatches();
} END_TEST

START_TEST(structure_truncated_chain_element) {
    Pki pki = defaultPki();
    UA_ByteString parts[2] = {BS(VAL_L), {sizeof(VAL_I) / 2, VAL_I}};
    UA_ByteString cert = concat(2, parts);
    expectStatus("DER L + truncated I", &pki, &cert,
                 UA_STATUSCODE_BADCERTIFICATEINVALID);
    UA_ByteString_clear(&cert);

    cert = pemChain(2, parts);
    expectStatus("PEM L + truncated I", &pki, &cert,
                 UA_STATUSCODE_BADCERTIFICATEINVALID);
    UA_ByteString_clear(&cert);
    reportMismatches();
} END_TEST

/* Part 6, Table 50: the version shall be V3 */
START_TEST(structure_x509_v1) {
    Pki pki = emptyPki();
    pkiTrust(&pki, BS(VAL_S_V1));
    UA_ByteString cert = BS(VAL_S_V1);
    expectStatus("trusted v1 certificate", &pki, &cert,
                 UA_STATUSCODE_BADCERTIFICATEINVALID);
    reportMismatches();
} END_TEST

/* RFC 5280, 4.2: a certificate with an unrecognized critical extension must be
 * rejected */
START_TEST(structure_unknown_critical_extension) {
    Pki pki = defaultPki();
    UA_ByteString cert = BS(VAL_L_CRITEXT);
    expectStatus("L_critext", &pki, &cert, UA_STATUSCODE_BADCERTIFICATEINVALID);
    reportMismatches();
} END_TEST

/* Part 6, Table 50: marking basicConstraints critical has no effect */
START_TEST(structure_critical_basic_constraints) {
    Pki pki = defaultPki();
    UA_ByteString cert = BS(VAL_L_BCCRIT);
    expectStatus("L_bccrit", &pki, &cert, UA_STATUSCODE_GOOD);
    reportMismatches();
} END_TEST

/* RFC 5280, 4.1.1.2: signatureAlgorithm must equal the signature field in the
 * TBSCertificate */
START_TEST(structure_signature_algorithm_mismatch) {
    Pki pki = defaultPki();
    UA_ByteString cert = BS(VAL_L_SIGALG_MISMATCH);
    expectStatus("L_sigalg_mismatch", &pki, &cert,
                 UA_STATUSCODE_BADCERTIFICATEINVALID);
    reportMismatches();
} END_TEST

/*****************************/
/* 2 Build Certificate Chain */
/*****************************/

START_TEST(chain_complete) {
    Pki pki = defaultPki();
    UA_ByteString cert = BS(VAL_L);
    expectStatus("L", &pki, &cert, UA_STATUSCODE_GOOD);
    reportMismatches();
} END_TEST

START_TEST(chain_missing_intermediate) {
    Pki pki = emptyPki();
    pkiTrust(&pki, BS(VAL_R));
    pkiCrl(&pki, BS(VAL_CRL_R));
    pkiCrl(&pki, BS(VAL_CRL_I));
    UA_ByteString cert = BS(VAL_L);
    expectStatus("L without I", &pki, &cert,
                 UA_STATUSCODE_BADCERTIFICATECHAININCOMPLETE);
    reportMismatches();
} END_TEST

/* The chain ends at a self-signed certificate even if an intermediate CA is
 * trusted (Part 4, 6.1.3) */
START_TEST(chain_missing_root) {
    Pki pki = emptyPki();
    pkiTrust(&pki, BS(VAL_I));
    pkiCrl(&pki, BS(VAL_CRL_R));
    pkiCrl(&pki, BS(VAL_CRL_I));
    UA_ByteString cert = BS(VAL_L);
    expectStatus("L with trusted I, without R", &pki, &cert,
                 UA_STATUSCODE_BADCERTIFICATECHAININCOMPLETE);
    reportMismatches();
} END_TEST

START_TEST(chain_in_pem_bundle) {
    Pki pki = defaultPki();
    pki.issuersSize = 0;
    UA_ByteString parts[2] = {BS(VAL_L), BS(VAL_I)};
    UA_ByteString cert = pemChain(2, parts);
    expectStatus("PEM L+I", &pki, &cert, UA_STATUSCODE_GOOD);
    UA_ByteString_clear(&cert);
    reportMismatches();
} END_TEST

/* Part 6, 6.2.6: chains are stored by appending the DER encoded certificates */
START_TEST(chain_in_der_bundle) {
    Pki pki = defaultPki();
    pki.issuersSize = 0;
    UA_ByteString parts[2] = {BS(VAL_L), BS(VAL_I)};
    UA_ByteString cert = concat(2, parts);
    expectStatus("DER L+I", &pki, &cert, UA_STATUSCODE_GOOD);
    UA_ByteString_clear(&cert);
    reportMismatches();
} END_TEST

START_TEST(chain_with_root_in_bundle) {
    Pki pki = defaultPki();
    pki.issuersSize = 0;
    UA_ByteString parts[3] = {BS(VAL_L), BS(VAL_I), BS(VAL_R)};
    UA_ByteString cert = concat(3, parts);
    expectStatus("DER L+I+R", &pki, &cert, UA_STATUSCODE_GOOD);
    UA_ByteString_clear(&cert);

    cert = pemChain(3, parts);
    expectStatus("PEM L+I+R", &pki, &cert, UA_STATUSCODE_GOOD);
    UA_ByteString_clear(&cert);
    reportMismatches();
} END_TEST

START_TEST(chain_with_unrelated_certificate_in_bundle) {
    Pki pki = defaultPki();
    pki.issuersSize = 0;
    UA_ByteString parts[3] = {BS(VAL_L), BS(VAL_X), BS(VAL_I)};
    UA_ByteString cert = concat(3, parts);
    expectStatus("DER L+X+I", &pki, &cert, UA_STATUSCODE_GOOD);
    UA_ByteString_clear(&cert);

    cert = pemChain(3, parts);
    expectStatus("PEM L+X+I", &pki, &cert, UA_STATUSCODE_GOOD);
    UA_ByteString_clear(&cert);
    reportMismatches();
} END_TEST

/* The chain length is limited. The root is at depth 9 for L_depth8 and at
 * depth 10 for L_depth9. */
START_TEST(chain_maximum_depth) {
    Pki pki = chainPki();
    pkiIssuer(&pki, BS(VAL_I2));
    pkiIssuer(&pki, BS(VAL_I3));
    pkiIssuer(&pki, BS(VAL_I4));
    pkiIssuer(&pki, BS(VAL_I5));
    pkiIssuer(&pki, BS(VAL_I6));
    pkiIssuer(&pki, BS(VAL_I7));
    pkiIssuer(&pki, BS(VAL_I8));
    pkiIssuer(&pki, BS(VAL_I9));
    UA_ByteString cert = BS(VAL_L_DEPTH8);
    expectStatus("8 intermediates", &pki, &cert, UA_STATUSCODE_GOOD);
    cert = BS(VAL_L_DEPTH9);
    expectStatus("9 intermediates", &pki, &cert,
                 UA_STATUSCODE_BADCERTIFICATECHAININCOMPLETE);
    reportMismatches();
} END_TEST

/* A is issued by B and B by A. The chain never reaches a self-signed
 * certificate. */
START_TEST(chain_issuer_loop) {
    Pki pki = emptyPki();
    pkiTrust(&pki, BS(VAL_LOOP_A));
    pkiIssuer(&pki, BS(VAL_LOOP_A));
    pkiIssuer(&pki, BS(VAL_LOOP_B));
    UA_ByteString cert = BS(VAL_L_LOOP);
    expectStatus("L_loop", &pki, &cert, UA_STATUSCODE_BADCERTIFICATECHAININCOMPLETE);
    reportMismatches();
} END_TEST

START_TEST(chain_ca_in_issuer_and_trust_list) {
    Pki pki = defaultPki();
    pkiTrust(&pki, BS(VAL_I));
    pkiIssuer(&pki, BS(VAL_R));
    UA_ByteString cert = BS(VAL_L);
    expectStatus("R and I in both lists", &pki, &cert, UA_STATUSCODE_GOOD);
    reportMismatches();
} END_TEST

/* D has the subject of I but another key. Trying D first must not prevent
 * finding I. */
START_TEST(chain_decoy_issuer_same_name) {
    Pki pki = defaultPki();
    pki.issuersSize = 0;
    pkiIssuer(&pki, BS(VAL_D));
    pkiIssuer(&pki, BS(VAL_I));
    UA_ByteString cert = BS(VAL_L);
    expectStatus("D before I in the issuer list", &pki, &cert, UA_STATUSCODE_GOOD);

    pki = defaultPki();
    UA_ByteString parts[2] = {BS(VAL_L), BS(VAL_D)};
    cert = pemChain(2, parts);
    expectStatus("D in the bundle", &pki, &cert, UA_STATUSCODE_GOOD);
    UA_ByteString_clear(&cert);
    reportMismatches();
} END_TEST

/* As above, but the decoy has a P-256 key while L has an RSA signature */
START_TEST(chain_decoy_issuer_other_key_type) {
    Pki pki = defaultPki();
    pki.issuersSize = 0;
    pkiIssuer(&pki, BS(VAL_D_EC));
    pkiIssuer(&pki, BS(VAL_I));
    UA_ByteString cert = BS(VAL_L);
    expectStatus("D_ec before I in the issuer list", &pki, &cert, UA_STATUSCODE_GOOD);

    pki = defaultPki();
    UA_ByteString parts[2] = {BS(VAL_L), BS(VAL_D_EC)};
    cert = pemChain(2, parts);
    expectStatus("D_ec in the bundle", &pki, &cert, UA_STATUSCODE_GOOD);
    UA_ByteString_clear(&cert);
    reportMismatches();
} END_TEST

/* A CA sent along with the certificate is used to build the chain, but it is
 * not trusted and not stored */
START_TEST(chain_bundled_untrusted_root_grants_no_trust) {
    Pki pki = chainPki();
    UA_ByteString parts[2] = {BS(VAL_LX), BS(VAL_X)};
    UA_ByteString lx2 = BS(VAL_LX2);
    UA_ByteString bundles[2] = {concat(2, parts), pemChain(2, parts)};
    const char *bundleNames[2] = {"DER Lx+X", "PEM Lx+X"};
    for(size_t b = 0; b < 2; b++) {
        for(int kind = 0; kind < STORE_KINDS; kind++) {
            UA_CertificateGroup group;
            UA_StatusCode res = createGroup((StoreKind)kind, &pki, &group);
            ck_assert_uint_eq(res, UA_STATUSCODE_GOOD);
            res = group.verifyCertificate(&group, &bundles[b]);
            checkResult(bundleNames[b], (StoreKind)kind, res,
                        UA_STATUSCODE_BADCERTIFICATEUNTRUSTED);
            res = group.verifyCertificate(&group, &lx2);
            checkResult("Lx2 afterwards", (StoreKind)kind, res,
                        UA_STATUSCODE_BADCERTIFICATECHAININCOMPLETE);
            group.clear(&group);
        }
        UA_ByteString_clear(&bundles[b]);
    }
    reportMismatches();
} END_TEST

/* The subject of R_longname is longer than 256 characters as a string */
START_TEST(chain_long_issuer_name) {
    Pki pki = emptyPki();
    pkiTrust(&pki, BS(VAL_R_LONGNAME));
    UA_ByteString cert = BS(VAL_L_LONGNAME);
    expectStatus("L_longname", &pki, &cert, UA_STATUSCODE_GOOD);
    reportMismatches();
} END_TEST

static UA_ByteString meshCas[9][3] = {
    {BS_INIT(VAL_MESH_1_1), BS_INIT(VAL_MESH_1_2), BS_INIT(VAL_MESH_1_3)},
    {BS_INIT(VAL_MESH_2_1), BS_INIT(VAL_MESH_2_2), BS_INIT(VAL_MESH_2_3)},
    {BS_INIT(VAL_MESH_3_1), BS_INIT(VAL_MESH_3_2), BS_INIT(VAL_MESH_3_3)},
    {BS_INIT(VAL_MESH_4_1), BS_INIT(VAL_MESH_4_2), BS_INIT(VAL_MESH_4_3)},
    {BS_INIT(VAL_MESH_5_1), BS_INIT(VAL_MESH_5_2), BS_INIT(VAL_MESH_5_3)},
    {BS_INIT(VAL_MESH_6_1), BS_INIT(VAL_MESH_6_2), BS_INIT(VAL_MESH_6_3)},
    {BS_INIT(VAL_MESH_7_1), BS_INIT(VAL_MESH_7_2), BS_INIT(VAL_MESH_7_3)},
    {BS_INIT(VAL_MESH_8_1), BS_INIT(VAL_MESH_8_2), BS_INIT(VAL_MESH_8_3)},
    {BS_INIT(VAL_MESH_9_1), BS_INIT(VAL_MESH_9_2), BS_INIT(VAL_MESH_9_3)}
};

/* The certificate comes with a bundle of CAs that all have the same name. Each
 * level has three CAs with the same key, issued by the key of the next level.
 * So every certificate has three valid issuers and the number of paths grows
 * exponentially with the number of levels. No path ends in a self-signed
 * certificate. The bundle is sent before authentication (e.g. in the
 * OpenSecureChannel request), so the effort for building the chain must stay
 * bounded. No CRLs are loaded, so revocation does not stop the search. */
START_TEST(chain_search_is_bounded) {
    Pki pki = emptyPki();
    UA_ByteString ders[1 + 3 * MESH_LEVELS];
    size_t n = 0;
    ders[n++] = BS(VAL_L_MESH);
    for(size_t level = 0; level < MESH_LEVELS; level++)
        for(size_t i = 0; i < 3; i++)
            ders[n++] = meshCas[level][i];
    UA_ByteString pems[1 + 3 * MESH_LEVELS];
    for(size_t i = 0; i < n; i++)
        pems[i] = toPem(&ders[i]);
    UA_ByteString bundle = concat(n, pems);
    for(size_t i = 0; i < n; i++)
        UA_ByteString_clear(&pems[i]);

    UA_DateTime start = UA_DateTime_nowMonotonic();
    UA_StatusCode res = verifyIn(STORE_MEMORY, &pki, &bundle);
    UA_DateTime duration = UA_DateTime_nowMonotonic() - start;
    UA_ByteString_clear(&bundle);
    if(duration > UA_DATETIME_SEC)
        addMismatch("building the chain took %u ms",
                    (unsigned)(duration / UA_DATETIME_MSEC));
    /* Which error is returned when no candidate leads to a self-signed
     * certificate is covered by precedence_revoked_with_decoy_issuer */
    if(res == UA_STATUSCODE_GOOD)
        addMismatch("mesh bundle: accepted");
    reportMismatches();
} END_TEST

/***************/
/* 3 Signature */
/***************/

START_TEST(signature_broken_leaf) {
    Pki pki = defaultPki();
    UA_ByteString l = BS(VAL_L);
    UA_ByteString cert = flipLastByte(&l);
    expectStatus("L with broken signature", &pki, &cert,
                 UA_STATUSCODE_BADCERTIFICATEINVALID);
    UA_ByteString_clear(&cert);
    reportMismatches();
} END_TEST

/* Change one character of the subject. The signature no longer matches. */
START_TEST(signature_modified_tbs) {
    Pki pki = defaultPki();
    UA_ByteString l = BS(VAL_L);
    UA_ByteString cert;
    UA_StatusCode res = UA_ByteString_copy(&l, &cert);
    ck_assert_uint_eq(res, UA_STATUSCODE_GOOD);
    const char *cn = "Validation Leaf";
    size_t cnLen = strlen(cn);
    size_t pos = 0;
    for(; pos + cnLen <= cert.length; pos++) {
        if(memcmp(&cert.data[pos], cn, cnLen) == 0)
            break;
    }
    ck_assert_uint_le(pos + cnLen, cert.length);
    cert.data[pos + cnLen - 1] = 'g';
    expectStatus("L with modified subject", &pki, &cert,
                 UA_STATUSCODE_BADCERTIFICATEINVALID);
    UA_ByteString_clear(&cert);
    reportMismatches();
} END_TEST

/* Being in the trust list does not replace the signature check */
START_TEST(signature_broken_self_signed_trusted) {
    UA_ByteString s = BS(VAL_S);
    UA_ByteString cert = flipLastByte(&s);
    Pki pki = emptyPki();
    pkiTrust(&pki, cert);
    expectStatus("trusted S with broken signature", &pki, &cert,
                 UA_STATUSCODE_BADCERTIFICATEINVALID);
    UA_ByteString_clear(&cert);
    reportMismatches();
} END_TEST

START_TEST(signature_broken_intermediate) {
    UA_ByteString i = BS(VAL_I);
    UA_ByteString brokenI = flipLastByte(&i);
    Pki pki = defaultPki();
    pki.issuers[0] = brokenI;
    UA_ByteString cert = BS(VAL_L);
    expectStatus("I with broken signature", &pki, &cert,
                 UA_STATUSCODE_BADCERTIFICATEINVALID);
    UA_ByteString_clear(&brokenI);
    reportMismatches();
} END_TEST

START_TEST(signature_broken_trusted_root) {
    UA_ByteString r = BS(VAL_R);
    UA_ByteString brokenR = flipLastByte(&r);
    Pki pki = defaultPki();
    pki.trusted[0] = brokenR;
    UA_ByteString cert = BS(VAL_L);
    expectStatus("R with broken signature", &pki, &cert,
                 UA_STATUSCODE_BADCERTIFICATEINVALID);
    UA_ByteString_clear(&brokenR);
    reportMismatches();
} END_TEST

/* L_wrongkey names I as issuer, but is signed with the key of R */
START_TEST(signature_wrong_signing_key) {
    Pki pki = defaultPki();
    pkiIssuer(&pki, BS(VAL_R));
    UA_ByteString cert = BS(VAL_L_WRONGKEY);
    expectStatus("L_wrongkey", &pki, &cert, UA_STATUSCODE_BADCERTIFICATEINVALID);
    reportMismatches();
} END_TEST

START_TEST(signature_mixed_algorithms) {
    Pki pki = emptyPki();
    pkiTrust(&pki, BS(VAL_R_EC));
    UA_ByteString cert = BS(VAL_L_RSA_UNDER_EC);
    expectStatus("RSA leaf under P-256 CA", &pki, &cert, UA_STATUSCODE_GOOD);

    pki = defaultPki();
    cert = BS(VAL_L_EC);
    expectStatus("P-256 leaf under RSA CA", &pki, &cert, UA_STATUSCODE_GOOD);
    reportMismatches();
} END_TEST

/***************************/
/* 4 Security Policy Check */
/***************************/

/* The certificate is checked against the SecurityPolicy when the channel
 * context is created */
static UA_StatusCode
policyCheck(UA_SecurityPolicy *sp, const UA_ByteString *remote) {
    void *channelContext = NULL;
    UA_StatusCode res = sp->newChannelContext(sp, remote, &channelContext);
    if(res == UA_STATUSCODE_GOOD)
        sp->deleteChannelContext(sp, channelContext);
    return res;
}

static void
newBasic256Sha256(UA_SecurityPolicy *sp) {
    memset(sp, 0, sizeof(UA_SecurityPolicy));
    UA_StatusCode res = UA_SecurityPolicy_Basic256Sha256(
        sp, BS(VAL_L), BS(VAL_L_KEY), UA_Log_Stdout);
    ck_assert_uint_eq(res, UA_STATUSCODE_GOOD);
}

static void
expectPolicy(const char *what, UA_SecurityPolicy *sp, const UA_ByteString *remote,
             UA_StatusCode expected) {
    UA_StatusCode res = policyCheck(sp, remote);
    if(res != expected)
        addMismatch("%s: expected %s, got %s", what, UA_StatusCode_name(expected),
                    UA_StatusCode_name(res));
}

START_TEST(policy_accepts_matching_certificate) {
    UA_SecurityPolicy sp;
    newBasic256Sha256(&sp);
    UA_ByteString cert = BS(VAL_L);
    expectPolicy("RSA-2048, SHA-256 with Basic256Sha256", &sp, &cert,
                 UA_STATUSCODE_GOOD);
    sp.clear(&sp);
    reportMismatches();
} END_TEST

/* Basic256Sha256 has MinAsymmetricKeyLength 2048 */
START_TEST(policy_rsa_key_too_short) {
    UA_SecurityPolicy sp;
    newBasic256Sha256(&sp);
    UA_ByteString cert = BS(VAL_L_RSA1024);
    expectPolicy("RSA-1024 with Basic256Sha256", &sp, &cert,
                 UA_STATUSCODE_BADCERTIFICATEPOLICYCHECKFAILED);
    sp.clear(&sp);
    reportMismatches();
} END_TEST

/* Basic256Sha256 has MaxAsymmetricKeyLength 4096 */
START_TEST(policy_rsa_key_too_long) {
    UA_SecurityPolicy sp;
    newBasic256Sha256(&sp);
    UA_ByteString cert = BS(VAL_L_RSA8192);
    expectPolicy("RSA-8192 with Basic256Sha256", &sp, &cert,
                 UA_STATUSCODE_BADCERTIFICATEPOLICYCHECKFAILED);
    sp.clear(&sp);
    reportMismatches();
} END_TEST

/* The CertificateSignatureAlgorithm of Basic256Sha256 is RSA-PKCS15-SHA2-256 */
START_TEST(policy_sha1_signature) {
    UA_SecurityPolicy sp;
    newBasic256Sha256(&sp);
    UA_ByteString cert = BS(VAL_L_SHA1);
    expectPolicy("SHA-1 signed leaf with Basic256Sha256", &sp, &cert,
                 UA_STATUSCODE_BADCERTIFICATEPOLICYCHECKFAILED);
    sp.clear(&sp);
    reportMismatches();
} END_TEST

/* The steps of Table 100 are repeated for each certificate in the chain */
START_TEST(policy_sha1_signed_issuer_in_chain) {
    UA_SecurityPolicy sp;
    newBasic256Sha256(&sp);
    UA_ByteString parts[2] = {BS(VAL_L), BS(VAL_I_SHA1)};
    UA_ByteString cert = concat(2, parts);
    expectPolicy("L + SHA-1 signed I with Basic256Sha256", &sp, &cert,
                 UA_STATUSCODE_BADCERTIFICATEPOLICYCHECKFAILED);
    UA_ByteString_clear(&cert);
    sp.clear(&sp);
    reportMismatches();
} END_TEST

#ifdef TEST_ECC_POLICY
static void
newEccNistP256(UA_SecurityPolicy *sp) {
    memset(sp, 0, sizeof(UA_SecurityPolicy));
    UA_StatusCode res = UA_SecurityPolicy_EccNistP256(
        sp, UA_APPLICATIONTYPE_SERVER, BS(VAL_L_EC), BS(VAL_L_EC_KEY), UA_Log_Stdout);
    ck_assert_uint_eq(res, UA_STATUSCODE_GOOD);
}

START_TEST(policy_ecc_accepts_matching_certificate) {
    UA_SecurityPolicy sp;
    newEccNistP256(&sp);
    UA_ByteString cert = BS(VAL_L_EC);
    expectPolicy("P-256 with EccNistP256", &sp, &cert, UA_STATUSCODE_GOOD);
    sp.clear(&sp);
    reportMismatches();
} END_TEST

START_TEST(policy_ecc_wrong_curve) {
    UA_SecurityPolicy sp;
    newEccNistP256(&sp);
    UA_ByteString cert = BS(VAL_L_P384);
    expectPolicy("P-384 with EccNistP256", &sp, &cert,
                 UA_STATUSCODE_BADCERTIFICATEPOLICYCHECKFAILED);
    sp.clear(&sp);
    reportMismatches();
} END_TEST

START_TEST(policy_ecc_rsa_certificate) {
    UA_SecurityPolicy sp;
    newEccNistP256(&sp);
    UA_ByteString cert = BS(VAL_L);
    expectPolicy("RSA with EccNistP256", &sp, &cert,
                 UA_STATUSCODE_BADCERTIFICATEPOLICYCHECKFAILED);
    sp.clear(&sp);
    reportMismatches();
} END_TEST
#endif

/**********************/
/* 5 Trust List Check */
/**********************/

START_TEST(trust_untrusted_chain) {
    Pki pki = defaultPki();
    pki.trustedSize = 0;
    pkiIssuer(&pki, BS(VAL_R));
    UA_ByteString cert = BS(VAL_L);
    expectStatus("R and I only in the issuer list", &pki, &cert,
                 UA_STATUSCODE_BADCERTIFICATEUNTRUSTED);
    reportMismatches();
} END_TEST

START_TEST(trust_intermediate_as_anchor) {
    Pki pki = defaultPki();
    pki.trustedSize = 0;
    pki.issuersSize = 0;
    pkiTrust(&pki, BS(VAL_I));
    pkiIssuer(&pki, BS(VAL_R));
    UA_ByteString cert = BS(VAL_L);
    expectStatus("I trusted, R in the issuer list", &pki, &cert, UA_STATUSCODE_GOOD);
    reportMismatches();
} END_TEST

START_TEST(trust_leaf_with_untrusted_chain) {
    Pki pki = defaultPki();
    pki.trustedSize = 0;
    pkiTrust(&pki, BS(VAL_L));
    pkiIssuer(&pki, BS(VAL_R));
    UA_ByteString cert = BS(VAL_L);
    expectStatus("L trusted, I and R in the issuer list", &pki, &cert,
                 UA_STATUSCODE_GOOD);
    reportMismatches();
} END_TEST

/* Trusting the certificate itself does not make a missing chain complete */
START_TEST(trust_leaf_without_chain) {
    Pki pki = defaultPki();
    pki.trustedSize = 0;
    pki.issuersSize = 0;
    pkiTrust(&pki, BS(VAL_L));
    UA_ByteString cert = BS(VAL_L);
    expectStatus("L trusted, I and R missing", &pki, &cert,
                 UA_STATUSCODE_BADCERTIFICATECHAININCOMPLETE);
    reportMismatches();
} END_TEST

START_TEST(trust_removed_and_restored) {
    Pki pki = defaultPki();
    pkiIssuer(&pki, BS(VAL_R));
    UA_ByteString r = BS(VAL_R);
    UA_ByteString cert = BS(VAL_L);
    UA_TrustListDataType onlyR;
    UA_TrustListDataType_init(&onlyR);
    onlyR.specifiedLists = UA_TRUSTLISTMASKS_TRUSTEDCERTIFICATES;
    onlyR.trustedCertificates = &r;
    onlyR.trustedCertificatesSize = 1;
    for(int kind = 0; kind < STORE_KINDS; kind++) {
        UA_CertificateGroup group;
        UA_StatusCode res = createGroup((StoreKind)kind, &pki, &group);
        ck_assert_uint_eq(res, UA_STATUSCODE_GOOD);
        res = group.verifyCertificate(&group, &cert);
        checkResult("R trusted", (StoreKind)kind, res, UA_STATUSCODE_GOOD);
        res = group.removeFromTrustList(&group, &onlyR);
        ck_assert_uint_eq(res, UA_STATUSCODE_GOOD);
        res = group.verifyCertificate(&group, &cert);
        checkResult("R removed", (StoreKind)kind, res,
                    UA_STATUSCODE_BADCERTIFICATEUNTRUSTED);
        res = group.addToTrustList(&group, &onlyR);
        ck_assert_uint_eq(res, UA_STATUSCODE_GOOD);
        res = group.verifyCertificate(&group, &cert);
        checkResult("R added again", (StoreKind)kind, res, UA_STATUSCODE_GOOD);
        group.clear(&group);
    }
    reportMismatches();
} END_TEST

/* X_samename has the subject of R but another key. The chain via X_samename is
 * complete, but X_samename is not trusted. */
START_TEST(trust_same_subject_other_key) {
    Pki pki = chainPki();
    UA_ByteString parts[2] = {BS(VAL_LX_SAMENAME), BS(VAL_X_SAMENAME)};
    UA_ByteString cert = pemChain(2, parts);
    expectStatus("PEM Lx_samename+X_samename", &pki, &cert,
                 UA_STATUSCODE_BADCERTIFICATEUNTRUSTED);
    UA_ByteString_clear(&cert);

    pkiIssuer(&pki, BS(VAL_X_SAMENAME));
    cert = BS(VAL_LX_SAMENAME);
    expectStatus("X_samename in the issuer list", &pki, &cert,
                 UA_STATUSCODE_BADCERTIFICATEUNTRUSTED);
    reportMismatches();
} END_TEST

/* A trust list entry that holds a bundle (Lx and its CA X) must not make X
 * trusted. Rejecting the entry is fine as well. */
START_TEST(trust_bundle_in_trust_list_entry) {
    UA_ByteString parts[2] = {BS(VAL_LX), BS(VAL_X)};
    UA_ByteString entry = pemChain(2, parts);
    Pki pki = emptyPki();
    pkiTrust(&pki, entry);
    UA_ByteString lx2 = BS(VAL_LX2);
    for(int kind = 0; kind < STORE_KINDS; kind++) {
        UA_CertificateGroup group;
        UA_StatusCode res = createGroup((StoreKind)kind, &pki, &group);
        if(res != UA_STATUSCODE_GOOD)
            continue; /* The entry was rejected */
        res = group.verifyCertificate(&group, &lx2);
        group.clear(&group);
        if(res == UA_STATUSCODE_GOOD)
            addMismatch("Lx2 (%s): trusted through the CA in the bundle",
                        storeNames[kind]);
    }
    UA_ByteString_clear(&entry);
    reportMismatches();
} END_TEST

/* Trust list material that does not parse is rejected and the previous trust
 * list stays in place */
START_TEST(trust_invalid_material_rejected) {
    UA_Byte garbageData[48];
    memset(garbageData, 0x5a, sizeof(garbageData));
    UA_ByteString garbage = BS(garbageData);
    const UA_TrustListMasks masks[4] = {
        UA_TRUSTLISTMASKS_TRUSTEDCERTIFICATES, UA_TRUSTLISTMASKS_ISSUERCERTIFICATES,
        UA_TRUSTLISTMASKS_TRUSTEDCRLS, UA_TRUSTLISTMASKS_ISSUERCRLS};
    const char *maskNames[4] = {"trusted certificate", "issuer certificate",
                                "trusted CRL", "issuer CRL"};
    UA_ByteString cert = BS(VAL_L);
    for(size_t m = 0; m < 4; m++) {
        UA_TrustListDataType bad;
        UA_TrustListDataType_init(&bad);
        bad.specifiedLists = masks[m];
        if(masks[m] == UA_TRUSTLISTMASKS_TRUSTEDCERTIFICATES) {
            bad.trustedCertificates = &garbage;
            bad.trustedCertificatesSize = 1;
        } else if(masks[m] == UA_TRUSTLISTMASKS_ISSUERCERTIFICATES) {
            bad.issuerCertificates = &garbage;
            bad.issuerCertificatesSize = 1;
        } else if(masks[m] == UA_TRUSTLISTMASKS_TRUSTEDCRLS) {
            bad.trustedCrls = &garbage;
            bad.trustedCrlsSize = 1;
        } else {
            bad.issuerCrls = &garbage;
            bad.issuerCrlsSize = 1;
        }
        for(int kind = 0; kind < STORE_KINDS; kind++) {
            Pki pki = defaultPki();
            UA_CertificateGroup group;
            UA_StatusCode res = createGroup((StoreKind)kind, &pki, &group);
            ck_assert_uint_eq(res, UA_STATUSCODE_GOOD);
            char what[96];
            res = group.setTrustList(&group, &bad);
            if(res == UA_STATUSCODE_GOOD)
                addMismatch("setTrustList with a garbage %s (%s): returned Good",
                            maskNames[m], storeNames[kind]);
            snprintf(what, sizeof(what), "L after setTrustList with a garbage %s",
                     maskNames[m]);
            res = group.verifyCertificate(&group, &cert);
            checkResult(what, (StoreKind)kind, res, UA_STATUSCODE_GOOD);

            res = group.addToTrustList(&group, &bad);
            if(res == UA_STATUSCODE_GOOD)
                addMismatch("addToTrustList with a garbage %s (%s): returned Good",
                            maskNames[m], storeNames[kind]);
            snprintf(what, sizeof(what), "L after addToTrustList with a garbage %s",
                     maskNames[m]);
            res = group.verifyCertificate(&group, &cert);
            checkResult(what, (StoreKind)kind, res, UA_STATUSCODE_GOOD);
            group.clear(&group);
        }
    }
    reportMismatches();
} END_TEST

/*********************/
/* 6 Validity Period */
/*********************/

START_TEST(validity_leaf_expired) {
    Pki pki = defaultPki();
    UA_ByteString cert = BS(VAL_L_EXPIRED);
    expectStatus("L_expired", &pki, &cert, UA_STATUSCODE_BADCERTIFICATETIMEINVALID);
    reportMismatches();
} END_TEST

START_TEST(validity_leaf_not_yet_valid) {
    Pki pki = defaultPki();
    UA_ByteString cert = BS(VAL_L_FUTURE);
    expectStatus("L_future", &pki, &cert, UA_STATUSCODE_BADCERTIFICATETIMEINVALID);
    reportMismatches();
} END_TEST

START_TEST(validity_intermediate_expired) {
    Pki pki = defaultPki();
    pki.issuers[0] = BS(VAL_I_EXPIRED);
    UA_ByteString cert = BS(VAL_L);
    expectStatus("I_expired", &pki, &cert,
                 UA_STATUSCODE_BADCERTIFICATEISSUERTIMEINVALID);
    reportMismatches();
} END_TEST

START_TEST(validity_intermediate_not_yet_valid) {
    Pki pki = defaultPki();
    pki.issuers[0] = BS(VAL_I_FUTURE);
    UA_ByteString cert = BS(VAL_L);
    expectStatus("I_future", &pki, &cert,
                 UA_STATUSCODE_BADCERTIFICATEISSUERTIMEINVALID);
    reportMismatches();
} END_TEST

START_TEST(validity_root_expired) {
    Pki pki = defaultPki();
    pki.trusted[0] = BS(VAL_R_EXPIRED);
    UA_ByteString cert = BS(VAL_L);
    expectStatus("R_expired trusted", &pki, &cert,
                 UA_STATUSCODE_BADCERTIFICATEISSUERTIMEINVALID);
    reportMismatches();
} END_TEST

/* A certificate is trusted only if the chain is valid (Part 4, 6.1.3). This
 * includes the CAs above the trusted certificate. */
START_TEST(validity_issuer_expired_above_trusted_leaf) {
    Pki pki = defaultPki();
    pki.trusted[0] = BS(VAL_L);
    pki.issuers[0] = BS(VAL_I_EXPIRED);
    pkiIssuer(&pki, BS(VAL_R));
    UA_ByteString cert = BS(VAL_L);
    expectStatus("L trusted, I_expired", &pki, &cert,
                 UA_STATUSCODE_BADCERTIFICATEISSUERTIMEINVALID);
    reportMismatches();
} END_TEST

START_TEST(validity_root_expired_above_trusted_intermediate) {
    Pki pki = defaultPki();
    pki.trusted[0] = BS(VAL_I);
    pki.issuers[0] = BS(VAL_R_EXPIRED);
    UA_ByteString cert = BS(VAL_L);
    expectStatus("I trusted, R_expired", &pki, &cert,
                 UA_STATUSCODE_BADCERTIFICATEISSUERTIMEINVALID);
    reportMismatches();
} END_TEST

/* The Trust List Check comes before the Validity Period */
START_TEST(validity_untrusted_and_expired) {
    Pki pki = defaultPki();
    pki.trustedSize = 0;
    pkiIssuer(&pki, BS(VAL_R));
    UA_ByteString cert = BS(VAL_L_EXPIRED);
    expectStatus("L_expired, untrusted", &pki, &cert,
                 UA_STATUSCODE_BADCERTIFICATEUNTRUSTED);
    reportMismatches();
} END_TEST

START_TEST(validity_trusted_self_signed_expired) {
    Pki pki = emptyPki();
    pkiTrust(&pki, BS(VAL_S_EXPIRED));
    UA_ByteString cert = BS(VAL_S_EXPIRED);
    expectStatus("S_expired trusted", &pki, &cert,
                 UA_STATUSCODE_BADCERTIFICATETIMEINVALID);
    reportMismatches();
} END_TEST

/***********************/
/* 9 Certificate Usage */
/***********************/

/* An application certificate with the CA flag and the CA key usages. The
 * CertificateGroup rejects it (CTT Security Certificate Validation 029). */
START_TEST(usage_ca_leaf) {
    Pki pki = defaultPki();
    UA_ByteString cert = BS(VAL_L_CA);
    expectStatus("L_ca", &pki, &cert, UA_STATUSCODE_BADCERTIFICATEUSENOTALLOWED);
    reportMismatches();
} END_TEST

/* The CA flag alone has the same effect as in usage_ca_leaf */
START_TEST(usage_ca_leaf_without_certsign) {
    Pki pki = defaultPki();
    UA_ByteString cert = BS(VAL_L_CA_NOCERTSIGN);
    expectStatus("L_ca_nocertsign", &pki, &cert,
                 UA_STATUSCODE_BADCERTIFICATEUSENOTALLOWED);
    reportMismatches();
} END_TEST

/* Part 6, Table 50: the basicConstraints extension shall be present */
START_TEST(usage_leaf_without_basic_constraints) {
    Pki pki = defaultPki();
    UA_ByteString cert = BS(VAL_L_NOBC);
    expectStatus("L_nobc", &pki, &cert, UA_STATUSCODE_BADCERTIFICATEUSENOTALLOWED);
    reportMismatches();
} END_TEST

/* Part 6, Table 50: for RSA keys, the keyUsage shall include
 * digitalSignature, nonRepudiation, keyEncipherment and dataEncipherment */
START_TEST(usage_leaf_without_key_usage) {
    Pki pki = defaultPki();
    UA_ByteString cert = BS(VAL_L_NOKU);
    expectStatus("L_noku", &pki, &cert, UA_STATUSCODE_BADCERTIFICATEUSENOTALLOWED);
    reportMismatches();
} END_TEST

START_TEST(usage_rsa_leaf_missing_key_usage_bit) {
    Pki pki = defaultPki();
    UA_ByteString cert = BS(VAL_L_KU_NODS);
    expectStatus("without digitalSignature", &pki, &cert,
                 UA_STATUSCODE_BADCERTIFICATEUSENOTALLOWED);
    cert = BS(VAL_L_KU_NONR);
    expectStatus("without nonRepudiation", &pki, &cert,
                 UA_STATUSCODE_BADCERTIFICATEUSENOTALLOWED);
    cert = BS(VAL_L_KU_NOKE);
    expectStatus("without keyEncipherment", &pki, &cert,
                 UA_STATUSCODE_BADCERTIFICATEUSENOTALLOWED);
    cert = BS(VAL_L_KU_NODE);
    expectStatus("without dataEncipherment", &pki, &cert,
                 UA_STATUSCODE_BADCERTIFICATEUSENOTALLOWED);
    reportMismatches();
} END_TEST

/* Part 6, Table 50: for ECC keys, the keyUsage shall include digitalSignature */
START_TEST(usage_ecc_leaf_digital_signature_only) {
    Pki pki = defaultPki();
    UA_ByteString cert = BS(VAL_L_EC);
    expectStatus("L_ec", &pki, &cert, UA_STATUSCODE_GOOD);
    reportMismatches();
} END_TEST

/* Part 6, Table 50: self-signed certificates shall also include keyCertSign */
START_TEST(usage_self_signed_without_certsign) {
    Pki pki = emptyPki();
    pkiTrust(&pki, BS(VAL_S_NOCERTSIGN));
    UA_ByteString cert = BS(VAL_S_NOCERTSIGN);
    expectStatus("S_nocertsign trusted", &pki, &cert,
                 UA_STATUSCODE_BADCERTIFICATEUSENOTALLOWED);
    reportMismatches();
} END_TEST

/* Certificates created by open62541 itself are accepted */
START_TEST(usage_generated_certificates) {
    UA_String subject[3] = {UA_STRING_STATIC("C=DE"),
                            UA_STRING_STATIC("O=open62541 Test"),
                            UA_STRING_STATIC("CN=Validation Generated")};
    UA_String subjectAltName[2] = {
        UA_STRING_STATIC("DNS:localhost"),
        UA_STRING_STATIC("URI:urn:open62541.test.validation")};
    const char *keyTypeNames[2] = {"RSA", "EC"};
    UA_String keyTypes[2] = {UA_STRING_STATIC("RSA"), UA_STRING_STATIC("EC")};
    for(size_t k = 0; k < 2; k++) {
        UA_KeyValueMap *params = UA_KeyValueMap_new();
        UA_UInt16 keySize = 2048;
        UA_KeyValueMap_setScalar(params, UA_QUALIFIEDNAME(0, "key-size-bits"),
                                 &keySize, &UA_TYPES[UA_TYPES_UINT16]);
        UA_KeyValueMap_setScalar(params, UA_QUALIFIEDNAME(0, "key-type"),
                                 &keyTypes[k], &UA_TYPES[UA_TYPES_STRING]);
        UA_ByteString key = UA_BYTESTRING_NULL;
        UA_ByteString cert = UA_BYTESTRING_NULL;
        UA_StatusCode res = UA_CreateCertificate(
            UA_Log_Stdout, subject, 3, subjectAltName, 2, UA_CERTIFICATEFORMAT_DER,
            params, &key, &cert);
        UA_KeyValueMap_delete(params);
        ck_assert_uint_eq(res, UA_STATUSCODE_GOOD);

        Pki pki = emptyPki();
        pkiTrust(&pki, cert);
        expectStatus(keyTypeNames[k], &pki, &cert, UA_STATUSCODE_GOOD);
        UA_ByteString_clear(&key);
        UA_ByteString_clear(&cert);
    }
    reportMismatches();
} END_TEST

START_TEST(usage_issuer_without_basic_constraints) {
    Pki pki = defaultPki();
    pki.issuers[0] = BS(VAL_I_NOBC);
    UA_ByteString cert = BS(VAL_L);
    expectStatus("I_nobc", &pki, &cert,
                 UA_STATUSCODE_BADCERTIFICATEISSUERUSENOTALLOWED);
    reportMismatches();
} END_TEST

START_TEST(usage_issuer_not_ca) {
    Pki pki = defaultPki();
    pki.issuers[0] = BS(VAL_I_CAFALSE);
    UA_ByteString cert = BS(VAL_L);
    expectStatus("I_cafalse", &pki, &cert,
                 UA_STATUSCODE_BADCERTIFICATEISSUERUSENOTALLOWED);
    reportMismatches();
} END_TEST

START_TEST(usage_issuer_without_key_usage) {
    Pki pki = defaultPki();
    pki.issuers[0] = BS(VAL_I_NOKU);
    UA_ByteString cert = BS(VAL_L);
    expectStatus("I_noku", &pki, &cert,
                 UA_STATUSCODE_BADCERTIFICATEISSUERUSENOTALLOWED);
    reportMismatches();
} END_TEST

START_TEST(usage_issuer_without_crlsign) {
    Pki pki = defaultPki();
    pki.issuers[0] = BS(VAL_I_NOCRLSIGN);
    UA_ByteString cert = BS(VAL_L);
    expectStatus("I_nocrlsign", &pki, &cert,
                 UA_STATUSCODE_BADCERTIFICATEISSUERUSENOTALLOWED);
    reportMismatches();
} END_TEST

START_TEST(usage_root_not_ca) {
    Pki pki = defaultPki();
    pki.trusted[0] = BS(VAL_R_NOCA);
    UA_ByteString cert = BS(VAL_L);
    expectStatus("R_noca trusted", &pki, &cert,
                 UA_STATUSCODE_BADCERTIFICATEISSUERUSENOTALLOWED);
    reportMismatches();
} END_TEST

/* RFC 5280, 6.1.4 (l, m): R allows no intermediate CA below it */
START_TEST(usage_root_path_length_exceeded) {
    Pki pki = defaultPki();
    pki.trusted[0] = BS(VAL_R_PATHLEN0);
    UA_ByteString cert = BS(VAL_L);
    expectStatus("R_pathlen0 trusted", &pki, &cert,
                 UA_STATUSCODE_BADCERTIFICATEISSUERUSENOTALLOWED);
    reportMismatches();
} END_TEST

/* I_cafalse has the name and the key of I but no CA flag. Trying it first must
 * not prevent finding I. */
START_TEST(usage_non_ca_decoy_skipped) {
    Pki pki = defaultPki();
    pki.issuers[0] = BS(VAL_I_CAFALSE);
    pkiIssuer(&pki, BS(VAL_I));
    UA_ByteString cert = BS(VAL_L);
    expectStatus("I_cafalse before I in the issuer list", &pki, &cert,
                 UA_STATUSCODE_GOOD);

    pki = defaultPki();
    UA_ByteString parts[2] = {BS(VAL_L), BS(VAL_I_CAFALSE)};
    cert = pemChain(2, parts);
    expectStatus("I_cafalse in the bundle", &pki, &cert, UA_STATUSCODE_GOOD);
    UA_ByteString_clear(&cert);
    reportMismatches();
} END_TEST

/***************************/
/* 10 Find Revocation List */
/***************************/

START_TEST(crl_missing_for_issuer_of_leaf) {
    Pki pki = chainPki();
    pkiCrl(&pki, BS(VAL_CRL_R));
    UA_ByteString cert = BS(VAL_L);
    expectStatus("CRL of I missing", &pki, &cert,
                 UA_STATUSCODE_BADCERTIFICATEREVOCATIONUNKNOWN);
    reportMismatches();
} END_TEST

START_TEST(crl_missing_for_issuer_of_intermediate) {
    Pki pki = chainPki();
    pkiCrl(&pki, BS(VAL_CRL_I));
    UA_ByteString cert = BS(VAL_L);
    expectStatus("CRL of R missing", &pki, &cert,
                 UA_STATUSCODE_BADCERTIFICATEISSUERREVOCATIONUNKNOWN);
    reportMismatches();
} END_TEST

/* Without any CRL, the CertificateGroup treats revocation checks as disabled
 * by the administrator (Part 4, Table 100, Find Revocation List) */
START_TEST(crl_none_loaded) {
    Pki pki = chainPki();
    UA_ByteString cert = BS(VAL_L);
    expectStatus("no CRLs", &pki, &cert, UA_STATUSCODE_GOOD);
    reportMismatches();
} END_TEST

START_TEST(crl_from_issuer_crl_list) {
    Pki pki = chainPki();
    pkiCrl(&pki, BS(VAL_CRL_R));
    pkiIssuerCrl(&pki, BS(VAL_CRL_I));
    UA_ByteString cert = BS(VAL_L);
    expectStatus("CRL of I in the issuer CRLs", &pki, &cert, UA_STATUSCODE_GOOD);

    pki.issuerCrls[0] = BS(VAL_CRL_I_REVOKING);
    expectStatus("revoking CRL of I in the issuer CRLs", &pki, &cert,
                 UA_STATUSCODE_BADCERTIFICATEREVOKED);
    reportMismatches();
} END_TEST

START_TEST(crl_not_needed_for_self_signed) {
    Pki pki = defaultPki();
    pkiTrust(&pki, BS(VAL_S));
    UA_ByteString cert = BS(VAL_S);
    expectStatus("S trusted, CRLs of other CAs loaded", &pki, &cert,
                 UA_STATUSCODE_GOOD);
    reportMismatches();
} END_TEST

/* Trusting the certificate itself does not replace the revocation check */
START_TEST(crl_needed_for_trusted_leaf) {
    Pki pki = chainPki();
    pki.trusted[0] = BS(VAL_L);
    pkiIssuer(&pki, BS(VAL_R));
    pkiCrl(&pki, BS(VAL_CRL_R));
    UA_ByteString cert = BS(VAL_L);
    expectStatus("L trusted, CRL of I missing", &pki, &cert,
                 UA_STATUSCODE_BADCERTIFICATEREVOCATIONUNKNOWN);
    reportMismatches();
} END_TEST

/***********************/
/* 11 Revocation Check */
/***********************/

/* R trusted, I in the issuer list, the CRL of R and the given CRL(s) of I */
static Pki
crlPki(UA_ByteString crlOfI) {
    Pki pki = chainPki();
    pkiCrl(&pki, BS(VAL_CRL_R));
    pkiCrl(&pki, crlOfI);
    return pki;
}

START_TEST(revocation_leaf_revoked) {
    Pki pki = crlPki(BS(VAL_CRL_I_REVOKING));
    UA_ByteString cert = BS(VAL_L);
    expectStatus("L revoked", &pki, &cert, UA_STATUSCODE_BADCERTIFICATEREVOKED);
    reportMismatches();
} END_TEST

START_TEST(revocation_intermediate_revoked) {
    Pki pki = chainPki();
    pkiCrl(&pki, BS(VAL_CRL_R_REVOKING));
    pkiCrl(&pki, BS(VAL_CRL_I));
    UA_ByteString cert = BS(VAL_L);
    expectStatus("I revoked", &pki, &cert, UA_STATUSCODE_BADCERTIFICATEISSUERREVOKED);
    reportMismatches();
} END_TEST

/* Trusting the certificate itself does not override its revocation */
START_TEST(revocation_trusted_leaf_revoked) {
    Pki pki = crlPki(BS(VAL_CRL_I_REVOKING));
    pki.trusted[0] = BS(VAL_L);
    pkiIssuer(&pki, BS(VAL_R));
    UA_ByteString cert = BS(VAL_L);
    expectStatus("L trusted and revoked", &pki, &cert,
                 UA_STATUSCODE_BADCERTIFICATEREVOKED);
    reportMismatches();
} END_TEST

/* The CRL of X lists the serial number of L. It does not apply to
 * certificates issued by I. */
START_TEST(revocation_serial_of_other_issuer) {
    Pki pki = defaultPki();
    pkiCrl(&pki, BS(VAL_CRL_X_REVOKING));
    UA_ByteString cert = BS(VAL_L);
    expectStatus("serial of L revoked by X", &pki, &cert, UA_STATUSCODE_GOOD);
    reportMismatches();
} END_TEST

START_TEST(revocation_twenty_octet_serial) {
    Pki pki = crlPki(BS(VAL_CRL_I_REVOKING));
    UA_ByteString cert = BS(VAL_L_BIGSERIAL);
    expectStatus("L_bigserial revoked", &pki, &cert,
                 UA_STATUSCODE_BADCERTIFICATEREVOKED);
    reportMismatches();
} END_TEST

/* RFC 5280, 6.3.3 (f, g): the signature of the CRL is verified with the key
 * of the CA. A CRL that does not verify is not available. */
START_TEST(revocation_crl_broken_signature) {
    UA_ByteString revoking = BS(VAL_CRL_I_REVOKING);
    UA_ByteString broken = flipLastByte(&revoking);
    Pki pki = crlPki(broken);
    UA_ByteString cert = BS(VAL_L);
    expectStatus("revoking CRL of I with broken signature", &pki, &cert,
                 UA_STATUSCODE_BADCERTIFICATEREVOCATIONUNKNOWN);
    UA_ByteString_clear(&broken);
    reportMismatches();
} END_TEST

/* The forged CRLs carry the name of I but are signed with the key of D */
START_TEST(revocation_forged_crl_revoking) {
    Pki pki = crlPki(BS(VAL_CRL_I_FORGED_REVOKING));
    UA_ByteString cert = BS(VAL_L);
    expectStatus("only a forged revoking CRL of I", &pki, &cert,
                 UA_STATUSCODE_BADCERTIFICATEREVOCATIONUNKNOWN);

    pkiCrl(&pki, BS(VAL_CRL_I));
    expectStatus("forged revoking CRL and genuine CRL of I", &pki, &cert,
                 UA_STATUSCODE_GOOD);
    reportMismatches();
} END_TEST

START_TEST(revocation_forged_crl_empty) {
    Pki pki = crlPki(BS(VAL_CRL_I_FORGED));
    UA_ByteString cert = BS(VAL_L);
    expectStatus("only a forged empty CRL of I", &pki, &cert,
                 UA_STATUSCODE_BADCERTIFICATEREVOCATIONUNKNOWN);
    reportMismatches();
} END_TEST

/* RFC 5280, 6.3.3 (a): the nextUpdate of the CRL has passed */
START_TEST(revocation_stale_crl) {
    Pki pki = crlPki(BS(VAL_CRL_I_STALE));
    UA_ByteString cert = BS(VAL_L);
    expectStatus("stale CRL of I", &pki, &cert,
                 UA_STATUSCODE_BADCERTIFICATEREVOCATIONUNKNOWN);
    reportMismatches();
} END_TEST

START_TEST(revocation_crl_not_yet_valid) {
    Pki pki = crlPki(BS(VAL_CRL_I_FUTURE));
    UA_ByteString cert = BS(VAL_L);
    expectStatus("CRL of I with thisUpdate in 2100", &pki, &cert,
                 UA_STATUSCODE_BADCERTIFICATEREVOCATIONUNKNOWN);
    reportMismatches();
} END_TEST

/********************/
/* Error precedence */
/********************/

/* Part 4, 6.1.3: the steps of Table 100 are followed in order and processing
 * halts at the first error */

START_TEST(precedence_expired_and_revoked) {
    Pki pki = crlPki(BS(VAL_CRL_I_REVOKING));
    UA_ByteString cert = BS(VAL_L_EXPIRED);
    expectStatus("L_expired, revoked", &pki, &cert,
                 UA_STATUSCODE_BADCERTIFICATETIMEINVALID);
    reportMismatches();
} END_TEST

START_TEST(precedence_untrusted_and_revoked) {
    Pki pki = crlPki(BS(VAL_CRL_I_REVOKING));
    pki.trustedSize = 0;
    pkiIssuer(&pki, BS(VAL_R));
    UA_ByteString cert = BS(VAL_L);
    expectStatus("L untrusted, revoked", &pki, &cert,
                 UA_STATUSCODE_BADCERTIFICATEUNTRUSTED);
    reportMismatches();
} END_TEST

START_TEST(precedence_untrusted_and_crl_missing) {
    Pki pki = chainPki();
    pkiCrl(&pki, BS(VAL_CRL_R));
    pki.trustedSize = 0;
    pkiIssuer(&pki, BS(VAL_R));
    UA_ByteString cert = BS(VAL_L);
    expectStatus("L untrusted, CRL of I missing", &pki, &cert,
                 UA_STATUSCODE_BADCERTIFICATEUNTRUSTED);
    reportMismatches();
} END_TEST

/* The result must not depend on whether the decoy D (subject of I, other key)
 * is tried before or after I */
START_TEST(precedence_revoked_with_decoy_issuer) {
    Pki pki = crlPki(BS(VAL_CRL_I_REVOKING));
    pkiTrust(&pki, BS(VAL_D));
    UA_ByteString cert = BS(VAL_L);
    expectStatus("D in the trust list", &pki, &cert,
                 UA_STATUSCODE_BADCERTIFICATEREVOKED);

    pki = crlPki(BS(VAL_CRL_I_REVOKING));
    pki.issuersSize = 0;
    pkiIssuer(&pki, BS(VAL_D));
    pkiIssuer(&pki, BS(VAL_I));
    expectStatus("D before I in the issuer list", &pki, &cert,
                 UA_STATUSCODE_BADCERTIFICATEREVOKED);
    reportMismatches();
} END_TEST

static TCase *
stepTCase(const char *name) {
    TCase *tc = tcase_create(name);
    tcase_add_checked_fixture(tc, resetMismatches, NULL);
    return tc;
}

static Suite *
testSuite(void) {
    Suite *s = suite_create("Certificate validation steps");

    TCase *tc = stepTCase("1 Certificate Structure");
    tcase_add_test(tc, structure_empty_bytestring);
    tcase_add_test(tc, structure_null_data_with_length);
    tcase_add_test(tc, structure_garbage);
    tcase_add_test(tc, structure_truncated_der);
    tcase_add_test(tc, structure_trailing_garbage);
    tcase_add_test(tc, structure_truncated_chain_element);
    tcase_add_test(tc, structure_x509_v1);
    tcase_add_test(tc, structure_unknown_critical_extension);
    tcase_add_test(tc, structure_critical_basic_constraints);
    tcase_add_test(tc, structure_signature_algorithm_mismatch);
    suite_add_tcase(s, tc);

    tc = stepTCase("2 Build Certificate Chain");
    tcase_add_test(tc, chain_complete);
    tcase_add_test(tc, chain_missing_intermediate);
    tcase_add_test(tc, chain_missing_root);
    tcase_add_test(tc, chain_in_pem_bundle);
    tcase_add_test(tc, chain_in_der_bundle);
    tcase_add_test(tc, chain_with_root_in_bundle);
    tcase_add_test(tc, chain_with_unrelated_certificate_in_bundle);
    tcase_add_test(tc, chain_maximum_depth);
    tcase_add_test(tc, chain_issuer_loop);
    tcase_add_test(tc, chain_ca_in_issuer_and_trust_list);
    tcase_add_test(tc, chain_decoy_issuer_same_name);
    tcase_add_test(tc, chain_decoy_issuer_other_key_type);
    tcase_add_test(tc, chain_bundled_untrusted_root_grants_no_trust);
    tcase_add_test(tc, chain_long_issuer_name);
    tcase_set_timeout(tc, 60);
    suite_add_tcase(s, tc);

    /* In fork mode, the timeout stops an unbounded search */
    tc = stepTCase("2 Build Certificate Chain (bounded search)");
    tcase_add_test(tc, chain_search_is_bounded);
    tcase_set_timeout(tc, 30);
    suite_add_tcase(s, tc);

    tc = stepTCase("3 Signature");
    tcase_add_test(tc, signature_broken_leaf);
    tcase_add_test(tc, signature_modified_tbs);
    tcase_add_test(tc, signature_broken_self_signed_trusted);
    tcase_add_test(tc, signature_broken_intermediate);
    tcase_add_test(tc, signature_broken_trusted_root);
    tcase_add_test(tc, signature_wrong_signing_key);
    tcase_add_test(tc, signature_mixed_algorithms);
    suite_add_tcase(s, tc);

    tc = stepTCase("4 Security Policy Check");
    tcase_add_test(tc, policy_accepts_matching_certificate);
    tcase_add_test(tc, policy_rsa_key_too_short);
    tcase_add_test(tc, policy_rsa_key_too_long);
    tcase_add_test(tc, policy_sha1_signature);
    tcase_add_test(tc, policy_sha1_signed_issuer_in_chain);
#ifdef TEST_ECC_POLICY
    tcase_add_test(tc, policy_ecc_accepts_matching_certificate);
    tcase_add_test(tc, policy_ecc_wrong_curve);
    tcase_add_test(tc, policy_ecc_rsa_certificate);
#else
    (void)VAL_L_EC_KEY;
    (void)VAL_L_P384;
#endif
    suite_add_tcase(s, tc);

    tc = stepTCase("5 Trust List Check");
    tcase_add_test(tc, trust_untrusted_chain);
    tcase_add_test(tc, trust_intermediate_as_anchor);
    tcase_add_test(tc, trust_leaf_with_untrusted_chain);
    tcase_add_test(tc, trust_leaf_without_chain);
    tcase_add_test(tc, trust_removed_and_restored);
    tcase_add_test(tc, trust_same_subject_other_key);
    tcase_add_test(tc, trust_bundle_in_trust_list_entry);
    tcase_add_test(tc, trust_invalid_material_rejected);
    tcase_set_timeout(tc, 60);
    suite_add_tcase(s, tc);

    tc = stepTCase("6 Validity Period");
    tcase_add_test(tc, validity_leaf_expired);
    tcase_add_test(tc, validity_leaf_not_yet_valid);
    tcase_add_test(tc, validity_intermediate_expired);
    tcase_add_test(tc, validity_intermediate_not_yet_valid);
    tcase_add_test(tc, validity_root_expired);
    tcase_add_test(tc, validity_issuer_expired_above_trusted_leaf);
    tcase_add_test(tc, validity_root_expired_above_trusted_intermediate);
    tcase_add_test(tc, validity_untrusted_and_expired);
    tcase_add_test(tc, validity_trusted_self_signed_expired);
    suite_add_tcase(s, tc);

    tc = stepTCase("9 Certificate Usage");
    tcase_add_test(tc, usage_ca_leaf);
    tcase_add_test(tc, usage_ca_leaf_without_certsign);
    tcase_add_test(tc, usage_leaf_without_basic_constraints);
    tcase_add_test(tc, usage_leaf_without_key_usage);
    tcase_add_test(tc, usage_rsa_leaf_missing_key_usage_bit);
    tcase_add_test(tc, usage_ecc_leaf_digital_signature_only);
    tcase_add_test(tc, usage_self_signed_without_certsign);
    tcase_add_test(tc, usage_generated_certificates);
    tcase_add_test(tc, usage_issuer_without_basic_constraints);
    tcase_add_test(tc, usage_issuer_not_ca);
    tcase_add_test(tc, usage_issuer_without_key_usage);
    tcase_add_test(tc, usage_issuer_without_crlsign);
    tcase_add_test(tc, usage_root_not_ca);
    tcase_add_test(tc, usage_root_path_length_exceeded);
    tcase_add_test(tc, usage_non_ca_decoy_skipped);
    tcase_set_timeout(tc, 60);
    suite_add_tcase(s, tc);

    tc = stepTCase("10 Find Revocation List");
    tcase_add_test(tc, crl_missing_for_issuer_of_leaf);
    tcase_add_test(tc, crl_missing_for_issuer_of_intermediate);
    tcase_add_test(tc, crl_none_loaded);
    tcase_add_test(tc, crl_from_issuer_crl_list);
    tcase_add_test(tc, crl_not_needed_for_self_signed);
    tcase_add_test(tc, crl_needed_for_trusted_leaf);
    suite_add_tcase(s, tc);

    tc = stepTCase("11 Revocation Check");
    tcase_add_test(tc, revocation_leaf_revoked);
    tcase_add_test(tc, revocation_intermediate_revoked);
    tcase_add_test(tc, revocation_trusted_leaf_revoked);
    tcase_add_test(tc, revocation_serial_of_other_issuer);
    tcase_add_test(tc, revocation_twenty_octet_serial);
    tcase_add_test(tc, revocation_crl_broken_signature);
    tcase_add_test(tc, revocation_forged_crl_revoking);
    tcase_add_test(tc, revocation_forged_crl_empty);
    tcase_add_test(tc, revocation_stale_crl);
    tcase_add_test(tc, revocation_crl_not_yet_valid);
    suite_add_tcase(s, tc);

    tc = stepTCase("Error precedence");
    tcase_add_test(tc, precedence_expired_and_revoked);
    tcase_add_test(tc, precedence_untrusted_and_revoked);
    tcase_add_test(tc, precedence_untrusted_and_crl_missing);
    tcase_add_test(tc, precedence_revoked_with_decoy_issuer);
    suite_add_tcase(s, tc);

    return s;
}

int main(void) {
    Suite *s = testSuite();
    SRunner *sr = srunner_create(s);
    /* Fork mode (unless CK_FORK=no) keeps a crash or a timeout in one test from
     * stopping the others */
    srunner_run_all(sr, CK_NORMAL);
    int number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
#ifdef TEST_FILESTORE
    removeTree(STORE_PATH);
#endif
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
