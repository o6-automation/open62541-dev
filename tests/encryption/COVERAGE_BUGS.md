# Crypto Coverage Bugs

## Bug 1: Stack-use-after-scope in MbedTLS IP SAN certificate generation

**File:** `plugins/crypto/mbedtls/create_certificate.c`
**Function:** `UA_CreateCertificate`
**Lines:** ~200-210

**Issue:** When creating a certificate with an IP SAN (e.g. `"IP:127.0.0.1"`),
the IPv4 address was parsed into a stack-local `uint8_t ip[4]` array. A pointer
to this stack array was then stored in `cur_tmp->node.host`. Since `ip` is local
to the `for` loop iteration block, it goes out of scope before
`mbedtls_x509write_crt_set_subject_alt_name()` reads the data, causing a
stack-use-after-scope error (detected by ASan).

**Fix:** Heap-allocate the IP buffer with `mbedtls_calloc(1, 4)` and free it
in both SAN list cleanup loops (error and success paths) for nodes with type
`MBEDTLS_X509_SAN_IP_ADDRESS`.

**Severity:** High — undefined behavior (reading freed stack memory). In
practice, the stack memory is likely still readable on most platforms, so certs
are generated "correctly" by accident. But with ASan or on platforms that reuse
stack frames aggressively, this causes crashes or corrupt certificates.

**Discovered by:** IP SAN test in `check_crypto_coverage.c` with clang-18 ASan.
