#!/usr/bin/env bash
# Cross-SDK interoperability test orchestration script.
#
# Runs two scenarios:
#   Scenario A: open62541 C server  <-->  .NET OPC UA client
#   Scenario B: .NET OPC UA server  <-->  open62541 C client
#
# Prerequisites:
#   - C SDK built with encryption and examples (ci_server, check_interop_client)
#   - .NET SDK restored and built
#   - Certificates generated (via generate_interop_certs.sh)
#
# Usage: ./interop_test.sh <c_build_dir> <dotnet_sdk_dir> <cert_dir>

set -euo pipefail

C_BUILD_DIR="${1:?Usage: $0 <c_build_dir> <dotnet_sdk_dir> <cert_dir>}"
DOTNET_SDK_DIR="${2:?Usage: $0 <c_build_dir> <dotnet_sdk_dir> <cert_dir>}"
CERT_DIR="${3:?Usage: $0 <c_build_dir> <dotnet_sdk_dir> <cert_dir>}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

CI_SERVER="$C_BUILD_DIR/bin/examples/ci_server"
INTEROP_CLIENT="$C_BUILD_DIR/bin/tests/check_interop_client"
DOTNET_INTEROP_PROJECT="$REPO_ROOT/tests/interop/dotnet/Opc.Ua.Interop.Tests.csproj"
DOTNET_SERVER_PROJECT="$DOTNET_SDK_DIR/Applications/ConsoleReferenceServer/ConsoleReferenceServer.csproj"

RESULT=0
C_SERVER_PID=""
DOTNET_SERVER_PID=""
NODEOPCUA_SERVER_PID=""

cleanup() {
    echo ""
    echo "=== Cleaning up ==="
    if [[ -n "$C_SERVER_PID" ]] && kill -0 "$C_SERVER_PID" 2>/dev/null; then
        echo "  Stopping C server (PID $C_SERVER_PID)"
        kill "$C_SERVER_PID" 2>/dev/null || true
        wait "$C_SERVER_PID" 2>/dev/null || true
    fi
    if [[ -n "$DOTNET_SERVER_PID" ]] && kill -0 "$DOTNET_SERVER_PID" 2>/dev/null; then
        echo "  Stopping .NET server (PID $DOTNET_SERVER_PID)"
        kill "$DOTNET_SERVER_PID" 2>/dev/null || true
        wait "$DOTNET_SERVER_PID" 2>/dev/null || true
    fi
    if [[ -n "$NODEOPCUA_SERVER_PID" ]] && kill -0 "$NODEOPCUA_SERVER_PID" 2>/dev/null; then
        echo "  Stopping node-opcua server (PID $NODEOPCUA_SERVER_PID)"
        kill "$NODEOPCUA_SERVER_PID" 2>/dev/null || true
        wait "$NODEOPCUA_SERVER_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

wait_for_server() {
    local url="$1"
    local timeout="${2:-30}"
    local port="${url##*:}"
    local start=$SECONDS
    echo "  Waiting for server at $url (timeout: ${timeout}s)..."

    # Phase 1: wait for TCP port to open
    while (( SECONDS - start < timeout )); do
        if nc -z localhost "$port" 2>/dev/null; then
            break
        fi
        sleep 1
    done

    if ! nc -z localhost "$port" 2>/dev/null; then
        echo "  ERROR: Server did not open port within ${timeout}s"
        return 1
    fi

    # Phase 2: verify OPC UA-level readiness.
    # Some servers (e.g. .NET Reference Server) bind the TCP port well
    # before the OPC UA stack is initialised, returning BadServerHalted
    # on early requests.  Poll with a lightweight anonymous connect
    # until T-1 passes or we time out.
    #
    # NOTE: capture output before grepping – with set -o pipefail, piping
    # "$INTEROP_CLIENT | grep" would fail if the client exits non-zero
    # (e.g. T-3/T-4 fail on servers without the custom variable/method)
    # even when T-1 already printed PASS.
    echo "  Port open, verifying OPC UA readiness..."
    local probe_out
    while (( SECONDS - start < timeout )); do
        probe_out=$("$INTEROP_CLIENT" "opc.tcp://localhost:$port" 2>/dev/null) || true
        if echo "$probe_out" | grep -q 'PASS'; then
            echo "  Server is ready (took $(( SECONDS - start ))s)"
            return 0
        fi
        sleep 2
    done
    echo "  ERROR: Server did not become OPC-UA-ready within ${timeout}s"
    return 1
}

# ============================================================
# Verify prerequisites
# ============================================================

echo "=== Cross-SDK Interoperability Tests ==="
echo "  C build dir:    $C_BUILD_DIR"
echo "  .NET SDK dir:   $DOTNET_SDK_DIR"
echo "  Cert dir:       $CERT_DIR"
echo ""

for f in "$CI_SERVER" "$INTEROP_CLIENT"; do
    if [[ ! -x "$f" ]]; then
        echo "ERROR: Missing executable: $f"
        exit 1
    fi
done

for f in server_c.cert.der server_c.key.der client_c.cert.der client_c.key.der; do
    if [[ ! -f "$CERT_DIR/$f" ]]; then
        echo "ERROR: Missing certificate: $CERT_DIR/$f"
        exit 1
    fi
done

# ============================================================
# Scenario A: C server <--> .NET client
# ============================================================

echo ""
echo "=========================================="
echo "  Scenario A: C server <--> .NET client"
echo "=========================================="
echo ""

C_PORT=4840
echo "Starting C server on port $C_PORT..."
"$CI_SERVER" "$C_PORT" \
    "$CERT_DIR/server_c.cert.der" \
    "$CERT_DIR/server_c.key.der" \
    "$CERT_DIR/client_c.cert.der" \
    "$CERT_DIR/client_dotnet.cert.der" &
C_SERVER_PID=$!

if ! wait_for_server "localhost:$C_PORT"; then
    echo "FAIL: C server did not start"
    RESULT=1
else
    echo "Running C interop client against C server (self-test)..."
    if "$INTEROP_CLIENT" \
        "opc.tcp://localhost:$C_PORT" \
        "$CERT_DIR/client_c.cert.der" \
        "$CERT_DIR/client_c.key.der" \
        "$CERT_DIR/server_c.cert.der" 2>&1; then
        echo "PASS: Scenario A - C client self-test passed"
    else
        echo "FAIL: Scenario A - C client self-test failed"
        RESULT=1
    fi

    echo ""
    echo "Running .NET interop tests against C server..."
    export OPCUA_INTEROP_SERVER_URL="opc.tcp://localhost:$C_PORT"
    export OPCUA_INTEROP_CERT_DIR="$CERT_DIR"
    if dotnet test "$DOTNET_INTEROP_PROJECT" --no-build --verbosity normal \
         --configuration "${DOTNET_CONFIG:-Debug}" \
         --filter "TestCategory=Interop" 2>&1; then
        echo "PASS: Scenario A - .NET client tests passed"
    else
        echo "FAIL: Scenario A - .NET client tests failed"
        RESULT=1
    fi
    unset OPCUA_INTEROP_SERVER_URL
    unset OPCUA_INTEROP_CERT_DIR
fi

# Stop C server
if [[ -n "$C_SERVER_PID" ]] && kill -0 "$C_SERVER_PID" 2>/dev/null; then
    kill "$C_SERVER_PID" 2>/dev/null || true
    wait "$C_SERVER_PID" 2>/dev/null || true
fi
C_SERVER_PID=""

# ============================================================
# Scenario B: .NET server <--> C client
# ============================================================

echo ""
echo "=========================================="
echo "  Scenario B: .NET server <--> C client"
echo "=========================================="
echo ""

DOTNET_PORT=62541
echo "Starting .NET Reference Server on port $DOTNET_PORT..."
DOTNET_SERVER_DIR="$(dirname "$DOTNET_SERVER_PROJECT")"
(cd "$DOTNET_SERVER_DIR" && dotnet run --project "$DOTNET_SERVER_PROJECT" --no-build \
    --framework net9.0 \
    --configuration "${DOTNET_CONFIG:-Debug}" -- -a -c) &
DOTNET_SERVER_PID=$!

if ! wait_for_server "localhost:$DOTNET_PORT" 60; then
    echo "FAIL: .NET server did not start"
    RESULT=1
else
    echo "Running C interop client against .NET server..."
    # C client auto-tests all policies when certs are provided
    if "$INTEROP_CLIENT" \
        "opc.tcp://localhost:$DOTNET_PORT" \
        "$CERT_DIR/client_c.cert.der" \
        "$CERT_DIR/client_c.key.der" \
        "$CERT_DIR/server_dotnet.cert.der" 2>&1; then
        echo "PASS: Scenario B - C client tests passed"
    else
        echo "FAIL: Scenario B - C client tests failed"
        RESULT=1
    fi
fi

# Stop .NET server
if [[ -n "$DOTNET_SERVER_PID" ]] && kill -0 "$DOTNET_SERVER_PID" 2>/dev/null; then
    kill "$DOTNET_SERVER_PID" 2>/dev/null || true
    wait "$DOTNET_SERVER_PID" 2>/dev/null || true
fi
DOTNET_SERVER_PID=""

# ============================================================
# Scenario C: node-opcua server <--> C client
# ============================================================

echo ""
echo "=========================================="
echo "  Scenario C: node-opcua server <--> C client"
echo "=========================================="
echo ""

NODEOPCUA_PORT=62542
NODEOPCUA_SERVER_DIR="$REPO_ROOT/tests/interop/node-opcua"
NODE_PKI="$CERT_DIR/node_pki"
echo "Starting node-opcua server on port $NODEOPCUA_PORT..."
node "$NODEOPCUA_SERVER_DIR/server.mjs" \
    "$NODEOPCUA_PORT" \
    "$CERT_DIR/server_nodeopcua.cert.pem" \
    "$CERT_DIR/server_nodeopcua.key.pem" \
    "$NODE_PKI" &
NODEOPCUA_SERVER_PID=$!

if ! wait_for_server "localhost:$NODEOPCUA_PORT"; then
    echo "FAIL: node-opcua server did not start"
    RESULT=1
else
    echo "Running C interop client against node-opcua server..."
    # Policies not offered by node-opcua (e.g. Aes128/Aes256_RsaPss)
    # are automatically SKIP-ped by the C client (BadSecurityPolicyRejected).
    if "$INTEROP_CLIENT" \
        "opc.tcp://localhost:$NODEOPCUA_PORT" \
        "$CERT_DIR/client_c.cert.der" \
        "$CERT_DIR/client_c.key.der" \
        "$CERT_DIR/server_nodeopcua.cert.der" 2>&1; then
        echo "PASS: Scenario C - node-opcua server tests passed"
    else
        echo "FAIL: Scenario C - node-opcua server tests failed"
        RESULT=1
    fi
fi

# Stop node-opcua server
if [[ -n "$NODEOPCUA_SERVER_PID" ]] && kill -0 "$NODEOPCUA_SERVER_PID" 2>/dev/null; then
    kill "$NODEOPCUA_SERVER_PID" 2>/dev/null || true
    wait "$NODEOPCUA_SERVER_PID" 2>/dev/null || true
fi
NODEOPCUA_SERVER_PID=""

# ============================================================
# Summary
# ============================================================

echo ""
echo "=========================================="
if [[ $RESULT -eq 0 ]]; then
    echo "  All interop tests PASSED"
else
    echo "  Some interop tests FAILED"
fi
echo "=========================================="

exit $RESULT
