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
}
trap cleanup EXIT

wait_for_server() {
    local url="$1"
    local timeout="${2:-30}"
    local start=$SECONDS
    echo "  Waiting for server at $url (timeout: ${timeout}s)..."
    while (( SECONDS - start < timeout )); do
        if nc -z localhost "${url##*:}" 2>/dev/null; then
            echo "  Server is ready (took $(( SECONDS - start ))s)"
            return 0
        fi
        sleep 1
    done
    echo "  ERROR: Server did not start within ${timeout}s"
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
dotnet run --project "$DOTNET_SERVER_PROJECT" --no-build \
    --framework net9.0 \
    --configuration "${DOTNET_CONFIG:-Debug}" -- -a -c &
DOTNET_SERVER_PID=$!

if ! wait_for_server "localhost:$DOTNET_PORT"; then
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
