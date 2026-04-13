# Toolchain file for building open62541 with Emscripten (WASM)
#
# Usage:
#   mkdir build-wasm && cd build-wasm
#   emcmake cmake .. -DCMAKE_TOOLCHAIN_FILE=../tools/cmake/Toolchain-emscripten.cmake
#   emmake make
#
# Requires Emscripten SDK (emsdk) to be activated in the environment.

set(CMAKE_SYSTEM_NAME Emscripten)
set(CMAKE_SYSTEM_PROCESSOR wasm32)

# Force our architecture selection
set(UA_ARCHITECTURE "emscripten" CACHE STRING "Emscripten/WASM architecture" FORCE)

# Disable features that don't apply in browser
set(UA_ENABLE_ENCRYPTION OFF CACHE BOOL "" FORCE)
set(UA_ENABLE_ENCRYPTION_OPENSSL OFF CACHE BOOL "" FORCE)
set(UA_ENABLE_ENCRYPTION_MBEDTLS OFF CACHE BOOL "" FORCE)
set(UA_ENABLE_ENCRYPTION_LIBRESSL OFF CACHE BOOL "" FORCE)
set(UA_ENABLE_DISCOVERY OFF CACHE BOOL "" FORCE)
set(UA_ENABLE_DISCOVERY_MULTICAST OFF CACHE BOOL "" FORCE)
set(UA_ENABLE_DISCOVERY_MULTICAST_MDNSD OFF CACHE BOOL "" FORCE)
set(UA_ENABLE_DISCOVERY_MULTICAST_AVAHI OFF CACHE BOOL "" FORCE)

# Enable browser-relevant features
set(UA_ENABLE_SUBSCRIPTIONS ON CACHE BOOL "" FORCE)
set(UA_ENABLE_JSON_ENCODING ON CACHE BOOL "" FORCE)

# Single-threaded
set(UA_MULTITHREADING 0 CACHE STRING "" FORCE)

# Client only — no server in WASM
set(UA_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(UA_BUILD_UNIT_TESTS OFF CACHE BOOL "" FORCE)
