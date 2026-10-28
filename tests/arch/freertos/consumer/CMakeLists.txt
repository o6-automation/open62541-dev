cmake_minimum_required(VERSION 3.21)
project(freertos_header_consumer C)
# Set UA_ARCHITECTURE, external dependency paths and the toolchain on the CLI.
# No include directories are added to this parent scope or consumer target.
add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/../../../.." open62541)
add_library(consumer OBJECT consumer.c)
target_link_libraries(consumer PRIVATE open62541::open62541)
