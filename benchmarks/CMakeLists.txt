# ================================
# Google Benchmark Targets
# ================================
# Note: Single-config generators include this directory only for Release builds.
# Multi-config generators always include it; Ninja Multi-Config then leaves the
# bench targets out of Debug's "all" (see the end of this file).
# Google Benchmark is provided by third_party/CMakeLists.txt via FetchContent

# Output benchmarks to bin/benchmarks/
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${NOISEPQC_BIN_DIR}/benchmarks")
foreach(CONFIG_TYPE ${CMAKE_CONFIGURATION_TYPES})
    string(TOUPPER ${CONFIG_TYPE} CONFIG_TYPE_UPPER)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_${CONFIG_TYPE_UPPER} "${NOISEPQC_BIN_DIR}/${CONFIG_TYPE}/benchmarks")
endforeach()

# Benchmark: SHA-256 hashing, X25519 key generation and DH
add_executable(bench_example bench_example.cpp)
target_link_libraries(bench_example PRIVATE NoisePQC::noisepqc benchmark::benchmark benchmark::benchmark_main)

# Benchmark: Handshake performance (Classical, PQ, HFS)
add_executable(bench_handshake bench_handshake.cpp)
target_link_libraries(bench_handshake PRIVATE NoisePQC::noisepqc benchmark::benchmark benchmark::benchmark_main)

# Network benchmarks (server, client, stress test)
add_subdirectory(network)

# Debug benchmark binaries are never run, so Debug does not build them.
# Only Ninja Multi-Config supports a per-config EXCLUDE_FROM_ALL.
if(CMAKE_GENERATOR STREQUAL "Ninja Multi-Config")
    set_target_properties(bench_example bench_handshake bench_server bench_client bench_stress
        PROPERTIES EXCLUDE_FROM_ALL "$<CONFIG:Debug>")
endif()

# Link-time optimization in Release configs (cmake/BuildConfig.cmake)
foreach(TARGET_NAME bench_example bench_handshake)
    noisepqc_optimize_target(${TARGET_NAME})
endforeach()
