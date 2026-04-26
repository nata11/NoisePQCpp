# ================================
# Google Benchmark Targets
# ================================
# Note: This directory is only included for Release builds
# Google Benchmark is provided by third_party/CMakeLists.txt via FetchContent

# Output benchmarks to bin/benchmarks/
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${NOISEPQC_BIN_DIR}/benchmarks")
foreach(CONFIG_TYPE ${CMAKE_CONFIGURATION_TYPES})
    string(TOUPPER ${CONFIG_TYPE} CONFIG_TYPE_UPPER)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_${CONFIG_TYPE_UPPER} "${NOISEPQC_BIN_DIR}/${CONFIG_TYPE}/benchmarks")
endforeach()

# Benchmark: Initial test benchmark
add_executable(bench_example bench_example.cpp)
target_link_libraries(bench_example PRIVATE NoisePQC::noisepqc benchmark::benchmark benchmark::benchmark_main)

# Benchmark: Handshake performance (Classical, PQ, HFS)
add_executable(bench_handshake bench_handshake.cpp)
target_link_libraries(bench_handshake PRIVATE NoisePQC::noisepqc benchmark::benchmark benchmark::benchmark_main)

# Network benchmarks (server, client, stress test)
add_subdirectory(network)
