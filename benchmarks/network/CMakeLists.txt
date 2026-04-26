# ================================
# Network Benchmark Targets
# ================================
# These benchmarks require ASIO for TCP networking

# Output binaries to bin/benchmarks/network/
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${NOISEPQC_BIN_DIR}/benchmarks/network")
foreach(CONFIG_TYPE ${CMAKE_CONFIGURATION_TYPES})
    string(TOUPPER ${CONFIG_TYPE} CONFIG_TYPE_UPPER)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_${CONFIG_TYPE_UPPER} "${NOISEPQC_BIN_DIR}/${CONFIG_TYPE}/benchmarks/network")
endforeach()

# Network Benchmark: Server
add_executable(bench_server bench_server.cpp)
target_link_libraries(bench_server PRIVATE NoisePQC::noisepqc asio_static)

# Network Benchmark: Client with timing
add_executable(bench_client bench_client.cpp)
target_link_libraries(bench_client PRIVATE NoisePQC::noisepqc asio_static)

# Network Benchmark: Multi-client stress test
add_executable(bench_stress bench_stress.cpp)
target_link_libraries(bench_stress PRIVATE NoisePQC::noisepqc asio_static)
