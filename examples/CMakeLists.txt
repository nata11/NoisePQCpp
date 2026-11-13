# ================================
# Example Targets
# ================================

# Output examples to bin/examples/ (single-config) or bin/<Config>/examples/ (multi-config)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${NOISEPQC_BIN_DIR}/examples")
foreach(CONFIG_TYPE ${CMAKE_CONFIGURATION_TYPES})
    string(TOUPPER ${CONFIG_TYPE} CONFIG_TYPE_UPPER)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_${CONFIG_TYPE_UPPER} "${NOISEPQC_BIN_DIR}/${CONFIG_TYPE}/examples")
endforeach()

# Example: DH Sandbox
add_executable(dh_sandbox dh_sandbox.cpp)
target_link_libraries(dh_sandbox PRIVATE NoisePQC::noisepqc)

# Example: Protocol Sandbox
add_executable(protocol_sandbox protocol_sandbox.cpp)
target_link_libraries(protocol_sandbox PRIVATE NoisePQC::noisepqc)

# Example: Handshake Sandbox
add_executable(hs_sandbox hs_sandbox.cpp)
target_link_libraries(hs_sandbox PRIVATE NoisePQC::noisepqc)

# Example: Pattern Zoo to check various Patterns
add_executable(pattern_zoo pattern_zoo.cpp)
target_link_libraries(pattern_zoo PRIVATE NoisePQC::noisepqc)

# Example: Complete API Example (based on nyquist example_test.go)
add_executable(example_test example_test.cpp)
target_link_libraries(example_test PRIVATE NoisePQC::noisepqc)

# Example: Complete PQ API Example (based on example_test.cpp with pqXX/M768)
add_executable(example_test_pq example_test_pq.cpp)
target_link_libraries(example_test_pq PRIVATE NoisePQC::noisepqc)

# Example: ML-KEM Sandbox
add_executable(mlkem_sandbox mlkem_sandbox.cpp)
target_link_libraries(mlkem_sandbox PRIVATE NoisePQC::noisepqc)

# ================================
# ASIO Networking Examples
# ================================
add_subdirectory(asio-networking)

# Link-time optimization in Release configs (cmake/BuildConfig.cmake)
foreach(TARGET_NAME dh_sandbox protocol_sandbox hs_sandbox pattern_zoo example_test
        example_test_pq mlkem_sandbox)
    noisepqc_optimize_target(${TARGET_NAME})
endforeach()
