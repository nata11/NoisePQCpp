# ================================
# Catch2 Test Targets
# ================================

# Note: Catch2 is provided by third_party/CMakeLists.txt via FetchContent
# It is built with the project's toolchain (Clang 21 with libc++, GCC 15 with libstdc++, or MSVC) to ensure ABI compatibility

# Output tests to bin/tests/ (single-config) or bin/<Config>/tests/ (multi-config)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${NOISEPQC_BIN_DIR}/tests")
foreach(CONFIG_TYPE ${CMAKE_CONFIGURATION_TYPES})
    string(TOUPPER ${CONFIG_TYPE} CONFIG_TYPE_UPPER)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_${CONFIG_TYPE_UPPER} "${NOISEPQC_BIN_DIR}/${CONFIG_TYPE}/tests")
endforeach()

# Test: Cipher Module
add_executable(test_cipher test_cipher.cpp)
target_link_libraries(test_cipher PRIVATE NoisePQC::noisepqc Catch2::Catch2)

# Test: CipherState Module
add_executable(test_cipherstate test_cipherstate.cpp)
target_link_libraries(test_cipherstate PRIVATE NoisePQC::noisepqc Catch2::Catch2)

# Test: Dh Module
add_executable(test_dh test_dh.cpp)
target_link_libraries(test_dh PRIVATE NoisePQC::noisepqc Catch2::Catch2)

# Test: Hash Module
add_executable(test_hash test_hash.cpp)
target_link_libraries(test_hash PRIVATE NoisePQC::noisepqc Catch2::Catch2)

# Test: SymmetricState Module
add_executable(test_symmetricstate test_symmetricstate.cpp)
target_link_libraries(test_symmetricstate PRIVATE NoisePQC::noisepqc Catch2::Catch2)

# Test: Protocol Module
add_executable(test_protocol test_protocol.cpp)
target_link_libraries(test_protocol PRIVATE NoisePQC::noisepqc Catch2::Catch2)

# Test: HandshakeState Module
add_executable(test_handshakestate test_handshakestate.cpp)
target_link_libraries(test_handshakestate PRIVATE NoisePQC::noisepqc Catch2::Catch2)

# Test: Example (Complete API demonstration)
add_executable(test_example test_example.cpp)
target_link_libraries(test_example PRIVATE NoisePQC::noisepqc Catch2::Catch2)

# Test: Pattern Validation Module
add_executable(test_pattern test_pattern.cpp)
target_link_libraries(test_pattern PRIVATE NoisePQC::noisepqc Catch2::Catch2)

# Test: NoisePQC++ Post-Quantum Patterns
add_executable(test_noise_pq test_noise_pq.cpp)
target_link_libraries(test_noise_pq PRIVATE NoisePQC::noisepqc Catch2::Catch2)

# Test: HFS (Hybrid Forward Secrecy) Patterns
add_executable(test_hfs test_hfs.cpp)
target_link_libraries(test_hfs PRIVATE NoisePQC::noisepqc Catch2::Catch2)

# Test: Test Vectors (Cacophony)
add_executable(test_vectors test_vectors.cpp)
target_include_directories(test_vectors PRIVATE ${CMAKE_SOURCE_DIR}/third_party/nlohmann)
target_link_libraries(test_vectors PRIVATE NoisePQC::noisepqc Catch2::Catch2 noisepqc_testdata)

# Test: Wiping (secret material is scrubbed before its memory is freed)
add_executable(test_wiping test_wiping.cpp)
target_link_libraries(test_wiping PRIVATE NoisePQC::noisepqc Catch2::Catch2)

# Discover Catch2 tests
include(Catch)
# PRE_TEST keeps one test list per config; POST_BUILD shares one across multi-config builds
set(CMAKE_CATCH_DISCOVER_TESTS_DISCOVERY_MODE PRE_TEST)
catch_discover_tests(test_cipher)
catch_discover_tests(test_cipherstate)
catch_discover_tests(test_dh)
catch_discover_tests(test_hash)
catch_discover_tests(test_symmetricstate)
catch_discover_tests(test_protocol)
catch_discover_tests(test_handshakestate)
catch_discover_tests(test_example)
catch_discover_tests(test_pattern)
catch_discover_tests(test_noise_pq)
catch_discover_tests(test_hfs)
catch_discover_tests(test_vectors)
catch_discover_tests(test_wiping)

# Link-time optimization in Release configs (cmake/BuildConfig.cmake)
foreach(TARGET_NAME test_cipher test_cipherstate test_dh test_hash test_symmetricstate
        test_protocol test_handshakestate test_example test_pattern test_noise_pq test_hfs
        test_vectors)
    noisepqc_optimize_target(${TARGET_NAME})
endforeach()
noisepqc_optimize_target(test_wiping)
