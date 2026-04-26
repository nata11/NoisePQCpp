# ================================
# ASIO Networking Examples with NoisePQC++
# ================================
# Demonstrates secure client-server communication using
# the Noise Protocol XX handshake pattern over TCP.

# Output ASIO examples to bin/examples/asio/ (single-config) or bin/<Config>/examples/asio/ (multi-config)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${NOISEPQC_BIN_DIR}/examples/asio")
foreach(CONFIG_TYPE ${CMAKE_CONFIGURATION_TYPES})
    string(TOUPPER ${CONFIG_TYPE} CONFIG_TYPE_UPPER)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_${CONFIG_TYPE_UPPER} "${NOISEPQC_BIN_DIR}/${CONFIG_TYPE}/examples/asio")
endforeach()

# Noise Server - Accepts connections and echoes messages
add_executable(noise_server noise_server.cpp)
target_link_libraries(noise_server PRIVATE NoisePQC::noisepqc asio_static)

# Noise Client - Connects to server and sends interactive messages
add_executable(noise_client noise_client.cpp)
target_link_libraries(noise_client PRIVATE NoisePQC::noisepqc asio_static)

# ================================
# Multi-Mode Examples (XX, pqXX, XXhfs)
# ================================
# Supports mode selection via command line with prologue-based mode matching

# Multi-Mode Server - Supports xx, pqxx, xxhfs modes
add_executable(noise_server_multi noise_server_multi.cpp)
target_link_libraries(noise_server_multi PRIVATE NoisePQC::noisepqc asio_static)

# Multi-Mode Client - Supports xx, pqxx, xxhfs modes
add_executable(noise_client_multi noise_client_multi.cpp)
target_link_libraries(noise_client_multi PRIVATE NoisePQC::noisepqc asio_static)

# ================================
# Alice & Bob Quote Exchange Examples
# ================================
# Demonstrates secure quote exchange with verification
# Uses X448/M1024, AESGCM, SHA512 configuration

# Alice - Quote Exchange Server (Responder)
add_executable(alice alice.cpp)
target_link_libraries(alice PRIVATE NoisePQC::noisepqc asio_static noisepqc_testdata)
target_include_directories(alice PRIVATE ${CMAKE_SOURCE_DIR}/third_party/nlohmann)

# Bob - Quote Exchange Client (Initiator)
add_executable(bob bob.cpp)
target_link_libraries(bob PRIVATE NoisePQC::noisepqc asio_static noisepqc_testdata)
target_include_directories(bob PRIVATE ${CMAKE_SOURCE_DIR}/third_party/nlohmann)
