# ================================
# Build Configuration
# ================================
# This file contains build configuration for NoisePQC++:
# - Output directory settings
# - Debug/Production build options
#
# Options can be set via CMake command line: cmake -DOPTION_NAME=VALUE ..

# ================================
# Output Directories (consistent across platforms)
# ================================
set(NOISEPQC_BIN_DIR "${CMAKE_SOURCE_DIR}/bin")

# For single-config generators (Ninja, Make)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${NOISEPQC_BIN_DIR}")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${NOISEPQC_BIN_DIR}/lib")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${NOISEPQC_BIN_DIR}/lib")

# For multi-config generators (MSBuild, Xcode) - separate Debug/Release subdirs
foreach(CONFIG_TYPE ${CMAKE_CONFIGURATION_TYPES})
    string(TOUPPER ${CONFIG_TYPE} CONFIG_TYPE_UPPER)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_${CONFIG_TYPE_UPPER} "${NOISEPQC_BIN_DIR}/${CONFIG_TYPE}")
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_${CONFIG_TYPE_UPPER} "${NOISEPQC_BIN_DIR}/${CONFIG_TYPE}/lib")
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_${CONFIG_TYPE_UPPER} "${NOISEPQC_BIN_DIR}/${CONFIG_TYPE}/lib")
endforeach()

# ================================
# Test Data Directory
# ================================
# Interface library that provides TESTDATA_DIR compile definition
# Targets that need access to testdata can link to this
add_library(noisepqc_testdata INTERFACE)
target_compile_definitions(noisepqc_testdata INTERFACE TESTDATA_DIR="${CMAKE_SOURCE_DIR}/testdata")

# ================================
# Logging Configuration
# ================================
# Controls whether debug logging is compiled into the library
#
# ON  = Debug build with verbose logging enabled
#       Uses: CipherState.debug.cppm, SymmetricState.debug.cppm, HandshakeState.debug.cppm
#       Adds NOISE_DEBUG_BUILD compile definition
#       Enables detailed logging for cipher, symmetric, and handshake operations
#
# OFF = Production build without logging overhead
#       Uses: CipherState.cppm, SymmetricState.cppm, HandshakeState.cppm
#       Logging functions become no-ops, zero runtime overhead
#
option(NOISE_DEBUG_BUILD "Build with debug logging enabled" ON)

if(NOISE_DEBUG_BUILD)
    message(STATUS "NoisePQC++: Debug build with logging ENABLED")
    set(CIPHERSTATE_MODULE "${CMAKE_SOURCE_DIR}/src/CipherState.debug.cppm")
    set(SYMMETRICSTATE_MODULE "${CMAKE_SOURCE_DIR}/src/SymmetricState.debug.cppm")
    set(HANDSHAKESTATE_MODULE "${CMAKE_SOURCE_DIR}/src/HandshakeState.debug.cppm")
    add_compile_definitions(NOISE_DEBUG_BUILD)
else()
    message(STATUS "NoisePQC++: Production build with logging DISABLED")
    set(CIPHERSTATE_MODULE "${CMAKE_SOURCE_DIR}/src/CipherState.cppm")
    set(SYMMETRICSTATE_MODULE "${CMAKE_SOURCE_DIR}/src/SymmetricState.cppm")
    set(HANDSHAKESTATE_MODULE "${CMAKE_SOURCE_DIR}/src/HandshakeState.cppm")
endif()

# ================================
# Benchmark Configuration
# ================================
# Option to enable/disable benchmarks (useful to skip Google Benchmark download)
option(NOISEPQC_BUILD_BENCHMARKS "Build benchmarks (requires Release config)" ON)

# For multi-config generators (Ninja Multi-Config, Xcode, VS): include if option enabled
# For single-config generators (Ninja, Make): only include in Release if option enabled
if(NOISEPQC_BUILD_BENCHMARKS)
    if(CMAKE_CONFIGURATION_TYPES OR CMAKE_BUILD_TYPE STREQUAL "Release")
        # Use explicit paths since this file is in cmake/ subdirectory
        add_subdirectory(${CMAKE_SOURCE_DIR}/benchmarks ${CMAKE_BINARY_DIR}/benchmarks)
    endif()
endif()
