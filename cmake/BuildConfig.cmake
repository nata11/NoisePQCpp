# ================================
# Build Configuration
# ================================
# This file contains build configuration for NoisePQC++:
# - Botan ISA baseline flags
# - Output directory settings
# - Link-time optimization
# - Test data path
# - Debug/Production build options
# - Benchmarks
#
# Options can be set via CMake command line: cmake -DOPTION_NAME=VALUE ..

# ================================
# Botan ISA baseline flags
# ================================
# Normally set by the toolchain file. Fallback (cache var, overridable at
# configure time) covers the no-toolchain-file path, i.e. auto-detected MSVC
# on Windows.
if(NOT DEFINED NOISE_BOTAN_ARCH_FLAGS)
    if(MSVC)
        set(NOISE_BOTAN_ARCH_FLAGS "/arch:AVX2" CACHE STRING "ISA baseline flags (project-wide)")
    else()
        set(NOISE_BOTAN_ARCH_FLAGS "" CACHE STRING "ISA baseline flags (project-wide)")
    endif()
endif()
message(STATUS "NoisePQC++: Botan arch flags: '${NOISE_BOTAN_ARCH_FLAGS}'")
# The ISA baseline applies project-wide (every C++ compile and
# link, in every config, third-party and CMake's std-module targets
# included), so all TUs share one CPU target. The floor is unchanged:
# COMDAT copies from botan_all.cpp already imposed it on every binary.
# (The variable keeps its historical name.)
string(APPEND CMAKE_CXX_FLAGS " ${NOISE_BOTAN_ARCH_FLAGS}")

# ================================
# Output Directories (same layout on every platform)
# ================================
# Outputs live in each build tree (e.g. build/bin, cmake-build-*/bin), so
# separate build dirs never overwrite each other's binaries. Override at
# configure time, e.g. -DNOISEPQC_BIN_DIR=<path-to-source>/bin for the
# old source-tree location (used up to 1.0.0).
set(NOISEPQC_BIN_DIR "${CMAKE_BINARY_DIR}/bin" CACHE PATH "Root directory for built executables and libraries")

# For single-config generators (Ninja)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${NOISEPQC_BIN_DIR}")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${NOISEPQC_BIN_DIR}/lib")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${NOISEPQC_BIN_DIR}/lib")

# For multi-config generators (Ninja Multi-Config) - separate Debug/Release subdirs
foreach(CONFIG_TYPE ${CMAKE_CONFIGURATION_TYPES})
    string(TOUPPER ${CONFIG_TYPE} CONFIG_TYPE_UPPER)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_${CONFIG_TYPE_UPPER} "${NOISEPQC_BIN_DIR}/${CONFIG_TYPE}")
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_${CONFIG_TYPE_UPPER} "${NOISEPQC_BIN_DIR}/${CONFIG_TYPE}/lib")
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_${CONFIG_TYPE_UPPER} "${NOISEPQC_BIN_DIR}/${CONFIG_TYPE}/lib")
endforeach()

# ================================
# Interprocedural optimization (Release configs only)
# ================================
# Per-config target properties, because a multi-config generator cannot
# decide at configure time which config is being built. Clang gets ThinLTO
# (CMake's default for Clang); LTO archives hold bitcode, so each toolchain
# file sets a matching CMAKE_AR/CMAKE_RANLIB.
include(CheckIPOSupported)
check_ipo_supported(RESULT IPO_SUPPORTED OUTPUT IPO_MSG LANGUAGES CXX)
if(NOT IPO_SUPPORTED)
    message(STATUS "NoisePQC++: IPO not supported: ${IPO_MSG}")
endif()

# Applied to botan_static, noisepqc, and every executable target.
# (asio_static deliberately excluded.) Executables also get a link-time
# dead-strip in non-Debug configs; the static libs already compile with
# -ffunction-sections -fdata-sections.
function(noisepqc_optimize_target target)
    if(IPO_SUPPORTED)
        set_target_properties(${target} PROPERTIES
            INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE
            INTERPROCEDURAL_OPTIMIZATION_RELWITHDEBINFO TRUE)
    endif()
    get_target_property(TARGET_TYPE ${target} TYPE)
    if(TARGET_TYPE STREQUAL "EXECUTABLE")
        if(MSVC)
            target_link_options(${target} PRIVATE
                "$<$<NOT:$<CONFIG:Debug>>:/OPT:REF;/OPT:ICF>")
        elseif(APPLE)
            target_link_options(${target} PRIVATE
                $<$<NOT:$<CONFIG:Debug>>:LINKER:-dead_strip>)
        else()
            target_link_options(${target} PRIVATE
                $<$<NOT:$<CONFIG:Debug>>:LINKER:--gc-sections>)
        endif()
    endif()
endfunction()

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

# For multi-config generators (Ninja Multi-Config): include if option enabled
# For single-config generators (Ninja): only include in Release if option enabled
if(NOISEPQC_BUILD_BENCHMARKS)
    if(CMAKE_CONFIGURATION_TYPES OR CMAKE_BUILD_TYPE STREQUAL "Release")
        # Use explicit paths since this file is in cmake/ subdirectory
        add_subdirectory(${CMAKE_SOURCE_DIR}/benchmarks ${CMAKE_BINARY_DIR}/benchmarks)
    endif()
endif()
