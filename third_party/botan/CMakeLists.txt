# ================================
# Botan Static Library Configuration
# ================================

# Verify PLATFORM_DIR is set by parent
if(NOT DEFINED PLATFORM_DIR)
    message(FATAL_ERROR "PLATFORM_DIR must be set before configuring Botan")
endif()

# Define the path to the platform-specific source directory
set(PLATFORM_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/${PLATFORM_DIR})

# Verify the platform directory exists
if(NOT EXISTS ${PLATFORM_SRC_DIR})
    message(FATAL_ERROR "Platform directory not found: ${PLATFORM_SRC_DIR}")
endif()

# Add the static library target
add_library(botan_static STATIC
    ${PLATFORM_SRC_DIR}/botan_all.cpp
)

# Set its include directory as PUBLIC
target_include_directories(botan_static
    PUBLIC
    ${PLATFORM_SRC_DIR}
)

message(STATUS "Configured Botan static library from: ${PLATFORM_DIR}")

# ================================
# Botan compile options
# ================================
# Botan is performance-critical third-party code: always optimized,
# independent of the project build type. There is never a reason to debug
# Botan internals at -O0, and NOISE_DEBUG_BUILD logging builds must still
# measure realistic crypto costs.
if(MSVC)
    # /O2 is incompatible with the /RTC1 CMake adds to MSVC Debug configs,
    # so MSVC Debug keeps default /Od (accepted platform limitation).
    target_compile_options(botan_static PRIVATE
        $<$<NOT:$<CONFIG:Debug>>:/O2>
        ${NOISE_BOTAN_ARCH_FLAGS} /Gy /w)
else()
    # -O3 appended after any config default; last optimization flag wins.
    target_compile_options(botan_static PRIVATE
        -O3 ${NOISE_BOTAN_ARCH_FLAGS} -ffunction-sections -fdata-sections -w)
endif()
target_compile_definitions(botan_static PRIVATE NDEBUG)

# Link-time optimization in Release configs (cmake/BuildConfig.cmake)
noisepqc_optimize_target(botan_static)
