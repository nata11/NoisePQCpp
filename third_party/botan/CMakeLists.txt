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