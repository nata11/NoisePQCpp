# ================================
# Platform Detection Logic
# ================================
# Detects the operating system and processor architecture,
# then sets PLATFORM_DIR for platform-specific configurations.

if (CMAKE_SYSTEM_NAME STREQUAL "Windows")
    # Target: Windows 11 (x86_64)
    message(STATUS "Configuring for Windows x64")
    set(PLATFORM_DIR "plat_win_x86")

elseif (CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    # Target: macOS (Apple Silicon)
    message(STATUS "Detected macOS processor: '${CMAKE_SYSTEM_PROCESSOR}'")

    if (CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64" OR
            CMAKE_SYSTEM_PROCESSOR MATCHES "arm64" OR
            CMAKE_SYSTEM_PROCESSOR STREQUAL "" OR
            CMAKE_OSX_ARCHITECTURES MATCHES "arm64")
        # Apple Silicon Mac
        message(STATUS "Configuring for macOS Apple Silicon (arm64)")
        set(PLATFORM_DIR "plat_mac_arm64")

    elseif (CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64" OR
            CMAKE_OSX_ARCHITECTURES MATCHES "x86_64")
        message(FATAL_ERROR "macOS on Intel (x86_64) is not supported since NoisePQC++ 1.1.0 (Apple Silicon only)")

    else ()
        message(FATAL_ERROR "Unsupported macOS processor: '${CMAKE_SYSTEM_PROCESSOR}', CMAKE_OSX_ARCHITECTURES: '${CMAKE_OSX_ARCHITECTURES}'")
    endif ()

elseif (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    # Targets: Linux (x86_64 and aarch64)
    if (CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64")
        # Linux arm64 (Raspberry Pi 5 and other aarch64 hosts)
        message(STATUS "Configuring for Linux aarch64")
        set(PLATFORM_DIR "plat_linux_arm64")
    elseif (CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64")
        # Ubuntu (x86_64) - Detect compiler toolchain
        if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
            message(STATUS "Configuring for Linux x86_64 with Clang compiler")
            set(PLATFORM_DIR "plat_linux_x86_clang")
        elseif (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
            message(STATUS "Configuring for Linux x86_64 with GCC compiler")
            set(PLATFORM_DIR "plat_linux_x86_gcc")
        else ()
            message(FATAL_ERROR "Unsupported compiler for Linux x86_64: ${CMAKE_CXX_COMPILER_ID}. Only Clang and GCC are supported.")
        endif ()
    else ()
        message(FATAL_ERROR "Unsupported Linux processor: ${CMAKE_SYSTEM_PROCESSOR}")
    endif ()

else ()
    message(FATAL_ERROR "Unsupported platform: ${CMAKE_SYSTEM_NAME}")
endif ()