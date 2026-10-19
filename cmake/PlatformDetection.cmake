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
    # Targets: macOS (Apple Silicon; Intel builds but is untested as of 1.0.0)
    message(STATUS "Detected macOS processor: '${CMAKE_SYSTEM_PROCESSOR}'")

    if (CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64" OR
            CMAKE_SYSTEM_PROCESSOR MATCHES "arm64" OR
            CMAKE_SYSTEM_PROCESSOR STREQUAL "" OR
            CMAKE_OSX_ARCHITECTURES MATCHES "arm64")
        # Apple Silicon Mac (including M4)
        message(STATUS "Configuring for macOS Apple Silicon (arm64)")
        set(PLATFORM_DIR "plat_mac_arm64")

    elseif (CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64" OR
            CMAKE_OSX_ARCHITECTURES MATCHES "x86_64")
        # Intel Mac: untested as of 1.0.0; plat_mac_x86 will be removed in a future release
        message(STATUS "Configuring for macOS Intel (x86_64)")
        message(WARNING "macOS on Intel (x86_64) is untested as of NoisePQC++ 1.0.0. "
                "The build should work, pinned to the macOS 26 SDK. The Intel Botan sources "
                "(third_party/botan/plat_mac_x86) will be removed in a future release.")
        set(PLATFORM_DIR "plat_mac_x86")

    else ()
        message(FATAL_ERROR "Unsupported macOS processor: '${CMAKE_SYSTEM_PROCESSOR}', CMAKE_OSX_ARCHITECTURES: '${CMAKE_OSX_ARCHITECTURES}'")
    endif ()

elseif (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    # Targets: Linux (x86_64 and aarch64)
    if (CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64")
        # Raspberry Pi 4/5 (arm64)
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