# ================================
# Platform Detection Logic
# ================================
# Detects the operating system and processor architecture,
# then sets PLATFORM_DIR for platform-specific configurations.

# Helper function to add macOS std module target. Necessary for C++20 `import std;` support in CLion on macOS.
function(add_mac_std_module_target base_dir)
    add_library(unused_std_target STATIC)
    target_sources(unused_std_target
        PRIVATE
        FILE_SET CXX_MODULES
        BASE_DIRS ${base_dir}
        FILES ${base_dir}/std.cppm ${base_dir}/std.compat.cppm)
endfunction()

if (CMAKE_SYSTEM_NAME STREQUAL "Windows")
    # Target: Windows 11 (x86_64)
    message(STATUS "Configuring for Windows x64")
    set(PLATFORM_DIR "plat_win_x86")

elseif (CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    # Targets: macOS (Intel and Apple Silicon)
    message(STATUS "Detected macOS processor: '${CMAKE_SYSTEM_PROCESSOR}'")

    if (CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64" OR
            CMAKE_SYSTEM_PROCESSOR MATCHES "arm64" OR
            CMAKE_SYSTEM_PROCESSOR STREQUAL "" OR
            CMAKE_OSX_ARCHITECTURES MATCHES "arm64")
        # Apple Silicon Mac (including M4)
        message(STATUS "Configuring for macOS Apple Silicon (arm64)")
        set(PLATFORM_DIR "plat_mac_arm64")
        # For Mac CLion C++23 import std; modules support
        add_mac_std_module_target(/opt/homebrew/opt/llvm@18/share/libc++/v1)

    elseif (CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64" OR
            CMAKE_OSX_ARCHITECTURES MATCHES "x86_64")
        # Intel Mac
        message(STATUS "Configuring for macOS Intel (x86_64)")
        set(PLATFORM_DIR "plat_mac_x86")
        # For Mac CLion C++23 import std; modules support
        add_mac_std_module_target(/usr/local/opt/llvm@18/share/libc++/v1)

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