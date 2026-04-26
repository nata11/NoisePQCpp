# ================================
# NoisePQC++ Module Library
# ================================
# This library compiles all C++23 modules once and provides them
# to all consuming targets (tests, examples) via linking.
# This eliminates the need for each target to compile its own
# copy of the modules, significantly improving rebuild times.

set(NOISE_MODULES
    ${CMAKE_CURRENT_SOURCE_DIR}/Common.cppm
    ${CMAKE_CURRENT_SOURCE_DIR}/Errors.cppm
    ${CMAKE_CURRENT_SOURCE_DIR}/Cipher.cppm
    ${CMAKE_CURRENT_SOURCE_DIR}/Hash.cppm
    ${CMAKE_CURRENT_SOURCE_DIR}/Dh.cppm
    ${CIPHERSTATE_MODULE}
    ${SYMMETRICSTATE_MODULE}
    ${HANDSHAKESTATE_MODULE}
    ${CMAKE_CURRENT_SOURCE_DIR}/Protocol.cppm
    ${CMAKE_CURRENT_SOURCE_DIR}/Pattern.cppm
    ${CMAKE_CURRENT_SOURCE_DIR}/Noise.cppm
)

# Create a static library containing all NoisePQC++ modules
add_library(noisepqc STATIC)

target_sources(noisepqc
    PUBLIC
    FILE_SET modules TYPE CXX_MODULES
    BASE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}
    FILES ${NOISE_MODULES}
)

# Link dependencies (Botan is required by the modules)
target_link_libraries(noisepqc PUBLIC botan_static)

# Export as NoisePQC::noisepqc for clean consumption
add_library(NoisePQC::noisepqc ALIAS noisepqc)
