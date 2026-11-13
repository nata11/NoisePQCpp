FROM ubuntu:26.04

LABEL org.opencontainers.image.source=https://github.com/nata11/NoisePQCpp
LABEL org.opencontainers.image.description="NoisePQC++ build environment with Clang 21 on Ubuntu 26.04"
LABEL org.opencontainers.image.title="NoisePQC++ Clang 21 Build Environment"
LABEL org.opencontainers.image.version="1.1.0"
LABEL org.opencontainers.image.licenses="Apache-2.0"

ARG DEBIAN_FRONTEND=noninteractive
ARG CMAKE_VERSION=4.3.5
ARG TARGETARCH

# System dependencies, Clang 21, libc++, Ninja, Git, Python, and useful tools.
# Ubuntu 26.04 ships Clang 21 natively — no LLVM apt repository needed.
# clang-tools-21 provides clang-scan-deps-21, required by CMake for C++ modules.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    wget \
    git \
    xz-utils \
    unzip \
    tar \
    pkg-config \
    build-essential \
    python3 \
    python3-venv \
    python3-pip \
    clang-21 \
    clang-tools-21 \
    lld-21 \
    llvm-21 \
    libc++-21-dev \
    libc++abi-21-dev \
    libunwind-21-dev \
    ninja-build \
    gdb \
    valgrind \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Install exact CMake 4.3.5 from Kitware release. Ubuntu's packaged cmake is
# not guaranteed to be >= 4.3, which the top-level CMakeLists.txt requires.
# TARGETARCH is provided by Docker BuildKit/buildx.
RUN case "${TARGETARCH}" in \
      "amd64") CMAKE_ARCH="x86_64" ;; \
      "arm64") CMAKE_ARCH="aarch64" ;; \
      *) echo "Unsupported TARGETARCH=${TARGETARCH}" && exit 1 ;; \
    esac && \
    curl -fsSL "https://github.com/Kitware/CMake/releases/download/v${CMAKE_VERSION}/cmake-${CMAKE_VERSION}-linux-${CMAKE_ARCH}.sh" \
      -o /tmp/cmake.sh && \
    chmod +x /tmp/cmake.sh && \
    /tmp/cmake.sh --skip-license --prefix=/usr/local && \
    rm /tmp/cmake.sh

# Helpful generic name if CMake looks for clang-scan-deps without the version suffix.
RUN ln -sf /usr/bin/clang-scan-deps-21 /usr/bin/clang-scan-deps

# Python environment for benchmark analysis notebooks/scripts.
RUN python3 -m venv /opt/noisepqc-venv
ENV PATH="/opt/noisepqc-venv/bin:${PATH}"

RUN pip install --upgrade pip setuptools wheel && \
    pip install \
      "pandas>=2.0.0" \
      "numpy>=1.24.0" \
      "matplotlib>=3.7.0" \
      "seaborn>=0.12.0" \
      "jupyterlab>=4.0.0" \
      "notebook>=7.0.0" \
      "scipy>=1.10.0"

ENV CC=/usr/bin/clang-21
ENV CXX=/usr/bin/clang++-21
ENV CMAKE_GENERATOR=Ninja

WORKDIR /workspace

# Sanity checks for artifact reviewers.
# The libc++.modules.json assertion is not cosmetic: cmake/clang21-linux-toolchain.cmake
# hardcodes this exact path via CMAKE_CXX_STDLIB_MODULES_JSON, and `import std;`
# fails at configure time if it is missing or moved.
RUN cmake --version && \
    ninja --version && \
    clang++-21 --version && \
    clang-scan-deps-21 --version && \
    python3 --version && \
    git --version && \
    test -f /usr/lib/llvm-21/lib/libc++.modules.json && \
    echo "OK: /usr/lib/llvm-21/lib/libc++.modules.json present"

CMD ["/bin/bash"]
