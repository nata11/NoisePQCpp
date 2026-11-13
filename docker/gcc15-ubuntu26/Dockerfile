FROM ubuntu:26.04

LABEL org.opencontainers.image.source=https://github.com/nata11/NoisePQCpp
LABEL org.opencontainers.image.description="NoisePQC++ build environment with GCC 15.2 on Ubuntu 26.04"
LABEL org.opencontainers.image.title="NoisePQC++ GCC 15 Build Environment"
LABEL org.opencontainers.image.version="1.1.0"
LABEL org.opencontainers.image.licenses="Apache-2.0"

ARG DEBIAN_FRONTEND=noninteractive
ARG CMAKE_VERSION=4.3.5
ARG TARGETARCH

# This image is published for linux/amd64 only. Fail loudly rather than
# producing an arm64 image that is not part of the release.
RUN test "${TARGETARCH}" = "amd64" || \
    (echo "This image is amd64-only (got TARGETARCH=${TARGETARCH}). Use the Clang 21 image for arm64." && exit 1)

# System dependencies. Ubuntu 26.04 ships GCC 15.2 as the build-essential
# default — no source build, unlike the 0.9.0 Debian Trixie image.
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
    gcc-15 \
    g++-15 \
    libstdc++-15-dev \
    python3 \
    python3-venv \
    python3-pip \
    ninja-build \
    gdb \
    valgrind \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Install exact CMake 4.3.5 from Kitware release.
RUN curl -fsSL "https://github.com/Kitware/CMake/releases/download/v${CMAKE_VERSION}/cmake-${CMAKE_VERSION}-linux-x86_64.sh" \
      -o /tmp/cmake.sh && \
    chmod +x /tmp/cmake.sh && \
    /tmp/cmake.sh --skip-license --prefix=/usr/local && \
    rm /tmp/cmake.sh

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

ENV CC=/usr/bin/gcc-15
ENV CXX=/usr/bin/g++-15
ENV CMAKE_GENERATOR=Ninja

WORKDIR /workspace

# Sanity checks for artifact reviewers. The libstdc++ std-module manifest must
# be discoverable or `import std;` fails at configure time; gcc15-linux-toolchain.cmake
# deliberately does not hardcode its path, so locate it and print what was found.
RUN cmake --version && \
    ninja --version && \
    g++-15 --version && \
    python3 --version && \
    git --version && \
    (find /usr/lib/gcc /usr/share/gcc /usr/include/c++ -name 'libstdc++.modules.json' -print -quit | grep -q . \
      && echo "OK: libstdc++.modules.json found" \
      || (echo "FAIL: libstdc++.modules.json not found — import std will not work" && exit 1))

CMD ["/bin/bash"]
