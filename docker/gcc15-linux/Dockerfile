FROM debian:trixie AS gcc-builder

ARG DEBIAN_FRONTEND=noninteractive
ARG GCC_VERSION=15.2.0

# Build dependencies required to compile GCC from source.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    xz-utils \
    build-essential \
    flex \
    bison \
    texinfo \
    libgmp-dev \
    libmpfr-dev \
    libmpc-dev \
    libisl-dev \
    zlib1g-dev \
    libzstd-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tmp

# Download and verify GCC 15.2.0 source.
RUN curl -fsSLO "https://gcc.gnu.org/pub/gcc/releases/gcc-${GCC_VERSION}/gcc-${GCC_VERSION}.tar.xz" && \
    curl -fsSLO "https://gcc.gnu.org/pub/gcc/releases/gcc-${GCC_VERSION}/sha512.sum" && \
    grep "  gcc-${GCC_VERSION}.tar.xz$" sha512.sum | sha512sum -c - && \
    tar -xf "gcc-${GCC_VERSION}.tar.xz" && \
    mkdir gcc-build

WORKDIR /tmp/gcc-build

# Install GCC as /opt/gcc-15/bin/gcc-15 and /opt/gcc-15/bin/g++-15.
# This matches the existing NoisePQC++ GCC toolchain file.
RUN "../gcc-${GCC_VERSION}/configure" \
      --prefix=/opt/gcc-15 \
      --program-suffix=-15 \
      --disable-multilib \
      --disable-bootstrap \
      --enable-languages=c,c++ \
      --enable-libstdcxx-backtrace && \
    make -j"$(nproc)" && \
    make install-strip


FROM debian:trixie

LABEL org.opencontainers.image.source=https://github.com/nata11/NoisePQCpp
LABEL org.opencontainers.image.description="NoisePQC++ build environment with GCC 15.2.0"
LABEL org.opencontainers.image.title="NoisePQC++ Clang 18 Build Environment"
LABEL org.opencontainers.image.version="0.9.0"
LABEL org.opencontainers.image.licenses="Apache-2.0"

ARG DEBIAN_FRONTEND=noninteractive
ARG CMAKE_VERSION=4.0.4
ARG TARGETARCH

# Runtime/build environment for NoisePQC++.
# Debian Trixie provides ninja-build 1.12.1.
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
    ninja-build \
    libgmp10 \
    libmpfr6 \
    libmpc3 \
    libisl23 \
    zlib1g \
    libzstd1 \
    gdb \
    valgrind \
    jq \
    && rm -rf /var/lib/apt/lists/*

COPY --from=gcc-builder /opt/gcc-15 /opt/gcc-15

# Install exact CMake 4.0.4 from Kitware release.
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

# Python environment for benchmark analysis notebooks/scripts.
RUN python3 -m venv /opt/noisepqc-venv
ENV PATH="/opt/noisepqc-venv/bin:/opt/gcc-15/bin:${PATH}"
ENV LD_LIBRARY_PATH="/opt/gcc-15/lib64"

RUN pip install --upgrade pip setuptools wheel && \
    pip install \
      "pandas>=2.0.0" \
      "numpy>=1.24.0" \
      "matplotlib>=3.7.0" \
      "seaborn>=0.12.0" \
      "jupyterlab>=4.0.0" \
      "notebook>=7.0.0" \
      "scipy>=1.10.0"

ENV CC=/opt/gcc-15/bin/gcc-15
ENV CXX=/opt/gcc-15/bin/g++-15
ENV CMAKE_GENERATOR=Ninja

WORKDIR /workspace

# Sanity checks for artifact reviewers.
RUN cmake --version && \
    ninja --version && \
    gcc-15 --version && \
    g++-15 --version && \
    python3 --version && \
    git --version

CMD ["/bin/bash"]