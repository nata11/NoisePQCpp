# Docker Image Usage Guide

Pre-configured Docker images provide everything needed to build, test, and benchmark NoisePQC++ on Linux without installing compilers or dependencies locally.

Two generations of images are published on GitHub Container Registry (GHCR):

- **Current (1.0.0)**: Ubuntu 26.04 with Clang 21 or GCC 15.2, and CMake 4.3.5. These track `main` and match the toolchain files in `cmake/`. Use these unless you are reproducing the 0.9.0 paper results.
- **Archived (0.9.0, paper artifact)**: Debian Trixie with Clang 18 or GCC 15.2, and CMake 4.0.4. These are pinned to the `v0.9.0` release and its paper artifact, and are kept unchanged so published digests stay reproducible. See [Archived Images (0.9.0 — Paper Artifact)](#archived-images-090--paper-artifact).

## Current Images (1.0.0)

| Image | Architectures | Base | Compiler | CMake | Ninja |
|-------|---------------|------|----------|-------|-------|
| `ghcr.io/nata11/noisepqcpp-clang21-ubuntu26:1.0.0` | amd64, arm64 | Ubuntu 26.04 | Clang 21.1.8 | 4.3.5 | 1.13.2 |
| `ghcr.io/nata11/noisepqcpp-gcc15-ubuntu26:1.0.0` | amd64 only | Ubuntu 26.04 | GCC 15.2.0 | 4.3.5 | 1.13.2 |

**There is no arm64 GCC image.** `noisepqcpp-gcc15-ubuntu26` is published for amd64 only. On arm64 hosts (Apple Silicon, Raspberry Pi 5, ARM servers), use the Clang 21 image.

Both images also include Git, Python 3 with analysis libraries (pandas, numpy, matplotlib, seaborn, scipy, JupyterLab), gdb, valgrind, and jq. Clang 21 and GCC 15.2 come from Ubuntu 26.04's own packages. CMake 4.3.5 is the pinned Kitware release.

The Clang 21 `:1.0.0` tag is a multi-arch manifest, so Docker automatically selects the right architecture for your host. Architecture-specific tags are also published:

- `ghcr.io/nata11/noisepqcpp-clang21-ubuntu26:1.0.0-amd64`
- `ghcr.io/nata11/noisepqcpp-clang21-ubuntu26:1.0.0-arm64`
- `ghcr.io/nata11/noisepqcpp-gcc15-ubuntu26:1.0.0-amd64`

Pull the image for your compiler of choice:

```bash
# Clang 21
docker pull ghcr.io/nata11/noisepqcpp-clang21-ubuntu26:1.0.0

# GCC 15 (amd64 only)
docker pull ghcr.io/nata11/noisepqcpp-gcc15-ubuntu26:1.0.0
```

**Apple Silicon Macs**: The Clang 21 image runs natively as `linux/arm64`. The GCC 15 image is amd64-only, so it always runs under emulation. Force the platform explicitly:

```bash
docker run --rm -it --platform linux/amd64 \
  ghcr.io/nata11/noisepqcpp-gcc15-ubuntu26:1.0.0
```

Emulated builds will be slower than native arm64. If GNU `tar` inside an amd64 Ubuntu 26.04 container fails with `Cannot open: Function not implemented`, Docker Desktop is emulating amd64 with Rosetta. In that case, turn off **Use Rosetta for x86_64/amd64 emulation on Apple Silicon** in Docker Desktop's settings so it falls back to QEMU.

### Getting the Source and Building

The images contain no NoisePQC++ source. There are two ways to get it into the container: clone inside the container, or mount a local clone.

#### Option A: Clone Inside the Container

Start the container and clone the repository:

```bash
docker run --rm -it ghcr.io/nata11/noisepqcpp-clang21-ubuntu26:1.0.0
```

Inside the container:

```bash
git clone https://github.com/nata11/NoisePQCpp.git
cd NoisePQCpp
```

#### Option B: Mount a Local Clone

Clone the repository on your host machine, then mount it into the container:

```bash
git clone https://github.com/nata11/NoisePQCpp.git

docker run --rm -it -v "$(pwd)/NoisePQCpp":/workspace/NoisePQCpp \
  ghcr.io/nata11/noisepqcpp-clang21-ubuntu26:1.0.0
```

Inside the container:

```bash
cd NoisePQCpp
```

#### Building with Clang 21

```bash
cmake -B build -S . -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=cmake/clang21-linux-toolchain.cmake \
  -DCMAKE_BUILD_TYPE=Release \
  -DNOISE_DEBUG_BUILD=OFF \
  -DNOISEPQC_BUILD_BENCHMARKS=ON

cmake --build build -j$(nproc)

ctest --test-dir build --output-on-failure
```

#### Building with GCC 15

Use the GCC 15 image instead (amd64 only):

```bash
docker run --rm -it --platform linux/amd64 \
  ghcr.io/nata11/noisepqcpp-gcc15-ubuntu26:1.0.0
```

Then configure with the GCC toolchain file:

```bash
cmake -B build -S . -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=cmake/gcc15-linux-toolchain.cmake \
  -DCMAKE_BUILD_TYPE=Release \
  -DNOISE_DEBUG_BUILD=OFF \
  -DNOISEPQC_BUILD_BENCHMARKS=ON

cmake --build build -j$(nproc)

ctest --test-dir build --output-on-failure
```

### Published Digests for Version 1.0.0

For strict reproducibility, pull the 1.0.0 images by their **immutable SHA256 digest** instead of by tag. These digests were read from the live registry with `docker buildx imagetools inspect`. Attestation manifests (`unknown/unknown`) are not listed.

**Clang 21 image** (`ghcr.io/nata11/noisepqcpp-clang21-ubuntu26`):

| Reference | SHA256 Digest |
|-----------|---------------|
| Multi-arch manifest (`:1.0.0`) | `sha256:d649f903c411370a75d005b54511347b4727f2f89d17ebd51de5b61c1732a03f` |
| `linux/amd64` | `sha256:3bde45c272c95ddb71fa988bc41eaf12171d2d1f49b5724142699713d9057d06` |
| `linux/arm64` | `sha256:08af1912236cae79a5c602083ebbe55bf2c332f8b7a7e6f7e98a60d7d99a451e` |

**GCC 15 image** (`ghcr.io/nata11/noisepqcpp-gcc15-ubuntu26`, amd64 only):

| Reference | SHA256 Digest |
|-----------|---------------|
| Manifest list (`:1.0.0`) | `sha256:ce68be5ba19c1989f19c913dd4663977270f2c9ee9086f5590e6b533b4c1778d` |
| `linux/amd64` | `sha256:30fe52faf002d2f38248e45843a11741c1fbc52732940798e21908460e9dd838` |

#### Pulling 1.0.0 Images by Digest

Pull the manifest list and let Docker select your architecture:

```bash
docker pull ghcr.io/nata11/noisepqcpp-clang21-ubuntu26@sha256:d649f903c411370a75d005b54511347b4727f2f89d17ebd51de5b61c1732a03f
docker pull ghcr.io/nata11/noisepqcpp-gcc15-ubuntu26@sha256:ce68be5ba19c1989f19c913dd4663977270f2c9ee9086f5590e6b533b4c1778d
```

Or pin to a specific architecture with the per-platform digest:

```bash
# Clang 21, linux/amd64
docker pull ghcr.io/nata11/noisepqcpp-clang21-ubuntu26@sha256:3bde45c272c95ddb71fa988bc41eaf12171d2d1f49b5724142699713d9057d06

# Clang 21, linux/arm64
docker pull ghcr.io/nata11/noisepqcpp-clang21-ubuntu26@sha256:08af1912236cae79a5c602083ebbe55bf2c332f8b7a7e6f7e98a60d7d99a451e

# GCC 15, linux/amd64
docker pull ghcr.io/nata11/noisepqcpp-gcc15-ubuntu26@sha256:30fe52faf002d2f38248e45843a11741c1fbc52732940798e21908460e9dd838
```

## Running Benchmarks

After a successful Release build with `-DNOISEPQC_BUILD_BENCHMARKS=ON`, run the handshake benchmark:

```bash
./bin/benchmarks/bench_handshake
```

To save the results for later analysis:

```bash
mkdir -p benchmark-results

# JSON output (for programmatic analysis)
./bin/benchmarks/bench_handshake \
  --benchmark_out=benchmark-results/handshake_results.json \
  --benchmark_out_format=json

# Text output
./bin/benchmarks/bench_handshake \
  | tee benchmark-results/handshake_results.txt
```

**Note**: Use `NOISE_DEBUG_BUILD=OFF` (as shown in the build commands above) for accurate benchmark results. Debug logging adds overhead that skews measurements.

## Archived Images (0.9.0 — Paper Artifact)

These are the images used for the NoisePQC++ 0.9.0 release and its paper. They are kept unchanged so that their published digests remain reproducible.

> **Important: use these images with the `v0.9.0` source tag, not current `main`.** The build instructions below use `cmake/clang18-linux-toolchain.cmake`, which was removed from the repository in commit `f591e07`. Current `main` targets Clang 21 and CMake 4.3, which these images do not provide. Check out the release tag after cloning:
>
> ```bash
> git clone https://github.com/nata11/NoisePQCpp.git
> cd NoisePQCpp
> git checkout v0.9.0
> ```
>
> Without this checkout, configuring inside a 0.9.0 image fails with a missing-toolchain-file error.

### Available Images (0.9.0)

The following multi-arch images are hosted on GitHub Container Registry (GHCR):

| Image | Architectures | Base | Compiler | CMake | Ninja |
|-------|---------------|------|----------|-------|-------|
| `ghcr.io/nata11/noisepqcpp-clang18-linux:0.9.0` | amd64, arm64 | Debian Trixie | Clang 18.1.8 | 4.0.4 | 1.12.1 |
| `ghcr.io/nata11/noisepqcpp-gcc15-linux:0.9.0` | amd64, arm64 | Debian Trixie | GCC 15.2.0 | 4.0.4 | 1.12.1 |

Both images also include Git, Python 3 with analysis libraries (pandas, numpy, matplotlib, seaborn, scipy), gdb, valgrind, and jq.

The `:0.9.0` tag is a multi-arch manifest — Docker automatically selects the right architecture for your host. Architecture-specific tags are also published if you want to pin a specific arch without using `--platform`:

- `ghcr.io/nata11/noisepqcpp-clang18-linux:0.9.0-amd64`
- `ghcr.io/nata11/noisepqcpp-clang18-linux:0.9.0-arm64`
- `ghcr.io/nata11/noisepqcpp-gcc15-linux:0.9.0-amd64`
- `ghcr.io/nata11/noisepqcpp-gcc15-linux:0.9.0-arm64`

Pull the image for your compiler of choice:

```bash
# Clang 18
docker pull ghcr.io/nata11/noisepqcpp-clang18-linux:0.9.0

# GCC 15
docker pull ghcr.io/nata11/noisepqcpp-gcc15-linux:0.9.0
```

**Apple Silicon Macs**: Docker automatically pulls the native `linux/arm64` variant from the multi-arch manifest. If you specifically want to run the `linux/amd64` image under Rosetta emulation (e.g., to reproduce an amd64-only result), force the platform:

```bash
docker run --rm -it --platform linux/amd64 \
  ghcr.io/nata11/noisepqcpp-clang18-linux:0.9.0
```

Emulated builds will be slower than native arm64.

> **Performance note (0.9.0 Debian images)**: In our testing, builds produced with the **Clang 18** image consistently outperform the GCC 15 image on the NoisePQC++ test and benchmark suites. If you only need to validate one configuration (e.g., reproducing benchmark numbers), prefer the Clang 18 image. Use the GCC 15 image when you specifically want to verify behavior under a second compiler.
>
> This observation comes from the 0.9.0 Debian Trixie images. It has not been re-measured with Clang 21 or on Ubuntu 26.04.

### Getting the Source and Building (0.9.0)

There are two ways to get the NoisePQC++ source into the container: clone inside the container, or mount a local clone. In both cases, run `git checkout v0.9.0` after cloning (see the note at the top of this section).

#### Option A: Clone Inside the Container

Start the container and clone the repository:

```bash
docker run --rm -it ghcr.io/nata11/noisepqcpp-clang18-linux:0.9.0
```

Inside the container:

```bash
git clone https://github.com/nata11/NoisePQCpp.git
cd NoisePQCpp
```

#### Option B: Mount a Local Clone

Clone the repository on your host machine, then mount it into the container:

```bash
git clone https://github.com/nata11/NoisePQCpp.git

docker run --rm -it -v "$(pwd)/NoisePQCpp":/workspace/NoisePQCpp \
  ghcr.io/nata11/noisepqcpp-clang18-linux:0.9.0
```

Inside the container:

```bash
cd NoisePQCpp
```

#### Building with Clang 18

```bash
cmake -B build -S . -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=cmake/clang18-linux-toolchain.cmake \
  -DCMAKE_BUILD_TYPE=Release \
  -DNOISE_DEBUG_BUILD=OFF \
  -DNOISEPQC_BUILD_BENCHMARKS=ON

cmake --build build -j$(nproc)

ctest --test-dir build --output-on-failure
```

#### Building with GCC 15

Use the GCC 15 image instead:

```bash
docker run --rm -it ghcr.io/nata11/noisepqcpp-gcc15-linux:0.9.0
```

Then configure with the GCC toolchain file:

```bash
cmake -B build -S . -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=cmake/gcc15-linux-toolchain.cmake \
  -DCMAKE_BUILD_TYPE=Release \
  -DNOISE_DEBUG_BUILD=OFF \
  -DNOISEPQC_BUILD_BENCHMARKS=ON

cmake --build build -j$(nproc)

ctest --test-dir build --output-on-failure
```

### Reproducible Builds (Pull by Digest)

For strict reproducibility (e.g., academic papers, artifact evaluation), pull images by their **immutable SHA256 digest** instead. A digest is content-addressed: a given digest always identifies the exact same image bytes, regardless of how tags evolve.

#### Published Digests for Version 0.9.0

**Clang 18 image** (`ghcr.io/nata11/noisepqcpp-clang18-linux`):

| Reference | SHA256 Digest |
|-----------|---------------|
| Multi-arch manifest (`:0.9.0`) | `sha256:2184a70a4881dd049a52a183cd9215437f5c8eb56b20686c5ae2e63e325524a0` |
| `linux/amd64` | `sha256:ba3f7d2cde37a095f9cffb4ef8b6b32f8ec5ff4347aec04ea437391d96127e12` |
| `linux/arm64` | `sha256:bb9f5d8671f8e9e3d1a19ec30a95b896c7619cce2168fbe75a80f4f377811dcb` |

**GCC 15 image** (`ghcr.io/nata11/noisepqcpp-gcc15-linux`):

| Reference | SHA256 Digest |
|-----------|---------------|
| Multi-arch manifest (`:0.9.0`) | `sha256:adfe1ff0d8895ffdd7216a523f578580a461db9db69d9e70d487ea6460fb603c` |
| `linux/amd64` | `sha256:f85ad31766ea0119e054119720ca80c0281c5a5d983025897bec84d0f5290fa8` |
| `linux/arm64` | `sha256:0c003abd6cb6dd3c7dfedb7e353709acdd3b7359c388e437420287243c0943b5` |

#### Pulling by Digest

Pull the multi-arch manifest and let Docker auto-select your architecture:

```bash
docker pull ghcr.io/nata11/noisepqcpp-clang18-linux@sha256:2184a70a4881dd049a52a183cd9215437f5c8eb56b20686c5ae2e63e325524a0
docker pull ghcr.io/nata11/noisepqcpp-gcc15-linux@sha256:adfe1ff0d8895ffdd7216a523f578580a461db9db69d9e70d487ea6460fb603c
```

Or pin to a specific architecture by using the per-arch manifest digest directly:

```bash
# Clang 18, linux/amd64
docker pull ghcr.io/nata11/noisepqcpp-clang18-linux@sha256:ba3f7d2cde37a095f9cffb4ef8b6b32f8ec5ff4347aec04ea437391d96127e12

# Clang 18, linux/arm64
docker pull ghcr.io/nata11/noisepqcpp-clang18-linux@sha256:bb9f5d8671f8e9e3d1a19ec30a95b896c7619cce2168fbe75a80f4f377811dcb

# GCC 15, linux/amd64
docker pull ghcr.io/nata11/noisepqcpp-gcc15-linux@sha256:f85ad31766ea0119e054119720ca80c0281c5a5d983025897bec84d0f5290fa8

# GCC 15, linux/arm64
docker pull ghcr.io/nata11/noisepqcpp-gcc15-linux@sha256:0c003abd6cb6dd3c7dfedb7e353709acdd3b7359c388e437420287243c0943b5
```

Once you have pulled by digest, the rest of the workflow (running the container, cloning the repo, building, testing, benchmarking) is identical to the tag-based instructions above.
