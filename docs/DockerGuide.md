# Docker Image Usage Guide

Pre-configured Docker images provide everything needed to build, test, and benchmark NoisePQC++ on Linux without installing compilers or dependencies locally.

## Available Images

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

> **Performance note**: In our testing, builds produced with the **Clang 18** image consistently outperform the GCC 15 image on the NoisePQC++ test and benchmark suites. If you only need to validate one configuration (e.g., reproducing benchmark numbers), prefer the Clang 18 image. Use the GCC 15 image when you specifically want to verify behavior under a second compiler.

## Getting the Source and Building

There are two ways to get the NoisePQC++ source into the container: clone inside the container, or mount a local clone.

### Option A: Clone Inside the Container

Start the container and clone the repository:

```bash
docker run --rm -it ghcr.io/nata11/noisepqcpp-clang18-linux:0.9.0
```

Inside the container:

```bash
git clone https://github.com/nata11/NoisePQCpp.git
cd NoisePQCpp
```

### Option B: Mount a Local Clone

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

### Building with Clang 18

```bash
cmake -B build -S . -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=cmake/clang18-linux-toolchain.cmake \
  -DCMAKE_BUILD_TYPE=Release \
  -DNOISE_DEBUG_BUILD=OFF \
  -DNOISEPQC_BUILD_BENCHMARKS=ON

cmake --build build -j$(nproc)

ctest --test-dir build --output-on-failure
```

### Building with GCC 15

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

## Reproducible Builds (Pull by Digest)

For strict reproducibility (e.g., academic papers, artifact evaluation), pull images by their **immutable SHA256 digest** instead. A digest is content-addressed: a given digest always identifies the exact same image bytes, regardless of how tags evolve.

### Published Digests for Version 0.9.0

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

### Pulling by Digest

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
