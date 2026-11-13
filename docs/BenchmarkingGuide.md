# Benchmarking Guide

This guide explains how to configure CMake, build, and run the NoisePQC++ benchmark suite. For detailed instructions on running individual benchmarks, filtering, exporting results, and analysis, see [benchmarks/README.md](../benchmarks/README.md).

## Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [CMake Configuration](#cmake-configuration)
- [Building Benchmarks](#building-benchmarks)
- [Benchmark Targets](#benchmark-targets)
- [Quick Start: Running Benchmarks](#quick-start-running-benchmarks)
- [Automated Benchmark Suite](#automated-benchmark-suite)
- [Troubleshooting](#troubleshooting)

---

## Overview

NoisePQC++ includes three categories of benchmarks:

- **Local handshake benchmarks** — 41 benchmarks: 36 handshakes across classical (8), PQ (12) and HFS (16) configurations with various DH/KEM algorithm combinations, plus 5 key-generation benchmarks
- **Network benchmarks** — TCP client/server benchmarks measuring real-world handshake latency over TCP in 6 protocol modes (`nn`, `xx`, `pqnn`, `pqxx`, `nnhfs`, `xxhfs`), all covered by the automated run (`scripts/run_benchmarks.sh`)
- **Stress tests** — Multi-threaded concurrent handshake throughput and latency under load

The local benchmarks (`bench_handshake`, `bench_example`) use [Google Benchmark](https://github.com/google/benchmark) v1.10.0, downloaded via CMake FetchContent at configure time; the network benchmarks are standalone programs.

---

## Prerequisites

- **Release build configuration**. Single-config generators build benchmarks only when `CMAKE_BUILD_TYPE=Release`. Ninja Multi-Config builds them in every config except Debug.
- Compiler, CMake, and Ninja requirements are the same as the main project — see [Build Guide](BuildGuide.md#prerequisites)
- **Python 3**: required by `scripts/run_benchmarks.sh` (CSV conversion, standard library only); the render script and notebook also need the packages in `analysis/requirements.txt`

---

## CMake Configuration

### NOISEPQC_BUILD_BENCHMARKS Option

Benchmarks are controlled by the `NOISEPQC_BUILD_BENCHMARKS` CMake option, defined in `cmake/BuildConfig.cmake`:

```cmake
option(NOISEPQC_BUILD_BENCHMARKS "Build benchmarks (requires Release config)" ON)
```

**Default**: `ON` — benchmarks are enabled by default.

To disable benchmarks (skips Google Benchmark download entirely):

```bash
cmake -B build -S . -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=cmake/clang21-macOS-toolchain.cmake \
  -DCMAKE_BUILD_TYPE=Release \
  -DNOISEPQC_BUILD_BENCHMARKS=OFF
```

### Build Type Requirements

The build type determines whether benchmarks are actually compiled:

| Generator Type | Condition for Benchmarks to Build |
|---|---|
| **Single-config** (Ninja) | `CMAKE_BUILD_TYPE` must be `Release` |
| **Multi-config** (Ninja Multi-Config) | Always included when option is `ON`; build with `--config Release` |

**Important**: With single-config Ninja, if you configure with `-DCMAKE_BUILD_TYPE=Debug`, benchmarks will **not** be built even if `NOISEPQC_BUILD_BENCHMARKS=ON`. This is intentional — benchmarks should only be run with compiler optimizations enabled.

### Google Benchmark Download

Google Benchmark v1.10.0 is fetched via CMake FetchContent (`third_party/CMakeLists.txt`) only when:
1. `NOISEPQC_BUILD_BENCHMARKS` is `ON`, **and**
2. The build type condition above is met

The download happens during the CMake configure step. On subsequent builds, the cached source is reused.

FetchContent configuration:
- `BENCHMARK_ENABLE_TESTING=OFF` — benchmark's own tests are disabled
- `BENCHMARK_ENABLE_INSTALL=OFF` — benchmark is not installed system-wide
- `BENCHMARK_ENABLE_GTEST_TESTS=OFF` — GTest integration is disabled

---

## Building Benchmarks

### Single-Config Generator (Ninja)

```bash
# Configure — Release is required for benchmarks
cmake -B build -S . -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=cmake/clang21-macOS-toolchain.cmake \
  -DCMAKE_BUILD_TYPE=Release \
  -DNOISE_DEBUG_BUILD=OFF

# Build all targets (includes benchmarks)
cmake --build build -j$(sysctl -n hw.ncpu)

# Or build only a specific benchmark target
cmake --build build --target bench_handshake
```

### Multi-Config Generator (Ninja Multi-Config)

```bash
# Configure — no CMAKE_BUILD_TYPE needed
cmake -B build -S . -G "Ninja Multi-Config" \
  -DCMAKE_TOOLCHAIN_FILE=cmake/clang21-macOS-toolchain.cmake \
  -DNOISE_DEBUG_BUILD=OFF

# Build benchmarks in Release configuration
cmake --build build --config Release

# Or build a specific target in Release
cmake --build build --config Release --target bench_handshake
```

### Output Locations

Benchmark binaries are placed under the build directory (`build/` in the commands above):

| Generator | Local Benchmarks | Network Benchmarks |
|---|---|---|
| Single-config | `build/bin/benchmarks/` | `build/bin/benchmarks/network/` |
| Multi-config | `build/bin/Release/benchmarks/` | `build/bin/Release/benchmarks/network/` |

Each build directory has its own `bin/`, so separate builds never overwrite each other's binaries. CLion profiles build in `cmake-build-<profile>/`, so their benchmarks are in `cmake-build-<profile>/bin/Release/benchmarks/`. To put outputs somewhere else, configure with `-DNOISEPQC_BIN_DIR=<path>`.

---

## Benchmark Targets

| Target | Description | Source |
|---|---|---|
| `bench_example` | Primitive benchmarks (SHA256 hashing, X25519 key generation and DH) | `benchmarks/bench_example.cpp` |
| `bench_handshake` | 36 handshake and 5 key-generation benchmarks (classical, PQ, HFS) | `benchmarks/bench_handshake.cpp` |
| `bench_server` | TCP server for network handshake benchmarks | `benchmarks/network/bench_server.cpp` |
| `bench_client` | TCP client with handshake timing and statistics | `benchmarks/network/bench_client.cpp` |
| `bench_stress` | Multi-threaded concurrent handshake stress test | `benchmarks/network/bench_stress.cpp` |

For detailed descriptions of each target and the specific benchmarks they run, see [benchmarks/README.md](../benchmarks/README.md).

---

## Quick Start: Running Benchmarks

### Local Handshake Benchmarks

```bash
# Run all 41 benchmarks
./build/bin/Release/benchmarks/bench_handshake

# Run only classical pattern benchmarks
./build/bin/Release/benchmarks/bench_handshake --benchmark_filter=Classical

# Run only post-quantum benchmarks
./build/bin/Release/benchmarks/bench_handshake --benchmark_filter=pq

# Run only HFS benchmarks
./build/bin/Release/benchmarks/bench_handshake --benchmark_filter=hfs

# Export results to JSON
mkdir -p out
./build/bin/Release/benchmarks/bench_handshake \
  --benchmark_out=out/handshake_results.json \
  --benchmark_out_format=json
```

### Network Benchmarks

```bash
# Terminal 1: Start the server (XX pattern)
./build/bin/Release/benchmarks/network/bench_server --mode xx

# Terminal 2: Run the client
./build/bin/Release/benchmarks/network/bench_client --mode xx --iterations 100

# Stress test with concurrent clients
./build/bin/Release/benchmarks/network/bench_stress --mode xx --clients 10 --iterations 50
```

A server and its clients must use the same `--mode`. Six modes are
supported: `nn`, `xx`, `pqnn`, `pqxx`, `nnhfs` and `xxhfs`. The `ik`, `kk`,
`pqik`, `pqkk`, `ikhfs` and `kkhfs` modes that `--help` lists aren't supported
yet: the responder's static key isn't sent before the handshake.

For filtering options, export formats, latency simulation, available network modes, and analysis workflows, see [benchmarks/README.md](../benchmarks/README.md).

---

## Automated Benchmark Suite

The `scripts/run_benchmarks.sh` script builds and runs the complete benchmark suite in one shot:

```bash
./scripts/run_benchmarks.sh
```

This automates:
1. Configuring and building all benchmark targets (Release) in the script's own build directory
2. System and build details (`system_info.txt`)
3. Local benchmark execution with JSON export
4. JSON-to-CSV conversion via `analysis/scripts/json_to_csv.py`
5. Network benchmarks across all 6 modes (`nn`, `xx`, `pqnn`, `pqxx`, `nnhfs`, `xxhfs`)
6. Stress tests in the `xx`, `pqxx` and `xxhfs` modes with 1, 5, and 10 concurrent clients
7. Summary of all generated data files

### Options

| Option | Default | Meaning |
|---|---|---|
| `--toolchain FILE` | chosen by host (see below) | CMake toolchain file |
| `--build-dir DIR` | `out/bench-<toolchain file name without .cmake>` | Build directory, configured on every run |
| `--out-dir DIR` | `out/bench-results/<UTC yyyymmddThhmmssZ>-<host name>` | Where the results are written |
| `--build-only` | off | Configure, build, verify the five binaries and write `system_info.txt`, then stop. No benchmark runs |
| `-h`, `--help` | | Show the usage text |

An unknown option is an error. A relative `FILE` or `DIR` is relative to the current directory.

- **Toolchain.** Without `--toolchain`, the script picks `cmake/clang21-macOS-toolchain.cmake` on macOS. On Linux it picks `cmake/clang21-linux-toolchain.cmake` if `/usr/bin/clang++-21` exists, otherwise `cmake/gcc15-linux-toolchain.cmake` if `g++-15` is on `PATH`. To use GCC on a host that has both compilers, pass `--toolchain cmake/gcc15-linux-toolchain.cmake`.
- **Build directory.** The script uses its own build directory under `out/` (ignored by git), for example `out/bench-clang21-linux-toolchain`, never an IDE's. It configures that directory on every run with `-G "Ninja Multi-Config"`, `-DNOISE_DEBUG_BUILD=OFF` and `-DNOISEPQC_BUILD_BENCHMARKS=ON`, so debug logging is always off in the measured binaries. If the directory was configured with a different toolchain file, the script stops with an error, because CMake ignores a changed toolchain file in an existing build directory.
- **Output directory.** Each run writes to a new directory, for example `out/bench-results/20261106T164500Z-myhost`. `analysis/data/` holds the tracked data of the v0.9.0 paper. The script writes there only when you pass `--out-dir analysis/data`, and then it prints a warning first.
- **Run details.** `system_info.txt` records the commit and whether the working tree was clean, the OS and CPU, the compiler, the toolchain file, `NOISE_DEBUG_BUILD`, `NOISE_BOTAN_ARCH_FLAGS` and the number of `bench_handshake` registrations.
- **Linux arm64.** Numbers taken on Linux arm64 with 1.0.0 or 1.1.0 reflect Botan's portable code paths; see the [known limitation in the Build Guide](BuildGuide.md#isa-baseline-optimization-and-linking).

To generate figures and the report from a run, pass its output directory to the render script. The benchmark script prints this line when it finishes:

```bash
python3 analysis/scripts/render_results.py --data-dir <out-dir>
```

By default the figures are saved to `out/render/<data-dir name>/figures/` and the Markdown report to `out/render/<data-dir name>/BENCHMARK_RESULTS.md`; `--figures-dir` and `--output` override them, and the tracked `analysis/figures/` is written only when you pass it as `--figures-dir`. For running, filtering and exporting individual benchmarks, see [benchmarks/README.md](../benchmarks/README.md).

---

## Troubleshooting

### Benchmarks Not Building

**Problem**: Benchmark targets are missing after building.

**Cause**: Single-config generator without Release build type.

**Solution**: Ensure `CMAKE_BUILD_TYPE=Release` is set:

```bash
cmake -B build -S . -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=cmake/clang21-macOS-toolchain.cmake \
  -DCMAKE_BUILD_TYPE=Release \
  -DNOISE_DEBUG_BUILD=OFF
```

Or use a multi-config generator and build with `--config Release`.

### Google Benchmark Download Fails

**Problem**: FetchContent fails to download Google Benchmark during configure.

**Solution**:
- Check internet connectivity
- Try a clean configure: `rm -rf build && cmake -B build ...`
- Verify Git is installed (FetchContent uses Git for cloning)

### Benchmark Targets Not Found After Disabling

**Problem**: Previously built benchmark targets no longer exist.

**Cause**: `NOISEPQC_BUILD_BENCHMARKS` was set to `OFF` or build type changed from Release.

**Solution**: Reconfigure with benchmarks enabled and Release build type:

```bash
rm -rf build
cmake -B build -S . -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=cmake/clang21-macOS-toolchain.cmake \
  -DCMAKE_BUILD_TYPE=Release \
  -DNOISE_DEBUG_BUILD=OFF \
  -DNOISEPQC_BUILD_BENCHMARKS=ON
cmake --build build
```

---

**For More Information**:
- [benchmarks/README.md](../benchmarks/README.md) — Detailed benchmark running, filtering, export, and analysis
- [Build Guide](BuildGuide.md) — General build instructions
- [scripts/run_benchmarks.sh](../scripts/run_benchmarks.sh) — Automated benchmark suite script
