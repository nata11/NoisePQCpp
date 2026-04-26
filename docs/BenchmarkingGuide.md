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

- **Local handshake benchmarks** — 42 benchmarks measuring handshake latency for classical, post-quantum, and HFS patterns with various DH/KEM algorithm combinations
- **Network benchmarks** — TCP client/server benchmarks measuring real-world handshake latency over the network for 12 protocol modes
- **Stress tests** — Multi-threaded concurrent handshake throughput and latency under load

All benchmarks use [Google Benchmark](https://github.com/google/benchmark) v1.9.1, which is automatically downloaded via CMake FetchContent on first build.

---

## Prerequisites

- **Release build configuration** — benchmarks are only built in Release mode (single-config generators) or when using a multi-config generator
- Compiler, CMake, and Ninja requirements are the same as the main project — see [Build Guide](BuildGuide.md#prerequisites)
- **Python 3** (optional) — required for CSV conversion and result analysis scripts in `analysis/`

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
  -DCMAKE_TOOLCHAIN_FILE=cmake/clang18-macOS-toolchain.cmake \
  -DCMAKE_BUILD_TYPE=Release \
  -DNOISEPQC_BUILD_BENCHMARKS=OFF
```

### Build Type Requirements

The build type determines whether benchmarks are actually compiled:

| Generator Type | Condition for Benchmarks to Build |
|---|---|
| **Single-config** (Ninja, Make) | `CMAKE_BUILD_TYPE` must be `Release` |
| **Multi-config** (Ninja Multi-Config, Xcode, VS) | Always included when option is `ON`; build with `--config Release` |

**Important**: With single-config Ninja, if you configure with `-DCMAKE_BUILD_TYPE=Debug`, benchmarks will **not** be built even if `NOISEPQC_BUILD_BENCHMARKS=ON`. This is intentional — benchmarks should only be run with compiler optimizations enabled.

### Google Benchmark Download

Google Benchmark v1.9.1 is fetched via CMake FetchContent (`third_party/CMakeLists.txt`) only when:
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
  -DCMAKE_TOOLCHAIN_FILE=cmake/clang18-macOS-toolchain.cmake \
  -DCMAKE_BUILD_TYPE=Release

# Build all targets (includes benchmarks)
cmake --build build -j$(sysctl -n hw.ncpu)

# Or build only a specific benchmark target
cmake --build build --target bench_handshake
```

### Multi-Config Generator (Ninja Multi-Config)

```bash
# Configure — no CMAKE_BUILD_TYPE needed
cmake -B build -S . -G "Ninja Multi-Config" \
  -DCMAKE_TOOLCHAIN_FILE=cmake/clang18-macOS-toolchain.cmake

# Build benchmarks in Release configuration
cmake --build build --config Release

# Or build a specific target in Release
cmake --build build --config Release --target bench_handshake
```

### Output Locations

Benchmark binaries are placed in:

| Generator | Local Benchmarks | Network Benchmarks |
|---|---|---|
| Single-config | `bin/benchmarks/` | `bin/benchmarks/network/` |
| Multi-config | `bin/Release/benchmarks/` | `bin/Release/benchmarks/network/` |

---

## Benchmark Targets

| Target | Description | Source |
|---|---|---|
| `bench_example` | Primitive benchmarks (SHA256 hashing, X25519 key generation and DH) | `benchmarks/bench_example.cpp` |
| `bench_handshake` | 42 handshake benchmarks across classical, PQ, and HFS patterns | `benchmarks/bench_handshake.cpp` |
| `bench_server` | TCP server for network handshake benchmarks | `benchmarks/network/bench_server.cpp` |
| `bench_client` | TCP client with handshake timing and statistics | `benchmarks/network/bench_client.cpp` |
| `bench_stress` | Multi-threaded concurrent handshake stress test | `benchmarks/network/bench_stress.cpp` |

For detailed descriptions of each target and the specific benchmarks they run, see [benchmarks/README.md](../benchmarks/README.md).

---

## Quick Start: Running Benchmarks

### Local Handshake Benchmarks

```bash
# Run all 42 handshake benchmarks
./bin/Release/benchmarks/bench_handshake

# Run only classical pattern benchmarks
./bin/Release/benchmarks/bench_handshake --benchmark_filter=Classical

# Run only post-quantum benchmarks
./bin/Release/benchmarks/bench_handshake --benchmark_filter=pq

# Run only HFS benchmarks
./bin/Release/benchmarks/bench_handshake --benchmark_filter=hfs

# Export results to JSON
./bin/Release/benchmarks/bench_handshake \
  --benchmark_format=json \
  --benchmark_out=analysis/data/handshake_results.json
```

### Network Benchmarks

```bash
# Terminal 1: Start the server (XX pattern)
./bin/Release/benchmarks/network/bench_server --mode xx

# Terminal 2: Run the client
./bin/Release/benchmarks/network/bench_client --mode xx --iterations 100

# Stress test with concurrent clients
./bin/Release/benchmarks/network/bench_stress --mode xx --clients 10 --iterations 50
```

For filtering options, export formats, latency simulation, available network modes, and analysis workflows, see [benchmarks/README.md](../benchmarks/README.md).

---

## Automated Benchmark Suite

The `scripts/run_benchmarks.sh` script runs the complete benchmark suite in one shot:

```bash
./scripts/run_benchmarks.sh
```

This automates:
1. System information capture (`analysis/data/system_info.txt`)
2. Release build of all benchmark targets
3. Local benchmark execution with JSON export
4. JSON-to-CSV conversion via `analysis/scripts/json_to_csv.py`
5. Network benchmarks across all 12 modes
6. Stress tests with 1, 5, and 10 concurrent clients
7. Summary of all generated data files

Output is written to `analysis/data/`. To generate figures from the results:

```bash
python3 analysis/scripts/render_results.py
```

Figures are saved to `analysis/figures/`. For the complete automated workflow details, see [benchmarks/README.md](../benchmarks/README.md).

---

## Troubleshooting

### Benchmarks Not Building

**Problem**: Benchmark targets are missing after building.

**Cause**: Single-config generator without Release build type.

**Solution**: Ensure `CMAKE_BUILD_TYPE=Release` is set:

```bash
cmake -B build -S . -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=cmake/clang18-macOS-toolchain.cmake \
  -DCMAKE_BUILD_TYPE=Release
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
  -DCMAKE_TOOLCHAIN_FILE=cmake/clang18-macOS-toolchain.cmake \
  -DCMAKE_BUILD_TYPE=Release \
  -DNOISEPQC_BUILD_BENCHMARKS=ON
cmake --build build
```

---

**For More Information**:
- [benchmarks/README.md](../benchmarks/README.md) — Detailed benchmark running, filtering, export, and analysis
- [Build Guide](BuildGuide.md) — General build instructions
- [scripts/run_benchmarks.sh](../scripts/run_benchmarks.sh) — Automated benchmark suite script
