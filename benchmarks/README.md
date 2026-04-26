# NoisePQC++ Performance Benchmarks

Comprehensive performance benchmarking suite for NoisePQC++ using Google Benchmark framework.

## Overview

This directory contains performance benchmarks for measuring and analyzing the performance of the Noise Protocol Framework implementation across Classical, Post-Quantum, and Hybrid Forward Secrecy patterns.

## Available Benchmarks

### Local Handshake Benchmarks

**File**: `bench_handshake.cpp`

Measures local handshake performance without network overhead:
- **Classical patterns** (XX, NK, IK, etc.) with X25519 and X448
- **Post-Quantum patterns** (pqXX, pqNK, etc.) with ML-KEM-512/768/1024
- **Hybrid Forward Secrecy patterns** (XXhfs, NKhfs, etc.) with X25519/X448 + ML-KEM combinations

**Usage**:
```bash
# Build in Release mode (required for accurate benchmarks)
cmake --build cmake-build-release --config Release --target bench_handshake

# Run all handshake benchmarks
./bin/Release/benchmarks/bench_handshake

# Run specific pattern benchmarks
./bin/Release/benchmarks/bench_handshake --benchmark_filter=XX
./bin/Release/benchmarks/bench_handshake --benchmark_filter=pqXX
./bin/Release/benchmarks/bench_handshake --benchmark_filter=XXhfs

# Export results to JSON for analysis
./bin/Release/benchmarks/bench_handshake --benchmark_format=json \
  --benchmark_out=results/handshake_results.json
```

### Network Benchmarks

**Directory**: `network/`

Real-world network performance benchmarks measuring handshake performance over TCP:

#### bench_server.cpp
Network benchmark server that measures handshake completion rates:
- Supports Classical, PQ, and HFS patterns
- Handles concurrent client connections
- Reports handshakes per second

**Usage**:
```bash
# Start benchmark server (Terminal 1)
./bin/Release/benchmarks/network/bench_server

# The server listens on port 12345 by default
# Server outputs handshake completion metrics
```

#### bench_client.cpp
Network benchmark client that measures end-to-end handshake latency:
- Connects to benchmark server
- Measures handshake completion time
- Reports latency statistics

**Usage**:
```bash
# Run benchmark client (Terminal 2)
./bin/Release/benchmarks/network/bench_client

# With specific pattern
./bin/Release/benchmarks/network/bench_client --pattern=pqXX
```

#### bench_stress.cpp
Stress testing tool for concurrent handshakes:
- Spawns multiple concurrent clients
- Measures throughput under load
- Tests scalability and resource usage

**Usage**:
```bash
# Run stress test with default settings
./bin/Release/benchmarks/network/bench_stress

# With custom parameters
./bin/Release/benchmarks/network/bench_stress \
  --clients=100 \
  --duration=60 \
  --pattern=XXhfs
```

### Example Benchmark

**File**: `bench_example.cpp`

Simple benchmark example demonstrating Google Benchmark usage with NoisePQC++.

## Building Benchmarks

### Prerequisites

- **C++23 Compiler**: Clang 18+, GCC 15.2+, or MSVC 19.44+
- **CMake** 4.0+
- **Ninja** build system
- **Google Benchmark** (automatically downloaded via FetchContent)

### Build Instructions

**IMPORTANT**: Always build benchmarks in **Release mode** for accurate performance measurements.

```bash
# Configure with Multi-Config Ninja generator
cmake -B cmake-build-release -S . -G "Ninja Multi-Config" \
  -DCMAKE_TOOLCHAIN_FILE=cmake/clang18-macOS-toolchain.cmake

# Build all benchmarks in Release mode
cmake --build cmake-build-release --config Release

# Or build specific benchmark
cmake --build cmake-build-release --config Release --target bench_handshake
cmake --build cmake-build-release --config Release --target bench_server
cmake --build cmake-build-release --config Release --target bench_client
cmake --build cmake-build-release --config Release --target bench_stress
```

**Benchmark executables** are located in:
- `bin/Release/benchmarks/` (handshake benchmarks)
- `bin/Release/benchmarks/network/` (network benchmarks)

## Running Benchmarks

### Basic Usage

```bash
cd bin/Release/benchmarks

# Run all handshake benchmarks
./bench_handshake

# Run with verbose output
./bench_handshake --benchmark_verbosity=high

# Run with specific iterations
./bench_handshake --benchmark_min_time=5.0

# List all available benchmarks
./bench_handshake --benchmark_list_tests
```

### Filtering Benchmarks

```bash
# Run only XX pattern benchmarks
./bench_handshake --benchmark_filter=XX

# Run only Post-Quantum benchmarks
./bench_handshake --benchmark_filter=pq

# Run only HFS benchmarks
./bench_handshake --benchmark_filter=hfs

# Run specific DH algorithm benchmarks
./bench_handshake --benchmark_filter=X25519
./bench_handshake --benchmark_filter=X448
```

### Exporting Results

```bash
# Export to JSON
./bench_handshake --benchmark_format=json \
  --benchmark_out=../../../results/handshake_results.json

# Export to CSV
./bench_handshake --benchmark_format=csv \
  --benchmark_out=../../../results/handshake_results.csv

# Export with console output
./bench_handshake --benchmark_format=json \
  --benchmark_out=results.json \
  --benchmark_out_format=json
```

## Performance Analysis

### Analysis Tools

The `analysis/` directory contains tools for analyzing benchmark results:

**Jupyter Notebook** (`benchmark_analysis.ipynb`):
- Visualize performance trends
- Compare Classical vs PQ vs HFS patterns
- Analyze throughput and latency distributions
- Generate performance charts

**JSON to CSV Converter** (`scripts/json_to_csv.py`):
```bash
cd analysis/scripts
python3 json_to_csv.py ../../results/handshake_results.json
```

### Setting Up Analysis Environment

```bash
cd analysis

# Install Python dependencies
pip3 install -r requirements.txt

# Start Jupyter notebook
jupyter notebook benchmark_analysis.ipynb
```

## Benchmark Patterns

### Classical Patterns

| Pattern | Description | Use Case |
|---------|-------------|----------|
| XX | Full mutual authentication | General purpose, server-to-server |
| NK | Known responder public key | Client-to-server, server identity known |
| IK | Immediate known responder | Minimal latency mutual auth |

### Post-Quantum Patterns

| Pattern | Description | Quantum Resistance |
|---------|-------------|-------------------|
| pqXX | PQ mutual authentication | Full quantum resistance |
| pqNK | PQ known responder | Quantum-resistant server auth |
| pqIK | PQ immediate known | Low-latency PQ auth |

### Hybrid Forward Secrecy Patterns

| Pattern | Description | Security Level |
|---------|-------------|----------------|
| XXhfs | DH + KEM mutual auth | Defense-in-depth |
| NKhfs | DH + KEM known responder | Hybrid server auth |
| IKhfs | DH + KEM immediate | Low-latency hybrid |

## Interpreting Results

### Key Metrics

- **Time** - Average time per handshake operation (ns, μs, ms)
- **CPU** - CPU time consumed
- **Iterations** - Number of test iterations performed
- **Bytes/sec** - Throughput measurement

### Performance Expectations

**Classical patterns** (X25519):
- XX handshake: ~500-800 μs
- NK handshake: ~300-500 μs

**Post-Quantum patterns** (ML-KEM-768):
- pqXX handshake: ~1-2 ms
- pqNK handshake: ~800 μs - 1.5 ms

**Hybrid patterns** (X25519 + ML-KEM-768):
- XXhfs handshake: ~1.5-2.5 ms
- NKhfs handshake: ~1-2 ms

*Note: Times vary based on CPU, compiler optimizations, and system load*

## Network Benchmark Workflow

### Complete Benchmarking Session

```bash
# Terminal 1: Start server
cd bin/Release/benchmarks/network
./bench_server > server_metrics.txt

# Terminal 2: Run standard client test
./bench_client --pattern=XX > client_xx_results.txt

# Terminal 3: Run stress test
./bench_stress --clients=50 --duration=30 > stress_results.txt

# Analyze results
cd ../../../../analysis
python3 scripts/analyze_network_results.py \
  ../results/server_metrics.txt \
  ../results/client_xx_results.txt
```

## Troubleshooting

### Issue: Benchmark results are inconsistent

**Solution**:
- Ensure you built in **Release mode** (`--config Release`)
- Close other applications to reduce system load
- Run benchmarks multiple times and average results
- Use `--benchmark_min_time=5.0` for longer, more stable tests

### Issue: Network benchmarks fail to connect

**Solution**:
- Ensure server is running before starting client
- Check that port 12345 is not in use: `lsof -i :12345`
- Verify firewall settings allow local connections
- Check that both server and client use matching patterns

### Issue: Benchmarks take too long

**Solution**:
- Use filters to run specific benchmarks: `--benchmark_filter=XX`
- Reduce minimum time: `--benchmark_min_time=1.0`
- Run fewer iterations (Google Benchmark auto-adjusts)

## Best Practices

1. **Always use Release builds** - Debug builds are 10-100x slower
2. **Minimize system load** - Close unnecessary applications
3. **Run multiple times** - Average results for consistency
4. **Export results** - Save data for trend analysis
5. **Use filters** - Focus on relevant patterns
6. **Document system specs** - Include CPU, RAM, OS in reports

## Additional Resources

- **Main README**: [../README.md](../README.md)
- **Examples**: [../examples/README.md](../examples/README.md)
- **Tests**: [../tests/README.md](../tests/README.md)
- **Google Benchmark Docs**: https://github.com/google/benchmark
- **Noise Protocol Spec**: https://noiseprotocol.org/noise.html

---

**Version**: NoisePQC++ v0.9.0
**Last Updated**: 2026-04-25
**Google Benchmark**: v1.9.1 (auto-downloaded)
