# NoisePQC++ Performance Benchmarks

Comprehensive performance benchmarking suite for NoisePQC++: Google Benchmark micro-benchmarks and TCP network benchmarks.

## Overview

This directory contains performance benchmarks for measuring and analyzing the performance of the Noise Protocol Framework implementation across Classical, Post-Quantum, and Hybrid Forward Secrecy patterns.

## Available Benchmarks

### Local Handshake Benchmarks

**File**: `bench_handshake.cpp`

Measures local handshake performance without network overhead:
- **Classical patterns** (NN, XX, IK, KK) with X25519 and X448
- **Post-Quantum patterns** (pqNN, pqXX, pqIK, pqKK) with ML-KEM-512/768/1024
- **Hybrid Forward Secrecy patterns** (NNhfs, XXhfs, IKhfs, KKhfs) with X25519 + ML-KEM-512/768/1024 and X448 + ML-KEM-1024
- **Key generation** for X25519, X448 and ML-KEM-512/768/1024

**Usage**:
```bash
# Build in Release mode (required for accurate benchmarks)
cmake --build build --config Release --target bench_handshake

# Run all handshake benchmarks
./build/bin/Release/benchmarks/bench_handshake

# Run specific pattern benchmarks
./build/bin/Release/benchmarks/bench_handshake --benchmark_filter=XX
./build/bin/Release/benchmarks/bench_handshake --benchmark_filter=pqXX
./build/bin/Release/benchmarks/bench_handshake --benchmark_filter=XXhfs

# Export results to JSON for analysis (out/ is ignored by git)
mkdir -p out
./build/bin/Release/benchmarks/bench_handshake \
  --benchmark_out=out/handshake_results.json --benchmark_out_format=json
```

### Network Benchmarks

**Directory**: `network/`

Real-world network performance benchmarks measuring handshake performance over TCP:

#### bench_server.cpp
Network benchmark responder that bench_client and bench_stress connect to:
- Supports the modes listed under **Modes** below
- Serves one connection at a time
- Prints each handshake (unless `--quiet`) and the connection count at exit; the clients do the timing

**Usage**:
```bash
# Terminal 1: start the server (here for the XX pattern)
./build/bin/Release/benchmarks/network/bench_server --mode xx

# Options: --port <p> (default 12346), --count <n> (exit after n successful
# handshakes; by default it runs until stopped), --quiet
```

#### bench_client.cpp
Network benchmark client that measures end-to-end handshake latency:
- Connects to benchmark server
- Measures handshake completion time
- Reports latency statistics

**Usage**:
```bash
# Terminal 2: 100 handshakes against the server (use the server's mode)
./build/bin/Release/benchmarks/network/bench_client --mode xx --iterations 100

# A post-quantum pattern, with the results written as CSV
./build/bin/Release/benchmarks/network/bench_client --mode pqxx --iterations 100 --output client_pqxx.csv

# Other options: --host <h> (default localhost), --port <p>, --latency <ms>, --quiet
```

#### bench_stress.cpp
Stress testing tool for concurrent handshakes:
- Spawns multiple concurrent clients
- Measures throughput under load
- Tests scalability and resource usage

**Usage**:
```bash
# 10 concurrent clients, 10 handshakes each (the defaults), against a server in the same mode
./build/bin/Release/benchmarks/network/bench_stress --mode xx

# With custom parameters
./build/bin/Release/benchmarks/network/bench_stress --mode xxhfs --clients 50 --iterations 20 --output stress_xxhfs.csv

# Other options: --host, --port, --ramp-up <ms> (default 10), --quiet
```

**Modes.** The three programs take the same `--mode` values, and a server
and its clients must use the same one. Six modes are supported: `nn`, `xx`,
`pqnn`, `pqxx`, `nnhfs` and `xxhfs`. `--help` also lists `ik`, `kk`, `pqik`,
`pqkk`, `ikhfs` and `kkhfs`, which aren't supported yet: their initiator needs
the responder's static key before the handshake, and the programs don't send
it, so every handshake fails (`Success: 0/n`). Each option takes its value as a
separate argument (`--clients 50`, not `--clients=50`).

### Example Benchmark

**File**: `bench_example.cpp`

Primitive benchmarks: SHA-256 hashing (64 B to 8 KiB), X25519 key generation and DH.

## Building Benchmarks

### Prerequisites

- **C++23 Compiler**: Clang 21, GCC 15.2+, or MSVC 19.44+
- **CMake** 4.3+
- **Ninja** build system
- **Google Benchmark** v1.10.0 (automatically downloaded via FetchContent)
- **asio** 1.39.0 for the network benchmarks (automatically downloaded via FetchContent)

### Build Instructions

**IMPORTANT**: Always build benchmarks in **Release mode** for accurate performance measurements.

```bash
# Configure with Multi-Config Ninja generator (debug logging off for measurements)
cmake -B build -S . -G "Ninja Multi-Config" \
  -DCMAKE_TOOLCHAIN_FILE=cmake/clang21-macOS-toolchain.cmake \
  -DNOISE_DEBUG_BUILD=OFF

# Build all benchmarks in Release mode
cmake --build build --config Release

# Or build specific benchmark
cmake --build build --config Release --target bench_handshake
cmake --build build --config Release --target bench_server
cmake --build build --config Release --target bench_client
cmake --build build --config Release --target bench_stress
```

**Benchmark executables** are located in:
- `build/bin/Release/benchmarks/` (handshake benchmarks)
- `build/bin/Release/benchmarks/network/` (network benchmarks)

## Running Benchmarks

### Basic Usage

```bash
cd build/bin/Release/benchmarks

# Run all handshake benchmarks
./bench_handshake

# Run with verbose output
./bench_handshake --benchmark_verbosity=high

# Run each benchmark for at least 5 seconds
./bench_handshake --benchmark_min_time=5s

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
# From the repository root; out/ is ignored by git
mkdir -p out

# Export to JSON (the console keeps the normal table)
./build/bin/Release/benchmarks/bench_handshake \
  --benchmark_out=out/handshake_results.json --benchmark_out_format=json

# Export to CSV
./build/bin/Release/benchmarks/bench_handshake \
  --benchmark_out=out/handshake_results.csv --benchmark_out_format=csv
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
python3 analysis/scripts/json_to_csv.py out/handshake_results.json out/handshake_results.csv
python3 analysis/scripts/json_to_csv.py --split out/handshake_results.json out/csv/   # one CSV per category
```

### Setting Up Analysis Environment

```bash
# Install the Python dependencies in a virtual environment
python3 -m venv out/venv && . out/venv/bin/activate
pip install -r analysis/requirements.txt

# Start Jupyter notebook
jupyter notebook analysis/benchmark_analysis.ipynb
```

## Benchmark Patterns

### Classical Patterns

| Pattern | Description | Use Case |
|---------|-------------|----------|
| NN | Ephemeral keys only | Anonymous sessions, baseline cost |
| XX | Full mutual authentication | General purpose, server-to-server |
| IK | Immediate known responder | Minimal latency mutual auth |
| KK | Both static keys known in advance | Pre-provisioned peers |

### Post-Quantum Patterns

| Pattern | Description | Quantum Resistance |
|---------|-------------|-------------------|
| pqNN | PQ ephemeral keys only | Quantum-resistant anonymous sessions |
| pqXX | PQ mutual authentication | Full quantum resistance |
| pqIK | PQ immediate known | Low-latency PQ auth |
| pqKK | PQ, both static keys known in advance | Quantum-resistant pre-provisioned peers |

### Hybrid Forward Secrecy Patterns

| Pattern | Description | Security Level |
|---------|-------------|----------------|
| NNhfs | DH + KEM, ephemeral keys only | Hybrid anonymous sessions |
| XXhfs | DH + KEM mutual auth | Defense-in-depth |
| IKhfs | DH + KEM immediate | Low-latency hybrid |
| KKhfs | DH + KEM, both static keys known in advance | Hybrid pre-provisioned peers |

## Interpreting Results

### Key Metrics

- **Time** - Average time per handshake operation (ns, μs, ms)
- **CPU** - CPU time consumed
- **Iterations** - Number of test iterations performed
- **Bytes/sec** - Throughput measurement

## Network Benchmark Workflow

### Complete Benchmarking Session

```bash
cd build/bin/Release/benchmarks/network

# Terminal 1: a server that exits after 150 successful handshakes
./bench_server --mode xx --count 150 > server_log.txt

# Terminal 2: 100 handshakes, as CSV
./bench_client --mode xx --iterations 100 --output client_xx.csv

# Then: 5 clients x 10 handshakes, as CSV
./bench_stress --mode xx --clients 5 --iterations 10 --output stress_xx.csv
```

## Troubleshooting

### Issue: Benchmark results are inconsistent

**Solution**:
- Ensure you built in **Release mode** (`--config Release`)
- Close other applications to reduce system load
- Run benchmarks multiple times and average results
- Use `--benchmark_min_time=5s` for longer, more stable tests

### Issue: Network benchmarks fail to connect

**Solution**:
- Ensure server is running before starting client
- Check that port 12346 (the network benchmarks' default) is not in use: `lsof -i :12346`
- Verify firewall settings allow local connections
- Check that both server and client use the same `--mode`

### Issue: Benchmarks take too long

**Solution**:
- Use filters to run specific benchmarks: `--benchmark_filter=XX`
- Reduce minimum time: `--benchmark_min_time=1s`
- Run fewer iterations (Google Benchmark auto-adjusts)

## Best Practices

1. **Always use Release builds with `NOISE_DEBUG_BUILD=OFF`** - Debug builds leave NoisePQC++ unoptimized, and debug logging adds overhead
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

**Version**: NoisePQC++ v1.1.0
**Last Updated**: 2026-11-13
**Google Benchmark**: v1.10.0 (auto-downloaded)
