#!/usr/bin/env bash
# =============================================================================
# NoisePQC++ Benchmark Runner
# Builds and runs all benchmarks, captures results to analysis/data/
# =============================================================================
set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

BUILD_DIR="$PROJECT_ROOT/cmake-build-release-clang-21"
TOOLCHAIN="$PROJECT_ROOT/cmake/clang21-macOS-toolchain.cmake"
BIN_DIR="$PROJECT_ROOT/bin/Release/benchmarks"
NET_BIN="$BIN_DIR/network"
DATA_DIR="$PROJECT_ROOT/analysis/data"
SCRIPTS_DIR="$PROJECT_ROOT/analysis/scripts"

NET_PORT_BASE=12346
NET_ITERATIONS=100
STRESS_CLIENTS=(1 5 10)
STRESS_ITER_PER_CLIENT=20
BENCH_MIN_TIME="3s"

# Network modes: ik/kk variants require out-of-band static key exchange
# which is not yet implemented in the bench_client/server protocol.
# Only nn and xx modes (and their PQ/HFS variants) work currently.
CLASSICAL_MODES=(nn xx)
PQ_MODES=(pqnn pqxx)
HFS_MODES=(nnhfs xxhfs)
ALL_NET_MODES=("${CLASSICAL_MODES[@]}" "${PQ_MODES[@]}" "${HFS_MODES[@]}")
STRESS_MODES=(xx pqxx xxhfs)

TMPDIR_BENCH="$(mktemp -d)"

# ---------------------------------------------------------------------------
# Cleanup trap
# ---------------------------------------------------------------------------
SERVER_PID=""
cleanup() {
    if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    rm -rf "$TMPDIR_BENCH"
}
trap cleanup EXIT INT TERM

# ---------------------------------------------------------------------------
# Helper: wait for server with timeout
# ---------------------------------------------------------------------------
wait_for_server() {
    local pid=$1
    local timeout=${2:-60}
    local elapsed=0
    while kill -0 "$pid" 2>/dev/null && (( elapsed < timeout )); do
        sleep 1
        (( elapsed++ ))
    done
    if kill -0 "$pid" 2>/dev/null; then
        echo "  [WARN] Server PID $pid did not exit within ${timeout}s, killing..."
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    fi
}

# ---------------------------------------------------------------------------
# Helper: check port availability
# ---------------------------------------------------------------------------
port_available() {
    ! lsof -i :"$1" >/dev/null 2>&1
}

# ---------------------------------------------------------------------------
echo "============================================================"
echo "NoisePQC++ Benchmark Runner"
echo "============================================================"
echo "Project root: $PROJECT_ROOT"
echo "Build dir:    $BUILD_DIR"
echo "Data output:  $DATA_DIR"
echo ""

mkdir -p "$DATA_DIR"

# ---------------------------------------------------------------------------
# Step 1: Capture system info
# ---------------------------------------------------------------------------
echo "[1/8] Capturing system information..."
{
    echo "=== NoisePQC++ Benchmark System Info ==="
    echo "Date: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    echo ""
    echo "--- OS ---"
    uname -a
    if command -v sw_vers &>/dev/null; then
        sw_vers
    fi
    echo ""
    echo "--- CPU ---"
    if command -v sysctl &>/dev/null; then
        echo "Model: $(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo 'N/A')"
        echo "Cores: $(sysctl -n hw.ncpu 2>/dev/null || echo 'N/A')"
        echo "Frequency: $(sysctl -n hw.cpufrequency_max 2>/dev/null || echo 'N/A') Hz"
    fi
    echo ""
    echo "--- Memory ---"
    if command -v sysctl &>/dev/null; then
        mem_bytes=$(sysctl -n hw.memsize 2>/dev/null || echo 0)
        echo "Total: $(( mem_bytes / 1073741824 )) GB"
    fi
    echo ""
    echo "--- Compiler ---"
    if [[ -f "$TOOLCHAIN" ]]; then
        # Extract compiler path from toolchain file
        COMPILER=$(grep 'CMAKE_C_COMPILER' "$TOOLCHAIN" | head -1 | sed 's/.*"\(.*\)".*/\1/' || echo "clang++")
        CXX_COMPILER=$(grep 'CMAKE_CXX_COMPILER' "$TOOLCHAIN" | head -1 | sed 's/.*"\(.*\)".*/\1/' || echo "clang++")
        echo "C Compiler: $COMPILER"
        echo "C++ Compiler: $CXX_COMPILER"
        "$CXX_COMPILER" --version 2>/dev/null || echo "(version unavailable)"
    fi
    echo ""
    echo "--- CMake ---"
    cmake --version | head -1
    echo ""
    echo "--- Build Configuration ---"
    echo "Generator: Ninja Multi-Config"
    echo "Config: Release"
    echo "Benchmark min time: $BENCH_MIN_TIME"
} > "$DATA_DIR/system_info.txt" 2>&1

echo "  -> $DATA_DIR/system_info.txt"

# ---------------------------------------------------------------------------
# Step 2: Build benchmark targets
# ---------------------------------------------------------------------------
echo ""
echo "[2/8] Building benchmark targets (Release)..."

if [[ ! -d "$BUILD_DIR" ]]; then
    echo "  Configuring CMake..."
    cmake -G "Ninja Multi-Config" -B "$BUILD_DIR" \
        -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN" \
        -DNOISEPQC_BUILD_BENCHMARKS=ON
fi

cmake --build "$BUILD_DIR" --config Release \
    --target bench_example bench_handshake bench_server bench_client bench_stress \
    --parallel

echo "  -> Build complete"

# Verify binaries exist
for bin in bench_example bench_handshake; do
    if [[ ! -x "$BIN_DIR/$bin" ]]; then
        echo "ERROR: $BIN_DIR/$bin not found after build"
        exit 1
    fi
done
for bin in bench_server bench_client bench_stress; do
    if [[ ! -x "$NET_BIN/$bin" ]]; then
        echo "ERROR: $NET_BIN/$bin not found after build"
        exit 1
    fi
done

# ---------------------------------------------------------------------------
# Step 3: Run bench_example
# ---------------------------------------------------------------------------
echo ""
echo "[3/8] Running bench_example..."

"$BIN_DIR/bench_example" \
    --benchmark_format=json \
    --benchmark_out="$DATA_DIR/example_results.json" \
    --benchmark_min_time="$BENCH_MIN_TIME"

echo "  -> $DATA_DIR/example_results.json"

# ---------------------------------------------------------------------------
# Step 4: Run bench_handshake
# ---------------------------------------------------------------------------
echo ""
echo "[4/8] Running bench_handshake (42 benchmarks, ~3s each)..."

"$BIN_DIR/bench_handshake" \
    --benchmark_format=json \
    --benchmark_out="$DATA_DIR/handshake_results.json" \
    --benchmark_min_time="$BENCH_MIN_TIME"

echo "  -> $DATA_DIR/handshake_results.json"

# ---------------------------------------------------------------------------
# Step 5: Convert JSON to CSV
# ---------------------------------------------------------------------------
echo ""
echo "[5/8] Converting JSON to split CSVs..."

python3 "$SCRIPTS_DIR/json_to_csv.py" \
    --split "$DATA_DIR/handshake_results.json" "$DATA_DIR/"

echo "  -> handshake_classical.csv, handshake_pq.csv, handshake_hfs.csv, handshake_keygen.csv"

# ---------------------------------------------------------------------------
# Step 6: Run network benchmarks (client mode)
# ---------------------------------------------------------------------------
echo ""
echo "[6/8] Running network benchmarks (${#ALL_NET_MODES[@]} modes, $NET_ITERATIONS iterations each)..."

NET_PORT=$NET_PORT_BASE

for mode in "${ALL_NET_MODES[@]}"; do
    echo "  [$mode] port=$NET_PORT..."

    # Find available port
    while ! port_available "$NET_PORT"; do
        echo "    Port $NET_PORT in use, trying next..."
        (( NET_PORT++ ))
    done

    # Start server
    "$NET_BIN/bench_server" --mode "$mode" --port "$NET_PORT" --count "$NET_ITERATIONS" --quiet &
    SERVER_PID=$!
    sleep 1

    # Verify server started
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        echo "  [WARN] Server for mode=$mode failed to start, skipping..."
        SERVER_PID=""
        (( NET_PORT++ ))
        continue
    fi

    # Run client
    "$NET_BIN/bench_client" --mode "$mode" --port "$NET_PORT" \
        --iterations "$NET_ITERATIONS" \
        --output "$TMPDIR_BENCH/net_${mode}.csv" --quiet || true

    # Wait for server to exit
    wait_for_server "$SERVER_PID" 30
    SERVER_PID=""
    (( NET_PORT++ ))
done

# Concatenate per-mode CSVs into one file
echo "  Concatenating network results..."
FIRST=true
for mode in "${ALL_NET_MODES[@]}"; do
    CSV="$TMPDIR_BENCH/net_${mode}.csv"
    if [[ -f "$CSV" ]]; then
        if $FIRST; then
            cat "$CSV" > "$DATA_DIR/network_results.csv"
            FIRST=false
        else
            tail -n +2 "$CSV" >> "$DATA_DIR/network_results.csv"
        fi
    fi
done

if [[ -f "$DATA_DIR/network_results.csv" ]]; then
    ROWS=$(( $(wc -l < "$DATA_DIR/network_results.csv") - 1 ))
    echo "  -> $DATA_DIR/network_results.csv ($ROWS data rows)"
else
    echo "  [WARN] No network results captured"
fi

# ---------------------------------------------------------------------------
# Step 7: Run stress benchmarks
# ---------------------------------------------------------------------------
echo ""
echo "[7/8] Running stress benchmarks (modes: ${STRESS_MODES[*]}, clients: ${STRESS_CLIENTS[*]})..."

# Write CSV header (bench_stress appends data-only rows)
echo "mode,clients,iterations,duration_sec,success,errors,throughput,mean_us,p95_us,p99_us" \
    > "$DATA_DIR/stress_results.csv"

for mode in "${STRESS_MODES[@]}"; do
    for num_clients in "${STRESS_CLIENTS[@]}"; do
        TOTAL_CONNS=$(( num_clients * STRESS_ITER_PER_CLIENT ))
        echo "  [$mode] clients=$num_clients, iterations=$STRESS_ITER_PER_CLIENT..."

        # Find available port
        while ! port_available "$NET_PORT"; do
            (( NET_PORT++ ))
        done

        # Start server with enough capacity
        "$NET_BIN/bench_server" --mode "$mode" --port "$NET_PORT" \
            --count "$TOTAL_CONNS" --quiet &
        SERVER_PID=$!
        sleep 1

        if ! kill -0 "$SERVER_PID" 2>/dev/null; then
            echo "  [WARN] Server for stress mode=$mode failed to start, skipping..."
            SERVER_PID=""
            (( NET_PORT++ ))
            continue
        fi

        # Run stress test
        "$NET_BIN/bench_stress" --mode "$mode" --port "$NET_PORT" \
            --clients "$num_clients" --iterations "$STRESS_ITER_PER_CLIENT" \
            --output "$DATA_DIR/stress_results.csv" --quiet || true

        wait_for_server "$SERVER_PID" 60
        SERVER_PID=""
        (( NET_PORT++ ))
    done
done

STRESS_ROWS=$(( $(wc -l < "$DATA_DIR/stress_results.csv") - 1 ))
echo "  -> $DATA_DIR/stress_results.csv ($STRESS_ROWS data rows)"

# ---------------------------------------------------------------------------
# Step 8: Summary
# ---------------------------------------------------------------------------
echo ""
echo "[8/8] Benchmark run complete!"
echo ""
echo "============================================================"
echo "Files generated in $DATA_DIR:"
echo "============================================================"
ls -lh "$DATA_DIR/"
echo ""
echo "Next step: run the render script to generate figures and the MD report:"
echo "  python3 analysis/scripts/render_results.py"
