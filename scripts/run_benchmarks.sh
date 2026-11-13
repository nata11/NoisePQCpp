#!/usr/bin/env bash
# =============================================================================
# NoisePQC++ Benchmark Runner
# Configures and builds the benchmarks in the script's own build directory
# (debug logging off), runs them, and captures the results in a new output
# directory under out/. Run with --help for the options.
# Works with macOS bash 3.2.
# =============================================================================
set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SCRIPTS_DIR="$PROJECT_ROOT/analysis/scripts"

usage() {
    cat <<'USAGE'
Usage: scripts/run_benchmarks.sh [options]

Configures and builds the benchmark targets (Release, debug logging off), then
runs the local, network and stress benchmarks and writes the results to a new
output directory.

Options:
  --toolchain FILE   CMake toolchain file. Default by host:
                       macOS  cmake/clang21-macOS-toolchain.cmake
                       Linux  cmake/clang21-linux-toolchain.cmake if
                              /usr/bin/clang++-21 exists, otherwise
                              cmake/gcc15-linux-toolchain.cmake if g++-15 is
                              on PATH
  --build-dir DIR    Build directory. Default: out/bench-<toolchain file name
                     without .cmake>, e.g. out/bench-clang21-linux-toolchain.
                     The script configures it on every run. A directory that
                     was configured with another toolchain file is an error.
  --out-dir DIR      Output directory. Default:
                     out/bench-results/<UTC yyyymmddThhmmssZ>-<host name>.
                     analysis/data (the tracked data of the v0.9.0 paper) is
                     written only when it is passed here.
  --build-only       Configure, build, verify the binaries and write
                     <out-dir>/system_info.txt, then stop. No benchmark runs.
  -h, --help         Show this help.

A relative FILE or DIR is relative to the current directory. The defaults are
relative to the project root, and out/ is ignored by git.
USAGE
}

die() {
    echo "ERROR: $*" >&2
    exit 1
}

abs_path() {
    case "$1" in
        /*) echo "$1" ;;
        *)  echo "$PWD/$1" ;;
    esac
}

TOOLCHAIN=""
BUILD_DIR=""
DATA_DIR=""
BUILD_ONLY=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --toolchain|--build-dir|--out-dir)
            [[ $# -ge 2 && -n "$2" ]] || die "$1 needs a value (see --help)"
            case "$1" in
                --toolchain) TOOLCHAIN="$2" ;;
                --build-dir) BUILD_DIR="$2" ;;
                --out-dir)   DATA_DIR="$2" ;;
            esac
            shift 2
            ;;
        --toolchain=?*) TOOLCHAIN="${1#*=}"; shift ;;
        --build-dir=?*) BUILD_DIR="${1#*=}"; shift ;;
        --out-dir=?*)   DATA_DIR="${1#*=}"; shift ;;
        --build-only)   BUILD_ONLY=1; shift ;;
        -h|--help)      usage; exit 0 ;;
        *)
            echo "ERROR: unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

# Toolchain file: the one given, or the host's default.
if [[ -z "$TOOLCHAIN" ]]; then
    case "$(uname -s)" in
        Darwin)
            TOOLCHAIN="$PROJECT_ROOT/cmake/clang21-macOS-toolchain.cmake"
            ;;
        Linux)
            if [[ -e /usr/bin/clang++-21 ]]; then
                TOOLCHAIN="$PROJECT_ROOT/cmake/clang21-linux-toolchain.cmake"
            elif command -v g++-15 >/dev/null 2>&1; then
                TOOLCHAIN="$PROJECT_ROOT/cmake/gcc15-linux-toolchain.cmake"
            else
                die "no default toolchain: neither /usr/bin/clang++-21 nor g++-15 was found. Pass --toolchain FILE."
            fi
            ;;
        *)
            die "no default toolchain for $(uname -s). Pass --toolchain FILE."
            ;;
    esac
fi
[[ -f "$TOOLCHAIN" ]] || die "toolchain file not found: $TOOLCHAIN"
TOOLCHAIN="$(cd "$(dirname "$TOOLCHAIN")" && pwd)/$(basename "$TOOLCHAIN")"
TOOLCHAIN_STEM="$(basename "$TOOLCHAIN" .cmake)"

# Build directory: the script's own, never an IDE's.
if [[ -z "$BUILD_DIR" ]]; then
    BUILD_DIR="$PROJECT_ROOT/out/bench-$TOOLCHAIN_STEM"
else
    BUILD_DIR="$(abs_path "$BUILD_DIR")"
fi
BIN_DIR="$BUILD_DIR/bin/Release/benchmarks"
NET_BIN="$BIN_DIR/network"
CACHE_FILE="$BUILD_DIR/CMakeCache.txt"

# Output directory: a new one per run, unless one is given.
if [[ -z "$DATA_DIR" ]]; then
    DATA_DIR="$PROJECT_ROOT/out/bench-results/$(date -u '+%Y%m%dT%H%M%SZ')-$(hostname -s)"
else
    DATA_DIR="$(abs_path "$DATA_DIR")"
fi

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
        elapsed=$((elapsed + 1))
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
    if command -v lsof >/dev/null 2>&1; then
        ! lsof -i :"$1" >/dev/null 2>&1
    else
        ! ss -ltn 2>/dev/null | awk '{ print $4 }' | grep -q ":$1\$"
    fi
}

# ---------------------------------------------------------------------------
# Helper: read one value from the build directory's CMake cache
# ---------------------------------------------------------------------------
cache_value() {
    awk -v key="$1" 'index($0, key ":") == 1 { sub(/^[^=]*=/, ""); print; exit }' "$CACHE_FILE"
}

# ---------------------------------------------------------------------------
echo "============================================================"
echo "NoisePQC++ Benchmark Runner"
echo "============================================================"
echo "Project root: $PROJECT_ROOT"
echo "Toolchain:    $TOOLCHAIN"
echo "Build dir:    $BUILD_DIR"
echo "Data output:  $DATA_DIR"
echo ""

# CMake keeps the toolchain an existing cache was created with and ignores a
# different one, so a mismatch has to stop here.
if [[ -f "$CACHE_FILE" ]]; then
    CACHED_TOOLCHAIN="$(cache_value CMAKE_TOOLCHAIN_FILE)"
    if [[ "$CACHED_TOOLCHAIN" != "$TOOLCHAIN" ]]; then
        echo "ERROR: toolchain mismatch for build dir $BUILD_DIR" >&2
        echo "  configured with: ${CACHED_TOOLCHAIN:-(no toolchain file)}" >&2
        echo "  requested:       $TOOLCHAIN" >&2
        echo "  CMake ignores a changed toolchain file in an existing build dir." >&2
        echo "  Pass another --build-dir, or remove this one." >&2
        exit 1
    fi
fi

mkdir -p "$DATA_DIR"
DATA_DIR="$(cd "$DATA_DIR" && pwd -P)"

if [[ "$DATA_DIR" == "$(cd "$PROJECT_ROOT/analysis/data" 2>/dev/null && pwd -P)" ]]; then
    echo "WARNING: --out-dir is analysis/data: this run overwrites the tracked data of the v0.9.0 paper."
    echo ""
fi

# ---------------------------------------------------------------------------
# Step 1: Configure and build the benchmark targets
# ---------------------------------------------------------------------------
echo "[1/8] Configuring and building benchmark targets (Release)..."

echo "  Configuring CMake..."
cmake -G "Ninja Multi-Config" -S "$PROJECT_ROOT" -B "$BUILD_DIR" \
    -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN" \
    -DNOISE_DEBUG_BUILD=OFF \
    -DNOISEPQC_BUILD_BENCHMARKS=ON

DEBUG_BUILD="$(cache_value NOISE_DEBUG_BUILD)"
if [[ "$DEBUG_BUILD" != "OFF" ]]; then
    die "NOISE_DEBUG_BUILD is '$DEBUG_BUILD' in $CACHE_FILE (expected OFF)"
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

# Number of bench_handshake registrations (listing them runs no benchmark)
HANDSHAKE_COUNT="$("$BIN_DIR/bench_handshake" --benchmark_list_tests | wc -l | tr -d ' ')"

# ---------------------------------------------------------------------------
# Step 2: Capture system info and build details
# ---------------------------------------------------------------------------
echo ""
echo "[2/8] Capturing system information..."

# The toolchain files set the compiler as a plain variable, so it is not in
# CMakeCache.txt. CMake records the compiler it configured in the build dir.
CXX_COMPILER="$(cache_value CMAKE_CXX_COMPILER)"
if [[ -z "$CXX_COMPILER" ]]; then
    for f in "$BUILD_DIR"/CMakeFiles/*/CMakeCXXCompiler.cmake; do
        [[ -f "$f" ]] || continue
        CXX_COMPILER="$(sed -n 's/^set(CMAKE_CXX_COMPILER "\(.*\)")$/\1/p' "$f")"
    done
fi

if GIT_COMMIT="$(git -C "$PROJECT_ROOT" rev-parse HEAD 2>/dev/null)"; then
    if [[ -z "$(git -C "$PROJECT_ROOT" status --porcelain)" ]]; then
        GIT_CLEAN="yes"
    else
        GIT_CLEAN="no"
    fi
else
    GIT_COMMIT="unknown (not a git checkout)"
    GIT_CLEAN="unknown"
fi

{
    echo "=== NoisePQC++ Benchmark System Info ==="
    echo "Date: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    echo ""
    echo "--- Source ---"
    echo "Commit: $GIT_COMMIT"
    echo "Working tree clean: $GIT_CLEAN"
    echo ""
    echo "--- OS ---"
    uname -a
    if [[ "$(uname -s)" == "Darwin" ]]; then
        sw_vers
        echo ""
        echo "--- CPU ---"
        echo "Model: $(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo 'N/A')"
        echo "Cores: $(sysctl -n hw.ncpu 2>/dev/null || echo 'N/A')"
        cpu_freq="$(sysctl -n hw.cpufrequency_max 2>/dev/null || true)"
        echo "Frequency: ${cpu_freq:-N/A} Hz"
        echo ""
        echo "--- Memory ---"
        mem_bytes=$(sysctl -n hw.memsize 2>/dev/null || echo 0)
        echo "Total: $(( mem_bytes / 1073741824 )) GB"
    else
        echo ""
        echo "--- CPU ---"
        lscpu 2>/dev/null || echo "(lscpu unavailable)"
        echo "Cores: $(nproc 2>/dev/null || echo 'N/A')"
        echo ""
        echo "--- Memory ---"
        grep MemTotal /proc/meminfo 2>/dev/null || echo "(MemTotal unavailable)"
    fi
    echo ""
    echo "--- Compiler ---"
    echo "C++ Compiler: ${CXX_COMPILER:-unknown}"
    if [[ -n "$CXX_COMPILER" ]]; then
        "$CXX_COMPILER" --version 2>/dev/null || echo "(version unavailable)"
    fi
    echo ""
    echo "--- CMake ---"
    cmake --version | head -1
    echo ""
    echo "--- Build Configuration ---"
    echo "Build dir: $BUILD_DIR"
    echo "Generator: $(cache_value CMAKE_GENERATOR)"
    echo "Config: Release"
    echo "CMAKE_TOOLCHAIN_FILE=$(cache_value CMAKE_TOOLCHAIN_FILE)"
    echo "NOISE_DEBUG_BUILD=$DEBUG_BUILD"
    echo "NOISE_BOTAN_ARCH_FLAGS=$(cache_value NOISE_BOTAN_ARCH_FLAGS)"
    echo "bench_handshake registrations: $HANDSHAKE_COUNT"
    echo "Benchmark min time: $BENCH_MIN_TIME"
} > "$DATA_DIR/system_info.txt" 2>&1

echo "  -> $DATA_DIR/system_info.txt"

if [[ "$BUILD_ONLY" -eq 1 ]]; then
    echo ""
    echo "Build only: the five benchmark binaries are in $BIN_DIR"
    echo "(bench_handshake has $HANDSHAKE_COUNT registrations). No benchmark was run."
    exit 0
fi

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
echo "[4/8] Running bench_handshake ($HANDSHAKE_COUNT benchmarks, ~$BENCH_MIN_TIME each)..."

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
echo "  python3 analysis/scripts/render_results.py --data-dir $DATA_DIR"
