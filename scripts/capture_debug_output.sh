#!/usr/bin/env bash
#
# capture_debug_output.sh — Capture color-coded debug output from pattern_zoo
# and produce white-background HTML, Markdown, and/or PNG files.
#
# Usage: ./scripts/capture_debug_output.sh [--html] [--md] [--png] <PATTERN>
# Set PATTERN_ZOO to run another Debug pattern_zoo (built with NOISE_DEBUG_BUILD=ON).
#
# Examples:
#   ./scripts/capture_debug_output.sh XXhfs           # default: HTML + Markdown
#   ./scripts/capture_debug_output.sh --html pqXX     # HTML only
#   ./scripts/capture_debug_output.sh --md XX          # Markdown only
#   ./scripts/capture_debug_output.sh --png XXhfs      # PNG only (requires Chrome)
#   ./scripts/capture_debug_output.sh --html --png XX  # HTML + PNG
#

set -euo pipefail

# --- Resolve project root relative to this script's location ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

PATTERN_ZOO="${PATTERN_ZOO:-${PROJECT_ROOT}/cmake-build-debug-clang-21/bin/Debug/examples/pattern_zoo}"
CHROME="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"

# --- Valid patterns (must match the six lists in pattern_zoo.cpp) ---
VALID_PATTERNS=(
    # Category keywords
    ONEWAY BASIC DEFER PSK PQC HFS
    # One-Way (3)
    N K X
    # Fundamental Interactive (12)
    NN NK NX KN KK KX XN XK XX IN IK IX
    # Deferred (23)
    NK1 NX1 X1N X1K XK1 X1K1 X1X XX1 X1X1
    K1N K1K KK1 K1K1 K1X KX1 K1X1
    I1N I1K IK1 I1K1 I1X IX1 I1X1
    # PSK (21)
    Npsk0 Kpsk0 Xpsk1
    NNpsk0 NNpsk2 NKpsk0 NKpsk2 NXpsk2
    XNpsk3 XKpsk3 XXpsk3
    KNpsk0 KNpsk2 KKpsk0 KKpsk2 KXpsk2
    INpsk1 INpsk2 IKpsk1 IKpsk2 IXpsk2
    # Post-Quantum (13)
    pqN pqNN pqNK pqNX pqXN pqXK pqXX
    pqKN pqKK pqKX pqIN pqIK pqIX
    # HFS (12)
    NNhfs NKhfs NXhfs KNhfs KKhfs KXhfs
    XNhfs XKhfs XXhfs INhfs IKhfs IXhfs
)

# --- Functions ---

usage() {
    echo "Usage: $(basename "$0") [--html] [--md] [--png] <PATTERN>"
    echo ""
    echo "Captures color-coded debug output from pattern_zoo and converts"
    echo "to white-background HTML, Markdown, and/or PNG files."
    echo ""
    echo "Options (can be combined):"
    echo "  --html    Output HTML"
    echo "  --md      Output Markdown (inline HTML spans for color)"
    echo "  --png     Output PNG screenshot (requires Google Chrome)"
    echo "  (default) Output both HTML and Markdown"
    echo "  Set PATTERN_ZOO=<path> to run another Debug pattern_zoo (default: cmake-build-debug-clang-21/bin/Debug/examples/pattern_zoo)"
    echo ""
    echo "Categories:  ONEWAY  BASIC  DEFER  PSK  PQC  HFS"
    echo ""
    echo "Patterns:    N K X NN NK NX ... XXhfs pqXX etc."
    echo "             (84 patterns total; run pattern_zoo without arguments for the list)"
    echo ""
    echo "Output:  output/debug-logs/debug_<pattern>.html"
    echo "         output/debug-logs/debug_<pattern>.md"
    echo "         output/debug-logs/debug_<pattern>.png"
    exit 1
}

validate_pattern() {
    local pattern="$1"
    for valid in "${VALID_PATTERNS[@]}"; do
        if [[ "${valid}" == "${pattern}" ]]; then
            return 0
        fi
    done
    return 1
}

# --- Argument parsing ---

OUTPUT_HTML=false
OUTPUT_MD=false
OUTPUT_PNG=false
HAS_FORMAT_FLAG=false
PATTERN=""

for arg in "$@"; do
    case "${arg}" in
        --html)
            OUTPUT_HTML=true
            HAS_FORMAT_FLAG=true
            ;;
        --md)
            OUTPUT_MD=true
            HAS_FORMAT_FLAG=true
            ;;
        --png)
            OUTPUT_PNG=true
            HAS_FORMAT_FLAG=true
            ;;
        --help|-h)
            usage
            ;;
        -*)
            echo "Error: Unknown option '${arg}'"
            echo ""
            usage
            ;;
        *)
            if [[ -n "${PATTERN}" ]]; then
                echo "Error: Multiple patterns specified ('${PATTERN}' and '${arg}')"
                echo ""
                usage
            fi
            PATTERN="${arg}"
            ;;
    esac
done

# Default: HTML + Markdown when no format flags are given
if [[ "${HAS_FORMAT_FLAG}" == false ]]; then
    OUTPUT_HTML=true
    OUTPUT_MD=true
fi

if [[ -z "${PATTERN}" ]]; then
    usage
fi

# --- Validate pattern ---

if ! validate_pattern "${PATTERN}"; then
    echo "Error: '${PATTERN}' is not a valid pattern or category."
    echo ""
    usage
fi

# --- Check prerequisites ---

if ! command -v aha &>/dev/null; then
    echo "Error: 'aha' is not installed. Install with: brew install aha"
    exit 1
fi

if [[ ! -x "${PATTERN_ZOO}" ]]; then
    echo "Error: Debug pattern_zoo binary not found at:"
    echo "  ${PATTERN_ZOO}"
    echo ""
    echo "Build it with:"
    echo "  cmake --build cmake-build-debug-clang-21 --target pattern_zoo"
    echo "Or set PATTERN_ZOO to a Debug pattern_zoo built with NOISE_DEBUG_BUILD=ON."
    exit 1
fi

if [[ "${OUTPUT_PNG}" == true ]] && [[ ! -x "${CHROME}" ]]; then
    echo "Error: Google Chrome not found at:"
    echo "  ${CHROME}"
    echo ""
    echo "PNG output requires Google Chrome for headless screenshot rendering."
    exit 1
fi

# --- Output directory and filenames ---

PATTERN_LOWER="$(echo "${PATTERN}" | tr '[:upper:]' '[:lower:]')"

OUTPUT_DIR="${PROJECT_ROOT}/output/debug-logs"
mkdir -p "${OUTPUT_DIR}"

HTML_FILE="${OUTPUT_DIR}/debug_${PATTERN_LOWER}.html"
MD_FILE="${OUTPUT_DIR}/debug_${PATTERN_LOWER}.md"
PNG_FILE="${OUTPUT_DIR}/debug_${PATTERN_LOWER}.png"

# --- Style used for both HTML and Markdown ---

BODY_STYLE="background-color:#ffffff; color:#1a1a1a; font-family:'Menlo','Consolas','DejaVu Sans Mono',monospace; font-size:9pt; line-height:1.4; padding:12px;"

# --- Run pattern_zoo, remap colors, and convert to HTML ---
# HTML is always generated (needed as input for Markdown and PNG)

echo "Running pattern_zoo ${PATTERN}..."
"${PATTERN_ZOO}" "${PATTERN}" 2>&1 | \
    sed \
        -e 's/\x1b\[96m/\x1b[38;5;30m/g' \
        -e 's/\x1b\[95m/\x1b[38;5;90m/g' \
        -e 's/\x1b\[92m/\x1b[38;5;28m/g' \
        -e 's/\x1b\[93m/\x1b[38;5;130m/g' \
        -e 's/\x1b\[97m/\x1b[38;5;240m/g' \
        -e 's/\x1b\[37m/\x1b[38;5;100m/g' \
        -e 's/\x1b\[36m/\x1b[38;5;31m/g' \
        -e 's/\x1b\[94m/\x1b[38;5;25m/g' \
        -e 's/\x1b\[38;5;81m/\x1b[38;5;37m/g' \
        -e 's/\x1b\[91m/\x1b[38;5;160m/g' \
        -e 's/\x1b\[32m/\x1b[38;5;22m/g' \
        -e 's/\x1b\[33m/\x1b[38;5;94m/g' \
        -e 's/\x1b\[34m/\x1b[38;5;25m/g' \
        -e 's/\x1b\[35m/\x1b[38;5;91m/g' \
    | aha \
        --style "${BODY_STYLE}" \
        --title "NoisePQC++ ${PATTERN} Debug Log" \
        --word-wrap \
    > "${HTML_FILE}"

# --- Generate Markdown from the HTML ---

if [[ "${OUTPUT_MD}" == true ]]; then
    {
        echo "# NoisePQC++ ${PATTERN} Debug Log"
        echo ""
        echo "<pre style=\"${BODY_STYLE}\">"
        sed -n '/<pre>/,/<\/pre>/p' "${HTML_FILE}" | sed '1d;$d'
        echo "</pre>"
    } > "${MD_FILE}"
fi

# --- Generate PNG via Chrome headless ---

if [[ "${OUTPUT_PNG}" == true ]]; then
    echo "Rendering PNG via Chrome headless..."
    "${CHROME}" \
        --headless \
        --screenshot="${PNG_FILE}" \
        --window-size=1200,16000 \
        --disable-gpu \
        "file://${HTML_FILE}" 2>/dev/null

    if command -v magick &>/dev/null; then
        echo "Trimming whitespace with ImageMagick..."
        magick "${PNG_FILE}" -trim +repage "${PNG_FILE}"
    else
        echo "Warning: ImageMagick not found. PNG has untrimmed whitespace at the bottom."
        echo "  Install with: brew install imagemagick"
    fi
fi

# --- Clean up HTML if not requested ---

if [[ "${OUTPUT_HTML}" == false ]]; then
    rm -f "${HTML_FILE}"
fi

# --- Report ---

echo ""
echo "Done. Output:"
if [[ "${OUTPUT_HTML}" == true ]]; then
    echo "  ${HTML_FILE}"
fi
if [[ "${OUTPUT_MD}" == true ]]; then
    echo "  ${MD_FILE}"
fi
if [[ "${OUTPUT_PNG}" == true ]]; then
    echo "  ${PNG_FILE}"
fi
