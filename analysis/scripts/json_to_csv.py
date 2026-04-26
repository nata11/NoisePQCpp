#!/usr/bin/env python3
"""
Convert Google Benchmark JSON output to CSV format for analysis.

Usage:
    python json_to_csv.py input.json output.csv
    python json_to_csv.py --split input.json output_dir/

The --split option creates separate CSV files for each benchmark category
(classical, pq, hfs, keygen).
"""

import json
import argparse
import sys
from pathlib import Path
import csv


# Standard Google Benchmark JSON keys (not custom counters)
STANDARD_KEYS = {
    "name", "family_index", "per_family_instance_index", "run_name",
    "run_type", "repetitions", "repetition_index", "threads",
    "iterations", "real_time", "cpu_time", "time_unit",
    "bytes_per_second", "items_per_second",
}


def parse_benchmark_name(name: str) -> dict:
    """Parse benchmark name to extract components.

    Examples:
        "Classical/NN/X25519/0/0" -> {mode: "Classical", pattern: "NN", algo: "X25519"}
        "PQ/pqNN/M768/1/0" -> {mode: "PQ", pattern: "pqNN", algo: "M768"}
        "HFS/NNhfs/X25519+M768/0/1/0" -> {mode: "HFS", pattern: "NNhfs", algo: "X25519+M768"}
        "KeyGen/X25519" -> {mode: "KeyGen", pattern: "X25519", algo: "X25519"}
    """
    parts = name.split("/")
    result = {"mode": parts[0], "pattern": "", "algo": ""}

    if parts[0] == "KeyGen":
        result["pattern"] = parts[1] if len(parts) > 1 else ""
        result["algo"] = parts[1] if len(parts) > 1 else ""
    elif len(parts) >= 3:
        result["pattern"] = parts[1]
        result["algo"] = parts[2]

    return result


def convert_json_to_csv(json_path: Path, csv_path: Path):
    """Convert a single JSON file to CSV."""
    with open(json_path, "r") as f:
        data = json.load(f)

    benchmarks = data.get("benchmarks", [])
    if not benchmarks:
        print(f"No benchmarks found in {json_path}")
        return

    # Get all counter keys from first benchmark for header
    # Counters may be under a "counters" sub-object or at the top level
    first_bm = benchmarks[0]
    if "counters" in first_bm:
        counter_keys = sorted(first_bm["counters"].keys())
    else:
        # Detect top-level custom counters (Google Benchmark v1.9+)
        counter_keys = sorted(k for k in first_bm.keys() if k not in STANDARD_KEYS)

    # Write CSV
    with open(csv_path, "w", newline="") as f:
        fieldnames = [
            "name", "mode", "pattern", "algo",
            "real_time_us", "cpu_time_us", "iterations",
            "bytes_per_second"
        ] + counter_keys

        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for bm in benchmarks:
            parsed = parse_benchmark_name(bm["name"])

            # Convert time to microseconds
            time_unit = bm.get("time_unit", "ns")
            time_factor = 1.0 if time_unit == "us" else 0.001  # ns to us

            row = {
                "name": bm["name"],
                "mode": parsed["mode"],
                "pattern": parsed["pattern"],
                "algo": parsed["algo"],
                "real_time_us": bm.get("real_time", 0) * time_factor,
                "cpu_time_us": bm.get("cpu_time", 0) * time_factor,
                "iterations": bm.get("iterations", 0),
                "bytes_per_second": bm.get("bytes_per_second", 0),
            }

            # Add counters (from sub-object or top-level)
            counters = bm.get("counters", bm)
            for key in counter_keys:
                row[key] = counters.get(key, 0)

            writer.writerow(row)

    print(f"Converted {len(benchmarks)} benchmarks to {csv_path}")


def split_and_convert(json_path: Path, output_dir: Path):
    """Split JSON into separate CSVs by mode (classical, pq, hfs, keygen)."""
    with open(json_path, "r") as f:
        data = json.load(f)

    benchmarks = data.get("benchmarks", [])
    if not benchmarks:
        print(f"No benchmarks found in {json_path}")
        return

    # Group by mode
    groups = {"classical": [], "pq": [], "hfs": [], "keygen": []}

    for bm in benchmarks:
        parsed = parse_benchmark_name(bm["name"])
        mode = parsed["mode"].lower()

        if mode == "classical":
            groups["classical"].append(bm)
        elif mode == "pq":
            groups["pq"].append(bm)
        elif mode == "hfs":
            groups["hfs"].append(bm)
        elif mode == "keygen":
            groups["keygen"].append(bm)

    # Write each group to separate CSV
    output_dir.mkdir(parents=True, exist_ok=True)

    for group_name, bms in groups.items():
        if not bms:
            continue

        csv_path = output_dir / f"handshake_{group_name}.csv"

        # Get counter keys (from sub-object or top-level)
        counter_keys = []
        if bms and "counters" in bms[0]:
            counter_keys = sorted(bms[0]["counters"].keys())
        elif bms:
            counter_keys = sorted(k for k in bms[0].keys() if k not in STANDARD_KEYS)

        with open(csv_path, "w", newline="") as f:
            fieldnames = [
                "name", "mode", "pattern", "algo",
                "real_time_us", "cpu_time_us", "iterations",
                "bytes_per_second"
            ] + counter_keys

            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            for bm in bms:
                parsed = parse_benchmark_name(bm["name"])

                time_unit = bm.get("time_unit", "ns")
                time_factor = 1.0 if time_unit == "us" else 0.001

                row = {
                    "name": bm["name"],
                    "mode": parsed["mode"],
                    "pattern": parsed["pattern"],
                    "algo": parsed["algo"],
                    "real_time_us": bm.get("real_time", 0) * time_factor,
                    "cpu_time_us": bm.get("cpu_time", 0) * time_factor,
                    "iterations": bm.get("iterations", 0),
                    "bytes_per_second": bm.get("bytes_per_second", 0),
                }

                counters = bm.get("counters", bm)
                for key in counter_keys:
                    row[key] = counters.get(key, 0)

                writer.writerow(row)

        print(f"Wrote {len(bms)} benchmarks to {csv_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Convert Google Benchmark JSON to CSV"
    )
    parser.add_argument("input", type=Path, help="Input JSON file")
    parser.add_argument("output", type=Path, help="Output CSV file or directory (with --split)")
    parser.add_argument("--split", action="store_true",
                        help="Split output into separate files by category")

    args = parser.parse_args()

    if not args.input.exists():
        print(f"Error: Input file not found: {args.input}")
        sys.exit(1)

    if args.split:
        split_and_convert(args.input, args.output)
    else:
        convert_json_to_csv(args.input, args.output)


if __name__ == "__main__":
    main()
