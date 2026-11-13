#!/usr/bin/env python3
"""
NoisePQC++ Benchmark Results Renderer

Reads benchmark CSVs from a data directory (default analysis/data/, the data of
the v0.9.0 paper), generates publication-quality figures, and produces a Markdown
document with tables, figures, and an academic summary suitable for a research
paper subsection.

Paths resolve from the repository root, not the current directory. By default the
figures go to out/render/<data-dir name>/figures/ and the Markdown to
out/render/<data-dir name>/BENCHMARK_RESULTS.md (out/ is ignored by git). The
tracked analysis/figures/ is written only when it is passed as --figures-dir.

Usage:
    python3 analysis/scripts/render_results.py
    python3 analysis/scripts/render_results.py --data-dir out/bench-results/<run>
    python3 analysis/scripts/render_results.py --figures-dir analysis/figures
"""

import matplotlib
matplotlib.use('Agg')  # Headless rendering

import argparse
import shutil
import textwrap
from datetime import datetime
from pathlib import Path
from typing import Optional

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

# =============================================================================
# Publication-quality settings
# =============================================================================
plt.rcParams.update({
    'font.size': 12,
    'figure.dpi': 100,
    'savefig.dpi': 300,
    'figure.figsize': (10, 6),
    'axes.labelsize': 12,
    'axes.titlesize': 14,
    'legend.fontsize': 10,
    'xtick.labelsize': 10,
    'ytick.labelsize': 10,
    'axes.grid': True,
    'grid.alpha': 0.3,
})

# Colorblind-friendly Wong palette
COLORS = {
    'Classical': '#0072B2',
    'PQ': '#D55E00',
    'HFS': '#009E73',
    'X25519': '#56B4E9',
    'X448': '#E69F00',
    'M512': '#CC79A7',
    'M768': '#F0E442',
    'M1024': '#999999',
}

# Known key sizes (from specifications)
KEY_SIZES = {
    'X25519': {'public_key': 32, 'shared_secret': 32, 'ciphertext': 32},
    'X448': {'public_key': 56, 'shared_secret': 56, 'ciphertext': 56},
    'ML-KEM-512': {'public_key': 800, 'shared_secret': 32, 'ciphertext': 768},
    'ML-KEM-768': {'public_key': 1184, 'shared_secret': 32, 'ciphertext': 1088},
    'ML-KEM-1024': {'public_key': 1568, 'shared_secret': 32, 'ciphertext': 1568},
}


# =============================================================================
# Data loading
# =============================================================================
def load_csv(path: Path) -> Optional[pd.DataFrame]:
    """Load CSV if it exists, return None otherwise."""
    if path.exists() and path.stat().st_size > 0:
        df = pd.read_csv(path)
        if len(df) > 0:
            return df
    return None


def load_all_data(data_dir: Path) -> dict:
    """Load all benchmark data files."""
    data = {
        'classical': load_csv(data_dir / 'handshake_classical.csv'),
        'pq': load_csv(data_dir / 'handshake_pq.csv'),
        'hfs': load_csv(data_dir / 'handshake_hfs.csv'),
        'keygen': load_csv(data_dir / 'handshake_keygen.csv'),
        'network': load_csv(data_dir / 'network_results.csv'),
        'stress': load_csv(data_dir / 'stress_results.csv'),
        'system_info': '',
    }

    sysinfo_path = data_dir / 'system_info.txt'
    if sysinfo_path.exists():
        data['system_info'] = sysinfo_path.read_text()

    loaded = [k for k, v in data.items()
              if (isinstance(v, pd.DataFrame) and not v.empty) or
                 (isinstance(v, str) and v != '') or
                 (v is not None and not isinstance(v, (pd.DataFrame, str)))]
    print(f"Loaded data: {', '.join(loaded)}")
    return data


# =============================================================================
# Figure generators — each returns a Markdown snippet
# =============================================================================
def plot_latency_comparison(data: dict, figures_dir: Path) -> str:
    """Grouped bar chart: Classical vs PQ vs HFS latency."""
    df_c, df_pq, df_hfs = data['classical'], data['pq'], data['hfs']
    if df_c is None and df_pq is None and df_hfs is None:
        return "_No handshake latency data available._\n"

    fig, ax = plt.subplots(figsize=(14, 7))
    base_patterns = ['NN', 'XX', 'IK', 'KK']
    plot_data = []

    if df_c is not None:
        for p in base_patterns:
            mask = (df_c['pattern'] == p) & (df_c['algo'] == 'X25519')
            if mask.any():
                plot_data.append({'Pattern': p, 'Mode': 'Classical (X25519)',
                                  'Latency': df_c.loc[mask, 'real_time_us'].mean()})

    if df_pq is not None:
        for p in base_patterns:
            mask = (df_pq['pattern'] == f'pq{p}') & (df_pq['algo'] == 'M768')
            if mask.any():
                plot_data.append({'Pattern': p, 'Mode': 'PQ (ML-KEM-768)',
                                  'Latency': df_pq.loc[mask, 'real_time_us'].mean()})

    if df_hfs is not None:
        for p in base_patterns:
            mask = df_hfs['pattern'] == f'{p}hfs'
            if 'algo' in df_hfs.columns:
                mask = mask & df_hfs['algo'].str.contains('X25519.*M768', na=False)
            if mask.any():
                plot_data.append({'Pattern': p, 'Mode': 'HFS (X25519+ML-KEM-768)',
                                  'Latency': df_hfs.loc[mask, 'real_time_us'].mean()})

    if not plot_data:
        return "_No matching handshake data for latency comparison._\n"

    df_plot = pd.DataFrame(plot_data)
    patterns = list(dict.fromkeys(df_plot['Pattern']))
    modes = list(dict.fromkeys(df_plot['Mode']))
    x = np.arange(len(patterns))
    width = 0.25

    for i, mode in enumerate(modes):
        mode_data = df_plot[df_plot['Mode'] == mode]
        latencies = []
        for p in patterns:
            vals = mode_data[mode_data['Pattern'] == p]['Latency'].values
            latencies.append(vals[0] if len(vals) > 0 else 0)

        color = COLORS['Classical'] if 'Classical' in mode else \
                COLORS['PQ'] if 'PQ' in mode else COLORS['HFS']
        bars = ax.bar(x + i * width, latencies, width, label=mode, color=color)
        for bar, val in zip(bars, latencies):
            if val > 0:
                ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height(),
                        f'{val:.0f}', ha='center', va='bottom', fontsize=8)

    ax.set_xlabel('Handshake Pattern')
    ax.set_ylabel('Latency (microseconds)')
    ax.set_title('Handshake Latency: Classical vs Post-Quantum vs Hybrid')
    ax.set_xticks(x + width)
    ax.set_xticklabels(patterns)
    ax.legend()
    plt.tight_layout()
    _save_fig(fig, figures_dir, 'fig_latency_comparison')

    # Build markdown table
    md = "![Handshake Latency Comparison](figures/fig_latency_comparison.png)\n\n"
    md += _build_latency_table(df_c, df_pq, df_hfs, base_patterns)
    return md


def _build_latency_table(df_c, df_pq, df_hfs, patterns) -> str:
    """Build a Markdown table of latency values with overhead ratios."""
    header = "| Pattern | Classical (us) | PQ (us) | HFS (us) | PQ Overhead | HFS Overhead |\n"
    header += "|---------|---------------|---------|----------|-------------|--------------|\n"
    rows = []

    for p in patterns:
        c_val = _get_latency(df_c, p, 'X25519')
        pq_val = _get_latency(df_pq, f'pq{p}', 'M768')
        hfs_val = _get_hfs_latency(df_hfs, f'{p}hfs')

        c_str = f'{c_val:.1f}' if c_val else 'N/A'
        pq_str = f'{pq_val:.1f}' if pq_val else 'N/A'
        hfs_str = f'{hfs_val:.1f}' if hfs_val else 'N/A'
        pq_oh = f'{pq_val / c_val:.2f}x' if c_val and pq_val else 'N/A'
        hfs_oh = f'{hfs_val / c_val:.2f}x' if c_val and hfs_val else 'N/A'

        rows.append(f"| {p} | {c_str} | {pq_str} | {hfs_str} | {pq_oh} | {hfs_oh} |")

    latex = _build_latency_latex(df_c, df_pq, df_hfs, patterns)
    return header + '\n'.join(rows) + '\n\n' + latex + '\n'


def _build_latency_latex(df_c, df_pq, df_hfs, patterns) -> str:
    """Build a LaTeX table embedded in an HTML comment."""
    lines = [
        "<!-- LATEX:",
        "\\begin{table}[ht]",
        "\\centering",
        "\\caption{Handshake latency comparison across Classical, Post-Quantum, and Hybrid Forward Secrecy modes.}",
        "\\label{tab:latency}",
        "\\begin{tabular}{lrrrrr}",
        "\\toprule",
        "Pattern & Classical ($\\mu$s) & PQ ($\\mu$s) & HFS ($\\mu$s) & PQ Overhead & HFS Overhead \\\\",
        "\\midrule",
    ]
    for p in patterns:
        c_val = _get_latency(df_c, p, 'X25519')
        pq_val = _get_latency(df_pq, f'pq{p}', 'M768')
        hfs_val = _get_hfs_latency(df_hfs, f'{p}hfs')
        c_s = f'{c_val:.1f}' if c_val else '--'
        pq_s = f'{pq_val:.1f}' if pq_val else '--'
        hfs_s = f'{hfs_val:.1f}' if hfs_val else '--'
        pq_oh = f'{pq_val / c_val:.2f}x' if c_val and pq_val else '--'
        hfs_oh = f'{hfs_val / c_val:.2f}x' if c_val and hfs_val else '--'
        lines.append(f"{p} & {c_s} & {pq_s} & {hfs_s} & {pq_oh} & {hfs_oh} \\\\")
    lines += ["\\bottomrule", "\\end{tabular}", "\\end{table}", "-->"]
    return '\n'.join(lines)


def plot_cpu_time(data: dict, figures_dir: Path) -> str:
    """CPU time breakdown by mode."""
    df_c, df_pq, df_hfs = data['classical'], data['pq'], data['hfs']
    if df_c is None and df_pq is None and df_hfs is None:
        return "_No CPU time data available._\n"

    fig, axes = plt.subplots(1, 3, figsize=(15, 5))
    datasets = [
        (df_c, 'Classical', COLORS['Classical']),
        (df_pq, 'Post-Quantum', COLORS['PQ']),
        (df_hfs, 'Hybrid (HFS)', COLORS['HFS']),
    ]

    for ax, (df, title, color) in zip(axes, datasets):
        if df is None:
            ax.text(0.5, 0.5, 'No data', ha='center', va='center', transform=ax.transAxes)
            ax.set_title(title)
            continue
        patterns = df['pattern'].unique()
        cpu_times = [df[df['pattern'] == p]['cpu_time_us'].mean() for p in patterns]
        bars = ax.bar(patterns, cpu_times, color=color)
        ax.set_xlabel('Pattern')
        ax.set_ylabel('CPU Time (us)')
        ax.set_title(f'{title} Handshakes')
        ax.tick_params(axis='x', rotation=45)
        for bar, val in zip(bars, cpu_times):
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height(),
                    f'{val:.0f}', ha='center', va='bottom', fontsize=8)

    plt.tight_layout()
    _save_fig(fig, figures_dir, 'fig_cpu_time')
    return "![CPU Time Analysis](figures/fig_cpu_time.png)\n"


def plot_keygen(data: dict, figures_dir: Path) -> str:
    """Key generation performance table and chart."""
    df_kg = data['keygen']
    if df_kg is None:
        return "_No key generation data available._\n"

    fig, ax = plt.subplots(figsize=(10, 5))
    algos = df_kg['pattern'].unique()
    times_ns = [df_kg[df_kg['pattern'] == a]['real_time_us'].mean() * 1000 for a in algos]

    algo_colors = []
    for a in algos:
        if 'X25519' in a:
            algo_colors.append(COLORS['X25519'])
        elif 'X448' in a:
            algo_colors.append(COLORS['X448'])
        elif '512' in a:
            algo_colors.append(COLORS['M512'])
        elif '768' in a:
            algo_colors.append(COLORS['M768'])
        elif '1024' in a:
            algo_colors.append(COLORS['M1024'])
        else:
            algo_colors.append('#888888')

    bars = ax.bar(algos, times_ns, color=algo_colors)
    ax.set_xlabel('Algorithm')
    ax.set_ylabel('Key Generation Time (ns)')
    ax.set_title('Key Generation Performance')
    ax.tick_params(axis='x', rotation=30)
    for bar, val in zip(bars, times_ns):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height(),
                f'{val:.0f}', ha='center', va='bottom', fontsize=9)
    plt.tight_layout()
    _save_fig(fig, figures_dir, 'fig_keygen')

    # Table
    md = "![Key Generation Performance](figures/fig_keygen.png)\n\n"
    md += "| Algorithm | Mean Time (ns) |\n"
    md += "|-----------|---------------|\n"
    for algo, t in zip(algos, times_ns):
        md += f"| {algo} | {t:.0f} |\n"
    return md + '\n'


def plot_key_sizes(figures_dir: Path) -> str:
    """Key and ciphertext size chart (static data)."""
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))
    algos = list(KEY_SIZES.keys())
    x = np.arange(len(algos))

    colors = [COLORS.get('X25519') if 'X25519' in a else
              COLORS.get('X448') if 'X448' in a else
              COLORS.get('M512') if '512' in a else
              COLORS.get('M768') if '768' in a else
              COLORS.get('M1024') for a in algos]

    pub_keys = [KEY_SIZES[a]['public_key'] for a in algos]
    bars1 = ax1.bar(x, pub_keys, color=colors)
    ax1.set_xlabel('Algorithm')
    ax1.set_ylabel('Size (bytes)')
    ax1.set_title('Public Key Sizes')
    ax1.set_xticks(x)
    ax1.set_xticklabels(algos, rotation=45, ha='right')
    for bar, val in zip(bars1, pub_keys):
        ax1.text(bar.get_x() + bar.get_width() / 2, bar.get_height(),
                 f'{val}', ha='center', va='bottom', fontsize=9)

    ciphertexts = [KEY_SIZES[a]['ciphertext'] for a in algos]
    bars2 = ax2.bar(x, ciphertexts, color=colors)
    ax2.set_xlabel('Algorithm')
    ax2.set_ylabel('Size (bytes)')
    ax2.set_title('Ciphertext / DH Exchange Sizes')
    ax2.set_xticks(x)
    ax2.set_xticklabels(algos, rotation=45, ha='right')
    for bar, val in zip(bars2, ciphertexts):
        ax2.text(bar.get_x() + bar.get_width() / 2, bar.get_height(),
                 f'{val}', ha='center', va='bottom', fontsize=9)

    plt.tight_layout()
    _save_fig(fig, figures_dir, 'fig_key_sizes')

    md = "![Key and Ciphertext Sizes](figures/fig_key_sizes.png)\n\n"
    md += "| Algorithm | Public Key (B) | Ciphertext (B) | Shared Secret (B) |\n"
    md += "|-----------|---------------|----------------|-------------------|\n"
    for a in algos:
        ks = KEY_SIZES[a]
        md += f"| {a} | {ks['public_key']} | {ks['ciphertext']} | {ks['shared_secret']} |\n"
    return md + '\n'


def plot_message_overhead(data: dict, figures_dir: Path) -> str:
    """Bytes per handshake comparison."""
    df_c, df_pq, df_hfs = data['classical'], data['pq'], data['hfs']
    has_bytes = any(df is not None and 'bytes_per_hs' in df.columns
                    for df in [df_c, df_pq, df_hfs])
    if not has_bytes:
        return "_No message overhead data available._\n"

    fig, ax = plt.subplots(figsize=(12, 6))
    base_patterns = ['NN', 'XX', 'IK', 'KK']
    plot_data = []

    if df_c is not None and 'bytes_per_hs' in df_c.columns:
        for p in base_patterns:
            mask = (df_c['pattern'] == p) & (df_c['algo'] == 'X25519')
            if mask.any():
                plot_data.append({'Pattern': p, 'Mode': 'Classical',
                                  'Bytes': df_c.loc[mask, 'bytes_per_hs'].mean()})

    if df_pq is not None and 'bytes_per_hs' in df_pq.columns:
        for p in base_patterns:
            mask = (df_pq['pattern'] == f'pq{p}') & (df_pq['algo'] == 'M768')
            if mask.any():
                plot_data.append({'Pattern': p, 'Mode': 'PQ',
                                  'Bytes': df_pq.loc[mask, 'bytes_per_hs'].mean()})

    if df_hfs is not None and 'bytes_per_hs' in df_hfs.columns:
        for p in base_patterns:
            mask = df_hfs['pattern'] == f'{p}hfs'
            if mask.any():
                plot_data.append({'Pattern': p, 'Mode': 'HFS',
                                  'Bytes': df_hfs.loc[mask, 'bytes_per_hs'].mean()})

    if not plot_data:
        return "_No bytes_per_hs data available._\n"

    df_plot = pd.DataFrame(plot_data)
    patterns = list(dict.fromkeys(df_plot['Pattern']))
    modes = list(dict.fromkeys(df_plot['Mode']))
    x = np.arange(len(patterns))
    width = 0.25

    for i, mode in enumerate(modes):
        mode_data = df_plot[df_plot['Mode'] == mode]
        vals = [mode_data[mode_data['Pattern'] == p]['Bytes'].values[0]
                if len(mode_data[mode_data['Pattern'] == p]) > 0 else 0
                for p in patterns]
        color = COLORS.get(mode, '#888888')
        bars = ax.bar(x + i * width, vals, width, label=mode, color=color)
        for bar, val in zip(bars, vals):
            if val > 0:
                ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height(),
                        f'{val:.0f}', ha='center', va='bottom', fontsize=8)

    ax.set_xlabel('Handshake Pattern')
    ax.set_ylabel('Total Bytes Exchanged')
    ax.set_title('Handshake Message Overhead: Bytes per Handshake')
    ax.set_xticks(x + width)
    ax.set_xticklabels(patterns)
    ax.legend()
    plt.tight_layout()
    _save_fig(fig, figures_dir, 'fig_message_overhead')

    md = "![Message Overhead](figures/fig_message_overhead.png)\n\n"
    md += "| Pattern | Classical (B) | PQ (B) | HFS (B) | PQ Growth | HFS Growth |\n"
    md += "|---------|--------------|--------|---------|-----------|------------|\n"
    for p in patterns:
        c = _get_bytes(df_c, p, 'X25519')
        pq = _get_bytes(df_pq, f'pq{p}', 'M768')
        hfs = _get_hfs_bytes(df_hfs, f'{p}hfs')
        c_s = f'{c:.0f}' if c else 'N/A'
        pq_s = f'{pq:.0f}' if pq else 'N/A'
        hfs_s = f'{hfs:.0f}' if hfs else 'N/A'
        pq_g = f'{pq / c:.1f}x' if c and pq else 'N/A'
        hfs_g = f'{hfs / c:.1f}x' if c and hfs else 'N/A'
        md += f"| {p} | {c_s} | {pq_s} | {hfs_s} | {pq_g} | {hfs_g} |\n"
    return md + '\n'


def plot_network_rtt(data: dict, figures_dir: Path) -> str:
    """Network handshake RTT chart."""
    df_net = data['network']
    if df_net is None:
        return "_No network benchmark data available._\n"

    fig, ax = plt.subplots(figsize=(12, 6))

    # Group by mode and compute statistics
    modes = df_net['mode'].unique()
    mode_stats = []
    for mode in sorted(modes):
        mode_data = df_net[(df_net['mode'] == mode) & (df_net['success'] == True)]
        if len(mode_data) == 0:
            continue
        rtt_us = mode_data['rtt_ns'].values / 1000.0
        mode_stats.append({
            'mode': mode,
            'mean': np.mean(rtt_us),
            'std': np.std(rtt_us),
            'p50': np.percentile(rtt_us, 50),
            'p95': np.percentile(rtt_us, 95),
            'p99': np.percentile(rtt_us, 99),
            'count': len(mode_data),
        })

    if not mode_stats:
        return "_No successful network handshake data._\n"

    df_stats = pd.DataFrame(mode_stats)

    # Categorize modes
    x = np.arange(len(df_stats))
    bar_colors = []
    for m in df_stats['mode']:
        if m.startswith('pq'):
            bar_colors.append(COLORS['PQ'])
        elif m.endswith('hfs'):
            bar_colors.append(COLORS['HFS'])
        else:
            bar_colors.append(COLORS['Classical'])

    bars = ax.bar(x, df_stats['mean'], yerr=df_stats['std'], color=bar_colors,
                  capsize=4, alpha=0.85)
    ax.set_xlabel('Handshake Mode')
    ax.set_ylabel('Mean RTT (us)')
    ax.set_title('Network Handshake Round-Trip Time')
    ax.set_xticks(x)
    ax.set_xticklabels(df_stats['mode'].str.upper(), rotation=45, ha='right')

    for bar, val in zip(bars, df_stats['mean']):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height(),
                f'{val:.0f}', ha='center', va='bottom', fontsize=8)

    # Legend
    from matplotlib.patches import Patch
    legend_elements = [
        Patch(facecolor=COLORS['Classical'], label='Classical'),
        Patch(facecolor=COLORS['PQ'], label='Post-Quantum'),
        Patch(facecolor=COLORS['HFS'], label='Hybrid (HFS)'),
    ]
    ax.legend(handles=legend_elements)
    plt.tight_layout()
    _save_fig(fig, figures_dir, 'fig_network_rtt')

    md = "![Network RTT](figures/fig_network_rtt.png)\n\n"
    md += "| Mode | Mean RTT (us) | Std Dev (us) | P50 (us) | P95 (us) | P99 (us) | N |\n"
    md += "|------|--------------|-------------|---------|---------|---------|---|\n"
    for _, row in df_stats.iterrows():
        md += (f"| {row['mode'].upper()} | {row['mean']:.1f} | {row['std']:.1f} | "
               f"{row['p50']:.1f} | {row['p95']:.1f} | {row['p99']:.1f} | {row['count']:.0f} |\n")
    return md + '\n'


def plot_throughput(data: dict, figures_dir: Path) -> str:
    """Throughput scaling with concurrent clients."""
    df_stress = data['stress']
    if df_stress is None:
        return "_No stress test data available._\n"

    fig, ax = plt.subplots(figsize=(10, 6))
    modes = df_stress['mode'].unique()

    for mode in sorted(modes):
        mode_data = df_stress[df_stress['mode'] == mode].sort_values('clients')
        if len(mode_data) == 0:
            continue

        color = COLORS['PQ'] if mode.startswith('pq') else \
                COLORS['HFS'] if mode.endswith('hfs') else COLORS['Classical']
        ax.plot(mode_data['clients'], mode_data['throughput'], 'o-',
                label=mode.upper(), color=color, markersize=8, linewidth=2)

    ax.set_xlabel('Number of Concurrent Clients')
    ax.set_ylabel('Handshakes per Second')
    ax.set_title('Throughput Scaling with Concurrent Clients')
    ax.legend()
    plt.tight_layout()
    _save_fig(fig, figures_dir, 'fig_throughput_scaling')

    md = "![Throughput Scaling](figures/fig_throughput_scaling.png)\n\n"
    md += "| Mode | Clients | Throughput (hs/s) | Mean RTT (us) | P95 (us) | P99 (us) |\n"
    md += "|------|---------|-------------------|--------------|---------|----------|\n"
    for _, row in df_stress.iterrows():
        md += (f"| {row['mode'].upper()} | {row['clients']:.0f} | {row['throughput']:.1f} | "
               f"{row['mean_us']:.1f} | {row['p95_us']:.1f} | {row['p99_us']:.1f} |\n")
    return md + '\n'


def generate_summary_table(data: dict, figures_dir: Path) -> str:
    """Master summary table of all benchmarks."""
    summary = []
    datasets = [
        ('Classical', data['classical']),
        ('Post-Quantum', data['pq']),
        ('Hybrid (HFS)', data['hfs']),
    ]

    for mode, df in datasets:
        if df is None:
            continue
        for pattern in df['pattern'].unique():
            pdata = df[df['pattern'] == pattern]
            row = {
                'Mode': mode,
                'Pattern': pattern,
                'Algorithm': pdata['algo'].iloc[0] if 'algo' in pdata.columns else 'N/A',
                'Latency (us)': pdata['real_time_us'].mean(),
                'CPU Time (us)': pdata['cpu_time_us'].mean(),
            }
            if 'bytes_per_hs' in pdata.columns:
                row['Bytes/HS'] = pdata['bytes_per_hs'].mean()
            if 'messages' in pdata.columns:
                row['Messages'] = int(pdata['messages'].iloc[0])
            summary.append(row)

    if not summary:
        return "_No summary data available._\n"

    df_summary = pd.DataFrame(summary)

    # Save CSV
    df_summary.to_csv(figures_dir / 'summary_stats.csv', index=False)

    md = "| Mode | Pattern | Algorithm | Latency (us) | CPU Time (us) |"
    has_bytes = 'Bytes/HS' in df_summary.columns
    has_msgs = 'Messages' in df_summary.columns
    if has_bytes:
        md += " Bytes/HS |"
    if has_msgs:
        md += " Messages |"
    md += "\n"

    md += "|------|---------|-----------|-------------|--------------|"
    if has_bytes:
        md += "----------|"
    if has_msgs:
        md += "----------|"
    md += "\n"

    for _, row in df_summary.iterrows():
        md += f"| {row['Mode']} | {row['Pattern']} | {row['Algorithm']} | {row['Latency (us)']:.1f} | {row['CPU Time (us)']:.1f} |"
        if has_bytes:
            md += f" {row.get('Bytes/HS', 0):.0f} |"
        if has_msgs:
            md += f" {row.get('Messages', 0):.0f} |"
        md += "\n"

    return md + '\n'


def generate_academic_summary(data: dict) -> str:
    """Generate ~350 word academic summary with real computed numbers."""
    df_c, df_pq, df_hfs = data['classical'], data['pq'], data['hfs']

    # Compute key statistics
    stats = {}
    if df_c is not None:
        for p in ['NN', 'XX', 'IK', 'KK']:
            mask = (df_c['pattern'] == p) & (df_c['algo'] == 'X25519')
            if mask.any():
                stats[f'c_{p}'] = df_c.loc[mask, 'real_time_us'].mean()

    if df_pq is not None:
        for p in ['pqNN', 'pqXX', 'pqIK', 'pqKK']:
            mask = (df_pq['pattern'] == p) & (df_pq['algo'] == 'M768')
            if mask.any():
                stats[f'pq_{p}'] = df_pq.loc[mask, 'real_time_us'].mean()

    if df_hfs is not None:
        for p in ['NNhfs', 'XXhfs', 'IKhfs', 'KKhfs']:
            mask = df_hfs['pattern'] == p
            if mask.any():
                stats[f'hfs_{p}'] = df_hfs.loc[mask, 'real_time_us'].mean()

    # Compute overhead ratios
    pq_overheads = []
    hfs_overheads = []
    for base in ['NN', 'XX', 'IK', 'KK']:
        c_key = f'c_{base}'
        pq_key = f'pq_pq{base}'
        hfs_key = f'hfs_{base}hfs'
        if c_key in stats and pq_key in stats:
            pq_overheads.append(stats[pq_key] / stats[c_key])
        if c_key in stats and hfs_key in stats:
            hfs_overheads.append(stats[hfs_key] / stats[c_key])

    avg_pq_oh = np.mean(pq_overheads) if pq_overheads else None
    avg_hfs_oh = np.mean(hfs_overheads) if hfs_overheads else None

    # Compute bandwidth ratios
    bw_pq_ratios = []
    if df_c is not None and df_pq is not None:
        if 'bytes_per_hs' in df_c.columns and 'bytes_per_hs' in df_pq.columns:
            for base in ['NN', 'XX', 'IK', 'KK']:
                c_b = _get_bytes(df_c, base, 'X25519')
                pq_b = _get_bytes(df_pq, f'pq{base}', 'M768')
                if c_b and pq_b:
                    bw_pq_ratios.append(pq_b / c_b)
    avg_bw_ratio = np.mean(bw_pq_ratios) if bw_pq_ratios else None

    # Classical range
    c_vals = [v for k, v in stats.items() if k.startswith('c_')]
    c_range = f"{min(c_vals):.1f}--{max(c_vals):.1f}" if c_vals else "N/A"

    # Build summary
    parts = []
    parts.append(
        "We present a preliminary performance evaluation of our NoisePQC++ implementation, "
        "measuring the computational overhead introduced by post-quantum (PQ) and hybrid "
        "forward secrecy (HFS) extensions to the Noise Protocol Framework. "
        "All benchmarks were executed on a single machine in Release configuration using "
        "the Clang 18 compiler with full optimizations. Each benchmark was run for a "
        "minimum of three seconds to ensure measurement stability via the Google Benchmark "
        "framework."
    )

    if c_vals:
        parts.append(
            f"Classical X25519-based handshakes establish a performance baseline, completing in "
            f"{c_range} microseconds across the NN, XX, IK, and KK patterns."
        )

    if avg_pq_oh is not None:
        parts.append(
            f"Post-quantum handshakes using ML-KEM-768 (NIST Security Level 3) introduce "
            f"a mean overhead factor of {avg_pq_oh:.2f}x over their classical counterparts. "
            f"This overhead is primarily attributable to the larger key encapsulation operations "
            f"and the increased number of protocol messages in certain patterns (e.g., pqXX "
            f"requires four messages compared to three for classical XX)."
        )

    if avg_hfs_oh is not None:
        parts.append(
            f"Hybrid forward secrecy patterns, which combine X25519 key exchange with "
            f"ML-KEM-768 key encapsulation, exhibit a mean overhead factor of {avg_hfs_oh:.2f}x "
            f"relative to classical handshakes. The HFS overhead is higher than pure PQ due to "
            f"the additional Diffie-Hellman computation performed alongside the KEM operation, "
            f"providing defense-in-depth against both classical and quantum adversaries."
        )

    if avg_bw_ratio is not None:
        parts.append(
            f"From a bandwidth perspective, PQ handshakes require approximately "
            f"{avg_bw_ratio:.1f}x the wire bytes of classical handshakes, driven by the larger "
            f"ML-KEM public keys (1,184 bytes for ML-KEM-768 vs. 32 bytes for X25519) and "
            f"ciphertext sizes (1,088 bytes vs. 32 bytes)."
        )

    parts.append(
        "These preliminary results demonstrate that post-quantum and hybrid Noise protocol "
        "extensions are practically feasible for deployment, with handshake latencies remaining "
        "well within the sub-millisecond range suitable for interactive applications. "
        "A comprehensive evaluation including cipher suite permutations, per-component latency "
        "breakdown, memory profiling, and comparison against reference implementations is "
        "reserved for future work."
    )

    return ' '.join(parts) + '\n'


# =============================================================================
# Helpers
# =============================================================================
def _save_fig(fig, figures_dir: Path, name: str):
    """Save figure as PNG and PDF."""
    fig.savefig(figures_dir / f'{name}.png', bbox_inches='tight')
    fig.savefig(figures_dir / f'{name}.pdf', bbox_inches='tight')
    plt.close(fig)
    print(f"  Saved {name}.png/.pdf")


def _get_latency(df, pattern, algo) -> Optional[float]:
    if df is None:
        return None
    mask = (df['pattern'] == pattern) & (df['algo'] == algo)
    if mask.any():
        return df.loc[mask, 'real_time_us'].mean()
    return None


def _get_hfs_latency(df, pattern) -> Optional[float]:
    if df is None:
        return None
    mask = df['pattern'] == pattern
    if 'algo' in df.columns:
        mask = mask & df['algo'].str.contains('X25519.*M768', na=False)
    if mask.any():
        return df.loc[mask, 'real_time_us'].mean()
    return None


def _get_bytes(df, pattern, algo) -> Optional[float]:
    if df is None or 'bytes_per_hs' not in df.columns:
        return None
    mask = (df['pattern'] == pattern) & (df['algo'] == algo)
    if mask.any():
        return df.loc[mask, 'bytes_per_hs'].mean()
    return None


def _get_hfs_bytes(df, pattern) -> Optional[float]:
    if df is None or 'bytes_per_hs' not in df.columns:
        return None
    mask = df['pattern'] == pattern
    if mask.any():
        return df.loc[mask, 'bytes_per_hs'].mean()
    return None


# =============================================================================
# Markdown assembly
# =============================================================================
def assemble_markdown(sections: dict, system_info: str, data: dict) -> str:
    """Assemble the full Markdown document."""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Extract system summary from system_info.txt
    sys_summary = "See system_info.txt for details"
    for line in system_info.splitlines():
        if 'Model:' in line:
            sys_summary = line.strip().replace('Model: ', '')
            break

    md = f"""# NoisePQC++ Preliminary Benchmark Results

> **Generated:** {timestamp}
> **System:** {sys_summary}
> **Configuration:** Release mode, Clang 18, C++23
> **Framework:** Google Benchmark (local), ASIO TCP (network)

---

## Table of Contents

1. [Handshake Latency Comparison](#1-handshake-latency-comparison)
2. [CPU Time Analysis](#2-cpu-time-analysis)
3. [Key Generation Performance](#3-key-generation-performance)
4. [Key and Ciphertext Sizes](#4-key-and-ciphertext-sizes)
5. [Message Overhead Analysis](#5-message-overhead-analysis)
6. [Network Round-Trip Time](#6-network-round-trip-time)
7. [Throughput Scaling](#7-throughput-scaling)
8. [Summary Statistics](#8-summary-statistics)
9. [Preliminary Performance Evaluation](#9-preliminary-performance-evaluation)
10. [Methodology](#10-methodology)

---

## 1. Handshake Latency Comparison

{sections.get('latency', '_Not available._')}

---

## 2. CPU Time Analysis

{sections.get('cpu_time', '_Not available._')}

---

## 3. Key Generation Performance

{sections.get('keygen', '_Not available._')}

---

## 4. Key and Ciphertext Sizes

{sections.get('key_sizes', '_Not available._')}

---

## 5. Message Overhead Analysis

{sections.get('message_overhead', '_Not available._')}

---

## 6. Network Round-Trip Time

{sections.get('network_rtt', '_Not available._')}

---

## 7. Throughput Scaling

{sections.get('throughput', '_Not available._')}

---

## 8. Summary Statistics

{sections.get('summary', '_Not available._')}

---

## 9. Preliminary Performance Evaluation

{sections.get('academic_summary', '_Not available._')}

---

## 10. Methodology

### System Specification

```
{system_info.strip() if system_info else 'System information not captured.'}
```

### Benchmark Parameters

- **Local benchmarks:** Google Benchmark framework with minimum 3-second runtime per benchmark
- **Network benchmarks:** 100 iterations per handshake mode over TCP loopback
- **Stress tests:** 1, 5, and 10 concurrent clients with 20 iterations each
- **Build:** Release mode with full compiler optimizations (-O2)

### Reproducibility

Results can be reproduced by running:
```bash
./scripts/run_benchmarks.sh
python3 analysis/scripts/render_results.py
```

---

_This document was auto-generated by `render_results.py` from benchmark data in `analysis/data/`._
"""
    return md


# =============================================================================
# Main
# =============================================================================
REPO_ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description="NoisePQC++ Benchmark Results Renderer")
    parser.add_argument('--data-dir', type=Path, default=Path('analysis/data'),
                        help='Directory containing benchmark CSVs (default: analysis/data, '
                             'the v0.9.0 paper data; relative to the repository root)')
    parser.add_argument('--figures-dir', type=Path, default=None,
                        help='Directory to save figures (default: out/render/<data-dir name>/figures)')
    parser.add_argument('--output', type=Path, default=None,
                        help='Output Markdown file path (default: out/render/<data-dir name>/BENCHMARK_RESULTS.md)')
    parser.add_argument('--no-copy-figures', action='store_true',
                        help='Do not copy figures to output directory')
    args = parser.parse_args()

    # Resolve paths from the repository root (a relative path is relative to it)
    data_dir = (REPO_ROOT / args.data_dir).resolve()
    render_dir = REPO_ROOT / 'out' / 'render' / data_dir.name
    figures_dir = (REPO_ROOT / args.figures_dir).resolve() if args.figures_dir else (render_dir / 'figures').resolve()
    output_path = (REPO_ROOT / args.output).resolve() if args.output else (render_dir / 'BENCHMARK_RESULTS.md').resolve()

    tracked_figures = (REPO_ROOT / 'analysis' / 'figures').resolve()
    if figures_dir == tracked_figures:
        print("WARNING: --figures-dir is analysis/figures: this run overwrites the tracked figures of the v0.9.0 paper.")
        print()

    print(f"Data dir:    {data_dir}")
    print(f"Figures dir: {figures_dir}")
    print(f"Output:      {output_path}")
    print()

    figures_dir.mkdir(parents=True, exist_ok=True)

    # Load data
    data = load_all_data(data_dir)
    print()

    # Generate each section
    sections = {}
    print("Generating figures and tables...")

    sections['latency'] = plot_latency_comparison(data, figures_dir)
    sections['cpu_time'] = plot_cpu_time(data, figures_dir)
    sections['keygen'] = plot_keygen(data, figures_dir)
    sections['key_sizes'] = plot_key_sizes(figures_dir)
    sections['message_overhead'] = plot_message_overhead(data, figures_dir)
    sections['network_rtt'] = plot_network_rtt(data, figures_dir)
    sections['throughput'] = plot_throughput(data, figures_dir)
    sections['summary'] = generate_summary_table(data, figures_dir)
    sections['academic_summary'] = generate_academic_summary(data)

    print()

    # Assemble document
    md_content = assemble_markdown(sections, data['system_info'], data)

    # Write MD file
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(md_content)
    print(f"Wrote {output_path}")

    # Copy figures to the output's figures/ dir, unless that is the figures dir itself
    # (it is by default, and copying a file onto itself raises)
    out_figures = (output_path.parent / 'figures').resolve()
    if not args.no_copy_figures and out_figures != figures_dir:
        out_figures.mkdir(parents=True, exist_ok=True)
        for png in figures_dir.glob('*.png'):
            shutil.copy2(png, out_figures / png.name)
        print(f"Copied figures to {out_figures}")

    print("\nDone!")


if __name__ == '__main__':
    main()
