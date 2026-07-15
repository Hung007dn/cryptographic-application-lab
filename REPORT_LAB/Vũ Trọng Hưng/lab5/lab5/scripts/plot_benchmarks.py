#!/usr/bin/env python3
"""
Signature Benchmark Plotter
Vẽ đồ thị từ kết quả benchmark của Lab 5
"""

import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns
import os
import sys

# Set style
plt.style.use('seaborn-v0_8-darkgrid')
sns.set_palette("Set2")

def load_data(csv_file):
    """Load benchmark data from CSV"""
    if not os.path.exists(csv_file):
        print(f"Error: {csv_file} not found!")
        print("Please run sigtool --benchmark first")
        sys.exit(1)
    
    df = pd.read_csv(csv_file)
    return df

def plot_keygen_latency(df, output_dir):
    """Plot key generation latency comparison"""
    fig, ax = plt.subplots(figsize=(10, 6))
    
    keygen_data = df[df['Operation'] == 'keygen']
    algorithms = keygen_data['Algorithm'].values
    latencies = keygen_data['TimeMS'].values
    
    bars = ax.bar(algorithms, latencies, color=['#2ecc71', '#3498db', '#e74c3c'])
    ax.set_ylabel('Time (ms)', fontsize=12)
    ax.set_xlabel('Algorithm', fontsize=12)
    ax.set_title('Key Generation Latency', fontsize=14, fontweight='bold')
    
    # Add value labels on bars
    for bar, lat in zip(bars, latencies):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
                f'{lat:.2f} ms', ha='center', va='bottom', fontsize=10)
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'keygen_latency.png'), dpi=150)
    plt.close()
    print(f"  Saved: keygen_latency.png")

def plot_signing_latency(df, output_dir):
    """Plot signing latency comparison"""
    fig, ax = plt.subplots(figsize=(10, 6))
    
    sign_data = df[(df['Operation'] == 'sign') & (df['MessageSizeBytes'] == 1024)]
    algorithms = sign_data['Algorithm'].values
    latencies = sign_data['TimeMS'].values
    
    bars = ax.bar(algorithms, latencies, color=['#2ecc71', '#3498db', '#e74c3c'])
    ax.set_ylabel('Time (ms)', fontsize=12)
    ax.set_xlabel('Algorithm', fontsize=12)
    ax.set_title('Signing Latency (1 KiB message)', fontsize=14, fontweight='bold')
    
    for bar, lat in zip(bars, latencies):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
                f'{lat:.3f} ms', ha='center', va='bottom', fontsize=10)
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'signing_latency.png'), dpi=150)
    plt.close()
    print(f"  Saved: signing_latency.png")

def plot_verification_latency(df, output_dir):
    """Plot verification latency comparison"""
    fig, ax = plt.subplots(figsize=(10, 6))
    
    verify_data = df[(df['Operation'] == 'verify') & (df['MessageSizeBytes'] == 1024)]
    algorithms = verify_data['Algorithm'].values
    latencies = verify_data['TimeMS'].values
    
    bars = ax.bar(algorithms, latencies, color=['#2ecc71', '#3498db', '#e74c3c'])
    ax.set_ylabel('Time (ms)', fontsize=12)
    ax.set_xlabel('Algorithm', fontsize=12)
    ax.set_title('Verification Latency (1 KiB message)', fontsize=14, fontweight='bold')
    
    for bar, lat in zip(bars, latencies):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
                f'{lat:.3f} ms', ha='center', va='bottom', fontsize=10)
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'verification_latency.png'), dpi=150)
    plt.close()
    print(f"  Saved: verification_latency.png")

def plot_throughput_comparison(df, output_dir):
    """Plot throughput comparison (ops/sec)"""
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
    
    # Signing throughput
    sign_data = df[(df['Operation'] == 'sign') & (df['MessageSizeBytes'] == 1024)]
    algorithms = sign_data['Algorithm'].values
    sign_throughput = sign_data['ThroughputOpsPerSec'].values
    
    bars1 = ax1.bar(algorithms, sign_throughput, color=['#2ecc71', '#3498db', '#e74c3c'])
    ax1.set_ylabel('Operations per second', fontsize=12)
    ax1.set_xlabel('Algorithm', fontsize=12)
    ax1.set_title('Signing Throughput (1 KiB)', fontsize=12, fontweight='bold')
    
    for bar, val in zip(bars1, sign_throughput):
        ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 50,
                f'{val:.0f}', ha='center', va='bottom', fontsize=9)
    
    # Verification throughput
    verify_data = df[(df['Operation'] == 'verify') & (df['MessageSizeBytes'] == 1024)]
    verify_throughput = verify_data['ThroughputOpsPerSec'].values
    
    bars2 = ax2.bar(algorithms, verify_throughput, color=['#2ecc71', '#3498db', '#e74c3c'])
    ax2.set_ylabel('Operations per second', fontsize=12)
    ax2.set_xlabel('Algorithm', fontsize=12)
    ax2.set_title('Verification Throughput (1 KiB)', fontsize=12, fontweight='bold')
    
    for bar, val in zip(bars2, verify_throughput):
        ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 500,
                f'{val:.0f}', ha='center', va='bottom', fontsize=9)
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'throughput_comparison.png'), dpi=150)
    plt.close()
    print(f"  Saved: throughput_comparison.png")

def plot_sign_verify_comparison(df, output_dir):
    """Plot sign vs verify latency for each algorithm"""
    fig, axes = plt.subplots(1, 3, figsize=(15, 5))
    
    algorithms = ['ECDSA-P256', 'ECDSA-P384', 'RSA-PSS-3072']
    colors = ['#2ecc71', '#3498db', '#e74c3c']
    
    for idx, algo in enumerate(algorithms):
        ax = axes[idx]
        
        sign_data = df[(df['Algorithm'] == algo) & (df['Operation'] == 'sign') & (df['MessageSizeBytes'] == 1024)]
        verify_data = df[(df['Algorithm'] == algo) & (df['Operation'] == 'verify') & (df['MessageSizeBytes'] == 1024)]
        
        ops = ['Sign', 'Verify']
        latencies = [sign_data['TimeMS'].values[0] if len(sign_data) > 0 else 0,
                     verify_data['TimeMS'].values[0] if len(verify_data) > 0 else 0]
        
        bars = ax.bar(ops, latencies, color=[colors[idx], colors[idx]])
        ax.set_ylabel('Time (ms)', fontsize=10)
        ax.set_title(algo, fontsize=12, fontweight='bold')
        
        for bar, lat in zip(bars, latencies):
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.1,
                    f'{lat:.3f} ms', ha='center', va='bottom', fontsize=9)
    
    plt.suptitle('Sign vs Verify Latency Comparison', fontsize=14, fontweight='bold')
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'sign_vs_verify.png'), dpi=150)
    plt.close()
    print(f"  Saved: sign_vs_verify.png")

def plot_message_size_impact(df, output_dir):
    """Plot latency vs message size for each algorithm"""
    fig, axes = plt.subplots(1, 2, figsize=(14, 6))
    
    # Signing latency vs message size
    ax1 = axes[0]
    for algo in ['ECDSA-P256', 'ECDSA-P384', 'RSA-PSS-3072']:
        algo_data = df[(df['Algorithm'] == algo) & (df['Operation'] == 'sign')]
        if len(algo_data) > 0:
            sizes = algo_data['MessageSizeBytes'].values
            sizes_kb = sizes / 1024
            latencies = algo_data['TimeMS'].values
            ax1.plot(sizes_kb, latencies, 'o-', linewidth=2, markersize=8, label=algo)
    
    ax1.set_xlabel('Message Size (KB)', fontsize=12)
    ax1.set_ylabel('Signing Time (ms)', fontsize=12)
    ax1.set_title('Signing Latency vs Message Size', fontsize=12, fontweight='bold')
    ax1.legend()
    ax1.grid(True, alpha=0.3)
    
    # Verification latency vs message size
    ax2 = axes[1]
    for algo in ['ECDSA-P256', 'ECDSA-P384', 'RSA-PSS-3072']:
        algo_data = df[(df['Algorithm'] == algo) & (df['Operation'] == 'verify')]
        if len(algo_data) > 0:
            sizes = algo_data['MessageSizeBytes'].values
            sizes_kb = sizes / 1024
            latencies = algo_data['TimeMS'].values
            ax2.plot(sizes_kb, latencies, 'o-', linewidth=2, markersize=8, label=algo)
    
    ax2.set_xlabel('Message Size (KB)', fontsize=12)
    ax2.set_ylabel('Verification Time (ms)', fontsize=12)
    ax2.set_title('Verification Latency vs Message Size', fontsize=12, fontweight='bold')
    ax2.legend()
    ax2.grid(True, alpha=0.3)
    
    plt.suptitle('Impact of Message Size on Performance', fontsize=14, fontweight='bold')
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'message_size_impact.png'), dpi=150)
    plt.close()
    print(f"  Saved: message_size_impact.png")

def plot_algorithm_comparison(df, output_dir):
    """Comprehensive algorithm comparison"""
    fig, ax = plt.subplots(figsize=(12, 8))
    
    # Prepare data for grouped bar chart
    operations = ['KeyGen', 'Sign', 'Verify']
    algorithms = ['ECDSA-P256', 'ECDSA-P384', 'RSA-PSS-3072']
    
    x = np.arange(len(operations))
    width = 0.25
    
    colors = {'ECDSA-P256': '#2ecc71', 'ECDSA-P384': '#3498db', 'RSA-PSS-3072': '#e74c3c'}
    
    for i, algo in enumerate(algorithms):
        values = []
        # KeyGen
        kg_data = df[(df['Algorithm'] == algo) & (df['Operation'] == 'keygen')]
        values.append(kg_data['TimeMS'].values[0] if len(kg_data) > 0 else 0)
        
        # Sign (1 KiB)
        sign_data = df[(df['Algorithm'] == algo) & (df['Operation'] == 'sign') & (df['MessageSizeBytes'] == 1024)]
        values.append(sign_data['TimeMS'].values[0] if len(sign_data) > 0 else 0)
        
        # Verify (1 KiB)
        verify_data = df[(df['Algorithm'] == algo) & (df['Operation'] == 'verify') & (df['MessageSizeBytes'] == 1024)]
        values.append(verify_data['TimeMS'].values[0] if len(verify_data) > 0 else 0)
        
        offset = (i - 1) * width
        bars = ax.bar(x + offset, values, width, label=algo, color=colors[algo])
        
        # Add value labels
        for bar, val in zip(bars, values):
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
                   f'{val:.2f}', ha='center', va='bottom', fontsize=8)
    
    ax.set_ylabel('Time (ms)', fontsize=12)
    ax.set_xlabel('Operation', fontsize=12)
    ax.set_title('Algorithm Performance Comparison', fontsize=14, fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels(operations)
    ax.legend()
    ax.grid(True, alpha=0.3, axis='y')
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'algorithm_comparison.png'), dpi=150)
    plt.close()
    print(f"  Saved: algorithm_comparison.png")

def plot_heatmap(df, output_dir):
    """Create performance heatmap"""
    # Pivot table for heatmap
    pivot_data = df[df['MessageSizeBytes'] == 1024]
    heatmap_data = pivot_data.pivot_table(
        index='Algorithm', 
        columns='Operation', 
        values='TimeMS',
        aggfunc='first'
    )
    
    fig, ax = plt.subplots(figsize=(10, 6))
    sns.heatmap(heatmap_data, annot=True, fmt='.3f', cmap='YlOrRd', 
                xticklabels=True, yticklabels=True, ax=ax)
    ax.set_title('Performance Heatmap (Time in ms, 1 KiB message)', fontsize=14, fontweight='bold')
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'performance_heatmap.png'), dpi=150)
    plt.close()
    print(f"  Saved: performance_heatmap.png")

def plot_rsa_vs_ecdsa(df, output_dir):
    """Direct RSA vs ECDSA comparison"""
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
    
    # Get data for ECDSA-P256 and RSA-PSS-3072
    ecdsa_sign = df[(df['Algorithm'] == 'ECDSA-P256') & (df['Operation'] == 'sign')]
    rsa_sign = df[(df['Algorithm'] == 'RSA-PSS-3072') & (df['Operation'] == 'sign')]
    
    ecdsa_verify = df[(df['Algorithm'] == 'ECDSA-P256') & (df['Operation'] == 'verify')]
    rsa_verify = df[(df['Algorithm'] == 'RSA-PSS-3072') & (df['Operation'] == 'verify')]
    
    # Signing comparison
    sizes = []
    ecdsa_times = []
    rsa_times = []
    
    for size in [1024, 16384, 1048576, 8388608]:
        ecdsa_val = ecdsa_sign[ecdsa_sign['MessageSizeBytes'] == size]['TimeMS'].values
        rsa_val = rsa_sign[rsa_sign['MessageSizeBytes'] == size]['TimeMS'].values
        
        if len(ecdsa_val) > 0 and len(rsa_val) > 0:
            sizes.append(size / 1024)
            ecdsa_times.append(ecdsa_val[0])
            rsa_times.append(rsa_val[0])
    
    ax1.plot(sizes, ecdsa_times, 'o-', linewidth=2, markersize=8, label='ECDSA-P256', color='#2ecc71')
    ax1.plot(sizes, rsa_times, 's-', linewidth=2, markersize=8, label='RSA-PSS-3072', color='#e74c3c')
    ax1.set_xlabel('Message Size (KB)', fontsize=12)
    ax1.set_ylabel('Signing Time (ms)', fontsize=12)
    ax1.set_title('ECDSA vs RSA: Signing Performance', fontsize=12, fontweight='bold')
    ax1.legend()
    ax1.grid(True, alpha=0.3)
    
    # Verification comparison
    ecdsa_verify_times = []
    rsa_verify_times = []
    
    for size in [1024, 16384, 1048576, 8388608]:
        ecdsa_val = ecdsa_verify[ecdsa_verify['MessageSizeBytes'] == size]['TimeMS'].values
        rsa_val = rsa_verify[rsa_verify['MessageSizeBytes'] == size]['TimeMS'].values
        
        if len(ecdsa_val) > 0 and len(rsa_val) > 0:
            ecdsa_verify_times.append(ecdsa_val[0])
            rsa_verify_times.append(rsa_val[0])
    
    ax2.plot(sizes, ecdsa_verify_times, 'o-', linewidth=2, markersize=8, label='ECDSA-P256', color='#2ecc71')
    ax2.plot(sizes, rsa_verify_times, 's-', linewidth=2, markersize=8, label='RSA-PSS-3072', color='#e74c3c')
    ax2.set_xlabel('Message Size (KB)', fontsize=12)
    ax2.set_ylabel('Verification Time (ms)', fontsize=12)
    ax2.set_title('ECDSA vs RSA: Verification Performance', fontsize=12, fontweight='bold')
    ax2.legend()
    ax2.grid(True, alpha=0.3)
    
    plt.suptitle('ECDSA-P256 vs RSA-PSS-3072 Performance Comparison', fontsize=14, fontweight='bold')
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'rsa_vs_ecdsa.png'), dpi=150)
    plt.close()
    print(f"  Saved: rsa_vs_ecdsa.png")

def main():
    print("=" * 50)
    print("Signature Benchmark Plotter")
    print("=" * 50)
    
    # Find CSV file
    script_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(script_dir)
    
    csv_file = os.path.join(parent_dir, 'signature_benchmark_results.csv')
    
    if not os.path.exists(csv_file):
        # Try current directory
        csv_file = 'signature_benchmark_results.csv'
    
    print(f"Loading data from: {csv_file}")
    df = load_data(csv_file)
    
    print(f"Loaded {len(df)} records")
    print("\nGenerating plots...")
    
    # Create output directory for plots
    output_dir = os.path.join(parent_dir, 'benchmark_plots')
    os.makedirs(output_dir, exist_ok=True)
    
    # Generate all plots
    plot_keygen_latency(df, output_dir)
    plot_signing_latency(df, output_dir)
    plot_verification_latency(df, output_dir)
    plot_throughput_comparison(df, output_dir)
    plot_sign_verify_comparison(df, output_dir)
    plot_message_size_impact(df, output_dir)
    plot_algorithm_comparison(df, output_dir)
    plot_heatmap(df, output_dir)
    plot_rsa_vs_ecdsa(df, output_dir)
    
    print(f"\n All plots saved to: {output_dir}")
    print("\nGenerated plots:")
    print("  - keygen_latency.png")
    print("  - signing_latency.png")
    print("  - verification_latency.png")
    print("  - throughput_comparison.png")
    print("  - sign_vs_verify.png")
    print("  - message_size_impact.png")
    print("  - algorithm_comparison.png")
    print("  - performance_heatmap.png")
    print("  - rsa_vs_ecdsa.png")

if __name__ == "__main__":
    main()