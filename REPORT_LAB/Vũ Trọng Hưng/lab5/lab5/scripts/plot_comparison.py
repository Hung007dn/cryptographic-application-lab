import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import os
import sys

def load_data(csv_file):
    """Load benchmark data from CSV"""
    if not os.path.exists(csv_file):
        print(f"Error: {csv_file} not found!")
        print("Please run sigtool --benchmark first")
        sys.exit(1)
    
    df = pd.read_csv(csv_file)
    return df

def plot_algorithm_comparison_bar(df, output_dir):
    """Bar chart comparing all algorithms across operations"""
    fig, ax = plt.subplots(figsize=(12, 7))
    
    operations = ['KeyGen', 'Sign (1KB)', 'Verify (1KB)']
    algorithms = ['ECDSA-P256', 'ECDSA-P384', 'RSA-PSS-3072']
    colors = ['#2ecc71', '#3498db', '#e74c3c']
    
    x = np.arange(len(operations))
    width = 0.25
    
    for i, (algo, color) in enumerate(zip(algorithms, colors)):
        values = []
        
        # KeyGen
        kg_data = df[(df['Algorithm'] == algo) & (df['Operation'] == 'keygen')]
        values.append(kg_data['TimeMS'].values[0] if len(kg_data) > 0 else 0)
        
        # Sign (1KB)
        sign_data = df[(df['Algorithm'] == algo) & (df['Operation'] == 'sign') & (df['MessageSizeBytes'] == 1024)]
        values.append(sign_data['TimeMS'].values[0] if len(sign_data) > 0 else 0)
        
        # Verify (1KB)
        verify_data = df[(df['Algorithm'] == algo) & (df['Operation'] == 'verify') & (df['MessageSizeBytes'] == 1024)]
        values.append(verify_data['TimeMS'].values[0] if len(verify_data) > 0 else 0)
        
        offset = (i - 1) * width
        bars = ax.bar(x + offset, values, width, label=algo, color=color, alpha=0.8)
        
        # Add value labels on bars
        for bar, val in zip(bars, values):
            if val > 0:
                ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
                       f'{val:.2f}', ha='center', va='bottom', fontsize=9, fontweight='bold')
    
    ax.set_ylabel('Time (ms)', fontsize=12)
    ax.set_xlabel('Operation', fontsize=12)
    ax.set_title('Algorithm Performance Comparison (Lower is Better)', fontsize=14, fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels(operations)
    ax.legend(loc='upper left', fontsize=10)
    ax.grid(True, alpha=0.3, axis='y')
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'comparison_bar.png'), dpi=150, bbox_inches='tight')
    plt.close()
    print(f"  Saved: comparison_bar.png")

def plot_algorithm_comparison_grouped(df, output_dir):
    """Grouped bar chart for each algorithm"""
    fig, axes = plt.subplots(1, 3, figsize=(15, 6))
    
    algorithms = ['ECDSA-P256', 'ECDSA-P384', 'RSA-PSS-3072']
    titles = ['ECDSA-P256', 'ECDSA-P384', 'RSA-PSS-3072']
    colors = ['#2ecc71', '#3498db', '#e74c3c']
    
    for idx, (algo, title, color) in enumerate(zip(algorithms, titles, colors)):
        ax = axes[idx]
        
        # Get data for this algorithm
        keygen = df[(df['Algorithm'] == algo) & (df['Operation'] == 'keygen')]
        sign_1kb = df[(df['Algorithm'] == algo) & (df['Operation'] == 'sign') & (df['MessageSizeBytes'] == 1024)]
        sign_16kb = df[(df['Algorithm'] == algo) & (df['Operation'] == 'sign') & (df['MessageSizeBytes'] == 16384)]
        sign_1mb = df[(df['Algorithm'] == algo) & (df['Operation'] == 'sign') & (df['MessageSizeBytes'] == 1048576)]
        sign_8mb = df[(df['Algorithm'] == algo) & (df['Operation'] == 'sign') & (df['MessageSizeBytes'] == 8388608)]
        verify_1kb = df[(df['Algorithm'] == algo) & (df['Operation'] == 'verify') & (df['MessageSizeBytes'] == 1024)]
        verify_16kb = df[(df['Algorithm'] == algo) & (df['Operation'] == 'verify') & (df['MessageSizeBytes'] == 16384)]
        verify_1mb = df[(df['Algorithm'] == algo) & (df['Operation'] == 'verify') & (df['MessageSizeBytes'] == 1048576)]
        verify_8mb = df[(df['Algorithm'] == algo) & (df['Operation'] == 'verify') & (df['MessageSizeBytes'] == 8388608)]
        
        categories = ['KeyGen', 'Sign\n1KB', 'Sign\n16KB', 'Sign\n1MB', 'Sign\n8MB', 
                      'Verify\n1KB', 'Verify\n16KB', 'Verify\n1MB', 'Verify\n8MB']
        
        values = []
        values.append(keygen['TimeMS'].values[0] if len(keygen) > 0 else 0)
        values.append(sign_1kb['TimeMS'].values[0] if len(sign_1kb) > 0 else 0)
        values.append(sign_16kb['TimeMS'].values[0] if len(sign_16kb) > 0 else 0)
        values.append(sign_1mb['TimeMS'].values[0] if len(sign_1mb) > 0 else 0)
        values.append(sign_8mb['TimeMS'].values[0] if len(sign_8mb) > 0 else 0)
        values.append(verify_1kb['TimeMS'].values[0] if len(verify_1kb) > 0 else 0)
        values.append(verify_16kb['TimeMS'].values[0] if len(verify_16kb) > 0 else 0)
        values.append(verify_1mb['TimeMS'].values[0] if len(verify_1mb) > 0 else 0)
        values.append(verify_8mb['TimeMS'].values[0] if len(verify_8mb) > 0 else 0)
        
        bars = ax.bar(categories, values, color=color, alpha=0.7)
        ax.set_ylabel('Time (ms)', fontsize=10)
        ax.set_title(title, fontsize=12, fontweight='bold')
        ax.set_xticklabels(categories, rotation=45, ha='right', fontsize=8)
        ax.grid(True, alpha=0.3, axis='y')
        
        # Add value labels for small values
        for bar, val in zip(bars, values):
            if val > 0 and val < 10:
                ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.1,
                       f'{val:.3f}', ha='center', va='bottom', fontsize=7)
            elif val > 0:
                ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
                       f'{val:.2f}', ha='center', va='bottom', fontsize=7)
    
    plt.suptitle('Detailed Performance by Algorithm', fontsize=14, fontweight='bold')
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'comparison_grouped.png'), dpi=150, bbox_inches='tight')
    plt.close()
    print(f"  Saved: comparison_grouped.png")

def plot_radar_comparison(df, output_dir):
    """Radar chart comparing algorithms across metrics"""
    from math import pi
    
    algorithms = ['ECDSA-P256', 'ECDSA-P384', 'RSA-PSS-3072']
    
    # Normalize metrics (lower is better -> invert for radar)
    metrics = ['KeyGen (ms)', 'Sign 1KB (ms)', 'Verify 1KB (ms)']
    
    # Collect values
    values = {}
    for algo in algorithms:
        vals = []
        # KeyGen
        kg = df[(df['Algorithm'] == algo) & (df['Operation'] == 'keygen')]
        vals.append(kg['TimeMS'].values[0] if len(kg) > 0 else 0)
        # Sign 1KB
        sign = df[(df['Algorithm'] == algo) & (df['Operation'] == 'sign') & (df['MessageSizeBytes'] == 1024)]
        vals.append(sign['TimeMS'].values[0] if len(sign) > 0 else 0)
        # Verify 1KB
        verify = df[(df['Algorithm'] == algo) & (df['Operation'] == 'verify') & (df['MessageSizeBytes'] == 1024)]
        vals.append(verify['TimeMS'].values[0] if len(verify) > 0 else 0)
        values[algo] = vals
    
    # Normalize (higher score = better performance)
    max_vals = [max(values[a][i] for a in algorithms) for i in range(3)]
    normalized = {}
    for algo in algorithms:
        norm = [max_vals[i] / values[algo][i] if values[algo][i] > 0 else 0 for i in range(3)]
        normalized[algo] = norm
    
    # Radar chart
    angles = [n / float(len(metrics)) * 2 * pi for n in range(len(metrics))]
    angles += angles[:1]
    
    fig, ax = plt.subplots(figsize=(8, 8), subplot_kw=dict(polar=True))
    
    colors = ['#2ecc71', '#3498db', '#e74c3c']
    for algo, color in zip(algorithms, colors):
        norm_vals = normalized[algo]
        norm_vals += norm_vals[:1]
        ax.plot(angles, norm_vals, 'o-', linewidth=2, label=algo, color=color)
        ax.fill(angles, norm_vals, alpha=0.15, color=color)
    
    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(metrics, fontsize=10)
    ax.set_ylim(0, 1.2)
    ax.set_title('Algorithm Performance Radar Chart (Higher = Better)', fontsize=14, fontweight='bold', pad=20)
    ax.legend(loc='upper right', bbox_to_anchor=(1.3, 1.0))
    ax.grid(True)
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'comparison_radar.png'), dpi=150, bbox_inches='tight')
    plt.close()
    print(f"  Saved: comparison_radar.png")

def plot_speedup_chart(df, output_dir):
    """Speedup chart comparing RSA vs ECDSA"""
    fig, ax = plt.subplots(figsize=(10, 6))
    
    # Get baseline (ECDSA-P256)
    ecdsa_sign = df[(df['Algorithm'] == 'ECDSA-P256') & (df['Operation'] == 'sign')]
    ecdsa_verify = df[(df['Algorithm'] == 'ECDSA-P256') & (df['Operation'] == 'verify')]
    
    rsa_sign = df[(df['Algorithm'] == 'RSA-PSS-3072') & (df['Operation'] == 'sign')]
    rsa_verify = df[(df['Algorithm'] == 'RSA-PSS-3072') & (df['Operation'] == 'verify')]
    
    sizes = [1024, 16384, 1048576, 8388608]
    size_labels = ['1 KB', '16 KB', '1 MB', '8 MB']
    
    sign_speedup = []
    verify_speedup = []
    
    for size in sizes:
        ecdsa_s = ecdsa_sign[ecdsa_sign['MessageSizeBytes'] == size]['TimeMS'].values
        rsa_s = rsa_sign[rsa_sign['MessageSizeBytes'] == size]['TimeMS'].values
        ecdsa_v = ecdsa_verify[ecdsa_verify['MessageSizeBytes'] == size]['TimeMS'].values
        rsa_v = rsa_verify[rsa_verify['MessageSizeBytes'] == size]['TimeMS'].values
        
        if len(ecdsa_s) > 0 and len(rsa_s) > 0:
            sign_speedup.append(rsa_s[0] / ecdsa_s[0])
        if len(ecdsa_v) > 0 and len(rsa_v) > 0:
            verify_speedup.append(ecdsa_v[0] / rsa_v[0])  # RSA verify is faster
    
    x = np.arange(len(sizes))
    width = 0.35
    
    bars1 = ax.bar(x - width/2, sign_speedup, width, label='RSA Sign / ECDSA Sign (RSA slower)', color='#e74c3c', alpha=0.7)
    bars2 = ax.bar(x + width/2, verify_speedup, width, label='ECDSA Verify / RSA Verify (RSA faster)', color='#2ecc71', alpha=0.7)
    
    ax.set_ylabel('Speedup Ratio', fontsize=12)
    ax.set_xlabel('Message Size', fontsize=12)
    ax.set_title('RSA vs ECDSA Performance Comparison', fontsize=14, fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels(size_labels)
    ax.axhline(y=1, color='black', linestyle='--', alpha=0.5)
    ax.legend()
    ax.grid(True, alpha=0.3, axis='y')
    
    # Add value labels
    for bar, val in zip(bars1, sign_speedup):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
               f'{val:.1f}x', ha='center', va='bottom', fontsize=9)
    for bar, val in zip(bars2, verify_speedup):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
               f'{val:.1f}x', ha='center', va='bottom', fontsize=9)
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'comparison_speedup.png'), dpi=150, bbox_inches='tight')
    plt.close()
    print(f"  Saved: comparison_speedup.png")

def main():
    print("=" * 50)
    print("Algorithm Comparison Plotter")
    print("=" * 50)
    
    # Find CSV file
    script_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(script_dir)
    
    csv_file = os.path.join(parent_dir, 'signature_benchmark_results.csv')
    
    if not os.path.exists(csv_file):
        csv_file = 'signature_benchmark_results.csv'
    
    print(f"Loading data from: {csv_file}")
    df = load_data(csv_file)
    
    print(f"Loaded {len(df)} records")
    print("\nGenerating comparison plots...")
    
    # Create output directory
    output_dir = os.path.join(parent_dir, 'benchmark_plots')
    os.makedirs(output_dir, exist_ok=True)
    
    # Generate comparison plots
    plot_algorithm_comparison_bar(df, output_dir)
    plot_algorithm_comparison_grouped(df, output_dir)
    plot_radar_comparison(df, output_dir)
    plot_speedup_chart(df, output_dir)
    
    print(f"\n All comparison plots saved to: {output_dir}")

if __name__ == "__main__":
    main()