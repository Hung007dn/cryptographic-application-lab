#!/usr/bin/env python3

import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import os
import sys

def load_data(csv_file):
    if not os.path.exists(csv_file):
        print(f"Error: {csv_file} not found!")
        sys.exit(1)
    return pd.read_csv(csv_file)

def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(script_dir)
    csv_file = os.path.join(parent_dir, 'signature_benchmark_results.csv')
    
    if not os.path.exists(csv_file):
        csv_file = 'signature_benchmark_results.csv'
    
    df = load_data(csv_file)
    
    output_dir = os.path.join(parent_dir, 'benchmark_plots')
    os.makedirs(output_dir, exist_ok=True)
    
    # Filter for sign/verify operations with varying message sizes
    sign_data = df[df['Operation'] == 'sign']
    verify_data = df[df['Operation'] == 'verify']
    
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    
    # ECDSA-P256
    ax = axes[0, 0]
    ecdsa_sign = sign_data[sign_data['Algorithm'] == 'ECDSA-P256']
    ecdsa_verify = verify_data[verify_data['Algorithm'] == 'ECDSA-P256']
    
    sizes = ecdsa_sign['MessageSizeBytes'].values / 1024
    ax.plot(sizes, ecdsa_sign['TimeMS'].values, 'o-', label='Sign', linewidth=2, markersize=8)
    ax.plot(sizes, ecdsa_verify['TimeMS'].values, 's-', label='Verify', linewidth=2, markersize=8)
    ax.set_xlabel('Message Size (KB)')
    ax.set_ylabel('Time (ms)')
    ax.set_title('ECDSA-P256 Latency')
    ax.legend()
    ax.grid(True, alpha=0.3)
    
    # ECDSA-P384
    ax = axes[0, 1]
    ecdsa_sign = sign_data[sign_data['Algorithm'] == 'ECDSA-P384']
    ecdsa_verify = verify_data[verify_data['Algorithm'] == 'ECDSA-P384']
    
    sizes = ecdsa_sign['MessageSizeBytes'].values / 1024
    ax.plot(sizes, ecdsa_sign['TimeMS'].values, 'o-', label='Sign', linewidth=2, markersize=8)
    ax.plot(sizes, ecdsa_verify['TimeMS'].values, 's-', label='Verify', linewidth=2, markersize=8)
    ax.set_xlabel('Message Size (KB)')
    ax.set_ylabel('Time (ms)')
    ax.set_title('ECDSA-P384 Latency')
    ax.legend()
    ax.grid(True, alpha=0.3)
    
    # RSA-PSS-3072
    ax = axes[1, 0]
    rsa_sign = sign_data[sign_data['Algorithm'] == 'RSA-PSS-3072']
    rsa_verify = verify_data[verify_data['Algorithm'] == 'RSA-PSS-3072']
    
    sizes = rsa_sign['MessageSizeBytes'].values / 1024
    ax.plot(sizes, rsa_sign['TimeMS'].values, 'o-', label='Sign', linewidth=2, markersize=8)
    ax.plot(sizes, rsa_verify['TimeMS'].values, 's-', label='Verify', linewidth=2, markersize=8)
    ax.set_xlabel('Message Size (KB)')
    ax.set_ylabel('Time (ms)')
    ax.set_title('RSA-PSS-3072 Latency')
    ax.legend()
    ax.grid(True, alpha=0.3)
    
    # Comparison
    ax = axes[1, 1]
    for algo in ['ECDSA-P256', 'ECDSA-P384', 'RSA-PSS-3072']:
        algo_data = sign_data[sign_data['Algorithm'] == algo]
        sizes = algo_data['MessageSizeBytes'].values / 1024
        ax.plot(sizes, algo_data['TimeMS'].values, 'o-', label=f'{algo} (Sign)', linewidth=2, markersize=6)
    
    ax.set_xlabel('Message Size (KB)')
    ax.set_ylabel('Time (ms)')
    ax.set_title('Signing Latency Comparison')
    ax.legend(fontsize=8)
    ax.grid(True, alpha=0.3)
    
    plt.suptitle('Signature Latency Analysis', fontsize=14, fontweight='bold')
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'latency_analysis.png'), dpi=150)
    plt.close()
    
    print(f" Saved: latency_analysis.png")

if __name__ == "__main__":
    main()