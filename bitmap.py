import hashlib, math, os
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
sns.set_theme(style="darkgrid", rc={"figure.figsize": (14,4)})

def load_words():
    with open("./words.txt") as f:
        words = [w.strip() for w in f.readlines()]
    return words

def md5_bit_array(words):
    n = len(words)
    bits = np.zeros((n, 128), dtype=np.uint8)
    for i,w in enumerate(words):
        h = hashlib.md5(w.encode('utf8')).digest()
        # unpackbits yields bits per byte (MSB first inside each byte)
        b = np.unpackbits(np.frombuffer(h, dtype=np.uint8))
        bits[i,:] = b
    return bits

def bit_stats(frac, n):
    se = 0.5 / math.sqrt(n)
    z = (frac - 0.5) / se
    # two-sided p-value from z using erf
    pvals = 2 * (1 - 0.5 * (1 + np.vectorize(math.erf)(np.abs(z)/math.sqrt(2))))
    return z, pvals

def main():
    words = load_words()
    bits = md5_bit_array(words)
    n = bits.shape[0]
    frac = bits.mean(axis=0)   # fraction of ones per bit

    # Plot fraction-of-1s per bit
    plt.figure(figsize=(14,4))
    plt.plot(range(128), frac, marker='o', markersize=3, linewidth=1)
    plt.axhline(0.5, color='k', linestyle='--', alpha=0.5)
    plt.xlabel('MD5 bit index (0 = first/most-significant bit of digest byte 0)')
    plt.ylabel('Fraction of ones across samples')
    plt.title(f'Fraction of 1-bits per MD5 bit position (N={n})')
    plt.tight_layout()
    plt.savefig('md5_bit_fraction.png', dpi=150)
    print("Saved md5_bit_fraction.png")

    # Heatmap of first min(500,n) samples
    rows = min(500, n)
    plt.figure(figsize=(14,6))
    sns.heatmap(bits[:rows,:], cmap='Greys', cbar=False)
    plt.title(f'Heatmap of MD5 bits for first {rows} words (rows=words, cols=bits)')
    plt.xlabel('bit index')
    plt.ylabel('sample index (first rows)')
    plt.tight_layout()
    plt.savefig('md5_bits_heatmap.png', dpi=150)
    print("Saved md5_bits_heatmap.png")

    # Statistical test: z-scores and Bonferroni-corrected significance
    z, p = bit_stats(frac, n)
    alpha = 0.05
    bonf = alpha / 128
    sig_bits = np.where(p < bonf)[0]
    print(f"Bits with p < {alpha}/128 (Bonferroni): {sig_bits.tolist()}")
    # Save a small CSV of results
    import csv
    with open('md5_bit_stats.csv', 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['bit_index','frac_ones','zscore','pvalue','significant_bonf'])
        for i,(fr,zi,pi) in enumerate(zip(frac,z,p)):
            w.writerow([i,float(fr),float(zi),float(pi), int(pi < bonf)])
    print("Saved md5_bit_stats.csv")

if __name__ == "__main__":
    main()