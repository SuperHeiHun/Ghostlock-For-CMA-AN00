import math, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

d = open(r'E:\Test\Temp\cve-2026-43499\kernel_raw.bin', 'rb').read()
n = len(d)
WIN = 8192
STEP = 4096


def entropy(seg):
    if not seg:
        return 0
    freq = [0] * 256
    for b in seg:
        freq[b] += 1
    ln = len(seg)
    e = 0.0
    for c in freq:
        if c:
            p = c / ln
            e -= p * math.log2(p)
    return e


results = []
for base in range(0, n - WIN, STEP):
    e = entropy(d[base:base + WIN])
    if e > 7.0:
        results.append((base, e))

# merge
merged = []
for base, e in results:
    if merged and base - merged[-1][1] <= STEP:
        merged[-1][1] = base + WIN
        merged[-1][2] = max(merged[-1][2], e)
    else:
        merged.append([base, base + WIN, e])

print(f'high-entropy regions (>7.0 bits/byte, {WIN}B windows): {len(merged)}')
for a, b, e in merged:
    print(f'  {a:#x} .. {b:#x}  size={b-a:,}  peak={e:.2f}')
