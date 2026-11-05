import struct, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

d = open(r'E:\Test\Temp\cve-2026-43499\kernel_raw.bin', 'rb').read()
n = len(d)


def v2f(v):
    return v - 0xffffff8008080000 + 0x80000


BASE, END = 0x21869e8, 0x2712df8
out = open(r'E:\Test\Temp\cve-2026-43499\triples_dump.txt', 'w', encoding='utf-8')
cnt = 0
off = BASE
while off + 24 <= END:
    a = struct.unpack_from('<Q', d, off)[0]
    b = struct.unpack_from('<Q', d, off + 8)[0]
    c = struct.unpack_from('<Q', d, off + 16)[0]
    if not (a >= 0xffffff0000000000 and b >= 0xffffff0000000000 and 0 < c < 0x100000000):
        break
    fo = v2f(b)
    enc = b''
    if 0 <= fo < n:
        # encoded name: read until \0 (up to 256)
        seg = d[fo:fo + 256]
        nul = seg.find(b'\x00')
        enc = seg[:nul if nul >= 0 else 256]
    out.write(f'{a:#x} {b:#x} {c:#x} {enc.hex()}\n')
    cnt += 1
    off += 24
out.close()
print(f'dumped {cnt} triples -> triples_dump.txt')

# stats: encoded length distribution
lens = []
for line in open(r'E:\Test\Temp\cve-2026-43499\triples_dump.txt', encoding='utf-8'):
    parts = line.split()
    if len(parts) >= 4:
        lens.append(len(parts[3]) // 2)
from collections import Counter
cc = Counter(lens)
print('encoded length distribution (top 15):', cc.most_common(15))
print('total with len>0:', sum(1 for x in lens if x > 0))
