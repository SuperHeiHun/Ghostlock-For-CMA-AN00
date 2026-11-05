import struct, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

d = open(r'E:\Test\Temp\cve-2026-43499\kernel_raw.bin', 'rb').read()
n = len(d)

addends = [
    ('enc_table(_text-rel)', 0xa08e000 - 0x80000),
    ('names(_text-rel)', 0xa09085a - 0x80000),
    ('whitelist(_text-rel)', 0xa057000 - 0x80000),
    ('checked(_text-rel)', 0xa060000 - 0x80000),
    ('stream(_text-rel)', 0x9769310 - 0x80000),
]

for desc, addend in addends:
    for width, fmt in (('u64', '<Q'), ('u32', '<I')):
        needle = struct.pack(fmt, addend)
        pos, hits = 0, []
        while True:
            pos = d.find(needle, pos)
            if pos < 0:
                break
            hits.append(pos)
            pos += 1
        if hits:
            print(f'{desc} [{width} {addend:#x}]: {len(hits)} hits')
            for h in hits[:4]:
                vaddr = h - 0x80000 + 0xffffff8008080000
                print(f'   @file {h:#x} (vaddr {vaddr:#x})')

print('=== RELA table scan ===')
runs = []
i = 0x80000
while i + 24 <= n:
    a = struct.unpack_from('<Q', d, i)[0]
    if a < 0x3308000:
        j = i
        c = 0
        while j + 24 <= n:
            ro = struct.unpack_from('<Q', d, j)[0]
            ri = struct.unpack_from('<Q', d, j + 8)[0]
            ra = struct.unpack_from('<Q', d, j + 16)[0]
            if ro < 0x3308000 and (ri >> 32) == 0 and ra < 0x3308000:
                c += 1
                j += 24
            else:
                break
        if c >= 200:
            runs.append((i, c))
            i = j
            continue
        i += 8
    else:
        i += 8
print(f'RELA-like runs >=200: {[(hex(o), c) for o, c in runs[:8]]}')
