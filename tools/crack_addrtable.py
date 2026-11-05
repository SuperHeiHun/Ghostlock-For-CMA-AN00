import struct, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

d = open(r'E:\Test\Temp\cve-2026-43499\kernel_raw.bin', 'rb').read()
START, SIZE = 0x200e000, 0xb000
enc = d[START:START + SIZE]
print(f'encrypted table: {START:#x} len {SIZE} ({SIZE//4} u32s)')

print('--- first 64 bytes ---')
print(' '.join(f'{b:02x}' for b in enc[:64]))

# 1. known plaintext attempt: first kallsyms symbol = _text = 0xffffff8008080000
#    if stored as u32 LE: 00 00 08 80 | ff ff ff ff (low/high halves)
#    if stored as u32 offset from something: try patterns
p0_expected = struct.pack('<II', 0x08080000, 0xffffff80)
print('expected LE u64 of _text:', p0_expected.hex())

# 2. key-period autocorrelation: c[i] ^ c[i+P] small => repeated key + ascending plaintext
print('--- period detection (count of small XOR at distance P) ---')
best = []
for P in range(1, 512):
    cnt = 0
    tot = 0
    for i in range(0, SIZE - 4 * (P + 1), 4):
        ci = struct.unpack_from('<I', enc, i)[0]
        cj = struct.unpack_from('<I', enc, i + 4 * P)[0]
        x = ci ^ cj
        tot += 1
        if x < 0x1000000:
            cnt += 1
    if tot and cnt / tot > 0.5:
        best.append((P, cnt, tot))
for P, c, t in best[:12]:
    print(f'  period {P} (u32 steps): {c}/{t} small-xor')
if not best:
    print('  no period found in u32 view')

# 3. byte-level period check (XOR key on bytes)
print('--- byte-level period ---')
bestb = []
for P in range(1, 512):
    cnt = sum(1 for i in range(SIZE - P) if (enc[i] ^ enc[i + P]) == 0)
    if cnt > SIZE // 8:
        bestb.append((P, cnt))
for P, c in bestb[:10]:
    print(f'  byte period {P}: {c} zero-xors')
if not bestb:
    print('  none')
