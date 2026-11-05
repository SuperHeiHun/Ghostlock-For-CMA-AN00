import struct, sys, lzma, bz2, hashlib

PAYLOAD = r'E:\Test\Temp\cve-2026-43499\payload.bin'
OUT = r'E:\Test\Temp\cve-2026-43499\boot.img'
TARGET = sys.argv[1] if len(sys.argv) > 1 else 'boot'
BLOCK = 4096


def read_varint(data, pos):
    result, shift = 0, 0
    while True:
        b = data[pos]
        result |= (b & 0x7F) << shift
        pos += 1
        if not (b & 0x80):
            return result, pos
        shift += 7


def parse_pb(data):
    pos, out = 0, []
    n = len(data)
    while pos < n:
        tag, pos = read_varint(data, pos)
        field, wt = tag >> 3, tag & 7
        if wt == 0:
            val, pos = read_varint(data, pos)
        elif wt == 1:
            val = data[pos:pos+8]; pos += 8
        elif wt == 2:
            ln, pos = read_varint(data, pos)
            val = data[pos:pos+ln]; pos += ln
        elif wt == 5:
            val = data[pos:pos+4]; pos += 4
        else:
            raise ValueError(f'wire {wt} @ {pos}')
        out.append((field, wt, val))
    return out


f = open(PAYLOAD, 'rb')
f.seek(24)
m = f.read(226799)
blob_base = 227090

target_ops = []
for fl, w, v in parse_pb(m):
    if fl != 13 or w != 2:
        continue
    name = None
    ops = []
    for f2, w2, v2 in parse_pb(v):
        if f2 == 1 and w2 == 2:
            name = v2.decode()
        elif f2 == 8 and w2 == 2:
            op = {'type': 0, 'data_offset': 0, 'data_length': 0, 'extents': [], 'sha': None}
            for f3, w3, v3 in parse_pb(v2):
                if f3 == 1 and w3 == 0:
                    op['type'] = v3
                elif f3 == 2 and w3 == 0:
                    op['data_offset'] = v3
                elif f3 == 3 and w3 == 0:
                    op['data_length'] = v3
                elif f3 == 6 and w3 == 2:
                    ext = {'start': 0, 'num': 0}
                    for f4, w4, v4 in parse_pb(v3):
                        if f4 == 1 and w4 == 0:
                            ext['start'] = v4
                        elif f4 == 2 and w4 == 0:
                            ext['num'] = v4
                    op['extents'].append(ext)
                elif f3 == 8 and w3 == 2:
                    op['sha'] = v3
            ops.append(op)
    if name:
        target_ops = (name, ops)
        if name == TARGET:
            break

name, ops = target_ops
print(f'extracting partition: {name}, {len(ops)} operations')
out = open(OUT, 'wb')
total = 0
for idx, op in enumerate(ops):
    f.seek(blob_base + op['data_offset'])
    data = f.read(op['data_length'])
    t = op['type']
    if t == 0:
        chunk = data
    elif t == 1:
        chunk = bz2.decompress(data)
    elif t == 8:
        chunk = lzma.decompress(data)
    elif t == 6:
        chunk = b'\x00' * sum(e['num'] * BLOCK for e in op['extents'])
    else:
        raise SystemExit(f'unsupported op type {t} at {idx}')
    if op['sha']:
        got = hashlib.sha256(data).hexdigest()
        want = op['sha'].hex()
        ok = 'OK' if got == want else f'MISMATCH want={want}'
        print(f'  op{idx}: type={t} in={op["data_length"]:,} out={len(chunk):,} sha[{ok}]')
    for ext in op['extents']:
        offset = ext['start'] * BLOCK
        length = ext['num'] * BLOCK
        out.seek(offset)
        out.write(chunk[:length] if length <= len(chunk) else chunk.ljust(length, b'\x00'))
        total = max(total, offset + length)
out.close()
print(f'boot.img written, {total:,} bytes (={total//BLOCK} blocks)')
