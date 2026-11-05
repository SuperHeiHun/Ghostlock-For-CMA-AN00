#!/usr/bin/env python3
"""boot.img -> raw kernel extractor (Android boot image v0/v1/v2, gzip/lz4/raw kernel)."""
import struct, sys, gzip, io, os

MAGIC = b'ANDROID!'

def find_boot_header(data):
    """Return (header_dict, kernel_offset) supporting MTK headers (magic at 0 or 512)."""
    for off in (0, 512, 2048):
        if data[off:off+8] == MAGIC:
            hdr = parse_header(data, off)
            return hdr, off
    # MTK: magic string then header at 512? some MTK boot.img: 'ANDROID!' at 512 with pre-header
    idx = data.find(MAGIC)
    if idx >= 0:
        return parse_header(data, idx), idx
    raise SystemExit('no ANDROID magic found')

def parse_header(data, off):
    (magic, kernel_size, kernel_addr, ramdisk_size, ramdisk_addr,
     second_size, second_addr, tags_addr, page_size, dt_size,
     unused, os_ver, hdr_ver) = struct.unpack_from('<8s9I2HI', data, off)
    # v0: 10th field dt_size; header version at offset 40 for v1/v2
    h = dict(kernel_size=kernel_size, kernel_addr=kernel_addr,
             ramdisk_size=ramdisk_size, page_size=page_size,
             header_version=hdr_ver)
    # v3 has different layout; detect: for v3, field layout differs, but 4.14 Android11 -> v0/v1/v2
    page = page_size if 512 <= page_size <= 8192 else 2048
    n = (off + page - 1) // page * page  # first page
    kernel_off = n + page
    # kernel occupies [n+page, n+page+kernel_size) rounded to page; v0: ramdisk after
    h['kernel_offset'] = kernel_off
    return h

def try_decompress(blob):
    # gzip (zlib stream decode ignores trailing garbage, e.g. MTK padding)
    if blob[:2] == b'\x1f\x8b':
        import zlib
        d = zlib.decompressobj(31)
        out = d.decompress(blob)
        out += d.flush()
        return 'gzip', out
    # raw kernel (ARM64 Image: magic 'ARM\x64' at +0x38)
    if len(blob) > 0x40 and blob[0x38:0x3c] == b'ARM\x64':
        return 'raw', blob
    # lz4 legacy/frame
    if blob[:4] in (b'\x04\x22\x4d\x18', b'\x02!L\x18', b'\x02!M\x18'):
        import lz4.frame
        return 'lz4', lz4.frame.decompress(blob)
    # lzma/xz
    if blob[:6] == b'\xfd7zXZ':
        import lzma
        return 'xz', lzma.decompress(blob)
    # brute: scan for gzip magic within first 1KB (some packers offset it)
    for i in range(min(1024, len(blob)-2)):
        if blob[i:i+2] == b'\x1f\x8b':
            try:
                return 'gzip@%d' % i, gzip.decompress(blob[i:])
            except Exception:
                pass
    return None, None

def main():
    src = sys.argv[1]
    dst = sys.argv[2] if len(sys.argv) > 2 else 'kernel_raw.bin'
    data = open(src, 'rb').read()
    hdr, base = find_boot_header(data)
    print(f"boot header @ {base}: {hdr}")
    blob = data[hdr['kernel_offset']:hdr['kernel_offset'] + hdr['kernel_size'] + 4096]
    kind, kern = try_decompress(blob)
    if kern is None:
        raise SystemExit('cannot decompress kernel blob; head=%r' % blob[:16])
    open(dst, 'wb').write(kern)
    print(f"kernel: {kind}, {len(kern)} bytes -> {dst}")
    if len(kern) > 0x40:
        print("ARM64 magic @0x38:", kern[0x38:0x3c])
        print("build id:", kern[0x40:0x60] if kern[0x40:0x44]==b'Android' else kern[:32])

if __name__ == '__main__':
    main()
