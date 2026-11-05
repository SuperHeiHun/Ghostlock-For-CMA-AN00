#!/usr/bin/env python3
"""Extract kallsyms from a raw ARM64 kernel Image (4.14, CONFIG_KALLSYMS_BASE_RELATIVE=n).

Layout: [addresses num*8][num_syms u8..u64][names][markers u32*][token_table][token_index u16*256]
Alignment padding may exist between sections -> validate by exact tiling, tolerate small gaps.
"""
import struct, sys

def find_token_tables(data):
    """Locate kallsyms_token_index: 256 LE u16, [0]==0, strictly increasing, small."""
    cands = []
    n = len(data)
    pos = 0
    two_zeros = b'\x00\x00'
    while True:
        pos = data.find(two_zeros, pos, n - 510)
        if pos < 0:
            break
        w = struct.unpack_from('<4H', data, pos)
        if w[0] == 0 and w[1] > w[0] and w[1] <= 0x1000:
            a = struct.unpack_from('<256H', data, pos)
            ok = True
            for i in range(2, 256):
                if a[i] <= a[i-1] or a[i] > 0x1000:
                    ok = False
                    break
            if ok:
                cands.append((pos, a))
        pos += 1
    return cands

def resolve_token_table(data, idx_off, idx):
    """token_table ends right before token_index. Verify exact tiling:
    token i occupies [tt+i_off, tt+i_off_next-1] with null at i_off_next-1."""
    last_off = idx[255]
    for tail in range(1, 24):  # len(last token)+1
        tt = idx_off - (last_off + tail)
        if tt < 0:
            continue
        ok = True
        for i in range(255):
            s = tt + idx[i]
            nul = tt + idx[i+1] - 1
            if nul <= s or nul - s > 21:
                ok = False; break
            if data[nul] != 0:
                ok = False; break
            if any(data[s:nul] == 0 for _ in ()):  # noop guard
                break
        if not ok:
            continue
        # verify first token null: idx[0]==0 -> data[tt] == 0 (empty token 0? token_table
        # starts with empty string for kernel) -- kernel token 0 may be non-empty; only
        # check that string at tt+idx[0] is printable-ish
        seg = data[tt:tt + 32]
        printable = sum(1 for b in seg[:16] if 32 <= b < 127 or b == 0)
        if printable >= 12:
            return tt
    return None

def expand_names(data, names_off, num, tokens):
    syms = []
    p = names_off
    ap = data  # local
    for i in range(num):
        ln = ap[p]
        p += 1
        out = bytearray()
        for j in range(ln):
            out += tokens[ap[p + j]]
        p += ln
        syms.append(out.decode('latin1'))
    return syms, p

def try_extract(data, tt, idx):
    tokens = []
    for i in range(256):
        s = tt + idx[i]
        e = data.index(b'\x00', s)
        tokens.append(data[s:e])
    # scan for num_syms u64 in a window before token_table
    lo = max(0, tt - 16 * 1024 * 1024)
    pos = lo
    while pos < tt - 8:
        num = struct.unpack_from('<Q', data, pos)[0]
        if 30000 <= num <= 200000:
            names_off = pos + 8
            if names_off >= tt:
                pos += 8
                continue
            # sanity: first name length byte must be small
            if data[names_off] > 0x3f:
                pos += 8
                continue
            try:
                syms, names_end = expand_names(data, names_off, num, tokens)
            except IndexError:
                pos += 8
                continue
            gap = tt - names_end
            mcount = (num + 255) // 256
            # allow alignment padding between sections (0..512 bytes)
            if mcount * 4 <= gap <= mcount * 4 + 512:
                addr_off = names_off - 8 - num * 8
                if addr_off >= 0:
                    addrs = struct.unpack_from('<%dQ' % num, data, addr_off)
                    if (addrs[0] > 0xffff000000000000 and
                        all(addrs[i] < addrs[i+1] for i in range(num - 1))):
                        return addr_off, num, syms
        pos += 8
    return None

def main():
    src, dst = sys.argv[1], sys.argv[2]
    data = open(src, 'rb').read()
    print(f"scanning {len(data)} bytes ...")
    cands = find_token_tables(data)
    print(f"token_index candidates: {[hex(c[0]) for c in cands]}")
    for idx_off, idx in cands:
        tt = resolve_token_table(data, idx_off, idx)
        if tt is None:
            continue
        print(f"token_table @ {hex(tt)} (index @ {hex(idx_off)})")
        f = try_extract(data, tt, idx)
        if f:
            addr_off, num, syms = f
            addrs = struct.unpack_from('<%dQ' % num, data, addr_off)
            with open(dst, 'w') as fh:
                for a, s in zip(addrs, syms):
                    t = s[0] if s else '?'
                    nm = s[1:] if len(s) > 1 else ''
                    fh.write('%016x %s %s\n' % (a, t, nm))
            print(f"OK: {num} symbols, addr table @ {hex(addr_off)} -> {dst}")
            want = ('_stext', '_text', '_sdata', 'init_task', 'init_cred', 'selinux_enforcing',
                    'commit_creds', 'prepare_kernel_cred', 'modprobe_path', 'core_pattern',
                    'kmalloc_caches', '__kmalloc', 'configfs_read_file', 'configfs_write_file',
                    'noop_llseek', 'generic_pipe_buf_confirm', 'remove_waiter',
                    'task_blocks_on_rt_mutex', 'rt_mutex_adjust_prio_chain', 'enforcing_setup',
                    'ashmem_init', 'coredump_sysctls')
            print("--- key symbols ---")
            with open(dst) as fh:
                for line in fh:
                    p = line.split()
                    if len(p) >= 3 and p[2] in want:
                        print(line.rstrip())
            return
    raise SystemExit("no valid kallsyms found")

if __name__ == '__main__':
    main()
