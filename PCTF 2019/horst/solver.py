import os
import random
from hashlib import sha1
from horst import Permutation

with open('data.txt', 'r') as f:
    data = eval(f.read())

(x1, y1), (t1, u1) = data[0]
(x2, y2), (t2, u2) = data[1]

# Left-hand side: l
l1, l2 = x1.inv() * u1, x2.inv() * u2
# Right-hand side: k^{-1} r k
r1, r2 = y1 * t1, y2 * t2

k = [-1 for _ in range(64)]
kinv = [-1 for _ in range(64)]
called = []

def backtrack(idx):
    if idx in called:
        st = set(range(64)) - set(called)
        if len(st) == 0:
            k_str = str(Permutation(k)).encode('ascii')
            print("PCTF{%s}" % sha1(k_str).hexdigest())
            exit(0)
        backtrack(min(st))
        return

    called.append(idx)
    p, q = l1[idx], l2[idx]

    # Running backtracking for: `l = k^{-1} r k`
    # If `l[idx] = p`, then `k[r[kinv[idx]]] = p`
    # Let's say `kinv[idx] = a, r[a] = b, k[b] = p`.
    # Just do possible all the (a, b) pairs for backtracking.

    # Possible `a` values
    if kinv[idx] != -1:
        arange = [kinv[idx]]
    else:
        # Values which are not used
        arange = list(set(range(64)) - set(kinv))

    for a in arange:

        # If k[a] is assigned, flag_ka is True.
        flag_ka = False
        if kinv[idx] == -1:
            flag_ka = True
            kinv[idx] = a
            k[a] = idx

        b = r1[a]
        c = r2[a]
        
        if ((k[b] != -1 and k[b] != p) or (kinv[p] != -1 and kinv[p] != b)
           or (k[c] != -1 and k[c] != q) or (kinv[q] != -1 and kinv[q] != c)):
            # Set back
            if flag_ka:
                kinv[idx] = -1
                k[a] = -1
            continue

        # If k[b] is assigned, flag_kb is True, and so on.
        flag_kb, flag_kc = False, False
        if k[b] == -1:
            flag_kb = True
            k[b] = p
            kinv[p] = b
        if k[c] == -1:
            flag_kc = True
            k[c] = q
            kinv[q] = c
            
        backtrack(p)
        
        # Set back
        if flag_kc:
            k[c] = -1
            kinv[q] = -1
        if flag_kb:
            k[b] = -1
            kinv[p] = -1
        if flag_ka:
            kinv[idx] = -1
            k[a] = -1

    called.pop()

backtrack(0)
