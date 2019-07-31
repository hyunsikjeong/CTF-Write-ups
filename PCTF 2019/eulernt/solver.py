import math
import gmpy2

primes = [3, 5, 7, 19, 29, 37, 43, 47,
          59, 61, 89, 97, 101, 103, 107,
          109, 167, 173, 179, 181, 191,
          193, 197, 199, 211, 223, 227,
          229, 233, 239, 241, 251, 257,
          263, 269, 271, 277, 281, 283,
          293, 307, 311, 313, 317, 331]

v = 1
for p in primes:
    v *= p

N = 1
for i in range(2, 333):
    N *= i

Nv_root = gmpy2.isqrt(N // v)
v_root = gmpy2.isqrt(v)

# Rough upper limit
lim = v_root + v_root // 10000
primes = [3, 5, 7, 11, 13, 17, 19, 23]

def backtrack(idx, val):
    if idx == len(primes):
        lg = int(math.log(v_root, 2) - math.log(val, 2))
        final = val * (2 ** lg) * Nv_root
        fstr = str(final)
        if len(fstr) == 349 and fstr[:8] == '32147263':
            print(final)
        final *= 2
        fstr = str(final)
        if len(fstr) == 349 and fstr[:8] == '32147263':
            print(final)
        return

    while True:
        val *= primes[idx]
        if val > lim:
            return
        backtrack(idx + 1, val)

backtrack(0, 1)
