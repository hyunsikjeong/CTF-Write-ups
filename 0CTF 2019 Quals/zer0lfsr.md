# zer0lfsr

We can get $v_{6i + k}$ value from $v_{k}, v_{6 + k}, \ldots v_{42+k}$ in the third LFSR.

So, for each $k​$ from 0 to 5, fix $v_{k}, v_{6 + k}, \ldots v_{42+k}​$ (total 8bits, so 2 ** 8 possibilities), and calculate $v_{6i+k}​$.

The $i$th result bit means that there are two or three ones if it is 1, and there are two or three zeros if it is 0. From this, we can get a special property: If $v_{6i+k}$ and $result_{6i+k}$ differs, we can get the value of the first/second LFSR. It is $\neg v_{6i+k}$.

With this property, run z3 to get satisfying $v_{k}, v_{6 + k}, \ldots v_{42+k}$ values. From those values, calculate the flag.

```python
from z3 import *

with open('keystream', 'rb') as f:
    data = f.read().decode()

arr = []
for d in data:
    t = ord(d)
    temp_arr = []
    for i in range(8):
        temp_arr.append(t % 2)
        t //= 2
    temp_arr.reverse()
    arr.extend(temp_arr)

def getLFSRResult(dist):
    lfsr = [ (1 << i) for i in range(48) ]
    res = []
    for i in range(65536):
        output = lfsr[0] ^ lfsr[dist]
        res.append(output)
        lfsr.append(output)
        lfsr.pop(0)

    return res

res1 = getLFSRResult(25)
res2 = getLFSRResult(34)

def getEq(X, res, val):
    eq = None
    for i in range(48):
        if res & (1 << i) != 0:
            if eq is None:
                eq = X[i]
            else:
                eq = Xor(eq, X[i])
    if val == 0:
        eq = Not(eq)
    return eq

init3 = [ 0 for i in range(48) ]

for dist in range(0, 6):
    for init in range(0, 2 ** 8):
        lfsr = [ (init >> i) & 1 for i in range(8) ]

        X1 = [ Bool("x1_%s" % (i)) for i in range(48) ]
        X2 = [ Bool("x2_%s" % (i)) for i in range(48) ]
        sol1 = Solver()
        sol2 = Solver()

        # for i in range(dist, 65536, 6):
        for i in range(dist, 600 + dist, 6):
            lfsr.append( lfsr[0] ^ lfsr[1] )
            lfsr.pop(0)

            if lfsr[-1] ^ arr[i] == 1:
                sol1.add(getEq(X1, res1[i], arr[i]))
                sol2.add(getEq(X2, res2[i], arr[i]))

        if sol1.check() == sat and sol2.check() == sat:
            for i in range(8):
                init3[ dist + i * 6 ] = (init >> i) & 1

lfsr = [ init3[i] for i in range(48) ]

X1 = [ Bool("x1_%s" % (i)) for i in range(48) ]
X2 = [ Bool("x2_%s" % (i)) for i in range(48) ]
sol1 = Solver()
sol2 = Solver()

for i in range(512): # 65536?
    lfsr.append( lfsr[0] ^ lfsr[6] )
    lfsr.pop(0)

    if lfsr[-1] ^ arr[i] == 1:
        sol1.add(getEq(X1, res1[i], arr[i]))
        sol2.add(getEq(X2, res2[i], arr[i]))

print("Eq all added")

if sol1.check() == unsat or sol2.check() == unsat:
    print("UNSAT!!!!!!!!!!!")
    exit(0)

model1 = sol1.model()
model2 = sol2.model()

init1 = [ 1 if model1.evaluate(X1[j]) else 0 for j in range(48) ]
init2 = [ 1 if model2.evaluate(X2[j]) else 0 for j in range(48) ]

print(init1)
print(init2)
print(init3)

init = [init1, init2, init3]
res = bytes(0)
for i in range(3):
    for j in range(0, 48, 8):
        val = 0
        for k in range(8):
            val <<= 1
            val += init[i][j + k]
        res += bytes([val])

import hashlib
print("flag{"+hashlib.sha256(res).hexdigest()+"}")
```

The flag is `flag{b527e2621131134ec22250cfbca75e8c9f5ae4f40370871fd55910927f66a1b4}`.