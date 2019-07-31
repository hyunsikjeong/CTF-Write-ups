# Fixed Point

Basically, the problem asks `CRC128("flag{X}") = X`, of which `X` is 128bit number which can be represented as string.

`CRC128(P)` is the function in $GF(2^{128})$, and it just get a remainder from dividing $P \times x^{128}$ by some irreducible polynomial. In the binary, a polynomial value is 0xb595cf9c8d708e2166d545cf7cfdd4f9. Also, `CRC128` is coded in reversed form, so we need to reverse `0xb595cf9c8d708e2166d545cf7cfdd4f9`, which is `0x9f2bbf3ef3a2ab6684710eb139f3a9ad`, and can finally get a polynomial:

```
sage: P = PolynomialRing(GF(2), 'x')
sage: n = P('x^128 + x^127 + x^124 + x^123 + x^122 + x^121 + x^120 + x^117 + x^115 + x^113 + x^112 + x^111 
....: + x^109 + x^108 + x^107 + x^106 + x^105 + x^104 + x^101 + x^100 + x^99 + x^98 + x^97 + x^95 + x^94 + 
....: x^93 + x^92 + x^89 + x^88 + x^87 + x^85 + x^81 + x^79 + x^77 + x^75 + x^73 + x^72 + x^70 + x^69 + x^6
....: 6 + x^65 + x^63 + x^58 + x^54 + x^53 + x^52 + x^48 + x^43 + x^42 + x^41 + x^39 + x^37 + x^36 + x^32 +
....:  x^29 + x^28 + x^27 + x^24 + x^23 + x^22 + x^21 + x^20 + x^17 + x^16 + x^15 + x^13 + x^11 + x^8 + x^7
....:  + x^5 + x^3 + x^2 + 1')
sage: R.<a> = GF(2^128, modulus=n)
```

In the binary, CRC calculation is started with `2 ** 128 - 1`, not `0`. So we need to calculate 1. $ ("flag\{" \times x^{128 + 8} + "\}" ) \times x^{128}$ and 2. $(x^{127} + x^{126} + \ldots + x + 1)\times x^{128  + 6 \times 8}$. (`flag{X}` is total 22byte, so we need to push extra 8byte to calculate `2 ** 128 - 1` in the field.) Let's say each value $A$ and $B$. Then we can say: $A+B+X \times x^{128 + 8} + X = 0$. So $X = (A+B) / (x^{136}  + 1)$.

---

We can get `"flag" + "\x00" * 16 + "}"` by:

```python
s = 'flag{' + '\x00' * 16 + '}'

v = 0
for ch in s:
    for i in range(8):
        v <<= 1
        v |= (ord(ch) >> i) & 1

print(v)
```

Be aware that LSB of each character is used as the first bit. The value is `38242421995674019291107961882899594820395629440663742`. 

So, we can get the value of the flag:

```
sage: T.<a> = GF(2^1024)
sage: A = R(P(T.fetch_int(38242421995674019291107961882899594820395629440663742 << 128)))
sage: A
a^127 + a^126 + a^123 + a^121 + a^120 + a^118 + a^117 + a^116 + a^115 + a^114 + a^113 + a^103 + a^102 + a^99 + a^98 + a^95 + a^93 + a^91 + a^90 + a^89 + a^88 + a^87 + a^86 + a^83 + a^79 + a^78 + a^77 + a^75 + a^74 + a^72 + a^71 + a^67 + a^66 + a^63 + a^61 + a^60 + a^59 + a^58 + a^56 + a^55 + a^54 + a^52 + a^50 + a^47 + a^44 + a^43 + a^42 + a^41 + a^33 + a^31 + a^29 + a^27 + a^23 + a^22 + a^19 + a^18 + a^14 + a^10 + a^9 + a^8 + a^7 + a^6 + a^3 + a
sage: B = R(P(T.fetch_int( ( (1 << 128) - 1) << (128 + 6 * 8))))
sage: C = R(P('x^136 + 1'))
sage: ((A+B)/C).integer_representation()
306720065127973829491666368359800108837L
sage: hex(((A+B)/C).integer_representation())
'0xe6c022c39eedef5fa2aaa5f05d5df725L'
```

To get a flag, flip each 8 bits:

```python
flag = 0xe6c022c39eedef5fa2aaa5f05d5df725
flag = format(flag, '0128b')

s = ''
for i in range(0, 128, 8):
    s += format(int(flag[i:i+8][::-1], 2), '02x')
print(s)
```

The flag is `flag{670344c379b7f7fa4555a50fbabaefa4}`.