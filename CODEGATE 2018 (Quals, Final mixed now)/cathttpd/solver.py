
# v25 = 7023739967326218356

# v26 = 7237377322690830659
# v27 = 7237412644501860931

iv = [0x73316874, 0x61795649]

key1 = [0x68746143, 0x64705454]
key2 = [0x68743243, 0x64707474]

outputs = [ [0x13570a56, 0x4b0957b6],
            [0x97f23069, 0x36a40677],
            [0xbdc64767, 0x5b5d42ec],
            [0x327fc73d, 0x0266c6bb],
            [0xd6423da8, 0x49a0f56c],
            [0x8b5fb6b0, 0xe829d376],
            [0xfb55afbb, 0xdb110091] ]

def subblock(p, q, key, stage):
    v3 = (-1640531527) * (stage+1)
    v3 %= 0x100000000

    p -= (q + v3) ^ (16 * q + key[0]) ^ ( (q>>5) + key[1])
    p %= 0x100000000

    return p


flag = ""

for i in range(7):
    p, q = outputs[i]
    for j in range(0x20):
        q = subblock(q, p, key2, 0x1F-j)
        p = subblock(p, q, key1, 0x1F-j)

    if i == 0:
        p ^= iv[0]
        q ^= iv[1]
    else:
        p ^= outputs[i-1][0]
        q ^= outputs[i-1][1]

    
    for j in range(4):
        flag += chr(p % 256)
        p = p // 256

    for j in range(4):
        flag += chr(q % 256)
        q = q // 256

print(flag)
