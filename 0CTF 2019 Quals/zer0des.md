# zer0des

Just implement the part 4.3 of [this paper](http://www.cs.technion.ac.il/~biham/Reports/differential-cryptanalysis-of-the-data-encryption-standard-biham-shamir-authors-latex-version.pdf).

There are three stages:

1. Get 30 bits of the subkey of the stage 8. (18bit from $S_6, S_7, S_8$, then 12bit from $S_2, S_5$)
2. Get the other 18 bits of the subkey of the stage 8.
3. Get the unknown 8bit of the key itself by brute-force attack.

---

## 0. Local generator

Generate key pairs, of which concept is described in the paper.

```python
import os,random,sys,string
import des

def genkey():
    tmp = os.urandom(8)
    key = ''
    for ch in tmp:
        key += chr(ord(ch)&0xfe)
    return key

key = genkey()

with open('key', 'wb') as f:
    f.write(key)

def gen_cryptpair():
    first = os.urandom(8)
    second = ''
    diff = [0x40, 0x5C, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00]
    for i in range(8):
        second += chr( ord(first[i]) ^ diff[i] )

    first_bits = des.str_to_bits(first)
    second_bits = des.str_to_bits(second)

    first = des.bits_to_str([first_bits[x-1] for x in des.IP_1])
    second = des.bits_to_str([second_bits[x-1] for x in des.IP_1])
    
    return (first, second)

def encrypt_wo_IP(msg, key):
    enc = des.encrypt(msg, key)
    enc_bits = des.str_to_bits(enc)
    enc = des.bits_to_str([enc_bits[x-1] for x in des.IP])

    return enc

f = open('data', 'wb')

for i in xrange(150000):
    if i % 1000 == 0:
        print("Writing", i)
    first, second = gen_cryptpair()
    first_enc = encrypt_wo_IP(first, key)
    second_enc = encrypt_wo_IP(second, key)

    f.write(first)
    f.write(second)
    f.write(first_enc)
    f.write(second_enc)

f.close()
```

---

## 1. Stage 1

```python
import os,random,sys,string
import des

# 0. Preprocess

def sbox_out(num, input):
    bits = [ (input >> (5 - i)) & 1 for i in range(6)]
    row = bits[0]*2+bits[5]
    col = bits[1]*8+bits[2]*4+bits[3]*2+bits[4]
    return des.SBOX[num][row][col]

def encrypt_wo_IP(msg, key):
    enc = des.encrypt(msg, key)
    enc_bits = des.str_to_bits(enc)
    enc = des.bits_to_str([enc_bits[x-1] for x in des.IP])

    return enc

preproc_sI = [ dict() for _ in range(8) ]

for boxnum in range(8):
    for input1 in range(2 ** 6):
        output1 = sbox_out(boxnum, input1)
        for input2 in range(2 ** 6):
            output2 = sbox_out(boxnum, input2)
            input_diff = input1 ^ input2
            output_diff = output1 ^ output2

            diff_pair = (input_diff, output_diff)
            if diff_pair not in preproc_sI[boxnum]:
                preproc_sI[boxnum][diff_pair] = set()
            if input1 not in preproc_sI[boxnum][diff_pair]:
                preproc_sI[boxnum][diff_pair].add(input1)

P_rev = [0 for i in range(32)]
for i in range(32):
    P_rev[ des.P[i] - 1 ] = i

# 1. Get 30bit of K8

key678_count = dict()
key678_list = dict()

datafile = open('data', 'rb')

for count in xrange(1,150001):
    if count % 5000 == 0:
        print("Count: ", count)
    

    first = datafile.read(8)
    second = datafile.read(8)
    first_enc = datafile.read(8)
    second_enc = datafile.read(8)
    
    h = des.str_to_bits(first_enc)[32:]
    h_prime = des.xor_bits(des.str_to_bits(first_enc)[32:], des.str_to_bits(second_enc)[32:])
    H_prime = des.xor_bits(des.str_to_bits(first_enc)[:32], des.str_to_bits(second_enc)[:32])

    SEh = [h[x-1] for x in des.E]
    SIh_prime = [h_prime[x-1] for x in des.E]
    SOh_prime = [H_prime[x] for x in P_rev]

    keys = [[], [], [], [], []]
    failed = False
    for boxnum in [2, 5, 6, 7, 8]:
        seg0 = SEh[ (boxnum - 1) * 6 : boxnum * 6 ]
        seg1 = SIh_prime[ (boxnum - 1) * 6 : boxnum * 6 ]
        seg2 = SOh_prime[ (boxnum - 1) * 4 : boxnum * 4 ]

        seh = int(''.join(map(str, seg0)), 2)
        inp = int(''.join(map(str, seg1)), 2)
        out = int(''.join(map(str, seg2)), 2)

        if (inp, out) not in preproc_sI[boxnum - 1]:
            failed = True
            break

        for pos_inp in preproc_sI[boxnum - 1][(inp, out)]:
            if boxnum == 2:
                keys[0].append(seh ^ pos_inp)
            else:
                keys[boxnum - 4].append(seh ^ pos_inp)

    if failed: continue

    for key_6 in keys[2]:
        for key_7 in keys[3]:
            for key_8 in keys[4]:
                key_678 = (key_6, key_7, key_8)
                if key_678 not in key678_count:
                    key678_count[key_678] = 1
                    key678_list[key_678] = [(first, second, first_enc, second_enc, keys[0], keys[1])]
                else:
                    key678_count[key_678] += 1
                    key678_list[key_678].append((first, second, first_enc, second_enc, keys[0], keys[1]))

import operator
key_678 = max(key678_count.iteritems(), key=operator.itemgetter(1))[0]
key678_values = key678_list[key_678]
print(key_678)
print(len(key678_values))

key25_count = dict()
for (_, _, _, _, keys_2, keys_5) in key678_values:
    for key_2 in keys_2:
        for key_5 in keys_5:
            if (key_2, key_5) in key25_count:
                key25_count[(key_2, key_5)] += 1
            else:
                key25_count[(key_2, key_5)] = 1
key_25 = max(key25_count.iteritems(), key=operator.itemgetter(1))[0]
print(key_25)

pos_inouts = []
for (f, s, fe, se, _, _) in key678_values:
    pos_inouts.append( (f, s, fe, se) )

with open('stage1', 'w') as f:
    key_25678 = (key_25[0], key_25[1], key_678[0], key_678[1], key_678[2])
    f.write(str(key_25678) + '\n')
    f.write(str(pos_inouts) + '\n')
```

## 2. Stage 2

```python
import os,random,sys,string
import des

with open('stage1', 'r') as f:
    key_25678 = eval(f.readline())
    pos_inouts = eval(f.readline())

print(key_25678)

def get_subkey_pos():
    kbits = [ i for i in range(56) ]
    left = kbits[:28]
    right = kbits[28:]
    subkeys = []
    R = des.R
    PC_2 = des.PC_2
    for i in range(des.ROUNDS):
        left = left[R[i]:]+left[:R[i]]
        right = right[R[i]:]+right[:R[i]]
        cur = left + right
        subkeys.append([cur[x-1] for x in PC_2])
    return subkeys

subkey_pos = get_subkey_pos()
subkey_map_78 = [None for i in range(48)]
for i in range(48):
    pivot = subkey_pos[7][i]
    for j in range(48):
        if pivot == subkey_pos[6][j]:
            subkey_map_78[j] = i

maxval, maxK8 = 0, None
def conv_6bitkey(key):
    bits = [ (key >> (5 - i)) & 1 for i in range(6)]
    return bits

K8 = [0 for _ in range(6)] + conv_6bitkey(key_25678[0])
K8 = K8 + [0 for _ in range(12)]
K8 = K8 + conv_6bitkey(key_25678[1]) + conv_6bitkey(key_25678[2])
K8 = K8 + conv_6bitkey(key_25678[3]) + conv_6bitkey(key_25678[4])

pos_outs = []
for (_, _, first_enc, second_enc) in pos_inouts:
    first_enc_bits = des.str_to_bits(first_enc)
    second_enc_bits = des.str_to_bits(second_enc)

    f_prime = des.str_to_bits("\x40\x5C\x00\x00")
    h_prime = des.xor_bits(first_enc_bits[32:], second_enc_bits[32:])
    G_prime = des.xor_bits(f_prime, h_prime)

    pos_outs.append( (first_enc_bits, second_enc_bits, G_prime) )

S238_idxs = []
for idx in xrange(32):
    if (des.P[idx] >= 5 and des.P[idx] <= 12) or (des.P[idx] >= 29):
        S238_idxs.append(idx)

for rest in xrange(2 ** 18):
    for i in range(6):
        K8[i] = (rest >> (17 - i)) & 1
    for i in range(12):
        K8[12 + i] = (rest >> (11 - i)) & 1
    # Temporal K7, for getting S2, S3, S8
    K7 = [ 0 if subkey_map_78[i] is None else K8[subkey_map_78[i]] for i in range(48)]

    count = 0
    for (first_enc, second_enc, G_prime) in pos_outs: # first_enc_bits, second_enc_bits
        H = des.F(first_enc[32:], K8)
        Hstar = des.F(second_enc[32:], K8)
        g = des.xor_bits(H, first_enc[:32])
        gstar = des.xor_bits(Hstar, second_enc[:32])
        G_temp, Gstar_temp = des.F(g, K7), des.F(gstar, K7)
        G_prime_temp = des.xor_bits(G_temp, Gstar_temp)

        flag = True
        for idx in S238_idxs:
            if G_prime_temp[idx] != G_prime[idx]:
                flag = False
                break

        if flag:
            count += 1

    if rest % 1000 == 0:
        print(rest, maxval, maxK8)
    if maxval < count:
        maxval = count
        maxK8 = K8[:]

    # Early return, maybe dangerous
    if maxval > 10:
        break

print(maxval, maxK8)

with open('stage2', 'w') as f:
    f.write(str(maxK8))
```

## 3. Stage 3

```python
import os,random,sys,string
import des

with open('stage1', 'r') as f:
    f.readline()
    pos_inouts = eval(f.readline())

with open('stage2', 'r') as f:
    K8 = eval(f.read())

def encrypt_without_IP(msg, key):
    enc = des.encrypt(msg, key)
    enc_bits = des.str_to_bits(enc)
    enc = des.bits_to_str([enc_bits[x-1] for x in des.IP])

    return enc

def get_subkey_pos():
    kbits = [ i for i in range(64) ]
    kbits = [ kbits[x-1] for x in des.PC_1 ]
    left = kbits[:28]
    right = kbits[28:]
    subkeys = []
    R = des.R
    PC_2 = des.PC_2
    for i in range(des.ROUNDS):
        left = left[R[i]:]+left[:R[i]]
        right = right[R[i]:]+right[:R[i]]
        cur = left + right
        subkeys.append([cur[x-1] for x in PC_2])
    return subkeys

subkey_pos = get_subkey_pos()

solveKey = [ None for i in range(64) ]
for i in xrange(7, 64, 8):
    solveKey[i] = 0

for i in xrange(48):
    solveKey[ subkey_pos[7][i] ] = K8[i]

empty_idxs = []
for i in xrange(64):
    if solveKey[i] is None:
        empty_idxs.append(i)

for rest in xrange(2 ** 8):
    for i in xrange(8):
        t = (rest >> i) & 1
        solveKey[ empty_idxs[i] ] = t

    (first, second, first_enc, second_enc) = pos_inouts[0]
    if first_enc == encrypt_without_IP(first, des.bits_to_str(solveKey)) and second_enc == encrypt_without_IP(second, des.bits_to_str(solveKey)):
        with open('stage3', 'wb') as f:
            f.write(des.bits_to_str(solveKey))
```

## 4. Solver

To solve fast, run those three code files by PyPy. On the other hand, I wanted to use pwntools with Python 2, which is not compatible with PyPy as I know. So I wrote the solver like this:

```python
from pwn import *
import string
from hashlib import sha256
import os,random,sys,string
import des

r = remote('111.186.63.15', 10001)

l = r.readuntil('\n')

sha256value = l.split('== ')[1][:64]
sha256input = l.split('(XXXX+')[1].split(') == ')[0]

print(l)

def select(idx, s):
    if idx == 4:
        if sha256(s).hexdigest() == sha256value:
            return s
        else:
            return None
    for ch in string.printable.strip():
        ret = select(idx + 1, ch + s)
        if ret is not None:
            return ret
    return None

proof = select(0, sha256input)

r.sendline(proof[:4])

print("Proof clear: ", proof)

def gen_cryptpair():
    first = os.urandom(8)
    second = ''
    diff = [0x40, 0x5C, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00]
    for i in range(8):
        second += chr( ord(first[i]) ^ diff[i] )

    first_bits = des.str_to_bits(first)
    second_bits = des.str_to_bits(second)

    first = des.bits_to_str([first_bits[x-1] for x in des.IP_1])
    second = des.bits_to_str([second_bits[x-1] for x in des.IP_1])
    
    return (first, second)

def send_to_server(r, msg):
    r.sendline(msg)
    enc = r.recvuntil('\n')[:-1].decode('hex')
    assert len(enc) == 8 * 1250
    enc_bits = des.str_to_bits(enc)

    enc = ""
    for i in xrange(1250):
        enc += des.bits_to_str([enc_bits[x-1 + 64 * i] for x in des.IP])

    return enc

f = open('data', 'wb')

for i in xrange(240):
    print("Getting pack #", i)
    r.recvuntil("plaintext(hex): ")
    pairs = []
    msg = ""
    for j in xrange(625):
        first, second = gen_cryptpair()
        pairs.append((first, second))
        msg += first.encode('hex') + second.encode('hex')
    
    enc = send_to_server(r, msg)

    for j in xrange(625):
        f.write(pairs[j][0])
        f.write(pairs[j][1])
        f.write(enc[16 * j : 16 * j + 8])
        f.write(enc[16 * j + 8 : 16 * j + 16])

f.close()

os.system('./pypy2.7/bin/pypy stage1.py')
print("stage1 finished!")

os.system('./pypy2.7/bin/pypy stage2.py')
print("stage2 finished!")

os.system('./pypy2.7/bin/pypy stage3.py')
print("stage3 finished!")

with open('stage3', 'rb') as f:
    key = f.read()

r.sendline('')
r.sendline(key.encode('hex'))

r.interactive()

r.close()
```

The flag is: `flag{but_th3_litt1e_sticky_leave5_and_tHe_pRec1ous_t0mbs_and_the_b1Ue_sky_ANd_The_woman_you_loVe_How_will_you_lIVe_h0w_wi1l_yoU_love_them_wiTh_5uch_a_h3ll_in_YouR_h34rt_and_y0ur_he4d__How__Can__You__}`