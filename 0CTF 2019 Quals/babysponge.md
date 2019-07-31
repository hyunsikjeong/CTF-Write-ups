# babysponge

Cannot control 6 bytes, which represents a space with the size 2 ** 48. Actually, 2 ** 48 is enough to do the birthday attack.

Just calculate a collision:

```python
import os,random,sys,string
from hashlib import sha256
import CompactFIPS202

state_to_value = dict()

rate = 1552
rateInBytes = rate//8

count = 0
while True:
    count += 1
    if count % 10000 == 0:
        print("Count: ", count)
    randombytes = os.urandom(rateInBytes)
    randombytes = bytearray(randombytes + b'\x00\x00\x00\x00\x00\x00')

    output = CompactFIPS202.KeccakF1600(randombytes)
    output_last6 = output[-6:]
    output_value = sum([ output_last6[i] << (8 * i) for i in xrange(6) ])

    if output_value in state_to_value:
        print("COLLISION!!!")
        with open("collision", "wb") as f:
            f.write(state_to_value[output_value])
            f.write(randombytes)
    else:
        state_to_value[output_value] = randombytes
```

I was able to see a collision about `count = 18000000`. The collision value is:

```
4fd9a8f362dc9ecf8f38fa2937e8b3e4e0cbdf9b2921871e79b61275c7b8ddf1a6373ece646e5c6fc7507ded8d70d86ef7a48bad4fffed4af1b5a9593e7f89db64fc487bdc7e39f0bfca7abd1cbfa2b3e689d228e677a60e56612c7df3c618bb13d7907826d818bb90c515a40f2e134cc9477b948c01c06b64e3bfdafa39c612816bdfeba3d4166abfc851c81d6dab044e09a3107f4cc68fb1a00ffcb781be7e236026e2c7ca323f58d81d09af7ead090419a2c57726b6fe12d7e14675a757a4720d3ec08967ca0807450d31f54442e88c6e78abd5d6ed574b743e6e19b0b624d86fad0eb30efbf407ee14962be33bef465e903dcc7d8e4879563ef60d2ff9d8b61aee88eef1a61d2f9d656e648ec3c0377e422b6fb175ce497638aaca76ab700762a6a76fe7fde4241771a2ec03334e71f41fe5487777ec9a40ada9cc01d93a2560a33f6af7e3fcf12e8fbb5e926be56a8e74c865c6468723aaf54eda887817bedcc3d3375c853243566f1cfa51cdd49c09656bf217171aa66dc1f5be4823572fc2ebee
e586da56a06aa6b213d889f5691f9718fd4a1cf7d7f3dee3fc5ff6106d701fbe87437de424769380d40c6b821238606d9ccaa87600426f05aa1a73281f53253fe271211cc6cc084a2814aea8e985424d47389564db096d91c82bd4e4f84f9fdedaa14202372a11bc9418e92cbea3375316b964613abc93e26bccfa3a9ea3e4d6ffbeb0bff111239157f2b949ded347f28e64487bca7c188df9eece62e7b0b71c805d550079e1ab1669c7baa9218d2b8b718450761d2f7a442ceb2a6eaafd77043826df3c4781c9a52bed9624a6ebbb59a91b804264e03dfcb9b5ba0a4577e2474d5e2d9034229a461059c858adad1a19b9a04caec3883deef35ff69e0fa42dd36c038ef15681a5cb3ac745df335cd274f6fe338358577cf5da6c4300cf9b2ca8c459f9115f90604c5bb6d9387bd3f3bd89b8879dea93c3635889e2fca03687eaa9a48edb4e16288ed95c78ef0421cf4675433fd701975809e5a924ec757fbf62fb3f5e373a4a18865d0f3f18bb3612db928351e611776825d550866ba69c6df98f119656
```

To solve:

```python
from pwn import *
import string
from hashlib import sha256
import os,random,sys,string
import CompactFIPS202

r = remote('111.186.63.14', 10001)

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

r.send(proof[:4])

print("Proof clear: ", proof)

msg1 = "4fd9a8f362dc9ecf8f38fa2937e8b3e4e0cbdf9b2921871e79b61275c7b8ddf1a6373ece646e5c6fc7507ded8d70d86ef7a48bad4fffed4af1b5a9593e7f89db64fc487bdc7e39f0bfca7abd1cbfa2b3e689d228e677a60e56612c7df3c618bb13d7907826d818bb90c515a40f2e134cc9477b948c01c06b64e3bfdafa39c612816bdfeba3d4166abfc851c81d6dab044e09a3107f4cc68fb1a00ffcb781be7e236026e2c7ca323f58d81d09af7ead090419a2c57726b6fe12d7e14675a757a4720d3ec08967ca0807450d31f54442e88c6e78abd5d6ed574b743e6e19b0b624d86fad0eb30efbf407ee14962be33bef465e903dcc7d8e4879563ef60d2ff9d8b61aee88eef1a61d2f9d656e648ec3c0377e422b6fb175ce497638aaca76ab700762a6a76fe7fde4241771a2ec03334e71f41fe5487777ec9a40ada9cc01d93a2560a33f6af7e3fcf12e8fbb5e926be56a8e74c865c6468723aaf54eda887817bedcc3d3375c853243566f1cfa51cdd49c09656bf217171aa66dc1f5be4823572fc2ebee"
msg2 = "e586da56a06aa6b213d889f5691f9718fd4a1cf7d7f3dee3fc5ff6106d701fbe87437de424769380d40c6b821238606d9ccaa87600426f05aa1a73281f53253fe271211cc6cc084a2814aea8e985424d47389564db096d91c82bd4e4f84f9fdedaa14202372a11bc9418e92cbea3375316b964613abc93e26bccfa3a9ea3e4d6ffbeb0bff111239157f2b949ded347f28e64487bca7c188df9eece62e7b0b71c805d550079e1ab1669c7baa9218d2b8b718450761d2f7a442ceb2a6eaafd77043826df3c4781c9a52bed9624a6ebbb59a91b804264e03dfcb9b5ba0a4577e2474d5e2d9034229a461059c858adad1a19b9a04caec3883deef35ff69e0fa42dd36c038ef15681a5cb3ac745df335cd274f6fe338358577cf5da6c4300cf9b2ca8c459f9115f90604c5bb6d9387bd3f3bd89b8879dea93c3635889e2fca03687eaa9a48edb4e16288ed95c78ef0421cf4675433fd701975809e5a924ec757fbf62fb3f5e373a4a18865d0f3f18bb3612db928351e611776825d550866ba69c6df98f119656"

r.recvuntil("first message(hex): ")
r.sendline(msg1)
r.recvuntil("second message(hex): ")
r.sendline(msg2)

r.interactive()

r.close()
```

The flag is : `flag{I_wAs_th3_sh4d0w_Of_the_waXwing_sLAin__By_the_fAlse_@4zure9_in_the_window_pan3}`.