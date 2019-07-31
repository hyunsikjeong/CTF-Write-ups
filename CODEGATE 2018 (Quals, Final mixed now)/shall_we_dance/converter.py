filename = '4.bin'

with open(filename, 'rb') as f:
    data = f.read()

data = list(data)
data.reverse()

for i in range( len(data) ):
    data[i] -= i
    data[i] %= 0x100
    data[i] ^= 0xAD

with open('4.wav', 'wb') as f:
    f.write( bytes(data) )

        
