#!/usr/bin/env python3
import gmpy2

from decimal import Decimal

N = int(gmpy2.fac(333))
#N = 10334465434588059156093965538297516550622260041682062823432902469783188597914276568552700194849877929894375950252570477080418352732597658745665925604704669227133726477243854317836635130694123893711638533001980496229875665476598568821806170303765540489814402234159901540440432134155844542962445153646330595588291605924429211352279943471372817279938720974895260387784578239150931816946786416232516666251965421919651838044618050991294403546958930745419743836966520198735201123255884089263272829846640538826979843642885775791641575109178753509580001660392092396798648924375401024147883702298145910046889402880394195369984000000000000000000000000000000000000000000000000000000000000000000000000000000000
sN = int(gmpy2.isqrt(N))
#sN = 3214726338988757399964463840205273148284735043324463579894976679845078166928105412104944973948893914339037572694382785661727648297539107767478128297633669341356440278480314502443731079340424764653103468238563073341496690901434197268615240607985890327844073738551115260849983966971570699838147501655616953786428037017304945538845583678438817092853062

k = int(input("Enter number: "))

goodness = Decimal(abs(k - sN)) / sN 

if k and N % k == 0 and goodness < 1e-8:
    print(open('/home/eulernt/flag.txt').read())
elif k and N % k == 0 and goodness < 1e-4:
	print("Good work! You're getting there.")
else:
    print("Nope!")
