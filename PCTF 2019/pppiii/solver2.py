
lockpairs = [
    [(4, 3, []), (3, 0, []), (2, 1, []), (0, 2, []), (2, 0, [])],
    [(0, 4, []), (0, 2, [4]), (0, 1, [2, 4]), (4, 2, [0]), (4, 1, [0, 2]), (2, 1, [0, 4]), (4, 3, [2]), (2, 3, [4]), (4, 1, [])],
    [(2, 1, []), (1, 2, []), (1, 0, []), (1, 4, []), (1, 3, [])],
    [(4, 3, []), (3, 0, []), (2, 1, []), (1, 4, [])],
    [(1, 2, []), (1, 3, [2]), (2, 3, [1]), (2, 3, [])],
    [(4, 3, []), (3, 0, []), (3, 2, []), (2, 1, []), (0, 2, [])],
    [(0, 2, []), (2, 1, []), (3, 0, []), (3, 4, [])],
    [(1, 3, []), (1, 2, [3]), (3, 2, [1])],
    [(0, 2, []), (2, 1, []), (3, 4, [])],
    [(3, 1, []), (3, 4, []), (0, 2, []), (2, 1, [])],
    [(1, 3, []), (1, 2, [3]), (3, 2, [1]), (3, 0, [])],
    [(4, 1, []), (4, 2, [1]), (1, 2, [4]), (2, 1, []), (0, 1, []), (0, 2, [1]), (1, 2, [0])],
    [(0, 1, []), (1, 2, []), (1, 3, [2]), (2, 3, [1]), (1, 3, [])],
    [(0, 2, []), (2, 1, []), (0, 4, [])],
    [(3, 1, []), (3, 2, [1]), (1, 2, [])],
]

foods = [
    [0, 3, 6, 9, 12],
    [1, 6, 11, -1, -1],
    [1, 4, 8, 14, -1],
    [2, 8, -1, -1, -1],
    [1, 5, 9, 10, 13],
]

def compare_taste(user, food):
    v2 = (2 * (user - food)) % 30
    v4 = (2 * (food - user) + 1) % 30
    return min(v2, v4)

choices = []

# Choice for each likelihood
for v in range(15):
    choice = []
    for i in range(5):
        ansidx, ans = 0, compare_taste(v, foods[i][0])
        for j in range(1, 5):
            if foods[i][j] == -1:
                break
            t = compare_taste(v, foods[i][j])
            if ans > t:
                ansidx, ans = j, t

        choice.append(ansidx)
    choices.append(choice)

# Possible deadlock pairs
pos_dl_pairs = []

for i in range(15):
    for j in range(i + 1, 15):

        for (p1, q1, r1) in lockpairs[i]:
            for (p2, q2, r2) in lockpairs[j]:
                if p2 == q1 and p1 == q2:

                    gatelocks = list(set(r1) & set(r2))
                    # If `i`th person and `j`th person picks a same food
                    # in row `p1` and `p2`, it will cause a deadlock.
                    pos_dl_pairs.append( (i, j, p1, p2, gatelocks) )

deadlocks = [ [ [] for i in range(15) ] for j in range(15) ]

for (u1, u2, i1, i2, gatelocks) in pos_dl_pairs:
    for v1 in range(15):
        for v2 in range(15):
            if v1 == v2: continue
            if choices[v1][i1] == choices[v2][i1] and choices[v1][i2] == choices[v2][i2]:
                # Check if there's a gate lock.
                # If yes, it could not cause a deadlock.
                flag = True
                for g in gatelocks:
                    if choices[v1][g] == choices[v2][g]:
                        flag = False
                        break
                
                if flag:
                    deadlocks[u1][v1].append( (u2, v2) )

ans = []
check = [ [ 0 for i in range(15) ] for j in range(15) ]

def backtrack(idx):
    if idx == 15:
        with open("ans.txt", "a") as f:
            f.write(str(ans) + "\n")
        print(ans)
        return
    for i in range(15):
        if check[idx][i] > 0:
            continue
        if idx == 6 and choices[i][1] == 1:
            continue
        
        for u in range(idx + 1, 15):
            check[u][i] += 1
        for (u, v) in deadlocks[idx][i]:
            check[u][v] += 1
        
        ans.append(i)
        backtrack(idx + 1)
        ans.pop()

        for u in range(idx + 1, 15):
            check[u][i] -= 1
        for (u, v) in deadlocks[idx][i]:
            check[u][v] -= 1

backtrack(0)
