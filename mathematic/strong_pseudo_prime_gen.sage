def crt_backtrack(options, mods, erem, emod):
    if not options:
        return (erem, emod)
    for o in options[0]:
        try:
            c = crt([erem, o], [emod, mods[0]])
            return crt_backtrack(options[1:], mods[1:], c, lcm([mods[0], emod]))
        except ValueError: pass
def generate_basis(n):
    basis = [True] * n
    for i in range(3, int(n**0.5)+1, 2):
        if basis[i]:
            basis[i*i::2*i] = [False]*((n-i*i-1)//(2*i)+1)
    return [2] + [i for i in range(3, n, 2) if basis[i]]
TARGET_BITLEN = 800
def gen_strong_pseudoprime(A):
    def app_k(k, S, a):
        kinv = pow(k, -1, 4*a)
        return set((kinv * (s + k - 1)) % (4*a) for s in S)

    def intersect(x):
        s = x[0]
        for y in x[1:]:
            s &= y
        return s
    S_a = {}
    for a in A:
        s = set()
        p = 3
        while p < 50000:
            if legendre_symbol(a, p) == -1:
                s.add(p % (4*a))
            p = next_prime(p)

        S_a[a] = s
    ks = [1, next_prime(max(A)), next_prime(200)]
    cso, ms = [], []
    for a in A:
        cso.append(list(map(int, intersect([app_k(k, S_a[a], a) for k in ks]))))
        ms.append(4*a)
    ems = [ks[1], ks[2]]
    erem = crt(list(map(int, [ks[1] - pow(ks[2], -1, ks[1]), ks[2] - pow(ks[1], -1, ks[2])])), ems)
    emod = lcm(ems)
    p1, mod = crt_backtrack(cso, ms, erem, emod)
    p1 += ((2**(TARGET_BITLEN // 3 + 3) - p1) // mod) * mod
    while True:
        p2 = ks[1] * (p1 - 1) + 1
        p3 = ks[2] * (p1 - 1) + 1
        if is_prime(p1) and is_prime(p2) and is_prime(p3):
            break
        p1 += mod
    return (p1, p2, p3)
print(gen_strong_pseudoprime(generate_basis(64)))