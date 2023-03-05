import logging

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.number import *
from Crypto.Util.Padding import pad, unpad
from sage.all import GF
from sage.all import identity_matrix
from sage.matrix.matrix2 import _jordan_form_vector_in_difference
def find_eigenvalues(A):
    """
    Computes the eigenvalues and P matrices for a specific matrix A.
    :param A: the matrix A.
    :return: a generator generating tuples of
        K: the extension field of the eigenvalue,
        k: the degree of the factor of the charpoly associated with the eigenvalue,
        e: the multiplicity of the factor of the charpoly associated with the eigenvalue,
        l: the eigenvalue,
        P: the transformation matrix P (only the first e columns are filled)
    """
    factors = {}
    for g, e in A.charpoly().factor():
        k = g.degree()
        if k not in factors or e > factors[k][0]:
            factors[k] = (e, g)

    p = A.base_ring().order()
    for k, (e, g) in factors.items():
        logging.debug(f"Found factor {g} with degree {k} and multiplicity {e}")
        K = GF(p ** k, "x", modulus=g, impl="modn" if k == 1 else "pari")
        l = K.gen()
        # Assuming there is only 1 Jordan block for this eigenvalue.
        Vlarge = ((A - l) ** e).right_kernel().basis()
        Vsmall = ((A - l) ** (e - 1)).right_kernel().basis()
        v = _jordan_form_vector_in_difference(Vlarge, Vsmall)
        P = identity_matrix(K, A.nrows())
        for i in reversed(range(e)):
            P.set_row(i, v)
            v = (A - l) * v

        P = P.transpose()
        yield K, k, e, l, P

def dlog(A, B):
    """
    Computes l such that A^l = B.
    :param A: the matrix A
    :param B: the matrix B
    :return: a generator generating values for l and m, where A^l = B mod m.
    """
    assert A.is_square() and B.is_square() and A.nrows() == B.nrows()

    p = A.base_ring().order()
    for K, k, e, l, P in find_eigenvalues(A):
        B_ = P ** -1 * B * P
        logging.debug(f"Computing dlog in {K}...")
        yield int(B_[0, 0].log(l)), int(p ** k - 1)
        if e >= 2:
            B1 = B_[e - 1, e - 1]
            B2 = B_[e - 2, e - 1]
            yield int((l * B2) / B1), int(p ** k)

KEY_LENGTH = 128

def derive_aes_key(M):
    mat_str = ''.join(str(x) for row in M for x in row)
    return SHA256.new(data=mat_str.encode()).digest()[:KEY_LENGTH]


P = GF(2)
G = Matrix(P, [[int(i) for i in row]for row in open('d:\\matrix_revolution\\generator.txt').read().splitlines()])
A = Matrix(P, [[int(i) for i in row] for row in open('d:\\matrix_revolution\\alice.pub').read().splitlines()])
B = Matrix(P, [[int(i) for i in row] for row in open('d:\\matrix_revolution\\bob.pub').read().splitlines()])

# print(G.multiplicative_order())
# ans = []
# for privkey, mod in dlog(G,A):
#     ans.append((privkey, mod))

ans = [(411973000499645090, 2305843009213693951), (314598098609833643099290850, 618970019642690137449562111)]
print(ans)
from sage.arith.misc import crt
res = [ans[0][0], ans[1][0]]
md = [ans[0][1], ans[1][1]]
A_priv = crt(res, md)

print(A_priv)

assert(G^A_priv == A)
sharekey = B^A_priv
flag_enc = {"iv": "43f14157442d75142d0d4993e99a9582", "ciphertext": "22abc3b347ffef55ec82488e5b4a338da5af7ef1918ac46f95029a4d94ace4cb2700fa9aeb31e6a4facee2601e99dabd6f9a81494c55f011e9227c9a6ae8d802"}
iv = bytes.fromhex(flag_enc["iv"])
ciphertext = bytes.fromhex(flag_enc["ciphertext"])
key = derive_aes_key(sharekey)
cipher = AES.new(key, AES.MODE_CBC, iv)
print(cipher.decrypt(ciphertext))