from telnetlib import Telnet
from json import dumps, loads
from Crypto.Util.number import getPrime,isPrime, long_to_bytes, bytes_to_long
from Crypto.Random import get_random_bytes
from random import randint
from hashlib import sha256
from pkcs1 import emsa_pkcs1_v15
import string

import re
BIT_LENGTH = 768
s = Telnet('socket.cryptohack.org', int(13394))
s.read_until(b'Just do it multiple times to make sure...\n')
BTC_PAT = re.compile("^Please send all my money to ([1-9A-HJ-NP-Za-km-z]+)$")
#addr = BTC_PAT.match("Please send all my money to BNZcjmRm6Gk8XjC1nd4r3bJ6Gw8Baz3yRMy")
#print(addr.group(1))
N = 0
factors = []
SIG = 0
token = ''
def btc_check(msg):
    alpha = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    addr = BTC_PAT.match(msg)
    if not addr:
        return False
    addr = addr.group(1)
    raw = b"\0" * (len(addr) - len(addr.lstrip(alpha[0])))
    res = 0
    for c in addr:
        res *= 58
        res += alpha.index(c)
    raw += long_to_bytes(res)

    if len(raw) != 25:
        return False
    if raw[0] not in [0, 5]:
        return False
    return raw[-4:] == sha256(sha256(raw[:-4]).digest()).digest()[:4]

def xor(a,b):
	return bytes([i^^j for i,j in zip(a,b)])
def get_rand_ascii(ln : int):
	alpha = string.ascii_lowercase + string.ascii_uppercase
	a = [alpha[randint(0, len(alpha) - 1)] for i in range(ln)]
	return ''.join(a) 
def request(obj):
	print(obj)
	msg = dumps(obj)
	s.write(msg.encode() + b'\n')
def response():
	msg = loads(s.read_until(b'\n'))
	return msg 

def dlp(B, A, N, factors): # A^x = B
	x = []
	q = 1
	#print("A:", A,"B:",B)
	moduli = []
	for i in factors:
		Fp = GF(i)
		a = Fp(A%i)
		b = Fp(B%i)
		print("a:",a)
		print("b:",b)
		print("i:",i)
		#print("a:",a,"b:",b)
		#print("A mod i:",A%i, "B mod i:",B%i)
		X = discrete_log(b, a)
		#_a = Mod(A, i)
		#_b = Mod(B, i)
		#print("X found:",X, "WA found:", discrete_log(_b, _a, i-1))
		#print("order:",Fp(A).multiplicative_order(),"i-1:",i-1)
		assert(pow(A, X, i) == (B%i))
		x.append(X)
		moduli.append(Fp(A).multiplicative_order())
		
		print("calculate completed!")

	ans = crt(x, moduli)
	assert(pow(A, ans, N) == B)
	return ans

def generate_smooth_prime(bitlen):

	while True:
		p = 2
		while int(p).bit_length() <bitlen:
			p *= getPrime(20)
		if isPrime(p + 1) and GF(p + 1)(SIG).multiplicative_order() == p:
			return p + 1
def generate_smooth_N(bitlen):
	N = 1
	factors =[]
	while (int(N).bit_length() < bitlen):
		p = getPrime(24)
		while GF(p)(SIG).multiplicative_order() != p - 1 or (p in factors):
			p = next_prime(p + 1)
		N *= p 
		factors.append(p)
	return (N,  factors)
def test_func():
	for i in range(4):
		N, factors = generate_smooth_N(500)
		for test in range(20):
			a = randint(1, pow(2, 300))
			x = randint(1, pow(2, 100))
			b = pow(a, x, N)
			X = dlp(b, a, N, factors)
			print("success on test", test)


#test_func()
def get_rand_char(ln : int):
	a = [chr(randint(32, 127)) for i in range(ln)]
	return ''.join(a)
def btc_gen():
	alpha = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	while  True:
		raw = b"\x05" + get_random_bytes(20)
		q = sha256(sha256(raw).digest()).digest()[:4]
		raw += q 
		raw = bytes_to_long(raw)

		res = ''
		while raw > 0:
			res += alpha[raw%58]
			raw //= int(58)
		res = res[::-1]
		if res[0] != '1':
			return res
def generate(pre : bytes, suf : bytes, mid : int):
	while True:

		md = get_rand_char(mid).encode()
		q = pre + md + suf
		digest = emsa_pkcs1_v15.encode(q, BIT_LENGTH //8)
		if isPrime(bytes_to_long(digest)):
			print("generate successfully!")
			return q
def generate_ascii(pre : bytes, suf : bytes, mid : int):
	while True:

		md = get_rand_ascii(mid).encode()
		q = pre + md + suf
		digest = emsa_pkcs1_v15.encode(q, BIT_LENGTH //8)
		if isPrime(bytes_to_long(digest)):
			print("generate successfully!")
			return q
def generateprime(pre : bytes, suf : bytes, mid : int):
	while True:
		md = get_random_bytes(mid)
		q = pre + md + suf
		if isPrime(bytes_to_long(q)):
			print("generate prime successfully!")
			return q 


def stage0(token : bytes):
	print("stage 0")
	D = 0
	msg = b''
	cnt = 0
	while True:
		#try:

			msg = generate(b"This is a test" ,b" for a fake signature." + token, 5)
			digest = emsa_pkcs1_v15.encode(msg, BIT_LENGTH //8)
			#print("digest:",bytes_to_long(digest))
			#print("N:", N)
			#print("SIG:",SIG)
			D = dlp(bytes_to_long(digest), SIG, N, factors )
			print("generate success")
			break
		#except:
			#print("attempted",cnt)
			#cnt += 1

	
	request({"option":"claim", "msg": msg.decode(), "index" : int(0), "e" : hex(D)[2:]})
	msg = response()
	print("stage 0 message:")
	print(msg)
	return bytes.fromhex(msg["secret"])

def stage1(token : bytes):
	print("stage 1")
	D = 0
	msg = b''
	cnt = 0
	while True:
		try:

			msg = generate_ascii(b"My name is " ,b" and I own CryptoHack.org" + token, 5)
			digest = emsa_pkcs1_v15.encode(msg, BIT_LENGTH //8)
			#print("digest:",bytes_to_long(digest))
			#print("N:", N)
			#print("SIG:",SIG)
			D = dlp(bytes_to_long(digest), SIG, N, factors )
			print("generate success")
			break
		except:
			print("attempted",cnt)
			cnt += 1
	request({"option":"claim", "msg": msg.decode(), "index" : int(1), "e" : hex(D)[2:]})
	msg = response()
	print("stage 1 message:")
	print(msg)
	return bytes.fromhex(msg["secret"])

def stage2(token : bytes):
	print("stage 2")
	D = 0
	msg = b''
	cnt= 0
	while True:
		try:
			msg = b'Please send all my money to ' + btc_gen().encode() + token
			digest = emsa_pkcs1_v15.encode(msg, BIT_LENGTH //8)
			#print("digest:",bytes_to_long(digest))
			#print("N:", N)
			#print("SIG:",SIG)
			D = dlp(bytes_to_long(digest), SIG, N, factors )
			print("generate success")
			break
		except:
			print("attempted",cnt)
			cnt += 1
	request({"option":"claim", "msg": msg.decode(), "index" : int(2), "e" : hex(D)[2:]})
	msg = response()
	print("stage 2 message:")
	print(msg)
	return bytes.fromhex(msg["secret"])

#get signature
request({"option" : "get_signature"})

msg = response()
SIG = int(msg["signature"], 16)
#print(msg)

#init N
#p = generate_smooth_prime(BIT_LENGTH + 20)
# i already gen it,so i just used p because why do i have to gen it again?
p = 124501470252602145144192816820077846444928047953815297602054281089158352961563062340245574384567302297487632304684730277297142744920684334035859149108746046347339469998994282017667098669003782387041171528566998426560250550237794490559989489279
q = 7
while SIG%q==0 or GF(q)(SIG).multiplicative_order() != q-1:
	q = next_prime(q + 1)
N = p*q
factors = [p,q]

#set pubkey
request({"option":"set_pubkey", "pubkey" : hex(N)})
msg = response()
token = msg["suffix"]

#print(msg)
#test stage 1
m0 = stage0(token.encode())
m1 = stage1(token.encode())
m2 = stage2(token.encode())
print(xor(m0,xor(m1,m2)))
# p = getPrime(64)
# g = 2
# x = 12345678999999
# a = pow(g, x, p**7)
# ZP = Zp(p, prec=7)
# X = (ZP(a).log()/ZP(g).log()).lift_x()
# print(X)


