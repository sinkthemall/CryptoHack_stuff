
from requests import Session
from json import loads, dumps
gf2e = GF(2 ** 128, name="y", modulus=x ** 128 + x ** 7 + x ** 2 + x + 1)


# Converts an integer to a gf2e element, little endian.
def _to_gf2e(n):
    return gf2e([(n >> i) & 1 for i in range(127, -1, -1)])

def _from_gf2e(p):
    n = p.integer_representation()
    ans = 0
    for i in range(128):
        ans <<= 1
        ans |= ((n >> i) & 1)

    return ans
def _ghash(h, a, c):
    la = len(a)
    lc = len(c)
    p = gf2e(0)
    for i in range(la // 16):
        p += _to_gf2e(int.from_bytes(a[16 * i:16 * (i + 1)], byteorder="big"))
        p *= h

    if la % 16 != 0:
        p += _to_gf2e(int.from_bytes(a[-(la % 16):] + bytes(16 - la % 16), byteorder="big"))
        p *= h

    for i in range(lc // 16):
        p += _to_gf2e(int.from_bytes(c[16 * i:16 * (i + 1)], byteorder="big"))
        p *= h

    if lc % 16 != 0:
        p += _to_gf2e(int.from_bytes(c[-(lc % 16):] + bytes(16 - lc % 16), byteorder="big"))
        p *= h

    p += _to_gf2e(((8 * la) << 64) | (8 * lc))
    p *= h
    return p
def recover_possible_auth_keys(a1, c1, t1, a2, c2, t2):
    """
    Recovers possible authentication keys from two messages encrypted with the same authentication key.
    More information: Joux A., "Authentication Failures in NIST version of GCM"
    :param a1: the associated data of the first message (bytes)
    :param c1: the ciphertext of the first message (bytes)
    :param t1: the authentication tag of the first message (bytes)
    :param a2: the associated data of the second message (bytes)
    :param c2: the ciphertext of the second message (bytes)
    :param t2: the authentication tag of the second message (bytes)
    :return: a generator generating possible authentication keys (gf2e element)
    """
    h = gf2e["h"].gen()
    p1 = _ghash(h, a1, c1) + _to_gf2e(int.from_bytes(t1, byteorder="big"))
    p2 = _ghash(h, a2, c2) + _to_gf2e(int.from_bytes(t2, byteorder="big"))
    for h, _ in (p1 + p2).roots():
        yield h

s = Session()
url = "http://aes.cryptohack.org/forbidden_fruit/"
from Crypto.Util.number import bytes_to_long, long_to_bytes
def encrypt(message):
    msg = s.get(url + "encrypt/" + message.encode().hex()).text
    print(msg)
    msg = loads(msg)
    msg["associated_data"] = bytes.fromhex(msg["associated_data"])
    msg["nonce"] = bytes.fromhex(msg["nonce"])
    msg["tag"] = bytes.fromhex(msg["tag"])
    msg["ciphertext"] = bytes.fromhex(msg["ciphertext"])
    return msg

def find_ghash_iv_0(ciphertext, H : int, AD, tag):
    p = gf2e(0)
    
    la = len(AD)
    lc = len(ciphertext)
    for i in range(la//16):
        p += _to_gf2e(bytes_to_long(AD[i*16 : (i + 1)*16]))
        p *= _to_gf2e(H)
    if la % 16 != 0:
        p += _to_gf2e(bytes_to_long(AD[-(la%16) : ] + bytes(16 - (la%16))))
        p *= _to_gf2e(H) 
    
    for i in range(lc//16):
        p += _to_gf2e(bytes_to_long(ciphertext[i*16 : (i + 1)*16]))
        p *= _to_gf2e(H)
    if lc %16 != 0:
        p += _to_gf2e(bytes_to_long(ciphertext[-(lc%16) : ] + bytes(16 - lc%16)))
        p *= _to_gf2e(H)
    
    p += _to_gf2e(((la*8) << 64) | (8 * lc))
    p *= _to_gf2e(H)
    p += _to_gf2e(bytes_to_long(tag))
    return _from_gf2e(p)

def calculate_tag(ciphertext, H : int, AD, ghash_iv):
    p = gf2e(0)
    
    la = len(AD)
    lc = len(ciphertext)
    for i in range(la//16):
        p += _to_gf2e(bytes_to_long(AD[i*16 : (i + 1)*16]))
        p *= _to_gf2e(H)
    if la % 16 != 0:
        p += _to_gf2e(bytes_to_long(AD[-(la%16) : ] + bytes(16 - (la%16))))
        p *= _to_gf2e(H) 
    
    for i in range(lc//16):
        p += _to_gf2e(bytes_to_long(ciphertext[i*16 : (i + 1)*16]))
        p *= _to_gf2e(H)
    if lc %16 != 0:
        p += _to_gf2e(bytes_to_long(ciphertext[-(lc%16) : ] + bytes(16 - lc%16)))
        p *= _to_gf2e(H)
    
    p += _to_gf2e(((la*8) << 64) | (8 * lc))
    p *= _to_gf2e(H)
    p += _to_gf2e(ghash_iv)
    return _from_gf2e(p)
plaintext1 = "Just a text lmao"#should be multiple of 16
plaintext2 = "another text LOL"#should be multiple of 16
m1 = encrypt(plaintext1)
m2 = encrypt(plaintext2)
H_key = recover_possible_auth_keys(m1["associated_data"], m1["ciphertext"], m1["tag"], m2["associated_data"], m2["ciphertext"], m2["tag"])
H = 0
for i in H_key:
    H = _from_gf2e(i)

ghash_iv = find_ghash_iv_0(m1["ciphertext"], H, m1["associated_data"], m1["tag"])
target_plaintext = "give me the flag"
msg = loads(s.get(url + "encrypt/" + target_plaintext.encode().hex()).text)
target_ciphertext = bytes.fromhex(msg["ciphertext"])
AD = "CryptoHack".encode()
tag = (int(calculate_tag(target_ciphertext, H, AD, ghash_iv))).to_bytes(16, 'big')
payload = {"ciphertext" : target_ciphertext.hex(), "nonce" : m1["nonce"].hex(), "tag" : tag.hex(), "associated_data" : AD.hex()}
msg = s.get(url + "decrypt/" + payload["nonce"] + "/" + payload["ciphertext"] + "/" + payload["tag"] + "/" + payload["associated_data"]).text
print(bytes.fromhex(loads(msg)["plaintext"]))

