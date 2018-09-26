import base58
import hashlib
from binascii import b2a_hex, a2b_hex

def sha256(data):
    sha256_ = hashlib.sha256()
    sha256_.update(data)
    return sha256_.digest()

sha_bitcoin = lambda data: sha256(sha256(data))

def ripemd160_hash(data):
    obj = hashlib.new('ripemd160', data)
    return obj.digest()#, obj.hexdigest()


def base58Encode(prefix, data):
    checksum = sha_bitcoin(prefix + data)[:4]
    return base58.b58encode(prefix + data + checksum)

def base58Decode(prefix, data):
    raw = base58.b58decode(data)
    assert (raw.startswith(prefix))

    checksum = sha_bitcoin(raw[:-4])[:4]
    assert (checksum == raw[-4:])
    return raw[len(prefix):-4]


if __name__ == '__main__':
    assert(b'MVPu6mtUK8iAg9NCki32nGjUrbkN1DpaSN' == base58Encode(bytes([0x32]), bytes([0xeb, 0xca, 0x12, 0xa3, 0x21, 0x10, 0x54, 0xca, 0x27, 0x5e, 0x4e, 0x3d, 0xf1, 0x62, 0xa4, 0xf7, 0xcc, 0x08, 0x99, 0x8d])))
    assert(bytes([0xeb, 0xca, 0x12, 0xa3, 0x21, 0x10, 0x54, 0xca, 0x27, 0x5e, 0x4e, 0x3d, 0xf1, 0x62, 0xa4, 0xf7, 0xcc, 0x08, 0x99, 0x8d]) == base58Decode(bytes([0x32]), b'MVPu6mtUK8iAg9NCki32nGjUrbkN1DpaSN'))