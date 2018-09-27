from mnemonic import Mnemonic
import pysodium
from Crypto.Cipher import AES

import utility

prefix_tz1 = bytes([6, 161, 159])
prefix_edpk = bytes([13, 15, 37, 217])
prefix_edsk = bytes([43, 246, 78, 7])
prefix_edsig = bytes([9, 245, 205, 134, 18])

watermark_block = bytes([1])
watermark_endorsement = bytes([2])
watermark_generic = bytes([3])

def generateMnemonic():
    m = Mnemonic('english')
    return m.generate(160)

def checkMnemonic(mnemonic):
    m = Mnemonic('english')
    return m.check(mnemonic)

def generateKeys(m, p):
    s = Mnemonic.to_seed(m, p)
    pk, sk = pysodium.crypto_sign_seed_keypair(s[:32])
    pkh = pysodium.crypto_generichash(pk, outlen=20)
    return utility.base58Encode(prefix_tz1, pkh), utility.base58Encode(prefix_edpk, pk), utility.base58Encode(prefix_edsk, sk)

def generateKeysNoSeed():
    pk, sk = pysodium.crypto_sign_keypair()
    pkh = pysodium.crypto_generichash(pk, outlen=20)
    return utility.base58Encode(prefix_tz1, pkh), utility.base58Encode(prefix_edpk, pk), utility.base58Encode(prefix_edsk, sk)

def checkAddress(pkh):
    try:
        utility.base58Decode(prefix_tz1, pkh)
        return True
    except:
        return False

def sign(data, sk, watermark):
    '''
    :param data: bytes
    :param sk: base58 encoded bytes
    :param watermark: bytes
    :return: signed bytes
    '''
    bb = watermark + data
    sig = pysodium.crypto_sign_detached(
        pysodium.crypto_generichash(bb, outlen=32),
        utility.base58Decode(prefix_edsk, sk)
    )
    edsig = utility.base58Encode(prefix_edsig, sig)
    sbytes = sig + data
    return {
        'bytes' : data,
        'sig' : sig,
        'edsig' : edsig,
        'sbytes' : sbytes
    }

def verify(data, sig, pk):
    '''
    :param data: bytes
    :param sig:  bytes
    :param pk:  bytes
    :return:
    '''
    return pysodium.crypto_sign_verify_detached(sig, data, utility.base58Decode(prefix_edpk, pk))

def aes_decrypt(data, secret):
    sec = utility.sha256(utility.ripemd160_hash(secret))
    cipher = AES.new(sec, AES.MODE_ECB)
    decrypted = cipher.decrypt(data)
    #paddingLen = decrypted[-1]
    return decrypted.rstrip(b'\x00')

def aes_encrypt(data, secret):
    sec = utility.sha256(utility.ripemd160_hash(secret))
    cipher = AES.new(sec, AES.MODE_ECB)
    padding = AES.block_size - (len(data) % AES.block_size)
    return cipher.encrypt(data + bytes([0] * padding) )