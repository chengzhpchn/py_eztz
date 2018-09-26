from unittest import TestCase
import crypto

class TestCrypto(TestCase):
    def test_0_generateMnemonic(self):
        print( crypto.generateMnemonic() )

    def test_1_generateKeys(self):
        mnemonic = 'stadium record van start fluid capable address disagree hole magnet face metal gift lounge series'
        to_seed_passphrase = '123456'

        pkh, pk, sk= crypto.generateKeys(mnemonic, to_seed_passphrase)
        self.assertEqual(b'tz1icsb9uQy3EriLmbjaaeDRfdbp9wJ7F3BY', pkh)
        self.assertEqual(b'edskRoRpyuhCbSjvUhJH3knGm53rVwdeNx4wuqaLRaCSd4gZzTbmTumHBFZRPNMSNsDv7AUnpuNZPDtx9qhuZ2vGVAFFx6aVpX', sk)

    def test_2_sign(self):
        pass

    def test_3_verfy(self):
        pass

    def test_4_aes_en_decrypt(self):
        encrypted = b"\xee\x890\xf6\r\xcc\x82\x84]\x85y\x90\xf6y\xd1Y\xbe[J\xfeD\xd6g\x1c\xdc)\x9d\xe5\xf8\xc8\x86\xd2&\xaf\x1e\xb3_,\x88\x183g\xebm\x18\xda]V\xe7\xe6z@5;\xf2\x12\xce\xfc\xef\xcd\x04}\x07|\xa4\x07\xbb\x1a\x81',\x018|\xa5y\x15\xc8 \nJ\xd8\xf3c`s\xdc\x06\x03\xb6\x15\xc8\xdb\xa1\x05\xf2\xc5S'\xd7\x87\xb7\nb!\x1e\xb1\xde\xbd4\xf7+1G<x\xb1D}\xcc\x9e\r\x93D\xa2\xec\xe2lF\xaa\xc9\x85\xf4\xa0YWR@\xdc2zj\xbc~\xa1\xb2\xb3V\x8c\x96\x0c\xc8\x81\x8a\xba\xe7i+\xac="
        expected = b"distance travel photo item great notable case guitar like cheap soda lizard elite fine grief end joke burger twenty smooth account slush all shuffle"
        passphrase = b'123456'
        #import pdb; pdb.set_trace()
        self.assertEqual(encrypted, crypto.aes_encrypt(expected, passphrase))
        self.assertEqual(expected, crypto.aes_decrypt(encrypted, passphrase))