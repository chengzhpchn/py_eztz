#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright (c) 2012-2015, Cenobit Technologies, Inc. http://cenobit.es/
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
# * Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
# * Neither the name of the Cenobit Technologies nor the names of
#    its contributors may be used to endorse or promote products derived from
#    this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
from flask import Flask
from flask_jsonrpc import JSONRPC, InvalidParamsError
import crypto
import json
from binascii import b2a_hex, a2b_hex
# Flask application
app = Flask(__name__)

# Flask-JSONRPC
jsonrpc = JSONRPC(app, '/api', enable_web_browsable_api=True)

@jsonrpc.method('index')
def index():
    return 'Welcome to Flask JSON-RPC'

str2bytes = lambda s: bytes(s, "utf-8")
bytes2str = lambda b: str(b, "utf-8")

@jsonrpc.method('new_account') # (passphrase=String) -> String
def new_account(passphrase):
    pkh, pk, sk = crypto.generateKeysNoSeed()

    # save the encrypted sk
    encrypted_sk = crypto.aes_encrypt(sk, str2bytes(passphrase))
    AccountManager.save_account(pkh, pk, encrypted_sk)

    return bytes2str(pkh)

@jsonrpc.method('import_account(mnemonic=String, seed_passphrase=String, enc_passphrase=String) -> String')
def import_account(mnemonic, seed_passphrase, enc_passphrase):
    if not crypto.checkMnemonic(str2bytes(mnemonic)):
        raise InvalidParamsError("Invalid mnemonic")

    pkh, pk, sk = crypto.generateKeys(str2bytes(mnemonic), str2bytes(seed_passphrase))
    encrypted_sk = crypto.aes_encrypt(sk, str2bytes(enc_passphrase))

    AccountManager.save_account(pkh, pk, encrypted_sk)

    return bytes2str(pkh)

@jsonrpc.method('chk_address')
def chk_address(tz1_address):
    return crypto.checkAddress(str2bytes(tz1_address))

@jsonrpc.method('get_publickey')
def get_publickey(tz1_address):
    pk, _ = AccountManager.load_account(str2bytes(tz1_address))
    return bytes2str(pk)

@jsonrpc.method('sign(pkh=String, passphrase=String, data=String) -> dict')
def sign(pkh, passphrase, data):
    _, encrypted_sk = AccountManager.load_account(str2bytes(pkh))
    sk = crypto.aes_decrypt(encrypted_sk, str2bytes(passphrase))
    if not sk.startswith(b'edsk'):
        raise InvalidParamsError("passphrase error")
    sigs = crypto.sign( a2b_hex(data), sk, crypto.watermark_generic)
    return {'edsig':bytes2str(sigs['edsig']),
            'sbytes':bytes2str( b2a_hex( sigs['sbytes'] ) )}

class AccountManager:
    account_file_fmt = "./accounts/py-eztz-account-%s.json"
    buff = {} # pkh :  (pk, enc_sk)
    @classmethod
    def save_account(cls, pkh, pk, encrypted_sk):
        if pkh in cls.buff:
            cls.buff.pop( pkh )
        filename = cls.account_file_fmt % bytes2str(pkh)
        with open(filename, 'w') as fw:
            data = {
                'public-key' : bytes2str(pk),
                'encrypted-private-key' : bytes2str(b2a_hex(encrypted_sk))
            }
            fw.write(json.dumps(data))

    @classmethod
    def load_account(cls, pkh):
        if pkh in cls.buff:
            return cls.buff[pkh]
        import os
        filename = cls.account_file_fmt % bytes2str(pkh)
        if not os.path.exists(filename):
            raise InvalidParamsError("account[%s] not exist" % bytes2str(pkh))
        with open(filename, 'r') as fr:
            data = json.loads(fr.read())
            ret = ( str2bytes(data['public-key']), a2b_hex(data['encrypted-private-key']) )
            cls.buff[pkh] = ret
            return ret


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
