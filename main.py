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
from flask_jsonrpc import JSONRPC
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

@jsonrpc.method('new_account') # (passphrase=String) -> String
def new_account(passphrase):
    pkh, pk, sk = crypto.generateKeysNoSeed()

    # save the encrypted sk
    encrypted_sk = crypto.aes_encrypt(sk, passphrase.encode('utf-8'))
    AccountManager.save_account(pkh, pk, encrypted_sk)

    return pkh.decode('utf-8')

@jsonrpc.method('chk_address')
def chk_address(tz1_address):
    return crypto.checkAddress(tz1_address)

@jsonrpc.method('sign(pkh=String, passphrase=String, data=String) -> dict')
def sign(pkh, passphrase, data):
    pkh = pkh.encode('utf-8')
    result = []
    err = AccountManager.load_account(pkh, result)
    if err:
        return err
    _, encrypted_sk = result[0]
    sk = crypto.aes_decrypt(encrypted_sk, passphrase.encode('utf-8'))
    sigs = crypto.sign( a2b_hex(data.encode('utf-8')), sk, crypto.watermark_generic)
    return {'edsig':b2a_hex( sigs['edsig'] ).decode('utf-8'),
            'sbytes':b2a_hex( sigs['sbytes'] ).decode('utf-8')}

class AccountManager:
    account_file_fmt = "./accounts/py-eztz-account-%s.json"

    @classmethod
    def save_account(cls, pkh, pk, encrypted_sk):
        filename = cls.account_file_fmt % pkh.decode('utf-8')
        with open(filename, 'w') as fw:
            data = {
                'public-key' : pk.decode('utf-8'),
                'encrypted-private-key' : b2a_hex(encrypted_sk).decode('utf-8')
            }
            fw.write(json.dumps(data))

    @classmethod
    def load_account(cls, pkh, result):
        import os
        filename = cls.account_file_fmt % pkh.decode('utf-8')
        if not os.path.exists(filename):
            return "account[%s] not exist" % pkh.decode('utf-8')
        with open(filename, 'r') as fr:
            data = json.loads(fr.read())
            result.append( (data['public-key'].encode('utf-8'), a2b_hex(data['encrypted-private-key'].encode('utf-8'))) )


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
