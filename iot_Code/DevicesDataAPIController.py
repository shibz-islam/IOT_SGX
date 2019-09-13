# -*- coding: utf-8 -*-
from Crypto.Cipher import AES
from flask import Flask, url_for, jsonify, request
from cryptography.fernet import Fernet
import hashlib

import base64
import hashlib
from Crypto.Cipher import AES
from Crypto import Random

BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]


# Helper Function for Encrption
def encryptData(raw, password):
    private_key = hashlib.sha256(password.encode("utf-8")).digest()
    raw = pad(raw)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    return base64.b64encode(iv + cipher.encrypt(raw))

# Helper Function for Decryption
def decryptData(enc, password):
    private_key = hashlib.sha256(password.encode("utf-8")).digest()
    enc = base64.b64decode(enc)
    iv = enc[:16]
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(enc[16:]))

#TODO : add to handle all data in HSML format and return parsed data
def processDataAndReturnParsedJson(data):
    parsed_hsml_data = None
    return parsed_hsml_data


######################
# =============================================================================
# key = Fernet.generate_key()
# secretKeyFile = open('key.key', 'wb')
# secretKeyFile.write(key) # The key is type bytes still
# secretKeyFile.close()
# =============================================================================
# =============================================================================
#
# file=open('key.key','rb')
# content=file.read()
# file.close()
# =============================================================================
#####################

app = Flask(__name__)
import random


@app.route('/processDeviceData')
def api_root():
    # Main Controller which will Manage the device services
    if request.method == 'POST':
        encrypted_data = "False"
    try:
        password = "passwordForEncryption"
        fetch_device_data = request.get_json().get("data")
        parsed_data = processDataAndReturnParsedJson(fetch_device_data)
        print("Inside API: ", parsed_data)
        encrypted_data = encryptData(parsed_data, password)
        resp = jsonify(**{'d': dict(data=encrypted_data)})
        resp.status_code = 200

    except Exception as e:
        resp = jsonify(**{'d': dict(data=encrypted_data)})
        resp.status_code = 500
    return resp


if __name__ == '__main__':
    app.run()