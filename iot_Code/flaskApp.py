# -*- coding: utf-8 -*-

from flask import Flask, url_for,jsonify
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

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
# =============================================================================
# message=(str(29.58)).encode()
# f = Fernet(key)
# encryptedTemp=f.encrypt(message)
# 
# encryptedInString=encryptedTemp.decode('utf-8')
# 
# decrtyptedMessage=f.decrypt(encryptedInString.encode())
# =============================================================================

app = Flask(__name__)
import os, random


def read_data_from_file(filepath, filename):
    path = os.path.join(filepath, filename)
    file = open(path, 'rb')
    data = file.read()
    file.close()
    return data


def fernet_encryption():
    did = '1'
    dtype = 'TemperatureSensor'
    secretByteKey = Fernet.generate_key()
    f = Fernet(secretByteKey)
    devId=f.encrypt(did.encode())
    devType=f.encrypt(dtype.encode())
    data=f.encrypt(str(round(random.uniform(25.0,30.0),2)).encode())
    d = {'deviceId': devId.decode('utf-8'), 'deviceType': devType.decode('utf-8'), 'data': {'temp': data.decode('utf-8')}}
    return d


def aes_gcm_encryption():
    did = '1'
    dtype = 'TemperatureSensor'
    aad = "authenticated but unencrypted data"
    # key = AESGCM.generate_key(bit_length=128)
    # iv = os.urandom(12)
    key = read_data_from_file("/home/shihab/Desktop", 'key.key')
    iv = read_data_from_file("/home/shihab/Desktop", 'iv')
    aesgcm = AESGCM(key)
    devId = aesgcm.encrypt(iv, did.encode(), aad.encode())
    devType = aesgcm.encrypt(iv, dtype.encode(), aad.encode())
    data = aesgcm.encrypt(iv, str(round(random.uniform(25.0, 30.0), 2)).encode(), aad.encode())
    d = {'deviceId': devId.decode('ISO-8859-1'), 'deviceType': devType.decode('ISO-8859-1'),
         'data': {'temp': data.decode('ISO-8859-1')}}
    return d


@app.route('/')
def api_root():
    #d={'deviceId':'1','deviceType':'TemperatureSensor','data':str(random.uniform(28.0,30.0))}
    #return(jsonify(d))
    return 'Welcome Preeti'


@app.route('/temp')
def api_temp():
    # d= fernet_encryption()

    d = aes_gcm_encryption()

    print(jsonify(d))
    return(jsonify(d))


@app.route('/articles')
def api_articles():
    return 'List of ' + url_for('api_articles')


@app.route('/articles/<articleid>')
def api_article(articleid):
    return 'You are reading ' + articleid


if __name__ == '__main__':
    app.run()
