import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import json, time, threading
import socketClient, CryptoHelper, Helper, Constants
from MongoManager import MongoManager


def write_bytes_to_file(filename, data):
    secretKeyFile = open(filename, 'wb')
    secretKeyFile.write(data)  # The key is type bytes still
    secretKeyFile.close()


def aes_gcm_encryption():
    data = "a secret message"
    aad = "authenticated but unencrypted data"
    data = data.encode()
    aad = aad.encode()

    key = AESGCM.generate_key(bit_length=128)
    write_bytes_to_file('key.key', key)
    aesgcm = AESGCM(key)
    iv = os.urandom(12)
    write_bytes_to_file('iv', iv)

    ct = aesgcm.encrypt(iv, data, aad)
    print(ct)
    print(type(ct))
    ct = ct.decode('ISO-8859-1')
    print(ct)
    dct = aesgcm.decrypt(iv, ct.encode('ISO-8859-1'), aad)
    print(dct.decode())


def simulate_iot_data():
    soc2 = socketClient.connect_to_server(port=20004)
    sample_data1 = {'deviceID': '234', 'deviceType': 'TemperatureSensor', 'data': '90.0'}
    sample_data2 = {'deviceID': '567', 'deviceType': 'HumiditySensor', 'data': '70.0'}
    count = 0
    while True:
        if count%2==0:
            sample_data = sample_data1
        else:
            sample_data = sample_data2
        jd = Helper.get_json_data(sample_data)
        enc_rule = CryptoHelper.aes_gcm_encryption_with_tag(jd)
        socketClient.send_to_server(soc2, enc_rule)
        count += 1
        if count == 2:
            break
        # time.sleep(30)
    soc2.close()


def save_rule_in_db():
    mm = MongoManager(ip='localhost', port=27017, db_name='IOT', collection_name='rulebase')
    mm.init_connection()

    # rule = "{'deviceID': '123', 'ruleID': '168hlp', 'userID': '849gtt', 'name': 'TempRule', 'measurement': 'Temperature', 'operator': '1', 'threshold': 60.0, 'action': '0', 'email': 'abc@gmail.com', 'email_title': 'Alert!'}"
    rule = "{'deviceID': '345', 'ruleID': '526dfg', 'userID': '563y2k', 'name': 'HumRule', 'measurement': 'Humidity', 'operator': '0', 'threshold': 30.0, 'action': '0', 'email': 'abc@gmail.com', 'email_title': 'Alert!'}"
    json_data = Helper.get_json_data(rule)
    print(json_data)

    enc_rule = CryptoHelper.aes_gcm_encryption_with_tag(json_data)
    json_data = json.loads(enc_rule)
    print(json_data)

    mm.insert_one_into_db(json_data)


if __name__ == '__main__':
    # aes_gcm_encryption()
    simulate_iot_data()


