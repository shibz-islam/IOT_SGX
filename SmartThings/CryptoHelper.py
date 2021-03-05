import Helper
import json, os, random
from base64 import b64encode, b64decode
from Cryptodome.Cipher import AES



TAG_LENGTH = 16
IV_LENGTH = 12
KEY = [0xee, 0xbc, 0x1f, 0x57, 0x48, 0x7f, 0x51, 0x92, 0x1c, 0x04, 0x65, 0x66, 0x5f, 0x8a, 0xe6, 0xd1]
IV = [0x99, 0xaa, 0x3e, 0x68, 0xed, 0x81, 0x73, 0xa0, 0xee, 0xd0, 0x66, 0x84]
AAD = [0x4d, 0x23, 0xc3, 0xce, 0xc3, 0x34, 0xb4, 0x9b, 0xdb, 0x37, 0x0c, 0x43, 0x7f, 0xec, 0x78, 0xde]

key_bytearray = bytearray.fromhex(bytearray(KEY).hex())
iv_bytearray = bytearray.fromhex(bytearray(IV).hex())
aad_bytearray = bytearray.fromhex(bytearray(AAD).hex())


""" 
Encryption 
"""
def aes_gcm_encryption_with_tag(data):
    """

    :param data: json format
    :return: str of json
    """
    msg_byte = json.dumps(data).encode()
    cipher = AES.new(key_bytearray, AES.MODE_GCM, nonce=iv_bytearray)
    cipher.update(aad_bytearray)
    ciphertext, tag = cipher.encrypt_and_digest(msg_byte)
    #print("CipherText: ", ciphertext, len(ciphertext))
    #print("Tag: ", tag, len(tag))

    json_k = ['cp', 'tag']
    json_v = [b64encode(x).decode('utf-8') for x in [ciphertext, tag]]
    #json_v = [x.decode('latin-1') for x in [ciphertext, tag]]
    result_json =  Helper.get_json_data(dict(zip(json_k, json_v)))
    print("Message after encryption: ", result_json)
    return json.dumps(result_json)



""" 
Decryption 
"""
def aes_gcm_decryption_with_tag(data):
    """

    :param data:
    :return: decrypted json
    """

    b64 = json.loads(data)
    json_k = ['cp', 'tag']
    jv = {k: b64decode(b64[k]) for k in json_k}
    #print("@Msg: ", jv)

    cipher = AES.new(key_bytearray, AES.MODE_GCM, nonce=iv_bytearray)
    cipher.update(aad_bytearray)
    plaintext = cipher.decrypt_and_verify(jv['cp'], jv['tag'])
    if plaintext is not None:
        decrypted_msg = json.loads(plaintext.decode())
        print("@Message after decryption: ", decrypted_msg)
        return decrypted_msg
    return None


def test():
    data = "{'deviceId': 2, 'deviceType': 'Bulb', 'data': 1234}"
    json_data = Helper.get_json_data(data)
    ct = aes_gcm_encryption_with_tag(json_data)
    json_data = aes_gcm_decryption_with_tag(ct)


if __name__ == '__main__':
    test()
