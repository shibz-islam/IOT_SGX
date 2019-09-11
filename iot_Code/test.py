import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


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


if __name__ == '__main__':
    aes_gcm_encryption()
