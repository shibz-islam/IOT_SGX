#include <Python.h>
#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <string.h>


/* AES-GCM test data from NIST public test vectors */

static const unsigned char gcm_key[] = {
        0xee, 0xbc, 0x1f, 0x57, 0x48, 0x7f, 0x51, 0x92, 0x1c, 0x04, 0x65, 0x66,
        0x5f, 0x8a, 0xe6, 0xd1, 0x65, 0x8b, 0xb2, 0x6d, 0xe6, 0xf8, 0xa0, 0x69,
        0xa3, 0x52, 0x02, 0x93, 0xa5, 0x72, 0x07, 0x8f
};

static const unsigned char gcm_key2[] = { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf };

static const unsigned char gcm_iv[] = {
        0x99, 0xaa, 0x3e, 0x68, 0xed, 0x81, 0x73, 0xa0, 0xee, 0xd0, 0x66, 0x84
};

static const unsigned char gcm_pt[] = {
        0xf5, 0x6e, 0x87, 0x05, 0x5b, 0xc3, 0x2d, 0x0e, 0xeb, 0x31, 0xb2, 0xea,
        0xcc, 0x2b, 0xf2, 0xa5
};

static const unsigned char gcm_aad[] = {
        0x4d, 0x23, 0xc3, 0xce, 0xc3, 0x34, 0xb4, 0x9b, 0xdb, 0x37, 0x0c, 0x43,
        0x7f, 0xec, 0x78, 0xde
};

static const unsigned char gcm_ct[] = {
        0xf7, 0x26, 0x44, 0x13, 0xa8, 0x4c, 0x0e, 0x7c, 0xd5, 0x36, 0x86, 0x7e,
        0xb9, 0xf2, 0x17, 0x36
};

static const unsigned char gcm_tag[] = {
        0x67, 0xba, 0x05, 0x10, 0x26, 0x2a, 0xe4, 0x87, 0xd7, 0x37, 0xee, 0x62,
        0x98, 0xf7, 0x7e, 0x0c
};

//static const unsigned char gcm_temp[] = {
//        'a', 'b', 'c', 'd', 'e', 'f'
//};


void aes_gcm_encrypt_decrypt(char* gcm_temp, int gcm_len, char *encMessageOut, char *decMessageOut, char *tag){
    unsigned char gcm_output[1024];
    unsigned char gcm_output_tag[1024];
    int rv, outlen, tmplen, gcm_output_len;
//    printf("gcm_temp: %ld\n", sizeof(gcm_temp));

    /*ENCRYPT*/
    EVP_CIPHER_CTX *ctx;
    printf("--------- AES GCM Encrypt: ----------\n");
    printf("*** Plaintext:\n");
    BIO_dump_fp(stdout, gcm_temp, gcm_len);
    ctx = EVP_CIPHER_CTX_new();
    /* Set cipher type and mode */
    EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
    /* Set IV length if default 96 bits is not appropriate */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, sizeof(gcm_iv), NULL);
    /* Initialise key and IV */
    EVP_EncryptInit_ex(ctx, NULL, NULL, gcm_key2, gcm_iv);
    /* Zero or more calls to specify any AAD */
    EVP_EncryptUpdate(ctx, NULL, &outlen, gcm_aad, sizeof(gcm_aad));
    /* Encrypt plaintext */
    EVP_EncryptUpdate(ctx, gcm_output, &outlen, gcm_temp, gcm_len);
    /* Output encrypted block */
    printf("*** Ciphertext:\n");
    gcm_output_len = strlen(gcm_output);
    BIO_dump_fp(stdout, gcm_output, outlen);
    printf("%s\n", gcm_output);
    /* Finalise: note get no output for GCM */
    rv = EVP_EncryptFinal_ex(ctx, gcm_output, &outlen);

    printf("Encryption Verify %s\n", rv > 0 ? "Successful!" : "Failed!");
    /* Get tag */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, gcm_output_tag);
    /* Output tag */
    printf("*** Tag:\n");
    BIO_dump_fp(stdout, gcm_output_tag, strlen(gcm_output_tag));

    memcpy(encMessageOut, gcm_output, gcm_output_len);
    memcpy(tag, gcm_output_tag, 16);


    //EVP_CIPHER_CTX_free(ctx);

    /*DECRYPT*/
    unsigned char outbuf[1024];
    printf("--------- AES GCM Decrypt: ----------\n");
    printf("*** Ciphertext:\n");
    BIO_dump_fp(stdout, gcm_output, strlen(gcm_output));
    printf("*** Tag:\n");
    BIO_dump_fp(stdout, gcm_output_tag, strlen(gcm_output_tag));
    ctx = EVP_CIPHER_CTX_new();
    /* Select cipher */
    EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
    /* Set IV length, omit for 96 bits */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, sizeof(gcm_iv), NULL);
    /* Specify key and IV */
    EVP_DecryptInit_ex(ctx, NULL, NULL, gcm_key2, gcm_iv);
    /* Zero or more calls to specify any AAD */
    EVP_DecryptUpdate(ctx, NULL, &tmplen, gcm_aad, sizeof(gcm_aad));
    /* Decrypt plaintext */
    EVP_DecryptUpdate(ctx, outbuf, &tmplen, gcm_output, strlen(gcm_output));
    /* Output decrypted block */
    printf("*** Plaintext:\n");
    BIO_dump_fp(stdout, outbuf, tmplen);
//    printf("tmplen: %d\n", tmplen);
    /* Set expected tag value. */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, strlen(gcm_output_tag),
                        (void *)gcm_output_tag);
    /* Finalise: note get no output for GCM */
    rv = EVP_DecryptFinal_ex(ctx, outbuf, &tmplen);
    /*
     * Print out return value. If this is not successful authentication
     * failed and plaintext is not trustworthy.
     */
    printf("Tag Verify %s\n", rv > 0 ? "Successful!" : "Failed!");
    EVP_CIPHER_CTX_free(ctx);

    memcpy(decMessageOut, outbuf, tmplen);
}


void aes_gcm_encrypt(char* gcm_temp, int gcm_len, char *encMessageOut, char *tag)
{
    unsigned char gcm_output[1024];
    unsigned char gcm_output_tag[1024];
    int rv, outlen, tmplen, gcm_output_len;
//    printf("gcm_temp: %ld\n", sizeof(gcm_temp));

    /*ENCRYPT*/
    EVP_CIPHER_CTX *ctx;
    printf("\n--------- AES GCM Encrypt: ----------\n");
    printf("*** Plaintext:\n");
    BIO_dump_fp(stdout, gcm_temp, gcm_len);
    ctx = EVP_CIPHER_CTX_new();
    /* Set cipher type and mode */
    EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
    /* Set IV length if default 96 bits is not appropriate */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, sizeof(gcm_iv), NULL);
    /* Initialise key and IV */
    EVP_EncryptInit_ex(ctx, NULL, NULL, gcm_key2, gcm_iv);
    /* Zero or more calls to specify any AAD */
    EVP_EncryptUpdate(ctx, NULL, &outlen, gcm_aad, sizeof(gcm_aad));
    /* Encrypt plaintext */
    EVP_EncryptUpdate(ctx, gcm_output, &outlen, gcm_temp, gcm_len);
    /* Output encrypted block */
    printf("*** Ciphertext:\n");
    gcm_output_len = strlen(gcm_output);
    BIO_dump_fp(stdout, gcm_output, outlen);
    printf("%s\n", gcm_output);
    /* Finalise: note get no output for GCM */
    rv = EVP_EncryptFinal_ex(ctx, gcm_output, &outlen);

    printf("Encryption Verify %s\n", rv > 0 ? "Successful!" : "Failed!");
    /* Get tag */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, gcm_output_tag);
    /* Output tag */
    printf("*** Tag:\n");
    BIO_dump_fp(stdout, gcm_output_tag, strlen(gcm_output_tag));
    printf("$$$$ gcm_output_tag = %d\n", strlen(gcm_output_tag));

    memcpy(encMessageOut, gcm_output, gcm_output_len);
    memcpy(tag, gcm_output_tag, 16);

    encMessageOut[gcm_output_len] = '\0';
    tag[16] = '\0';

    EVP_CIPHER_CTX_free(ctx);
    printf("--------- End Encryption: ----------\n\n");
}


void aes_gcm_decrypt(char* gcm_output, int gcm_output_len, char* decMessageOut, char *gcm_output_tag)
{

    int rv, tmplen;
//    printf("gcm_temp: %ld\n", sizeof(gcm_temp));

    EVP_CIPHER_CTX *ctx;

    unsigned char outbuf[1024];
    printf("\n--------- AES GCM Decrypt: ----------\n");
    printf("*** Ciphertext:\n");
    BIO_dump_fp(stdout, gcm_output, gcm_output_len);
    printf("*** Tag:\n");
    BIO_dump_fp(stdout, gcm_output_tag, strlen(gcm_output_tag));
    ctx = EVP_CIPHER_CTX_new();
    /* Select cipher */
    EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
    /* Set IV length, omit for 96 bits */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, sizeof(gcm_iv), NULL);
    /* Specify key and IV */
    EVP_DecryptInit_ex(ctx, NULL, NULL, gcm_key2, gcm_iv);
    /* Zero or more calls to specify any AAD */
    EVP_DecryptUpdate(ctx, NULL, &tmplen, gcm_aad, sizeof(gcm_aad));
    /* Decrypt plaintext */
    EVP_DecryptUpdate(ctx, outbuf, &tmplen, gcm_output, gcm_output_len);
    /* Output decrypted block */
    printf("*** Plaintext:\n");
    BIO_dump_fp(stdout, outbuf, tmplen);

    memcpy(decMessageOut, outbuf, tmplen);
    decMessageOut[tmplen] = '\0';
//    printf("decMessageOut = %s\n", decMessageOut);
//    printf("decMessageOut length: %d\n", strlen(decMessageOut));

    /* Set expected tag value. */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, strlen(gcm_output_tag),
                        (void *)gcm_output_tag);
    /* Finalise: note get no output for GCM */


    rv = EVP_DecryptFinal_ex(ctx, outbuf, &tmplen);
    /*
     * Print out return value. If this is not successful authentication
     * failed and plaintext is not trustworthy.
     */
    printf("Tag Verify %s\n", rv > 0 ? "Successful!" : "Failed!");

    EVP_CIPHER_CTX_free(ctx);

    printf("--------- End Decryption: ----------\n\n");


}


static PyObject* encrypt_msg(PyObject* self, PyObject* args)
{
    int n;
    char *data;
    if(!PyArg_ParseTuple(args, "si", &data, &n ))
        return NULL;
    printf("Got Data: %s\n", data);
    printf("Length of Data: %d\n", n);

    char *encMessage = (char *) malloc((n+1)*sizeof(char));
    char *tag = (char *) malloc((16+1)*sizeof(char));

    printf("Calling aes_gcm_encrypt...\n");
    aes_gcm_encrypt(data, n, encMessage, tag);
    int extra = 0;
    if (strlen(encMessage) > n)
        extra = strlen(encMessage) - n;
    printf("Length of encMessage: %d, and tag: %d\n", strlen(encMessage), strlen(tag));

    return Py_BuildValue("y#y#", encMessage, strlen(encMessage)-extra, tag, strlen(tag)-1);
}


static PyObject* decrypt_msg(PyObject* self, PyObject* args)
{
    int n, m;
    char *data;
    char *tag;
    if(!PyArg_ParseTuple(args, "s#s#", &data, &n, &tag, &m ))
        return NULL;
    printf("Got Data: %s\n", data);
    printf("Length of Data: %d\n", n);
    printf("Got Tag length: %d\n", m);

    char *decMessage = (char *) malloc((n+1)*sizeof(char));

    printf("Calling aes_gcm_encrypt_decrypt...\n");
    aes_gcm_decrypt(data, n, decMessage, tag);
    printf("decMessage: %s\n", decMessage);
    printf("Length of decMessage: %d\n", strlen(decMessage));
    int extra = 0;
    if (strlen(decMessage) > n)
        extra = strlen(decMessage) - n;

    return Py_BuildValue("y#", decMessage, strlen(decMessage)-extra);
}


static PyObject* encrypt_decrypt_msg(PyObject* self, PyObject* args)
{
    int n;
    char *data;
    if(!PyArg_ParseTuple(args, "s", &data))
        return NULL;
    printf("Got Data: %s\n", data);
    n = strlen(data);
    printf("Length of Data: %d\n", n);

    char *encMessage = (char *) malloc((n+1)*sizeof(char));
    char *decMessage = (char *) malloc((n+1)*sizeof(char));
    char *tag = (char *) malloc((16+1)*sizeof(char));

    printf("Calling aes_gcm_encrypt_decrypt...\n");
//    aes_gcm_encrypt_decrypt(data, strlen(data), encMessage, decMessage, tag);
    aes_gcm_encrypt(data, n, encMessage, tag);
    aes_gcm_decrypt(encMessage, n, decMessage, tag);

    printf("encMessage: %s\n", encMessage);
    printf("decMessage: %s\n", decMessage);

    printf("Length of encMessage: %ld\n", strlen(encMessage));
    printf("Length of decMessage: %ld\n", strlen(decMessage));
    printf("Length of Tag: %ld\n", strlen(tag));
//    return Py_BuildValue("si", gcm_output, strlen(gcm_output));
//    char data[] = "Hello";
//    aes_gcm_encrypt_decrypt(data, strlen(data));
}



// Our Module's Function Definition struct
// We require this `NULL` to signal the end of our method
// definition
static PyMethodDef myMethods[] = {
    { "encrypt_msg", encrypt_msg, METH_VARARGS, "returns encrypted message" },
    { "decrypt_msg", decrypt_msg, METH_VARARGS, "returns decrypted message" },
    { "encrypt_decrypt_msg", encrypt_decrypt_msg, METH_VARARGS, "encryption and decryption test" },
    { NULL, NULL, 0, NULL }
};

// Our Module Definition struct
static struct PyModuleDef cryptoTestModule = {
    PyModuleDef_HEAD_INIT,
    "cryptoTestModule",
    "Test Module",
    -1,
    myMethods
};

// Initializes our module using our above struct
PyMODINIT_FUNC PyInit_cryptoTestModule(void)
{
    return PyModule_Create(&cryptoTestModule);
}