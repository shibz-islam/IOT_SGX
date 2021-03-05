//
// Created by shihab on 7/16/19.
//

#include "aes_gcm.h"
#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <string.h>

static const unsigned char gcm_key[] = {
        0xee, 0xbc, 0x1f, 0x57, 0x48, 0x7f, 0x51, 0x92, 0x1c, 0x04, 0x65, 0x66, 0x5f, 0x8a, 0xe6, 0xd1
};
static const unsigned char gcm_iv[] = {
        0x99, 0xaa, 0x3e, 0x68, 0xed, 0x81, 0x73, 0xa0, 0xee, 0xd0, 0x66, 0x84
};
static const unsigned char gcm_aad[] = {
        0x4d, 0x23, 0xc3, 0xce, 0xc3, 0x34, 0xb4, 0x9b, 0xdb, 0x37, 0x0c, 0x43,
        0x7f, 0xec, 0x78, 0xde
};


unsigned char gcm_output[1024];
unsigned char gcm_output_tag[1024];

void aes_gcm_encrypt(char *msg, int msg_len, char *encMessageOut, char *tag)
{
    printf("\n--------- AES GCM Encrypt: ----------\n");
    printf("msg_len: %ld\n", msg_len);
    //const unsigned char* t_msg = reinterpret_cast<const unsigned char *>( msg );
    EVP_CIPHER_CTX *ctx;
    int outlen, tmplen, rv, output_len;
    unsigned char outbuf[1024];
    printf("AES GCM Encrypt:\n");
    printf("Plaintext:\n");
    BIO_dump_fp(stdout, msg, msg_len);
    ctx = EVP_CIPHER_CTX_new();
    /* Set cipher type and mode */
    EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
    /* Set IV length if default 96 bits is not appropriate */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, sizeof(gcm_iv), NULL);
    /* Initialise key and IV */
    EVP_EncryptInit_ex(ctx, NULL, NULL, gcm_key, gcm_iv);
    /* Zero or more calls to specify any AAD */
    EVP_EncryptUpdate(ctx, NULL, &outlen, gcm_aad, sizeof(gcm_aad));
    /* Encrypt plaintext */
    EVP_EncryptUpdate(ctx, gcm_output, &outlen, reinterpret_cast<const unsigned char *>( msg ), msg_len);
    /* Output encrypted block */
    printf("Ciphertext:\n");
    output_len = strlen(reinterpret_cast<const char *> (gcm_output));
    BIO_dump_fp(stdout, reinterpret_cast<const char *> (gcm_output), output_len);
    /* Finalise: note get no output for GCM */
    rv = EVP_EncryptFinal_ex(ctx, gcm_output, &outlen);
    printf("Encryption Verify %s\n", rv > 0 ? "Successful!" : "Failed!");
    /* Get tag */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, gcm_output_tag);
    /* Output tag */
    printf("Tag:\n");
    BIO_dump_fp(stdout, reinterpret_cast<const char *> (gcm_output_tag), 16);
    EVP_CIPHER_CTX_free(ctx);

    printf("output_len: %ld\n", output_len);

    memcpy(encMessageOut,reinterpret_cast<const char *> (gcm_output),output_len);
    encMessageOut[output_len] = '\0';
    memcpy(tag,reinterpret_cast<const char *> (gcm_output_tag),16);

    printf("--------- End Encryption: ----------\n\n");
}


void aes_gcm_decrypt(char* gcm_output, int gcm_output_len, char* decMessageOut, char *gcm_output_tag)
{
    printf("\n--------- AES GCM Decrypt: ----------\n");
    int rv, tmplen;
    printf("gcm_output_len: %ld\n", gcm_output_len);

    EVP_CIPHER_CTX *ctx;

    unsigned char outbuf[1024];
    printf("\n--------- AES GCM Decrypt: ----------\n");
    printf("*** Ciphertext:\n");
    BIO_dump_fp(stdout, gcm_output, gcm_output_len);
    printf("*** Tag:\n");
    BIO_dump_fp(stdout, reinterpret_cast<const char *> (gcm_output_tag), strlen(gcm_output_tag));
    ctx = EVP_CIPHER_CTX_new();
    /* Select cipher */
    EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
    /* Set IV length, omit for 96 bits */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, sizeof(gcm_iv), NULL);
    /* Specify key and IV */
    EVP_DecryptInit_ex(ctx, NULL, NULL, gcm_key, gcm_iv);
    /* Zero or more calls to specify any AAD */
    EVP_DecryptUpdate(ctx, NULL, &tmplen, gcm_aad, sizeof(gcm_aad));
    /* Decrypt plaintext */
    EVP_DecryptUpdate(ctx, outbuf, &tmplen, reinterpret_cast<const unsigned char *> (gcm_output), gcm_output_len);
    /* Output decrypted block */
    printf("*** Plaintext:\n");
    BIO_dump_fp(stdout, reinterpret_cast<const char *> (outbuf), tmplen);

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

