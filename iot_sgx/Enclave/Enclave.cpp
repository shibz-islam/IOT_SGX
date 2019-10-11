/*
 * Copyright (C) 2011-2018 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "Enclave.h"
#include "Enclave_t.h" /* print_string */
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>
#include "analytics_utils.h"
#include "MessageParser.h"
#include "RuleBase.h"


char savedString[100] = "Default Enclave savedText";
int savedInt = -1;
const char *keyname = "/home/shihab/Desktop/key.key";
int keysize = 16;
const char *ivname = "/home/shihab/Desktop/iv";
int ivsize = 12;

// change a buffer with a constant string
void enclaveChangeBuffer(char *buf, size_t len)
{
    const char *secret = "Hello Enclave!";
    if (len > strlen(secret))
    {
        memcpy(buf, secret, strlen(secret) + 1);
    } else {
        memcpy(buf, "false", strlen("false") + 1);
    }
}

// write a var to the buffer
void enclaveStringSave(char *input, size_t len) {
    if ((strlen(input) + 1) < 100)
    {
        memcpy(savedString, input, strlen(input) + 1);
    } else {
        memcpy(input, "false", strlen("false") + 1);
    }
}

// save the buffer to a var
void enclaveStringLoad(char *output, size_t len) {
    if (len > strlen(savedString))
    {
        memcpy(output, savedString, strlen(savedString) + 1);
    } else {
        memcpy(output, "false", strlen("false") + 1);
    }
}

// save a int to a var
void enclaveSaveInt(int input) {
    savedInt = input;
}

// return a var
int enclaveLoadInt() {
    return savedInt;
}

/*
 * printf:
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
int printf(const char* fmt, ...)
{
    char buf[BUFSIZ] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
}


/*
 * Crypto functions
 */

void ecall_encrypt_message(struct message *msg){
    char* decMessage =  msg->text;
    size_t decMessageLen = strlen(decMessage);
    size_t encMessageLen = decMessageLen;
    char *encMessage = (char *) malloc((decMessageLen+1)*sizeof(char));
    char *tag_msg = (char *) malloc((16+1)*sizeof(char));
    encryptMessageAES(decMessage, decMessageLen, encMessage, encMessageLen, tag_msg);
    encMessage[encMessageLen] = '\0';
    tag_msg[16] = '\0';
    printf("Encrypted message: %s with length %ld\n", encMessage, strlen(encMessage));
    printf("Tag: %s with length %ld\n", tag_msg, strlen(tag_msg));

    struct message newMSG[1];
    newMSG->text = encMessage;
    newMSG->tag = tag_msg;
    ocall_get_message_from_enclave(newMSG);
}


void ecall_decrypt_message(struct message *msg){
    char* encMessage =  msg->text;
    size_t len = strlen(encMessage);
    char* tag = msg->tag;
    size_t decMessageLen = len;
    printf("### From Enclave - Data, tag: \n %s\n %s\n", encMessage, tag);
    printf("### From Enclave - Data, tag sizes: \n %ld\n %ld\n", len, strlen(tag));
    char *decMessage = (char *) malloc((decMessageLen+1)*sizeof(char));
    decryptMessageAES(encMessage, len, decMessage, decMessageLen, tag);
    decMessage[decMessageLen] = '\0';
    printf("Decrypted message: %s with length %ld\n", decMessage, strlen(decMessage));


//    struct message newMSG[1];
//    newMSG->text = decMessage;
//    ecall_encrypt_message(newMSG);


    start_rule_base(decMessage);

}


void ecall_decrypt_rule(struct message* msg){
    char* encMessage =  msg->text;
    size_t len = strlen(encMessage);
    char* tag = msg->tag;
    size_t decMessageLen = len;
    printf("### From Enclave - Data, tag: \n %s\n %s\n", encMessage, tag);
    printf("### From Enclave - Data, tag sizes: \n %ld\n %ld\n", len, strlen(tag));
    char *decMessage = (char *) malloc((decMessageLen+1)*sizeof(char));
    decryptMessageAES(encMessage, len, decMessage, decMessageLen, tag);
    decMessage[decMessageLen] = '\0';
    printf("Decrypted message: %s with length %ld\n", decMessage, strlen(decMessage));

    save_rule_base(decMessage);
}