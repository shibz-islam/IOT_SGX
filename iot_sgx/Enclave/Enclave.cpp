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
#include "Constants.h"



/*
 * For Test Purpose
 */

char savedString[100] = "Default Enclave savedText";
int savedInt = -1;

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

void encrypt_message(char* decMessage, struct message* newMSG){
    size_t decMessageLen = strlen(decMessage);
    size_t encMessageLen = decMessageLen;
    char *encMessage = (char *) malloc((decMessageLen+1)*sizeof(char));
    char *tag_msg = (char *) malloc((16+1)*sizeof(char));
    encryptMessageAES(decMessage, decMessageLen, encMessage, encMessageLen, tag_msg);
    encMessage[encMessageLen] = '\0';
    tag_msg[16] = '\0';
    //printf("Encrypted message: %s with length %ld\n", encMessage, strlen(encMessage));
    //printf("Tag: %s with length %ld\n", tag_msg, strlen(tag_msg));
    newMSG->text = encMessage;
    newMSG->tag = tag_msg;
}


char* decrypt_message(char* encMessage, char* tag){
    size_t len = strlen(encMessage);
    size_t decMessageLen = len;
    printf("### From Enclave - Data, tag: \n %s\n %s\n", encMessage, tag);
    //printf("### From Enclave - Data, tag sizes: \n %ld\n %ld\n", len, strlen(tag));
    char *decMessage = (char *) malloc((decMessageLen+1)*sizeof(char));
    decryptMessageAES(encMessage, len, decMessage, decMessageLen, tag);
    decMessage[decMessageLen] = '\0';
    printf("Decrypted message: %s with length %ld\n", decMessage, strlen(decMessage));
    return decMessage;
}


/*
 * Helper functions
 */

void get_rule_from_file(char *msg){
    std::map<std::string, std::string>device_info_map = parse_decrypted_string(msg);
    std::string device_id = device_info_map.at(RULE_DEVICE_ID);
    printf("Device Id = %s\n", device_id.c_str());
    struct rule newRule[1];
    newRule->deviceID = (char*)device_id.c_str();

    int *totalRules = static_cast<int *>(malloc(sizeof(int)));
    ocall_get_rule_count_by_id(newRule, totalRules);
    printf("Total rules=%d with deviceID=%s\n", *totalRules, device_id.c_str());

//    size_t len = *totalRules;
    if(*totalRules>0)
    {
        struct rule ruleset[*totalRules];
        ocall_get_rules_by_id(newRule, ruleset, *totalRules);

        printf("Total Rules = %d\n", *totalRules);
        for(int i=0; i < *totalRules; i=i+1){
            printf("*** Rule=%s, Tag=%s\n", ruleset[i].rule, ruleset[i].tag);
            decrypt_message(ruleset[i].rule, ruleset[i].tag);
            //TODO: handle the rules
        }
    } else{
        printf("No rules for Device ID: %s\n",device_id.c_str());
    }
}


/*
 * ecall functions
 */


void ecall_encrypt_message(struct message *msg){
    struct message newMSG[1];
    encrypt_message(msg->text, newMSG);
    ocall_get_message_from_enclave(newMSG);
}


void ecall_decrypt_message(struct message *msg){
    char *decMessage = decrypt_message(msg->text, msg->tag);
    get_rule_from_file(decMessage);
}


void ecall_decrypt_rule(struct message* msg){
    char *decMessage = decrypt_message(msg->text, msg->tag);

    struct rule newRule[1];
    if (parse_rule(decMessage, newRule))
    {
        printf("newRule.deviceid = %s\n", newRule->deviceID);
        printf("newRule.rule = %s\n", newRule->rule);
        char *decMessage = (char *) malloc((strlen(newRule->rule))*sizeof(char));
        decMessage = newRule->rule;
        struct message newMsg[1];
        encrypt_message(decMessage, newMsg);

        newRule->rule = newMsg->text;
        newRule->tag = newMsg->tag;
        newRule->isEncrypted = 1;

        ocall_store_rules(newRule);
    }
}



void ecall_get_rules_from_db(struct message* msg, size_t len){
//    printf("Total len = %ld\n", len);
//    for (int i = 0; i < len; ++i) {
//        char* encMessage =  msg[i].text;
//        size_t len = strlen(encMessage);
//        char* tag = msg[i].tag;
//        size_t decMessageLen = len;
//        printf("### From Enclave - Data, tag: \n %s\n %s\n", encMessage, tag);
//        printf("### From Enclave - Data, tag sizes: \n %ld\n %ld\n", len, strlen(tag));
//        char *decMessage = (char *) malloc((decMessageLen+1)*sizeof(char));
//        decryptMessageAES(encMessage, len, decMessage, decMessageLen, tag);
//        decMessage[decMessageLen] = '\0';
//        printf("Decrypted message: %s with length %ld\n", decMessage, strlen(decMessage));
//        save_rule_base(decMessage);
//    }
}