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
#include "sgx_trts.h"
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>
#include "analytics_utils.h"
#include "MessageParser.h"
#include "Constants.h"
#include "RuleManager.h"


RuleManager ruleManagerObj;

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
 * Enclave Initialization
 */
//void ecall_initialize_enclave(){
//    ruleManagerObj = RuleManager();
//
//}



/*****************
 * ocall functions
 *****************/


int get_rule_count_from_file(std::string device_id){
    struct rule new_rule[1];
    new_rule->deviceID = (char*)device_id.c_str();

    int *total_rules = static_cast<int *>(malloc(sizeof(int)));
    ocall_get_rule_count_by_id(new_rule, total_rules);
    //printf("Total rules=%d with deviceID=%s\n", *total_rules, device_id.c_str());
    return *total_rules;
}


void get_rule_from_file(std::string device_id, struct rule *ruleset, int total_rules){
    struct rule new_rule[1];
    new_rule->deviceID = (char*)device_id.c_str();
    ocall_get_rules_by_id(new_rule, ruleset, total_rules);

    for(int i=0; i < total_rules; i=i+1){
        //printf("*** Rule=%s, Tag=%s\n", ruleset[i].rule, ruleset[i].tag);
        char *decMessage = (char *) malloc((strlen(ruleset[i].rule)+1)*sizeof(char));
        sgx_status_t status = decryptMessageAES(ruleset[i].rule, strlen(ruleset[i].rule), decMessage, strlen(ruleset[i].rule), ruleset[i].tag);
        if(status != 0){
            printf("Error! Decryption failed!");
            free(decMessage);
            delete ruleset;
            return;
        }
        ruleset[i].deviceID = new_rule->deviceID;
        ruleset[i].rule = decMessage;
        ruleset[i].isEncrypted = 0;
        //TODO: handle the rules
    }
}

void save_rule_in_file(struct rule *newRule){
    char *encMessage = (char *) malloc((strlen(newRule->rule)+1)*sizeof(char));
    char *tag_msg = (char *) malloc((16+1)*sizeof(char));
    sgx_status_t status = encryptMessageAES(newRule->rule, strlen(newRule->rule), encMessage, strlen(newRule->rule), tag_msg);
    if(status != 0){
        printf("Error! Encryption failed!");
        free(encMessage);
        free(tag_msg);
        delete newRule;
        return;
    }
    //encrypt_message(decMessage, newMsg);
    //printf("######## Testing decryption\n");
    //decrypt_message(newMsg->text, newMsg->tag);

    newRule->rule = encMessage;
    newRule->tag = tag_msg;
    newRule->isEncrypted = 1;

    ocall_store_rules(newRule);
}

void sendAlertForRuleActionEmail(struct ruleActionProperty *property){
    ocall_send_alert_for_rule_action_email(property);
}

void sendAlertForRuleActionDevice(struct ruleActionProperty *property){
    char *encMessage = (char *) malloc((strlen(property->msg)+1)*sizeof(char));
    char *tag_msg = (char *) malloc((16+1)*sizeof(char));
    sgx_status_t status = encryptMessageAES(property->msg, strlen(property->msg), encMessage, strlen(property->msg), tag_msg);
    if(status != 0){
        printf("Error! Decryption failed!");
        free(encMessage);
        free(tag_msg);
        delete property;
        return;
    }
    property->msg = encMessage;
    property->tag = tag_msg;
    ocall_send_alert_for_rule_action_device(property);
}



/*********************
 * ecall functions
 *********************/



void ecall_decrypt_message(struct message *msg){
    char *decMessage = (char *) malloc((strlen(msg->text)+1)*sizeof(char));
    sgx_status_t status = decryptMessageAES(msg->text, strlen(msg->text), decMessage, strlen(msg->text), msg->tag);
    //printf("Status = %d\n", status);
    if(status != 0){
        printf("Error! Decryption failed!");
        free(decMessage);
        //delete[] msg->text;
        //delete[] msg->tag;
        //delete msg;
        return;
    }
    //TODO: Check memory first
    std::map<std::string, std::string>device_info_map = parse_decrypted_string(decMessage);
    std::string device_id = device_info_map.at(RULE_DEVICE_ID);
    //printf("$$ Device Id = %s\n", device_id.c_str());

    if(ruleManagerObj.isRuleExistInCache(device_id))
    {
        ruleManagerObj.checkRuleSatisfiability(device_id, device_info_map);
    }
    else
    {
        int total_rules = get_rule_count_from_file(device_id);
        if(total_rules>0)
        {   struct rule ruleset[total_rules];
            get_rule_from_file(device_id, ruleset, total_rules);
            ruleManagerObj.saveRulesInCache(ruleset, total_rules);
            ruleManagerObj.checkRuleSatisfiability(device_id, device_info_map);
        }
        else {
            printf("No rules found in file for Device ID: %s\n",device_id.c_str());
        }
    }
}


void ecall_decrypt_rule(struct message* msg){
    char *decMessage = (char *) malloc((strlen(msg->text)+1)*sizeof(char));
    sgx_status_t status = decryptMessageAES(msg->text, strlen(msg->text), decMessage, strlen(msg->text), msg->tag);
    if (status != 0){
        printf("Error! Decryption failed!");
        free(decMessage);
        //delete[] msg->text;
        //delete[] msg->tag;
        //delete msg;
        return;
    }
    struct rule newRule[1];
    if (ruleManagerObj.parseRule(decMessage, newRule))
    {
        //printf("newRule.deviceid = %s\n", newRule->deviceID);
        //printf("newRule.rule = %s\n", newRule->rule);

        ruleManagerObj.saveRulesInCache(newRule, 1);

        save_rule_in_file(newRule);
    }
}
