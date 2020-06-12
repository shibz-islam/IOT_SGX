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
#include "cJSON.h"
#include "RuleParser.h"


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



/*****************
 * ocall functions
 *****************/

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


void load_previous_rules(){
    size_t numRules = 0;
    ocall_get_rule_count(&numRules, NULL, 1);

    if(numRules > 0){
        Rule ruleset[numRules];
        size_t isSuccess = 0;
        ocall_get_rules(&isSuccess, ruleset, numRules, NULL, 1);
        if(isSuccess == 1){
            isSuccess = 0;
            for(int i=0; i < numRules; i++){
                //printf("\n*** deviceid=%s, ruleLength=%ld, rule=%s\n", ruleset[i].deviceID, ruleset[i].ruleLength, ruleset[i].rule);

                char *decMessage = (char *) malloc(ruleset[i].ruleLength*sizeof(char));
                sgx_status_t status = decryptMessageAES(ruleset[i].rule, ruleset[i].ruleLength, decMessage, ruleset[i].ruleLength, ruleset[i].tag);
                if(status != 0){
                    printf("Error! Decryption failed!");
                    free(decMessage);
                    //delete[] msg->text;
                }
                else{
                    Rule *myRule = new Rule();
                    myRule->rule = decMessage;
                    myRule->ruleLength = ruleset[i].ruleLength;
                    ruleManagerObj.didReceiveRule(myRule, false);
                }

            }

        }

    }
}



/*********************
 * ecall functions
 *********************/


/*
 * Enclave Initialization
 */
void ecall_initialize_enclave(){
    ruleManagerObj = RuleManager();
    load_previous_rules();
}



void ecall_decrypt_message(struct message *msg){

    char *decMessage = (char *) malloc(msg->textLength*sizeof(char));
    sgx_status_t status = decryptMessageAES(msg->text, msg->textLength, decMessage, msg->textLength, msg->tag);
    //printf("Status = %d\n", status);
    if(status != 0){
        printf("Error! Decryption failed!");
        free(decMessage);
        //delete[] msg->text;
        //delete[] msg->tag;
        //delete msg;
        return;
    }

    ruleManagerObj.didReceiveDeviceEvent(decMessage);
}


void ecall_decrypt_rule(struct message* msg){
    //printf("ecall_decrypt_rule");
    char *decMessage = (char *) malloc((msg->textLength+1)*sizeof(char));
    sgx_status_t status = decryptMessageAES(msg->text, msg->textLength, decMessage, msg->textLength, msg->tag);
    if (status != 0){
        printf("Error! Decryption failed!");
        free(decMessage);
        //delete[] msg->text;
        //delete[] msg->tag;
        //delete msg;
        return;
    }

    Rule *myRule = new Rule();
    myRule->rule = decMessage;
    myRule->ruleLength = msg->textLength;
    ruleManagerObj.didReceiveRule(myRule, true);

    free(decMessage);
    delete  myRule;

}

void ecall_check_timer_rule(int hour, int min){
    ruleManagerObj.didReceiveRequestToCheckTimerRule(hour, min);
}
int ecall_check_pending_timer_rule(int hour, int min){
    return ruleManagerObj.didReceiveRequestToCheckPendingTimerRule(hour, min);
}
