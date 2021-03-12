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
#include "Constants.h"
#include "RuleManager.h"
#include "cJSON.h"
#include "RuleParser.h"
#include "EnclaveHelper.h"
#include "RuleConflictDetectionManager.h"
#include "EnclaveDatabaseManager.h"
#include "TimerQueueManager.h"

#include "sgx_tae_service.h"


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

static inline void free_allocated_memory(void *pointer)
{
    if(pointer != NULL)
    {
        free(pointer);
        pointer = NULL;
    }
}

static inline void free_allocated_memory_void(void **pointer)
{
    if(*pointer != NULL)
    {
        free(*pointer);
        *pointer = NULL;
    }
}

static inline void free_allocated_memory_char(char **pointer)
{
    if(*pointer != NULL)
    {
        free(*pointer);
        *pointer = NULL;
    }
}

static inline void free_allocated_memory_rule(Rule **pointer)
{
    if(*pointer != NULL)
    {
        free(*pointer);
        *pointer = NULL;
    }
}

static inline void free_allocated_memory_rule_comp(RuleComponent **pointer)
{
    if(*pointer != NULL)
    {
        free(*pointer);
        *pointer = NULL;
    }
}




/*****************
 * ocall functions
 *****************/




/*********************
 * ecall functions
 *********************/


/*
 * Enclave Initialization
 */
void ecall_initialize_enclave(int isEncryption){
    isEncryptionEnabled = isEncryption == 1? true : false;
    setupEnclave();
}

/*
 * The main entry point in the Enclave to receive the device events
 * Tasks: Receive a device event from outside of enclave, decrypt the event, perform rule automation
 */
int ecall_did_receive_event(struct Message *msg){
    char *decMessage = NULL;
    if(isEncryptionEnabled){
        /* decrypt event */
        decMessage = (char *) malloc((msg->textLength+1) * sizeof(char));
        sgx_status_t status = decryptMessageAES(msg->text, msg->textLength, decMessage, msg->textLength, msg->tag);
        if(status != 0){
            printf("Enclave:: Error! Decryption failed!");
            free(decMessage);
            return -1;
        }
    }else{
        decMessage = (char *) malloc((msg->textLength+1)*sizeof(char));
        memcpy(decMessage, msg->text, msg->textLength);
        decMessage[msg->textLength] = '\0';
    }
    printf("Enclave:: Event = %s", decMessage);

    struct DeviceEvent *myEvent = (DeviceEvent*) malloc( sizeof( struct DeviceEvent));
    if (myEvent == NULL) {
        printf("Enclave:: Memory allocation error!\n");
        free(decMessage);
        return -1;
    }

    if(startParsingDeviceEvent(decMessage, myEvent)){
        printDeviceEventInfo(myEvent);
        startRuleAutomation(myEvent);
    }

    free(decMessage);
    deleteDeviceEvent(&myEvent);
    return 0;
}

/*
 * The main entry point in the Enclave to receive the rules
 *  Tasks: Receive a rule from outside of enclave, decrypt the rule, check for any conflict with existing rules, store the rule in db if no conflict
 */
int ecall_did_receive_rule(struct Message* msg){
    char *decMessage = NULL;
    if(isEncryptionEnabled){
        /* decrypt rule */
        decMessage = (char *) malloc((msg->textLength+1)*sizeof(char));
        sgx_status_t status = decryptMessageAES(msg->text, msg->textLength, decMessage, msg->textLength, msg->tag);
        if (status != 0){
            printf("Enclave:: Error! Decryption failed!");
            free(decMessage);
            return -1;
        }
    }else{
        decMessage = (char *) malloc((msg->textLength+1)*sizeof(char));
        memcpy(decMessage, msg->text, msg->textLength);
        decMessage[msg->textLength] = '\0';
    }
    printf("Enclave:: Rule = %s", decMessage);

    struct Rule *myrule;
    if(initRule(&myrule)){
        /* parse rule */
        if(startParsingRule(decMessage, myrule)){
            printRuleInfo(myrule);
            /* conflict detection */
            if(!startRuleConflictDetection(myrule)){
                //updateGraph(myrule);
                /* store in db */
                if(storeRuleInDB(decMessage, myrule)){
                    printf("Enclave:: Rule stored in DB.");
                }
            }else{
                printf("Enclave:: Error! Rules conflict!");
            }
        }
    }

    free(decMessage);
    deleteRule(&myrule);
    return 0;
}

/*
 * Get the earliest timer from the priority queue
 */
int ecall_get_latest_timer(struct TimerRule *msg){
    bool isSuccess = getNextTimer(msg);
    return isSuccess? 1: 0;
}

/*
 * A call to fire the action event after the corresponding timer has set
 */
int ecall_fire_timer(char *ruleID){
    bool isSuccess = startTimerRuleHandler(ruleID);
    return isSuccess? 1: 0;
}

/*
 * A call to reset all the timers in the priority queue
 */
int ecall_reset_timers(){
    bool isSuccess = resetQueue();
    return isSuccess? 1: 0;
}