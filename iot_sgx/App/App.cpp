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


#include <stdio.h>
#include <string.h>
#include <assert.h>

# include <unistd.h>
# include <pwd.h>
# define MAX_PATH FILENAME_MAX
#define MAX_BUF_LEN 100

#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"
#include "ErrorSupport.h"

#include <sys/uio.h>

#include <cstdint>
#include <iostream>
#include <fstream>
#include <sstream>
#include <memory>
#include <string>
#include <curl/curl.h>
#include <jsoncpp/json/json.h>
#include <thread>

#include "SocketManager.h"
#include "JSONParser.h"
#include "MongoManager.h"
#include "aes_gcm.h"
#include "MongoHelper.h"
#include "EmailManager.h"
#include "IoTMQTTWrapper.h"

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;
sgx_status_t ret = SGX_SUCCESS;
sgx_launch_token_t token = {0};
int updated = 0;
int socketConnection = 0;
char ruleFilePath[] = "/home/shihab/Desktop/rules.bin"; //TODO: remove hard-coded filepath
IoTMQTTWrapper *mqttObj;
std::string topicForData = "topic/utd/iot/server/data";


/*
 *   Initialize the enclave: Call sgx_create_enclave to initialize an enclave instance
 */
int initialize_enclave(void)
{
    char token_path[MAX_PATH] = {'\0'};
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int updated = 0;
    
    /* Step 1: try to retrieve the launch token saved by last transaction 
     *         if there is no token, then create a new one.
     */
    /* try to get the token saved in $HOME */
    const char *home_dir = getpwuid(getuid())->pw_dir;
    
    if (home_dir != NULL && 
        (strlen(home_dir)+strlen("/")+sizeof(TOKEN_FILENAME)+1) <= MAX_PATH) {
        /* compose the token path */
        strncpy(token_path, home_dir, strlen(home_dir));
        strncat(token_path, "/", strlen("/"));
        strncat(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME)+1);
    } else {
        /* if token path is too long or $HOME is NULL */
        strncpy(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
    }

    FILE *fp = fopen(token_path, "rb");
    if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL) {
        printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
    }

    if (fp != NULL) {
        /* read the token from saved file */
        size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
        if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
            /* if token is invalid, clear the buffer */
            memset(&token, 0x0, sizeof(sgx_launch_token_t));
            printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
        }
    }
    /* Step 2: call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        ret_error_support(ret);
        if (fp != NULL) fclose(fp);
        return -1;
    }

    /* Step 3: save the launch token if it is updated */
    if (updated == FALSE || fp == NULL) {
        /* if the token is not updated, or file handler is invalid, do not perform saving */
        if (fp != NULL) fclose(fp);
        return 0;
    }

    /* reopen the file with write capablity */
    fp = freopen(token_path, "wb", fp);
    if (fp == NULL) return 0;
    size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
    if (write_num != sizeof(sgx_launch_token_t))
        printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
    fclose(fp);

    /* Utilize edger8r attributes */
    edger8r_array_attributes();
    edger8r_pointer_attributes();
    edger8r_type_attributes();
    edger8r_function_attributes();

    /* Utilize trusted libraries */
    ecall_libc_functions();
    ecall_libcxx_functions();
    ecall_thread_functions();

    return 0;
}


/*
 * OCall functions
 */

void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    printf("%s", str);
}


void ocall_store_rules(Rule *rules, size_t numDevices) {
    printf("---------ocall_store_rules----------\n");
    FILE *fptr;
    if ((fptr = fopen(ruleFilePath, "a")) == NULL) {
        printf("Error! opening file");
        return;
    }
    for (int i = 0; i < numDevices; ++i, rules++) {
        //Device ID
        unsigned short sizeOfId = strlen(rules->deviceID) + 1;
        fwrite(&sizeOfId, sizeof(unsigned short), 1, fptr);
        fwrite(rules->deviceID, sizeof(char), sizeOfId, fptr);
        //printf("deviceid = %d, %s\n", sizeOfId, rules->deviceID);
        //Rule
        unsigned short sizeOfRule = rules->ruleLength;
        fwrite(&sizeOfRule, sizeof(unsigned short), 1, fptr);
        fwrite(rules->rule, sizeof(char), sizeOfRule, fptr);
        //printf("Rule from file = %d, %s\n", sizeOfRule, rules->rule);
        //Tag
        unsigned short sizeOfTag= rules->tagLength;
        fwrite(&sizeOfTag, sizeof(unsigned short), 1, fptr);
        fwrite(rules->tag, sizeof(char), sizeOfTag, fptr);
        //printf("Tag from file = %d, %s\n", sizeOfTag, rules->tag);

    }
    fclose(fptr);
    //delete[] rules;
}

size_t ocall_get_rule_count(Rule *property, int isCountAll){
    printf("---------ocall_get_rule_count----------\n");
    FILE *fptr;
    if ((fptr = fopen(ruleFilePath, "rb")) == NULL) {
        printf("Error! opening file\n");
        return 0;
    }
    unsigned short stringLength = 0;
    size_t count = 0;
    std::vector<std::string> rule_tag_vec;
    while (!feof(fptr)) {
        size_t ret = fread(&stringLength, sizeof(unsigned short), 1, fptr);
        if (ret > 0) {
            //deviceID
            char *deviceId_from_file = (char*)malloc(sizeof(char) * stringLength);
            fread(deviceId_from_file, sizeof(char), stringLength, fptr);
            //printf("deviceid = %d, %s\n", stringLength, deviceId_from_file);
            //Rule
            fread(&stringLength, sizeof(unsigned short), 1, fptr);
            char *rule_from_file = (char*)malloc(sizeof(char) * stringLength);
            fread(rule_from_file, sizeof(char), stringLength, fptr);
            //printf("Rule from file = %d, %s\n", stringLength, rule_from_file);
            //Tag
            fread(&stringLength, sizeof(unsigned short), 1, fptr);
            char *tag_from_file = (char*)malloc(sizeof(char) * stringLength);
            fread(tag_from_file, sizeof(char), stringLength, fptr);
            //printf("Rule from file = %d, %s\n", stringLength, tag_from_file);

            if (isCountAll == 0){
                if (strcmp(deviceId_from_file, property->deviceID) == 0){
                    count++;
                }
            }
            else{
                count++;
            }

            free(deviceId_from_file);
            free(rule_from_file);
            free(tag_from_file);
        }
    }
    printf("Total rules on file = %ld\n", count);
    return count;
}

size_t ocall_get_rules(Rule *ruleset, int len, Rule *property, int isFetchAll){
    printf("---------ocall_get_rules----------\n");
    FILE *fptr;
    if ((fptr = fopen(ruleFilePath, "rb")) == NULL) {
        printf("Error! opening file\n");
        return 0;
    }
    unsigned short stringLength = 0;
    unsigned short ruleLength = 0;
    unsigned short tagLength = 0;
    int count = 0;
    while (!feof(fptr)) {
        size_t ret = fread(&stringLength, sizeof(unsigned short), 1, fptr);
        if (ret > 0) {
            //deviceID
            char *deviceId_from_file = (char*)malloc(sizeof(char) * stringLength);
            fread(deviceId_from_file, sizeof(char), stringLength, fptr);
            //printf("deviceid = %d, %s\n", stringLength, deviceId_from_file);


            //Rule
            fread(&ruleLength, sizeof(unsigned short), 1, fptr);
            char *rule_from_file = (char*)malloc(sizeof(char) * ruleLength);
            fread(rule_from_file, sizeof(char), ruleLength, fptr);
            //printf("Rule from file = %ld, %s\n", strlen(rule_from_file), rule_from_file);


            //Tag
            fread(&tagLength, sizeof(unsigned short), 1, fptr);
            char *tag_from_file = (char*)malloc(sizeof(char) * tagLength);
            fread(tag_from_file, sizeof(char), tagLength, fptr);
            //printf("Tag from file = %d, %s\n", stringLength, tag_from_file);


            if (isFetchAll == 0){
                if (strcmp(deviceId_from_file, property->deviceID) == 0){
                    ruleset->deviceID = deviceId_from_file;
                    ruleset->ruleLength = ruleLength;
                    ruleset->rule = rule_from_file;
                    ruleset->tagLength = tagLength;
                    ruleset->tag = tag_from_file;
                    count++;
                    if(count != len)
                        ruleset++;
                }
            }
            else{
                ruleset->deviceID = deviceId_from_file;
                ruleset->ruleLength = ruleLength;
                ruleset->rule = rule_from_file;
                ruleset->tagLength = tagLength;
                ruleset->tag = tag_from_file;
                //ruleset[count].deviceID = deviceId_from_file;
                //ruleset[count].rule = rule_from_file;
                //ruleset[count].tag = tag_from_file;
                count++;
                if(count != len)
                    ruleset++;
            }


            //free(deviceId_from_file);
            //free(rule_from_file);
            //free(tag_from_file);
        }
    }
    /*
    for(int i=0; i < count; i++, ruleset++){
        printf("*** deviceid=%s, rule=%s\n", ruleset->deviceID, ruleset->rule);
    }
    fclose(fptr);
    */
    return 1;
}


void ocall_send_alert_for_rule_action_email(struct ruleActionProperty *property){
    printf("Sending email...\n");
    sendEmail("dml.utd@gmail.com", std::string(property->address), "", "Do not Reply", std::string(property->msg), "password");
}


void ocall_send_alert_for_rule_action_device(struct ruleActionProperty *property){
    printf("Sending alert to device...\n");
    std::string message = make_json_from_message(property);
    mqttObj->publishMessage(property->address, message.c_str());
}


/*
void get_rules_from_db(){
    MongoManager mObj("mongodb://localhost:27017", "IOT", "rulebase");
    //mObj.initConnection();

    int totalDocuments = mObj.getCount();
    if(totalDocuments > 0)
    {
        std::vector<std::string> rules;
        rules = mObj.getAllData();

        struct message msg[totalDocuments];
        char buffer[LIMIT];
        std::string temp;
        for (int i = 0; i < rules.size() ; ++i) {
            temp = rules[i];
            memcpy(buffer, temp.c_str(), temp.length());
            parse_data_with_tag_index(buffer, msg, i);
            //printf("###### i=%d, -- data= %s\n", i, msg[i].text);
        }
        //printf("size = %f\n", sizeof(msg)/ sizeof(msg[0]));
        //ecall_get_rules_from_db(global_eid, msg, totalDocuments);
    }
}
*/


/*
 * MQTT
*/

void MQTTSetup(){
    mosqpp::lib_init();
    mqttObj = new IoTMQTTWrapper("iot_mqtt_server", "localhost", 1883); //TODO: Remove hard-coded values
    mqttObj->loop_start();
    mosqpp::lib_cleanup();
}

void didReceiveMessageFromMQTT(char* payload){
    struct message msg[1];
    if(parse_data_with_tag(payload, msg) > 0)
        ecall_decrypt_message(global_eid, msg);
}


int open_socket()
{
    printf("Opening Socket for IoT Data...\n");
    char buffer[LIMIT];
    int n;
    SocketManager socketObj(20004);
    socketConnection = socketObj.establish_connection();
    int count = 0;
    while(1){
        bzero(buffer,LIMIT);
        n = read(socketConnection,buffer,LIMIT);
        if (n < 0)
            perror("ERROR reading from socket");

        if(strlen(buffer) > 0){
            //printf("buffer len: %d\n",strlen(buffer));
            if(strcmp(buffer, "quit")==0)
                break;

            struct message msg[1];
            if(parse_data_with_tag(buffer, msg) > 0)
                ecall_decrypt_message(global_eid, msg);

            count++;
        }
        if(count==200)
            break;
    }
    socketObj.close_connection();
    return 0;
}


int open_socket_for_rules()
{
    printf("Opening Socket for Rules...\n");
    char buffer[LIMIT];
    int n;
    SocketManager socketObj(20003);
    int socketConnection2 = socketObj.establish_connection();
    int count = 0;
    while(1){
        bzero(buffer,LIMIT);
        n = read(socketConnection2,buffer,LIMIT);
        if (n < 0)
            perror("ERROR reading from socket");

        if(strlen(buffer) > 0){
            //printf("buffer len: %d\n",strlen(buffer));
            if(strcmp(buffer, "quit")==0)
                break;

            struct message msg[1];
            if(parse_data_with_tag(buffer, msg) > 0)
                ecall_decrypt_rule(global_eid, msg);

            count++;
        }
        if(count==100)
            break;
    }
    socketObj.close_connection();
    return 0;
}


void start_mqtt_service(){
    MQTTSetup();
    mqttObj->subscribeTopic(topicForData.c_str());
    while (true){}
}


/*
 * Application entry
 */
int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);

    /* Initialize the enclave */
    if(initialize_enclave() < 0){
        printf("Enter a character before exit ...\n");
        getchar();
        return -1; 
    }

    ecall_initialize_enclave(global_eid);


    //MQTTSetup();

    //get_rules_from_db();

    std::thread t1(open_socket);
    //std::thread t2(open_socket_for_rules);

    t1.join();
    //t2.join();

//    ocall_manager();


    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);
    
    printf("Info: SampleEnclave successfully returned.\n");

    printf("Enter a character before exit ...\n");
    getchar();
    return 0;
}

