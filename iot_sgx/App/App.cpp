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
#include <chrono>

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;
sgx_status_t ret = SGX_SUCCESS;
sgx_launch_token_t token = {0};
int updated = 0;
int socketConnection = 0;
int socketConnectionTest = 0;
std::string ruleFilename = "rules"; //TODO: remove hard-coded filepath
std::string ruleUnencFilename = "rules_unenc";
std::string ruleFilename_ext = "_r10000.bin";

std::string basepath = "experiments/";

std::string resultFilename = "execution_time(microseconds)";
std::string resultFilenameUnenc = "execution_time_unenc(microseconds)";
std::string filename_ext = "_june28_r400_c100_d10000.txt";

IoTMQTTWrapper *mqttObj;
std::string topicForData = "topic/utd/iot/server/data";
std::chrono::high_resolution_clock::time_point START_TIME;
bool isEncryptionEnabled = true;

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


size_t ocall_store_rules(Rule *rules, size_t numDevices) {
    printf("\n---------ocall_store_rules----------\n");
    std::string filepath = "";
    if(isEncryptionEnabled)
        filepath = basepath + ruleFilename + ruleFilename_ext;
    else
        filepath = basepath + ruleUnencFilename + ruleFilename_ext;
    FILE *fptr = fopen(filepath.c_str(), "ab+");
    if (fptr == NULL) {
        printf("Error! opening file");
        return 0;
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
        unsigned short sizeOfTag = rules->tagLength;
        fwrite(&sizeOfTag, sizeof(unsigned short), 1, fptr);
        fwrite(rules->tag, sizeof(char), sizeOfTag, fptr);
        //printf("Tag from file = %d, %s\n", sizeOfTag, rules->tag);

    }
    //printf("\ntrying to close file pointer....\n");
    fclose(fptr);
    printf("\nclosed file pointer....\n");
    return 1;
    //delete[] rules;
}

size_t ocall_get_rule_count(Rule *property, int isCountAll){
    printf("\n---------ocall_get_rule_count----------\n");
    std::string filepath = "";
    if(isEncryptionEnabled)
        filepath = basepath + ruleFilename + ruleFilename_ext;
    else
        filepath = basepath + ruleUnencFilename + ruleFilename_ext;
    FILE *fptr = fopen(filepath.c_str(), "rb");
    if (fptr == NULL) {
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
    printf("\n---------ocall_get_rules----------\n");
    std::string filepath = "";
    if(isEncryptionEnabled)
        filepath = basepath + ruleFilename + ruleFilename_ext;
    else
        filepath = basepath + ruleUnencFilename + ruleFilename_ext;
    FILE *fptr = fopen(filepath.c_str(), "rb");
    if (fptr == NULL) {
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
    printf("\n---------ocall_send_alert----------\n");
    printf("Sending alert to device...%s\n", property->address);
    if(isEncryptionEnabled){
        std::string message = make_json_from_message(property);
        mqttObj->publishMessage(property->address, message.c_str());
    }
    else{
        mqttObj->publishMessage(property->address, property->msg);
    }
    //printf("Command send...\n");
}


std::string getLocalTime(){
    time_t rawtime;
    struct tm * timeinfo;
    char buffer[80];

    time (&rawtime);
    timeinfo = localtime(&rawtime);

    strftime(buffer,sizeof(buffer),"%d-%m-%Y %H:%M:%S",timeinfo);
    std::string str(buffer);
    return str;
}


size_t ocall_log_execution_time(char *id){
    auto endTime = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(endTime - START_TIME);
    printf("\nTime taken by function: %ld microseconds\n", duration.count());

    std::string line = getLocalTime() + ";" + std::string(id) + ";" + std::to_string(duration.count());

    std::ofstream fout;
    std::string filename;
    if(isEncryptionEnabled){
        filename = basepath + resultFilename + filename_ext;
    }
    else{
        filename = basepath + resultFilenameUnenc + filename_ext;
    }
    fout.open(filename.c_str(), std::ios::app);
    if(!fout) {
        printf("Error in creating file!!!\n");
        return 0;
    }
    fout << line << std::endl;
    fout.close();
    printf("Closed file pointer\n");
    return 1;
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

void start_mqtt_service(){
    MQTTSetup();
    mqttObj->subscribeTopic(topicForData.c_str());
    while (true){}
}


int open_socket()
{
    printf("\nOpening Socket for IoT Data...\n");
    char buffer[LIMIT];
    int n;
    SocketManager socketObj(20007);
    socketConnection = socketObj.establish_connection();
    int count = 0;
    while(1){
        bzero(buffer,LIMIT);
        n = read(socketConnection,buffer,LIMIT);
        if (n < 0)
            perror("ERROR reading from socket\n");

        if(strlen(buffer) > 0){
            //printf("buffer len: %d\n",strlen(buffer));
            if(strcmp(buffer, "quit")==0)
                break;

            START_TIME = std::chrono::high_resolution_clock::now();

            struct message msg[1];
            if(isEncryptionEnabled){
                if(parse_data_with_tag(buffer, msg) > 0)
                    ecall_decrypt_message(global_eid, msg);
            }else{
                char *temp = (char *) malloc((strlen(buffer)+1)*sizeof(char));
                memcpy(temp, buffer, strlen(buffer));
                temp[strlen(buffer)] = '\0';
                msg->text = temp;
                msg->tag = NULL;
                msg->textLength = strlen(buffer);
                ecall_decrypt_message(global_eid, msg);
                //printf("\n####### Done #######\n");
            }
            count++;
            delete[] msg->text;
            delete[] msg->tag;
        }
        if(count==10000)
            break;
    }
    socketObj.close_connection();
    return 0;
}


int open_socket_for_rules()
{
    printf("\nOpening Socket for Rules...\n");
    char buffer[LIMIT];
    int n;
    SocketManager socketObj(20005);
    int socketConnection2 = socketObj.establish_connection();
    int count = 0;
    while(1){
        bzero(buffer,LIMIT);
        n = read(socketConnection2,buffer,LIMIT);
        if (n < 0)
            perror("ERROR reading from socket\n");

        if(strlen(buffer) > 0){
            printf("buffer len: %d\n",strlen(buffer));
            if(strcmp(buffer, "quit")==0)
                break;

            struct message msg[1];
            if(isEncryptionEnabled){
                if(parse_data_with_tag(buffer, msg) > 0)
                    ecall_decrypt_rule(global_eid, msg);
            }
            else{
                char *temp = (char *) malloc((strlen(buffer)+1)*sizeof(char));
                memcpy(temp, buffer, strlen(buffer));
                temp[strlen(buffer)] = '\0';
                msg->text = temp;
                msg->tag = NULL;
                msg->textLength = strlen(buffer);
                ecall_decrypt_rule(global_eid, msg);
            }
            count++;
            delete[] msg->text;
            delete[] msg->tag;
        }
        if(count==10000)
            break;
    }
    socketObj.close_connection();
    return 0;
}

void ocall_send_test_data(){
    std::string temp = "got data";
    send(socketConnectionTest , temp.c_str() , temp.length() , 0 );
    //write(socketConnectionTest, temp.c_str(), temp.length());
}

int open_socket_for_test()
{
    printf("\nOpening Socket for test...\n");
    char buffer[LIMIT];
    int n;
    SocketManager socketObj(20009);
    socketConnectionTest = socketObj.establish_connection();
    int count = 0;
    while(1){
        bzero(buffer,LIMIT);
        n = read(socketConnectionTest,buffer,LIMIT);
        if (n < 0)
            perror("ERROR reading from socket\n");

        if(strlen(buffer) > 0){
            printf("buffer: %s\n len: %d\n", buffer, strlen(buffer));
            if(strcmp(buffer, "quit")==0)
                break;
            ocall_send_test_data();
        }
        if(count==2)
            break;
    }
    socketObj.close_connection();
    return 0;
}

int timer_thread(){
    usleep(10 * 1000000);
    using std::chrono::system_clock;
    std::time_t tt;

    struct std::tm * ptm;
    while (true){
        tt = system_clock::to_time_t (system_clock::now());
        ptm = std::localtime(&tt);
        printf("Current time: %d:%d\n", ptm->tm_hour, ptm->tm_min);

        ecall_check_timer_rule(global_eid, ptm->tm_hour, ptm->tm_min);

        printf("Waiting for the next hour to begin...\n");
        ++ptm->tm_hour; ptm->tm_min; ptm->tm_sec=0;
        std::this_thread::sleep_until (system_clock::from_time_t (mktime(ptm)));
    }
}

void timer_thread_2(){
    usleep(15 * 1000000);
    using std::chrono::system_clock;
    std::time_t tt;

    struct std::tm * ptm;
    while (true){
        tt = system_clock::to_time_t (system_clock::now());
        ptm = std::localtime(&tt);
        printf("Current time (pending thread): %d:%d\n", ptm->tm_hour, ptm->tm_min);

        int fireTime = 0;
        ecall_check_pending_timer_rule(global_eid, &fireTime, ptm->tm_hour, ptm->tm_min);
        printf("fireTime: %d\n", fireTime);
        if(fireTime == 0){
            //TODO: send the data;
        }
        else if(fireTime > 0 && fireTime < 60){
            ptm->tm_hour; ptm->tm_min+=fireTime; ptm->tm_sec=0;
            printf("Waiting for the next time to continue...\n");
            std::this_thread::sleep_until (system_clock::from_time_t (mktime(ptm)));
        }else if (fireTime == -1){
            ++ptm->tm_hour; ptm->tm_min; ptm->tm_sec=0;
            printf("Waiting for the next hour to continue...\n");
            std::this_thread::sleep_until (system_clock::from_time_t (mktime(ptm)));
        }else{
            ptm->tm_hour; ++ptm->tm_min; ptm->tm_sec=0;
            printf("Unknown value...Waiting for the next Minute to continue...\n");
            std::this_thread::sleep_until (system_clock::from_time_t (mktime(ptm)));
        }
    }
}


/*
 * Application entry
 */
int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);

    /**
     * Run command: ./app open_socket_for_rules open_socket timer_thread isEncryptionEnable
     * True = 1, False = 0
     */

    if(argc != 5){
        printf("\nPlease enter valid values to run the program..\n./app open_socket_for_rules open_socket timer_thread isEncryptionEnable ...\n");
        printf("Enter a character before exit ...\n");
        getchar();
        return -1;
    }

    /* Initialize the enclave */
    if(initialize_enclave() < 0){
        printf("Enter a character before exit ...\n");
        getchar();
        return -1; 
    }

    isEncryptionEnabled = strcmp(argv[argc - 1], "1") == 0;
    printf("isEncryptionEnabled: %d\n", isEncryptionEnabled);

    ecall_initialize_enclave(global_eid, isEncryptionEnabled);
    MQTTSetup();


    std::thread t1, t2, t3, t4;
    if(strcmp(argv[1], "1") == 0){
        t1 = std::thread(open_socket_for_test);
        t1.join();
    }
    if(strcmp(argv[2], "1") == 0){
        t2 = std::thread(open_socket);
        t2.join();
    }
    if(strcmp(argv[3], "1") == 0){
        t3 = std::thread(timer_thread);
        t4 = std::thread(timer_thread_2);
        t3.join();
        t4.join();
    }


    //get_rules_from_db();


    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);
    
    printf("Info: SampleEnclave successfully returned.\n");

    printf("Enter a character before exit ...\n");
    getchar();
    return 0;
}

