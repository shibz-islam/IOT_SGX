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
#include <vector>
#include <map>

#include "SocketManager.h"
#include "JSONParser.h"
#include "MongoManager.h"
#include "aes_gcm.h"
#include "EmailManager.h"
#include "IoTMQTTWrapper.h"
#include <chrono>
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/thread/thread.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>

using std::chrono::system_clock;

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;
sgx_status_t ret = SGX_SUCCESS;
sgx_launch_token_t token = {0};
int updated = 0;

/* Global variables */
int socketConnection = 0;
bool isEncryptionEnabled = true;
MongoManager *mongoObj;
IoTMQTTWrapper *mqttObj;



class Timer
{
    public:
        Timer(boost::asio::io_service& io, int duration, std::string id)
                : timer_(io, boost::posix_time::seconds(duration)),
                  count_(0),
                  duration_(duration),
                  id_(id),
                  isActive_(true)
        {
        }

        ~Timer()
        {
            std::cout << "Destroying Timer with id: " << id_  << std::endl;
        }

        void start()
        {
            std::cout << "Starting Timer with id: " << id_  << std::endl;
            timer_.async_wait(boost::bind(&Timer::end, this));
        }

        void deactivate()
        {
            isActive_ = false;
            timer_.cancel();
        }

        void end()
        {
            std::cout << "End Timer with id: " << id_  << std::endl;
            if(isActive_){
                int retValue = 0;
                ecall_fire_timer(global_eid, &retValue, (char*)id_.c_str());
                if(retValue == 1) printf("Timer Success! with ruleid=%s\n", (char*)id_.c_str());
            }
        }

    private:
        boost::asio::deadline_timer timer_;
        int count_;
        int duration_;
        std::string id_;
        bool isActive_;
};

std::map<std::string, Timer*> timerMap;




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
    printf("%s\n", str);
}

size_t ocall_write_to_file(DatabaseElement *element, int count){
    bool returnValue = mongoObj->insertRule(element, count);
    return returnValue == true? 1:0;
}

size_t ocall_read_rule_count(DatabaseElement *element){
    return mongoObj->retrieveRuleCount(element);
}

size_t ocall_read_rule(DatabaseElement *element, size_t count){
    bool returnValue = mongoObj->retrieveRule(element, count);
    return returnValue == true? 1:0;
}

size_t ocall_read_rule_info(DatabaseElement *element, size_t count){
    bool returnValue = mongoObj->retrieveRuleInfo(element, count);
    return returnValue == true? 1:0;
}

size_t ocall_send_rule_commands(struct Message *msg){
    //TODO: send the response
    printf("---------ocall_send_rule_commands----------\n");
    //printf("Sending alert to device...%s, %s\n", msg->address, msg->text);
    bool returnValue = false;
    if(isEncryptionEnabled){
        std::string response = make_json_from_message(msg);
        returnValue = mqttObj->publishMessage(msg->address, response.c_str());
    }
    else{
        returnValue = mqttObj->publishMessage(msg->address, msg->text);
    }
    return returnValue == true? 1:0;
}

size_t ocall_get_current_time(){
    std::time_t tt;
    struct std::tm * ptm;
    tt = system_clock::to_time_t (system_clock::now());
    ptm = std::localtime(&tt);
    printf("Current time: %d:%d:%d\n", ptm->tm_hour, ptm->tm_min, ptm->tm_sec);
    size_t seconds = (ptm->tm_hour*60 + ptm->tm_min)*60;
    return seconds;
}

size_t ocall_remove_timer_info(char *id){
    int returnValue = timerMap.erase(std::string(id));
    return returnValue > 0 ? 1:0;
}


/*
 * MongoDB
*/
void mongoSetup(){
    mongoObj = new MongoManager("mongodb://localhost:27017", "IOT", "RulebaseTest"); //TODO: take DB info from command line
    mongoObj->initConnection();
}


/*
 * MQTT
*/
void MQTTSetup(){
    mosqpp::lib_init();
    mqttObj = new IoTMQTTWrapper("iot_mqtt_server", "localhost", 1883); //TODO: take mqtt info from command line
    mqttObj->loop_start();
    mosqpp::lib_cleanup();
}


/*
 * Socket functions
 */

int open_socket_for_events()
{
    printf("\nOpening Socket for IoT Data...\n");
    char buffer[LIMIT];
    int n;
    SocketManager socketObj(20008);
    socketConnection = socketObj.establish_connection();
    int count = 0;
    while(1){
        bzero(buffer,LIMIT);
        n = read(socketConnection,buffer,LIMIT);
        if (n < 0){
            perror("ERROR! reading from socket\n");
            continue;
        }

        if(strlen(buffer) > 0){
            std::cout << "\n\n ***** Device Event received: *****" << std::endl;
            //printf("buffer len: %d\n",strlen(buffer));
            if(strcmp(buffer, "quit")==0)
                break;

            struct Message *msg = (Message*) malloc( sizeof( struct Message ));
            int returnValue = 0;
            if(isEncryptionEnabled){
                if(parse_data_with_tag(buffer, msg, false)){
                    msg->isEncrypted = 1;
                    ecall_did_receive_event(global_eid, &returnValue, msg);
                    free(msg->text);
                    free(msg->tag);
                }
            }
            else{
                msg->text = (char *) malloc((strlen(buffer)+1)*sizeof(char));
                memcpy(msg->text, buffer, strlen(buffer));
                msg->text[strlen(buffer)] = '\0';
                msg->tag = NULL;
                msg->textLength = strlen(buffer);
                msg->isEncrypted = 0;
                ecall_did_receive_event(global_eid, &returnValue, msg);
                free(msg->text);
            }
            free(msg);
            count++;
        }

        //TODO: Testing purpose only
        if(count==100000)
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
    SocketManager socketObj(20006);
    int socketConnection2 = socketObj.establish_connection();
    int count = 0;
    while(1){
        bzero(buffer,LIMIT);
        n = read(socketConnection2,buffer,LIMIT);
        if (n < 0){
            perror("ERROR! reading from socket\n");
            continue;
        }

        if(strlen(buffer) > 0){
            std::cout << "\n\n ***** Rule received: *****" << std::endl;
            //printf("buffer len: %d\n",strlen(buffer));
            if(strcmp(buffer, "quit")==0)
                break;

            struct Message *msg = (Message*) malloc( sizeof( struct Message ));
            int returnValue = 0;
            if(isEncryptionEnabled){
                if(parse_data_with_tag(buffer, msg, false)){
                    msg->isEncrypted = 1;
                    ecall_did_receive_rule(global_eid, &returnValue, msg);
                    free(msg->text);
                    free(msg->tag);
                }
            }
            else{
                msg->text = (char *) malloc((strlen(buffer)+1)*sizeof(char));
                memcpy(msg->text, buffer, strlen(buffer));
                msg->text[strlen(buffer)] = '\0';
                msg->tag = NULL;
                msg->textLength = strlen(buffer);
                ecall_did_receive_rule(global_eid, &returnValue, msg);
                free(msg->text);
            }
            free(msg);
            count++;
        }

        //TODO: Testing purpose only
        if(count==100000)
            break;
    }
    socketObj.close_connection();
    return 0;
}

void start_timer_thread(){
    timerMap = std::map<std::string, Timer*>();
    boost::asio::io_service io;

    std::time_t tt = system_clock::to_time_t (system_clock::now());
    struct std::tm * ptm = std::localtime(&tt);
    int current_day = ptm->tm_mday;

    int count = 0;
    int returnValue = 0;

    while (true){
        struct TimerRule *tRule = (TimerRule*) malloc( sizeof( struct TimerRule ));
        ecall_get_latest_timer(global_eid, &returnValue, tRule);
        if(returnValue == 1){
            printf("App:: tRule:: id=%s, duration=%d\n", tRule->ruleID, tRule->duration);
            std::string currentID(tRule->ruleID);
            // check if timer for that rule is already active
            if(timerMap.count(currentID) <= 0){
                //TODO: replace default time value with tRule->duration
                Timer *newTimer = new Timer(io, 60, currentID);
                newTimer->start();
                timerMap.insert(std::make_pair(currentID, newTimer));

                if(io.stopped()){
                    printf("io stopped\n");
                    io.reset();
                }

                if(!io.stopped()){
                    printf("starting new timer thread\n");
                    boost::thread th([&] { io.run(); });
                }
            }
        }
        free(tRule);

        /* Sleep thread for some time */
        printf("Sleep for the 60 seconds...\n");
        std::this_thread::sleep_for(std::chrono::seconds(60));

        /* Reset timers every new day */
        tt = system_clock::to_time_t (system_clock::now());
        ptm = std::localtime(&tt);
        if(current_day != ptm->tm_mday){
            current_day = ptm->tm_mday;
            timerMap = {};
            returnValue = 0;
            ecall_reset_timers(global_eid, &returnValue);
            if(returnValue == 0){
                printf("Error! while reseting Queue...\n");
                break;
            }
        }

        //TODO:: Testing purpose only
        count++;
        if(count == 5)
            break;
    }
}

/*
 * Application entry
 */
int SGX_CDECL main(int argc, char *argv[])
{
    /**
     * Run command: ./app <open_socket_for_rules> <open_socket_for_events> <start_timer_thread> <isEncryptionEnable>
     * True = 1, False = 0
    **/

    if(argc != 5){
        printf("\nPlease enter valid values to run the program..\n ./app open_socket_for_rules open_socket_for_events start_timer_thread isEncryptionEnable ...\n");
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

    /* initialize other services */
    mongoSetup();
    MQTTSetup();

    /* setup the Enclave with argument values */
    ecall_initialize_enclave(global_eid, isEncryptionEnabled);

    int num_threads = 3;
    bool valid_threads[] = {false, false, false};
    boost::thread t[num_threads];

    /* start a thread to handle rules */
    if(strcmp(argv[1], "1") == 0){
        valid_threads[0] = true;
        t[0] = boost::thread(open_socket_for_rules);
    }

    /* start a thread to handle device events */
    if(strcmp(argv[2], "1") == 0){
        valid_threads[1] = true;
        t[1] = boost::thread(open_socket_for_events);
    }

    /* start a thread to handle time-based events */
    if(strcmp(argv[3], "1") == 0){
        valid_threads[2] = true;
        t[2] = boost::thread(start_timer_thread);
    }

    /* Join all the threads */
    for (int i = 0; i < num_threads; ++i) {
        if(valid_threads[i])  t[i].join();
    }

    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);
    
    printf("Info: Enclave successfully returned.\n");

    printf("Enter a character before exit ...\n");
    getchar();
    return 0;
}

