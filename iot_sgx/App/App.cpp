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

//#include "SocketConnection.h"
#include "JSONParser.h"
//#include "CurlHelper.h"
#include "MongoHelper.h"
#include "aes_gcm.h"

#include "SocketManager.h"


/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;
sgx_status_t ret = SGX_SUCCESS;
sgx_launch_token_t token = {0};
int updated = 0;
int socketConnection = 0;


typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }
    
    if (idx == ttl)
    	printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n", ret);
}


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
        print_error_message(ret);
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
 * Test AES
 */
void local_aes_test()
{
    char data[] = "{'deviceId': 2, 'deviceType': 'Bulb', 'data': 1234}";
    struct message msg[1];
    msg->text = data;

    char *encMessage = (char *) malloc((strlen(data)+1)*sizeof(char));
    char *tag = new char[16];
    aes_gcm_encrypt(data, strlen(data), encMessage, tag);

    char *decMessage = (char *) malloc((strlen(encMessage))*sizeof(char));
    aes_gcm_decrypt(encMessage, strlen(encMessage), decMessage, tag);
    printf("dec msg: %s\n", decMessage);
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

void ocall_get_message_from_enclave(struct message* msg){
    std::string json_msg = make_json_from_message(msg);
    write(socketConnection, json_msg.c_str(), json_msg.size());
}


/*
 * OCall Manager
 */
void ocall_test()
{
    char buffer[MAX_BUF_LEN] = "Hello World!";
    char secret[MAX_BUF_LEN] = "My secret string";
    char retSecret[MAX_BUF_LEN] = "";
    int secretIntValue = 0;
    int *secretIntPointer = &secretIntValue;
    // A bunch of Enclave calls (ECALL) will happen here.

    printf("\nApp: Buffertests:\n");

    // Change the buffer in the enclave
    printf("App: Buffer before change: %s\n", buffer);
    enclaveChangeBuffer(global_eid, buffer, MAX_BUF_LEN);
    printf("App: Buffer after change: %s\n", buffer);


    printf("\nApp: Stringtests:\n");

    // Load a string from enclave
    // should return the default savedString from the enclave
    enclaveStringLoad(global_eid, retSecret, MAX_BUF_LEN);
    printf("App: Returned Secret: %s\n", retSecret);

    // Save a string in the enclave
    enclaveStringSave(global_eid, secret, strlen(secret)+1);
    printf("App: Saved Secret: %s\n", secret);

    // Load a string from enclave
    // should return our secret string
    enclaveStringLoad(global_eid, retSecret, MAX_BUF_LEN);
    printf("App: Load Secret: %s\n", retSecret);


    printf("\nApp: Integertests:\n");

    // Load integer from enclave
    // should return defauld savedInt from enclave
    enclaveLoadInt(global_eid, secretIntPointer);
    printf("App: secretIntValue first load: %d\n", secretIntValue);

    // Save integer to enclave
    enclaveSaveInt(global_eid, 1337);
    printf("App: saved a 1337 to the enclave. \n", 1337);

    // Load integer from enclave
    // should return our saved 1337
    enclaveLoadInt(global_eid, secretIntPointer);
    printf("App: secretIntValue second load after 1337 was saved: %d\n", secretIntValue);
}

void ocall_manager()
{
    local_aes_test();
}


int open_socket()
{
    printf("Opening Socket for IoT Data...\n");
    char buffer[LIMIT];
    int n;
    SocketManager socketObj(20001);
    socketConnection = socketObj.establish_connection();
    int count = 0;
    while(1){
        bzero(buffer,LIMIT);
        n = read(socketConnection,buffer,LIMIT);
        if (n < 0)
            perror("ERROR reading from socket");

        printf("%s\n",buffer);
        if(strcmp(buffer, "quit")==0)
            break;


        struct message msg[1];
        parse_data_with_tag(buffer, msg);
        printf("---------Here 1--------");
        ecall_decrypt_message(global_eid, msg);

        count++;
        if(count==100)
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
    SocketManager socketObj(20002);
    int socketConnection2 = socketObj.establish_connection();
    int count = 0;
    while(1){
        bzero(buffer,LIMIT);
        n = read(socketConnection2,buffer,LIMIT);
        if (n < 0)
            perror("ERROR reading from socket");

        printf("Enc Msg: %s\n",buffer);
        if(strcmp(buffer, "quit")==0)
            break;

        struct message msg[1];
        parse_data_with_tag(buffer, msg);
        printf("---------Here--------");
        ecall_decrypt_rule(global_eid, msg);

        count++;
        if(count==100)
            break;
    }
    socketObj.close_connection();
    return 0;
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

    std::thread t1(open_socket);
    std::thread t2(open_socket_for_rules);
    t1.join();
    t2.join();

//    ocall_manager();

    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);
    
    printf("Info: SampleEnclave successfully returned.\n");

    printf("Enter a character before exit ...\n");
    getchar();
    return 0;
}

