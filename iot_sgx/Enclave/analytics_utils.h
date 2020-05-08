//
// Created by shihab on 3/29/19.
//
#include <sgx_trts.h>
#include <sgx_tseal.h>
#include "sgx_tcrypto.h"
#include <map>
#include <string>

#define BUFLEN 2048
#define SGX_AESGCM_MAC_SIZE 16
#define SGX_AESGCM_IV_SIZE 12

#ifndef IOTENCLAVE_ANALYTICS_UTILS_H
#define IOTENCLAVE_ANALYTICS_UTILS_H


sgx_status_t decryptMessageAES(char *encMessageIn, size_t len, char *decMessageOut, size_t lenOut, char *tag);
sgx_status_t encryptMessageAES(char *decMessageIn, size_t len, char *encMessageOut, size_t lenOut, char *tagMessageIn);



#endif //IOTENCLAVE_ANALYTICS_UTILS_H

