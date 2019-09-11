//
// Created by shihab on 7/16/19.
//

#ifndef IOTENCLAVE_AES_GCM_H
#define IOTENCLAVE_AES_GCM_H

void aes_gcm_encrypt(char *msg, int msg_len, char *encMessageOut, char *tag);
void aes_gcm_decrypt(char* gcm_output, int gcm_output_len, char* decMessageOut, char *gcm_output_tag);

#endif //IOTENCLAVE_AES_GCM_H
