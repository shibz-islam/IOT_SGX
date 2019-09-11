//
// Created by shihab on 9/11/19.
//

#include "RuleBase.h"
#include "MessageParser.h"
#include "Enclave.h"
#include "Enclave_t.h"

#include <map>
#include <string>


float THRESHOLD_TEMP = 25.0;


void compareFoobot(std::map<std::string, std::string>mmap){
    float temp_value = std::stof(mmap.at("data"));
    if(temp_value < THRESHOLD_TEMP){
        printf("Temp value: %f\n", temp_value);
        /*Do something*/
        std::string status = "ON";

        struct device newMDevice[1];
        newMDevice->uid = "1234";
        newMDevice->state = (char*) status.c_str();
        newMDevice->type = "Bulb";
        std::string newMsg =  device_to_string(newMDevice);

        struct message newMSG[1];
        newMSG->text = (char*) newMsg.c_str();
        ecall_encrypt_message(newMSG);
    } else{
        printf("Foobot Temp greater than threshold %f\n", THRESHOLD_TEMP);
    }
}


void start_rule_base(char *msg){
    std::map<std::string, std::string>device_info_map = parse_decrypted_string(msg);
    std::string device_type = device_info_map.at("deviceType");

    if(device_type == "Foobot"){
        printf("***Foobot -> device type = %s\n", device_type);
        compareFoobot(device_info_map);
    }
    else if(device_type == "Bulb"){
        printf("***Bulb -> device type = %s\n", device_type);
    }
    else{
        printf("***Invalid device type = %s\n", device_type);
    }
}


