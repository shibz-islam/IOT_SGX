//
// Created by shihab on 9/11/19.
//

#include "RuleBase.h"
#include "MessageParser.h"
#include "Enclave.h"
#include "Enclave_t.h"
#include "Constants.h"

#include <map>
#include <string>


std::map<std::string, std::map<std::string, std::string>>ruleset;


void save_rule_base(char *msg){
    std::map<std::string, std::string>rule_map = parse_decrypted_string(msg);


    std::string device_id;
    auto it = rule_map.find(Rule_DeviceID);
    if ( it != rule_map.end() ){
        device_id = it->second.c_str();
        printf("%s: %s\n", Rule_DeviceID, device_id);
        ruleset.insert(std::pair<std::string, std::map<std::string, std::string>>(device_id, rule_map));
    }
    else
        printf("Couldn't find %s\n", Rule_DeviceID);


    printf("Initial size of map = %ld\n", ruleset.size());
//    for(auto it = ruleset.cbegin(); it != ruleset.cend(); ++it)
//    {
//        printf("Key=%s, map size=%ld\n", it->first.c_str(), it->second.size());
//    }
}


void start_rule_base(char *msg){
    std::map<std::string, std::string>device_info_map = parse_decrypted_string(msg);
    std::string device_id = device_info_map.at(Rule_DeviceID);
    printf("Device Id = %s\n", device_id);

    auto it = ruleset.find(device_id);
    if ( it != ruleset.end() ){
        std::map<std::string, std::string>rule_map = it->second;
        int rule_operator = std::stoi(rule_map.at(Rule_Operator));
        float device_data = std::stof(device_info_map.at("data"));

        switch(rule_operator){
            case Operator_Gt:
                {
                    float threshold = std::stof(rule_map.at(Rule_Threshold));
                    if(device_data > threshold)
                        printf("%f > %f\n", device_data, threshold);
                    else
                        printf("GT condition does not hold => device data:%f and threshold:%f\n", device_data, threshold);
                    break;
                }
            case Operator_Lt:
                {
                    float threshold = std::stof(rule_map.at(Rule_Threshold));
                    if(device_data < threshold)
                        printf("%f < %f\n", device_data, threshold);
                    else
                        printf("LT condition does not hold => device data:%f and threshold:%f\n", device_data, threshold);
                    break;
                }
            case Operator_Eq:
                {
                    float threshold = std::stof(rule_map.at(Rule_Threshold));
                    if (device_data == threshold)
                        printf("%f == %f\n", device_data, threshold);
                    else
                        printf("EQ condition does not hold => device data:%f and threshold:%f\n", device_data, threshold);
                    break;
                }
            default:
                printf("Unknown operator for data %f\n", device_data);
        }
    }
    else
        printf("Couldn't find %s\n", device_id);

}


