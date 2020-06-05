//
// Created by shihab on 3/5/20.
//

#include "RuleManager.h"
#include "MessageParser.h"
#include "Constants.h"
#include "Enclave.h"
#include "Enclave_t.h"
#include "RuleParser.h"

#define CACHE_SIZE 20


/*** HELPER METHODS ***/





/*** CLASS METHODS ***/


RuleManager::RuleManager() {
    //TODO: initialize the map
    cache = new LRUCache(CACHE_SIZE);
}


void RuleManager::saveRulesInCache(struct rule *newRule, int count) {
    for (int i = 0; i < count; ++i) {
        //printf("*** deviceID = %s\n", newRule[i].deviceID);
        //printf("*** rule = %s\n", newRule[i].rule);
        cache->put(std::string(newRule[i].deviceID), std::string(newRule[i].rule));
    }
}


std::string RuleManager::getRuleFromCache(std::string device_id) {
    return cache->get(device_id);
}

bool RuleManager::isRuleExistInCache(std::string device_id) {
    return cache->isKeyPresent(device_id);
}



/**
 *
 * @param msg
 * @param newRule
 * @return
 */
bool RuleManager::parseRule(char *msg, struct rule *newRule) {
    std::map<std::string, std::string>rule_map = parse_decrypted_string(msg);

    auto it = rule_map.find(RULE_DEVICE_ID);
    if ( it != rule_map.end() ){
        //printf("%s: %s\n", RULE_DEVICE_ID, it->second.c_str());
        std::string device_id_str = rule_map[RULE_DEVICE_ID];
        char* deviceID =  (char *) malloc((device_id_str.length()+1)*sizeof(char));
        memcpy(deviceID, device_id_str.c_str(), device_id_str.length()+1);
        deviceID[device_id_str.length()] = '\0';

        std::string value = map_to_string(rule_map);

        newRule->deviceID = deviceID;
        newRule->rule = (char*)value.c_str();
        return true;
    }
    else
        printf("Couldn't find %s\n", RULE_DEVICE_ID);
    return false;

//    printf("Initial size of map = %ld\n", ruleset.size());
}




/**
 *
 * @param msg
 */
void RuleManager::checkRuleSatisfiability(std::string device_id, std::map<std::string,std::string> device_info_map) {
    //printf("*** Device Id = %s\n", device_id.c_str());
    std::string rule_str = cache->get(device_id);
    std::map<std::string, std::string>rule_map = parse_decrypted_string((char*)rule_str.c_str());

    //printf("*** Rule string: %s\n", rule_str.c_str());

    int rule_operator = std::stoi(rule_map.at(RULE_OPERATOR));
    float device_data = std::stof(device_info_map.at(SENSOR_DATA));

    //TODO: think how to return the value of anomaly
    std::string msg;
    bool success = true;
    switch(rule_operator){
        case OPERATOR_GT:
        {
            float threshold = std::stof(rule_map.at(RULE_THRESHOLD));
            if(device_data > threshold){
                printf("%f > %f\n", device_data, threshold);
            }
            else{
                printf("GT condition does not hold => device data:%f and threshold:%f\n", device_data, threshold);
                msg = "GT condition does not hold";
                success = false;
                //performRuleAction(rule_map, msg);
            }
            break;
        }
        case OPERATOR_LT:
        {
            float threshold = std::stof(rule_map.at(RULE_THRESHOLD));
            if(device_data < threshold){
                printf("%f < %f\n", device_data, threshold);
            }
            else{
                printf("LT condition does not hold => device data:%f and threshold:%f\n", device_data, threshold);
                msg = "LT condition does not hold";
                success = false;
                //performRuleAction(&rule_map, &msg);
            }
            break;
        }
        case OPERATOR_EQ:
        {
            float threshold = std::stof(rule_map.at(RULE_THRESHOLD));
            if (device_data == threshold) {
                printf("%f == %f\n", device_data, threshold);
            }
            else{
                printf("EQ condition does not hold => device data:%f and threshold:%f\n", device_data, threshold);
                msg = "EQ condition does not hold";
                success = false;
                //performRuleAction(rule_map, msg);
            }
            break;
        }
        default: {
            printf("Unknown operator for data %f\n", device_data);
        }
    }

    if(!success){
        int rule_action = std::stoi(rule_map.at(RULE_ACTION));
        struct ruleActionProperty property[1];
        switch(rule_action){
            case EMAIL:
            {
                property->type = rule_action;
                if(rule_map.at(RULE_EMAIL).length()>0){
                    printf("Found email %s\n", rule_map.at(RULE_EMAIL));
                    property->address = (char*) rule_map.at(RULE_EMAIL).c_str();
                    property->msg = (char*) msg.c_str();
                    sendAlertForRuleActionEmail(property);
                }
                break;
            }
            case TEXT:
            {
                property->type = rule_action;
                property->address = (char*) rule_map.at(RULE_TEXT).c_str();
                property->msg = (char*) msg.c_str();
                //TODO: handle alert
                break;
            }
            case DEVICE:
            {
                property->type = rule_action;
                std::string topic_str = rule_map.at(RULE_EMAIL) + device_id;
                printf("topic: %s\n", topic_str.c_str());
                property->address = (char*) topic_str.c_str();
                property->msg = (char*) msg.c_str();
                sendAlertForRuleActionDevice(property);
                //TODO: handle alert
                break;
            }
            default: {
                printf("Unknown action for rule %s\n", rule_map.at(RULE_ID));
            }
        }
    }
}

RuleManager::~RuleManager() {

}

std::vector<std::string> split(std::string s, std::string delimiter){
    std::vector<std::string> list;
    size_t pos = 0;
    std::string token;
    while ((pos = s.find(delimiter)) != std::string::npos) {
        token = s.substr(0, pos);
        list.push_back(token);
        s.erase(0, pos + delimiter.length());
    }
    list.push_back(s);
    return list;
}

void RuleManager::didReceiveRule(char *rule){
    if (isRuleTypeIFAction(rule)){
        printf("Enclave# isRuleTypeIFAction\n");
        std::vector<std::string> deviceIdVector = parseRuleForDeviceID(rule);
        if (!deviceIdVector.empty()){
            //store Rules in cache
            for (const auto &id : deviceIdVector) {
                printf("Enclave# device id: %s\n", id.c_str());
                cache->put(id, std::string(rule));
            }
        } else{
            printf("Enclave# deviceIdVector empty\n");
        }
    }
    else{
        //TODO: handle Every/Sleep Actions
        printf("Enclave# not IFAction\n");
    }
}

void RuleManager::didReceiveDeviceEvent(char *event){
    DeviceEvent *deviceEvent = new DeviceEvent();
    if(parseDeviceEventData(event, deviceEvent)){
        printf("Enclave# parseDeviceEventData successful\n");
        //TODO: fetch Rule for deviceID
        if(cache->isKeyPresent(std::string(deviceEvent->deviceId))){
            //TODO: check rule satisfiability with device event
            std::string rule_str = cache->get(std::string(deviceEvent->deviceId));
            std::vector<std::string> rulesList = split(rule_str, ";");
            for (auto &rule : rulesList) {
                //printf("rule: %s\n", item.c_str());
                bool isSuccess = checkRuleSatisfiabilityWithDeviceEvent((char*)rule.c_str(), deviceEvent);
                std::vector<DeviceCommand*> deviceCommands = parseRuleForDeviceCommands((char*)rule.c_str(), isSuccess);
                if(!deviceCommands.empty()){
                    for (const auto &dc : deviceCommands) {
                        printf("Enclave# device id: %s\n", dc->deviceId);
                        printf("Enclave# command: %s\n", dc->command);
                    }
                } else{
                    printf("Enclave# deviceCommandsVector empty\n");
                }
            }
            rulesList.clear();
        } else{
            printf("Enclave# key not present in cache\n");
        }
    } else{
        printf("Enclave# parseDeviceEventData unsuccessful\n");
    }
}