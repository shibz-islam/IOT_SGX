//
// Created by shihab on 3/5/20.
//

#include "RuleManager.h"
#include "MessageParser.h"
#include "Constants.h"
#include "Enclave.h"
#include "Enclave_t.h"


/*** HELPER METHODS ***/





/*** CLASS METHODS ***/


RuleManager::RuleManager() {
    //TODO: initialize the map
    cache = new LRUCache(5);
}


void RuleManager::saveRulesInCache(struct rule *newRule, int count) {
    for (int i = 0; i < count; ++i) {
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
        std::string value = map_to_string(rule_map);
        newRule->deviceID = (char*)it->second.c_str();
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
    printf("Device Id = %s\n", device_id);
    std::string rule_str = cache->get(device_id);
    std::map<std::string, std::string>rule_map = parse_decrypted_string((char*)rule_str.c_str());

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
        struct ruleActionProperty *property;
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