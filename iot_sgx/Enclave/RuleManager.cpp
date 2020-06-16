//
// Created by shihab on 3/5/20.
//

#include "RuleManager.h"
#include "Constants.h"
#include "Enclave.h"
#include "Enclave_t.h"
#include "RuleParser.h"
#include "analytics_utils.h"


#define CACHE_SIZE 40


/*** CLASS METHODS ***/


RuleManager::RuleManager() {
    //TODO: initialize the map
    cache = new LRUCache(CACHE_SIZE);
    vecTimerQueue = std::vector<TimeRule>();
}

RuleManager::~RuleManager() {

}

/***********/
/* Cache */
/***********/

void RuleManager::saveRuleInCache(Rule newRule){
    cache->put(std::string(newRule.deviceID), std::string(newRule.rule));
}

std::string RuleManager::getCacheKeys(){
    return cache->getKeys();
}

std::string RuleManager::getRuleWithKey(std::string key){
    return cache->get(key);
}


bool RuleManager::isRuleExistInCache(std::string device_id) {
    return cache->isKeyPresent(device_id);
}


/***********/
/* Queue */
/***********/
void RuleManager::saveRuleInQueue(TimeRule timeRule){
    vecTimerQueue.push_back(timeRule);
}

void RuleManager::saveRuleInPriorityQueue(TimeRule timeRule){
    timerPriorityQueue.push(timeRule);
}

/***********/
/* Helper */
/***********/

void sendDeviceCommands(std::vector<DeviceCommand*> &deviceCommands){
    printf("\nTotal Device Commands: %ld\n", deviceCommands.size());
    for (const auto &dc : deviceCommands) {
        printf("Enclave# device id: %s\n", dc->deviceId);
        printf("Enclave# command: %s\n", dc->command);
        //TODO: send commands
        char *encMessage = (char *) malloc(strlen(dc->command)*sizeof(char));
        char *tag_msg = (char *) malloc((16+1)*sizeof(char));
        sgx_status_t status = encryptMessageAES(dc->command, strlen(dc->command), encMessage, strlen(dc->command), tag_msg);
        if(status != 0){
            printf("Error! Encryption failed! ");
            free(encMessage);
            free(tag_msg);
            return;
        }
        std::string tempAddr = mqttTopicName() + std::string(dc->deviceId);

        ruleActionProperty *property = new ruleActionProperty();
        property->msg = encMessage;
        property->tag = tag_msg;
        property->address = (char*)tempAddr.c_str();
        ocall_send_alert_for_rule_action_device(property);
        free(encMessage);
        free(tag_msg);
        tempAddr.clear();
        delete property;
    }
    deviceCommands.clear();
}

void getTimeRuleEvent(TimeRule &tr){
    std::vector<DeviceCommand*> deviceCommands;
    if(parseRuleForDeviceCommands(tr.rule, deviceCommands, true) && !deviceCommands.empty()){
        sendDeviceCommands(deviceCommands);
    } else{
        printf("Enclave# deviceCommandsVector empty ");
    }
}

/**
 *
 * @param msg
 */
void storeRulesWithDeviceID(std::vector<std::string> &deviceIdVector, Rule *myRule){
    //printf("\nTotal Device IDs: %ld\n", deviceIdVector.size());
    char *encMessage = (char *) malloc(myRule->ruleLength*sizeof(char));
    char *tag_msg = (char *) malloc((16+1)*sizeof(char));
    sgx_status_t status = encryptMessageAES(myRule->rule, myRule->ruleLength, encMessage, myRule->ruleLength, tag_msg);
    if(status != 0){
        printf("Error! Encryption failed! ");
        free(encMessage);
        free(tag_msg);
        delete myRule;
        return;
    }

    myRule->rule = encMessage;
    myRule->tag = tag_msg;

    int numDevices = deviceIdVector.size();
    Rule *myRuleList = new Rule[numDevices];
    //Rule myRuleList[numDevices];
    for (int i = 0; i < numDevices; ++i) {
        myRuleList[i].deviceID = (char*)deviceIdVector[i].c_str();
        myRuleList[i].rule = myRule->rule;
        myRuleList[i].ruleLength = myRule->ruleLength;
        myRuleList[i].tag = myRule->tag;
        myRuleList[i].tagLength = 16;
    }
    ocall_store_rules(myRuleList, numDevices);

    delete[] myRuleList;
    free(encMessage);
    free(tag_msg);
}


void storeTimerRulesWithRuleID(std::vector<TimeRule> &timeRules, Rule *myRule){
    char *encMessage = (char *) malloc(myRule->ruleLength*sizeof(char));
    char *tag_msg = (char *) malloc((16+1)*sizeof(char));
    sgx_status_t status = encryptMessageAES(myRule->rule, myRule->ruleLength, encMessage, myRule->ruleLength, tag_msg);
    if(status != 0){
        printf("Error! Encryption failed! ");
        free(encMessage);
        free(tag_msg);
        delete myRule;
        return;
    }

    myRule->rule = encMessage;
    myRule->tag = tag_msg;

    int numDevices = timeRules.size();
    Rule *myRuleList = new Rule[numDevices];
    //Rule myRuleList[numDevices];
    for (int i = 0; i < numDevices; ++i) {
        myRuleList[i].deviceID = timeRules[i].ruleID;
        myRuleList[i].rule = myRule->rule;
        myRuleList[i].ruleLength = myRule->ruleLength;
        myRuleList[i].tag = myRule->tag;
        myRuleList[i].tagLength = 16;
    }
    ocall_store_rules(myRuleList, numDevices);

    delete[] myRuleList;
    free(encMessage);
    free(tag_msg);
}

/******************/
/******************/

void RuleManager::didReceiveRule(Rule *myRule, bool isStoreInFile){
    printf("#didReceiveRule ");
    RuleType ruleType = parseRuleTypeAction(myRule->rule);
    switch (ruleType){
        case IF: {
            std::vector<std::string> deviceIdVector;
            if (parseRuleForDeviceID(myRule->rule, deviceIdVector) && !deviceIdVector.empty()){
                //store Rules in cache
                for (const auto &id : deviceIdVector) {
                    //printf("#Enclave: device id: %s\n", id.c_str());
                    cache->put(id, std::string(myRule->rule));
                }
                if (isStoreInFile)
                    storeRulesWithDeviceID(deviceIdVector, myRule);
            } else{
                printf("#Enclave: deviceIdVector empty ");
            }
            break;
        }
        case EVERY: {
            std::vector<TimeRule> timeRules;
            if(parseRuleForTimeInfo(myRule->rule, timeRules) && !timeRules.empty()){
                for (auto &timeRule : timeRules) {
                    printf("#Enclave: %s %s %d %s\n", timeRule.ruleID, timeRule.timeReference, timeRule.timeOffset, timeRule.unit);
                    if(configureTimeString(timeRule)){
                        char *tempRule = (char *) malloc((strlen(myRule->rule)+1)*sizeof(char));
                        memcpy(tempRule, myRule->rule, strlen(myRule->rule));
                        timeRule.rule = tempRule;
                        saveRuleInQueue(timeRule);
                    }else{
                        printf("Enclave# configureTimeString unsuccessful ");
                    }
                }
                if (isStoreInFile)
                    storeTimerRulesWithRuleID(timeRules, myRule);
            } else{
                printf("Enclave# parseRuleForTimeInfo unsuccessful ");
            }
            break;
        }
        case SLEEP: {
            break;
        }
        default:
            printf("#Enclave: Unknown Action ");
    }
}

void RuleManager::didReceiveDeviceEvent(char *event){
    printf("#didReceiveDeviceEvent ");
    //printf("#Enclave: cache keys= %s\n", cache->getKeys().c_str());
    DeviceEvent *deviceEvent = new DeviceEvent();
    if(parseDeviceEventData(event, deviceEvent)){
        //TODO: fetch Rule for deviceID
        //printf("#Enclave: device id: %s\n", deviceEvent->deviceId);
        //printf("#Enclave: device attr: %s\n", deviceEvent->attribute);
        //printf("#Enclave: device val: %s\n", deviceEvent->value);
        if(cache->isKeyPresent(std::string(deviceEvent->deviceId))){
            //TODO: check rule satisfiability with device event
            std::string rule_str = cache->get(std::string(deviceEvent->deviceId));
            printf("\n==> \nrule: %s\n", rule_str.c_str());
            std::vector<std::string> rulesList = split(rule_str, ";");
            for (auto &rule : rulesList) {
                //printf("rule: %s\n", item.c_str());
                bool isSuccess = checkRuleSatisfiabilityWithDeviceEvent((char*)rule.c_str(), deviceEvent);
                std::vector<DeviceCommand*> deviceCommands;
                if(parseRuleForDeviceCommands((char*)rule.c_str(), deviceCommands, isSuccess) && !deviceCommands.empty()){
                    sendDeviceCommands(deviceCommands);
                } else{
                    printf("#Enclave: deviceCommandsVector empty ");
                }
                deviceCommands.clear();
            }
            rulesList.clear();
        } else{
            printf("#Enclave: key not present in cache ");
        }
    } else{
        printf("#Enclave: parseDeviceEventData unsuccessful ");
    }
}

void RuleManager::didReceiveRequestToCheckTimerRule(int hour, int min){
    if(!vecTimerQueue.empty()){
        printf("checkTimerRule# vecTimerQueue size: %ld\n", vecTimerQueue.size());
        TimeRule tr;
        for (int i = 0; i < vecTimerQueue.size(); ++i) {
            tr = vecTimerQueue[i];
            printf("checkTimerRule# TimeRule: id=%s, h=%d, m=%d\n", tr.ruleID, tr.hour, tr.min);
            int timeDiffMinute = getTimeMinute(tr.hour, tr.min) - getTimeMinute(hour, min);
            if(timeDiffMinute > 0 && timeDiffMinute <= 60){
                saveRuleInPriorityQueue(tr);
            }
        }
    }
}

int RuleManager::didReceiveRequestToCheckPendingTimerRule(int hour, int min){
    if(!timerPriorityQueue.empty()){
        TimeRule tr = timerPriorityQueue.top();
        printf("checkPendingTimerRule# timerPriorityQueue size: %ld\n", timerPriorityQueue.size());
        printf("checkPendingTimerRule# TimeRule: id=%s, h=%d, m=%d\n", tr.ruleID, tr.hour, tr.min);
        int timeDiffMinute = getTimeMinute(tr.hour, tr.min) - getTimeMinute(hour, min);
        if(timeDiffMinute <= 1){
            timerPriorityQueue.pop();
            getTimeRuleEvent(tr);
            return 0;
        }
        else if ( timeDiffMinute > 1 && timeDiffMinute <= 60){
            return timeDiffMinute-1;
        }
    }
    return -1;
}