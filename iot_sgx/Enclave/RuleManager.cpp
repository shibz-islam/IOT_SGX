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

void RuleManager::sendDeviceCommands(std::vector<DeviceCommand*> &deviceCommands){
    printf("\nTotal Device Commands: %ld\n", deviceCommands.size());
    for (const auto &dc : deviceCommands) {
        printf("Enclave# device id: %s\n", dc->deviceId);
        printf("Enclave# command: %s\n", dc->command);
        //TODO: send commands
        char *encMessage = NULL;
        char *tag_msg = NULL;
        if(isEncryptionEnabled){
            encMessage = (char *) malloc(strlen(dc->command)*sizeof(char));
            tag_msg = (char *) malloc((16+1)*sizeof(char));
            sgx_status_t status = encryptMessageAES(dc->command, strlen(dc->command), encMessage, strlen(dc->command), tag_msg);
            if(status != 0){
                printf("Error! Encryption failed! ");
                free(encMessage);
                free(tag_msg);
                return;
            }
        }else{
            encMessage = dc->command;
            tag_msg = dc->deviceId;
        }

        std::string tempAddr = mqttTopicName() + std::string(dc->deviceId);

        ruleActionProperty *property = new ruleActionProperty();
        property->msg = encMessage;
        property->tag = tag_msg;
        property->address = (char*)tempAddr.c_str();

        //ocall_send_alert_for_rule_action_device(property);

        free(encMessage);
        free(tag_msg);
        tempAddr.clear();
        delete property;
    }
}


/**
 *
 * @param msg
 */
void RuleManager::storeRulesWithDeviceID(std::vector<std::string> &deviceIdVector, Rule *myRule){
    //printf("\nTotal Device IDs: %ld\n", deviceIdVector.size());
    char *encMessage = NULL;
    char *tag_msg = NULL;
    if(isEncryptionEnabled){
        encMessage = (char *) malloc(myRule->ruleLength*sizeof(char));
        tag_msg = (char *) malloc((16+1)*sizeof(char));
        sgx_status_t status = encryptMessageAES(myRule->rule, myRule->ruleLength, encMessage, myRule->ruleLength, tag_msg);
        if(status != 0){
            printf("Error! Encryption failed! ");
            free(encMessage);
            free(tag_msg);
            return;
        }
        myRule->rule = encMessage;
        myRule->tag = tag_msg;
        myRule->tagLength = 16;
    }else{
        std::string temp_tag("#");
        myRule->tag = (char*) temp_tag.c_str();
        myRule->tagLength = temp_tag.length();
    }

    int numDevices = deviceIdVector.size();
    Rule *myRuleList = new Rule[numDevices];
    //Rule myRuleList[numDevices];
    for (int i = 0; i < numDevices; ++i) {
        myRuleList[i].deviceID = (char*)deviceIdVector[i].c_str();
        myRuleList[i].rule = myRule->rule;
        myRuleList[i].ruleLength = myRule->ruleLength;
        myRuleList[i].tag = myRule->tag;
        myRuleList[i].tagLength = myRule->tagLength;
    }

    size_t isSuccess = 0;
    ocall_store_rules(&isSuccess, myRuleList, numDevices);
    if(isSuccess == 1)
        printf(" --- store successful---- ");
    else
        printf(" --- Error occured... store unsuccessful---- ");

    delete[] myRuleList;
    free(encMessage);
    free(tag_msg);
}


void RuleManager::storeTimerRulesWithRuleID(std::vector<TimeRule> &timeRules, Rule *myRule){
    char *encMessage = NULL;
    char *tag_msg = NULL;
    if(isEncryptionEnabled) {
        encMessage = (char *) malloc(myRule->ruleLength*sizeof(char));
        tag_msg = (char *) malloc((16+1)*sizeof(char));
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
        myRule->tagLength = 16;
    } else{
        std::string temp_tag("#");
        myRule->tag = (char*) temp_tag.c_str();
        myRule->tagLength = temp_tag.length();
    }

    int numDevices = timeRules.size();
    Rule *myRuleList = new Rule[numDevices];
    //Rule myRuleList[numDevices];
    for (int i = 0; i < numDevices; ++i) {
        myRuleList[i].deviceID = timeRules[i].ruleID;
        myRuleList[i].rule = myRule->rule;
        myRuleList[i].ruleLength = myRule->ruleLength;
        myRuleList[i].tag = myRule->tag;
        myRuleList[i].tagLength = myRule->tagLength;
    }
    size_t isSuccess = 0;
    ocall_store_rules(&isSuccess, myRuleList, numDevices);
    if(isSuccess == 1)
        printf(" --- store successful---- ");
    else
        printf(" --- Error occured... store unsuccessful---- ");


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
                    printf("#Enclave: device id: %s\n", id.c_str());
                    cache->put(id, std::string(myRule->rule));
                }
                if (isStoreInFile)
                    storeRulesWithDeviceID(deviceIdVector, myRule);
            } else{
                printf("#Enclave: deviceIdVector empty ");
            }
            //printf("---> clear vector...");
            deviceIdVector.clear();
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
        printf("#Enclave: device id: %s\n", deviceEvent->deviceId);
        printf("#Enclave: device attr: %s\n", deviceEvent->attribute);
        printf("#Enclave: device val: %s\n", deviceEvent->value);
        if(cache->isKeyPresent(std::string(deviceEvent->deviceId))){
            //TODO: check rule satisfiability with device event
            std::string rule_str = cache->get(std::string(deviceEvent->deviceId));
            printf("\n==> \nrule: %s\n", rule_str.c_str());
            std::vector<std::string> rulesList = split(rule_str, ";");
            for (auto &rule : rulesList) {
                //printf("rule: %s\n", item.c_str());
                bool isSuccess = checkRuleSatisfiabilityWithDeviceEvent((char*)rule.c_str(), deviceEvent);
                printf("#Enclave: done rule check...");
                std::vector<DeviceCommand*> deviceCommands;
                if(parseRuleForDeviceCommands((char*)rule.c_str(), deviceCommands, isSuccess) && !deviceCommands.empty()){
                    printf("#Enclave: done parseRuleForDeviceCommands...");
                    //sendDeviceCommands(deviceCommands);
                    printf("#Enclave: sendDeviceCommands func ");
                } else{
                    printf("#Enclave: deviceCommandsVector empty ");
                }
                deviceCommands.clear();
                size_t isLogged = 0;
                //ocall_log_execution_time( &isLogged, deviceEvent->deviceId);
            }
            rulesList.clear();
            printf("---> clear vector...");
        } else{
            printf("#Enclave: key not present in cache ");

        }

    } else{
        printf("#Enclave: parseDeviceEventData unsuccessful ");
    }
    //delete deviceEvent;
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
            std::vector<DeviceCommand*> deviceCommands;
            if(parseRuleForDeviceCommands(tr.rule, deviceCommands, true) && !deviceCommands.empty()){
                sendDeviceCommands(deviceCommands);
            } else{
                printf("Enclave# deviceCommandsVector empty ");
            }
            return 0;
        }
        else if ( timeDiffMinute > 1 && timeDiffMinute <= 60){
            return timeDiffMinute-1;
        }
    }
    return -1;
}