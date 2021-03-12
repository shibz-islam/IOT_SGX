//
// Created by shihab on 3/5/20.
//

#include "RuleManager.h"
#include "Constants.h"
#include "Enclave.h"
#include "Enclave_t.h"
#include "RuleParser.h"
#include "analytics_utils.h"
#include "RuleConflictDetectionManager.h"
#include "EnclaveDatabaseManager.h"
#include "TimerQueueManager.h"


static inline void free_allocated_memory(void *pointer)
{
    if(pointer != NULL)
    {
        free(pointer);
        pointer = NULL;
    }
}

static inline void free_allocated_memory_void(void **pointer)
{
    if(*pointer != NULL)
    {
        free(*pointer);
        *pointer = NULL;
    }
}



/******************************************************/
/* Setup */
/******************************************************/


void setupEnclave(){
    initQueue();
    /*
    initGraph();
    std::vector<Rule*> ruleset;
    if(retrieveRulesFromDB(ruleset, 0, "", "", ALL_QUERY)){
        for (int i = 0; i < ruleset.size(); ++i) {
            updateGraph(ruleset[i]);
            if(ruleset[i]->ruleType != IF && ruleset[i]->trigger->valueType == TEMPORAL){
                addToQueue(ruleset[i]);
            }
            deleteRule(&ruleset[i]);
        }
    }else{
        printf("RuleManager:: Rule retrieval failed!");
        ruleset.clear();
    }
     */
}




/******************************************************/
/* Parsing */
/******************************************************/

/*
 * startParsingRule:
 *  Parse the decrypted rule string and make a Struct Rule
 *  @params: decrypted rule string, Struct Rule
 *  returns: true if successful, else false
 */
bool startParsingRule(char *ruleString, Rule *myRule){
    printf("RuleManager:: #startParsingRule ");
    RuleType ruleType = parseRuleTypeAction(ruleString);
    switch (ruleType){
        case IF: {
            if(parseRule(ruleString, ruleType, myRule)){
                printf("RuleManager:: Rule parsing done! ");
                return true;
            }else{
                printf("RuleManager:: Rule parsing failed ");
            }
            break;
        }
        case EVERY:{
            if(parseRule(ruleString, ruleType, myRule)){
                printf("RuleManager:: 'Every' Rule parsing done! ");
                return true;
            }else{
                printf("RuleManager:: Rule parsing failed ");
            }
            break;
        }
        default:
            printf("RuleManager:: Unknown Action ");
    }
    return false;
}

/*
 * startParsingDeviceEvent:
 *  Parse the decrypted event string and make a Struct DeviceEvent
 *  @params: decrypted event string, Struct DeviceEvent
 *  returns: true if successful, else false
 */
bool startParsingDeviceEvent(char *event, DeviceEvent *myEvent){
    printf("RuleManager:: #startParsingDeviceEvent ");
    if(parseDeviceEventData(event, myEvent)){
        printf("RuleManager:: Event parsing done! ");
        return true;
    }else{
        printf("RuleManager:: Event parsing failed ");
    }
    return false;
}




/******************************************************/
/* Operation */
/******************************************************/

/*
 * returns false if there's no conflict, else return true.
 */
bool startRuleConflictDetection(Rule *myRule){
    printf("RuleManager:: #startRuleConflictDetection");
    return detectRuleConflicts(myRule);
}

/*
 * checkRuleSatisfiability:
 *  if the device event matches the trigger properties of a Rule, then the rule is satisfied
 *  @params: an incoming device event, a Rule fetched from DB
 *  returns true if the Rule is satisfied, else false.
 */
bool checkRuleSatisfiability(DeviceEvent *myEvent, Rule *myRule){
    if(strcmp(myEvent->deviceID, myRule->trigger->deviceID) == 0){
        if(strcmp(myEvent->attribute, myRule->trigger->attribute) == 0){
            if(myEvent->valueType == STRING && myRule->trigger->valueType == STRING){
                if(strcmp(myEvent->valueString, myRule->trigger->valueString) == 0){
                    printf("RuleManager:: Success! Device event satisfies the rule!");
                }else{
                    printf("RuleManager:: Failed! Values do not match!");
                    return false;
                }
            } else if((myEvent->valueType == NUMBER && myRule->trigger->valueType == NUMBER) || (myEvent->valueType == INTEGER && myRule->trigger->valueType == INTEGER)){
                bool isSatisfied = false;
                switch (myRule->trigger->operatorType){
                    case EQ:{
                        if(myEvent->value == myRule->trigger->value)
                            isSatisfied = true;
                        break;
                    }
                    case GT:{
                        if(myEvent->value > myRule->trigger->value)
                            isSatisfied = true;
                        break;
                    }
                    case GTE:{
                        if(myEvent->value >= myRule->trigger->value)
                            isSatisfied = true;
                        break;
                    }
                    case LT:{
                        if(myEvent->value < myRule->trigger->value)
                            isSatisfied = true;
                        break;
                    }
                    case LTE:{
                        if(myEvent->value <= myRule->trigger->value)
                            isSatisfied = true;
                        break;
                    }
                    default:
                        printf("RuleManager:: Error! Invalid operator type!");
                }
                if(isSatisfied)
                    printf("RuleManager:: Success! Device event satisfies the rule!");
                else{
                    printf("RuleManager:: Failed! Values do not match!");
                    return false;
                }
            } else{
                printf("RuleManager:: Failed! Value types do not match!");
                return false;
            }
        }else{
            printf("RuleManager:: Failed! Device attributes do not match!");
            return false;
        }
    }else{
        printf("RuleManager:: Failed! Devices do not match!");
        return false;
    }
    return true;
}

/*
 * startRuleAutomation:
 *  Check if an incoming device event satisfies any rule stored in the DB.
 *  @params: device event
 *  returns: true if any Rule is satisfied, else returns false.
 */
bool startRuleAutomation(DeviceEvent *myEvent){
    printf("RuleManager:: #startRuleAutomation");
    std::vector<Rule*> ruleset;
    bool isSuccess = myEvent->valueType == STRING ? retrieveRulesFromDB(ruleset, 0, myEvent->deviceID, myEvent->valueString, BY_TRIGGER_DEVICE_ID_ATTR) : retrieveRulesFromDB(ruleset, 0, myEvent->deviceID, "", BY_TRIGGER_DEVICE_ID);
    if(isSuccess){
        for (int i = 0; i < ruleset.size(); ++i) {
            /* verify if the rule is satisfied */
            if(checkRuleSatisfiability(myEvent, ruleset[i])){
                //printRuleInfo(ruleset[i]);
                sendRuleCommands(ruleset[i]); /* send action commands */
            }
            deleteRule(&ruleset[i]);
        }
    }else{
        printf("RuleManager:: Rule retrieval failed!");
        return false;
    }
    ruleset.clear();
    return true;
}

/*
 * sendRuleCommands:
 *  sends action-commands to respective devices according to the Action part of the Rule
 *  @params: a Rule
 *  returns: true if command sent successfully, else false
 */
bool sendRuleCommands(Rule *myRule){
    Message *response = (Message*) malloc(sizeof(Message));
    response->address = myRule->action->deviceID;
    if(isEncryptionEnabled){
        /* encrypt the command */
        int len = strlen(myRule->responseCommand);
        response->text = (char *) malloc(sizeof(char) * (len+1));
        response->tag = (char *) malloc(sizeof(char) * (SGX_AESGCM_MAC_SIZE+1));
        sgx_status_t status = encryptMessageAES(myRule->responseCommand, len, response->text, len, response->tag);
        if(status != SGX_SUCCESS){
            deleteMessage(&response);
            return false;
        }
        response->textLength = len;
        response->tagLength = SGX_AESGCM_MAC_SIZE;
    } else{
        response->text = myRule->responseCommand;
    }

    size_t isSuccess = 1;
    ocall_send_rule_commands(&isSuccess, response); /* pass the response to the REE via ocall */

    if (isSuccess){
        printf("RuleManager:: Successfully sent rule command to device!");
    }else{
        printf("RuleManager:: Failed to send rule command to device!");
    }

    deleteMessage(&response);
    return isSuccess == 1? true : false;
}