//
// Created by shihab on 9/11/19.
//

#include "EnclaveHelper.h"
#include <stdio.h> /* vsnprintf */
#include <string.h>
#include <ctype.h>


std::string mqttTopicForData = "topic/utd/iot/server/data/";
bool isEncryptionEnabled = true;

void toLowerCase(char *str){
    int i, s = strlen(str);
    for (i = 0; i < s; i++)
        str[i] = tolower(str[i]);
}

RuleType getRuleType(char *key){
    toLowerCase(key);
    if(strcmp(key, "if")==0){
        return IF;
    }else if(strcmp(key, "every")==0){
        return EVERY;
    } else if(strcmp(key, "sleep")==0){
        return SLEEP;
    } else{
        return UNKNOWN_RULE;
    }
}

ValueType getValueType(char *key){
    toLowerCase(key);
    if(strcmp(key, "string")==0){
        return STRING;
    }else if(strcmp(key, "integer")==0){
        return INTEGER;
    } else if(strcmp(key, "number")==0){
        return NUMBER;
    } else{
        return UNKNOWN_VALUE;
    }
}

OperatorType getOperatorType (char *key){
    if(strcmp(key, "equals")==0 || strcmp(key, "equal")==0){
        return EQ;
    }else if(strcmp(key, "greater_than")==0 || strcmp(key, "gt")==0){
        return GT;
    }
    else if(strcmp(key, "less_than")==0 || strcmp(key, "lt")==0){
        return LT;
    }
    else if(strcmp(key, "greater_than_or_equals")==0 || strcmp(key, "greater_than_or_equal")==0 || strcmp(key, "gte")==0){
        return GTE;
    }
    else if(strcmp(key, "less_than_or_equals")==0 || strcmp(key, "less_than_or_equal")==0 || strcmp(key, "lte")==0){
        return LTE;
    }
    else{
        return INVALID_OP;
    }
}

TimeReferenceType getTimeReferenceType (char *key){
    toLowerCase(key);
    if(strcmp(key, "now")==0){
        return NOW;
    } else if(strcmp(key, "midnight")==0){
        return MIDNIGHT;
    } else if(strcmp(key, "sunrise")==0){
        return SUNRISE;
    } else if(strcmp(key, "noon")==0){
        return NOON;
    } else if(strcmp(key, "sunset")==0){
        return SUNSET;
    } else {
        return UNKNOWN_TIME_REFERENCE;
    }
}

TimeUnitType getTimeUnitType (char *key){
    toLowerCase(key);
    if(strcmp(key, "second")==0){
        return SECOND;
    } else if(strcmp(key, "minute")==0){
        return MINUTE;
    } else if(strcmp(key, "hour")==0){
        return HOUR;
    } else if(strcmp(key, "day")==0){
        return DAY;
    } else if(strcmp(key, "week")==0){
        return WEEK;
    } else if(strcmp(key, "month")==0){
        return MONTH;
    } else if(strcmp(key, "year")==0){
        return YEAR;
    } else {
        return UNKNOWN_TIME_UNIT;
    }
}

std::string getTimeString(TimeReferenceType timeReferenceType, int timeOffset, TimeUnitType timeUnitType){
    int h = 0;
    switch (timeReferenceType){
        case MIDNIGHT:{
            h = 00; break;
        }
        case SUNRISE:{
            h = 06; break;
        }
        case NOON:{
            h = 12; break;
        }
        case SUNSET:{
            h = 18; break;
        }
        case NOW:
        default:{
            printf("invalid time reference... ");
            return "";
        }
    }

    int hourOffset = 0, minOffset = 0;
    switch (timeUnitType){
        case MINUTE:{
            hourOffset = timeOffset / 60;
            minOffset = timeOffset % 60;
            //printf("%d, %d, %d\n", hour, hourOffset, minOffset);
            hourOffset = minOffset >= 0 ? hourOffset : hourOffset-1;
            minOffset = minOffset >= 0 ? minOffset : 60+minOffset;
            break;
        }
        case HOUR:{
            hourOffset = timeOffset;
            break;
        }
        default:{
            printf("invalid time unit... ");
            return "";
        }
    }

    h = h + hourOffset;
    if (h < 0)
        h = h + 24;
    printf("time String: %d:%d\n", h, minOffset);

    std::string timeString = std::to_string(h) + ":" + std::to_string(minOffset) + ":" + "00";
    return timeString;
}

int getTimeMinute(int h, int m){
    return h*60+m;
}

int getTimeSecond(int h, int m){
    return (h*60+m)*60;
}

std::string mqttTopicName(){
    return mqttTopicForData;
}

bool initRule(Rule **myrule){
    *myrule = (Rule*) malloc( sizeof( struct Rule ));
    if (*myrule == NULL) {
        printf("EnclaveHelper:: Memory allocation error!");
        return false;
    }
    (*myrule)->trigger = (RuleComponent*) malloc( sizeof( struct RuleComponent ));
    if ((*myrule)->trigger == NULL) {
        printf("EnclaveHelper:: Memory allocation error!");
        return false;
    }
    (*myrule)->action = (RuleComponent*) malloc( sizeof( struct RuleComponent ));
    if ((*myrule)->action == NULL) {
        printf("EnclaveHelper:: Memory allocation error!");
        return false;
    }
    return true;
}

bool deleteRule(Rule **myrule){
    if (*myrule == NULL) {
        printf("EnclaveHelper:: Rule NULL!");
        return false;
    }

    if ((*myrule)->trigger != NULL) {
        //printf("EnclaveHelper:: trigger!");
        if ((*myrule)->trigger->deviceID != NULL) free((*myrule)->trigger->deviceID);
        if ((*myrule)->trigger->capability != NULL) free((*myrule)->trigger->capability);
        if ((*myrule)->trigger->attribute != NULL) free((*myrule)->trigger->attribute);
        if ((*myrule)->trigger->valueString != NULL) free((*myrule)->trigger->valueString);
        free((*myrule)->trigger);
        (*myrule)->trigger = NULL;
    }
    if ((*myrule)->action != NULL){
        //printf("EnclaveHelper:: action!");
        if ((*myrule)->action->deviceID != NULL) free((*myrule)->action->deviceID);
        //printf("EnclaveHelper:: capability!");
        if ((*myrule)->action->capability != NULL) free((*myrule)->action->capability);
        //printf("EnclaveHelper:: attribute!");
        if ((*myrule)->action->attribute != NULL) free((*myrule)->action->attribute);
        //printf("EnclaveHelper:: valueString!");
        if ((*myrule)->action->valueString != NULL) free((*myrule)->action->valueString);
        //printf("EnclaveHelper:: action full!");
        free((*myrule)->action);
        (*myrule)->action = NULL;
    }
    //printf("EnclaveHelper:: myrule!");
    if ((*myrule)->ruleID != NULL) free((*myrule)->ruleID);
    if ((*myrule)->responseCommand != NULL) free((*myrule)->responseCommand);
    free(*myrule);
    *myrule = NULL;
    return true;
}

bool deleteDeviceEvent(DeviceEvent **myEvent){
    if (*myEvent == NULL) {
        printf("EnclaveHelper:: Device Event NULL!");
        return false;
    }
    if((*myEvent)->deviceID != NULL) free((*myEvent)->deviceID);
    //printf("EnclaveHelper:: capability!");
    if((*myEvent)->capability != NULL) free((*myEvent)->capability);
    //printf("EnclaveHelper:: attribute!");
    if((*myEvent)->attribute != NULL) free((*myEvent)->attribute);
    //printf("EnclaveHelper:: valueString!");
    if((*myEvent)->valueString != NULL) free((*myEvent)->valueString);
    //printf("EnclaveHelper:: unit!");
    if((*myEvent)->unit != NULL) free((*myEvent)->unit);
    //printf("EnclaveHelper:: timestamp!");
    if((*myEvent)->timestamp != NULL) free((*myEvent)->timestamp);
    //printf("EnclaveHelper:: freeing event!");
    free(*myEvent);
    *myEvent = NULL;
    return true;
}

bool deleteMessage(Message **msg){
    if((*msg)->isEncrypted){

        if((*msg)->text != NULL){
            //printf("EnclaveHelper:: text!");
            free((*msg)->text);
        }

        if((*msg)->tag != NULL) {
            //printf("EnclaveHelper:: tag!");
            free((*msg)->tag);
        }
    }
    //printf("EnclaveHelper:: freeing msg!");
    free(*msg);
    *msg = NULL;
    return true;
}


/*
 * Printing
 */

void printRuleInfo(Rule *myRule){
    if(myRule->ruleType == IF){
        if(myRule->trigger->valueType == STRING && myRule->action->valueType == STRING){
            printf("Rule:: id=%s, tr_device_id=%s, tr_attr=%s, tr_value=%s, ac_device_id=%s, ac_attr=%s, ac_value=%s",
                   myRule->ruleID, myRule->trigger->deviceID, myRule->trigger->attribute, myRule->trigger->valueString,
                   myRule->action->deviceID, myRule->action->attribute, myRule->action->valueString);

        }
        else if (myRule->trigger->valueType == NUMBER && myRule->action->valueType == NUMBER){
            printf("Rule:: id=%s, tr_device_id=%s, tr_attr=%s, tr_value=%f, ac_device_id=%s, ac_attr=%s, ac_value=%f",
                   myRule->ruleID, myRule->trigger->deviceID, myRule->trigger->attribute, myRule->trigger->value,
                   myRule->action->deviceID, myRule->action->attribute, myRule->action->value);
        }
        else if (myRule->trigger->valueType == STRING && myRule->action->valueType == NUMBER){
            printf("Rule:: id=%s, tr_device_id=%s, tr_attr=%s, tr_value=%s, ac_device_id=%s, ac_attr=%s, ac_value=%f",
                   myRule->ruleID, myRule->trigger->deviceID, myRule->trigger->attribute, myRule->trigger->valueString,
                   myRule->action->deviceID, myRule->action->attribute, myRule->action->value);
        }
        else if (myRule->trigger->valueType == NUMBER && myRule->action->valueType == STRING){
            printf("Rule:: id=%s, tr_device_id=%s, tr_attr=%s, tr_value=%f, ac_device_id=%s, ac_attr=%s, ac_value=%s",
                   myRule->ruleID, myRule->trigger->deviceID, myRule->trigger->attribute, myRule->trigger->value,
                   myRule->action->deviceID, myRule->action->attribute, myRule->action->valueString);
        }
        else{
            printf("Error! Something went wrong while trying to print!");
        }
    } else if(myRule->ruleType == EVERY){
        printf("Rule:: id=%s, tr_device_id=%s, time_ref_type=%d, time_offset=%d, ac_device_id=%s, ac_attr=%s, ac_value=%s",
                myRule->ruleID, myRule->trigger->deviceID, myRule->trigger->timeReferenceType, myRule->trigger->timeOffset, myRule->action->deviceID, myRule->action->attribute, myRule->action->valueString);
    } else {
        printf("Error! Unknown rule type");
    }

}

void printDeviceEventInfo(DeviceEvent *myEvent){
    if(myEvent->valueType == STRING){
        printf("DeviceEvent:: Event: deviceID=%s, capability=%s, attribute=%s, value=%s", myEvent->deviceID, myEvent->capability, myEvent->attribute, myEvent->valueString);
    } else{
        printf("DeviceEvent:: Event: deviceID=%s, capability=%s, attribute=%s, value=%f", myEvent->deviceID, myEvent->capability, myEvent->attribute, myEvent->value);
    }
}

void printConflictType(ConflictType conflict){
    switch (conflict){
        case SHADOW:{
            printf("RuleConflict:: Shadow!");
            break;
        }
        case EXECUTION:{
            printf("RuleConflict:: Execution!");
            break;
        }
        case MUTUAL:{
            printf("RuleConflict:: Environment Mutual Conflict!");
            break;
        }
        case DEPENDENCE:{
            printf("RuleConflict:: Dependence!");
            break;
        }
        case CHAIN:{
            printf("RuleConflict:: Chaining exist!");
            break;
        }
        case CHAIN_FWD:{
            printf("RuleConflict:: Forward Chaining exist!");
            break;
        }
        default:
            printf("RuleConflict: No conflict detected!");
    }
}

void check_error_code(sgx_status_t stat){
    //printf("STATUS: %d",stat);
    /* More Error Codes in SDK Developer Reference */
    switch (stat){
        case SGX_SUCCESS:
            printf("SGX_SUCCESS, with code=%d",stat);
            break;
        case SGX_ERROR_INVALID_PARAMETER:
            printf("SGX_ERROR_INVALID_PARAMETER, with code=%d", stat);
            break;
        case SGX_ERROR_MAC_MISMATCH:
            printf("SGX_ERROR_MAC_MISMATCH, with code=%d", stat);
            break;
        case SGX_ERROR_OUT_OF_MEMORY:
            printf("SGX_ERROR_OUT_OF_MEMORY, with code=%d", stat);
            break;
        case SGX_ERROR_UNEXPECTED:
            printf("SGX_ERROR_UNEXPECTED, with code=%d", stat);
            break;
        case SGX_ERROR_AE_SESSION_INVALID:
            printf("SGX_ERROR_AE_SESSION_INVALID, with code=%d", stat);
            break;
        default:
            printf("Unknown error, with code=%d", stat);
    }
    return;
}