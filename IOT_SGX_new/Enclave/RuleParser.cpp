//
// Created by shihab on 6/2/20.
//
#include "RuleParser.h"


bool parseTriggerDevice(cJSON *triggerObj, Rule *myrule){
    //printf("RuleParser:: #parseTriggerDevice ");
    const cJSON *capability = cJSON_GetObjectItem(triggerObj, "capability");
    if (cJSON_IsString(capability) && (capability->valuestring != NULL)) {
        myrule->trigger->capability = (char*) malloc(strlen(capability->valuestring) + 1);
        memcpy(myrule->trigger->capability, capability->valuestring, strlen(capability->valuestring));
        myrule->trigger->capability[strlen(capability->valuestring)] = '\0';
    }else
        return false;

    const cJSON *attribute = cJSON_GetObjectItem(triggerObj, "attribute");
    if (cJSON_IsString(attribute) && (attribute->valuestring != NULL)) {
        myrule->trigger->attribute = (char*) malloc(strlen(attribute->valuestring) + 1);
        memcpy(myrule->trigger->attribute, attribute->valuestring, strlen(attribute->valuestring));
        myrule->trigger->attribute[strlen(attribute->valuestring)] = '\0';
    }else
        return false;

    const cJSON *deviceList = cJSON_GetObjectItem(triggerObj, "devices");
    if (cJSON_IsArray(deviceList)){
        for (int i = 0 ; i < cJSON_GetArraySize(deviceList) ; i++){
            //printf("Device id: %s ",cJSON_GetArrayItem(deviceList, i)->valuestring);
            myrule->trigger->deviceID = (char*) malloc(strlen(cJSON_GetArrayItem(deviceList, i)->valuestring) + 1);
            memcpy(myrule->trigger->deviceID, cJSON_GetArrayItem(deviceList, i)->valuestring, strlen(cJSON_GetArrayItem(deviceList, i)->valuestring));
            myrule->trigger->deviceID[strlen(cJSON_GetArrayItem(deviceList, i)->valuestring)] = '\0';
            break;
        }
    }else
        return false;

    return true;
}

bool parseActionDevice(const cJSON *actionCommand, Rule *myrule){
    //printf("RuleParser:: #parseActionDevice ");
    const cJSON *capability = cJSON_GetObjectItem(actionCommand, "capability");
    if (cJSON_IsString(capability) && (capability->valuestring != NULL)) {
        myrule->action->capability = (char*) malloc(strlen(capability->valuestring) + 1);
        memcpy(myrule->action->capability, capability->valuestring, strlen(capability->valuestring));
        myrule->action->capability[strlen(capability->valuestring)] = '\0';
    }else
        return false;

    const cJSON *attribute = cJSON_GetObjectItem(actionCommand, "command");
    if (cJSON_IsString(attribute) && (attribute->valuestring != NULL)) {
        myrule->action->attribute = (char*) malloc(strlen(attribute->valuestring) + 1);
        memcpy(myrule->action->attribute, attribute->valuestring, strlen(attribute->valuestring));
        myrule->action->attribute[strlen(attribute->valuestring)] = '\0';
    }else
        return false;

    /*arguments section*/
    const cJSON *arguments = cJSON_GetObjectItem(actionCommand, "arguments");
    if(cJSON_IsArray(arguments)){
        if(cJSON_GetArraySize(arguments) > 0){
            const cJSON *arg0 = cJSON_GetArrayItem(arguments, 0)->child;
            if (cJSON_IsString(arg0) && (arg0->valuestring != NULL)){
                myrule->action->valueType = STRING;
                myrule->action->valueString = (char*) malloc(strlen(arg0->valuestring) + 1);
                memcpy(myrule->action->valueString, arg0->valuestring, strlen(arg0->valuestring));
                myrule->action->valueString[strlen(arg0->valuestring)] = '\0';
            } else if(cJSON_IsNumber(arg0)){
                myrule->action->valueType = NUMBER;
                myrule->action->value = arg0->valuedouble;
                myrule->action->valueString = NULL;
            }
        }else{
            myrule->action->valueType = STRING;
            myrule->action->valueString = (char*) malloc(strlen(myrule->action->attribute) + 1);
            memcpy(myrule->action->valueString, myrule->action->attribute, strlen(myrule->action->attribute));
            myrule->action->valueString[strlen(myrule->action->attribute)] = '\0';
            //myrule->action->valueString = myrule->action->attribute;
        }
    } else{
        printf("RuleParser:: arguments is not an array!");
    }

    return true;
}

bool parseConditionValue(const cJSON *triggerValue, Rule *myrule){
    //printf("RuleParser:: #parseConditionValue ");
    ValueType triggerValueType = getValueType(triggerValue->child->string);
    const cJSON *value = NULL;
    switch (triggerValueType){
        case STRING:{
            myrule->trigger->valueType = STRING;
            value = cJSON_GetObjectItemCaseSensitive(triggerValue, "string");
            if (cJSON_IsString(value) && (value->valuestring != NULL))
            {
                myrule->trigger->valueString = (char*) malloc(strlen(value->valuestring) + 1);
                memcpy(myrule->trigger->valueString, value->valuestring, strlen(value->valuestring));
                myrule->trigger->valueString[strlen(value->valuestring)] = '\0';
            }
            break;
        }
        case INTEGER:{
            myrule->trigger->valueType = NUMBER;
            myrule->trigger->valueString = NULL;
            value = cJSON_GetObjectItemCaseSensitive(triggerValue, "integer");
            if (cJSON_IsNumber(value))
            {
                myrule->trigger->value = value->valueint;
            }
            break;
        }
        case NUMBER:{
            myrule->trigger->valueType = NUMBER;
            myrule->trigger->valueString = NULL;
            value = cJSON_GetObjectItemCaseSensitive(triggerValue, "number");
            if (cJSON_IsNumber(value))
            {
                myrule->trigger->value = value->valuedouble;
            }
            break;
        }
        default:
            printf("RuleParser:: Unknown Trigger Value ");
            return false;
    }
    return true;
}

bool parseRuleForTrigger(const cJSON *trigger, Rule *myRule){
    //printf("RuleParser:: #parseRuleForTrigger ");
    const cJSON *condition = trigger->child;
    OperatorType triggerOperatorType = getOperatorType(condition->string);
    //printf("operator type = %d ", triggerOperatorType);
    myRule->trigger->operatorType = triggerOperatorType;

    const cJSON *triggerObj = NULL;
    const cJSON *triggerValue = NULL;
    switch (triggerOperatorType){
        case EQ:{
            //printf("*** EQ");
            triggerObj = cJSON_GetObjectItemCaseSensitive(condition, "left");
            triggerValue = cJSON_GetObjectItemCaseSensitive(condition, "right");
            break;
        }
        case GT:{
            //printf("*** GT");
            triggerObj = cJSON_GetObjectItemCaseSensitive(condition, "right");
            triggerValue = cJSON_GetObjectItemCaseSensitive(condition, "left");
            break;
        }
        case LT:{
            //printf("*** LT");
            triggerObj = cJSON_GetObjectItemCaseSensitive(condition, "right");
            triggerValue = cJSON_GetObjectItemCaseSensitive(condition, "left");
            break;
        }
        case GTE:{
            //printf("*** GTE");
            triggerObj = cJSON_GetObjectItemCaseSensitive(condition, "right");
            triggerValue = cJSON_GetObjectItemCaseSensitive(condition, "left");
            break;
        }
        case LTE:{
            //printf("*** LTE");
            triggerObj = cJSON_GetObjectItemCaseSensitive(condition, "right");
            triggerValue = cJSON_GetObjectItemCaseSensitive(condition, "left");
            break;
        }
        default:{
            printf("RuleParser:: Unknown Trigger OperatorType ");
            return false;
        }
    }

    if (!cJSON_IsNull(triggerObj) && !cJSON_IsNull(triggerValue)){
        if (parseTriggerDevice(triggerObj->child, myRule) && parseConditionValue(triggerValue, myRule)){
            return true;
        }
    } else{
        printf("RuleParser:: Unknown object ");
        return false;
    }

    return false;
}

bool parseRuleForTimeTrigger(const cJSON *trigger, Rule *myRule){
    //printf("RuleParser:: #parseRuleForTimeTrigger ");
    const cJSON *condition = trigger->child;
    if(strcmp(condition->string, "specific") == 0){
        const cJSON *reference = cJSON_GetObjectItem(condition, "reference");
        if (cJSON_IsString(reference) && (reference->valuestring != NULL)) {
            myRule->trigger->timeReferenceType = getTimeReferenceType(reference->valuestring);
        }else
            return false;

        const cJSON *offset = cJSON_GetObjectItem(condition, "offset");
        if (cJSON_IsObject(offset)){
            const cJSON *valueObj = cJSON_GetObjectItem(offset, "value");
            const cJSON *value = cJSON_GetObjectItem(valueObj, "integer");
            if (cJSON_IsNumber(value)) {
                myRule->trigger->timeOffset = value->valueint;
                //printf("RuleParser:: %d / %d", myRule->trigger->timeOffset, value->valueint);
            }
            else
                return false;

            const cJSON *unitObj = cJSON_GetObjectItem(offset, "unit");
            if (cJSON_IsString(unitObj) && (unitObj->valuestring != NULL)){
                myRule->trigger->timeUnitType = getTimeUnitType(unitObj->valuestring);
            }else
                return false;

        }else
            return false;

    }else{
        printf("RuleParser:: Unknown Time OperatorType ");
        return false;
    }
}

bool parseRuleForActionList(const cJSON *actions, Rule *myrule){
    //printf("RuleParser:: #parseRuleForActionList ");
    const cJSON *action = NULL;
    cJSON_ArrayForEach(action, actions)
    {
        char *commandType = action->child->string;
        //printf("command key: \"%s\"\n", commandType);
        if (strcmp(commandType, "command") == 0){
            const cJSON *commandJson = cJSON_GetObjectItem(action, "command");
            //char *str = cJSON_Print(commandJson);

            const cJSON *deviceList = cJSON_GetObjectItem(commandJson, "devices");
            if (cJSON_IsArray(deviceList)){
                for (int i = 0 ; i < cJSON_GetArraySize(deviceList) ; i++){
                    //printf("Device id: %s\n",cJSON_GetArrayItem(deviceList, i)->valuestring);
                    myrule->action->deviceID = (char*) malloc(strlen(cJSON_GetArrayItem(deviceList, i)->valuestring) + 1);
                    memcpy(myrule->action->deviceID, cJSON_GetArrayItem(deviceList, i)->valuestring, strlen(cJSON_GetArrayItem(deviceList, i)->valuestring));
                    myrule->action->deviceID[strlen(cJSON_GetArrayItem(deviceList, i)->valuestring)] = '\0';
                    break;
                }
            }else
                return false;

            //store response command of the Rule
            cJSON *monitor = cJSON_CreateObject();
            if(cJSON_AddItemToObject(monitor, "commands", cJSON_GetObjectItemCaseSensitive(commandJson, "commands"))){
                char *str = cJSON_Print(monitor);
                //printf("*** cJSON_Print = %s", str);
                myrule->responseCommand = (char*) malloc(strlen(str) + 1);
                memcpy(myrule->responseCommand, str, strlen(str));
                myrule->responseCommand[strlen(str)] = '\0';
                //printf("*** myrule->responseCommand = %s", myrule->responseCommand);
                cJSON_free(str);

            }
            cJSON_free(monitor);

            const cJSON *actionCommand = NULL;
            const cJSON *commandList = cJSON_GetObjectItemCaseSensitive(commandJson, "commands");
            cJSON_ArrayForEach(actionCommand, commandList)
            {
                return parseActionDevice(actionCommand, myrule);
                break;
            }
        }
        break;
    }
    return false;
}

bool parseRuleForAction(const cJSON *command, Rule *myrule, RuleType type){
    //printf("RuleParser:: #parseRuleForAction ");
    if(type == IF){
        const cJSON *condition = command->child;
        while (condition){
            char *conditionType = condition->string;
            if (strcmp(conditionType, "then") == 0){
                //printf("RuleParser:: then ");
                return parseRuleForActionList(condition, myrule);
            }
            else if (strcmp(conditionType, "else") == 0){
                //printf("RuleParser:: else ");
            }
            condition = condition->next;
        }
        return false;
    } else if(type == EVERY){
        const cJSON *condition = command->child->next;
        char *conditionType = condition->string;
        //printf("conditionType = %s", conditionType);
        if (strcmp(conditionType, "actions") == 0){
            return parseRuleForActionList(condition, myrule);
        }
    }
    return false;
}



/***************************************************/
/* Rule */
/***************************************************/

RuleType parseRuleTypeAction(char *rule){
    //printf("RuleParser:: #isRuleTypeIFAction ");
    cJSON *rule_json = cJSON_Parse(rule);
    if (rule_json == NULL)
    {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL)
        {
            printf("RuleParser:: Error before: %s\n", error_ptr);
        }
        cJSON_Delete(rule_json);
        return UNKNOWN_RULE;
    }
    const cJSON *action = NULL;
    const cJSON *actions = cJSON_GetObjectItemCaseSensitive(rule_json, "actions");
    cJSON_ArrayForEach(action, actions)
    {
        char *actionType = action->child->string;
        //printf("action key: %s", actionType);
        RuleType rt = getRuleType(actionType);
        cJSON_Delete(rule_json);
        return rt;
    }
    cJSON_Delete(rule_json);
    return UNKNOWN_RULE;
}

bool parseRuleConditionIF(char *rule, Rule *myRule){
    //printf("RuleParser:: #parseRuleConditionIF ");
    cJSON *rule_json = cJSON_Parse(rule);
    if (rule_json == NULL)
    {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL)
        {
            printf("RuleParser:: Error before: %s\n", error_ptr);
        }
        cJSON_Delete(rule_json);
        return false;
    }

    const cJSON *ruleID = cJSON_GetObjectItemCaseSensitive(rule_json, "ruleID");
    if (cJSON_IsString(ruleID) && (ruleID->valuestring != NULL)){
        //printf("ruleID: \"%s\"\n", ruleID->valuestring);
        myRule->ruleID = (char*) malloc(strlen(ruleID->valuestring) + 1);
        memcpy(myRule->ruleID, ruleID->valuestring, strlen(ruleID->valuestring));
        myRule->ruleID[strlen(ruleID->valuestring)] = '\0';
    }else{
        cJSON_Delete(rule_json);
        return false;
    }

    const cJSON *action = NULL;
    const cJSON *actions = cJSON_GetObjectItemCaseSensitive(rule_json, "actions");
    cJSON_ArrayForEach(action, actions)
    {
        const cJSON *trigger = cJSON_GetObjectItem(action, "if");
        if(parseRuleForTrigger(trigger, myRule) && parseRuleForAction(trigger, myRule, IF)){
            cJSON_Delete(rule_json);
            return true;
        }
        break;
    }
    cJSON_Delete(rule_json);
    return false;
}

bool parseRuleConditionEVERY(char *rule, Rule *myRule){
    //printf("RuleParser:: #parseRuleConditionEVERY ");
    cJSON *rule_json = cJSON_Parse(rule);
    if (rule_json == NULL)
    {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL)
        {
            printf("RuleParser:: Error before: %s\n", error_ptr);
        }
        cJSON_Delete(rule_json);
        return false;
    }

    const cJSON *ruleID = cJSON_GetObjectItemCaseSensitive(rule_json, "ruleID");
    if (cJSON_IsString(ruleID) && (ruleID->valuestring != NULL)){
        //printf("ruleID: \"%s\"\n", ruleID->valuestring);
        myRule->ruleID = (char*) malloc(strlen(ruleID->valuestring) + 1);
        memcpy(myRule->ruleID, ruleID->valuestring, strlen(ruleID->valuestring));
        myRule->ruleID[strlen(ruleID->valuestring)] = '\0';
    }else{
        cJSON_Delete(rule_json);
        return false;
    }

    const cJSON *action = NULL;
    const cJSON *actions = cJSON_GetObjectItemCaseSensitive(rule_json, "actions");
    cJSON_ArrayForEach(action, actions)
    {
        const cJSON *trigger = cJSON_GetObjectItem(action, "every");
        if(parseRuleForTimeTrigger(trigger, myRule) && parseRuleForAction(trigger, myRule, EVERY)){
            /*create dummy deviceID for trigger*/
            myRule->trigger->deviceID = "clock";
            myRule->trigger->valueType = TEMPORAL;
            cJSON_Delete(rule_json);
            return true;
        }
        break;
    }
    cJSON_Delete(rule_json);
    return false;
}

bool parseRule(char *rule, RuleType type, Rule *myRule){
    myRule->ruleType = type;
    if(type == IF){
        return parseRuleConditionIF(rule, myRule);
    } else if(type == EVERY) {
        return parseRuleConditionEVERY(rule, myRule);
    } else{
        return false;
    }
}


/***************************************************/
/* Device Event */
/***************************************************/

bool parseDeviceEventData(char *event, DeviceEvent *deviceEvent){
    //printf("RuleParser:: #parseDeviceEventData ");
    //printf("Event = %s", event);
    cJSON *event_json = cJSON_Parse(event);

    if (event_json == NULL)
    {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL)
        {
            printf("RuleParser:: Error before: %s\n", error_ptr);
        }
        cJSON_Delete(event_json);
        return false;
    }

    const cJSON *deviceId = cJSON_GetObjectItemCaseSensitive(event_json, "deviceID");
    if (cJSON_IsString(deviceId) && (deviceId->valuestring != NULL)) {
        //printf("deviceId: \"%s\", length:%ld\n", deviceId->valuestring, strlen(deviceId->valuestring));
        deviceEvent->deviceID = (char*) malloc(strlen(deviceId->valuestring) + 1);
        memcpy(deviceEvent->deviceID, deviceId->valuestring, strlen(deviceId->valuestring));
        deviceEvent->deviceID[strlen(deviceId->valuestring)] = '\0';
    } else{
        cJSON_Delete(event_json);
        return false;
    }

    const cJSON *capability_json = event_json->child->next;
    if (cJSON_IsObject(capability_json) && !cJSON_IsNull(capability_json)) {
        //printf("capability: \"%s\"\n", capability_json->string);
        deviceEvent->capability = (char*) malloc(strlen(capability_json->string) + 1);
        memcpy(deviceEvent->capability, capability_json->string, strlen(capability_json->string));
        deviceEvent->capability[strlen(capability_json->string)] = '\0';
    } else{
        printf("RuleParser:: couldn't parse capability!");
        cJSON_Delete(event_json);
        return false;
    }

    const cJSON *attribute_json = capability_json->child;
    if (cJSON_IsObject(attribute_json) && !cJSON_IsNull(attribute_json)) {
        //printf("attribute: \"%s\"\n", attribute_json->string);
        deviceEvent->attribute = (char*) malloc(strlen(attribute_json->string) + 1);
        memcpy(deviceEvent->attribute, attribute_json->string, strlen(attribute_json->string));
        deviceEvent->attribute[strlen(attribute_json->string)] = '\0';
    } else{
        printf("RuleParser:: couldn't parse attribute!");
        cJSON_Delete(event_json);
        return false;
    }

    const cJSON *valueObj = cJSON_GetObjectItemCaseSensitive(attribute_json, "value");
    if(!cJSON_IsNull(valueObj)){
        if (cJSON_IsString(valueObj) && (valueObj->valuestring != NULL)) {
            deviceEvent->valueType = STRING;
            deviceEvent->valueString = (char*) malloc(strlen(valueObj->valuestring) + 1);
            memcpy(deviceEvent->valueString, valueObj->valuestring, strlen(valueObj->valuestring));
            deviceEvent->valueString[strlen(valueObj->valuestring)] = '\0';
        } else if (cJSON_IsNumber(valueObj)){
            //printf("RuleParser:: int=%d, double=%lf, float=%f",valueObj->valueint, valueObj->valuedouble, (float)valueObj->valuedouble);
            deviceEvent->valueType = NUMBER;
            deviceEvent->value = (float)valueObj->valuedouble;
            deviceEvent->valueString = NULL;
        } else{
            printf("RuleParser:: Unknown Event Value type!");
            cJSON_Delete(event_json);
            return false;
        }
    } else{
        cJSON_Delete(event_json);
        return false;
    }

    const cJSON *unitObj = cJSON_GetObjectItemCaseSensitive(attribute_json, "unit");
    if (!cJSON_IsNull(unitObj) && cJSON_IsString(unitObj) && (unitObj->valuestring != NULL))
    {
        //printf("unit: \"%s\"\n", unitObj->valuestring);
        deviceEvent->unit = (char*) malloc(strlen(unitObj->valuestring) + 1);
        memcpy(deviceEvent->unit, unitObj->valuestring, strlen(unitObj->valuestring));
        deviceEvent->unit[strlen(unitObj->valuestring)] = '\0';
    }

    const cJSON *timestampObj = cJSON_GetObjectItemCaseSensitive(attribute_json, "timestamp");
    if (!cJSON_IsNull(timestampObj) && cJSON_IsString(timestampObj) && (timestampObj->valuestring != NULL))
    {
        //printf("timestamp: \"%s\"\n", timestampObj->valuestring);
        deviceEvent->timestamp = (char*) malloc(strlen(timestampObj->valuestring) + 1);
        memcpy(deviceEvent->timestamp, timestampObj->valuestring, strlen(timestampObj->valuestring));
        deviceEvent->timestamp[strlen(timestampObj->valuestring)] = '\0';
    } else{
        deviceEvent->timestamp = NULL;
        //cJSON_Delete(event_json);
        //return false;
    }

    cJSON_Delete(event_json);
    return true;
}
