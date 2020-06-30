//
// Created by shihab on 6/2/20.
//
#include "RuleParser.h"



bool parseOperandDevice(cJSON *condition, DeviceEvent *event){
    const cJSON *capability = cJSON_GetObjectItem(condition, "capability");
    if (cJSON_IsString(capability) && (capability->valuestring != NULL))
    {
        //printf("capability: \"%s\"\n", capability->valuestring);
        if (strcmp(capability->valuestring, event->capability.c_str()) == 0){
            const cJSON *attribute = cJSON_GetObjectItem(condition, "attribute");
            if (cJSON_IsString(attribute) && (attribute->valuestring != NULL))
            {
                printf("attribute: \"%s\"\n", attribute->valuestring);
                if(strcmp(attribute->valuestring, event->attribute.c_str()) == 0){
                    return true;
                }
            }

        }
    }
    return false;
}

std::string parseConditionValue(const cJSON *condition){
    char *valueType = condition->child->string;
    //printf("value key: \"%s\"\n", valueType);

    const cJSON *value = NULL;
    if (strcmp(valueType, "string") == 0){
        value = cJSON_GetObjectItemCaseSensitive(condition, "string");
        if (cJSON_IsString(value) && (value->valuestring != NULL))
        {
            //printf("value: \"%s\"\n", value->valuestring);
            return std::string(value->valuestring);
        }
    }
    else if (strcmp(valueType, "integer") == 0){
        value = cJSON_GetObjectItemCaseSensitive(condition, "integer");
        if (cJSON_IsNumber(value))
        {
            //printf("value: \"%d\"\n", value->valueint);
            return std::to_string(value->valueint);
        }
    }
    else if (strcmp(valueType, "number") == 0){
        value = cJSON_GetObjectItemCaseSensitive(condition, "number");
        if (cJSON_IsNumber(value))
        {
            //printf("value: \"%f\"\n", value->valuedouble);
            return std::to_string(value->valuedouble);
        }
    }
    else {
        printf("Unknown Condition Value ");
        return NULL;
    }
}

bool parseCommandIfForRuleEvent(const cJSON *command, DeviceEvent *event){
    const cJSON *condition = command->child;
    char *conditionType = condition->string;

    if (strcmp(conditionType, "equals") == 0){
        //printf("*** equals ");
        const cJSON *conditionLeft = cJSON_GetObjectItemCaseSensitive(condition, "left");
        if (parseOperandDevice(conditionLeft->child, event)){
            const cJSON *conditionRight = cJSON_GetObjectItemCaseSensitive(condition, "right");
            std::string value = parseConditionValue(conditionRight);
            printf("Event value=%s, Rule value=%s\n", event->value.c_str(), value.c_str());
            if (strcmp(value.c_str(), event->value.c_str()) == 0)
                return true;
        }
    }
    else if (strcmp(conditionType, "between") == 0) {
        //printf("*** between\n");
        const cJSON *conditionBetween = cJSON_GetObjectItemCaseSensitive(condition, "value");
        if (parseOperandDevice(conditionBetween->child, event)){
            const cJSON *conditionStart = cJSON_GetObjectItemCaseSensitive(condition, "start");
            std::string valueStart = parseConditionValue(conditionStart);
            const cJSON *conditionEnd = cJSON_GetObjectItemCaseSensitive(condition, "end");
            std::string valueEnd = parseConditionValue(conditionEnd);
            if ((std::stod(event->value.c_str()) > std::stod(valueStart.c_str())) && (std::stod(event->value.c_str()) < std::stod(valueEnd.c_str())))
                return true;
        }
    }
    else{
        if(strcmp(conditionType, "greater_than") == 0 || strcmp(conditionType, "greater_than_or_equals") == 0 || strcmp(conditionType, "less_than") == 0 || strcmp(conditionType, "less_than_or_equals") == 0 )
        {
            //printf("*** others ");
            const cJSON *conditionRight = cJSON_GetObjectItemCaseSensitive(condition, "right");
            if (parseOperandDevice(conditionRight->child, event)){
                const cJSON *conditionLeft = cJSON_GetObjectItemCaseSensitive(condition, "left");
                std::string value = parseConditionValue(conditionLeft);
                if (strcmp(conditionType, "greater_than") == 0){
                    return (std::stod(event->value.c_str()) >= std::stod(value.c_str()));;
                }
                else if (strcmp(conditionType, "greater_than_or_equals") == 0){
                    return (std::stod(event->value.c_str()) >= std::stod(value.c_str()));
                }
                else if (strcmp(conditionType, "less_than") == 0){
                    return (std::stod(event->value.c_str()) < std::stod(value.c_str()));
                }
                else if (strcmp(conditionType, "less_than_or_equals") == 0){
                    return (std::stod(event->value.c_str()) <= std::stod(value.c_str()));
                }
            } else{
                printf("failed parseOperandDevice ");
            }
        }
        else{
            printf("Error: Unknown Condition Type ");
        }
    }
    return false;

//    while (condition){
//        condition = condition->next;
//    }
}

std::vector<char*> parseActionCommandsList(const cJSON *commands){
    const cJSON *command = NULL;
    std::vector<char*> commandVector;
    cJSON_ArrayForEach(command, commands)
    {
        char *commandType = command->child->string;
        //printf("command key: \"%s\"\n", commandType);
        if (strcmp(commandType, "command") == 0){
            const cJSON *commandJson = cJSON_GetObjectItem(command, "command");
            char *str = cJSON_Print(commandJson);
            if (str != NULL)
            {
                commandVector.push_back(str);
                //printf("Command Json: %s\n", str);
            }
        }
    }
    return commandVector;
}

std::vector<char*> parseCommandIfForRuleCommand(const cJSON *command, bool isSatisfied){
    const cJSON *condition = command->child;
    std::vector<char*> ruleCommandsVector;
    while (condition){
        char *conditionType = condition->string;
        if(isSatisfied){
            if (strcmp(conditionType, "then") == 0){
                printf("***then ");
                ruleCommandsVector = parseActionCommandsList(condition);
//                for (int i = 0; i < ruleCommandsVector.size(); ++i) {
//                    printf("Command Json: %s\n", ruleCommandsVector[i]);
//                }
                break;
            }
        }
        else{
            if (strcmp(conditionType, "else") == 0){
                printf("***else ");
                ruleCommandsVector = parseActionCommandsList(condition);
//                for (int i = 0; i < ruleCommandsVector.size(); ++i) {
//                    printf("IF-Command Json: %s\n", ruleCommandsVector[i]);
//                }
                break;
            }
        }
        condition = condition->next;
    }
    return ruleCommandsVector;
}

std::vector<char*> parseCommandEveryForRuleCommand(const cJSON *command){
    const cJSON *condition = command->child;
    std::vector<char*> ruleCommandsVector;
    while (condition){
        char *conditionType = condition->string;
        if (strcmp(conditionType, "actions") == 0){
            printf("***actions");
            ruleCommandsVector = parseActionCommandsList(condition);
            for (int i = 0; i < ruleCommandsVector.size(); ++i) {
                printf("Every-Command Json: %s\n", ruleCommandsVector[i]);
            }
            break;
        }
        condition = condition->next;
    }
    return ruleCommandsVector;
}


bool parseConditionTimeValue(const cJSON *obj, RuleEvent *event){
    const cJSON *valueObj = cJSON_GetObjectItem(obj, "value");
    const cJSON *value = cJSON_GetObjectItem(valueObj, "integer");
    if (cJSON_IsNumber(value))
    {
        printf("value: \"%d\"\n", value->valueint);
        event->value = (char*)std::to_string(value->valueint).c_str();
        event->valueType = "integer";
        const cJSON *unitObj = cJSON_GetObjectItem(obj, "unit");
        if (cJSON_IsString(unitObj))
        {
            printf("unit: \"%s\"\n", unitObj->valuestring);
            event->unit = unitObj->valuestring;
            return true;
        }
    }
    return false;
}

bool parseCommandEveryForRuleEvent(const cJSON *command, RuleEvent *event){
    const cJSON *condition = command->child;
    while (condition){
        char *conditionType = condition->string;
        if (strcmp(conditionType, "specific") == 0){
            printf("***specific\n");
            event->capability = "specific";
            const cJSON *reference = cJSON_GetObjectItem(command, "reference");
            if (cJSON_IsString(reference))
                event->attribute = reference->valuestring;
            const cJSON *offset = cJSON_GetObjectItem(command, "offest");
            if (cJSON_IsObject(offset))
                return parseConditionTimeValue(offset, event);
            break;
        }
        else if (strcmp(conditionType, "interval") == 0){
            printf("***interval");
            event->capability = "interval";
            event->attribute = "Now";
            return parseConditionTimeValue(command, event);
        }
        condition = condition->next;
    }
    return false;
}

bool parseCommandSleepForRuleEvent(const cJSON *command, RuleEvent *event) {
    event->capability = "sleep";
    event->attribute = "duration";
    const cJSON *duration = cJSON_GetObjectItem(command, "duration");
    if (cJSON_IsObject(duration))
        return parseConditionTimeValue(duration, event);
    return false;
}

/***************************************************/
/***************************************************/
/***************************************************/

RuleType parseRuleTypeAction(char *rule){
    printf("#isRuleTypeIFAction ");
    cJSON *rule_json = cJSON_Parse(rule);
    if (rule_json == NULL)
    {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL)
        {
            printf("Error before: %s\n", error_ptr);
        }
        cJSON_Delete(rule_json);
        return RuleType_UNKNOWN;
    }
    const cJSON *action = NULL;
    const cJSON *actions = cJSON_GetObjectItemCaseSensitive(rule_json, "actions");
    cJSON_ArrayForEach(action, actions)
    {
        char *actionType = action->child->string;
        //printf("action key: \"%s\"\n", actionType);
        RuleType rt = getRuleType(actionType);
        cJSON_Delete(rule_json);
        return rt;
    }
    cJSON_Delete(rule_json);
    return RuleType_UNKNOWN;
}

bool parseRuleForDeviceID(char *rule, std::vector<std::string> &devicesVector){
    printf("#parseRuleForDeviceID ");
    cJSON *rule_json = cJSON_Parse(rule);
    const cJSON *action = NULL;
    const cJSON *actions = cJSON_GetObjectItemCaseSensitive(rule_json, "actions");
    cJSON_ArrayForEach(action, actions)
    {
        char *actionType = action->child->string;
        //printf("action key: \"%s\"\n", actionType);

        const cJSON *command = NULL;
        if (strcmp(actionType, "if") == 0){
            //printf("***if\n");
            command = cJSON_GetObjectItem(action, "if");
            const cJSON *condition = command->child;
            const cJSON *deviceObj = NULL;
            char *conditionType = condition->string;
            if (strcmp(conditionType, "equals") == 0){
                //printf("*** equals\n");
                deviceObj = cJSON_GetObjectItemCaseSensitive(condition, "left");
            }
            else if (strcmp(conditionType, "between") == 0){
                //printf("*** between\n");
                deviceObj = cJSON_GetObjectItemCaseSensitive(condition, "value");
            }
            else if(strcmp(conditionType, "greater_than") == 0 || strcmp(conditionType, "greater_than_or_equals") == 0 || strcmp(conditionType, "less_than") == 0 || strcmp(conditionType, "less_than_or_equals") == 0 ) {
                //printf("*** others\n");
                deviceObj = cJSON_GetObjectItemCaseSensitive(condition, "right");
            }
            else{
                printf("Unknown conditionType ");
                cJSON_Delete(rule_json);
                return false;
            }

            if (!cJSON_IsNull(deviceObj)){
                //printf("here...\n");
                const cJSON *deviceList = cJSON_GetObjectItem(deviceObj, "device")->child;
                if (cJSON_IsArray(deviceList)){
                    for (int i = 0 ; i < cJSON_GetArraySize(deviceList) ; i++){
                        printf("Device id: %s\n",cJSON_GetArrayItem(deviceList, i)->valuestring);
                        devicesVector.push_back(std::string(cJSON_GetArrayItem(deviceList, i)->valuestring));
                    }
                }
            } else{
                printf("Unknown object ");
                cJSON_Delete(rule_json);
                return false;
            }
        }
        else{
            printf("Unknown Command ");
            cJSON_Delete(rule_json);
            return false;
        }
    }
    cJSON_Delete(rule_json);
    return true;
}

bool parseDeviceEventData(char *event, DeviceEvent *deviceEvent){
    printf("#parseDeviceEventData ");
    cJSON *event_json = cJSON_Parse(event);
    bool isSuccess = true;
    if (event_json == NULL)
    {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL)
        {
            printf("Error before: %s\n", error_ptr);
        }
        return false;
    }

    const cJSON *deviceId = cJSON_GetObjectItemCaseSensitive(event_json, "deviceID");
    if (cJSON_IsString(deviceId) && (deviceId->valuestring != NULL))
    {
        //printf("deviceId: \"%s\", length:%ld\n", deviceId->valuestring, strlen(deviceId->valuestring));
        deviceEvent->deviceId = std::string(deviceId->valuestring);
    }

    const cJSON *deviceEventObj = NULL;
    const cJSON *deviceEvents = cJSON_GetObjectItemCaseSensitive(event_json, "deviceEvents");
    cJSON_ArrayForEach(deviceEventObj, deviceEvents)
    {
        const cJSON *capability = cJSON_GetObjectItemCaseSensitive(deviceEventObj, "capability");
        if (cJSON_IsString(capability) && (capability->valuestring != NULL))
        {
            //printf("capability: \"%s\"\n", capability->valuestring);
            deviceEvent->capability = std::string(capability->valuestring);
        }

        const cJSON *attribute = cJSON_GetObjectItemCaseSensitive(deviceEventObj, "attribute");
        if (cJSON_IsString(attribute) && (attribute->valuestring != NULL))
        {
            //printf("attribute: \"%s\"\n", attribute->valuestring);
            deviceEvent->attribute = std::string(attribute->valuestring);
        }

        const cJSON *valueObj = cJSON_GetObjectItemCaseSensitive(deviceEventObj, "value");
        if (!cJSON_IsNull(valueObj))
        {
            char *valueType = valueObj->child->string;
            //printf("valueType: \"%s\"\n", valueType);
            deviceEvent->valueType = std::string(valueType);

            const cJSON *value = NULL;
            if (strcmp(valueType, "string") == 0){
                value = cJSON_GetObjectItemCaseSensitive(valueObj, "string");
                if (cJSON_IsString(value) && (value->valuestring != NULL))
                {
                    //printf("value: \"%s\"\n", value->valuestring);
                    deviceEvent->value = std::string(value->valuestring);
                }
            }
            else if (strcmp(valueType, "integer") == 0){
                value = cJSON_GetObjectItemCaseSensitive(valueObj, "integer");
                if (cJSON_IsNumber(value))
                {
                    //printf("value: \"%d\"\n", value->valueint);
                    deviceEvent->value = std::to_string(value->valueint);

                }
            }
            else if (strcmp(valueType, "number") == 0){
                value = cJSON_GetObjectItemCaseSensitive(valueObj, "number");
                if (cJSON_IsNumber(value))
                {
                    //printf("value: \"%f\"\n", value->valuedouble);
                    deviceEvent->value = std::to_string(value->valuedouble);
                }
            } else{
                cJSON_Delete(event_json);
                printf("Unknown value type...");
                isSuccess = false;
            }
        }else{
            cJSON_Delete(event_json);
            isSuccess = false;
        }

        const cJSON *unit = cJSON_GetObjectItemCaseSensitive(deviceEventObj, "unit");
        if (cJSON_IsString(unit) && (unit->valuestring != NULL))
        {
            //printf("unit: \"%s\"\n", unit->valuestring);
            deviceEvent->unit = std::string(unit->valuestring);
        }
    }
    cJSON_Delete(event_json);
    return isSuccess;
}


/*
 * Check if Rule satisfies Device Event:
 * IF_Command: check Condition with Event
 * EVERY_Command:
 * SLEEP_Command:
 */
bool checkRuleSatisfiabilityWithDeviceEvent(char *rule, DeviceEvent *event){
    printf("#checkRuleSatisfiabilityWithDeviceEvent ");
    printf("\nRule= %s\n", rule);
    //printf("\n** Device Event: id=%s, cap=%s, attr=%s, val=%s, valType=%s, unit=%s\n", event->deviceId, event->capability, event->attribute, event->value, event->valueType, event->unit);
    cJSON *rule_json = cJSON_Parse(rule);
    if (rule_json == NULL)
    {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL)
        {
            printf("Error before: %s\n", error_ptr);
        }
        cJSON_Delete(rule_json);
        return false;
    }

    //const cJSON *ruleID = NULL;
    //ruleID = cJSON_GetObjectItemCaseSensitive(rule_json, "ruleID");
    //if (cJSON_IsString(ruleID) && (ruleID->valuestring != NULL))
        //printf("ruleID: \"%s\"\n", ruleID->valuestring);

    const cJSON *actions = NULL;
    const cJSON *action = NULL;
    actions = cJSON_GetObjectItemCaseSensitive(rule_json, "actions");
    cJSON_ArrayForEach(action, actions)
    {
        char *actionType = action->child->string;
        //printf("action key: \"%s\"\n", actionType);

        const cJSON *command = NULL;
        if (strcmp(actionType, "if") == 0){
            //printf("***if\n");
            command = cJSON_GetObjectItem(action, "if");
            //std::string temp(cJSON_Print(command));
            bool isSatisfied = parseCommandIfForRuleEvent(command, event);
            if(isSatisfied){
                printf("Rule is satisfied ");
            } else{
                printf("Rule not satisfied ");
            }
            cJSON_Delete(rule_json);
            return isSatisfied;
        }
        else if (strcmp(actionType, "every") == 0){
            printf("***every ");

        }
        else if (strcmp(actionType, "sleep") == 0){

        }
        else{
            printf("Unknown Command ");
        }
    }
    cJSON_Delete(rule_json);
    return false;
}


bool parseRuleForDeviceCommands(char *rule, std::vector<DeviceCommand*> &deviceCommandsVector, bool isSatisfied){
    printf("#parseRuleForDeviceCommands ");
    std::vector<char*> ruleCommandsVector;
    cJSON *rule_json = cJSON_Parse(rule);
    if (rule_json == NULL)
    {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL)
        {
            printf("Error before: %s\n", error_ptr);
        }
        return false;
    }
    const cJSON *actions = NULL;
    const cJSON *action = NULL;
    actions = cJSON_GetObjectItemCaseSensitive(rule_json, "actions");
    cJSON_ArrayForEach(action, actions)
    {
        char *actionType = action->child->string;
        //printf("action key: \"%s\"\n", actionType);

        const cJSON *command = NULL;
        if (strcmp(actionType, "if") == 0){
            //printf("***if\n");
            command = cJSON_GetObjectItem(action, "if");
            ruleCommandsVector = parseCommandIfForRuleCommand(command, isSatisfied);
        }
        else if (strcmp(actionType, "every") == 0){
            //printf("***every\n");
            command = cJSON_GetObjectItem(action, "every");
            ruleCommandsVector = parseCommandEveryForRuleCommand(command);
        }
        else if (strcmp(actionType, "sleep") == 0){

        }
        else{
            printf("Unknown Command... ");
        }
    }

    if(ruleCommandsVector.empty()){
        return false;
    }else{
        for (int i = 0; i < ruleCommandsVector.size(); ++i) {
            cJSON *deviceCommand = cJSON_Parse(ruleCommandsVector[i]);
            if(!cJSON_IsNull(deviceCommand)){
                cJSON *commandList = cJSON_GetObjectItemCaseSensitive(deviceCommand, "commands");
                if (!cJSON_IsNull(commandList)){
                    char *commandJsonString = cJSON_PrintUnformatted(commandList);
                    //printf("commands list: %s\n", commandJsonString);

                    cJSON *deviceList = cJSON_GetObjectItemCaseSensitive(deviceCommand, "devices");
                    if(cJSON_IsArray(deviceList)){
                        for (int j = 0 ; j < cJSON_GetArraySize(deviceList) ; j++){
                            DeviceCommand *dc = new DeviceCommand();
                            dc->deviceId = std::string(cJSON_GetArrayItem(deviceList, j)->valuestring);
                            //printf("deviceId: %s\n", dc->deviceId);
                            dc->command = std::string(commandJsonString);
                            deviceCommandsVector.push_back(dc);
                        }
                    } else{
                        printf("No array found for deviceId... ");
                    }
                }
                else {
                    printf("json parse error: commandList... ");
                    cJSON_Delete(rule_json);
                    return false;
                }
            }
            else{
                printf("json parse error: ruleCommandsVector... ");
                cJSON_Delete(rule_json);
                return false;
            }
        }
    }
    cJSON_Delete(rule_json);
    ruleCommandsVector.clear();
    return true;
}

bool parseRuleForTimeInfo(char *rule, std::vector<TimeRule> &timeRules){
    printf("#parseRuleForTimeInfo... ");
    cJSON *rule_json = cJSON_Parse(rule);

    const cJSON *ruleID = NULL;
    ruleID = cJSON_GetObjectItemCaseSensitive(rule_json, "ruleID");
    if (cJSON_IsString(ruleID) && (ruleID->valuestring != NULL))
        printf("ruleID: \"%s\"\n", ruleID->valuestring);

    const cJSON *action = NULL;
    const cJSON *actions = cJSON_GetObjectItemCaseSensitive(rule_json, "actions");
    cJSON_ArrayForEach(action, actions)
    {
        char *actionType = action->child->string;
        //printf("action key: \"%s\"\n", actionType);

        if (strcmp(actionType, "every") == 0){
            TimeRule tr;
            tr.ruleID = std::string(ruleID->valuestring);
            const cJSON *condition = cJSON_GetObjectItem(action, "every")->child;

            char *conditionType = condition->string;
            //printf("conditionType key: \"%s\"\n", conditionType);
            if (strcmp(conditionType, "specific") == 0){
                printf("***specific ");
                const cJSON *reference = cJSON_GetObjectItem(condition, "reference");
                if (cJSON_IsString(reference)){
                    tr.timeReference = std::string(reference->valuestring);
                    //printf("%s\n", reference->valuestring);
                }else{
                    printf("Unknown reference... ");
                    cJSON_Delete(rule_json);
                    return false;
                }
                const cJSON *offset = cJSON_GetObjectItem(condition, "offset");
                if (cJSON_IsObject(offset)){
                    const cJSON *valueObj = cJSON_GetObjectItem(offset, "value");
                    const cJSON *value = cJSON_GetObjectItem(valueObj, "integer");
                    if (cJSON_IsNumber(value))
                        tr.timeOffset = value->valueint;
                    const cJSON *unitObj = cJSON_GetObjectItem(offset, "unit");
                    if (cJSON_IsString(unitObj))
                        tr.unit = std::string(unitObj->valuestring);
                }else{
                    printf("Unknown offset... ");
                    cJSON_Delete(rule_json);
                    return false;
                }
            }
            else if (strcmp(conditionType, "interval") == 0){
                printf("***interval ");
                tr.timeReference = enum_to_string(NOW);
                const cJSON *valueObj = cJSON_GetObjectItem(condition, "value");
                const cJSON *value = cJSON_GetObjectItem(valueObj, "integer");
                if (cJSON_IsNumber(value))
                    tr.timeOffset = value->valueint;
                const cJSON *unitObj = cJSON_GetObjectItem(condition, "unit");
                if (cJSON_IsString(unitObj))
                    tr.unit = std::string(unitObj->valuestring);
            }
            else{
                printf("Unknown condition... ");
                cJSON_Delete(rule_json);
                return false;
            }
            timeRules.push_back(tr);
        }
        else{
            printf("Unknown Command... ");
            cJSON_Delete(rule_json);
            return false;
        }
    }
    cJSON_Delete(rule_json);
    return true;
}

bool configureTimeString(TimeRule &timeRule){
    int hour = 0;
    if ((timeRule.timeReference.compare(enum_to_string(NOW))) == 0){
        hour = 9; //TODO: get current time SGX
    }else if ((timeRule.timeReference.compare(enum_to_string(MIDNIGHT))) == 0){
        hour = 00;
    }else if ((timeRule.timeReference.compare(enum_to_string(SUNRISE))) == 0){
        hour = 06;
    }else if ((timeRule.timeReference.compare(enum_to_string(NOON))) == 0){
        hour = 12;
    }else if ((timeRule.timeReference.compare(enum_to_string(SUNSET))) == 0){
        hour = 18;
    }else{
        printf("Unknown time reference... ");
        return false;
    }

    int hourOffset = 0, minOffset = 0;
    if(strcmp(timeRule.unit.c_str(), "Minute") == 0){
        hourOffset = timeRule.timeOffset / 60;
        minOffset = timeRule.timeOffset % 60;
        //printf("%d, %d, %d\n", hour, hourOffset, minOffset);
        hourOffset = minOffset >= 0 ? hourOffset : hourOffset-1;
        minOffset = minOffset >= 0 ? minOffset : 60+minOffset;

    } else if(strcmp(timeRule.unit.c_str(), "Hour") == 0){
        hourOffset = timeRule.timeOffset;
    } else{
        printf("Unknown time unit...");
        return false;
    }
    hour = hour + hourOffset;
    if (hour < 0)
        hour = hour + 24;
    printf("time String: %d:%d\n", hour, minOffset);
    timeRule.hour = hour;
    timeRule.min = minOffset;

    return true;
}