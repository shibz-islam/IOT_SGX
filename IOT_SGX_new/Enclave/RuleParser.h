//
// Created by shihab on 6/4/20.
//

#ifndef IOT_SGX_RULEPARSER_H
#define IOT_SGX_RULEPARSER_H

#include "stdio.h"
#include "stdlib.h"
#include "string"
#include "vector"
#include "cJSON.h"
#include "Enclave.h"
#include "Enclave_t.h"
#include "EnclaveHelper.h"


RuleType parseRuleTypeAction(char *rule);
bool parseRule(char *rule, RuleType type, Rule *myRule);
bool parseDeviceEventData(char *event, DeviceEvent *deviceEvent);


#endif //IOT_SGX_RULEPARSER_H
