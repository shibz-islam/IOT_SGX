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


RuleType parseRuleTypeAction(char *rule);

bool parseRuleForDeviceID(char *rule, std::vector<std::string> &deviceIdVector);
bool parseDeviceEventData(char *event, DeviceEvent *deviceEvent);
bool checkRuleSatisfiabilityWithDeviceEvent(char *rule, DeviceEvent *event);
std::vector<DeviceCommand*> parseRuleForDeviceCommands(char *rule, bool isSatisfied);

bool parseRuleForTimeInfo(char *rule, std::vector<TimeRule> &timeRules);
bool configureTimeString(TimeRule &timeRule);

#endif //IOT_SGX_RULEPARSER_H
