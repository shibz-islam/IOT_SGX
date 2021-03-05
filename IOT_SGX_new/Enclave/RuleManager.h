//
// Created by shihab on 3/5/20.
//

#include <string>
#include <map>
#include <vector>
#include <queue>
#include "LRUCache.h"
#include "EnclaveHelper.h"

#ifndef IOTENCLAVE_RULEMANAGER_H
#define IOTENCLAVE_RULEMANAGER_H

void setupEnclave();

bool startParsingRule(char *ruleString, Rule *myRule);
bool startParsingDeviceEvent(char *event, DeviceEvent *myEvent);


bool startRuleAutomation(DeviceEvent *myEvent);

bool sendRuleCommands(Rule *myRule);

bool startRuleConflictDetection(Rule *myRule);



#endif //IOTENCLAVE_RULEMANAGER_H
