//
// Created by shihab on 9/11/19.
//

#ifndef IOTENCLAVE_ENCLAVEHELPER_H
#define IOTENCLAVE_ENCLAVEHELPER_H

#include "Enclave.h"
#include "Enclave_t.h"
#include <string>
#include <vector>

extern bool isEncryptionEnabled;

/* Methods*/
RuleType getRuleType(char *key);
ValueType getValueType(char *key);
OperatorType getOperatorType (char *key);
TimeReferenceType getTimeReferenceType (char *key);
TimeUnitType getTimeUnitType (char *key);

std::string getTimeString(TimeReferenceType timeReferenceType, int timeOffset, TimeUnitType timeUnitType);
int getTimeSecond(int h, int m);
int getTimeMinute(int h, int m);

std::string mqttTopicName();

bool initRule(Rule **myrule);
bool deleteRule(Rule **myrule);
bool deleteDeviceEvent(DeviceEvent **myEvent);
bool deleteMessage(Message **msg);

void printRuleInfo(Rule *myRule);
void printDeviceEventInfo(DeviceEvent *myEvent);
void printConflictType(ConflictType conflict);

void check_error_code(sgx_status_t stat);

#endif //IOTENCLAVE_ENCLAVEHELPER_H
