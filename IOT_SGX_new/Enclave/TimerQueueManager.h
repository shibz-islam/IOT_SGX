//
// Created by shihab on 12/10/20.
//
#include "EnclaveHelper.h"

#ifndef IOT_SGX_NEW_TIMERQUEUEMANAGER_H
#define IOT_SGX_NEW_TIMERQUEUEMANAGER_H

void initQueue();
bool addToQueue(Rule *rule);
bool resetQueue();

bool getNextTimer(TimerRule *tRule);
bool startTimerRuleHandler(char *ruleID);

#endif //IOT_SGX_NEW_TIMERQUEUEMANAGER_H
