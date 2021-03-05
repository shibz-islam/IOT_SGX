//
// Created by shihab on 12/6/20.
//

#include <string>
#include <vector>
#include "EnclaveHelper.h"

#ifndef IOT_SGX_NEW_ENCLAVEDATABASEMANAGER_H
#define IOT_SGX_NEW_ENCLAVEDATABASEMANAGER_H

bool storeRuleInDB(char *ruleString, Rule *rule);
size_t retrieveRuleCountFromDB(char *primaryKey, char *secondaryKey, DBQueryType queryType);
bool retrieveRulesFromDB(std::vector<Rule*>&ruleset, size_t ruleCount, char *primaryKey, char *secondaryKey, DBQueryType queryType);

    #endif //IOT_SGX_NEW_ENCLAVEDATABASEMANAGER_H
