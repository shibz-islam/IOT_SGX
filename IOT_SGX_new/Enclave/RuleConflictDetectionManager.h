//
// Created by shihab on 11/19/20.
//

#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include "EnclaveHelper.h"

#ifndef IOT_SGX_NEW_RULECONFLICTDETECTIONMANAGER_H
#define IOT_SGX_NEW_RULECONFLICTDETECTIONMANAGER_H

typedef std::pair<float, float> RangePair;
typedef std::pair<std::string, std::string> KeyPair;
typedef std::multimap<KeyPair, std::string > GraphEdgeMap;
typedef std::multimap<std::string, std::string> GraphNodeMap;

bool initGraph();
void updateGraph(Rule *edge);

bool detectRuleConflicts(Rule *edge);


#endif //IOT_SGX_NEW_RULECONFLICTDETECTIONMANAGER_H
