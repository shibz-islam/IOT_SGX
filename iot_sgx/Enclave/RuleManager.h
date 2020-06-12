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


class RuleManager {
private:
    LRUCache *cache;
    std::vector<TimeRule> vecTimerQueue;
    priority_queue<TimeRule, vector<TimeRule>, CompareTime> timerPriorityQueue;
public:
    RuleManager();
    virtual ~RuleManager();

    void didReceiveRule(struct Rule *myRule, bool isStoreInFile);
    void didReceiveDeviceEvent(char *event);
    void didReceiveRequestToCheckTimerRule(int hour, int min);
    int didReceiveRequestToCheckPendingTimerRule(int hour, int min);

    void saveRuleInCache(Rule newRule);
    std::string getCacheKeys();
    std::string getRuleWithKey(std::string key);
    bool isRuleExistInCache(std::string device_id);

    void saveRuleInQueue(TimeRule timeRule);
    void saveRuleInPriorityQueue(TimeRule timeRule);
};


#endif //IOTENCLAVE_RULEMANAGER_H
