//
// Created by shihab on 3/5/20.
//

#include <string>
#include <map>
#include "LRUCache.h"

#ifndef IOTENCLAVE_RULEMANAGER_H
#define IOTENCLAVE_RULEMANAGER_H

typedef std::pair<std::string,std::string> key_pair_str;


class RuleManager {
private:
    LRUCache *cache;
public:
    RuleManager();
    virtual ~RuleManager();

    void didReceiveRule(struct Rule *myRule);
    void didReceiveDeviceEvent(char *event);

    void saveRuleInCache(Rule newRule);
    std::string getCacheKeys();
    std::string getRuleWithKey(std::string key);
    bool isRuleExistInCache(std::string device_id);
};


#endif //IOTENCLAVE_RULEMANAGER_H
