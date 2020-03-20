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
    void saveRulesInCache(struct rule* newRule, int count);
    std::string getRuleFromCache(std::string device_id);
    bool isRuleExistInCache(std::string device_id);

    bool parseRule(char *msg, struct rule* newRule);
    void checkRuleSatisfiability(std::string device_id, std::map<std::string,std::string> device_info_map);

};


#endif //IOTENCLAVE_RULEMANAGER_H
