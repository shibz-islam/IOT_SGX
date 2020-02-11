//
// Created by shihab on 9/11/19.
//

#include <string>

#ifndef IOTENCLAVE_RULEBASE_H
#define IOTENCLAVE_RULEBASE_H

void start_rule_base(char *msg);
void save_rule_base(char *msg);

bool parse_rule(char *msg, struct rule* newRule);

#endif //IOTENCLAVE_RULEBASE_H
