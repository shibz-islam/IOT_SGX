//
// Created by shihab on 10/11/19.
//

#ifndef IOTENCLAVE_CONSTANTS_H
#define IOTENCLAVE_CONSTANTS_H

const std::string RULE_ID = "ruleID";
const std::string RULE_USER_ID = "userID";
const std::string RULE_DEVICE_ID = "deviceID";
const std::string RULE_THRESHOLD = "threshold";
const std::string RULE_OPERATOR = "operator";

enum EnumOperator {OPERATOR_GT, OPERATOR_LT, OPERATOR_EQ, OPERATOR_UNKNOWN};
enum EnumAction {EMAIL, ALERT};


#endif //IOTENCLAVE_CONSTANTS_H
