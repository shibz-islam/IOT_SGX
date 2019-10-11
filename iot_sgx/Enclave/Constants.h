//
// Created by shihab on 10/11/19.
//

#ifndef IOTENCLAVE_CONSTANTS_H
#define IOTENCLAVE_CONSTANTS_H

const std::string Rule_ID = "ruleID";
const std::string Rule_UserID = "userID";
const std::string Rule_DeviceID = "deviceID";
const std::string Rule_Threshold = "threshold";
const std::string Rule_Operator = "operator";

enum OperatorEnum {Operator_Gt, Operator_Lt, Operator_Eq, Operator_Unknown};
enum ActionEnum {email, alert};


#endif //IOTENCLAVE_CONSTANTS_H
