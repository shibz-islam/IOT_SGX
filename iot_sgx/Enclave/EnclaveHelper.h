//
// Created by shihab on 9/11/19.
//

#ifndef IOTENCLAVE_ENCLAVEHELPER_H
#define IOTENCLAVE_ENCLAVEHELPER_H

#include "Enclave.h"
#include "Enclave_t.h"
#include "string"
#include "vector"

enum TimeReference {Now, Midnight, Sunrise, Noon, Sunset};
enum TimeUnit {Second, Minute, Hour, Day, Week, Month, Year};
enum ValueType {string, integer, number};

char* enum_to_string(TimeReference type);
int getTimeMinute(int h, int m);
std::vector<std::string> split(std::string s, std::string delimiter);

class CompareTime {
public:
    bool operator()(TimeRule& t1, TimeRule& t2) // t2 has highest prio than t1 if t2 is earlier than t1
    {
        if (t2.hour < t1.hour) return true;
        if (t2.hour == t1.hour && t2.min <= t1.min) return true;
        return false;
    }
};

#endif //IOTENCLAVE_ENCLAVEHELPER_H
