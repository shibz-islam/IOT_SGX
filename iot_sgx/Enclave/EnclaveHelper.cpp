//
// Created by shihab on 9/11/19.
//

#include "EnclaveHelper.h"
#include <stdio.h> /* vsnprintf */
#include <string.h>
#include <ctype.h>
#include "Enclave.h"
#include "Enclave_t.h"

std::string mqttTopicForData = "topic/utd/iot/server/data/";

void toLowerCase(char *str){
    int i, s = strlen(str);
    for (i = 0; i < s; i++)
        str[i] = tolower(str[i]);
}

RuleType getRuleType(char *key){
    toLowerCase(key);
    if(strcmp(key, "if")==0){
        return IF;
    }else if(strcmp(key, "every")==0){
        return EVERY;
    }
    else if(strcmp(key, "sleep")==0){
        return SLEEP;
    } else{
        return RuleType_UNKNOWN;
    }
}

ValueType getValueType(char *key){
    toLowerCase(key);
    if(strcmp(key, "string")==0){
        return STRING;
    }else if(strcmp(key, "integer")==0){
        return INTEGER;
    }
    else if(strcmp(key, "number")==0){
        return NUMBER;
    } else{
        return ValueType_UNKNOWN;
    }
}

TimeReference getTimeReference(char *key){
    toLowerCase(key);
    if(strcmp(key, "now")==0){
        return NOW;
    }else if(strcmp(key, "midnight")==0){
        return MIDNIGHT;
    }else if(strcmp(key, "sunrise")==0){
        return SUNRISE;
    }else if(strcmp(key, "noon")==0){
        return NOON;
    }else if(strcmp(key, "sunset")==0){
        return SUNSET;
    }else{
        return TimeReference_UNKNOWN;
    }
}

TimeUnit getTimeUnit(char *key){
    toLowerCase(key);
    if(strcmp(key, "second")==0){
        return SECOND;
    }else if(strcmp(key, "minute")==0){
        return MINUTE;
    }else if(strcmp(key, "hour")==0){
        return HOUR;
    }else if(strcmp(key, "day")==0){
        return DAY;
    }else if(strcmp(key, "week")==0){
        return WEEK;
    }else if(strcmp(key, "month")==0){
        return MONTH;
    }else if(strcmp(key, "year")==0){
        return YEAR;
    }else{
        return TimeUnit_UNKNOWN;
    }
}

char* enum_to_string(TimeReference type) {
    switch(type) {
        case NOW:
            return "Now";
        case MIDNIGHT:
            return "Midnight";
        case SUNRISE:
            return "Sunrise";
        case NOON:
            return "Noon";
        case SUNSET:
            return "Sunset";
        default:
            return "Invalid";
    }
}

std::vector<std::string> split(std::string s, std::string delimiter){
    std::vector<std::string> list;
    size_t pos = 0;
    std::string token;
    while ((pos = s.find(delimiter)) != std::string::npos) {
        token = s.substr(0, pos);
        list.push_back(token);
        s.erase(0, pos + delimiter.length());
    }
    list.push_back(s);
    return list;
}

int getTimeMinute(int h, int m){
    return h*60+m;
}

std::string mqttTopicName(){
    return mqttTopicForData;
}