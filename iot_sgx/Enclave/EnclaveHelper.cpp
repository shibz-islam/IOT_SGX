//
// Created by shihab on 9/11/19.
//

#include "EnclaveHelper.h"
#include <stdio.h> /* vsnprintf */
#include <string.h>

#include "Enclave.h"
#include "Enclave_t.h"

char* enum_to_string(TimeReference type) {
    switch(type) {
        case Now:
            return "Now";
        case Midnight:
            return "Midnight";
        case Sunrise:
            return "Sunrise";
        case Noon:
            return "Noon";
        case Sunset:
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
