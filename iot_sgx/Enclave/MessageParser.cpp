//
// Created by shihab on 9/11/19.
//
#include <stdio.h> /* vsnprintf */
#include <string.h>
#include "MessageParser.h"
#include "Enclave.h"
#include "Enclave_t.h" /* print_string */


void removeChar(char *s, int c){

    int j, n = strlen(s);
    for (int i=j=0; i<n; i++)
        if (s[i] != c)
            s[j++] = s[i];
    s[j] = '\0';
}

std::map<std::string, std::string> parse_decrypted_string(char *decMessage) {
    removeChar(decMessage, '{');
    removeChar(decMessage, '}');
    removeChar(decMessage, '"');
    removeChar(decMessage, ' ');
    removeChar(decMessage, '\'');
    printf("After removing extra characters: %s\n", decMessage);

    std::map<std::string, std::string> mmap;

    char* token;
    char* rest = decMessage;

    while ((token = strtok_r(rest, ",", &rest)))
    {
//        printf("Token: %s\n", token);
        char *token2;
        char *rest2 = token;
        int c = 0;
        std::string k,v;
        while ((token2 = strtok_r(rest2, ":", &rest2))){
            if(c%2==0)
                k = token2;
            else
                v = token2;
            c++;
        }
        mmap.insert(std::pair<std::string, std::string>(k, v));
    }
//    printf("Initial size of map = %ld\n", mmap.size());
//    for(auto it = mmap.cbegin(); it != mmap.cend(); ++it)
//    {
//        printf("Key=%s, Value=%s\n", it->first.c_str(), it->second.c_str());
//    }

    return mmap;
}

std::string device_to_string(struct device *device){
    std::string output = "{";
    std::string result = "";
    std::string deviceId = "deviceId";
    std::string deviceType = "deviceType";
    std::string data = "data";
    std::string punc = "\"";

    output += punc + deviceId + punc + ":" + punc + device->uid + punc + ",";
    output += punc + deviceType + punc + ":" + punc + device->type + punc + ",";
    output += punc + data + punc + ":" + punc + device->state + punc + ",";
    result = output.substr(0, output.size() - 1 );
    result += "}";
    printf("String from Map = %s\n", result.c_str());
    return result;

}

std::string map_to_string(std::map<std::string,std::string> mmap) {
    std::string output = "{";
    std::string result = "";
    std::string punc = "\'";

    for (auto it = mmap.cbegin(); it != mmap.cend(); it++) {

        output += punc + it->first + punc + ":" + punc + it->second + punc + ",";
    }

    result = output.substr(0, output.size() - 1 );
    result += "}";
    printf("String from Map = %s\n", result.c_str());
    return result;
}

