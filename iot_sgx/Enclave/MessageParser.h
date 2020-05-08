//
// Created by shihab on 9/11/19.
//

#include <map>
#include <string>

#ifndef IOTENCLAVE_MESSAGEPARSER_H
#define IOTENCLAVE_MESSAGEPARSER_H

std::map<std::string, std::string> parse_decrypted_string(char *decMessage);
std::string device_to_string(struct device *device);
std::string map_to_string(std::map<std::string,std::string> mmap);


#endif //IOTENCLAVE_MESSAGEPARSER_H
