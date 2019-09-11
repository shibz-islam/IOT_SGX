//
// Created by shihab on 6/5/19.
//
#include <iostream>
#include <string.h>
#ifndef IOTENCLAVE_JSONPARSER_H
#define IOTENCLAVE_JSONPARSER_H

std::string make_json_from_message(struct message *ptr);
int parse_data_with_tag(char *buffer, struct message *ptr);

#endif //IOTENCLAVE_JSONPARSER_H
