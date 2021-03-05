//
// Created by shihab on 6/5/19.
//
#include <iostream>
#include <string.h>
#ifndef IOTENCLAVE_JSONPARSER_H
#define IOTENCLAVE_JSONPARSER_H

std::string make_json_from_message(struct Message *ptr);
std::string make_json_encrypted_data(char *text, size_t textLength, char *tag, size_t tagLength);
bool parse_data_with_tag(char *buffer, struct Message *ptr, bool isAllocated);
bool parse_data_length_with_tag(char *buffer, struct Message *ptr);
int parse_data_with_tag_index(char *buffer, struct Message *ptr, int index);

#endif //IOTENCLAVE_JSONPARSER_H
