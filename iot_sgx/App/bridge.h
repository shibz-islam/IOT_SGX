//
// Created by shihab on 3/24/19.
//
#include <string>
#include <vector>
#include "Sensor.h"

#ifndef PYTHONEMBEDDINGTEST_BRIDGE_H
#define PYTHONEMBEDDINGTEST_BRIDGE_H

std::vector<Sensor*> connect(std::string fileName, std::string funcName);
char* encode_string(std::string value);


#endif //PYTHONEMBEDDINGTEST_BRIDGE_H
