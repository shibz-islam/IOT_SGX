/*
 * Copyright (C) 2011-2018 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


/* User defined types */


#define LOOPS_PER_THREAD 500
typedef void *buffer_t;
typedef int array_t[10];

/* Enums */
enum ValueType {STRING, INTEGER, NUMBER, TEMPORAL, UNKNOWN_VALUE};
enum OperatorType { GT, LT, EQ, GTE, LTE, INVALID_OP};
enum RuleType {IF, EVERY, SLEEP, UNKNOWN_RULE};
enum DBQueryType {BY_RULE, BY_TRIGGER_DEVICE_ID, BY_TRIGGER_DEVICE_ID_ATTR, BY_TRIGGER_ACTION_DEVICE_ID, BY_ACTION_DEVICE_ID, ALL_QUERY};
enum TimeReferenceType {NOW, MIDNIGHT, SUNRISE, NOON, SUNSET, UNKNOWN_TIME_REFERENCE};
enum TimeUnitType {SECOND, MINUTE, HOUR, DAY, WEEK, MONTH, YEAR, UNKNOWN_TIME_UNIT};
enum ConflictType {SHADOW, EXECUTION, MUTUAL, DEPENDENCE, CHAIN, CHAIN_FWD, NONE};
enum PriorityType {HIGH, MID, LOW};

struct Message {
    char* text;
    char* tag;
    size_t textLength;
    size_t tagLength;
    size_t isEncrypted;

    char *address;
};


struct RuleComponent {
    char *deviceID;

    char *capability;
    char *attribute;
    enum ValueType valueType;

    // for number/string values
    char *valueString;
    float value;
    enum OperatorType operatorType;

    // for temporal values
    enum TimeReferenceType timeReferenceType;
    int timeOffset;
    enum TimeUnitType timeUnitType;
};


struct Rule {
    char *ruleID;
    enum RuleType ruleType;

    struct RuleComponent *trigger;
    struct RuleComponent *action;

    enum PriorityType priorityType;
    char *timestamp;

    char *responseCommand;
};


struct DeviceEvent {
    char *deviceID;
    char *capability;
    char *attribute;
    enum ValueType valueType;
    char *valueString;
    float value;
    char *unit;
    char *timestamp;
};


struct DatabaseElement {
    char *ruleID;
    char *deviceID;
    char *attribute;
    char *deviceIDAction;
    enum ValueType valueType;
    struct Message *data;
    enum DBQueryType queryType;
};


struct TimerRule {
    char *ruleID;
    int hour;
    int minute;
    int second;
    int duration;
};
