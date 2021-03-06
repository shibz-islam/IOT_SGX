//
// Created by shihab on 12/10/20.
//

#include "TimerQueueManager.h"
#include <queue>
#include "RuleManager.h"
#include "EnclaveDatabaseManager.h"

struct CompareTime {
    bool operator()(TimerRule const & p1, TimerRule const & p2) {
        return p1.duration < p2.duration;
    }
};

std::priority_queue<TimerRule, std::vector<TimerRule>, CompareTime> timerQueue;


/*********************************************************************/
/* Clock */
/*********************************************************************/

/*
 * Calculate the duration from current time to a specific time
 */
int getUpdatedTime(int hour, int minute, int second){
    size_t desiredTime = getTimeSecond(hour, minute);

    size_t currentTime = -1;
    int timer_duration = -1;
    ocall_get_current_time(&currentTime); /* get the current time from the REE via ocall */
    if(currentTime != -1){
        printf("TimerQueueManager:: current time=%d; desired time=%d", currentTime, desiredTime);
        if((desiredTime - currentTime) > 0 ){
            timer_duration = desiredTime - currentTime;
        }
    }
    return timer_duration;
}

/*
 * Initializes a TimerRule object and get the duration of timer from time reference, time offset, and time unit.
 */
bool initTime(TimeReferenceType timeReferenceType, int timeOffset, TimeUnitType timeUnitType, TimerRule &tr){
    int h = 0;
    switch (timeReferenceType){
        case MIDNIGHT:{
            h = 00; break;
        }
        case SUNRISE:{
            h = 06; break;
        }
        case NOON:{
            h = 12; break;
        }
        case SUNSET:{
            h = 18; break;
        }
        case NOW:
        default:{
            printf("TimerQueueManager:: invalid time reference... ");
            return false;
        }
    }

    int hourOffset = 0, minOffset = 0;
    switch (timeUnitType){
        case MINUTE:{
            hourOffset = timeOffset / 60;
            minOffset = timeOffset % 60;
            //printf("%d, %d, %d\n", hour, hourOffset, minOffset);
            hourOffset = minOffset >= 0 ? hourOffset : hourOffset-1;
            minOffset = minOffset >= 0 ? minOffset : 60+minOffset;
            break;
        }
        case HOUR:{
            hourOffset = timeOffset;
            break;
        }
        default:{
            printf("TimerQueueManager:: invalid time unit... ");
            return false;
        }
    }

    h = h + hourOffset;
    if (h < 0)
        h = h + 24;

    tr.hour = h;
    tr.minute = minOffset;
    tr.second = 0;

    int timer_duration = getUpdatedTime(tr.hour, tr.minute, tr.second); //calculate the duration of timer according to current time
    if(timer_duration != -1){
        tr.duration = timer_duration;
        return true;
    }
    return false;
}





/*********************************************************************/
/* Queue */
/*********************************************************************/

/*
 * Initialize a priority queue for struct TimerRule. Elements are sorted according to the duration field in ascending order.
 */
void initQueue(){
    timerQueue = std::priority_queue<TimerRule, std::vector<TimerRule>, CompareTime>();
}

/*
 * Add a TimerRule object to the priority queue
 */
bool addToQueue(Rule *rule){
    char *id = (char*)malloc((strlen(rule->ruleID)+1) * sizeof(char));
    memcpy(id, rule->ruleID, strlen(rule->ruleID));
    id[strlen(rule->ruleID)] = '\0';

    TimerRule tr = {id, 0, 0, 0, 0};

    if(initTime(rule->trigger->timeReferenceType, rule->trigger->timeOffset, rule->trigger->timeUnitType, tr)){
        timerQueue.push(tr);
        return true;
    }
    return false;
}

/*
 * Remove the element from the top of the priority queue
 */
bool removeTopFromQueue(char *ruleID){
    if(!timerQueue.empty()){
        TimerRule tr = timerQueue.top();
        if(strcmp(tr.ruleID, ruleID) == 0){
            timerQueue.pop();
            free(tr.ruleID);
            return true;
        }
    }
    printf("TimerQueueManager:: top from queue remove failed!");
    return false;
}

/*
 * Get the top element from the priority queue
 */
bool getTopFromQueue(TimerRule *tRule){
    if(!timerQueue.empty()){
        TimerRule tr = timerQueue.top();
        //printf("TimerQueueManager:: time String: %d:%d, seconds=%d\n", tr.hour, tr.minute, tr.second);
        tRule->ruleID = tr.ruleID; //TODO:: free ruleID
        tRule->hour = tr.hour;
        tRule->minute = tr.minute;
        tRule->second = tr.second;
        tRule->duration = tr.duration;
        return true;
    }
    return false;
}

/*
 * Reset the priority queue: remove all the elements and then populate again from the DB
 */
bool resetQueue(){
    while (!timerQueue.empty()) {
        TimerRule tr = timerQueue.top();
        timerQueue.pop();
        free(tr.ruleID);
    }
    timerQueue = {};

    std::vector<Rule*> ruleset;
    if(retrieveRulesFromDB(ruleset, 0, "", "", ALL_QUERY)){
        for (int i = 0; i < ruleset.size(); ++i) {
            if(ruleset[i]->ruleType != IF && ruleset[i]->trigger->valueType == TEMPORAL){
                addToQueue(ruleset[i]);
            }
            deleteRule(&ruleset[i]);
        }
        ruleset.clear();
        return true;
    }else{
        printf("TimerQueueManager:: Rule retrieval failed!");
    }
    return false;
}




/*********************************************************************/
/* Timer */
/*********************************************************************/

/*
 * Get the next Timer from the priority queue according to the ascending duration of timer
 */
bool getNextTimer(TimerRule *tRule){
    if(getTopFromQueue(tRule)){
        int duration = getUpdatedTime(tRule->hour, tRule->minute, tRule->second);
        if(duration != -1){
            tRule->duration = duration;
            return true;
        }
    }
    return false;
}

/*
 * Activate the Rule: send command to action-device
 *  @params: ruleID of the rule
 *  returns: true if successfully sent, else false
 */
bool startTimerRuleHandler(char *ruleID){
    /* remove from priority queue */
    if(!removeTopFromQueue(ruleID))
        return false;

    printf("TimerQueueManager:: #startTimerRuleHandler with ruleid = %s", ruleID);
    std::vector<Rule*> ruleset;
    /* retrieve the rule from DB with ruleID */
    if(retrieveRulesFromDB(ruleset, 1, ruleID, "", BY_RULE)){
        printf("TimerQueueManager:: Retrieved rule!, size=%d", ruleset.size());
        for (int i = 0; i < ruleset.size(); ++i) {
            /* send the rule action commands to the specified device */
            bool ret = sendRuleCommands(ruleset[i]);
            deleteRule(&ruleset[i]);
            return ret;
        }
    }else{
        printf("TimerQueueManager:: Rule retrieval failed!");
        return false;
    }
}