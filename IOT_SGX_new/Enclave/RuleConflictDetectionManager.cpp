//
// Created by shihab on 11/19/20.
//


#include "RuleConflictDetectionManager.h"
#include "RuleManager.h"
#include "EnclaveDatabaseManager.h"

#define MAX 1000
#define MIN -1000


GraphEdgeMap edgeMap;
GraphNodeMap nodeMap;


RangePair getRangePair(float value, enum OperatorType op){
    if (op == GT){
        return std::make_pair(value+1,MAX);
    } else if (op == LT){
        return std::make_pair(MIN,value-1);
    } else if (op == GTE){
        return std::make_pair(value,MAX);
    } else if (op == LTE){
        return std::make_pair(MIN,value);
    } else{
        return std::make_pair(value,value);
    }
}

bool isOverlap(float value1, enum OperatorType op1, float value2, enum OperatorType op2){
    RangePair p1 = getRangePair(value1, op1);
    RangePair p2 = getRangePair(value2, op2);
    return std::max(p1.first, p2.first) <= std::min(p1.second, p2.second);
}

bool isTemporalOverlap(RuleComponent *item1, RuleComponent *item2){
    if(item1->timeReferenceType == item2->timeReferenceType){
        if(item1->timeOffset == item2->timeOffset) return true;
    } //TODO
    return false;
}

bool isStringValue(RuleComponent *item){
    if(item->valueType == STRING)
        return true;
    return false;
}

bool isNumberValue(RuleComponent *item){
    if(item->valueType == NUMBER || item->valueType == INTEGER)
        return true;
    return false;
}

bool isTemporalValue(RuleComponent *item){
    if(item->valueType == TEMPORAL)
        return true;
    return false;
}

bool isValueEqual(RuleComponent *item1, RuleComponent *item2){
    if(isStringValue(item1) && isStringValue(item2)){
        return strcmp(item1->valueString, item2->valueString) == 0;
    } else if(isNumberValue(item1) && isNumberValue(item2)){
        return item1->value == item2->value;
    } else{
        return false;
    }
}

/***
 * Graph Creation
 ***/

bool initGraph(){
    edgeMap = std::multimap<KeyPair, std::string>();
}

void addGraphNode(Rule *edge){

}

void addGraphEdge(Rule *edge){
    KeyPair key = std::make_pair(std::string(edge->trigger->deviceID), std::string(edge->action->deviceID));
    edgeMap.insert(std::make_pair(key, std::string(edge->ruleID)));
}

void updateGraph(Rule *edge){
    addGraphEdge(edge);
}

bool isNodePresent(string key){
    return !(nodeMap.find(key) == nodeMap.end());
}

bool isEdgePresent(KeyPair key) {
    return !(edgeMap.find(key) == edgeMap.end());
}


/***
 * Rule Conflict Detection
 ***/

bool checkShadowExecutionConflictBound(Rule *newEdge, Rule *oldEdge){
    if(isStringValue(newEdge->trigger) && isStringValue(oldEdge->trigger)){
        return strcmp(newEdge->trigger->valueString, oldEdge->trigger->valueString) == 0;
    }else if (isNumberValue(newEdge->trigger) && isNumberValue(oldEdge->trigger)){
        return isOverlap(newEdge->trigger->value, newEdge->trigger->operatorType, oldEdge->trigger->value, oldEdge->trigger->operatorType);
    }else if (isTemporalValue(newEdge->trigger) && isTemporalValue(oldEdge->trigger)){
        //TODO
        return isTemporalOverlap(newEdge->trigger, oldEdge->trigger);
    }
    return false;
}

ConflictType checkShadowExecutionConflict(Rule *newEdge, Rule *oldEdge){
    bool isSameAction = isValueEqual(newEdge->action, oldEdge->action);
    if(isSameAction){
        return checkShadowExecutionConflictBound(newEdge, oldEdge)? SHADOW : NONE;
    }else{
        return checkShadowExecutionConflictBound(newEdge, oldEdge)? EXECUTION : NONE;
    }
}

ConflictType checkMutualConflict(Rule *newEdge, Rule *oldEdge){
    /*
    if(isStringValue(newEdge->action)){
        printf("newEdge->action->valueString=%s, oldEdge->action->valueString=%s",newEdge->action->valueString, oldEdge->action->valueString);
        if(strcmp(newEdge->action->valueString, oldEdge->action->valueString) != 0)
            return MUTUAL;
    }else{
        printf("newEdge->action->value=%f, oldEdge->action->value=%f",newEdge->action->value, oldEdge->action->value);
        if(newEdge->action->value != oldEdge->action->value)
            return MUTUAL;
    }*/
    if(!isValueEqual(newEdge->action, oldEdge->action)){
        return MUTUAL;
    }
    return NONE;
}

ConflictType checkDependenceConflict(Rule *newEdge, Rule *oldEdge){
    if(!isValueEqual(newEdge->action, oldEdge->trigger) && !isValueEqual(newEdge->trigger, oldEdge->action))
        return NONE;
    return DEPENDENCE;
}

ConflictType checkChainingConflict(Rule *newEdge, Rule *oldEdge, bool isForwardChaining){
    if(isForwardChaining){
        if(isValueEqual(newEdge->trigger, oldEdge->action))
            return CHAIN;
    }else{
        if(isValueEqual(newEdge->action, oldEdge->trigger))
            return CHAIN;
    }
    return NONE;
}


Rule* getEdgeFromDB(std::string ruleID){
    printf("RuleConflictDetectionManager:: #getEdgeFromDB with ruleid = %s", (char*)ruleID.c_str());
    std::vector<Rule*> ruleset;
    if(retrieveRulesFromDB(ruleset, 1, (char*)ruleID.c_str(), "", BY_RULE)){
        printf("*** Retrieved rule!, size=%d", ruleset.size());
        for (int i = 0; i < ruleset.size(); ++i) {
            return ruleset[i];
        }
    }else{
        printf("RuleConflictDetectionManager:: Rule retrieval failed!");
        return NULL;
    }
}

ConflictType checkPossibleConflict(Rule *edge, std::string ruleID, ConflictType conflictType){
    ConflictType result = NONE;
    Rule *oldEdge = NULL;
    oldEdge = getEdgeFromDB(ruleID);
    if(oldEdge == NULL)
        return result;

    switch (conflictType){
        case SHADOW:
        case EXECUTION:{
            result =  checkShadowExecutionConflict(edge, oldEdge);
            break;
        }
        case MUTUAL:{
            result = checkMutualConflict(edge, oldEdge);
            break;
        }
        case DEPENDENCE:{
            result = checkDependenceConflict(edge, oldEdge);
            break;
        }
        case CHAIN:{
            result = checkChainingConflict(edge, oldEdge, false);
            break;
        }
        case CHAIN_FWD:{
            result = checkChainingConflict(edge, oldEdge, true);
            break;
        }
        default:
            printf("RuleConflict: No conflict type specified!");
    }

    printConflictType(result);
    if(result != NONE && oldEdge!=NULL){
        printf("RuleConflict:: Conflicted with:");
        printRuleInfo(oldEdge);
    }
    deleteRule(&oldEdge);
    //free(oldEdge);

    return result;
}

bool detectRuleConflicts2(Rule *edge){
    ConflictType result = NONE;
    std::vector<Rule*> ruleset;
    if(retrieveRulesFromDB(ruleset, 0, edge->action->deviceID, NULL, BY_ACTION_DEVICE_ID)){
        printf("RuleConflictDetectionManager:: Retrieved rule!, size=%d", ruleset.size());
        for (int i = 0; i < ruleset.size(); ++i) {
            if (strcmp(edge->trigger->deviceID, ruleset[i]->trigger->deviceID) == 0){
                /* shadow or execution */
                result =  checkShadowExecutionConflict(edge, ruleset[i]);
                if(result != NONE) break;
            }else{
                /* mutual */
                result = checkMutualConflict(edge, ruleset[i]);
                if(result != NONE) break;
            }
        }
        for (int i = 0; i < ruleset.size(); ++i) deleteRule(&ruleset[i]);
        ruleset.clear();
        if (result != NONE){
            printConflictType(result);
            return true;
        }
    }else{
        printf("RuleConflictDetectionManager:: Rule retrieval failed!");
    }

    if(retrieveRulesFromDB(ruleset, 0, edge->action->deviceID, NULL, BY_TRIGGER_DEVICE_ID)){
        printf("*** Retrieved rule!, size=%d", ruleset.size());
        for (int i = 0; i < ruleset.size(); ++i) {
            if (strcmp(edge->trigger->deviceID, ruleset[i]->action->deviceID) == 0){
                /* dependence */
                result =  checkDependenceConflict(edge, ruleset[i]);
                if(result != NONE) break;
            }else{
                /* chaining */
                result = checkChainingConflict(edge, ruleset[i], false);
                if(result != NONE) break;
            }
        }
        for (int i = 0; i < ruleset.size(); ++i) deleteRule(&ruleset[i]);
        ruleset.clear();
        if (result != NONE){
            printConflictType(result);
            return true;
        }
    }else{
        printf("RuleConflictDetectionManager:: Rule retrieval failed!");
    }

    if(retrieveRulesFromDB(ruleset, 0, edge->trigger->deviceID, "", BY_ACTION_DEVICE_ID)){
        printf("*** Retrieved rule!, size=%d", ruleset.size());
        for (int i = 0; i < ruleset.size(); ++i) {
            /* forward chaining */
            result = checkChainingConflict(edge, ruleset[i], true);
            if(result != NONE) break;
        }
        for (int i = 0; i < ruleset.size(); ++i) deleteRule(&ruleset[i]);
        ruleset.clear();
        if (result != NONE){
            printConflictType(result);
            return true;
        }
    }else{
        printf("RuleConflictDetectionManager:: Rule retrieval failed!");
    }

    return result == NONE? false:true;
}

bool detectRuleConflicts(Rule *edge){
    return detectRuleConflicts2(edge);

    std::string srcID(edge->trigger->deviceID);
    std::string destID(edge->action->deviceID);

    ConflictType result = NONE;

    GraphEdgeMap:: iterator itr;
    for (itr = edgeMap.begin(); itr != edgeMap.end(); ++itr)
    {
        if(destID == itr->first.second){
            if(srcID == itr->first.first){
                /* shadow or execution */
                result = checkPossibleConflict(edge, itr->second, SHADOW);
                if(result != NONE) break;
            }else{
                /* mutual */
                result = checkPossibleConflict(edge, itr->second, MUTUAL);
                if(result != NONE) break;
            }
        }else if(destID == itr->first.first){
            if(srcID == itr->first.second){
                /* dependence */
                result = checkPossibleConflict(edge, itr->second, DEPENDENCE);
                if(result != NONE) break;
            }else{
                /* chaining */
                result = checkPossibleConflict(edge, itr->second, CHAIN);
                if(result != NONE) break;
            }
        }else if(srcID == itr->first.second){
            /* forward chaining */
            result = checkPossibleConflict(edge, itr->second, CHAIN_FWD);
            if(result != NONE) break;
        }
    }

    return result == NONE? false:true;
}

