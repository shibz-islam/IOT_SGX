//
// Created by shihab on 12/6/20.
//

#include "EnclaveDatabaseManager.h"
#include "analytics_utils.h"
#include "RuleManager.h"


static inline void free_allocated_memory(void *pointer)
{
    if(pointer != NULL)
    {
        free(pointer);
        pointer = NULL;
    }
}

static inline void free_allocated_memory_void(void **pointer)
{
    if(*pointer != NULL)
    {
        free(*pointer);
        *pointer = NULL;
    }
}


void setAttributeValue(RuleComponent *trigger, DatabaseElement *dbElement){
    if(trigger->valueType == STRING){
        dbElement->attribute = trigger->valueString;
        dbElement->valueType = STRING;
    }else if(trigger->valueType == NUMBER){
        dbElement->attribute = (char*)std::to_string(trigger->value).c_str();
        dbElement->valueType = NUMBER;
    }else{
        dbElement->attribute = "";
        dbElement->valueType = TEMPORAL;
    }
}


bool storeRuleInDB(char *ruleString, Rule *myrule){
    size_t len = strlen(ruleString);
    DatabaseElement *dbElement = (DatabaseElement*) malloc(sizeof(struct DatabaseElement));
    dbElement->data = (Message*) malloc(sizeof(struct Message));
    dbElement->data->text = NULL;
    dbElement->data->tag = NULL;
    if(isEncryptionEnabled){
        dbElement->data->isEncrypted = 1;
        dbElement->data->text = (char *) malloc(sizeof(char) * (len+1));
        dbElement->data->tag = (char *) malloc(sizeof(char) * (SGX_AESGCM_MAC_SIZE+1));

        sgx_status_t status = encryptMessageAES(ruleString, len, dbElement->data->text, len, dbElement->data->tag);
        if(status != SGX_SUCCESS){
            //deleteMessage(&dbElement->data);
            free_allocated_memory_void((void**)&dbElement->data->text);
            free_allocated_memory_void((void**)&dbElement->data->tag);
            free_allocated_memory_void((void**)&dbElement->data);
            free_allocated_memory_void((void**)&dbElement);
            return false;
        }
        dbElement->data->textLength = len;
        dbElement->data->tagLength = SGX_AESGCM_MAC_SIZE;
    }else{
        dbElement->data->isEncrypted = 0;
        dbElement->data->text = ruleString;
        dbElement->data->textLength = len;
    }
    size_t isSuccess = 0;

    dbElement->ruleID = myrule->ruleID;
    dbElement->deviceID = myrule->trigger->deviceID;
    dbElement->deviceIDAction = myrule->action->deviceID;
    setAttributeValue(myrule->trigger, dbElement);
    //dbElement->data = data;

    ocall_write_to_file(&isSuccess, dbElement, 1);

    //deleteMessage(&dbElement->data);
    free_allocated_memory_void((void**)&dbElement->data->text);
    free_allocated_memory_void((void**)&dbElement->data->tag);
    free_allocated_memory_void((void**)&dbElement->data);
    free_allocated_memory_void((void**)&dbElement);

    return isSuccess == 1 ? true:false;
}


bool constructDatabaseQuery(DatabaseElement *dbElement, char *primaryKey, char *secondaryKey, DBQueryType queryType){
    switch (queryType){
        case BY_RULE:{
            dbElement->ruleID = primaryKey;
            //printf("BY_RULE, %s", dbElement->ruleID);
            break;
        }
        case BY_TRIGGER_DEVICE_ID:{
            dbElement->deviceID = primaryKey;
            //printf("BY_TRIGGER_DEVICE_ID, %s", dbElement->deviceID);
            break;
        }
        case BY_TRIGGER_DEVICE_ID_ATTR:{
            dbElement->deviceID = primaryKey;
            dbElement->attribute = secondaryKey;
            //printf("BY_TRIGGER_DEVICE_ID_ATTR, %s, %s", dbElement->deviceID, dbElement->attribute);
            break;
        }
        case BY_ACTION_DEVICE_ID:{
            dbElement->deviceIDAction = primaryKey;
            //printf("BY_ACTION_DEVICE_ID, %s", dbElement->deviceIDAction);
            break;
        }
        case BY_TRIGGER_ACTION_DEVICE_ID:{
            dbElement->deviceID = primaryKey;
            dbElement->deviceIDAction = secondaryKey;
            //printf("BY_TRIGGER_ACTION_DEVICE_ID, %s", dbElement->deviceID);
        }
        case ALL_QUERY:
            break;
        default: {
            printf("EnclaveDatabaseManager:: Unknown DB Query Type!");
            return false;
        }
    }
    dbElement->queryType = queryType;
    return true;
}


size_t retrieveRuleCountFromDB(char *primaryKey, char *secondaryKey, DBQueryType queryType){
    //printf("EnclaveDatabaseManager:: retrieveRuleCountFromDB...");
    DatabaseElement *dbElement = (DatabaseElement*) malloc(sizeof(DatabaseElement));
    size_t ruleCount = 0;
    if(constructDatabaseQuery(dbElement, primaryKey, secondaryKey, queryType)){
        ocall_read_rule_count(&ruleCount, dbElement);
    }
    if(dbElement != NULL) free(dbElement);
    return ruleCount;
}

bool retrieveRulesFromDB(std::vector<Rule*>&ruleset, size_t ruleCount, char *primaryKey, char *secondaryKey, DBQueryType queryType){
    printf("EnclaveDatabaseManager:: retrieveRulesFromDB...");
    if (ruleCount <= 0){
        /*  fetch rule count */
        ruleCount = retrieveRuleCountFromDB(primaryKey, secondaryKey, queryType);
        if (ruleCount <= 0) {
            printf("EnclaveDatabaseManager:: no rules found in DB...");
            return false;
        }
    }

    /*  construct DB query */
    DatabaseElement *dbElement = (DatabaseElement*) malloc(sizeof(DatabaseElement));
    if(!constructDatabaseQuery(dbElement, primaryKey, secondaryKey, queryType)){
        free(dbElement);
        return false;
    }

    /*  fetch rule info such as rule size */
    dbElement->data = (Message*) malloc(ruleCount * sizeof(Message));
    Message *startPosData = dbElement->data;
    size_t isRetrieved = 0;
    ocall_read_rule_info(&isRetrieved, dbElement, ruleCount);
    if(isRetrieved == 0){
        printf("EnclaveDatabaseManager:: Failed to fetch rule info!");
        free(dbElement->data);
        free(dbElement);
        return false;
    }

    /*  initialize DatabaseElement and Message */
    int count = 0;
    dbElement->data = startPosData;
    for(int i=0; i<ruleCount; i++){
        int len = dbElement->data->textLength;
        dbElement->data->text = (char *) malloc(sizeof(char) * (len+1));
        dbElement->data->tagLength = SGX_AESGCM_MAC_SIZE;
        if (dbElement->data->isEncrypted) dbElement->data->tag = (char *) malloc(sizeof(char) * (SGX_AESGCM_MAC_SIZE+1));

        count++;
        if(count != ruleCount) dbElement->data++;
    }

    /*  fetch rules */
    isRetrieved = 0;
    dbElement->data = startPosData;
    ocall_read_rule(&isRetrieved, dbElement, ruleCount);
    if(isRetrieved == 0){
        printf("EnclaveDatabaseManager:: Failed to fetch rules!");
        count = 0;
        dbElement->data = startPosData;
        for(int i=0; i<ruleCount; i++){
            if(dbElement->data->text != NULL) free(dbElement->data->text);
            if (dbElement->data->isEncrypted && dbElement->data->tag != NULL) free(dbElement->data->tag);
            count++;
            if(count != ruleCount) dbElement->data++;
        }
        free(dbElement->data);
        free(dbElement);
        return false;
    }

    /*  process rules */
    count = 0;
    dbElement->data = startPosData;
    for(int i=0; i<ruleCount; i++){
        printf("EnclaveDatabaseManager:: Rule number: i=%d",i+1);
        bool isSuccess = true;
        char *ruleString = (char *) malloc(sizeof(char) * (dbElement->data->textLength + 1));
        if(dbElement->data->isEncrypted){
            sgx_status_t status = decryptMessageAES(dbElement->data->text, dbElement->data->textLength, ruleString, dbElement->data->textLength, dbElement->data->tag);
            if(status != SGX_SUCCESS){
                isSuccess = false;
            }
        }else{
            memcpy(ruleString, dbElement->data->text, dbElement->data->textLength);
            ruleString[dbElement->data->textLength] = '\0';
            if (memcmp(ruleString, dbElement->data->text, dbElement->data->textLength) != 0){
                isSuccess = false;
            }
        }
        if (!isSuccess){
            printf("EnclaveDatabaseManager:: Rule decryption/copy failed!");
            free(ruleString);
        }else{
            struct Rule *myRule;
            if(initRule(&myRule)){
                if(startParsingRule(ruleString, myRule)){
                    printRuleInfo(myRule);
                    ruleset.push_back(myRule);
                } else{
                    printf("EnclaveDatabaseManager:: Rule parsing failed!");
                    isSuccess = false;
                }
            }else{
                printf("EnclaveDatabaseManager:: init Rule failed!");
                isSuccess = false;
            }
            free(ruleString);
        }
        //printf("freeing dbElement->data->text...");
        if(dbElement->data->text != NULL) free(dbElement->data->text);
        //printf("freeing dbElement->data->tag...");
        if (dbElement->data->isEncrypted && dbElement->data->tag != NULL) free(dbElement->data->tag);

        count++;
        if(count != ruleCount) dbElement->data++;
    }// for-loop

    dbElement->data = startPosData;
    //printf("freeing dbElement->data...");
    free(dbElement->data);
    //printf("freeing dbElement...");
    free(dbElement);

    return ruleset.size() > 0 ? true : false;
}
