//
// Created by shihab on 10/21/19.
//

#ifndef IOTENCLAVE_MONGOMANAGER_H
#define IOTENCLAVE_MONGOMANAGER_H

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <iostream>
#include <string.h>
#include <vector>

#include <bsoncxx/builder/stream/document.hpp>
#include <bsoncxx/json.hpp>
#include <mongocxx/client.hpp>
#include <mongocxx/instance.hpp>

using bsoncxx::builder::stream::close_array;
using bsoncxx::builder::stream::close_document;
using bsoncxx::builder::stream::document;
using bsoncxx::builder::stream::finalize;
using bsoncxx::builder::stream::open_array;
using bsoncxx::builder::stream::open_document;


class MongoManager {
private:
    std::string url;
    std::string db;
    std::string coll;
    mongocxx::collection myCollection;

public:
    MongoManager(std::string urlName, std::string dbName, std::string collectionName);
    int initConnection();
    std::vector<std::string> getAllData();
    int getCount();
};


#endif //IOTENCLAVE_MONGOMANAGER_H
