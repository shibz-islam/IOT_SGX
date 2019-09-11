//
// Created by shihab on 6/5/19.
//

#include "MongoHelper.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <iostream>
#include <string.h>

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

mongocxx::collection coll;

int mongo_setup_db()
{
    mongocxx::instance instance{}; // This should be done only once.
    mongocxx::uri uri("mongodb://localhost:27017");
    mongocxx::client client(uri);
    mongocxx::database db = client["temp"];
    coll = db["lamp"];
    return 0;
}

int mongo_fetch_db()
{
    printf(" --- Fetching All ---\n");
    auto cursor = coll.find({});
    for (auto doc : cursor) {
        std::cout << bsoncxx::to_json(doc) << std::endl;
    }
    return 0;
}

int mongo_update_db(struct device* s)
{
//    mongocxx::instance instance{}; // This should be done only once.
//    mongocxx::uri uri("mongodb://localhost:27017");
//    mongocxx::client client(uri);
//    mongocxx::database db = client["temp"];
//    coll = db["lamp"];
//    printf("Update.. \n");
//    std::string uid_str(s->uid);
//    std::string state_str(s->state);
//    bsoncxx::stdx::optional<mongocxx::result::update> result = coll.update_one(
//            document{} << "uid" << uid_str << finalize,
//            document{} << "$set" << open_document << "state" << state_str << close_document << finalize);
//    if(result) {
//        std::cout << "Record Updated!" << "\n";
//    }
//
//    printf(" --- Fetching All ---\n");
//    auto cursor = coll.find({});
//    for (auto doc : cursor) {
//        std::cout << bsoncxx::to_json(doc) << std::endl;
//    }
    return 0;
}