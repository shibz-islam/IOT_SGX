//
// Created by shihab on 10/21/19.
//

#include "MongoManager.h"

MongoManager::MongoManager(std::string urlName, std::string dbName, std::string collectionName) {
    url = urlName;
    db = dbName;
    coll = collectionName;
    mongocxx::instance instance{}; // This should be done only once.
}

int MongoManager::initConnection() {
    //mongocxx::uri uri("mongodb://localhost:27017");
    mongocxx::uri uri(url);
    mongocxx::client client(uri);

    mongocxx::database myDb = client[db];

    myCollection = myDb[coll];

    /*
    auto cursor = client.list_databases();
    for (auto doc : cursor) {
        std::cout << bsoncxx::to_json(doc) << std::endl;
    }

    auto cursor2 = myDb.list_collections({});
    for (auto doc : cursor2) {
        std::cout << bsoncxx::to_json(doc) << std::endl;
    }

    int count = myCollection.count_documents({});
    printf("count %d\n", count);

    auto cursor3 = myCollection.find({});
    printf("All documents ---\n");
    for (auto doc : cursor3) {
        std::cout << bsoncxx::to_json(doc) << std::endl;
    }
     */

    return 0;
}

std::vector<std::string> MongoManager::getAllData() {
    mongocxx::uri uri(url);
    mongocxx::client client(uri);

    mongocxx::database myDb = client[db];

    myCollection = myDb[coll];

    std::vector<std::string> rules;

    printf(" --- Fetching All ---\n");
    int count = myCollection.count_documents({});
    printf("count %d\n", count);
    if(count>0){
        auto cursor = myCollection.find({});
        for (auto doc : cursor) {
            //std::cout << bsoncxx::to_json(doc) << std::endl;
            rules.push_back(bsoncxx::to_json(doc));
        }
        printf("Rule size: %ld\n",rules.size());
    } else{
        printf("No record!\n");
    }

    return rules;
}

int MongoManager::getCount() {
    mongocxx::uri uri(url);
    mongocxx::client client(uri);

    mongocxx::database myDb = client[db];

    myCollection = myDb[coll];

    int count = myCollection.count_documents({});
    printf("Total documents: %d\n", count);
    return count;
}

/*
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
 */