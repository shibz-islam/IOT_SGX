from pymongo import MongoClient


class MongoManager:
    def __init__(self, ip, port, db_name, collection_name):
        self.ip = ip
        self.port = port
        self.db_name = db_name
        self.collection_name = collection_name
        self.myDb = 0
        self.myCollection = 0


    def init_connection(self):
        client = MongoClient(self.ip, self.port)
        # client = MongoClient("mongodb://localhost:27017/")
        self.myDb = client[self.db_name]
        self.myCollection = self.myDb[self.collection_name]


    def insert_one_into_db(self, data):
        id = self.myCollection.insert_one(data).inserted_id
        print("inserted: ", id)


    def get_count(self):
        count = self.myCollection.count_documents({})
        print("Count: ", count)
