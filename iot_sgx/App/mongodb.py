from pymongo import MongoClient

client = MongoClient('localhost', 27017)
#client = MongoClient("mongodb://localhost:27017/")

mydatabase = client['test']
mycollection = mydatabase['iot']


def insert():
    record_dict = {'name':'shihab', 'age': 26, 'address': 'abcd'}

    # id = mycollection.insert_many([
    # {'name':'rafee', 'age': 28, 'address': 'xyz'},
    # {'name':'faraz', 'age': 25, 'address': 'gables'},
    # {'name':'tahmid', 'age': 26, 'address': 'meadows'}
    # ])
    # print(id.inserted_id)


def get_count(a, b):
    cursor = mycollection.find({})
    for item in cursor:
        print(item['name'])
    print("Count: ", cursor.count())
    return cursor.count()


def get_dict(a, b):
    cursor = mycollection.find({})
    dict = {}
    return cursor


def get_namelist(a, b):
    cursor = mycollection.find({})
    list = []
    for item in cursor:
        list.append(item['name'])
    return list


def get_records():
    cursor = mycollection.find({})
    list = []
    for item in cursor:
        list.append(item)
    return list


if __name__ == '__main__':
    import sys, os

    print(os.getcwd())
    print(os.path.dirname(os.getcwd()))
    quit()