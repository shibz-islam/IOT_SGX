import json
import random, secrets
import string
from timeit import default_timer as timer
import Properties
from datetime import datetime


def read_json_from_file(filepath):
    with open(filepath, 'r') as openfile:
        json_object = json.load(openfile)
    # print(json_object)
    # print(type(json_object))
    # print("Total json objects in list: ", len(json_object))
    # for j in json_object:
    #     print(j['name'])
    return json_object


def write_json_list_in_file(filepath, json_list, indent):
    with open(filepath, 'w') as openfile:
        json.dump(json_list, openfile, indent=indent)


def read_data_from_file(filepath):
    with open(filepath, 'r') as openfile:
        data = openfile.readlines()
    return data


def write_data_to_file(filepath, data_list):
    f = open(filepath, "w")
    for item in data_list:
        f.write(item)
        f.write("\n")
    f.close()


def get_random_alphaNumeric_string(stringLength=8):
    lettersAndDigits = string.ascii_letters + string.digits
    str = ''.join((secrets.choice(lettersAndDigits) for i in range(stringLength)))
    #print(str)
    return str


def get_json_data(data):
    dataTemp = json.dumps(data)
    data_json = json.loads(dataTemp)
    return data_json


def log_response_time():
    end = timer()
    response_time = end - Properties.START_TIME
    line = datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "," + Properties.PENDING_ID + "," + response_time
    print("Response Time: ", line)
    if Properties.IS_ENCRYPTION_ENABLED:
        filepath = Properties.EXP_PATH + Properties.FILENAME_RECORD_RESPONSE_TIME + Properties.FILENAME_EXT
    else:
        filepath = Properties.EXP_PATH + Properties.FILENAME_RECORD_RESPONSE_TIME_UNENC + Properties.FILENAME_EXT
    write_data_to_file(filepath=filepath, data_list=[line])


def extract_values_from_json(obj, key):
    """Pull all values of specified key from nested JSON."""
    arr = []

    def extract(obj, arr, key):
        """Recursively search for values of key in JSON tree."""
        if isinstance(obj, dict):
            for k, v in obj.items():
                #print(k, v)
                if k == key:
                    arr.append(v)
                    #print("***")
                elif isinstance(v, (dict, list)):
                    extract(v, arr, key)
        elif isinstance(obj, list):
            for item in obj:
                extract(item, arr, key)
        return arr

    results = extract(obj, arr, key)
    return results


def check_existence_from_json(obj, key):
    """returns boolean"""
    arr = []

    def extract(obj, key):
        """Recursively search for values of key in JSON tree."""
        if isinstance(obj, dict):
            for k, v in obj.items():
                #print(k, v)
                if k == key:
                    return True
                elif isinstance(v, (dict, list)):
                    extract(v, key)
        elif isinstance(obj, list):
            for item in obj:
                extract(item, key)
        return False

    result = extract(obj, arr, key)
    return result