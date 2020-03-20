import random, json, threading, time
import Constants
import socketClient, CryptoHelper, Helper


device_type = ["0", "1", "2", "4", "5"]
operators = ["0", "1", "2"]
actions = ["0", "1"]

SIZE = 10


def randomNum(size):
    values = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
    ans = ""

    for x in range(size):
        ans = ans + str(random.choice(values))

    return ans


def send_rules(rules_array):
    soc = socketClient.connect_to_server(port=20003)
    count = 0
    print("##### start sending rules #####")
    for r in rules_array:
        jd = Helper.get_json_data(r)
        enc_rule = CryptoHelper.aes_gcm_encryption_with_tag(jd)
        socketClient.send_to_server(soc, enc_rule)

        count += 1
        if count == 100:
            break
        # time.sleep(60)
    soc.close()
    print("##### Done sending rules #####")


def send_data(data_array):
    soc = socketClient.connect_to_server(port=20004)
    count = 0
    print("##### start sending data #####")
    for d in data_array:
        print(d)
        jd = Helper.get_json_data(d)
        enc_data = CryptoHelper.aes_gcm_encryption_with_tag(jd)
        socketClient.send_to_server(soc, enc_data)

        count += 1
        if count == 200:
            break
        time.sleep(5)
    soc.close()
    print("##### Done sending data #####")


def simulate_data_for_rule_1(rule, data_array):
    num_of_data = int(randomNum(2))
    for i in range(num_of_data):
        data_instance = {}
        data_instance[Constants.RULE_DEVICE_ID] = rule[Constants.RULE_DEVICE_ID]
        data_instance[Constants.RULE_DEVICE_TYPE] = rule[Constants.RULE_DEVICE_TYPE]
        data_instance[Constants.SENSOR_DATA] = randomNum(2)
        data_array.append(data_instance)
        # print(data_instance)


def simulate_rule_1():
    # one-to-one mapping
    rules_array = []
    data_array = []
    for i in range(SIZE):
        rule = {}
        rule[Constants.RULE_DEVICE_ID] = Constants.RULE_DEVICE_ID + str(i)
        rule[Constants.RULE_ID] = Constants.RULE_ID + str(i)
        rule[Constants.RULE_USER_ID] = Constants.RULE_USER_ID + str(i)
        rule[Constants.RULE_DEVICE_TYPE] = random.choice(device_type)
        rule[Constants.RULE_THRESHOLD] = randomNum(2)
        rule[Constants.RULE_OPERATOR] = random.choice(operators)
        rule[Constants.RULE_ACTION] = random.choice(actions)
        rules_array.append(rule)
        print(rule)
        simulate_data_for_rule_1(rule, data_array)

    print("Total rule: ", len(rules_array))
    print("Total data: ", len(data_array))
    print("One sample data: ", data_array[0])

    t1 = threading.Thread(target=send_rules, args=(rules_array,))
    t1.start()

    time.sleep(30)

    t2 = threading.Thread(target=send_data, args=(data_array,))
    t2.start()

    t1.join()
    t2.join()



if __name__ == '__main__':
    simulate_rule_1()
