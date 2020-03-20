import random, json
import Constants


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


if __name__ == '__main__':
    simulate_rule_1()
