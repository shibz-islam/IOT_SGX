import Helper, Constants, DeviceManager, CryptoHelper, socketClient
import json, random, time
from Properties import Actions

#path = "/Users/shihab/Desktop/"
path = "datafiles/"
filename = "Ruleset.json"
ID_LENGTH = 12


def check_rule_action(rule):
    objects = rule['actions']
    for obj in objects:
        res = Helper.check_existence_from_json(obj=obj, key=Actions.COMMAND.name.lower())
        print(res)


def get_rules():
    rules_json = Helper.read_json_from_file(path + filename)
    return rules_json


def assign_users(rules_json):
    rule_list = []
    random.shuffle(rules_json)

    num_of_users = 5
    num_rules_per_user = int(len(rules_json) / num_of_users)

    for i in range(0, num_of_users):
        uid = Helper.get_random_alphaNumeric_string()
        for j in range(0, num_rules_per_user):
            rule = rules_json.pop()
            rule[Constants.RULE_USER_ID] = uid
            rule_list.append(rule)
    return rule_list


def start_simulation():

    rule_list = get_rules()
    #rule_list = assign_users(rule_list)
    rule_list = rule_list[:]
    count = 0
    soc = socketClient.connect_to_server(port=20003)
    for rule in rule_list:
        print("**********")
        print(json.dumps(rule))
        enc_rule = CryptoHelper.aes_gcm_encryption_with_tag(rule)
        #enc_rule = json.dumps(rule)
        socketClient.send_to_server(soc, enc_rule)
        time.sleep(2)
        count += 1
        print("Count=", count)
        if count == 50:
            break

    socketClient.send_to_server(soc, "quit")
    soc.close()


if __name__ == '__main__':
    start_simulation()


