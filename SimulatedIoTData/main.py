import RuleManager, DeviceManager, Helper, Constants
import random, json


def create_users():

    rules_json = RuleManager.get_rules()
    rule_id_list = []
    for rule in rules_json:
        rule_id_list.append(rule[Constants.RULE_ID])
    random.shuffle(rule_id_list)

    num_of_users = 5
    num_rules_per_user = int(len(rule_id_list)/num_of_users)

    json_list = []
    for i in range(0, num_of_users):
        uid = Helper.get_random_alphaNumeric_string()
        user_rules = []
        for j in range(0, num_rules_per_user):
            user_rules.append(rule_id_list.pop())
        #print(uid, user_rules)openfile
        json_obj = {}
        json_obj['userID'] = uid
        json_obj[Constants.RULE_ID] = user_rules
        json_obj[Constants.RULE_DEVICE_ID] = []
        json_list.append(json_obj)
    #print(json.dumps(json_list, indent=2))
    Helper.write_json_list_in_file('datafiles/records.json', json_list, indent=2)


if __name__ == '__main__':
    #create_users()
    print(Helper.get_random_alphaNumeric_string(stringLength=16))
