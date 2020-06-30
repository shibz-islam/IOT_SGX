import Helper, Constants, DeviceManager, CryptoHelper, socketClient, Properties
import json, random, time
from Properties import Actions
import copy

#path = "/Users/shihab/Desktop/"

ID_LENGTH = 12

DeviceDict = {}
TrackDeviceDict = {}

def check_rule_action(rule):
    objects = rule['actions']
    for obj in objects:
        res = Helper.check_existence_from_json(obj=obj, key=Actions.COMMAND.name.lower())
        print(res)


def get_rules():
    rules_json = Helper.read_json_from_file(Properties.datapath + str(Properties.RULE_COUNT) + Properties.ruleset_large_filename)
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


def track_device_ids(capability, newID):
    global TrackDeviceDict
    if capability in TrackDeviceDict:
        list = TrackDeviceDict[capability]
        list.append(newID)
    else:
        TrackDeviceDict[capability] = [newID]


def parse_device_condition_rule(obj):
    if 'device' in obj:
        if 'capability' in obj['device'] and 'devices' in obj['device']:
            capability = obj['device']['capability']
            device_id_list = DeviceDict[capability]
            #print(device_id_list)
            newID = random.choice(device_id_list)
            obj['device']['devices'] = [newID]
            track_device_ids(capability=capability, newID=newID)
            return True
    return False


def parse_device_command_rule(objs):
    for obj in objs:
        if 'command' in obj or 'notify' in obj:
            if 'command' in obj:
                if 'devices' in obj['command'] and 'commands' in obj['command']:
                    capability = obj['command']['commands'][0]['capability']
                    device_id_list = DeviceDict[capability]
                    newID = random.choice(device_id_list)
                    obj['command']['devices'] = [newID]
                    track_device_ids(capability=capability, newID=newID)
                else:
                    return False
        else:
            return False
    return True


def parse_if_action_rule(obj):
    is_success = False
    if 'equals' in obj:
        #print("Present, value =", obj['equals'])
        is_success = parse_device_condition_rule(obj=obj['equals']['left'])
    elif 'greater_than' in obj:
        #print("Present, value =", obj['greater_than'])
        is_success = parse_device_condition_rule(obj=obj['greater_than']['right'])
    elif 'greater_than_or_equals' in obj:
        #print("Present, value =", obj['greater_than_or_equals'])
        is_success = parse_device_condition_rule(obj=obj['greater_than_or_equals']['right'])
    elif 'less_than' in obj:
        #print("Present, value =", obj['less_than'])
        is_success = parse_device_condition_rule(obj=obj['less_than']['right'])
    elif 'less_than_or_equals' in obj:
        #print("Present, value =", obj['less_than_or_equals'])
        is_success = parse_device_condition_rule(obj=obj['less_than_or_equals']['right'])
    elif 'between' in obj:
        #print("Present, value =", obj['between'])
        is_success = parse_device_condition_rule(obj=obj['between']['value'])
    else:
        print("Unknown if value")
        is_success = False

    if is_success:
        if 'then' in obj and 'else' in obj:
            if parse_device_command_rule(objs=obj['then']) and parse_device_command_rule(objs=obj['else']):
                return True
    return False


def parse_every_action_rule(obj):
    actions = obj['actions']
    return parse_device_command_rule(actions)


def parse_rule(rule):
    rule['ruleID'] = Helper.get_random_alphaNumeric_string(stringLength=12)
    obj = rule['actions'][0]
    if 'if' in obj:
        #print("Present, value =", obj['if'])
        return parse_if_action_rule(obj=obj['if'])
    elif 'every' in obj:
        #print("Present, value =", obj['every'])
        return parse_every_action_rule(obj=obj['every'])
    elif 'sleep' in obj:
        print("Present, value =", obj['sleep'])
        return False
    else:
        print("Unknown value")
        return False


def simulated_new_rules():
    device_list = Helper.read_data_from_file(Properties.datapath + Properties.base_device_id_list_filename)
    global DeviceDict
    for device in device_list:
        items = device.rstrip().split(",", 1)
        capability = items[0]
        id_list = items[1].split(",")
        DeviceDict[capability] = id_list

    rule_list = Helper.read_json_from_file( Properties.datapath + Properties.base_ruleset_filename)
    print("Basic rule count = ", len(rule_list))
    new_rules = []
    num_copy_per_rule = int(Properties.RULE_COUNT / 40)
    for rule in rule_list:
        for i in range(num_copy_per_rule):
            rule_copy = copy.deepcopy(rule)
            if parse_rule(rule_copy):
                print(rule_copy)
                new_rules.append(rule_copy)
            else:
                print("Error for Rule: ", rule_copy)
        #break
    print(len(new_rules))
    Helper.write_json_list_in_file(filepath=Properties.datapath + str(Properties.RULE_COUNT) + Properties.ruleset_large_filename, json_list=new_rules, indent=2)

    print(TrackDeviceDict)
    print(len(TrackDeviceDict.keys()))
    tracked_id_list = []
    for key in TrackDeviceDict:
        element_list = TrackDeviceDict[key]
        listToStr = ','.join([elem for elem in element_list])
        listToStr = key + "," + listToStr
        #print(listToStr)
        tracked_id_list.append(listToStr)
    Helper.write_data_to_file(filepath=Properties.datapath + str(Properties.RULE_COUNT) + Properties.tracked_device_id_list_filename, data_list=tracked_id_list)


def start_simulation():
    soc = socketClient.connect_to_server(port=20005)
    rule_list = Helper.read_json_from_file(Properties.datapath + str(Properties.RULE_COUNT) + Properties.ruleset_large_filename)
    print("Total rules: ", len(rule_list))
    random.shuffle(rule_list)
    #rule_list = assign_users(rule_list)
    count = 0
    for rule in rule_list:
        print("**********")
        print(json.dumps(rule))
        if Properties.IS_ENCRYPTION_ENABLED:
            enc_rule = CryptoHelper.aes_gcm_encryption_with_tag(rule)
        else:
            enc_rule = json.dumps(rule)
        socketClient.send_to_server(soc, enc_rule)
        count += 1
        print("Count=", count)
        time.sleep(1)
        if count == Properties.RULE_COUNT/2:
            break

    socketClient.send_to_server(soc, "quit")
    soc.close()


def send_sample_rules():
    soc = socketClient.connect_to_server(port=20005)
    rule_list = Helper.read_json_from_file(
        Properties.datapath + Properties.base_ruleset_filename)
    print("Total rules: ", len(rule_list))
    count = 0
    for rule in rule_list:
        print("**********")
        print(json.dumps(rule))
        if Properties.IS_ENCRYPTION_ENABLED:
            enc_rule = CryptoHelper.aes_gcm_encryption_with_tag(rule)
        else:
            enc_rule = json.dumps(rule)
        socketClient.send_to_server(soc, enc_rule)
        count += 1
        print("Count=", count)
        time.sleep(1)
        if count == 2:
            break

    socketClient.send_to_server(soc, "quit")
    soc.close()



if __name__ == '__main__':
    start_simulation()
    #simulated_new_rules()
    #send_sample_rules()
