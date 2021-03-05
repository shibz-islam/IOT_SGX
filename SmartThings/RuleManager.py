import Helper, CryptoHelper, socketClient, Properties
import json, random, time
import copy


def start_simulation():
    soc = socketClient.connect_to_server(port=20006)
    rule_list = Helper.read_json_from_file(Properties.datapath + str(Properties.RULE_COUNT) + Properties.filename_test_ruleset)
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
        if count == 1:
            break

    socketClient.send_to_server(soc, "quit")
    soc.close()


def send_sample_rules():
    soc = socketClient.connect_to_server(port=20006)
    rule_list = Helper.read_json_from_file(
        Properties.datapath + Properties.filename_test_ruleset)
    print("Total rules: ", len(rule_list))
    random.shuffle(rule_list)

    #rule_list = rule_list[1:3]

    count = 0
    for rule in rule_list:
        print("**********")
        count += 1
        # if count==1:
        #     continue
        print(json.dumps(rule))
        if Properties.IS_ENCRYPTION_ENABLED:
            enc_rule = CryptoHelper.aes_gcm_encryption_with_tag(rule)
        else:
            enc_rule = json.dumps(rule)
        socketClient.send_to_server(soc, enc_rule)

        print("Count=", count)
        time.sleep(0.5)
        if count == Properties.RULE_COUNT:
            break

    socketClient.send_to_server(soc, "quit")
    soc.close()



if __name__ == '__main__':
    #start_simulation()
    #simulated_new_rules()
    send_sample_rules()
