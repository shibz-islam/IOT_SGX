import json, time, threading
import socketClient, CryptoHelper, Helper, Constants
from MongoManager import MongoManager


# TO-DO: fetch these from DB
Measurements = ['Temperature', 'Bulb', 'Humidity' ]
Operators = ['is greater than', 'is less than', 'is equal', 'state dependant']
Actions = ['email', 'alert']
Devices = ['TemperatureSensor', 'Smart Bulb', 'HumiditySensor'] # these devices correspond to that user
DeviceIDs = ['123', '234', '345']


rule_json = {}
soc = 0
rule_db = 0
# soc = socketClient.connect_to_server(port=20002)


def send_data(enc_rule):
    socketClient.send_to_server(soc, enc_rule)


def get_metadata():
    rule_name = str(input("Your Rule name: "))
    # print("Description: ")
    # rule_des = str(input())
    # print("Author: ")
    # rule_author = str(input())
    rule_json[Constants.RULE_NAME] = rule_name
    # rule_json['description'] = rule_des
    # rule_json['author'] = rule_author


def build_event():
    print(">>> ", Measurements)
    rule_measurement = int(input("Select a measurement (type index): "))
    if rule_measurement in range(len(Measurements)):
        rule_json[Constants.RULE_MEASUREMENT] = Measurements[rule_measurement]

    print(">>> ", Operators)
    rule_operator = int(input("Operator (type index): "))
    if rule_operator in range(len(Operators)):
        rule_json[Constants.RULE_OPERATOR] = rule_operator
    else:
        print("Wrong input! please try again.")
        exit(0)

    if rule_operator is not 3:
        rule_threshold = float(input("Threshold: "))
        rule_json[Constants.RULE_THRESHOLD] = rule_threshold


def build_action():
    print(">>> ", Actions)
    rule_action = int(input("Select an Action (type index): "))
    if rule_action in range(len(Actions)):
        rule_json[Constants.RULE_ACTION] = rule_action
        if rule_action == Constants.EnumAction.email.value:
            rule_json[Constants.RULE_EMAIL] = str(input("Email address: "))
            rule_json[Constants.RULE_EMAIL_TITLE] = str(input("Email Title "))
        elif rule_action == Constants.EnumAction.alert.value:
            rule_json[Constants.RULE_ALERT] = str(input("Alert address: "))
            rule_json[Constants.RULE_ALERT_TITLE] = str(input("Alert Title "))
        else:
            print("Unknown rule!")
    else:
        print("Wrong input! please try again.")
        exit(0)


def build_rule():

    print(">>> ", Devices)
    rule_device = int(input("Choose Device (type index or -1 to end):"))
    if rule_device in range(len(Devices)):
        rule_json[Constants.RULE_DEVICE_ID] = DeviceIDs[rule_device]
        get_metadata()
        build_event()
        build_action()
        print(rule_json)

        enc_rule = CryptoHelper.aes_gcm_encryption_with_tag(rule_json)
        # insert into DB
        json_rule = json.loads(enc_rule)
        rule_db.insert_one_into_db(json_rule)
        # Send to SGX
        send_data(enc_rule)
    else:
        print("Exiting....")
        return


def test_sample_rule():
    sample_rule1 = "{'deviceID': '234', 'ruleID': '890jol', 'userID': '563y2k', 'name': 'TempRule', 'measurement': 'Temperature', 'operator': '1', 'threshold': 50.0, 'action': '0', 'email': 'abc@gmail.com', 'email_title': 'Alert!'}"
    sample_rule2 = "{'deviceID': '567', 'ruleID': '469lef', 'userID': '563y2k', 'name': 'HumRule', 'measurement': 'Humidity', 'operator': '0', 'threshold': 50.0, 'action': '0', 'email': 'abc@gmail.com', 'email_title': 'Alert!'}"
    count = 0
    while True:
        if count % 2 == 0:
            sample_data = sample_rule1
        else:
            sample_data = sample_rule2
        jd = Helper.get_json_data(sample_data)
        enc_rule = CryptoHelper.aes_gcm_encryption_with_tag(jd)
        # insert into DB
        json_rule = json.loads(enc_rule)
        rule_db.insert_one_into_db(json_rule)
        # Send to SGX
        socketClient.send_to_server(soc, enc_rule)

        count += 1
        if count == 2:
            break
        time.sleep(60)


def test():
    t1 = threading.Thread(target=test_sample_rule)
    t1.start()
    t1.join()


if __name__ == '__main__':
    rule_db = MongoManager(ip='localhost', port=27017, db_name='IOT', collection_name='rulebase')
    rule_db.init_connection()
    soc = socketClient.connect_to_server(port=20002)
    test()
    # build_rule()
    soc.close()

    print("Finished!")
