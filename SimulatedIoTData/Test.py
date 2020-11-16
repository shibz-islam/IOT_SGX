import Helper, Properties, CryptoHelper, DeviceManager
import json, requests, time
from timeit import default_timer as timer
import socket
import threading


def operate_philips_hue(payload):
    print("payload:", payload)
    url = 'https://192.168.2.2/api/Ud3DJwRp8gmjjezMxCmubKAYcFb3daCtfxNTmwWF/lights/4/state'
    headers = {'content-type': 'application/json', 'Accept-Charset': 'UTF-8'}
    r = requests.put(url, data=json.dumps(payload), headers=headers, verify=False)


def simulate_data(device_profile, capability):
    device_id = "RFXUBklXGCN64Q9P"
    """ Attribute """
    attr = ""
    keys = list(device_profile['attributes'].keys())
    attr = keys[0]

    """ Value & Unit """
    property_list = Helper.extract_values_from_json(obj=device_profile['attributes'], key='properties')
    chosen_value, value_type, unit = DeviceManager.simulate_values(property_list)

    event = {
        "deviceID": device_id,
        "deviceEvents": [
            {
                "component": "main",
                "capability": capability,
                "attribute": attr,
                "value": {
                    value_type: chosen_value
                },
                "unit": unit,
                "data": []
            }
        ]
    }
    print("*******")
    print(event)
    return event, True


def connect_to_server(port=20003):
    # Create a socket object
    s = socket.socket()
    # connect to the server on local computer
    #s.connect(('127.0.0.1', port))
    s.connect(('10.176.148.127', port))
    print("Client Socket: ", s.getsockname())
    print("Server Socket: ", s.getpeername())
    return s


def send_to_server(s, j):
    s.send(j.encode())


def receive_from_server(s):
    while(True):
        msg = s.recv(1024)
        if(len(msg) > 0):
            print("*** Received: ", msg.decode())
            if msg.decode() == "quit":
                break
            payload = {}
            if Properties.IS_ENCRYPTION_ENABLED:
                dec_msg = CryptoHelper.aes_gcm_decryption_with_tag(msg)
                command_json = dec_msg[0]
                if "command" in command_json:
                    if command_json["command"] == "on":
                        payload = {"on": True}
                    else:
                        payload = {"on": False}
                    operate_philips_hue(payload=payload)
                    Helper.log_response_time()
            else:
                dec_msg = json.loads(json.dumps(msg.decode()))
                if dec_msg.find("off") == -1:
                    payload = {"on": True}
                else:
                    payload = {"on": False}
                operate_philips_hue(payload=payload)
                Helper.log_response_time()


def send_test_rule():
    soc = connect_to_server(port=20006)
    rule_list = Helper.read_json_from_file(
        Properties.datapath + "TestRules.json")
    print("Total rules: ", len(rule_list))
    count = 0
    for rule in rule_list:
        print("**********")
        print(json.dumps(rule))
        if Properties.IS_ENCRYPTION_ENABLED:
            enc_rule = CryptoHelper.aes_gcm_encryption_with_tag(rule)
        else:
            enc_rule = json.dumps(rule)
        send_to_server(soc, enc_rule)
        count += 1
        print("Count=", count)
        time.sleep(1)
        if count == len(rule_list):
            break

    send_to_server(soc, "quit")
    soc.close()


def send_device_events(soc):
    device_profiles = Helper.read_json_from_file(Properties.datapath + Properties.device_properties_filename)
    device_profile = None
    capability = "TemperatureMeasurement"
    for profile in device_profiles:
        if profile['id'] == capability:
            device_profile = profile
            break

    count = 0
    while True:
        event, is_success = simulate_data(device_profile, capability)
        if is_success:
            Properties.PENDING_ID = event["deviceID"]
            Properties.START_TIME = timer()
            if Properties.IS_ENCRYPTION_ENABLED:
                enc_rule = CryptoHelper.aes_gcm_encryption_with_tag(event)
            else:
                enc_rule = json.dumps(event)
            send_to_server(soc, enc_rule)
            #receive_from_server(soc)
            time.sleep(5)
            count += 1
            print("Count=", count)
        if count == 100:
            break

    send_to_server(soc, "quit")
    soc.close()



def test_device_events():
    soc = connect_to_server(port=20009)

    # creating thread
    t1 = threading.Thread(target=send_device_events, args=(soc,))
    t2 = threading.Thread(target=receive_from_server, args=(soc,))

    # starting thread 1
    t1.start()
    # starting thread 2
    t2.start()

    # wait until thread 1 is completely executed
    t1.join()
    # wait until thread 2 is completely executed
    t2.join()


if __name__ == '__main__':
    #send_test_rule()
    test_device_events()
