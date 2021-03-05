import requests, json, random, time
import Helper, Properties, socketClient, CryptoHelper
from MQTTClient import MQTTClient
import SmartThingsConnector

DEVICE_DICT = {}
MQTT_ACTIVE_DEVICES = []
MQTT_CLIENT = None

def send_request_for_device_list():
    """
    Get device info from SmartThings and save in a file
    :return:
    """
    items = SmartThingsConnector.call_api_request(device_id=None, sub_url=None)
    data = []
    for item in items['items']:
        info = item['deviceId'] + "," + item['name']
        data.append(info)
    Helper.write_data_to_file(Properties.datapath + Properties.filename_smartthings_devices, data)


def get_devices_info_from_file():
    """
    Get device info from file and store in the Global dictionary
    :return:
    """
    data = Helper.read_data_from_file(Properties.datapath + Properties.filename_smartthings_devices)
    for device in data:
        if '#' not in device:
            info = device.rstrip().split(',')
            DEVICE_DICT[info[1]] = {}
            DEVICE_DICT[info[1]]['name'] = info[0]
            DEVICE_DICT[info[1]]['device_id'] = info[1]
            DEVICE_DICT[info[1]]['capability'] = info[2]
            DEVICE_DICT[info[1]]['attribute'] = info[3]


def init_mqtt():
    global MQTT_CLIENT
    MQTT_CLIENT = MQTTClient(host="localhost", port=1883, keepalive=60)
    MQTT_CLIENT.run(forever=False)


def start_mqtt_service(device_id):
    global MQTT_CLIENT
    global MQTT_ACTIVE_DEVICES
    if MQTT_CLIENT is not None and device_id not in MQTT_ACTIVE_DEVICES:
        MQTT_ACTIVE_DEVICES.append(device_id)
        MQTT_CLIENT.subscribe(topic_name=Properties.MQTT_TOPIC_NAME + device_id)


def get_data_from_device(key):
    """
    Send api request to get the status of the device and send the event to SGX
    :param key: device id
    :return: Device Event in a SmartThings format
    """
    capability = DEVICE_DICT[key]['capability']
    attribute = DEVICE_DICT[key]['attribute']
    #print(key, capability, attribute)
    response_json = SmartThingsConnector.call_api_request(device_id=key, sub_url="components/main/status")
    if response_json[capability] is not None and response_json[capability][attribute] is not None:
        event = {"deviceID": key, capability: response_json[capability]}
        print("*** event:", event)
        return event
    return None


def start_process():
    get_devices_info_from_file()
    soc = socketClient.connect_to_server(port=20008)

    init_mqtt()
    for key in DEVICE_DICT.keys():
        start_mqtt_service(device_id=key)

    count = 0

    while True:
        print("**********")
        count += 1
        print("Count=", count)

        #device_key = random.choice(DEVICE_DICT.keys())
        if count%2==0:
            device_key = "f0c55b0b-e6fe-4fb4-b80b-9209703e3352"
        else:
            device_key = "f3cf86d6-db17-4c2d-930a-a6929dfdbbaf"

        event = get_data_from_device(device_key)
        if event is not None:
            #start_mqtt_service(device_id=device_key)
            Properties.PENDING_ID = event["deviceID"]
            if Properties.IS_ENCRYPTION_ENABLED:
                enc_rule = CryptoHelper.aes_gcm_encryption_with_tag(event)
            else:
                enc_rule = json.dumps(event)
            socketClient.send_to_server(soc, enc_rule)
            time.sleep(3)

        if count == 2:
            break

    socketClient.send_to_server(soc, "quit")
    soc.close()
    time.sleep(10)
    MQTT_CLIENT.disconnect()


def run_test_process():
    DEVICE_DICT.clear()
    get_devices_info_from_file()
    for key in DEVICE_DICT.keys():
        event = get_data_from_device(key)
        break


def send_sample_data_events():
    soc = socketClient.connect_to_server(port=20008)
    # init_mqtt()
    # get_devices_info_from_file()
    # for key in DEVICE_DICT.keys():
    #     start_mqtt_service(device_id=key)

    device_events = Helper.read_json_from_file(Properties.datapath + Properties.filename_test_events)
    count = 0
    for event in device_events:
        print("**********")
        count += 1
        # if count==1:
        #     continue

        print(json.dumps(event))
        if Properties.IS_ENCRYPTION_ENABLED:
            enc_rule = CryptoHelper.aes_gcm_encryption_with_tag(event)
        else:
            enc_rule = json.dumps(event)
        socketClient.send_to_server(soc, enc_rule)
        time.sleep(3)
        if count == 10:
            break
    socketClient.send_to_server(soc, "quit")
    soc.close()
    time.sleep(5)
    #MQTT_CLIENT.disconnect()


if __name__ == '__main__':
    #run_test_process()
    #send_sample_data_events()
    start_process()

