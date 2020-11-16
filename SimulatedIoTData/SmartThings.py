import requests, json, random, time
import Helper, Properties, socketClient, CryptoHelper
from MQTTClient import MQTTClient


BASE_URL = "https://api.smartthings.com/v1/devices"
TOKEN = 'Bearer 752ce680-b34d-4988-bf5b-b68023edcc80'
smartthings_devices_file = "smartthings_devices.txt"
DEVICE_DICT = {}


def call_api_request(device_id, sub_url):
    url = BASE_URL
    if device_id is not None:
        url = url + "/" + device_id + "/" + sub_url
    payload = {}
    headers = {
        'Authorization': TOKEN
    }
    response = requests.request("GET", url, headers=headers, data=payload)
    print(response.json())
    return response.json()


def send_request_device_list():
    items = call_api_request(device_id=None, sub_url=None)
    data = []
    for item in items['items']:
        info = item['deviceId'] + "," + item['name']
        data.append(info)
    Helper.write_data_to_file(Properties.datapath + smartthings_devices_file, data)


def send_request_device_component_status(device_id):
    items = call_api_request(device_id=device_id, sub_url="components/main/status")
    return items


def send_command_device(key, command):
    url = BASE_URL + "/" + key + "/commands"
    payload = command
    headers = {
        'Authorization': TOKEN,
        'Content-Type': 'application/json'
    }
    response = requests.request("POST", url, headers=headers, data=payload)
    print(response.text.encode('utf8'))


def get_devices_info_from_file():
    data = Helper.read_data_from_file(Properties.datapath + smartthings_devices_file)
    for device in data:
        if '#' not in device:
            info = device.rstrip().split(',')
            DEVICE_DICT[info[1]] = {}
            DEVICE_DICT[info[1]]['name'] = info[0]
            DEVICE_DICT[info[1]]['device_id'] = info[1]
            DEVICE_DICT[info[1]]['capability'] = info[2]
            DEVICE_DICT[info[1]]['attribute'] = info[3]


def start_mqtt_service_for_devices():
    mqtt_client = MQTTClient(host="localhost", port=1883, keepalive=60)
    mqtt_client.run(forever=False)
    for key in DEVICE_DICT.keys():
        mqtt_client.subscribe(topic_name=Properties.MQTT_TOPIC_NAME + key)


def get_data_from_device(key):
    capability = DEVICE_DICT[key]['capability']
    attribute = DEVICE_DICT[key]['attribute']
    print(key, capability, attribute)
    response_json = send_request_device_component_status(device_id=key)
    if response_json[capability] is not None and response_json[capability][attribute] is not None:
        event = {"deviceID": key, capability: response_json[capability]}
        print("event:", event)
        return event
    return None


def start_process():
    get_devices_info_from_file()
    soc = socketClient.connect_to_server(port=20007)
    #start_mqtt_service_for_devices()
    count = 0
    while True:
        device_key = random.choice(DEVICE_DICT.keys())
        event = get_data_from_device(device_key)
        if event is not None:
            Properties.PENDING_ID = event["deviceID"]
            if Properties.IS_ENCRYPTION_ENABLED:
                enc_rule = CryptoHelper.aes_gcm_encryption_with_tag(event)
            else:
                enc_rule = json.dumps(event)
            socketClient.send_to_server(soc, enc_rule)
            time.sleep(3)
            count += 1
            print("Count=", count)
        if count == 10000:
            break

    socketClient.send_to_server(soc, "quit")
    soc.close()


def test_process():
    get_devices_info_from_file()
    for key in DEVICE_DICT.keys():
        get_data_from_device(key)
        break


if __name__ == '__main__':
    test_process()
    #start_process()

