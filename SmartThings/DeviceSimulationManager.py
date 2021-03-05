import Helper, CryptoHelper, socketClient, Properties
from MQTTClient import MQTTClient
import json, random, time


filename_device_ids = "device_ids.txt"
ID_LENGTH = 16
valid_event_receiving_devices = ["Alarm", "ColorControl", "DishwasherMode", "DishwasherOperatingState", "DryerMode",
                                 "DryerOperatingState", "Humidifier", "Lock", "OvenMode", "OvenOperatingState",
                                 "RefrigerationSetpoint", "RobotCleanerCleaningMode", "SwitchLevel", "ThermostatMode",
                                 "TvChannel", "Valve", "WasherMode"]
valid_event_sending_devices = ["CarbonDioxideMeasurement",
                               "DoorControl",
                               "DustSensor",
                               "EnergyMeter",
                               "MotionSensor",
                               "PresenceSensor",
                               "RelativeHumidityMeasurement",
                               "SmokeDetector",
                               "SoundSensor",
                               "Switch",
                               "TemperatureMeasurement",
                               "WasherOperatingState",
                               "WaterSensor",
                               "WindowControl"]


def generate_device_ids():
    "device id creation for the first time for each device in the smartthings_device_config file"
    json_objects = Helper.read_json_from_file(Properties.datapath + Properties.filename_smartthings_device_config)
    list = []
    for device in json_objects:
        id = Helper.get_random_alphaNumeric_string(ID_LENGTH)
        capability = device['id']
        value = id + "," + capability
        list.append(value)
    # print(list)
    Helper.write_data_to_file(Properties.datapath + filename_device_ids, list)


def simulate_new_device_ids(count=100):
    "Create new device ids for each device, total specified by the count"
    device_list = Helper.read_data_from_file(Properties.datapath + filename_device_ids)
    #limit = 100
    id_list = []
    for device in device_list:
        items = device.rstrip().split(",")
        capability = items[1]
        device_id = items[0]
        id_str = capability
        for i in range(count):
            id = Helper.get_random_alphaNumeric_string(stringLength=16)
            id_str = id_str + "," + id
        id_list.append(id_str)
    Helper.write_data_to_file(filepath=Properties.datapath+"device_ids_list.txt", data_list=id_list)


def get_device_profiles():
    json_objects = Helper.read_json_from_file(Properties.datapath + Properties.filename_smartthings_device_config)
    device_ids = Helper.read_data_from_file(Properties.datapath + filename_device_ids)
    for device in json_objects:
        capability = device['id']
        for device_id in device_ids:
            items = device_id.rstrip().split(",")
            if capability == items[1]:
                device["deviceID"] = items[0]
                break
        # print(device)
    return json_objects


def is_valid_event_sending_device(capability):
    if capability in valid_event_sending_devices:
        return True
    return False


def start_mqtt_service_for_devices(device_list):
    mqtt_client = MQTTClient(host="localhost", port=1883, keepalive=60)
    mqtt_client.run(forever=False)
    for device in device_list:
        items = device.rstrip().split(",", 1)
        capability = items[0]
        if capability in valid_event_receiving_devices:
            device_ids = items[1].split(",")
            for dev_id in device_ids:
                mqtt_client.subscribe(topic_name=Properties.MQTT_TOPIC_NAME+dev_id)


def simulate_values(property_list):
    chosen_value = ""
    value_type = ""
    unit = ""
    if len(property_list) > 0:
        property = property_list[0]
        value = property['value']
        value_type = value['type']
        if value_type == 'string':
            if 'enum' in value:
                chosen_value = random.choice(value['enum'])
        elif value_type == 'number' or value_type == 'integer':
            min = 0
            max = 100
            if 'minimum' in value:
                min = value['minimum']
            if 'maximum' in value:
                max = value['maximum']
            chosen_value = random.randint(min, max)
        # print(chosen_value)

        if 'unit' in property:
            unit = property['unit']['default']
            # print(unit)
    return chosen_value, value_type, unit


def simulate_data(device_profile, device_list):
    """ Device ID & Capability """
    capability = device_profile['id']

    if not is_valid_event_sending_device(capability):
        return None, False

    device_id = ""
    for info in device_list:
        items = info.rstrip().split(",", 1)
        if capability == items[0]:
            id_list = items[1].split(",")
            device_id = random.choice(id_list)
            break

    """ Attribute """
    attr = ""
    keys = list(device_profile['attributes'].keys())
    attr = keys[0]

    """ Value & Unit """
    property_list = Helper.extract_values_from_json(obj=device_profile['attributes'], key='properties')
    chosen_value, value_type, unit = simulate_values(property_list)

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

    event_new = {
        "deviceID": device_id,
        capability: {
            attr:{
                "value": chosen_value,
                "unit": unit,
                "arguments": []
            }
        }
    }
    print("*******")
    print(event_new)
    return event_new, True


def start_simulation():
    "Create data events according to tracked devices and their configuration"
    soc = socketClient.connect_to_server(port=20008)

    device_profiles = Helper.read_json_from_file(Properties.datapath + Properties.filename_smartthings_device_config)
    device_list = Helper.read_data_from_file(Properties.datapath + str(Properties.RULE_COUNT) + Properties.filename_tracked_device_id_list)

    #start_mqtt_service_for_devices(device_list)

    count = 0
    while True:
        device_profile = random.choice(device_profiles)
        event, is_success = simulate_data(device_profile, device_list)
        if is_success:
            Properties.PENDING_ID = event["deviceID"]
            if Properties.IS_ENCRYPTION_ENABLED:
                enc_rule = CryptoHelper.aes_gcm_encryption_with_tag(event)
            else:
                enc_rule = json.dumps(event)
            socketClient.send_to_server(soc, enc_rule)
            time.sleep(1)
            count += 1
            print("Count=", count)
        if count == Properties.RULE_COUNT:
            break

    socketClient.send_to_server(soc, "quit")
    soc.close()


def send_sample_data_events():
    "Send sample data events directly from a file"
    device_events = Helper.read_json_from_file(Properties.datapath + Properties.filename_test_events)
    soc = socketClient.connect_to_server(port=20008)
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
        time.sleep(2)
        if count == 10:
            break
    socketClient.send_to_server(soc, "quit")
    soc.close()


if __name__ == '__main__':
    start_simulation()
    #send_sample_data_events()
    #simulate_new_device_ids(count=100)
