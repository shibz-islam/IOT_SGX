import Helper, Constants, CryptoHelper, socketClient, Properties
from MQTTClient import MQTTClient
import json, random, time


path = "datafiles/"
filename = "device_set.json"
device_id_filename = "device_ids.txt"
mqtt_topic_name = "topic/utd/iot/server/data/"
ID_LENGTH = 16

valid_event_receiving_devices = ["Alarm", "ColorControl",  "DishwasherMode", "DishwasherOperatingState", "DryerMode",
                                 "DryerOperatingState", "Humidifier", "Lock", "OvenMode", "OvenOperatingState",
                                 "RefrigerationSetpoint", "RobotCleanerCleaningMode", "Switch", "SwitchLevel",
                                 "ThermostatMode", "TvChannel", "Valve", "WasherMode", "WasherOperatingState", "WindowControl"]
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
    json_objects = Helper.read_json_from_file(path + filename)

    list = []
    for device in json_objects:
        id = Helper.get_random_alphaNumeric_string(ID_LENGTH)
        capability = device['id']
        value = id + "," + capability
        list.append(value)
    # print(list)
    Helper.write_data_to_file(path + device_id_filename, list)


def get_device_profiles():
    json_objects = Helper.read_json_from_file(path + filename)
    device_ids = Helper.read_data_from_file(path + device_id_filename)
    for device in json_objects:
        capability = device['id']
        for device_id in device_ids:
            items = device_id.rstrip().split(",")
            if capability == items[1]:
                device[Constants.RULE_DEVICE_ID] = items[0]
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
        items = device.rstrip().split(",")
        capability = items[1]
        device_id = items[0]
        if capability in valid_event_receiving_devices:
            mqtt_client.subscribe(topic_name=mqtt_topic_name+device_id)


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
        items = info.rstrip().split(",")
        if capability == items[1]:
            device_id = items[0]
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
    print("*******")
    print(event)
    return event, True


def start_simulation():
    soc = socketClient.connect_to_server(port=20004)

    device_profiles = Helper.read_json_from_file(path + filename)
    device_list = Helper.read_data_from_file(path + device_id_filename)

    start_mqtt_service_for_devices(device_list)

    count = 0
    while True:
        device_profile = random.choice(device_profiles)
        #device_profile = device_profiles[count]

        event, is_success = simulate_data(device_profile, device_list)
        if is_success:
            enc_rule = CryptoHelper.aes_gcm_encryption_with_tag(event)
            #enc_rule = json.dumps(event)
            Helper.record_start_time()
            socketClient.send_to_server(soc, enc_rule)
            time.sleep(10)
            count += 1
            print("Count=", count)
            if count == len(device_profiles):
                break


    socketClient.send_to_server(soc, "quit")
    soc.close()


def send_sample_data_events():
    device_events = Helper.read_json_from_file(path + "SampleDeviceEvents.json")
    # soc = socketClient.connect_to_server(port=20005)
    for event in device_events:
        # enc_rule = CryptoHelper.aes_gcm_encryption_with_tag(event)
        # enc_rule = json.dumps(event)
        # socketClient.send_to_server(soc, enc_rule)
        time.sleep(1)
    # socketClient.send_to_server(soc, "quit")
    # soc.close()


if __name__ == '__main__':
    start_simulation()
    # send_sample_data_events()
