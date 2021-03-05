from enum import Enum


class Actions(Enum):
    COMMAND = 1
    EVERY = 2
    IF = 3
    SLEEP = 4
    LOCATION = 5
    NOTIFY = 6


datapath = "datafiles/"
filename_test_ruleset = "100000_ruleset_large_new.json"
filename_test_events = "TestDeviceEvents.json"

filename_smartthings_ruleset = "SampleRulesetSmartThings.json"
filename_smartthings_events = "SampleDeviceEventsSmartThings.json"
filename_smartthings_devices = "smartthings_devices.txt"
filename_smartthings_device_config = "smartthings_device_config.json"

filename_tracked_device_id_list = "_tracked_device_id_list.txt"


EXP_PATH = "experiments/"
FILENAME_RECORD_RESPONSE_TIME = "record_response_time"
FILENAME_RECORD_RESPONSE_TIME_UNENC = "record_response_time_unenc"
FILENAME_EXT = "_june29.txt"

RULE_COUNT = 100000

IS_ENCRYPTION_ENABLED = True
START_TIME = 0
PENDING_ID = ""

MQTT_TOPIC_NAME = "iot/utd/data/"