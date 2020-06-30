from enum import Enum


class Actions(Enum):
    COMMAND = 1
    EVERY = 2
    IF = 3
    SLEEP = 4
    LOCATION = 5
    NOTIFY = 6


datapath = "datafiles/"
base_ruleset_filename = "Ruleset.json"
base_device_id_list_filename = "device_id_list.txt"
device_properties_filename = "device_set.json"

ruleset_large_filename = "_ruleset_large.json"
tracked_device_id_list_filename = "_tracked_device_id_list.txt"

EXP_PATH = "experiments/"
FILENAME_RECORD_RESPONSE_TIME = "record_response_time"
FILENAME_RECORD_RESPONSE_TIME_UNENC = "record_response_time_unenc"
FILENAME_EXT = "_June22.txt"

RULE_COUNT = 10000

IS_ENCRYPTION_ENABLED = False
START_TIME = 0
PENDING_ID = ""