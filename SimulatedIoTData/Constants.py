from enum import Enum, auto

RULE_ID = 'ruleID'
RULE_USER_ID =  'userID'
RULE_DEVICE_ID = 'deviceID'
RULE_DEVICE_TYPE = 'deviceType'
RULE_NAME = 'name'
RULE_DESCRIPTION = 'description'
RULE_AUTHOR = 'author'

RULE_THRESHOLD = 'threshold'
RULE_OPERATOR = 'operator'
RULE_MEASUREMENT = 'measurement'

RULE_ACTION = 'action'
RULE_EMAIL = 'email'
RULE_EMAIL_TITLE = 'email_title'
RULE_ALERT = 'alert'
RULE_ALERT_TITLE = 'alert_title'

SENSOR_DATA = 'data'


class EnumAction(Enum):
    email = 0
    alert = 1
