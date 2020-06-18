from enum import Enum


class Actions(Enum):
    COMMAND = 1
    EVERY = 2
    IF = 3
    SLEEP = 4
    LOCATION = 5
    NOTIFY = 6


START_TIME = 0