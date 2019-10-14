# -*- coding: utf-8 -*-

# -*- coding: utf-8 -*-
"""
Created on Thu Jan 10 11:27:07 2019

@author: Innive
"""



import threading, time, signal
import json
from kafka import KafkaProducer
import requests
import CryptoHelper, Helper, Properties
from datetime import timedelta
from Job import Job

resData={'data':[]}
TOTAL_COUNT = 0
COUNT_LIMIT = 500


class ProgramKilled(Exception):
    pass


def call_flask_app():
    res2 = requests.get('http://127.0.0.1:5000/temp')
    print(res2.json())
    publish_message(kafka_producer, 'IOT', 'iotHub', res2.json())
    # resData['data'].append(res2.json())
    # print(res)



def call_test_data_for_sgx():
    Properties.START_TIME = time.time()
    print("Start time = ", Properties.START_TIME)
    resBulb = {'deviceId': '345', 'deviceType': 'Foobot', 'data': '20.0'}
    json_data = Helper.get_json_data(resBulb)
    print(json_data)

    # msg, tag = CryptoHelper.encrypt_data_with_tag(json_data['data'])
    # json_data['data'] = msg
    # json_data['tag'] = tag
    # print(json_data)

    enc_json_data_with_tag = CryptoHelper.aes_gcm_encryption_with_tag(json_data)

    publish_message(kafka_producer, 'IOT', 'iotHub', enc_json_data_with_tag)
    time.sleep(Properties.SLEEP_TIME_SECONDS)


def send_data_from_device():
    headers = {"Accept": "application/json;charset=UTF-8",
               "X-API-KEY-TOKEN": "eyJhbGciOiJIUzI1NiJ9.eyJncmFudGVlIjoicHJlZXRpZHA5MEBnbWFpbC5jb20iLCJpYXQiOjE1NjAzNjY4MjcsInZhbGlkaXR5IjotMSwianRpIjoiZDc4MDU4MTMtNzYwMS00M2Q0LWEwNjUtMmMwNzY4MmRkODkyIiwicGVybWlzc2lvbnMiOlsidXNlcjpyZWFkIiwiZGV2aWNlOnJlYWQiXSwicXVvdGEiOjIwMCwicmF0ZUxpbWl0Ijo1fQ.hOynMDGdDoTsACa66krjyJXPRcpJOCVpXrUfZAroQSA"}
    r2 = requests.get(
        "https://api.foobot.io/v2/device/2C0A676E28802CA2/datapoint/5/last/90/?sensorList=pm%2Cvoc%2Chum%2Ctmp%2Cco2%2Callpollu",
        headers=headers)

    print(r2.json())
    r3 = r2.json()
    dataTemp = {'doc_id': time.ctime(), r3['sensors'][0]: r3['datapoints'][0][0],
                r3['sensors'][1]: r3['datapoints'][0][1], r3['sensors'][2]: r3['datapoints'][0][2],
                r3['sensors'][3]: r3['datapoints'][0][3], r3['sensors'][4]: r3['datapoints'][0][4],
                r3['sensors'][5]: r3['datapoints'][0][5], r3['sensors'][6]: r3['datapoints'][0][6]}
    res = {'deviceId': r3['uuid'], 'deviceType': 'AirQualitySensor', 'data': dataTemp}
    json_data = Helper.get_json_data(res)
    print(json_data)

    ct = CryptoHelper.aes_gcm_encryption_python(json_data)
    # CryptoHelper.aes_gcm_decryption_python(ct)
    publish_message(kafka_producer, topic_name='IOT', key='iotHub', value=ct)
    time.sleep(Properties.SLEEP_TIME_SECONDS)


def call_test_data_for_spark():
    send_data_from_device()


def foo():
    global TOTAL_COUNT
    if TOTAL_COUNT == COUNT_LIMIT:
        print("! QUIT !")
        quit()
    TOTAL_COUNT += 1
    print(time.ctime())
    # call_flask_app()
    if Properties.IS_SGX:
        call_test_data_for_sgx()
    else:
        call_test_data_for_spark()


def connect_kafka_producer():
    _producer = None
    try:
        _producer = KafkaProducer(bootstrap_servers=['10.176.148.202:9092'], api_version=(0, 10))
    except Exception as ex:
        print('Exception while connecting Kafka')
        print(str(ex))
    finally:
        return _producer


def publish_message(producer_instance, topic_name, key, value):
    try:
        key_bytes = bytes(key, encoding='utf-8')
        #text=str(value['deviceId'])+'||'+str(value['deviceType'])+'||'+str(value['data'])
        value_bytes=value.encode('utf-8')
        print("###############",value_bytes)
        producer_instance.send(topic_name, key=key_bytes, value=value_bytes)
        producer_instance.flush()
        print('Message published successfully.')
    except Exception as ex:
        print('Exception in publishing message')
        print(str(ex))


def signal_handler(signum, frame):
    raise ProgramKilled



if __name__ == "__main__":
    Helper.clear_file_content()
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    job = Job(interval=timedelta(seconds=Properties.WAIT_TIME_SECONDS), execute=foo)
    kafka_producer = connect_kafka_producer()
    job.start()
    
    while True:
          try:
              time.sleep(1)
          except ProgramKilled:
              print("Program killed: running cleanup code")
              job.stop()
              break
