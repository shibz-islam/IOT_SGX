import requests, json, random, time

BASE_URL = "https://api.smartthings.com/v1/devices"
TOKEN = 'Bearer 752ce680-b34d-4988-bf5b-b68023edcc80'


def call_api_request(device_id, sub_url):
    url = BASE_URL
    if device_id is not None and sub_url is not None:
        url = url + "/" + device_id + "/" + sub_url
    payload = {}
    headers = {
        'Authorization': TOKEN
    }
    response = requests.request("GET", url, headers=headers, data=payload)
    print("api request response: ", response.json())
    return response.json()


def send_command_device(key, command):
    url = BASE_URL + "/" + key + "/commands"
    payload = command
    headers = {
        'Authorization': TOKEN,
        'Content-Type': 'application/json'
    }
    response = requests.request("POST", url, headers=headers, data=payload)
    print("send_command_device response: ", response.text.encode('utf8'))
