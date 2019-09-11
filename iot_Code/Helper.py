import json, time, os
import Properties, CryptoHelper


def read_data_from_file(filepath, filename):
    path = os.path.join(filepath, filename)
    file = open(path, 'rb')
    data = file.read()
    file.close()
    return data


def get_json_data(data):
    dataTemp = json.dumps(data)
    data_json = json.loads(dataTemp)
    return data_json


def clear_file_content():
    open(Properties.log_filename, "w").close()


def write_time_difference(diff):
    file1 = open(Properties.log_filename, "a+")  # append mode
    file1.write(str(diff) + "\n")
    file1.close()


def calculate_avg_time():
    file1 = open(Properties.log_filename, "r")
    lines = file1.readlines()
    sum = 0
    count = 0
    for value in lines:
        sum += float(value)
        count += 1
    avg = sum/count
    print("*** Sum", sum)
    print("*** Average = ", avg)
    file1.close()


def report_start_time():
    Properties.START_TIME = time.time()


def report_end_time():
    Properties.END_TIME = time.time()
    diff = (Properties.END_TIME - Properties.START_TIME) * 1000
    print("Start time = ", Properties.START_TIME)
    print("End time = ", Properties.END_TIME)
    print("$$$$$ Time Difference (miliseconds) = ", diff)
    write_time_difference(diff)


if __name__ == '__main__':
    calculate_avg_time()
